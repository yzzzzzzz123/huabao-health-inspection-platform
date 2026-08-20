"""SQLite identity, artifact, state, and tamper-evident event index."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Mapping


DATABASE_SCHEMA_VERSION = "2"
MIGRATABLE_DATABASE_SCHEMA_VERSIONS = frozenset({"1"})
RUN_STATUSES = frozenset({"creating", "open", "sealing", "sealed", "deleting", "error"})
ACTIVE_STATUSES = frozenset({"creating", "open", "sealing", "deleting"})
POLICY_ACTIVATION_MODES = frozenset({"scheduled", "next_inspection"})


class StateStoreError(RuntimeError):
    """The durable control-plane index is invalid or unavailable."""


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


class StateStore:
    def __init__(self, project_root: Path, *, database_path: Path | None = None) -> None:
        self.project_root = project_root.resolve()
        self.database_path = (
            database_path.resolve()
            if database_path is not None
            else self.project_root / ".huabao" / "workspace-state.sqlite3"
        )
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.database_path,
            timeout=30.0,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA trusted_schema = OFF")
        connection.execute("PRAGMA busy_timeout = 30000")
        return connection

    def _connect_read_only(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            f"{self.database_path.as_uri()}?mode=ro&immutable=1",
            timeout=30.0,
            isolation_level=None,
            uri=True,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA trusted_schema = OFF")
        connection.execute("PRAGMA busy_timeout = 30000")
        return connection

    @staticmethod
    def _table_columns(connection: sqlite3.Connection, table: str) -> set[str]:
        try:
            rows = connection.execute(f'PRAGMA table_info("{table}")').fetchall()
        except sqlite3.DatabaseError as exc:
            raise StateStoreError(f"state database table cannot be inspected: {table}") from exc
        return {str(row["name"]) for row in rows}

    @classmethod
    def _preflight_schema(cls, connection: sqlite3.Connection) -> str | None:
        """Validate an existing database without changing journal or schema state.

        ``None`` means the database has no application tables and may be initialized.
        Every non-empty database must identify a supported schema before any mutable
        initialization is allowed.
        """

        try:
            rows = connection.execute(
                """
                SELECT name
                FROM sqlite_master
                WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
                ORDER BY name
                """
            ).fetchall()
            tables = {str(row["name"]) for row in rows}
            if not tables:
                return None
            if "metadata" not in tables:
                raise StateStoreError(
                    "unsupported state database without schema metadata"
                )
            row = connection.execute(
                "SELECT value FROM metadata WHERE key = 'schema_version'"
            ).fetchone()
        except sqlite3.DatabaseError as exc:
            raise StateStoreError("state database schema cannot be verified") from exc
        if row is None:
            raise StateStoreError(
                "unsupported state database without a schema version"
            )
        version = str(row["value"])
        if (
            version != DATABASE_SCHEMA_VERSION
            and version not in MIGRATABLE_DATABASE_SCHEMA_VERSIONS
        ):
            raise StateStoreError(f"unsupported database schema version: {version}")

        core_tables = {"metadata", "runs", "artifacts", "audit_events"}
        allowed_tables = core_tables | {"next_inspection_policy_claims"}
        if not core_tables.issubset(tables) or not tables.issubset(allowed_tables):
            raise StateStoreError(
                "state database tables do not match the declared schema"
            )

        base_run_columns = {
            "run_id",
            "business_date",
            "incarnation_id",
            "release_id",
            "platform_release_json",
            "platform_release_sha256",
            "workspace_version",
            "status",
            "active_slot",
            "workspace_path",
            "branch_name",
            "base_commit",
            "checkpoint_commit",
            "archive_path",
            "created_at",
            "seal_started_at",
            "sealed_at",
            "error_code",
            "error_message",
        }
        policy_run_columns = {
            "policy_version",
            "published_policy_sha256",
            "runtime_policy_sha256",
            "policy_activation_mode",
        }
        run_columns = cls._table_columns(connection, "runs")
        if not base_run_columns.issubset(run_columns):
            raise StateStoreError("state database runs table is incomplete")
        if version == "1":
            if policy_run_columns & run_columns or "next_inspection_policy_claims" in tables:
                raise StateStoreError("state database v1 schema is partially migrated")
        else:
            if not policy_run_columns.issubset(run_columns):
                raise StateStoreError("state database v2 runs table is incomplete")
            if "next_inspection_policy_claims" not in tables:
                raise StateStoreError("state database v2 claim table is missing")
            claim_columns = cls._table_columns(
                connection, "next_inspection_policy_claims"
            )
            expected_claim_columns = {
                "published_policy_sha256",
                "policy_version",
                "runtime_policy_sha256",
                "queued_at",
                "run_id",
                "incarnation_id",
            }
            if not expected_claim_columns.issubset(claim_columns):
                raise StateStoreError("state database v2 claim table is incomplete")
        return version

    @contextmanager
    def transaction(self, *, immediate: bool = True) -> Iterator[sqlite3.Connection]:
        connection = self.connect()
        try:
            connection.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    @staticmethod
    def _create_schema_v2(connection: sqlite3.Connection) -> None:
        connection.executescript(
            """
            CREATE TABLE metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE runs (
                run_id TEXT PRIMARY KEY,
                business_date TEXT NOT NULL UNIQUE,
                incarnation_id TEXT NOT NULL UNIQUE,
                release_id TEXT NOT NULL,
                platform_release_json TEXT NOT NULL,
                platform_release_sha256 TEXT NOT NULL,
                workspace_version TEXT NOT NULL,
                policy_version TEXT NOT NULL CHECK (length(trim(policy_version)) > 0),
                published_policy_sha256 TEXT NOT NULL CHECK (
                    length(published_policy_sha256) = 64
                    AND published_policy_sha256 = lower(published_policy_sha256)
                    AND published_policy_sha256 NOT GLOB '*[^0-9a-f]*'
                ),
                runtime_policy_sha256 TEXT NOT NULL CHECK (
                    length(runtime_policy_sha256) = 64
                    AND runtime_policy_sha256 = lower(runtime_policy_sha256)
                    AND runtime_policy_sha256 NOT GLOB '*[^0-9a-f]*'
                ),
                policy_activation_mode TEXT NOT NULL CHECK (
                    policy_activation_mode IN ('scheduled', 'next_inspection')
                ),
                status TEXT NOT NULL CHECK (
                    status IN ('creating','open','sealing','sealed','deleting','error')
                ),
                active_slot INTEGER UNIQUE CHECK (active_slot IS NULL OR active_slot = 1),
                workspace_path TEXT NOT NULL UNIQUE,
                branch_name TEXT NOT NULL UNIQUE,
                base_commit TEXT,
                checkpoint_commit TEXT,
                archive_path TEXT,
                created_at TEXT NOT NULL,
                seal_started_at TEXT,
                sealed_at TEXT,
                error_code TEXT,
                error_message TEXT
            );

            CREATE TABLE artifacts (
                run_id TEXT NOT NULL,
                artifact_id TEXT NOT NULL,
                relative_path TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                byte_count INTEGER NOT NULL CHECK (byte_count >= 0),
                media_type TEXT NOT NULL,
                writer TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (run_id, artifact_id),
                UNIQUE (run_id, relative_path),
                FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE CASCADE
            );

            CREATE TABLE audit_events (
                sequence INTEGER PRIMARY KEY,
                run_id TEXT NOT NULL,
                business_date TEXT NOT NULL,
                incarnation_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                occurred_at TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                event_hash TEXT NOT NULL UNIQUE
            );

            CREATE TABLE next_inspection_policy_claims (
                published_policy_sha256 TEXT PRIMARY KEY CHECK (
                    length(published_policy_sha256) = 64
                    AND published_policy_sha256 = lower(published_policy_sha256)
                    AND published_policy_sha256 NOT GLOB '*[^0-9a-f]*'
                ),
                policy_version TEXT NOT NULL CHECK (length(trim(policy_version)) > 0),
                runtime_policy_sha256 TEXT NOT NULL CHECK (
                    length(runtime_policy_sha256) = 64
                    AND runtime_policy_sha256 = lower(runtime_policy_sha256)
                    AND runtime_policy_sha256 NOT GLOB '*[^0-9a-f]*'
                ),
                queued_at TEXT NOT NULL CHECK (length(trim(queued_at)) > 0),
                run_id TEXT NOT NULL CHECK (length(trim(run_id)) > 0),
                incarnation_id TEXT NOT NULL CHECK (length(trim(incarnation_id)) > 0)
            );

            CREATE INDEX artifacts_run_idx ON artifacts(run_id, artifact_id);
            CREATE INDEX audit_events_run_idx
                ON audit_events(run_id, incarnation_id, sequence);
            CREATE INDEX next_inspection_policy_claims_run_idx
                ON next_inspection_policy_claims(run_id, incarnation_id);
            """
        )
        connection.execute(
            "INSERT INTO metadata(key, value) VALUES('schema_version', ?)",
            (DATABASE_SCHEMA_VERSION,),
        )

    @classmethod
    def _migrate_v1_to_v2(cls, connection: sqlite3.Connection) -> None:
        """Add policy bindings without rewriting or deleting legacy rows.

        Legacy rows predate a durable policy binding and therefore retain ``NULL``
        in the added columns. All inserts through :meth:`insert_run` require a
        complete binding, so only preserved pre-v2 records may remain unbound.
        """

        connection.execute(
            """
            ALTER TABLE runs ADD COLUMN policy_version TEXT
            CHECK (policy_version IS NULL OR length(trim(policy_version)) > 0)
            """
        )
        connection.execute(
            """
            ALTER TABLE runs ADD COLUMN published_policy_sha256 TEXT
            CHECK (
                published_policy_sha256 IS NULL OR (
                    length(published_policy_sha256) = 64
                    AND published_policy_sha256 = lower(published_policy_sha256)
                    AND published_policy_sha256 NOT GLOB '*[^0-9a-f]*'
                )
            )
            """
        )
        connection.execute(
            """
            ALTER TABLE runs ADD COLUMN runtime_policy_sha256 TEXT
            CHECK (
                runtime_policy_sha256 IS NULL OR (
                    length(runtime_policy_sha256) = 64
                    AND runtime_policy_sha256 = lower(runtime_policy_sha256)
                    AND runtime_policy_sha256 NOT GLOB '*[^0-9a-f]*'
                )
            )
            """
        )
        connection.execute(
            """
            ALTER TABLE runs ADD COLUMN policy_activation_mode TEXT
            CHECK (
                policy_activation_mode IS NULL
                OR policy_activation_mode IN ('scheduled', 'next_inspection')
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE next_inspection_policy_claims (
                published_policy_sha256 TEXT PRIMARY KEY CHECK (
                    length(published_policy_sha256) = 64
                    AND published_policy_sha256 = lower(published_policy_sha256)
                    AND published_policy_sha256 NOT GLOB '*[^0-9a-f]*'
                ),
                policy_version TEXT NOT NULL CHECK (length(trim(policy_version)) > 0),
                runtime_policy_sha256 TEXT NOT NULL CHECK (
                    length(runtime_policy_sha256) = 64
                    AND runtime_policy_sha256 = lower(runtime_policy_sha256)
                    AND runtime_policy_sha256 NOT GLOB '*[^0-9a-f]*'
                ),
                queued_at TEXT NOT NULL CHECK (length(trim(queued_at)) > 0),
                run_id TEXT NOT NULL CHECK (length(trim(run_id)) > 0),
                incarnation_id TEXT NOT NULL CHECK (length(trim(incarnation_id)) > 0)
            )
            """
        )
        connection.execute(
            """
            CREATE INDEX next_inspection_policy_claims_run_idx
                ON next_inspection_policy_claims(run_id, incarnation_id)
            """
        )
        connection.execute(
            "UPDATE metadata SET value = ? WHERE key = 'schema_version'",
            (DATABASE_SCHEMA_VERSION,),
        )

    def _initialize(self) -> None:
        if self.database_path.exists():
            connection = self._connect_read_only()
            try:
                self._preflight_schema(connection)
            finally:
                connection.close()

        connection = self.connect()
        try:
            version = self._preflight_schema(connection)
            if version is None:
                connection.execute("PRAGMA journal_mode = WAL")
                self._create_schema_v2(connection)
            elif version in MIGRATABLE_DATABASE_SCHEMA_VERSIONS:
                # A deferred transaction establishes a stable schema snapshot
                # without writing before the supported version is rechecked.
                connection.execute("BEGIN")
                try:
                    locked_version = self._preflight_schema(connection)
                    if locked_version != version:
                        raise StateStoreError(
                            "state database schema changed during migration preflight"
                        )
                    self._migrate_v1_to_v2(connection)
                    connection.commit()
                except BaseException:
                    connection.rollback()
                    raise
                connection.execute("PRAGMA journal_mode = WAL")
            else:
                connection.execute("PRAGMA journal_mode = WAL")
            if self._preflight_schema(connection) != DATABASE_SCHEMA_VERSION:
                raise StateStoreError("state database schema initialization failed")
        finally:
            connection.close()

    @staticmethod
    def _run_from_row(row: sqlite3.Row | None) -> dict[str, Any] | None:
        if row is None:
            return None
        value = dict(row)
        try:
            value["platform_release"] = json.loads(value.pop("platform_release_json"))
        except (KeyError, json.JSONDecodeError) as exc:
            raise StateStoreError("stored platform release is corrupt") from exc
        value["active"] = value.pop("active_slot") == 1
        return value

    @staticmethod
    def _artifact_from_row(row: sqlite3.Row | None) -> dict[str, Any] | None:
        if row is None:
            return None
        value = dict(row)
        value["bytes"] = value.pop("byte_count")
        return value

    def get_run(
        self,
        run_id: str,
        *,
        connection: sqlite3.Connection | None = None,
    ) -> dict[str, Any] | None:
        if connection is not None:
            return self._run_from_row(
                connection.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
            )
        local = self.connect()
        try:
            return self._run_from_row(
                local.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
            )
        finally:
            local.close()

    def get_run_by_business_date(
        self,
        business_date: str,
        *,
        connection: sqlite3.Connection | None = None,
    ) -> dict[str, Any] | None:
        query = "SELECT * FROM runs WHERE business_date = ?"
        if connection is not None:
            return self._run_from_row(connection.execute(query, (business_date,)).fetchone())
        local = self.connect()
        try:
            return self._run_from_row(local.execute(query, (business_date,)).fetchone())
        finally:
            local.close()

    def get_active_run(
        self,
        *,
        connection: sqlite3.Connection | None = None,
    ) -> dict[str, Any] | None:
        query = "SELECT * FROM runs WHERE active_slot = 1"
        if connection is not None:
            return self._run_from_row(connection.execute(query).fetchone())
        local = self.connect()
        try:
            return self._run_from_row(local.execute(query).fetchone())
        finally:
            local.close()

    def list_runs(self) -> list[dict[str, Any]]:
        connection = self.connect()
        try:
            return [
                self._run_from_row(row)  # type: ignore[arg-type]
                for row in connection.execute(
                    "SELECT * FROM runs ORDER BY business_date DESC"
                ).fetchall()
            ]
        finally:
            connection.close()

    @staticmethod
    def _required_text(value: Any, *, field: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise StateStoreError(f"{field} must be a non-empty string")
        return value

    @classmethod
    def _required_sha256(cls, value: Any, *, field: str) -> str:
        digest = cls._required_text(value, field=field)
        if (
            len(digest) != 64
            or digest != digest.lower()
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise StateStoreError(f"{field} must be a lowercase SHA-256 digest")
        return digest

    def insert_run(self, connection: sqlite3.Connection, value: Mapping[str, Any]) -> None:
        status = str(value["status"])
        if status not in RUN_STATUSES:
            raise StateStoreError(f"invalid run status: {status}")
        policy_version = self._required_text(
            value.get("policy_version"), field="policy_version"
        )
        published_policy_sha256 = self._required_sha256(
            value.get("published_policy_sha256"), field="published_policy_sha256"
        )
        runtime_policy_sha256 = self._required_sha256(
            value.get("runtime_policy_sha256"), field="runtime_policy_sha256"
        )
        policy_activation_mode = self._required_text(
            value.get("policy_activation_mode"), field="policy_activation_mode"
        )
        if policy_activation_mode not in POLICY_ACTIVATION_MODES:
            raise StateStoreError(
                f"invalid policy activation mode: {policy_activation_mode}"
            )
        connection.execute(
            """
            INSERT INTO runs(
                run_id, business_date, incarnation_id, release_id,
                platform_release_json, platform_release_sha256, workspace_version,
                policy_version, published_policy_sha256, runtime_policy_sha256,
                policy_activation_mode, status, active_slot, workspace_path,
                branch_name, base_commit, checkpoint_commit, archive_path,
                created_at, seal_started_at, sealed_at, error_code, error_message
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                value["run_id"],
                value["business_date"],
                value["incarnation_id"],
                value["release_id"],
                canonical_json(value["platform_release"]),
                value["platform_release_sha256"],
                value["workspace_version"],
                policy_version,
                published_policy_sha256,
                runtime_policy_sha256,
                policy_activation_mode,
                status,
                1 if status in ACTIVE_STATUSES else None,
                value["workspace_path"],
                value["branch_name"],
                value.get("base_commit"),
                value.get("checkpoint_commit"),
                value.get("archive_path"),
                value["created_at"],
                value.get("seal_started_at"),
                value.get("sealed_at"),
                value.get("error_code"),
                value.get("error_message"),
            ),
        )

    @staticmethod
    def _policy_claim_from_row(row: sqlite3.Row | None) -> dict[str, Any] | None:
        return None if row is None else dict(row)

    def get_next_inspection_policy_claim(
        self,
        published_policy_sha256: str,
        *,
        connection: sqlite3.Connection | None = None,
    ) -> dict[str, Any] | None:
        digest = self._required_sha256(
            published_policy_sha256, field="published_policy_sha256"
        )
        query = (
            "SELECT * FROM next_inspection_policy_claims "
            "WHERE published_policy_sha256 = ?"
        )
        if connection is not None:
            return self._policy_claim_from_row(connection.execute(query, (digest,)).fetchone())
        local = self.connect()
        try:
            return self._policy_claim_from_row(local.execute(query, (digest,)).fetchone())
        finally:
            local.close()

    def list_next_inspection_policy_claims(
        self,
        *,
        connection: sqlite3.Connection | None = None,
    ) -> list[dict[str, Any]]:
        query = (
            "SELECT * FROM next_inspection_policy_claims "
            "ORDER BY queued_at, published_policy_sha256"
        )
        if connection is not None:
            return [
                self._policy_claim_from_row(row)  # type: ignore[misc]
                for row in connection.execute(query).fetchall()
            ]
        local = self.connect()
        try:
            return [
                self._policy_claim_from_row(row)  # type: ignore[misc]
                for row in local.execute(query).fetchall()
            ]
        finally:
            local.close()

    def insert_next_inspection_policy_claim(
        self,
        connection: sqlite3.Connection,
        value: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Persist a one-time policy claim inside the caller's run transaction."""

        if not connection.in_transaction:
            raise StateStoreError(
                "next-inspection policy claim requires an active transaction"
            )
        claim = {
            "published_policy_sha256": self._required_sha256(
                value.get("published_policy_sha256"),
                field="published_policy_sha256",
            ),
            "policy_version": self._required_text(
                value.get("policy_version"), field="policy_version"
            ),
            "runtime_policy_sha256": self._required_sha256(
                value.get("runtime_policy_sha256"), field="runtime_policy_sha256"
            ),
            "queued_at": self._required_text(value.get("queued_at"), field="queued_at"),
            "run_id": self._required_text(value.get("run_id"), field="run_id"),
            "incarnation_id": self._required_text(
                value.get("incarnation_id"), field="incarnation_id"
            ),
        }
        run = self.get_run(claim["run_id"], connection=connection)
        if run is None:
            raise StateStoreError(
                "next-inspection policy claim requires a durable run in the same transaction"
            )
        expected = {
            "incarnation_id": run["incarnation_id"],
            "policy_version": run["policy_version"],
            "published_policy_sha256": run["published_policy_sha256"],
            "runtime_policy_sha256": run["runtime_policy_sha256"],
        }
        for field, expected_value in expected.items():
            if claim[field] != expected_value:
                raise StateStoreError(
                    f"next-inspection policy claim does not match run {field}"
                )
        if run["policy_activation_mode"] != "next_inspection":
            raise StateStoreError(
                "next-inspection policy claim requires a next_inspection run binding"
            )
        try:
            connection.execute(
                """
                INSERT INTO next_inspection_policy_claims(
                    published_policy_sha256, policy_version, runtime_policy_sha256,
                    queued_at, run_id, incarnation_id
                ) VALUES(?,?,?,?,?,?)
                """,
                (
                    claim["published_policy_sha256"],
                    claim["policy_version"],
                    claim["runtime_policy_sha256"],
                    claim["queued_at"],
                    claim["run_id"],
                    claim["incarnation_id"],
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise StateStoreError(
                "next-inspection policy version is already claimed"
            ) from exc
        return claim

    def update_run(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        **changes: Any,
    ) -> None:
        allowed = {
            "status",
            "base_commit",
            "checkpoint_commit",
            "archive_path",
            "seal_started_at",
            "sealed_at",
            "error_code",
            "error_message",
        }
        if not changes or not set(changes).issubset(allowed):
            raise StateStoreError("invalid run update fields")
        if "status" in changes:
            status = str(changes["status"])
            if status not in RUN_STATUSES:
                raise StateStoreError(f"invalid run status: {status}")
            changes["active_slot"] = 1 if status in ACTIVE_STATUSES else None
            allowed = allowed | {"active_slot"}
        assignments = ", ".join(f"{key} = ?" for key in changes)
        values = [changes[key] for key in changes]
        cursor = connection.execute(
            f"UPDATE runs SET {assignments} WHERE run_id = ?",  # noqa: S608 - keys are allowlisted
            (*values, run_id),
        )
        if cursor.rowcount != 1:
            raise StateStoreError(f"run does not exist: {run_id}")

    def delete_run(self, connection: sqlite3.Connection, run_id: str) -> None:
        cursor = connection.execute("DELETE FROM runs WHERE run_id = ?", (run_id,))
        if cursor.rowcount != 1:
            raise StateStoreError(f"run does not exist: {run_id}")

    def get_artifact(
        self,
        run_id: str,
        artifact_id: str,
        *,
        connection: sqlite3.Connection | None = None,
    ) -> dict[str, Any] | None:
        query = "SELECT * FROM artifacts WHERE run_id = ? AND artifact_id = ?"
        if connection is not None:
            return self._artifact_from_row(
                connection.execute(query, (run_id, artifact_id)).fetchone()
            )
        local = self.connect()
        try:
            return self._artifact_from_row(local.execute(query, (run_id, artifact_id)).fetchone())
        finally:
            local.close()

    def list_artifacts(
        self,
        run_id: str,
        *,
        connection: sqlite3.Connection | None = None,
    ) -> list[dict[str, Any]]:
        query = "SELECT * FROM artifacts WHERE run_id = ? ORDER BY artifact_id"
        if connection is not None:
            rows = connection.execute(query, (run_id,)).fetchall()
            return [self._artifact_from_row(row) for row in rows]  # type: ignore[list-item]
        local = self.connect()
        try:
            rows = local.execute(query, (run_id,)).fetchall()
            return [self._artifact_from_row(row) for row in rows]  # type: ignore[list-item]
        finally:
            local.close()

    def put_artifact(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        artifact_id: str,
        relative_path: str,
        sha256: str,
        byte_count: int,
        media_type: str,
        writer: str,
        created_at: str,
        replace: bool = False,
    ) -> None:
        if replace:
            connection.execute(
                """
                INSERT INTO artifacts(
                    run_id, artifact_id, relative_path, sha256, byte_count,
                    media_type, writer, created_at
                ) VALUES(?,?,?,?,?,?,?,?)
                ON CONFLICT(run_id, artifact_id) DO UPDATE SET
                    relative_path=excluded.relative_path,
                    sha256=excluded.sha256,
                    byte_count=excluded.byte_count,
                    media_type=excluded.media_type,
                    writer=excluded.writer,
                    created_at=excluded.created_at
                """,
                (
                    run_id,
                    artifact_id,
                    relative_path,
                    sha256,
                    byte_count,
                    media_type,
                    writer,
                    created_at,
                ),
            )
            return
        connection.execute(
            """
            INSERT INTO artifacts(
                run_id, artifact_id, relative_path, sha256, byte_count,
                media_type, writer, created_at
            ) VALUES(?,?,?,?,?,?,?,?)
            """,
            (
                run_id,
                artifact_id,
                relative_path,
                sha256,
                byte_count,
                media_type,
                writer,
                created_at,
            ),
        )

    def append_event(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        business_date: str,
        incarnation_id: str,
        event_type: str,
        occurred_at: str,
        payload: Mapping[str, Any],
    ) -> dict[str, Any]:
        previous = connection.execute(
            "SELECT sequence, event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        sequence = 1 if previous is None else int(previous["sequence"]) + 1
        previous_hash = "0" * 64 if previous is None else str(previous["event_hash"])
        body = {
            "sequence": sequence,
            "run_id": run_id,
            "business_date": business_date,
            "incarnation_id": incarnation_id,
            "event_type": event_type,
            "occurred_at": occurred_at,
            "payload": dict(payload),
            "previous_hash": previous_hash,
        }
        event_hash = hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()
        connection.execute(
            """
            INSERT INTO audit_events(
                sequence, run_id, business_date, incarnation_id, event_type,
                occurred_at, payload_json, previous_hash, event_hash
            ) VALUES(?,?,?,?,?,?,?,?,?)
            """,
            (
                sequence,
                run_id,
                business_date,
                incarnation_id,
                event_type,
                occurred_at,
                canonical_json(dict(payload)),
                previous_hash,
                event_hash,
            ),
        )
        return {**body, "event_hash": event_hash}

    def list_events(self, *, run_id: str | None = None) -> list[dict[str, Any]]:
        connection = self.connect()
        try:
            if run_id is None:
                rows = connection.execute(
                    "SELECT * FROM audit_events ORDER BY sequence"
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT * FROM audit_events WHERE run_id = ? ORDER BY sequence",
                    (run_id,),
                ).fetchall()
            result = []
            for row in rows:
                value = dict(row)
                value["payload"] = json.loads(value.pop("payload_json"))
                result.append(value)
            return result
        finally:
            connection.close()

    def verify_integrity(self) -> dict[str, Any]:
        connection = self.connect()
        try:
            integrity = str(connection.execute("PRAGMA integrity_check").fetchone()[0])
            foreign_keys = connection.execute("PRAGMA foreign_key_check").fetchall()
            rows = connection.execute("SELECT * FROM audit_events ORDER BY sequence").fetchall()
            previous_hash = "0" * 64
            expected_sequence = 1
            for row in rows:
                if int(row["sequence"]) != expected_sequence:
                    raise StateStoreError("audit event sequence is discontinuous")
                if row["previous_hash"] != previous_hash:
                    raise StateStoreError("audit event previous hash does not match")
                body = {
                    "sequence": int(row["sequence"]),
                    "run_id": row["run_id"],
                    "business_date": row["business_date"],
                    "incarnation_id": row["incarnation_id"],
                    "event_type": row["event_type"],
                    "occurred_at": row["occurred_at"],
                    "payload": json.loads(row["payload_json"]),
                    "previous_hash": row["previous_hash"],
                }
                calculated = hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()
                if calculated != row["event_hash"]:
                    raise StateStoreError("audit event hash does not match")
                previous_hash = calculated
                expected_sequence += 1
            return {
                "ok": integrity == "ok" and not foreign_keys,
                "sqlite_integrity": integrity,
                "foreign_key_violations": len(foreign_keys),
                "event_count": len(rows),
                "event_chain_head": previous_hash,
            }
        finally:
            connection.close()
