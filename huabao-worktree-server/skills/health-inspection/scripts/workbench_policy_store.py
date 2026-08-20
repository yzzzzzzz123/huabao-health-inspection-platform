"""Server-owned mutable health-policy storage for the business workbench.

The workbench policy database is deliberately separate from workspace state.
It stores one CAS-protected draft, immutable canonical JSON versions and a
tamper-evident version-selection ledger.  Runtime code never reads the legacy
repository: a clean installation receives only an unpublished editable draft;
published history can enter only through operator publication or the explicit
one-time ``import_state`` migration boundary.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
import re
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping, Sequence


DATABASE_SCHEMA_VERSION = "2"
MIGRATABLE_DATABASE_SCHEMA_VERSIONS = frozenset({"1"})
POLICY_SCHEMA_VERSION = "1.0"
DRAFT_SCHEMA_VERSION = "1.0"
SELECTION_SCHEMA_VERSION = "1.0"
DESCRIPTION_MAX_LENGTH = 500
NOTE_MAX_LENGTH = 500
METRIC_COUNT = 37
DIMENSIONS = ("traffic", "conversion", "product")
VERSION_RE = re.compile(r"^v1\.(0|[1-9][0-9]*)$")
METRIC_ID_RE = re.compile(r"^HI-(?:00[1-9]|0[1-2][0-9]|03[0-7])$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
TIME_RE = re.compile(r"^(?:[01][0-9]|2[0-3]):[0-5][0-9]$")
ACTIVATION_MODES = frozenset({"scheduled", "next_inspection"})
SCORING_FIELDS = frozenset(
    {
        "dimension_weight_percentages",
        "metric_weight_percentages",
        "band_thresholds",
        "dimension_band_thresholds",
    }
)
FIXED_RULE_FIELDS = (
    "position",
    "dimension",
    "dimension_label",
    "name",
    "frequency",
    "primary_output",
    "format",
    "precision",
    "favorable",
    "source",
    "baseline",
    "rule_type",
    "threshold_fields",
    "legacy_evaluation_status",
    "legacy_alert_rule",
)
USAGE_PROJECTION_FIELDS = (
    "run_id",
    "business_date",
    "status",
    "storage_type",
    "policy_sha256",
)
SELECTION_EVENT_TYPES = frozenset(
    {"version_selected", "automatic_restored", "selection_cleared"}
)
SELECTION_REASONS = {
    "version_selected": "operator_version_switch",
    "automatic_restored": "policy_published",
    "selection_cleared": "selected_version_deleted",
}
SHANGHAI = timezone(timedelta(hours=8), name="Asia/Shanghai")


class WorkbenchPolicyStoreError(RuntimeError):
    """Base error for durable workbench-policy operations."""

    status = 500
    code = "workbench_policy_store_error"


class PolicyValidationError(WorkbenchPolicyStoreError):
    status = 400
    code = "policy_validation_error"


class PolicyConflictError(WorkbenchPolicyStoreError):
    status = 409
    code = "policy_draft_conflict"


class PolicyImmutableError(WorkbenchPolicyStoreError):
    status = 409
    code = "immutable_policy_error"


class PolicyNotFoundError(WorkbenchPolicyStoreError):
    status = 404
    code = "policy_version_not_found"


class PolicyInUseError(WorkbenchPolicyStoreError):
    status = 409
    code = "policy_version_in_use"


class PolicyNotConfiguredError(WorkbenchPolicyStoreError):
    status = 409
    code = "policy_version_required"


def canonical_json(value: Any) -> str:
    """Return the only byte representation used for hashes and persistence."""

    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _copy(value: Any) -> Any:
    return copy.deepcopy(value)


def _is_redirect(path: Path) -> bool:
    if path.is_symlink():
        return True
    is_junction = getattr(path, "is_junction", None)
    return bool(is_junction is not None and is_junction())


def _version_ordinal(version: Any) -> int:
    text = str(version or "")
    match = VERSION_RE.fullmatch(text)
    if match is None:
        raise PolicyValidationError(f"invalid policy version: {text}")
    return int(match.group(1))


def _strict_revision(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise PolicyValidationError("draft_revision must be a positive integer")
    return value


def _strict_text(
    value: Any,
    *,
    field: str,
    maximum: int,
    allow_empty: bool,
) -> str:
    if not isinstance(value, str):
        raise PolicyValidationError(f"{field} must be text")
    result = value.strip()
    if not allow_empty and not result:
        raise PolicyValidationError(f"{field} cannot be empty")
    if len(result) > maximum:
        raise PolicyValidationError(f"{field} cannot exceed {maximum} characters")
    if any(ord(character) < 32 and character not in {"\n", "\t"} for character in result):
        raise PolicyValidationError(f"{field} cannot contain control characters")
    return result


def _inspection_schedule(value: Any) -> dict[str, str]:
    if isinstance(value, str):
        value = {"time": value}
    if not isinstance(value, Mapping) or set(value) != {"time"}:
        raise PolicyValidationError("inspection_schedule must contain only time")
    inspection_time = value.get("time")
    if not isinstance(inspection_time, str) or TIME_RE.fullmatch(inspection_time) is None:
        raise PolicyValidationError("inspection time must be HH:mm from 00:00 to 23:59")
    return {"time": inspection_time}


def _timestamp(value: Any, *, field: str, require_shanghai: bool = False) -> str:
    if not isinstance(value, str) or not value.strip():
        raise PolicyValidationError(f"{field} must be a timezone-aware timestamp")
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise PolicyValidationError(f"{field} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise PolicyValidationError(f"{field} must include a timezone")
    if require_shanghai and parsed.utcoffset() != timedelta(hours=8):
        raise PolicyValidationError(f"{field} must use the Asia/Shanghai offset")
    return value.strip()


def _threshold_fields(rule_type: Any) -> tuple[str, str]:
    if rule_type == "lower_bound":
        return ("yellow_min", "green_min")
    if rule_type == "upper_bound":
        return ("green_max", "yellow_max")
    raise PolicyValidationError(f"unsupported fixed rule type: {rule_type}")


def _number(value: Any, *, field: str, precision: int) -> int | float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise PolicyValidationError(f"{field} must be a finite number")
    numeric = float(value)
    if not math.isfinite(numeric):
        raise PolicyValidationError(f"{field} must be a finite number")
    try:
        decimal = Decimal(str(value))
        quantum = Decimal(1).scaleb(-precision)
        if decimal != decimal.quantize(quantum):
            raise PolicyValidationError(f"{field} exceeds precision {precision}")
    except InvalidOperation as exc:
        raise PolicyValidationError(f"{field} must be a finite number") from exc
    return int(decimal) if precision == 0 else float(decimal)


def _integer_percentage(value: Any, *, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 100:
        raise PolicyValidationError(f"{field} must be an integer from 1 to 100")
    return value


def _health_bands(value: Any, *, field: str) -> dict[str, int]:
    if not isinstance(value, Mapping) or set(value) != {"yellow_min", "green_min"}:
        raise PolicyValidationError(f"{field} must contain yellow_min and green_min")
    yellow = _integer_percentage(value["yellow_min"], field=f"{field}.yellow_min")
    green = _integer_percentage(value["green_min"], field=f"{field}.green_min")
    if yellow >= green:
        raise PolicyValidationError(f"{field}.yellow_min must be lower than green_min")
    return {"yellow_min": yellow, "green_min": green}


class WorkbenchPolicyStore:
    """Persist the complete editable workbench policy in server-owned SQLite."""

    def __init__(
        self,
        project_root: Path | str,
        *,
        database_path: Path | str | None = None,
    ) -> None:
        self.project_root = Path(project_root).expanduser().resolve()
        state_root = self.project_root / ".huabao"
        if _is_redirect(state_root) or (state_root.exists() and not state_root.is_dir()):
            raise WorkbenchPolicyStoreError(".huabao must be a regular server-owned directory")
        state_root.mkdir(parents=True, exist_ok=True)
        if state_root.resolve().parent != self.project_root:
            raise WorkbenchPolicyStoreError("workbench policy state escaped the server root")
        selected_input = (
            Path(database_path).expanduser()
            if database_path is not None
            else state_root / "workbench-policy.sqlite3"
        )
        if _is_redirect(selected_input):
            raise WorkbenchPolicyStoreError("workbench policy database must not be a link")
        selected_path = selected_input.resolve()
        if selected_path.parent != state_root.resolve():
            raise WorkbenchPolicyStoreError("workbench policy database must stay in .huabao")
        if selected_path.exists() and (_is_redirect(selected_path) or not selected_path.is_file()):
            raise WorkbenchPolicyStoreError("workbench policy database is not a regular file")
        self.database_path = selected_path
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
            f"{self.database_path.as_uri()}?mode=ro",
            timeout=30.0,
            isolation_level=None,
            uri=True,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA trusted_schema = OFF")
        connection.execute("PRAGMA busy_timeout = 30000")
        return connection

    @staticmethod
    def _preflight_schema(connection: sqlite3.Connection) -> str | None:
        """Validate an existing schema without mutating database state.

        ``None`` means the database is genuinely empty and may be initialized.
        A non-empty database must already carry this store's exact schema marker;
        otherwise opening it fails before WAL mode or any DDL is attempted.
        """

        try:
            table_rows = connection.execute(
                """
                SELECT name
                FROM sqlite_master
                WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
                ORDER BY name
                """
            ).fetchall()
            tables = {str(row["name"]) for row in table_rows}
            if not tables:
                return None
            if "metadata" not in tables:
                raise WorkbenchPolicyStoreError(
                    "unsupported workbench policy database without schema metadata"
                )
            row = connection.execute(
                "SELECT value FROM metadata WHERE key = 'schema_version'"
            ).fetchone()
        except sqlite3.DatabaseError as exc:
            raise WorkbenchPolicyStoreError(
                "workbench policy database schema cannot be verified"
            ) from exc
        if row is None:
            raise WorkbenchPolicyStoreError(
                "unsupported workbench policy database without a schema version"
            )
        version = str(row["value"])
        if (
            version != DATABASE_SCHEMA_VERSION
            and version not in MIGRATABLE_DATABASE_SCHEMA_VERSIONS
        ):
            raise WorkbenchPolicyStoreError(
                f"unsupported workbench policy schema: {version}"
            )
        core_tables = {
            "metadata",
            "policy_state",
            "policy_versions",
            "selection_events",
        }
        allowed_tables = core_tables | {"policy_version_tombstones"}
        if not core_tables.issubset(tables) or not tables.issubset(allowed_tables):
            raise WorkbenchPolicyStoreError(
                "workbench policy database tables do not match the declared schema"
            )
        if (
            version == DATABASE_SCHEMA_VERSION
            and "policy_version_tombstones" not in tables
        ):
            raise WorkbenchPolicyStoreError(
                "workbench policy database is missing the deletion audit table"
            )
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

    def _initialize(self) -> None:
        if self.database_path.exists():
            connection = self._connect_read_only()
            try:
                self._preflight_schema(connection)
            finally:
                connection.close()
        connection = self.connect()
        try:
            # Repeat the non-mutating check on the writable handle to close the
            # replacement race between the read-only probe and initialization.
            self._preflight_schema(connection)
            connection.execute("PRAGMA journal_mode = WAL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS policy_state (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    draft_revision INTEGER NOT NULL CHECK (draft_revision >= 1),
                    draft_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS policy_versions (
                    version TEXT PRIMARY KEY,
                    ordinal INTEGER NOT NULL UNIQUE CHECK (ordinal >= 0),
                    sha256 TEXT NOT NULL UNIQUE,
                    document_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    effective_at TEXT NOT NULL,
                    activation_mode TEXT NOT NULL CHECK (
                        activation_mode IN ('scheduled', 'next_inspection')
                    ),
                    note TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS policy_version_tombstones (
                    sha256 TEXT PRIMARY KEY,
                    version TEXT NOT NULL,
                    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
                    document_json TEXT NOT NULL,
                    deleted_at TEXT NOT NULL,
                    deletion_revision INTEGER NOT NULL UNIQUE CHECK (deletion_revision >= 1),
                    record_hash TEXT NOT NULL UNIQUE,
                    record_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS selection_events (
                    revision INTEGER PRIMARY KEY CHECK (revision >= 1),
                    record_hash TEXT NOT NULL UNIQUE,
                    record_json TEXT NOT NULL
                );
                """
            )
            row = connection.execute(
                "SELECT value FROM metadata WHERE key = 'schema_version'"
            ).fetchone()
            if row is None:
                connection.execute(
                    "INSERT INTO metadata(key, value) VALUES('schema_version', ?)",
                    (DATABASE_SCHEMA_VERSION,),
                )
            elif row["value"] in MIGRATABLE_DATABASE_SCHEMA_VERSIONS:
                connection.execute(
                    "UPDATE metadata SET value = ? WHERE key = 'schema_version'",
                    (DATABASE_SCHEMA_VERSION,),
                )
        finally:
            connection.close()

    @staticmethod
    def _decode_mapping(raw: str, *, field: str) -> dict[str, Any]:
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise PolicyImmutableError(f"stored {field} is invalid JSON") from exc
        if not isinstance(value, dict):
            raise PolicyImmutableError(f"stored {field} must be an object")
        return value

    def _catalog(self, connection: sqlite3.Connection) -> list[dict[str, Any]]:
        row = connection.execute(
            "SELECT value FROM metadata WHERE key = 'metric_catalog'"
        ).fetchone()
        if row is None:
            raise WorkbenchPolicyStoreError("workbench policy metric catalog is not initialized")
        try:
            value = json.loads(row["value"])
        except json.JSONDecodeError as exc:
            raise PolicyImmutableError("stored metric catalog is invalid JSON") from exc
        if not isinstance(value, list):
            raise PolicyImmutableError("stored metric catalog must be a list")
        return value

    @staticmethod
    def _catalog_from_rules(rules: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
        return [
            {"metric_id": str(rule["metric_id"])}
            | {field: _copy(rule.get(field)) for field in FIXED_RULE_FIELDS}
            for rule in sorted(rules, key=lambda item: int(item["position"]))
        ]

    @staticmethod
    def _validate_catalog_shape(rules: Any) -> list[dict[str, Any]]:
        if not isinstance(rules, list) or len(rules) != METRIC_COUNT:
            raise PolicyValidationError("policy must contain exactly 37 metric rules")
        expected_ids = {f"HI-{number:03d}" for number in range(1, METRIC_COUNT + 1)}
        positions: set[int] = set()
        identifiers: set[str] = set()
        normalized: list[dict[str, Any]] = []
        for raw in rules:
            if not isinstance(raw, Mapping):
                raise PolicyValidationError("each policy rule must be an object")
            rule = _copy(dict(raw))
            metric_id = str(rule.get("metric_id") or "")
            if METRIC_ID_RE.fullmatch(metric_id) is None or metric_id in identifiers:
                raise PolicyValidationError(f"invalid or duplicate metric_id: {metric_id}")
            position = rule.get("position")
            if isinstance(position, bool) or not isinstance(position, int) or position in positions:
                raise PolicyValidationError(f"invalid or duplicate position for {metric_id}")
            dimension = rule.get("dimension")
            if dimension not in DIMENSIONS:
                raise PolicyValidationError(f"invalid dimension for {metric_id}")
            precision = rule.get("precision")
            if isinstance(precision, bool) or not isinstance(precision, int) or not 0 <= precision <= 9:
                raise PolicyValidationError(f"invalid precision for {metric_id}")
            expected_fields = _threshold_fields(rule.get("rule_type"))
            if tuple(rule.get("threshold_fields") or ()) != expected_fields:
                raise PolicyValidationError(f"fixed threshold fields are invalid for {metric_id}")
            _strict_text(
                rule.get("description"),
                field=f"{metric_id}.description",
                maximum=DESCRIPTION_MAX_LENGTH,
                allow_empty=False,
            )
            identifiers.add(metric_id)
            positions.add(position)
            normalized.append(rule)
        if identifiers != expected_ids or positions != set(range(1, METRIC_COUNT + 1)):
            raise PolicyValidationError("the fixed 37-metric identity/order contract is incomplete")
        return sorted(normalized, key=lambda item: int(item["position"]))

    def _validate_thresholds(
        self,
        rule: Mapping[str, Any],
        thresholds: Any,
        *,
        allow_missing: bool,
    ) -> dict[str, int | float] | None:
        metric_id = str(rule["metric_id"])
        if thresholds is None and allow_missing:
            return None
        if not isinstance(thresholds, Mapping):
            raise PolicyValidationError(f"{metric_id}.thresholds must be an object")
        fields = _threshold_fields(rule["rule_type"])
        if set(thresholds) != set(fields):
            raise PolicyValidationError(
                f"{metric_id}.thresholds may contain only {', '.join(fields)}"
            )
        precision = int(rule["precision"])
        normalized = {
            field: _number(
                thresholds[field],
                field=f"{metric_id}.{field}",
                precision=precision,
            )
            for field in fields
        }
        if not normalized[fields[0]] < normalized[fields[1]]:
            raise PolicyValidationError(
                f"{metric_id}.{fields[0]} must be lower than {fields[1]}"
            )
        return normalized

    def _validate_rules(
        self,
        rules: Any,
        *,
        catalog: Sequence[Mapping[str, Any]] | None,
        allow_missing_thresholds: bool,
    ) -> list[dict[str, Any]]:
        normalized = self._validate_catalog_shape(rules)
        catalog_by_id = (
            {str(item["metric_id"]): item for item in catalog} if catalog is not None else None
        )
        for rule in normalized:
            metric_id = str(rule["metric_id"])
            if catalog_by_id is not None:
                expected = catalog_by_id.get(metric_id)
                if expected is None:
                    raise PolicyValidationError(f"unknown fixed metric: {metric_id}")
                for field in FIXED_RULE_FIELDS:
                    if rule.get(field) != expected.get(field):
                        raise PolicyValidationError(f"fixed policy field changed: {metric_id}.{field}")
            rule["description"] = _strict_text(
                rule.get("description"),
                field=f"{metric_id}.description",
                maximum=DESCRIPTION_MAX_LENGTH,
                allow_empty=False,
            )
            rule["thresholds"] = self._validate_thresholds(
                rule,
                rule.get("thresholds"),
                allow_missing=allow_missing_thresholds,
            )
        return normalized

    def _validate_scoring(
        self,
        value: Any,
        *,
        catalog: Sequence[Mapping[str, Any]],
    ) -> dict[str, Any]:
        if not isinstance(value, Mapping) or set(value) != SCORING_FIELDS:
            raise PolicyValidationError("scoring_config must contain the complete fixed contract")
        dimension_weights = value["dimension_weight_percentages"]
        if not isinstance(dimension_weights, Mapping) or set(dimension_weights) != set(DIMENSIONS):
            raise PolicyValidationError("dimension weights must cover traffic, conversion and product")
        normalized_dimension_weights = {
            dimension: _integer_percentage(
                dimension_weights[dimension], field=f"{dimension} dimension weight"
            )
            for dimension in DIMENSIONS
        }
        if sum(normalized_dimension_weights.values()) != 100:
            raise PolicyValidationError("dimension weights must sum to exactly 100")
        metric_weights = value["metric_weight_percentages"]
        metric_ids = [str(item["metric_id"]) for item in catalog]
        if not isinstance(metric_weights, Mapping) or set(metric_weights) != set(metric_ids):
            raise PolicyValidationError("metric weights must cover the fixed 37 metrics exactly")
        normalized_metric_weights = {
            metric_id: _integer_percentage(
                metric_weights[metric_id], field=f"{metric_id} metric weight"
            )
            for metric_id in metric_ids
        }
        for dimension in DIMENSIONS:
            dimension_ids = [
                str(item["metric_id"]) for item in catalog if item["dimension"] == dimension
            ]
            if sum(normalized_metric_weights[item] for item in dimension_ids) != 100:
                raise PolicyValidationError(
                    f"{dimension} metric weights must sum to exactly 100"
                )
        raw_dimension_bands = value["dimension_band_thresholds"]
        if not isinstance(raw_dimension_bands, Mapping) or set(raw_dimension_bands) != set(DIMENSIONS):
            raise PolicyValidationError("dimension bands must cover all three dimensions")
        return {
            "dimension_weight_percentages": normalized_dimension_weights,
            "metric_weight_percentages": normalized_metric_weights,
            "band_thresholds": _health_bands(value["band_thresholds"], field="overall bands"),
            "dimension_band_thresholds": {
                dimension: _health_bands(
                    raw_dimension_bands[dimension], field=f"{dimension} bands"
                )
                for dimension in DIMENSIONS
            },
        }

    @staticmethod
    def _document_hash(document: Mapping[str, Any]) -> str:
        payload = dict(document)
        payload.pop("sha256", None)
        return sha256_json(payload)

    def _validate_version_document(
        self,
        value: Any,
        *,
        catalog: Sequence[Mapping[str, Any]],
        migration_compatibility: bool,
    ) -> dict[str, Any]:
        if not isinstance(value, Mapping):
            raise PolicyValidationError("policy version must be an object")
        document = _copy(dict(value))
        version = str(document.get("version") or "")
        ordinal = _version_ordinal(version)
        if document.get("schema_version") != POLICY_SCHEMA_VERSION:
            raise PolicyValidationError(f"unsupported policy schema for {version}")
        if document.get("ordinal") != ordinal:
            raise PolicyValidationError(f"policy ordinal mismatch for {version}")
        expected_sha = document.get("sha256")
        if not isinstance(expected_sha, str) or SHA256_RE.fullmatch(expected_sha) is None:
            raise PolicyImmutableError(f"invalid policy SHA-256 for {version}")
        if self._document_hash(document) != expected_sha:
            raise PolicyImmutableError(f"canonical policy SHA-256 mismatch for {version}")
        _timestamp(document.get("created_at"), field="created_at")
        _timestamp(document.get("effective_at"), field="effective_at")
        _strict_text(
            document.get("note", ""), field="note", maximum=NOTE_MAX_LENGTH, allow_empty=True
        )
        mode = str(document.get("mode") or "")
        allow_missing = migration_compatibility and mode == "legacy"
        # Validate without replacing values, preserving the exact imported hash.
        self._validate_rules(
            document.get("rules"), catalog=catalog, allow_missing_thresholds=allow_missing
        )
        scoring = document.get("scoring_config")
        if scoring is None:
            if not (migration_compatibility and mode == "legacy"):
                raise PolicyValidationError(f"{version} is missing scoring_config")
        else:
            self._validate_scoring(scoring, catalog=catalog)
        schedule = document.get("inspection_schedule")
        if schedule is None:
            if not migration_compatibility:
                raise PolicyValidationError(f"{version} is missing inspection_schedule")
        else:
            _inspection_schedule(schedule)
        activation_mode = str(document.get("activation_mode") or "scheduled")
        if activation_mode not in ACTIVATION_MODES:
            raise PolicyValidationError(f"invalid activation_mode for {version}")
        previous = document.get("previous_sha256")
        if ordinal == 0:
            if previous not in {None, ""}:
                raise PolicyValidationError("v1.0 cannot bind a previous SHA-256")
        elif not isinstance(previous, str) or SHA256_RE.fullmatch(previous) is None:
            raise PolicyValidationError(f"invalid previous_sha256 for {version}")
        return document

    def _load_version_row(
        self,
        connection: sqlite3.Connection,
        version: str,
    ) -> dict[str, Any]:
        _version_ordinal(version)
        row = connection.execute(
            "SELECT * FROM policy_versions WHERE version = ?", (version,)
        ).fetchone()
        if row is None:
            raise PolicyNotFoundError(f"policy version does not exist: {version}")
        document = self._decode_mapping(row["document_json"], field=f"version {version}")
        actual_hash = self._document_hash(document)
        if (
            document.get("version") != row["version"]
            or document.get("ordinal") != row["ordinal"]
            or document.get("sha256") != row["sha256"]
            or actual_hash != row["sha256"]
            or document.get("created_at") != row["created_at"]
            or document.get("effective_at") != row["effective_at"]
            or (document.get("activation_mode") or "scheduled") != row["activation_mode"]
            or (document.get("note") or "") != row["note"]
        ):
            raise PolicyImmutableError(f"stored immutable policy changed: {version}")
        return document

    @staticmethod
    def _tombstone_record_hash(record: Mapping[str, Any]) -> str:
        payload = dict(record)
        payload.pop("record_hash", None)
        return sha256_json(payload)

    def _load_tombstones(
        self,
        connection: sqlite3.Connection,
        *,
        catalog: Sequence[Mapping[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        rows = connection.execute(
            """
            SELECT sha256, version, ordinal, document_json, deleted_at,
                   deletion_revision, record_hash, record_json
            FROM policy_version_tombstones
            ORDER BY deletion_revision
            """
        ).fetchall()
        result: list[dict[str, Any]] = []
        previous_hash = ""
        expected_record_fields = {
            "schema_version",
            "deletion_revision",
            "event_type",
            "version",
            "ordinal",
            "sha256",
            "deleted_at",
            "previous_hash",
            "record_hash",
        }
        for expected_revision, row in enumerate(rows, start=1):
            document = self._decode_mapping(
                row["document_json"], field=f"deleted version {row['sha256']}"
            )
            if (
                document.get("sha256") != row["sha256"]
                or document.get("version") != row["version"]
                or document.get("ordinal") != row["ordinal"]
                or self._document_hash(document) != row["sha256"]
            ):
                raise PolicyImmutableError("stored deleted policy document changed")
            if catalog is not None:
                self._validate_version_document(
                    document, catalog=catalog, migration_compatibility=True
                )
            record = self._decode_mapping(
                row["record_json"], field=f"policy deletion {expected_revision}"
            )
            if set(record) != expected_record_fields:
                raise PolicyImmutableError("policy deletion record fields changed")
            if (
                row["deletion_revision"] != expected_revision
                or record.get("deletion_revision") != expected_revision
                or record.get("schema_version") != POLICY_SCHEMA_VERSION
                or record.get("event_type") != "version_deleted"
                or record.get("version") != row["version"]
                or record.get("ordinal") != row["ordinal"]
                or record.get("sha256") != row["sha256"]
                or record.get("deleted_at") != row["deleted_at"]
                or record.get("previous_hash") != previous_hash
                or record.get("record_hash") != row["record_hash"]
                or self._tombstone_record_hash(record) != row["record_hash"]
            ):
                raise PolicyImmutableError("policy deletion audit hash chain is broken")
            _timestamp(record.get("deleted_at"), field="policy deletion deleted_at")
            previous_hash = str(record["record_hash"])
            result.append({"document": document, "record": record})
        return result

    def _load_version_chain(
        self,
        connection: sqlite3.Connection,
        *,
        catalog: Sequence[Mapping[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        """Load active versions and verify every active/deleted immutable lineage.

        Deleted nodes remain addressable by SHA-256, so an active chain may have
        visible ordinal gaps without losing its cryptographic ancestry.  Multiple
        generations may reuse the same ``v1.N`` label, but never the same SHA.
        """

        active = [
            self._load_version_row(connection, str(row["version"]))
            for row in connection.execute(
                "SELECT version FROM policy_versions ORDER BY ordinal"
            ).fetchall()
        ]
        tombstones = self._load_tombstones(connection, catalog=catalog)
        all_documents: dict[str, dict[str, Any]] = {}
        for document in [*(item["document"] for item in tombstones), *active]:
            sha256 = str(document.get("sha256") or "")
            if sha256 in all_documents:
                raise PolicyImmutableError("policy SHA-256 appears in active and deleted history")
            if catalog is not None:
                self._validate_version_document(
                    document, catalog=catalog, migration_compatibility=True
                )
            all_documents[sha256] = document
        for document in all_documents.values():
            current = document
            seen: set[str] = set()
            while True:
                current_sha = str(current.get("sha256") or "")
                if current_sha in seen:
                    raise PolicyImmutableError("policy SHA-256 ancestry contains a cycle")
                seen.add(current_sha)
                ordinal = int(current.get("ordinal", -1))
                version = str(current.get("version") or "")
                if version != f"v1.{ordinal}" or ordinal < 0:
                    raise PolicyImmutableError("policy version/ordinal lineage is inconsistent")
                previous_sha = str(current.get("previous_sha256") or "")
                if ordinal == 0:
                    if previous_sha:
                        raise PolicyImmutableError("policy v1.0 lineage must start at a root")
                    break
                previous = all_documents.get(previous_sha)
                if previous is None:
                    raise PolicyImmutableError(
                        f"policy SHA chain is broken at {version}: predecessor is unavailable"
                    )
                if int(previous.get("ordinal", -1)) != ordinal - 1:
                    raise PolicyImmutableError(
                        f"policy SHA chain is broken at {version}: ordinal is not continuous"
                    )
                current = previous
        return active

    def _insert_tombstone(
        self,
        connection: sqlite3.Connection,
        document: Mapping[str, Any],
        *,
        catalog: Sequence[Mapping[str, Any]],
    ) -> dict[str, Any]:
        tombstones = self._load_tombstones(connection, catalog=catalog)
        deleted_at = utc_now()
        record = {
            "schema_version": POLICY_SCHEMA_VERSION,
            "deletion_revision": len(tombstones) + 1,
            "event_type": "version_deleted",
            "version": document["version"],
            "ordinal": document["ordinal"],
            "sha256": document["sha256"],
            "deleted_at": deleted_at,
            "previous_hash": (
                tombstones[-1]["record"]["record_hash"] if tombstones else ""
            ),
        }
        record["record_hash"] = self._tombstone_record_hash(record)
        connection.execute(
            """
            INSERT INTO policy_version_tombstones(
                sha256, version, ordinal, document_json, deleted_at,
                deletion_revision, record_hash, record_json
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                document["sha256"],
                document["version"],
                document["ordinal"],
                canonical_json(document),
                deleted_at,
                record["deletion_revision"],
                record["record_hash"],
                canonical_json(record),
            ),
        )
        return record

    def _lineage_documents(
        self,
        connection: sqlite3.Connection,
        document: Mapping[str, Any],
        *,
        catalog: Sequence[Mapping[str, Any]],
    ) -> list[dict[str, Any]]:
        active = self._load_version_chain(connection, catalog=catalog)
        deleted = [
            item["document"]
            for item in self._load_tombstones(connection, catalog=catalog)
        ]
        by_sha = {str(item["sha256"]): item for item in [*deleted, *active]}
        current = by_sha.get(str(document.get("sha256") or ""))
        if current is None:
            raise PolicyImmutableError("policy lineage target is unavailable")
        lineage: list[dict[str, Any]] = []
        while True:
            lineage.append(current)
            previous_sha = str(current.get("previous_sha256") or "")
            if not previous_sha:
                break
            previous = by_sha.get(previous_sha)
            if previous is None:
                raise PolicyImmutableError("policy lineage predecessor is unavailable")
            current = previous
        lineage.reverse()
        return lineage

    def load_version(self, version: str) -> dict[str, Any]:
        with self.transaction(immediate=False) as connection:
            catalog = self._catalog(connection)
            documents = self._load_version_chain(connection, catalog=catalog)
            document = next(
                (item for item in documents if item["version"] == version), None
            )
            if document is None:
                raise PolicyNotFoundError(f"policy version does not exist: {version}")
            return _copy(document)

    def _read_draft(self, connection: sqlite3.Connection) -> dict[str, Any]:
        row = connection.execute("SELECT * FROM policy_state WHERE singleton = 1").fetchone()
        if row is None:
            raise WorkbenchPolicyStoreError("workbench policy draft is not initialized")
        draft = self._decode_mapping(row["draft_json"], field="draft")
        if draft.get("draft_revision") != row["draft_revision"]:
            raise PolicyImmutableError("stored draft revision is inconsistent")
        return draft

    def _validate_draft(
        self,
        draft: Any,
        *,
        catalog: Sequence[Mapping[str, Any]],
        version_by_name: Mapping[str, Mapping[str, Any]],
        allow_incomplete: bool = False,
    ) -> dict[str, Any]:
        if not isinstance(draft, Mapping):
            raise PolicyValidationError("draft must be an object")
        value = _copy(dict(draft))
        if value.get("schema_version") != DRAFT_SCHEMA_VERSION:
            raise PolicyValidationError("unsupported draft schema")
        value["draft_revision"] = _strict_revision(value.get("draft_revision"))
        base_version = value.get("base_version")
        if base_version is not None:
            _version_ordinal(base_version)
            base = version_by_name.get(str(base_version))
            if base is None:
                raise PolicyValidationError("draft base_version does not exist")
            if value.get("base_sha256") != base.get("sha256"):
                raise PolicyValidationError("draft base SHA-256 does not match its version")
        elif value.get("base_sha256") not in {None, ""}:
            raise PolicyValidationError("draft without a base version cannot bind a SHA-256")
        value["rules"] = self._validate_rules(
            value.get("rules"),
            catalog=catalog,
            allow_missing_thresholds=allow_incomplete,
        )
        if allow_incomplete and value.get("scoring_config") is None:
            value["scoring_config"] = None
        else:
            value["scoring_config"] = self._validate_scoring(
                value.get("scoring_config"), catalog=catalog
            )
        if allow_incomplete and value.get("inspection_schedule") is None:
            value["inspection_schedule"] = None
        else:
            value["inspection_schedule"] = _inspection_schedule(
                value.get("inspection_schedule")
            )
        if "updated_at" in value:
            _timestamp(value["updated_at"], field="draft.updated_at")
        else:
            value["updated_at"] = utc_now()
        return value

    @staticmethod
    def _store_draft(connection: sqlite3.Connection, draft: Mapping[str, Any]) -> None:
        connection.execute(
            """
            INSERT INTO policy_state(singleton, draft_revision, draft_json, updated_at)
            VALUES(1, ?, ?, ?)
            ON CONFLICT(singleton) DO UPDATE SET
                draft_revision = excluded.draft_revision,
                draft_json = excluded.draft_json,
                updated_at = excluded.updated_at
            """,
            (
                int(draft["draft_revision"]),
                canonical_json(draft),
                str(draft["updated_at"]),
            ),
        )

    @staticmethod
    def _insert_version(connection: sqlite3.Connection, document: Mapping[str, Any]) -> None:
        connection.execute(
            """
            INSERT INTO policy_versions(
                version, ordinal, sha256, document_json, created_at,
                effective_at, activation_mode, note
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                document["version"],
                document["ordinal"],
                document["sha256"],
                canonical_json(document),
                document["created_at"],
                document["effective_at"],
                document.get("activation_mode") or "scheduled",
                document.get("note") or "",
            ),
        )

    def import_state(
        self,
        versions: Sequence[Mapping[str, Any]] | Mapping[str, Any],
        draft: Mapping[str, Any],
        launch_selection: Mapping[str, Any] | Sequence[Mapping[str, Any]] | None = None,
        *,
        replace_if_empty: bool = True,
        trusted_source_sha256: str | None = None,
        legacy_display_rules: Sequence[Mapping[str, Any]] | None = None,
        legacy_scoring_config: Mapping[str, Any] | None = None,
        legacy_schedule: Mapping[str, Any] | str | None = None,
    ) -> dict[str, Any]:
        """Atomically import the real mutable policy state into an empty store.

        Version documents and source selection events retain their original
        canonical bytes and hashes.  The optional trusted source hash records
        the migration bundle identity; it never bypasses document validation.
        """

        if not isinstance(replace_if_empty, bool):
            raise PolicyValidationError("replace_if_empty must be boolean")
        if trusted_source_sha256 is not None and (
            not isinstance(trusted_source_sha256, str)
            or SHA256_RE.fullmatch(trusted_source_sha256) is None
        ):
            raise PolicyValidationError("trusted_source_sha256 must be a lowercase SHA-256")
        if isinstance(versions, Mapping):
            raw_versions = versions.get("versions")
            if raw_versions is None:
                raw_versions = list(versions.values())
        else:
            raw_versions = versions
        if not isinstance(raw_versions, Sequence) or isinstance(raw_versions, (str, bytes)):
            raise PolicyValidationError("versions must be a sequence")
        ordered = sorted(
            (_copy(dict(item)) for item in raw_versions if isinstance(item, Mapping)),
            key=lambda item: _version_ordinal(item.get("version")),
        )
        if len(ordered) != len(raw_versions) or not ordered:
            raise PolicyValidationError("versions must contain policy objects")
        if [_version_ordinal(item.get("version")) for item in ordered] != list(range(len(ordered))):
            raise PolicyValidationError("imported versions must be the continuous v1.N chain")
        catalog_rules = draft.get("rules") if isinstance(draft, Mapping) else None
        normalized_catalog_rules = self._validate_catalog_shape(catalog_rules)
        catalog = self._catalog_from_rules(normalized_catalog_rules)
        validated_versions: list[dict[str, Any]] = []
        previous_sha = ""
        for document in ordered:
            validated = self._validate_version_document(
                document, catalog=catalog, migration_compatibility=True
            )
            if str(validated.get("previous_sha256") or "") != previous_sha:
                raise PolicyImmutableError(
                    f"policy SHA chain is broken at {validated['version']}"
                )
            previous_sha = str(validated["sha256"])
            validated_versions.append(validated)
        version_by_name = {str(item["version"]): item for item in validated_versions}
        validated_draft = self._validate_draft(
            draft, catalog=catalog, version_by_name=version_by_name
        )
        has_legacy = any(str(item.get("mode") or "") == "legacy" for item in validated_versions)
        legacy_projection: dict[str, Any] | None = None
        if has_legacy:
            if (
                legacy_display_rules is None
                or legacy_scoring_config is None
                or legacy_schedule is None
            ):
                raise PolicyValidationError(
                    "legacy versions require display rules, scoring_config and schedule"
                )
            legacy_projection = {
                "rules": self._validate_rules(
                    list(legacy_display_rules),
                    catalog=catalog,
                    allow_missing_thresholds=False,
                ),
                "scoring_config": self._validate_scoring(
                    legacy_scoring_config, catalog=catalog
                ),
                "inspection_schedule": _inspection_schedule(legacy_schedule),
            }
        elif any(
            value is not None
            for value in (legacy_display_rules, legacy_scoring_config, legacy_schedule)
        ):
            raise PolicyValidationError(
                "legacy display projection was supplied without a legacy version"
            )
        source_events = self._normalize_import_selection(launch_selection)
        self._validate_selection_records(source_events, version_by_name=version_by_name)
        with self.transaction() as connection:
            counts = connection.execute(
                """
                SELECT
                    (SELECT COUNT(*) FROM policy_versions) AS versions,
                    (SELECT COUNT(*) FROM policy_version_tombstones) AS tombstones,
                    (SELECT COUNT(*) FROM policy_state) AS drafts,
                    (SELECT COUNT(*) FROM selection_events) AS events,
                    (SELECT COUNT(*) FROM metadata WHERE key = 'metric_catalog') AS catalogs
                """
            ).fetchone()
            if any(int(counts[key]) for key in counts.keys()):
                raise PolicyConflictError("policy import is allowed only into an empty store")
            connection.execute(
                "INSERT INTO metadata(key, value) VALUES('metric_catalog', ?)",
                (canonical_json(catalog),),
            )
            connection.execute(
                "INSERT INTO metadata(key, value) VALUES('migration_imported_at', ?)",
                (utc_now(),),
            )
            if trusted_source_sha256 is not None:
                connection.execute(
                    "INSERT INTO metadata(key, value) VALUES('migration_source_sha256', ?)",
                    (trusted_source_sha256,),
                )
            if legacy_projection is not None:
                connection.execute(
                    "INSERT INTO metadata(key, value) VALUES('legacy_projection', ?)",
                    (canonical_json(legacy_projection),),
                )
            for document in validated_versions:
                self._insert_version(connection, document)
            self._store_draft(connection, validated_draft)
            for record in source_events:
                connection.execute(
                    "INSERT INTO selection_events(revision, record_hash, record_json) VALUES(?, ?, ?)",
                    (record["revision"], record["record_hash"], canonical_json(record)),
                )
        return self.overview()

    def initialize_unpublished_draft(
        self,
        rules: Sequence[Mapping[str, Any]],
        *,
        scoring_config: Mapping[str, Any],
        inspection_schedule: Mapping[str, Any],
        template_sha256: str,
    ) -> bool:
        """Create only the editable draft/catalog for a clean installation.

        This method never inserts ``policy_versions`` or selection events.
        Thresholds may be absent in the initial draft; first publish remains
        fail-closed until an operator has completed every metric rule.
        """

        if SHA256_RE.fullmatch(str(template_sha256)) is None:
            raise PolicyValidationError("draft template SHA-256 is invalid")
        catalog_rules = self._validate_catalog_shape(list(rules))
        catalog = self._catalog_from_rules(catalog_rules)
        normalized_rules = self._validate_rules(
            list(rules),
            catalog=catalog,
            allow_missing_thresholds=True,
        )
        normalized_scoring = self._validate_scoring(scoring_config, catalog=catalog)
        normalized_schedule = _inspection_schedule(inspection_schedule)
        draft = {
            "schema_version": DRAFT_SCHEMA_VERSION,
            "draft_revision": 1,
            "base_version": None,
            "base_sha256": None,
            "updated_at": utc_now(),
            "rules": normalized_rules,
            "scoring_config": normalized_scoring,
            "inspection_schedule": normalized_schedule,
        }
        with self.transaction() as connection:
            counts = connection.execute(
                """
                SELECT
                    (SELECT COUNT(*) FROM policy_versions) AS versions,
                    (SELECT COUNT(*) FROM policy_version_tombstones) AS tombstones,
                    (SELECT COUNT(*) FROM policy_state) AS drafts,
                    (SELECT COUNT(*) FROM selection_events) AS events,
                    (SELECT COUNT(*) FROM metadata WHERE key = 'metric_catalog') AS catalogs
                """
            ).fetchone()
            if int(counts["drafts"]) == 1 and int(counts["catalogs"]) == 1:
                stored_template = connection.execute(
                    "SELECT value FROM metadata WHERE key = 'draft_template_sha256'"
                ).fetchone()
                if (
                    stored_template is not None
                    and stored_template["value"] != template_sha256
                ):
                    raise PolicyConflictError(
                        "stored unpublished draft template differs from this server release"
                    )
                return False
            if any(int(counts[key]) for key in counts.keys()):
                raise PolicyConflictError(
                    "cannot initialize an unpublished draft over partial policy state"
                )
            connection.execute(
                "INSERT INTO metadata(key, value) VALUES('metric_catalog', ?)",
                (canonical_json(catalog),),
            )
            connection.execute(
                "INSERT INTO metadata(key, value) VALUES('draft_template_sha256', ?)",
                (template_sha256,),
            )
            self._store_draft(connection, draft)
        return True

    @staticmethod
    def _selection_record_hash(record: Mapping[str, Any]) -> str:
        payload = dict(record)
        payload.pop("record_hash", None)
        return sha256_json(payload)

    def _normalize_import_selection(
        self,
        value: Mapping[str, Any] | Sequence[Mapping[str, Any]] | None,
    ) -> list[dict[str, Any]]:
        if value is None:
            return []
        if isinstance(value, Mapping) and isinstance(value.get("events"), list):
            raw_events: Any = value["events"]
        elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
            raw_events = value
        elif isinstance(value, Mapping) and "event_type" in value:
            raw_events = [value]
        elif isinstance(value, Mapping):
            if value.get("mode") != "manual" or not value.get("selected_version"):
                return []
            record = {
                "schema_version": SELECTION_SCHEMA_VERSION,
                "revision": 1,
                "event_type": "version_selected",
                "selected_version": value.get("selected_version"),
                "selected_sha256": value.get("selected_sha256"),
                "selected_at": value.get("selected_at") or utc_now(),
                "reason": "operator_version_switch",
                "previous_hash": "",
            }
            record["record_hash"] = self._selection_record_hash(record)
            return [record]
        else:
            raise PolicyValidationError("launch_selection must be an object or event sequence")
        result: list[dict[str, Any]] = []
        for raw in raw_events:
            if not isinstance(raw, Mapping):
                raise PolicyValidationError("selection event must be an object")
            result.append(_copy(dict(raw)))
        return result

    def _validate_selection_records(
        self,
        records: Sequence[Mapping[str, Any]],
        *,
        version_by_name: Mapping[str, Mapping[str, Any]],
    ) -> None:
        previous_hash = ""
        for expected_revision, raw in enumerate(records, start=1):
            record = dict(raw)
            if record.get("schema_version") != SELECTION_SCHEMA_VERSION:
                raise PolicyImmutableError("selection audit schema is unsupported")
            if record.get("revision") != expected_revision:
                raise PolicyImmutableError("selection audit revisions are not continuous")
            event_type = record.get("event_type")
            if event_type not in SELECTION_EVENT_TYPES:
                raise PolicyImmutableError("selection audit event type is invalid")
            if record.get("reason") != SELECTION_REASONS[event_type]:
                raise PolicyImmutableError("selection audit reason is invalid")
            if record.get("previous_hash") != previous_hash:
                raise PolicyImmutableError("selection audit hash chain is broken")
            record_hash = record.get("record_hash")
            if (
                not isinstance(record_hash, str)
                or SHA256_RE.fullmatch(record_hash) is None
                or self._selection_record_hash(record) != record_hash
            ):
                raise PolicyImmutableError("selection audit record hash is invalid")
            _timestamp(record.get("selected_at"), field="selection selected_at")
            if event_type == "version_selected":
                selected_version = str(record.get("selected_version") or "")
                _version_ordinal(selected_version)
                selected_sha = record.get("selected_sha256")
                if not isinstance(selected_sha, str) or SHA256_RE.fullmatch(selected_sha) is None:
                    raise PolicyImmutableError("selection version binding is invalid")
            elif record.get("selected_version") is not None or record.get("selected_sha256") is not None:
                raise PolicyImmutableError("automatic selection event cannot bind a version")
            previous_hash = record_hash
        if records and records[-1].get("event_type") == "version_selected":
            latest = records[-1]
            selected = version_by_name.get(str(latest.get("selected_version")))
            if selected is None or selected.get("sha256") != latest.get("selected_sha256"):
                raise PolicyImmutableError("current selected policy binding is unavailable")

    def _selection_records(self, connection: sqlite3.Connection) -> list[dict[str, Any]]:
        rows = connection.execute(
            "SELECT revision, record_hash, record_json FROM selection_events ORDER BY revision"
        ).fetchall()
        records: list[dict[str, Any]] = []
        for row in rows:
            record = self._decode_mapping(row["record_json"], field="selection event")
            if record.get("revision") != row["revision"] or record.get("record_hash") != row["record_hash"]:
                raise PolicyImmutableError("stored selection audit metadata changed")
            records.append(record)
        documents = self._load_version_chain(
            connection, catalog=self._catalog(connection)
        )
        version_by_name = {str(item["version"]): item for item in documents}
        self._validate_selection_records(records, version_by_name=version_by_name)
        return records

    def _append_selection(
        self,
        connection: sqlite3.Connection,
        *,
        event_type: str,
        document: Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        if event_type not in SELECTION_EVENT_TYPES:
            raise PolicyValidationError("invalid selection event type")
        records = self._selection_records(connection)
        record = {
            "schema_version": SELECTION_SCHEMA_VERSION,
            "revision": len(records) + 1,
            "event_type": event_type,
            "selected_version": document.get("version") if document is not None else None,
            "selected_sha256": document.get("sha256") if document is not None else None,
            "selected_at": utc_now(),
            "reason": SELECTION_REASONS[event_type],
            "previous_hash": records[-1]["record_hash"] if records else "",
        }
        record["record_hash"] = self._selection_record_hash(record)
        connection.execute(
            "INSERT INTO selection_events(revision, record_hash, record_json) VALUES(?, ?, ?)",
            (record["revision"], record["record_hash"], canonical_json(record)),
        )
        return record

    def _selection_overview(self, connection: sqlite3.Connection) -> dict[str, Any]:
        records = self._selection_records(connection)
        latest = records[-1] if records else None
        if latest is not None and latest["event_type"] == "version_selected":
            document = self._load_version_row(connection, str(latest["selected_version"]))
            return {
                "mode": "manual",
                "selected_version": document["version"],
                "selected_sha256": document["sha256"],
                "selected_at": latest["selected_at"],
                "selection_revision": latest["revision"],
            }
        actual_now = datetime.now(SHANGHAI)
        automatic: dict[str, Any] | None = None
        for candidate in self._load_version_chain(
            connection, catalog=self._catalog(connection)
        ):
            # next_inspection requires a durable run_queued/claim fact.  This
            # policy-only store has no authority to invent that fact merely
            # because the planned wall-clock timestamp has passed.
            if (candidate.get("activation_mode") or "scheduled") == "next_inspection":
                continue
            effective_at = datetime.fromisoformat(
                str(candidate["effective_at"]).replace("Z", "+00:00")
            )
            if effective_at <= actual_now:
                automatic = candidate
        return {
            "mode": "automatic",
            "selected_version": automatic["version"] if automatic else None,
            "selected_sha256": automatic["sha256"] if automatic else None,
            "selected_at": latest["selected_at"] if latest else None,
            "selection_revision": latest["revision"] if latest else 0,
        }

    @staticmethod
    def _next_schedule_occurrence(schedule_time: str, *, after: datetime) -> datetime:
        hour, minute = (int(item) for item in schedule_time.split(":"))
        local = after.astimezone(SHANGHAI)
        candidate = local.replace(hour=hour, minute=minute, second=0, microsecond=0)
        if candidate <= local:
            candidate += timedelta(days=1)
        return candidate

    @staticmethod
    def _schedule_for_documents(
        documents: Sequence[Mapping[str, Any]],
        target_ordinal: int,
    ) -> dict[str, str]:
        for document in sorted(
            (item for item in documents if int(item["ordinal"]) <= target_ordinal),
            key=lambda item: int(item["ordinal"]),
            reverse=True,
        ):
            if document.get("inspection_schedule") is not None:
                return _inspection_schedule(document["inspection_schedule"])
        return {"time": "09:00"}

    def _effective_document(
        self,
        connection: sqlite3.Connection,
        *,
        now: datetime | None = None,
    ) -> dict[str, Any] | None:
        documents = self._load_version_chain(
            connection, catalog=self._catalog(connection)
        )
        if not documents:
            return None
        selection = self._selection_overview(connection)
        if selection["mode"] == "manual":
            selected = next(
                (
                    item
                    for item in documents
                    if item["version"] == selection["selected_version"]
                    and item["sha256"] == selection["selected_sha256"]
                ),
                None,
            )
            if selected is None:
                raise PolicyImmutableError("current selected policy binding is unavailable")
            if (selected.get("activation_mode") or "scheduled") != "next_inspection":
                return selected
        actual_now = (now or datetime.now(SHANGHAI)).astimezone(SHANGHAI)
        eligible: list[dict[str, Any]] = []
        for document in documents:
            if (document.get("activation_mode") or "scheduled") == "next_inspection":
                continue
            effective_at = datetime.fromisoformat(str(document["effective_at"]).replace("Z", "+00:00"))
            if effective_at <= actual_now:
                eligible.append(document)
        return eligible[-1] if eligible else None

    def runtime_policy_for_launch(self) -> dict[str, Any]:
        """Freeze the selected published version into a self-hashed run policy.

        The published document remains immutable under ``published_sha256``.
        Runtime inheritance (legacy display rules and the most recent schedule)
        is materialized before a workspace is created, then the complete object
        receives its own ``sha256``.  An empty store never invents v1.0.
        """

        with self.transaction(immediate=False) as connection:
            catalog = self._catalog(connection)
            draft = self._read_draft(connection)
            documents = self._load_version_chain(connection, catalog=catalog)
            if not documents:
                raise PolicyNotConfiguredError(
                    "no published health-policy version exists; configure and publish one first"
                )
            selection = self._selection_overview(connection)
            target: dict[str, Any] | None = None
            if selection["mode"] == "manual":
                target = next(
                    (
                        item
                        for item in documents
                        if item["version"] == selection["selected_version"]
                        and item["sha256"] == selection["selected_sha256"]
                    ),
                    None,
                )
                if target is None:
                    raise PolicyImmutableError(
                        "selected health-policy version is no longer available"
                    )
            else:
                target = self._effective_document(connection)
            if target is None:
                raise PolicyNotConfiguredError(
                    "no published health-policy version is effective for this inspection"
                )
            runtime = self._display_document(
                connection,
                target,
                catalog=catalog,
                fallback_scoring=draft["scoring_config"],
            )
            # Historical versions without a scoring contract must preserve the
            # true-equal legacy scoring branch in deterministic calculation.
            if "scoring_config" not in target:
                runtime.pop("scoring_config", None)
            published_sha256 = str(target["sha256"])
            runtime.pop("sha256", None)
            runtime["published_sha256"] = published_sha256
            runtime["sha256"] = sha256_json(runtime)
            return _copy(runtime)

    def _commit_draft(
        self,
        connection: sqlite3.Connection,
        draft: dict[str, Any],
    ) -> dict[str, Any]:
        draft["draft_revision"] = int(draft["draft_revision"]) + 1
        draft["updated_at"] = utc_now()
        self._store_draft(connection, draft)
        return _copy(draft)

    @staticmethod
    def _require_revision(draft: Mapping[str, Any], requested: Any) -> None:
        revision = _strict_revision(requested)
        if int(draft["draft_revision"]) != revision:
            raise PolicyConflictError(
                "the policy draft changed in another window; refresh and retry"
            )

    def save_metric(
        self,
        metric_id: str,
        draft_revision: int,
        description: str,
        thresholds: Mapping[str, Any],
    ) -> dict[str, Any]:
        with self.transaction() as connection:
            catalog = self._catalog(connection)
            catalog_by_id = {str(item["metric_id"]): item for item in catalog}
            template = catalog_by_id.get(metric_id)
            if template is None:
                raise PolicyValidationError(f"unknown metric_id: {metric_id}")
            normalized_description = _strict_text(
                description,
                field=f"{metric_id}.description",
                maximum=DESCRIPTION_MAX_LENGTH,
                allow_empty=False,
            )
            normalized_thresholds = self._validate_thresholds(
                template, thresholds, allow_missing=False
            )
            draft = self._read_draft(connection)
            self._require_revision(draft, draft_revision)
            target = next(
                (rule for rule in draft["rules"] if rule["metric_id"] == metric_id), None
            )
            if target is None:
                raise PolicyImmutableError(f"draft lost fixed metric {metric_id}")
            if (
                target.get("description") == normalized_description
                and target.get("thresholds") == normalized_thresholds
            ):
                return _copy(draft)
            target["description"] = normalized_description
            target["thresholds"] = normalized_thresholds
            target["classification_enabled"] = True
            target["evaluation_status"] = "evaluated"
            return self._commit_draft(connection, draft)

    def save_scoring(
        self,
        draft_revision: int,
        scoring_config: Mapping[str, Any],
    ) -> dict[str, Any]:
        with self.transaction() as connection:
            catalog = self._catalog(connection)
            normalized = self._validate_scoring(scoring_config, catalog=catalog)
            draft = self._read_draft(connection)
            self._require_revision(draft, draft_revision)
            if draft.get("scoring_config") == normalized:
                return _copy(draft)
            draft["scoring_config"] = normalized
            return self._commit_draft(connection, draft)

    def save_schedule(self, time: str, draft_revision: int) -> dict[str, Any]:
        schedule = _inspection_schedule({"time": time})
        with self.transaction() as connection:
            draft = self._read_draft(connection)
            self._require_revision(draft, draft_revision)
            if draft.get("inspection_schedule") == schedule:
                return _copy(draft)
            draft["inspection_schedule"] = schedule
            return self._commit_draft(connection, draft)

    @staticmethod
    def _rule_changes(
        before: Mapping[str, Any], after: Mapping[str, Any]
    ) -> list[dict[str, Any]]:
        before_by_id = {str(item["metric_id"]): item for item in before.get("rules", [])}
        changes: list[dict[str, Any]] = []
        for item in after.get("rules", []):
            previous = before_by_id.get(str(item["metric_id"]), {})
            description_changed = previous.get("description") != item.get("description")
            thresholds_changed = previous.get("thresholds") != item.get("thresholds")
            if not description_changed and not thresholds_changed:
                continue
            changes.append(
                {
                    "metric_id": item["metric_id"],
                    "name": item.get("name"),
                    "dimension": item.get("dimension"),
                    "description_changed": description_changed,
                    "thresholds_changed": thresholds_changed,
                    "before_description": previous.get("description"),
                    "after_description": item.get("description"),
                    "before_thresholds": _copy(previous.get("thresholds")),
                    "after_thresholds": _copy(item.get("thresholds")),
                }
            )
        return changes

    @staticmethod
    def _scoring_changes(
        before: Mapping[str, Any], after: Mapping[str, Any]
    ) -> list[dict[str, Any]]:
        old = before.get("scoring_config") or {}
        new = after.get("scoring_config") or {}
        changes: list[dict[str, Any]] = []
        for dimension in DIMENSIONS:
            left = (old.get("dimension_weight_percentages") or {}).get(dimension)
            right = (new.get("dimension_weight_percentages") or {}).get(dimension)
            if left != right:
                changes.append(
                    {
                        "type": "dimension_weight",
                        "dimension": dimension,
                        "label": dimension,
                        "before": left,
                        "after": right,
                    }
                )
        for rule in after.get("rules", []):
            metric_id = str(rule["metric_id"])
            left = (old.get("metric_weight_percentages") or {}).get(metric_id)
            right = (new.get("metric_weight_percentages") or {}).get(metric_id)
            if left != right:
                changes.append(
                    {
                        "type": "metric_weight",
                        "dimension": rule.get("dimension"),
                        "metric_id": metric_id,
                        "label": f"{metric_id} · {rule.get('name') or metric_id}",
                        "before": left,
                        "after": right,
                    }
                )
        if old.get("band_thresholds") != new.get("band_thresholds"):
            changes.append(
                {
                    "type": "band_threshold",
                    "label": "总健康分红黄绿区间",
                    "before": _copy(old.get("band_thresholds")),
                    "after": _copy(new.get("band_thresholds")),
                }
            )
        for dimension in DIMENSIONS:
            left = (old.get("dimension_band_thresholds") or {}).get(dimension)
            right = (new.get("dimension_band_thresholds") or {}).get(dimension)
            if left != right:
                changes.append(
                    {
                        "type": "dimension_band_threshold",
                        "dimension": dimension,
                        "label": f"{dimension} 红黄绿区间",
                        "before": _copy(left),
                        "after": _copy(right),
                    }
                )
        return changes

    @staticmethod
    def _schedule_change(
        before: Mapping[str, Any], after: Mapping[str, Any]
    ) -> dict[str, Any] | None:
        left = (before.get("inspection_schedule") or {}).get("time") or "09:00"
        right = (after.get("inspection_schedule") or {}).get("time") or "09:00"
        if left == right:
            return None
        return {
            "type": "inspection_schedule",
            "label": "每日巡检时间",
            "before": left,
            "after": right,
        }

    def _display_document(
        self,
        connection: sqlite3.Connection,
        target: Mapping[str, Any],
        *,
        catalog: Sequence[Mapping[str, Any]],
        fallback_scoring: Mapping[str, Any],
    ) -> dict[str, Any]:
        value = _copy(dict(target))
        if str(target.get("mode") or "") == "legacy":
            row = connection.execute(
                "SELECT value FROM metadata WHERE key = 'legacy_projection'"
            ).fetchone()
            if row is None:
                raise PolicyImmutableError("legacy display projection is missing")
            projection = self._decode_mapping(
                row["value"], field="legacy display projection"
            )
            value["rules"] = self._validate_rules(
                projection.get("rules"),
                catalog=catalog,
                allow_missing_thresholds=False,
            )
            value["scoring_config"] = self._validate_scoring(
                projection.get("scoring_config"), catalog=catalog
            )
            value["inspection_schedule"] = _inspection_schedule(
                projection.get("inspection_schedule")
            )
        else:
            value.setdefault("scoring_config", _copy(fallback_scoring))
            lineage = self._lineage_documents(
                connection, target, catalog=catalog
            )
            value["inspection_schedule"] = self._schedule_for_documents(
                lineage, int(target["ordinal"])
            )
        return value

    def _comparison_document(
        self,
        connection: sqlite3.Connection,
        version: str | None,
        *,
        fallback_rules: Sequence[Mapping[str, Any]],
        fallback_scoring: Mapping[str, Any],
        fallback_schedule: Mapping[str, Any],
    ) -> dict[str, Any]:
        if version is None:
            return {
                "rules": _copy(fallback_rules),
                "scoring_config": _copy(fallback_scoring),
                "inspection_schedule": _copy(fallback_schedule),
            }
        catalog = self._catalog(connection)
        documents = self._load_version_chain(connection, catalog=catalog)
        target = next(
            (item for item in documents if item["version"] == version), None
        )
        if target is None:
            raise PolicyNotFoundError(f"policy version does not exist: {version}")
        return self._display_document(
            connection,
            target,
            catalog=catalog,
            fallback_scoring=fallback_scoring,
        )

    def publish(
        self,
        draft_revision: int,
        activation_mode: str,
        effective_at: str | None,
        note: str,
    ) -> dict[str, Any]:
        normalized_note = _strict_text(
            note, field="note", maximum=NOTE_MAX_LENGTH, allow_empty=True
        )
        if activation_mode not in ACTIVATION_MODES:
            raise PolicyValidationError("activation_mode must be scheduled or next_inspection")
        with self.transaction() as connection:
            catalog = self._catalog(connection)
            draft = self._read_draft(connection)
            self._require_revision(draft, draft_revision)
            draft["rules"] = self._validate_rules(
                draft.get("rules"), catalog=catalog, allow_missing_thresholds=False
            )
            draft["scoring_config"] = self._validate_scoring(
                draft.get("scoring_config"), catalog=catalog
            )
            draft["inspection_schedule"] = _inspection_schedule(
                draft.get("inspection_schedule")
            )
            documents = self._load_version_chain(connection, catalog=catalog)
            latest = documents[-1] if documents else None
            base = self._comparison_document(
                connection,
                str(draft["base_version"]) if draft.get("base_version") else None,
                fallback_rules=draft["rules"],
                fallback_scoring=draft["scoring_config"],
                fallback_schedule=draft["inspection_schedule"],
            )
            rule_changes = self._rule_changes(base, draft)
            scoring_changes = self._scoring_changes(base, draft)
            schedule_change = self._schedule_change(base, draft)
            if (
                latest is not None
                and not rule_changes
                and not scoring_changes
                and schedule_change is None
            ):
                raise PolicyValidationError("the draft has no publishable change")
            ordinal = int(latest["ordinal"]) + 1 if latest is not None else 0
            version = f"v1.{ordinal}"
            now = datetime.now(SHANGHAI)
            if activation_mode == "scheduled":
                parsed_text = _timestamp(
                    effective_at, field="effective_at", require_shanghai=True
                )
                parsed = datetime.fromisoformat(parsed_text.replace("Z", "+00:00"))
                if parsed.second or parsed.microsecond:
                    raise PolicyValidationError("effective_at must be aligned to a minute")
                if parsed < now:
                    raise PolicyValidationError("effective_at cannot be in the past")
                frozen_effective_at = parsed.isoformat(timespec="minutes")
            else:
                if effective_at not in {None, ""}:
                    raise PolicyValidationError(
                        "next_inspection effective_at is calculated by the server"
                    )
                frozen_effective_at = self._next_schedule_occurrence(
                    draft["inspection_schedule"]["time"], after=now
                ).isoformat(timespec="minutes")
            document: dict[str, Any] = {
                "schema_version": POLICY_SCHEMA_VERSION,
                "version": version,
                "ordinal": ordinal,
                "mode": "thresholds",
                "activation_mode": activation_mode,
                "created_at": now.isoformat(timespec="milliseconds"),
                "effective_at": frozen_effective_at,
                "note": normalized_note,
                "previous_sha256": str(latest["sha256"]) if latest is not None else "",
                "rules": _copy(draft["rules"]),
                "inspection_schedule": _copy(draft["inspection_schedule"]),
                "scoring_config": _copy(draft["scoring_config"]),
            }
            document["sha256"] = self._document_hash(document)
            self._validate_version_document(
                document, catalog=catalog, migration_compatibility=False
            )
            self._insert_version(connection, document)
            selection = self._selection_overview(connection)
            if selection["mode"] == "manual":
                self._append_selection(
                    connection, event_type="automatic_restored", document=None
                )
            draft["base_version"] = version
            draft["base_sha256"] = document["sha256"]
            self._commit_draft(connection, draft)
            return _copy(document)

    def select_version(self, version: str) -> dict[str, Any]:
        with self.transaction() as connection:
            documents = self._load_version_chain(
                connection, catalog=self._catalog(connection)
            )
            document = next(
                (item for item in documents if item["version"] == version), None
            )
            if document is None:
                raise PolicyNotFoundError(f"policy version does not exist: {version}")
            current = self._selection_overview(connection)
            if current["mode"] == "manual" and current["selected_version"] == version:
                return {"selected": True, **current}
            record = self._append_selection(
                connection, event_type="version_selected", document=document
            )
            return {
                "selected": True,
                "selected_version": version,
                "selected_sha256": document["sha256"],
                "selected_at": record["selected_at"],
                "selection_revision": record["revision"],
                "mode": "manual",
            }

    @staticmethod
    def _usage_bindings(
        value: Iterable[Mapping[str, Any]],
    ) -> list[dict[str, Any]]:
        """Normalize exact immutable workspace bindings.

        Version-only counts are rejected because a version label can be reused
        after logical deletion and therefore is not an immutable identity.
        """

        if isinstance(value, (Mapping, str, bytes)):
            raise PolicyValidationError(
                "workspace policy usage must be a sequence of version/SHA bindings"
            )
        try:
            raw_items = list(value)
        except TypeError as exc:
            raise PolicyValidationError("workspace policy usage must be iterable") from exc
        result: list[dict[str, Any]] = []
        for raw in raw_items:
            if not isinstance(raw, Mapping):
                raise PolicyValidationError("each workspace policy usage must be an object")
            version = str(raw.get("version") or "")
            _version_ordinal(version)
            sha256 = raw.get("sha256")
            if not isinstance(sha256, str) or SHA256_RE.fullmatch(sha256) is None:
                raise PolicyValidationError(
                    f"workspace policy usage for {version} must bind a lowercase SHA-256"
                )
            projection = {
                key: _copy(raw[key])
                for key in USAGE_PROJECTION_FIELDS
                if key in raw
            }
            projection["policy_sha256"] = sha256
            result.append(
                {"version": version, "sha256": sha256, "projection": projection}
            )
        result.sort(
            key=lambda item: (
                str(item["projection"].get("business_date") or ""),
                str(item["projection"].get("run_id") or ""),
                str(item["version"]),
                str(item["sha256"]),
            )
        )
        return result

    @staticmethod
    def _usage_for_document(
        bindings: Sequence[Mapping[str, Any]],
        document: Mapping[str, Any],
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        version = str(document["version"])
        sha256 = str(document["sha256"])
        exact = [
            _copy(item["projection"])
            for item in bindings
            if item["version"] == version and item["sha256"] == sha256
        ]
        conflicts = [
            _copy(item["projection"])
            for item in bindings
            if item["version"] == version and item["sha256"] != sha256
        ]
        return exact, conflicts

    def delete_version(
        self,
        version: str,
        *,
        in_use_versions: Iterable[Mapping[str, Any]],
    ) -> dict[str, Any]:
        bindings = self._usage_bindings(in_use_versions)
        with self.transaction() as connection:
            catalog = self._catalog(connection)
            documents = self._load_version_chain(connection, catalog=catalog)
            document = next(
                (item for item in documents if item["version"] == version), None
            )
            if document is None:
                raise PolicyNotFoundError(f"policy version does not exist: {version}")
            exact_usage, identity_conflicts = self._usage_for_document(bindings, document)
            if exact_usage:
                raise PolicyInUseError(
                    f"policy {version} with SHA-256 {document['sha256']} is bound to an existing workspace"
                )
            if identity_conflicts:
                raise PolicyInUseError(
                    f"policy {version} has existing workspace bindings with a different SHA-256"
                )
            selection = self._selection_overview(connection)
            draft = self._read_draft(connection)
            if selection["mode"] == "manual" and selection["selected_version"] == version:
                self._append_selection(
                    connection, event_type="selection_cleared", document=None
                )
            tombstone = self._insert_tombstone(
                connection, document, catalog=catalog
            )
            connection.execute("DELETE FROM policy_versions WHERE version = ?", (version,))
            remaining = self._load_version_chain(connection, catalog=catalog)
            if (
                draft.get("base_version") == version
                and draft.get("base_sha256") == document["sha256"]
            ):
                replacement = remaining[-1] if remaining else None
                draft["base_version"] = replacement["version"] if replacement else None
                draft["base_sha256"] = replacement["sha256"] if replacement else None
                self._commit_draft(connection, draft)
            next_ordinal = int(remaining[-1]["ordinal"]) + 1 if remaining else 0
            return {
                "deleted": True,
                "version": document["version"],
                "sha256": document["sha256"],
                "tombstone_revision": tombstone["deletion_revision"],
                "tombstone_hash": tombstone["record_hash"],
                "version_count": len(remaining),
                "next_version": f"v1.{next_ordinal}",
                "draft_revision": draft["draft_revision"],
                "launch_selection_cleared": (
                    selection["mode"] == "manual" and selection["selected_version"] == version
                ),
            }

    def _versions_with_projection(
        self,
        connection: sqlite3.Connection,
        *,
        in_use_versions: Iterable[Mapping[str, Any]] = (),
        now: datetime | None = None,
    ) -> list[dict[str, Any]]:
        catalog = self._catalog(connection)
        documents = self._load_version_chain(connection, catalog=catalog)
        selection = self._selection_overview(connection)
        effective = self._effective_document(connection, now=now)
        bindings = self._usage_bindings(in_use_versions)
        actual_now = (now or datetime.now(SHANGHAI)).astimezone(SHANGHAI)
        result: list[dict[str, Any]] = []
        for document in documents:
            item = _copy(document)
            item["activation_mode"] = document.get("activation_mode") or "scheduled"
            item["inspection_schedule"] = self._schedule_for_documents(
                documents, int(document["ordinal"])
            )
            item["inspection_time"] = item["inspection_schedule"]["time"]
            item["selected_for_next_run"] = (
                selection["selected_version"] == document["version"]
            )
            item["launch_selection_mode"] = selection["mode"]
            exact_usage, identity_conflicts = self._usage_for_document(
                bindings, document
            )
            item["run_usage"] = exact_usage
            item["run_usage_count"] = len(exact_usage)
            item["identity_conflicts"] = identity_conflicts
            item["identity_conflict_count"] = len(identity_conflicts)
            item["identity_conflict"] = bool(identity_conflicts)
            item["deletable"] = not exact_usage and not identity_conflicts
            if exact_usage:
                item["delete_block_reason"] = "已有日期 worktree 使用该版本及其精确 SHA-256"
            elif identity_conflicts:
                item["delete_block_reason"] = "已有日期 worktree 使用相同版本号但不同 SHA-256，身份冲突"
            else:
                item["delete_block_reason"] = None
            effective_at = datetime.fromisoformat(
                str(document["effective_at"]).replace("Z", "+00:00")
            )
            if item["activation_mode"] == "next_inspection":
                item["status"] = "next_inspection"
            elif effective_at > actual_now:
                item["status"] = "pending"
            elif effective is not None and effective["version"] == document["version"]:
                item["status"] = "current"
            else:
                item["status"] = "history"
            item["activated_at"] = (
                document["effective_at"]
                if item["activation_mode"] != "next_inspection"
                and effective_at <= actual_now
                else None
            )
            result.append(item)
        return result

    def list_versions(
        self,
        status: str | None = None,
        keyword: str | None = None,
        *,
        in_use_versions: Iterable[Mapping[str, Any]] = (),
    ) -> list[dict[str, Any]]:
        clean_status = str(status or "all").strip().lower()
        if clean_status not in {
            "all",
            "current",
            "history",
            "pending",
            "next_inspection",
            "effective",
        }:
            raise PolicyValidationError("unsupported policy version status filter")
        clean_keyword = str(keyword or "").strip().casefold()
        if len(clean_keyword) > 200:
            raise PolicyValidationError("policy version keyword is too long")
        with self.transaction(immediate=False) as connection:
            items = self._versions_with_projection(
                connection, in_use_versions=in_use_versions
            )
            result: list[dict[str, Any]] = []
            for item in items:
                if clean_status != "all":
                    if clean_status == "effective":
                        if item["status"] not in {"current", "history"}:
                            continue
                    elif item["status"] != clean_status:
                        continue
                if clean_keyword:
                    searchable = " ".join(
                        [
                            str(item.get("version") or ""),
                            str(item.get("note") or ""),
                            " ".join(
                                f"{rule.get('metric_id', '')} {rule.get('name', '')} {rule.get('description', '')}"
                                for rule in item.get("rules", [])
                            ),
                        ]
                    ).casefold()
                    if clean_keyword not in searchable:
                        continue
                result.append(item)
            return result

    def version_detail(self, version: str) -> dict[str, Any]:
        with self.transaction(immediate=False) as connection:
            catalog = self._catalog(connection)
            documents = self._load_version_chain(connection, catalog=catalog)
            document = next(
                (item for item in documents if item["version"] == version), None
            )
            if document is None:
                raise PolicyNotFoundError(f"policy version does not exist: {version}")
            lineage = self._lineage_documents(
                connection, document, catalog=catalog
            )
            previous_document = lineage[-2] if len(lineage) > 1 else None
            previous_version = (
                str(previous_document["version"])
                if previous_document is not None
                else None
            )
            draft = self._read_draft(connection)
            current = self._display_document(
                connection,
                document,
                catalog=catalog,
                fallback_scoring=draft["scoring_config"],
            )
            if previous_document is None:
                previous = {
                    "rules": _copy(current["rules"]),
                    "scoring_config": _copy(current["scoring_config"]),
                    "inspection_schedule": _copy(current["inspection_schedule"]),
                }
            else:
                previous = self._display_document(
                    connection,
                    previous_document,
                    catalog=catalog,
                    fallback_scoring=draft["scoring_config"],
                )
            changes = self._rule_changes(previous, current) if previous_version else []
            scoring_changes = self._scoring_changes(previous, current) if previous_version else []
            schedule_change = self._schedule_change(previous, current) if previous_version else None
            projected = _copy(document)
            projected["activation_mode"] = document.get("activation_mode") or "scheduled"
            projected["inspection_schedule"] = _copy(current["inspection_schedule"])
            return {
                "version": projected,
                "previous_version": previous_version,
                "changes": changes,
                "scoring_changes": scoring_changes,
                "schedule_change": schedule_change,
                "change_count": len(changes) + len(scoring_changes) + int(schedule_change is not None),
                "rules": _copy(current["rules"]),
                "scoring_config": _copy(current["scoring_config"]),
                "inspection_schedule": _copy(current["inspection_schedule"]),
                "metric_count": len(catalog),
            }

    def overview(self) -> dict[str, Any]:
        with self.transaction(immediate=False) as connection:
            catalog = self._catalog(connection)
            draft = self._read_draft(connection)
            documents = self._load_version_chain(connection, catalog=catalog)
            version_by_name = {str(item["version"]): item for item in documents}
            self._validate_draft(
                draft,
                catalog=catalog,
                version_by_name=version_by_name,
                allow_incomplete=True,
            )
            effective = self._effective_document(connection)
            base = self._comparison_document(
                connection,
                str(draft["base_version"]) if draft.get("base_version") else None,
                fallback_rules=draft["rules"],
                fallback_scoring=draft["scoring_config"],
                fallback_schedule=draft["inspection_schedule"],
            )
            rule_changes = self._rule_changes(base, draft)
            scoring_changes = self._scoring_changes(base, draft)
            schedule_change = self._schedule_change(base, draft)
            next_ordinal = int(documents[-1]["ordinal"]) + 1 if documents else 0
            effective_projection = None
            if effective is not None:
                effective_projection = {
                    key: effective.get(key)
                    for key in (
                        "version",
                        "mode",
                        "created_at",
                        "effective_at",
                        "note",
                        "sha256",
                    )
                }
                effective_projection["activation_mode"] = (
                    effective.get("activation_mode") or "scheduled"
                )
                effective_projection["inspection_schedule"] = self._schedule_for_documents(
                    documents, int(effective["ordinal"])
                )
            metric_catalog = [
                {
                    "metric_id": item["metric_id"],
                    **{field: _copy(item.get(field)) for field in FIXED_RULE_FIELDS},
                }
                for item in catalog
            ]
            return {
                "schema_version": POLICY_SCHEMA_VERSION,
                "metric_count": METRIC_COUNT,
                "metric_catalog": metric_catalog,
                "effective_version": effective_projection,
                "published_version_count": len(documents),
                "next_version": f"v1.{next_ordinal}",
                "launch_selection": self._selection_overview(connection),
                "draft": _copy(draft),
                "draft_etag": f'"draft-{draft["draft_revision"]}"',
                "draft_changes": rule_changes,
                "draft_scoring_changes": scoring_changes,
                "draft_schedule_change": schedule_change,
                "draft_change_count": (
                    len(rule_changes) + len(scoring_changes) + int(schedule_change is not None)
                ),
                "read_only": False,
                "write_operations": "server_owned_sqlite",
            }


# Short aliases keep route adapters readable without obscuring ownership.
PolicyStore = WorkbenchPolicyStore
PolicyStoreError = WorkbenchPolicyStoreError


__all__ = [
    "PolicyConflictError",
    "PolicyImmutableError",
    "PolicyInUseError",
    "PolicyNotFoundError",
    "PolicyNotConfiguredError",
    "PolicyStore",
    "PolicyStoreError",
    "PolicyValidationError",
    "WorkbenchPolicyStore",
    "WorkbenchPolicyStoreError",
    "canonical_json",
    "sha256_json",
]
