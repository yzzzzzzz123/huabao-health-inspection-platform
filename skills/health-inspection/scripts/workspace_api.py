"""Contract-bound Workspace API domain service.

Only artifact IDs registered in ``worktree-file-contract.json`` can cross this
boundary.  No public method accepts a server filesystem path.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import shutil
import sqlite3
import tempfile
import threading
import uuid
from dataclasses import dataclass, replace
from datetime import date, datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence


SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parents[2]

import sys

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from shared.runtime_env import (  # noqa: E402
    RELEASE_FIELDS,
    WORKSPACE_VERSION,
    RuntimeEnvironmentError,
    WorkspaceRuntimeConfig,
    load_workspace_config,
)
from state_store import StateStore, StateStoreError, canonical_json  # noqa: E402
from worktree_cli import (  # noqa: E402
    GitWorkspaceError,
    branch_exists,
    checkpoint_worktree,
    create_linked_worktree,
    ensure_git_root,
    list_linked_worktrees,
    registered_worktree,
    remove_daily_worktree,
    run_git,
    worktree_is_clean,
)


CONTRACT_PATH = Path("skills/health-inspection/contracts/worktree-file-contract.json")
ARTIFACT_ID_RE = re.compile(r"^[a-z][a-z0-9_]{0,127}$")
RUN_ID_RE = re.compile(r"^hi-(\d{4}-\d{2}-\d{2})$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
METRIC_ID_RE = re.compile(r"^HI-[0-9]{3}$")
PLATFORM_RELEASE_KEYS = frozenset((*RELEASE_FIELDS, "bound_at"))
STAGE_NAMES = (
    "data_operator",
    "inspector",
    "diagnostician",
    "advisor",
    "auditor",
    "reporter",
)
STAGE_OUTPUTS: dict[str, tuple[str, ...]] = {
    "data_operator": (
        "data_layer_facts",
        "data_layer_evidence_catalog",
        "data_layer_manifest",
    ),
    "inspector": (
        "inspector_inspection_json",
        "inspector_inspection_md",
        "inspector_intelligence",
    ),
    "diagnostician": (
        "diagnostician_diagnosis_json",
        "diagnostician_diagnosis_md",
        "diagnostician_intelligence",
    ),
    "advisor": (
        "advisor_action_plan_json",
        "advisor_action_plan_md",
        "advisor_intelligence",
    ),
    "auditor": (
        "auditor_audit_json",
        "auditor_audit_md",
        "auditor_intelligence",
    ),
    "reporter": (
        "reporter_daily_report_json",
        "reporter_daily_report_md",
        "reporter_intelligence",
    ),
}
STAGE_INPUT_PREFIX: dict[str, str] = {
    "data_operator": "data_layer_",
    "inspector": "inspector_",
    "diagnostician": "diagnostician_",
    "advisor": "advisor_",
    "auditor": "auditor_",
    "reporter": "reporter_",
}


class WorkspaceAPIError(RuntimeError):
    def __init__(
        self,
        status: int,
        code: str,
        message: str,
        *,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.details = dict(details or {})

    def as_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.details:
            value["details"] = self.details
        return {"error": value}


@dataclass(frozen=True, slots=True)
class ArtifactSpec:
    artifact_id: str
    relative_path: str
    writer: str
    write_mode: str
    states: tuple[str, ...]
    media_types: tuple[str, ...]
    max_bytes: int
    schema: str | None
    required: bool
    ui_visible: bool
    sensitivity: str
    dynamic: bool = False


@dataclass(frozen=True, slots=True)
class DynamicArtifactSpec:
    pattern: re.Pattern[str]
    path_template: str
    template: ArtifactSpec


class ArtifactRegistry:
    REQUIRED_FIELDS = frozenset(
        {
            "writer",
            "write_mode",
            "state",
            "media",
            "max_bytes",
            "schema",
            "required",
            "ui",
            "sensitivity",
        }
    )

    def __init__(self, contract_path: Path) -> None:
        self.contract_path = contract_path.resolve()
        try:
            raw_bytes = self.contract_path.read_bytes()
            document = json.loads(raw_bytes.decode("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise WorkspaceAPIError(500, "invalid_contract", "artifact contract is unreadable") from exc
        if not isinstance(document, dict) or document.get("schema_version") != "2.0":
            raise WorkspaceAPIError(500, "invalid_contract", "artifact contract schema must be 2.0")
        if document.get("workspace_version") != WORKSPACE_VERSION:
            raise WorkspaceAPIError(500, "invalid_contract", "workspace version mismatch")
        roots = document.get("runtime_roots")
        if roots != ["input", "context", "result"]:
            raise WorkspaceAPIError(500, "invalid_contract", "runtime roots are not fixed")
        self.workspace_version = str(document["workspace_version"])
        self.contract_sha256 = hashlib.sha256(raw_bytes).hexdigest()
        self.static: dict[str, ArtifactSpec] = {}
        seen_paths: set[str] = set()
        for raw in document.get("artifacts", []):
            spec = self._parse_static(raw)
            if spec.artifact_id in self.static or spec.relative_path in seen_paths:
                raise WorkspaceAPIError(500, "invalid_contract", "duplicate artifact ID or path")
            self.static[spec.artifact_id] = spec
            seen_paths.add(spec.relative_path)
        self.dynamic: list[DynamicArtifactSpec] = []
        patterns: set[str] = set()
        for raw in document.get("dynamic_artifacts", []):
            dynamic = self._parse_dynamic(raw)
            if dynamic.pattern.pattern in patterns:
                raise WorkspaceAPIError(500, "invalid_contract", "duplicate dynamic artifact pattern")
            patterns.add(dynamic.pattern.pattern)
            self.dynamic.append(dynamic)
        required_receipts = document.get("required_attempt_receipts")
        if not isinstance(required_receipts, list) or len(required_receipts) != 6:
            raise WorkspaceAPIError(500, "invalid_contract", "six attempt receipt rules are required")
        try:
            self.required_attempt_receipts = tuple(
                re.compile(f"^(?:{item})$") for item in required_receipts if isinstance(item, str)
            )
        except re.error as exc:
            raise WorkspaceAPIError(500, "invalid_contract", "attempt receipt regex is invalid") from exc
        if len(self.required_attempt_receipts) != 6:
            raise WorkspaceAPIError(500, "invalid_contract", "attempt receipt rules must be strings")

    @staticmethod
    def _safe_relative_path(value: Any, *, template: bool = False) -> str:
        if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
            raise WorkspaceAPIError(500, "invalid_contract", "artifact path is invalid")
        check = value
        if template:
            check = re.sub(r"\{[a-z_]+\}", "x", check)
        pure = PurePosixPath(check)
        if pure.is_absolute() or ".." in pure.parts or pure.parts[0] not in {
            "input",
            "context",
            "result",
        }:
            raise WorkspaceAPIError(500, "invalid_contract", "artifact path escapes runtime roots")
        return value

    @classmethod
    def _common(cls, raw: Mapping[str, Any]) -> dict[str, Any]:
        if not cls.REQUIRED_FIELDS.issubset(raw):
            raise WorkspaceAPIError(500, "invalid_contract", "artifact fields are incomplete")
        writer = raw["writer"]
        write_mode = raw["write_mode"]
        states = raw["state"]
        media = raw["media"]
        sensitivity = raw["sensitivity"]
        if writer not in {"server", "dolphin"}:
            raise WorkspaceAPIError(500, "invalid_contract", "artifact writer is invalid")
        if write_mode not in {"create_once", "server_create_once", "server_replace"}:
            raise WorkspaceAPIError(500, "invalid_contract", "artifact write mode is invalid")
        if not isinstance(states, list) or not states or not all(isinstance(x, str) for x in states):
            raise WorkspaceAPIError(500, "invalid_contract", "artifact states are invalid")
        if not isinstance(media, list) or not media or not all(isinstance(x, str) for x in media):
            raise WorkspaceAPIError(500, "invalid_contract", "artifact media types are invalid")
        if not isinstance(raw["max_bytes"], int) or not 1 <= raw["max_bytes"] <= 32 * 1024 * 1024:
            raise WorkspaceAPIError(500, "invalid_contract", "artifact max_bytes is invalid")
        if raw["schema"] is not None and not isinstance(raw["schema"], str):
            raise WorkspaceAPIError(500, "invalid_contract", "artifact schema is invalid")
        if not isinstance(raw["required"], bool) or not isinstance(raw["ui"], bool):
            raise WorkspaceAPIError(500, "invalid_contract", "artifact flags are invalid")
        if sensitivity not in {"business", "internal", "restricted"}:
            raise WorkspaceAPIError(500, "invalid_contract", "artifact sensitivity is invalid")
        return {
            "writer": writer,
            "write_mode": write_mode,
            "states": tuple(states),
            "media_types": tuple(item.lower() for item in media),
            "max_bytes": raw["max_bytes"],
            "schema": raw["schema"],
            "required": raw["required"],
            "ui_visible": raw["ui"],
            "sensitivity": sensitivity,
        }

    @classmethod
    def _parse_static(cls, raw: Any) -> ArtifactSpec:
        if not isinstance(raw, dict) or not isinstance(raw.get("id"), str):
            raise WorkspaceAPIError(500, "invalid_contract", "static artifact is invalid")
        artifact_id = raw["id"]
        if not ARTIFACT_ID_RE.fullmatch(artifact_id):
            raise WorkspaceAPIError(500, "invalid_contract", "static artifact ID is invalid")
        relative_path = cls._safe_relative_path(raw.get("path"))
        return ArtifactSpec(artifact_id, relative_path, **cls._common(raw))

    @classmethod
    def _parse_dynamic(cls, raw: Any) -> DynamicArtifactSpec:
        if not isinstance(raw, dict):
            raise WorkspaceAPIError(500, "invalid_contract", "dynamic artifact is invalid")
        pattern_text = raw.get("id_pattern")
        if not isinstance(pattern_text, str) or not pattern_text.startswith("^") or not pattern_text.endswith("$"):
            raise WorkspaceAPIError(500, "invalid_contract", "dynamic artifact pattern is invalid")
        try:
            pattern = re.compile(pattern_text)
        except re.error as exc:
            raise WorkspaceAPIError(500, "invalid_contract", "dynamic artifact pattern is invalid") from exc
        path_template = cls._safe_relative_path(raw.get("path_template"), template=True)
        template = ArtifactSpec("dynamic", path_template, **cls._common(raw), dynamic=True)
        return DynamicArtifactSpec(pattern, path_template, template)

    def resolve(self, artifact_id: str) -> ArtifactSpec:
        if not ARTIFACT_ID_RE.fullmatch(artifact_id):
            raise WorkspaceAPIError(404, "artifact_not_registered", "artifact ID is not registered")
        static = self.static.get(artifact_id)
        if static is not None:
            return static
        for dynamic in self.dynamic:
            match = dynamic.pattern.fullmatch(artifact_id)
            if match is None:
                continue
            try:
                relative_path = dynamic.path_template.format(**match.groupdict())
            except KeyError as exc:
                raise WorkspaceAPIError(500, "invalid_contract", "dynamic path template is invalid") from exc
            self._safe_relative_path(relative_path)
            return replace(dynamic.template, artifact_id=artifact_id, relative_path=relative_path)
        raise WorkspaceAPIError(404, "artifact_not_registered", "artifact ID is not registered")


def _canonical_json_bytes(value: Any) -> bytes:
    return (canonical_json(value) + "\n").encode("utf-8")


def _pretty_json_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _now_shanghai() -> str:
    return datetime.now(timezone(timedelta(hours=8))).isoformat(timespec="milliseconds")


def _parse_json_bytes(value: bytes, *, description: str) -> Any:
    try:
        text = value.decode("utf-8")
        return json.loads(
            text,
            parse_constant=lambda item: (_ for _ in ()).throw(ValueError(item)),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise WorkspaceAPIError(422, "invalid_artifact", f"{description} must be strict UTF-8 JSON") from exc


class WorkspaceService:
    def __init__(self, project_root: Path) -> None:
        self.project_root = project_root.resolve()
        self.config: WorkspaceRuntimeConfig = load_workspace_config(self.project_root)
        self.registry = ArtifactRegistry(self.project_root / CONTRACT_PATH)
        self.store = StateStore(self.project_root)
        self.worktrees_root = (self.project_root / "worktrees").resolve()
        self.history_root = (self.project_root / "history").resolve()
        self.worktrees_root.mkdir(parents=True, exist_ok=True)
        self.history_root.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        ensure_git_root(self.project_root)

    def get_config(self) -> dict[str, Any]:
        return {
            **self.config.public_projection(),
            "artifact_contract_sha256": self.registry.contract_sha256,
        }

    @staticmethod
    def _business_date(value: Any) -> str:
        if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
            raise WorkspaceAPIError(422, "invalid_business_date", "business_date must be YYYY-MM-DD")
        try:
            parsed = date.fromisoformat(value)
        except ValueError as exc:
            raise WorkspaceAPIError(422, "invalid_business_date", "business_date is not a real date") from exc
        if parsed.isoformat() != value:
            raise WorkspaceAPIError(422, "invalid_business_date", "business_date is not canonical")
        return value

    def _select_release(self, request: Mapping[str, Any]) -> Any:
        has_id = "release_id" in request
        has_document = "platform_release" in request
        if has_id == has_document:
            raise WorkspaceAPIError(
                422,
                "invalid_release_request",
                "provide exactly one of release_id or platform_release",
            )
        try:
            if has_id:
                release_id = request["release_id"]
                if not isinstance(release_id, str):
                    raise RuntimeEnvironmentError("release_id must be a string")
                return self.config.release_by_id(release_id)
            platform_release = request["platform_release"]
            if not isinstance(platform_release, dict):
                raise RuntimeEnvironmentError("platform_release must be an object")
            if "bound_at" in platform_release and not isinstance(platform_release["bound_at"], str):
                raise RuntimeEnvironmentError("platform_release.bound_at must be a string when supplied")
            return self.config.match_platform_release(platform_release)
        except RuntimeEnvironmentError as exc:
            raise WorkspaceAPIError(422, "release_not_registered", str(exc)) from exc

    @staticmethod
    def _run_response(run: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "run_id": run["run_id"],
            "business_date": run["business_date"],
            "incarnation_id": run["incarnation_id"],
            "platform_release_sha256": run["platform_release_sha256"],
            "platform_release": run["platform_release"],
            "status": run["status"],
            "workspace_version": run["workspace_version"],
        }

    def _run_or_404(
        self,
        run_id: str,
        *,
        connection: sqlite3.Connection | None = None,
    ) -> dict[str, Any]:
        if RUN_ID_RE.fullmatch(run_id) is None:
            raise WorkspaceAPIError(404, "workspace_not_found", "workspace does not exist")
        run = self.store.get_run(run_id, connection=connection)
        if run is None:
            raise WorkspaceAPIError(404, "workspace_not_found", "workspace does not exist")
        return run

    @staticmethod
    def _authorize(run: Mapping[str, Any], incarnation_id: str, release_sha256: str) -> None:
        if not incarnation_id or not release_sha256:
            raise WorkspaceAPIError(
                428,
                "workspace_binding_required",
                "X-Workspace-Incarnation and X-Platform-Release-SHA256 are required",
            )
        if not hmac.compare_digest(str(run["incarnation_id"]), incarnation_id) or not hmac.compare_digest(
            str(run["platform_release_sha256"]), release_sha256
        ):
            raise WorkspaceAPIError(409, "workspace_binding_mismatch", "workspace binding does not match")

    def _workspace_path(self, run: Mapping[str, Any]) -> Path:
        expected = (self.worktrees_root / str(run["business_date"])).resolve()
        if expected.parent != self.worktrees_root or run["workspace_path"] != f"worktrees/{run['business_date']}":
            raise WorkspaceAPIError(500, "workspace_identity_corrupt", "stored workspace identity is invalid")
        return expected

    def _archive_path(self, run: Mapping[str, Any]) -> Path:
        expected = (self.history_root / str(run["business_date"])).resolve()
        if expected.parent != self.history_root:
            raise WorkspaceAPIError(500, "workspace_identity_corrupt", "stored archive identity is invalid")
        return expected

    @staticmethod
    def _target_path(root: Path, relative_path: str) -> Path:
        root = root.resolve()
        target = (root / Path(*PurePosixPath(relative_path).parts)).resolve(strict=False)
        try:
            target.relative_to(root)
        except ValueError as exc:
            raise WorkspaceAPIError(500, "artifact_path_escape", "artifact path escapes workspace") from exc
        current = root
        for part in PurePosixPath(relative_path).parts[:-1]:
            current = current / part
            if current.exists() and current.is_symlink():
                raise WorkspaceAPIError(409, "artifact_symlink", "artifact parent may not be a symlink")
        if target.exists() and target.is_symlink():
            raise WorkspaceAPIError(409, "artifact_symlink", "artifact may not be a symlink")
        return target

    @staticmethod
    def _atomic_write(target: Path, content: bytes) -> None:
        target.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, target)
        finally:
            temporary.unlink(missing_ok=True)

    def _record_server_artifact(
        self,
        connection: sqlite3.Connection,
        *,
        run: Mapping[str, Any],
        artifact_id: str,
        content: bytes,
        media_type: str,
    ) -> dict[str, Any]:
        spec = self.registry.resolve(artifact_id)
        if spec.writer != "server" or media_type not in spec.media_types or len(content) > spec.max_bytes:
            raise WorkspaceAPIError(500, "invalid_server_artifact", "server artifact violates registry")
        target = self._target_path(self._workspace_path(run), spec.relative_path)
        digest = _sha256(content)
        existing = self.store.get_artifact(run["run_id"], artifact_id, connection=connection)
        replace_allowed = spec.write_mode == "server_replace"
        if existing is not None and not replace_allowed:
            if (
                existing["sha256"] != digest
                or existing["bytes"] != len(content)
                or not target.is_file()
                or _sha256(target.read_bytes()) != digest
            ):
                raise WorkspaceAPIError(409, "server_artifact_drift", f"{artifact_id} drifted")
            return existing
        self._atomic_write(target, content)
        self.store.put_artifact(
            connection,
            run_id=run["run_id"],
            artifact_id=artifact_id,
            relative_path=spec.relative_path,
            sha256=digest,
            byte_count=len(content),
            media_type=media_type,
            writer="server",
            created_at=_now_shanghai(),
            replace=replace_allowed,
        )
        return {
            "run_id": run["run_id"],
            "artifact_id": artifact_id,
            "relative_path": spec.relative_path,
            "sha256": digest,
            "bytes": len(content),
            "media_type": media_type,
            "writer": "server",
        }

    @staticmethod
    def _source_hash_receipt(worktree: Path) -> bytes:
        completed = run_git(worktree, ["ls-files", "-z"])
        lines: list[str] = []
        for relative in sorted(item for item in completed.stdout.split("\0") if item):
            if PurePosixPath(relative).parts[0] in {"input", "context", "result"}:
                continue
            path = worktree / Path(*PurePosixPath(relative).parts)
            if path.is_symlink() or not path.is_file():
                raise WorkspaceAPIError(409, "snapshot_file_invalid", "snapshot contains a link or non-file")
            lines.append(f"{_sha256(path.read_bytes())}  {relative}")
        return (("\n".join(lines) + "\n") if lines else "").encode("utf-8")

    def _initialize_runtime_receipts(
        self,
        worktree: Path,
        *,
        run_id: str,
        business_date: str,
        incarnation_id: str,
        created_at: str,
    ) -> None:
        runtime = (worktree / ".runtime").resolve()
        if runtime.parent != worktree.resolve():
            raise WorkspaceAPIError(500, "runtime_path_escape", "runtime path escapes worktree")
        environment = runtime / "environment"
        receipts = runtime / "dingtalk" / "receipts"
        locks = runtime / "dingtalk" / "locks"
        for directory in (environment, receipts, locks):
            directory.mkdir(parents=True, exist_ok=True)
            if directory.is_symlink():
                raise WorkspaceAPIError(409, "runtime_symlink", "runtime directory is a symlink")
        venv_receipt = {
            "schema_version": "1.0",
            "run_id": run_id,
            "business_date": business_date,
            "incarnation_id": incarnation_id,
            "captured_at": created_at,
            "execution_plane": "hosted_dolphin",
            "agent_venv": "not_applicable",
            "server_runtime": "python>=3.11-stdlib-only",
        }
        self._atomic_write(environment / "venv.json", _pretty_json_bytes(venv_receipt))

    def _verified_history_artifact(
        self,
        *,
        source_run: Mapping[str, Any],
        archive_manifest_records: Mapping[str, Mapping[str, Any]],
        artifact_id: str,
        connection: sqlite3.Connection,
        required: bool,
    ) -> tuple[Any | None, str | None]:
        indexed = self.store.get_artifact(
            source_run["run_id"],
            artifact_id,
            connection=connection,
        )
        if indexed is None:
            if required:
                raise WorkspaceAPIError(
                    409,
                    "historical_artifact_missing",
                    f"sealed history is missing {artifact_id}",
                )
            return None, None
        manifest_record = archive_manifest_records.get(artifact_id)
        if not isinstance(manifest_record, Mapping):
            raise WorkspaceAPIError(
                409,
                "historical_manifest_binding",
                f"archive manifest does not bind {artifact_id}",
            )
        expected_record = {
            "id": artifact_id,
            "path": indexed["relative_path"],
            "sha256": indexed["sha256"],
            "bytes": indexed["bytes"],
            "media_type": indexed["media_type"],
        }
        for key, value in expected_record.items():
            if manifest_record.get(key) != value:
                raise WorkspaceAPIError(
                    409,
                    "historical_manifest_binding",
                    f"archive manifest {artifact_id}.{key} differs",
                )
        archive = self._archive_path(source_run)
        spec = self.registry.resolve(artifact_id)
        path = self._target_path(archive, spec.relative_path)
        if not path.is_file() or path.is_symlink():
            raise WorkspaceAPIError(
                409,
                "historical_artifact_missing",
                f"archived {artifact_id} is missing",
            )
        content = path.read_bytes()
        if len(content) != indexed["bytes"] or _sha256(content) != indexed["sha256"]:
            raise WorkspaceAPIError(
                409,
                "historical_artifact_hash_mismatch",
                f"archived {artifact_id} failed hash verification",
            )
        return _parse_json_bytes(content, description=f"historical {artifact_id}"), indexed["sha256"]

    def _historical_runs_projection(
        self,
        connection: sqlite3.Connection,
        *,
        business_date: str,
    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        current = date.fromisoformat(business_date)
        due_dates = (
            (1, "next_day", (current - timedelta(days=1)).isoformat()),
            (6, "day_7", (current - timedelta(days=6)).isoformat()),
        )
        projection: list[dict[str, Any]] = []
        for age_days, review_window, source_date in due_dates:
            source_run = self.store.get_run_by_business_date(source_date, connection=connection)
            if source_run is None or source_run["status"] != "sealed":
                continue
            if source_run.get("archive_path") != f"history/{source_date}":
                raise WorkspaceAPIError(
                    409,
                    "historical_archive_identity",
                    "sealed historical run has no bound archive",
                )
            archive = self._archive_path(source_run)
            manifest_index = self.store.get_artifact(
                source_run["run_id"],
                "orchestrator_archive_manifest",
                connection=connection,
            )
            if manifest_index is None:
                raise WorkspaceAPIError(
                    409,
                    "historical_archive_manifest_missing",
                    "sealed historical run has no indexed archive manifest",
                )
            manifest_spec = self.registry.resolve("orchestrator_archive_manifest")
            manifest_path = self._target_path(archive, manifest_spec.relative_path)
            if not manifest_path.is_file() or manifest_path.is_symlink():
                raise WorkspaceAPIError(
                    409,
                    "historical_archive_manifest_missing",
                    "sealed historical archive manifest is missing",
                )
            manifest_bytes = manifest_path.read_bytes()
            if (
                len(manifest_bytes) != manifest_index["bytes"]
                or _sha256(manifest_bytes) != manifest_index["sha256"]
            ):
                raise WorkspaceAPIError(
                    409,
                    "historical_archive_manifest_hash_mismatch",
                    "sealed historical archive manifest failed hash verification",
                )
            manifest = _parse_json_bytes(
                manifest_bytes,
                description="historical archive manifest",
            )
            if not isinstance(manifest, dict):
                raise WorkspaceAPIError(409, "historical_archive_manifest_invalid", "archive manifest is invalid")
            identity = {
                "run_id": source_run["run_id"],
                "business_date": source_date,
                "incarnation_id": source_run["incarnation_id"],
                "platform_release_sha256": source_run["platform_release_sha256"],
                "platform_release": source_run["platform_release"],
            }
            for key, value in identity.items():
                if manifest.get(key) != value:
                    raise WorkspaceAPIError(
                        409,
                        "historical_archive_identity",
                        f"historical archive manifest {key} differs",
                    )
            raw_records = manifest.get("artifacts")
            if not isinstance(raw_records, list):
                raise WorkspaceAPIError(409, "historical_archive_manifest_invalid", "artifact list is invalid")
            manifest_records: dict[str, Mapping[str, Any]] = {}
            for record in raw_records:
                if not isinstance(record, Mapping) or not isinstance(record.get("id"), str):
                    raise WorkspaceAPIError(
                        409,
                        "historical_archive_manifest_invalid",
                        "historical artifact record is invalid",
                    )
                if record["id"] in manifest_records:
                    raise WorkspaceAPIError(
                        409,
                        "historical_archive_manifest_invalid",
                        "historical artifact IDs are duplicated",
                    )
                manifest_records[record["id"]] = record
            facts, facts_sha256 = self._verified_history_artifact(
                source_run=source_run,
                archive_manifest_records=manifest_records,
                artifact_id="data_layer_facts",
                connection=connection,
                required=True,
            )
            action_plan, action_plan_sha256 = self._verified_history_artifact(
                source_run=source_run,
                archive_manifest_records=manifest_records,
                artifact_id="advisor_action_plan_json",
                connection=connection,
                required=False,
            )
            projection.append(
                {
                    "source_run_id": source_run["run_id"],
                    "source_business_date": source_date,
                    "age_days": age_days,
                    "review_window": review_window,
                    "platform_release_sha256": source_run["platform_release_sha256"],
                    "archive_manifest_sha256": manifest_index["sha256"],
                    "facts_sha256": facts_sha256,
                    "facts": facts,
                    "action_plan_sha256": action_plan_sha256,
                    "action_plan": action_plan,
                }
            )
        query = {
            "schema_version": "1.0",
            "timezone": "Asia/Shanghai",
            "maximum_date_identities": 7,
            "queried_business_dates": [item[2] for item in due_dates],
            "trigger_offsets_days": [1, 6],
        }
        return query, projection

    def create_workspace(self, request: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(request, Mapping):
            raise WorkspaceAPIError(400, "invalid_request", "request must be a JSON object")
        allowed = {"business_date", "release_id", "platform_release"}
        if not set(request).issubset(allowed) or "business_date" not in request:
            raise WorkspaceAPIError(422, "invalid_request", "request contains unexpected or missing fields")
        business_date = self._business_date(request["business_date"])
        release = self._select_release(request)
        run_id = f"hi-{business_date}"
        branch = f"run/health-inspection/daily/{business_date}"
        worktree = self.worktrees_root / business_date
        incarnation_id = str(uuid.uuid4())
        created_at = _now_shanghai()
        platform_release = {**release.platform_release_core(), "bound_at": created_at}
        platform_release_bytes = _canonical_json_bytes(platform_release)
        release_sha256 = _sha256(platform_release_bytes)
        provisional = {
            "run_id": run_id,
            "business_date": business_date,
            "incarnation_id": incarnation_id,
            "release_id": release.release_id,
            "platform_release": platform_release,
            "platform_release_sha256": release_sha256,
            "workspace_version": self.registry.workspace_version,
            "status": "creating",
            "workspace_path": f"worktrees/{business_date}",
            "branch_name": branch,
            "created_at": created_at,
        }
        git_created = False
        with self._lock:
            try:
                with self.store.transaction() as connection:
                    if self.store.get_run_by_business_date(business_date, connection=connection):
                        raise WorkspaceAPIError(409, "business_date_exists", "business date already exists")
                    active = self.store.get_active_run(connection=connection)
                    if active is not None:
                        raise WorkspaceAPIError(
                            409,
                            "active_workspace_exists",
                            "another workspace is active",
                            details={"run_id": active["run_id"]},
                        )
                    if worktree.exists() or registered_worktree(self.project_root, worktree):
                        raise WorkspaceAPIError(409, "worktree_residue", "daily worktree residue exists")
                    if branch_exists(self.project_root, branch):
                        raise WorkspaceAPIError(409, "branch_residue", "daily branch residue exists")
                    historical_query, historical_runs = self._historical_runs_projection(
                        connection,
                        business_date=business_date,
                    )
                    self.store.insert_run(connection, provisional)
                    self.store.append_event(
                        connection,
                        run_id=run_id,
                        business_date=business_date,
                        incarnation_id=incarnation_id,
                        event_type="workspace_creating",
                        occurred_at=created_at,
                        payload={"release_id": release.release_id, "platform_release_sha256": release_sha256},
                    )
                    base_commit = create_linked_worktree(
                        self.project_root,
                        business_date=business_date,
                        run_id=run_id,
                        branch=branch,
                        worktree_path=worktree,
                    )
                    git_created = True
                    self.store.update_run(connection, run_id, base_commit=base_commit)
                    run = self._run_or_404(run_id, connection=connection)
                    self._initialize_runtime_receipts(
                        worktree,
                        run_id=run_id,
                        business_date=business_date,
                        incarnation_id=incarnation_id,
                        created_at=created_at,
                    )
                    self._record_server_artifact(
                        connection,
                        run=run,
                        artifact_id="platform_release",
                        content=platform_release_bytes,
                        media_type="application/json",
                    )
                    run_context = {
                        "schema_version": "1.0",
                        "workspace_version": self.registry.workspace_version,
                        "run_id": run_id,
                        "business_date": business_date,
                        "incarnation_id": incarnation_id,
                        "base_commit": base_commit,
                        "platform_release_sha256": release_sha256,
                        "created_at": created_at,
                        "scope": {
                            "timezone": "Asia/Shanghai",
                            "currency": "CNY",
                            "dimensions": ["traffic", "conversion", "product"],
                        },
                        "historical_query": historical_query,
                        "historical_runs": historical_runs,
                    }
                    self._record_server_artifact(
                        connection,
                        run=run,
                        artifact_id="run_context",
                        content=_pretty_json_bytes(run_context),
                        media_type="application/json",
                    )
                    run_state = {
                        "schema_version": "1.0",
                        "run_id": run_id,
                        "business_date": business_date,
                        "incarnation_id": incarnation_id,
                        "status": "open",
                        "platform_release_sha256": release_sha256,
                        "created_at": created_at,
                    }
                    self._record_server_artifact(
                        connection,
                        run=run,
                        artifact_id="run_state",
                        content=_pretty_json_bytes(run_state),
                        media_type="application/json",
                    )
                    environment = {
                        "schema_version": "1.0",
                        "run_id": run_id,
                        "business_date": business_date,
                        "captured_at": created_at,
                        "source_snapshot_commit": base_commit,
                        "runtime": {
                            "python": sys.version.split()[0],
                            "implementation": sys.implementation.name,
                            "stdlib_only": True,
                        },
                    }
                    self._record_server_artifact(
                        connection,
                        run=run,
                        artifact_id="environment_receipt",
                        content=_pretty_json_bytes(environment),
                        media_type="application/json",
                    )
                    self._record_server_artifact(
                        connection,
                        run=run,
                        artifact_id="environment_files_sha256",
                        content=self._source_hash_receipt(worktree),
                        media_type="text/plain",
                    )
                    self.store.update_run(connection, run_id, status="open")
                    self.store.append_event(
                        connection,
                        run_id=run_id,
                        business_date=business_date,
                        incarnation_id=incarnation_id,
                        event_type="workspace_created",
                        occurred_at=_now_shanghai(),
                        payload={"base_commit": base_commit, "platform_release_sha256": release_sha256},
                    )
                    completed = self._run_or_404(run_id, connection=connection)
                return self._run_response(completed)
            except WorkspaceAPIError:
                if git_created:
                    try:
                        remove_daily_worktree(
                            self.project_root,
                            business_date=business_date,
                            run_id=run_id,
                            branch=branch,
                            worktree_path=worktree,
                        )
                    except GitWorkspaceError:
                        pass
                raise
            except (GitWorkspaceError, StateStoreError, sqlite3.Error, OSError) as exc:
                if git_created:
                    try:
                        remove_daily_worktree(
                            self.project_root,
                            business_date=business_date,
                            run_id=run_id,
                            branch=branch,
                            worktree_path=worktree,
                        )
                    except GitWorkspaceError:
                        pass
                raise WorkspaceAPIError(500, "workspace_create_failed", str(exc)) from exc

    @staticmethod
    def _normalize_media_type(value: str) -> str:
        return value.partition(";")[0].strip().lower()

    def _validate_artifact_content(
        self,
        *,
        run: Mapping[str, Any],
        spec: ArtifactSpec,
        content: bytes,
        media_type: str,
    ) -> None:
        if len(content) > spec.max_bytes:
            raise WorkspaceAPIError(
                413,
                "artifact_too_large",
                "artifact exceeds contract maximum",
                details={"max_bytes": spec.max_bytes},
            )
        if media_type not in spec.media_types:
            raise WorkspaceAPIError(
                415,
                "artifact_media_type_mismatch",
                "Content-Type is not allowed for this artifact",
            )
        document: Any = None
        if media_type == "application/json":
            document = _parse_json_bytes(content, description=spec.artifact_id)
        elif media_type == "application/x-ndjson":
            try:
                text = content.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise WorkspaceAPIError(422, "invalid_artifact", "NDJSON must be UTF-8") from exc
            for number, line in enumerate(text.splitlines(), start=1):
                if not line.strip():
                    continue
                try:
                    json.loads(line)
                except json.JSONDecodeError as exc:
                    raise WorkspaceAPIError(
                        422,
                        "invalid_artifact",
                        f"NDJSON line {number} is invalid",
                    ) from exc
        else:
            try:
                text = content.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise WorkspaceAPIError(422, "invalid_artifact", "text artifact must be UTF-8") from exc
            if "\x00" in text:
                raise WorkspaceAPIError(422, "invalid_artifact", "text artifact contains NUL")
        if isinstance(document, dict):
            expected = {
                "run_id": run["run_id"],
                "business_date": run["business_date"],
                "incarnation_id": run["incarnation_id"],
                "platform_release_sha256": run["platform_release_sha256"],
            }
            for key, value in expected.items():
                if key in document and document[key] != value:
                    raise WorkspaceAPIError(409, "artifact_identity_mismatch", f"{key} does not match")
            if "platform_release" in document and document["platform_release"] != run["platform_release"]:
                raise WorkspaceAPIError(409, "artifact_release_mismatch", "platform_release does not match")

    def put_artifact(
        self,
        run_id: str,
        artifact_id: str,
        *,
        incarnation_id: str,
        release_sha256: str,
        content_type: str,
        content: bytes,
        content_sha256: str,
        if_none_match: str,
    ) -> dict[str, Any]:
        if if_none_match.strip() != "*":
            raise WorkspaceAPIError(428, "create_once_required", "If-None-Match: * is required")
        if not SHA256_RE.fullmatch(content_sha256):
            raise WorkspaceAPIError(
                422,
                "content_sha256_invalid",
                "X-Content-SHA256 must be a lowercase SHA-256",
            )
        calculated_sha256 = _sha256(content)
        if not hmac.compare_digest(content_sha256, calculated_sha256):
            raise WorkspaceAPIError(
                409,
                "content_sha256_mismatch",
                "X-Content-SHA256 does not match the request bytes",
            )
        spec = self.registry.resolve(artifact_id)
        if spec.writer != "dolphin" or spec.write_mode != "create_once":
            raise WorkspaceAPIError(403, "artifact_server_owned", "artifact is server-owned")
        media_type = self._normalize_media_type(content_type)
        with self._lock, self.store.transaction() as connection:
            run = self._run_or_404(run_id, connection=connection)
            self._authorize(run, incarnation_id, release_sha256)
            if run["status"] not in spec.states or run["status"] != "open":
                raise WorkspaceAPIError(409, "workspace_not_writable", "workspace is not writable")
            self._validate_artifact_content(
                run=run,
                spec=spec,
                content=content,
                media_type=media_type,
            )
            digest = calculated_sha256
            target = self._target_path(self._workspace_path(run), spec.relative_path)
            existing = self.store.get_artifact(run_id, artifact_id, connection=connection)
            if existing is not None:
                if (
                    existing["sha256"] == digest
                    and existing["bytes"] == len(content)
                    and existing["media_type"] == media_type
                    and target.is_file()
                    and _sha256(target.read_bytes()) == digest
                ):
                    return self._artifact_projection(existing, spec, created=False)
                raise WorkspaceAPIError(409, "artifact_overwrite_forbidden", "artifact already exists")
            if target.exists():
                if not target.is_file() or _sha256(target.read_bytes()) != digest:
                    raise WorkspaceAPIError(409, "artifact_residue", "unindexed artifact residue differs")
                self.store.put_artifact(
                    connection,
                    run_id=run_id,
                    artifact_id=artifact_id,
                    relative_path=spec.relative_path,
                    sha256=digest,
                    byte_count=len(content),
                    media_type=media_type,
                    writer="dolphin",
                    created_at=_now_shanghai(),
                )
                recovered = self.store.get_artifact(run_id, artifact_id, connection=connection)
                assert recovered is not None
                return self._artifact_projection(recovered, spec, created=False)
            self._atomic_write(target, content)
            occurred_at = _now_shanghai()
            self.store.put_artifact(
                connection,
                run_id=run_id,
                artifact_id=artifact_id,
                relative_path=spec.relative_path,
                sha256=digest,
                byte_count=len(content),
                media_type=media_type,
                writer="dolphin",
                created_at=occurred_at,
            )
            self.store.append_event(
                connection,
                run_id=run_id,
                business_date=run["business_date"],
                incarnation_id=run["incarnation_id"],
                event_type="artifact_created",
                occurred_at=occurred_at,
                payload={"artifact_id": artifact_id, "sha256": digest, "bytes": len(content)},
            )
            artifact = self.store.get_artifact(run_id, artifact_id, connection=connection)
            assert artifact is not None
            return self._artifact_projection(artifact, spec, created=True)

    @staticmethod
    def _artifact_projection(
        artifact: Mapping[str, Any],
        spec: ArtifactSpec,
        *,
        created: bool | None = None,
    ) -> dict[str, Any]:
        value = {
            "id": artifact["artifact_id"],
            "sha256": artifact["sha256"],
            "bytes": artifact["bytes"],
            "media_type": artifact["media_type"],
            "ui_visible": spec.ui_visible,
        }
        if created is not None:
            value["created"] = created
        return value

    def _artifact_source(self, run: Mapping[str, Any], spec: ArtifactSpec) -> Path:
        worktree = self._workspace_path(run)
        target = self._target_path(worktree, spec.relative_path)
        if target.is_file():
            return target
        if run["status"] == "sealed":
            archive = self._archive_path(run)
            archived = self._target_path(archive, spec.relative_path)
            if archived.is_file():
                return archived
        raise WorkspaceAPIError(409, "artifact_file_missing", "artifact file is missing")

    def get_artifact(
        self,
        run_id: str,
        artifact_id: str,
        *,
        incarnation_id: str,
        release_sha256: str,
    ) -> tuple[bytes, str, dict[str, Any]]:
        run = self._run_or_404(run_id)
        self._authorize(run, incarnation_id, release_sha256)
        spec = self.registry.resolve(artifact_id)
        artifact = self.store.get_artifact(run_id, artifact_id)
        if artifact is None:
            raise WorkspaceAPIError(404, "artifact_not_found", "artifact does not exist")
        if artifact["relative_path"] != spec.relative_path:
            raise WorkspaceAPIError(500, "artifact_index_corrupt", "artifact path differs from registry")
        content = self._artifact_source(run, spec).read_bytes()
        if len(content) != artifact["bytes"] or _sha256(content) != artifact["sha256"]:
            raise WorkspaceAPIError(409, "artifact_hash_mismatch", "artifact hash verification failed")
        return content, artifact["media_type"], self._artifact_projection(artifact, spec)

    def _stage_statuses(self, artifact_ids: set[str]) -> dict[str, str]:
        result: dict[str, str] = {}
        for stage in STAGE_NAMES:
            outputs = STAGE_OUTPUTS[stage]
            if all(item in artifact_ids for item in outputs):
                result[stage] = "completed"
                continue
            prefix = STAGE_INPUT_PREFIX[stage]
            attempt_prefix = f"{stage}_attempt_"
            if stage == "data_operator":
                attempt_prefix = "data_operator_attempt_"
            active = any(item.startswith(prefix) or item.startswith(attempt_prefix) for item in artifact_ids)
            result[stage] = "in_progress" if active else "pending"
        return result

    def _workspace_projection(
        self,
        run: Mapping[str, Any],
        artifacts: Sequence[Mapping[str, Any]],
    ) -> dict[str, Any]:
        projected = []
        ids: set[str] = set()
        for artifact in artifacts:
            spec = self.registry.resolve(str(artifact["artifact_id"]))
            ids.add(str(artifact["artifact_id"]))
            projected.append(self._artifact_projection(artifact, spec))
        return {
            **self._run_response(run),
            "active": bool(run["active"]),
            "created_at": run["created_at"],
            "sealed_at": run["sealed_at"],
            "checkpoint_commit": run["checkpoint_commit"],
            "stage_statuses": self._stage_statuses(ids),
            "artifacts": projected,
        }

    def get_workspace(
        self,
        run_id: str,
        *,
        incarnation_id: str | None = None,
        release_sha256: str | None = None,
    ) -> dict[str, Any]:
        run = self._run_or_404(run_id)
        if incarnation_id is not None or release_sha256 is not None:
            self._authorize(run, incarnation_id or "", release_sha256 or "")
        return self._workspace_projection(run, self.store.list_artifacts(run_id))

    def list_workspaces(self) -> list[dict[str, Any]]:
        result = []
        for run in self.store.list_runs():
            result.append(self._workspace_projection(run, self.store.list_artifacts(run["run_id"])))
        return result

    def _verify_indexed_files(
        self,
        run: Mapping[str, Any],
        artifacts: Sequence[Mapping[str, Any]],
    ) -> None:
        worktree = self._workspace_path(run)
        indexed_paths: set[str] = set()
        for artifact in artifacts:
            spec = self.registry.resolve(str(artifact["artifact_id"]))
            if artifact["relative_path"] != spec.relative_path:
                raise WorkspaceAPIError(409, "artifact_index_corrupt", "artifact path differs from registry")
            target = self._target_path(worktree, spec.relative_path)
            if not target.is_file() or target.is_symlink():
                raise WorkspaceAPIError(409, "artifact_file_missing", f"{spec.artifact_id} is missing")
            content = target.read_bytes()
            if len(content) != artifact["bytes"] or _sha256(content) != artifact["sha256"]:
                raise WorkspaceAPIError(409, "artifact_hash_mismatch", f"{spec.artifact_id} hash differs")
            if artifact["media_type"] not in spec.media_types or artifact["writer"] != spec.writer:
                raise WorkspaceAPIError(409, "artifact_index_corrupt", "artifact metadata differs")
            indexed_paths.add(spec.relative_path)
        actual_paths: set[str] = set()
        for root_name in ("input", "context", "result"):
            root = worktree / root_name
            if not root.exists():
                continue
            for current, directories, filenames in os.walk(root, followlinks=False):
                current_path = Path(current)
                for directory in list(directories):
                    if (current_path / directory).is_symlink():
                        raise WorkspaceAPIError(409, "artifact_symlink", "runtime directory is a symlink")
                for filename in filenames:
                    path = current_path / filename
                    if path.is_symlink():
                        raise WorkspaceAPIError(409, "artifact_symlink", "runtime artifact is a symlink")
                    actual_paths.add(path.relative_to(worktree).as_posix())
        extras = sorted(actual_paths - indexed_paths)
        missing = sorted(indexed_paths - actual_paths)
        if extras or missing:
            raise WorkspaceAPIError(
                409,
                "workspace_file_contract_violation",
                "workspace files do not equal indexed artifacts",
                details={"extra": extras, "missing": missing},
            )

    def _load_json_artifact(
        self,
        run: Mapping[str, Any],
        artifacts_by_id: Mapping[str, Mapping[str, Any]],
        artifact_id: str,
    ) -> Any:
        artifact = artifacts_by_id[artifact_id]
        spec = self.registry.resolve(artifact_id)
        return _parse_json_bytes(self._artifact_source(run, spec).read_bytes(), description=artifact_id)

    def _validate_facts(self, run: Mapping[str, Any], facts: Any) -> None:
        if not isinstance(facts, dict):
            raise WorkspaceAPIError(422, "facts_invalid", "facts must be an object")
        if facts.get("run_id") != run["run_id"] or facts.get("business_date") != run["business_date"]:
            raise WorkspaceAPIError(409, "facts_identity_mismatch", "facts identity does not match")
        metrics = facts.get("metrics")
        if not isinstance(metrics, list) or len(metrics) != 37:
            raise WorkspaceAPIError(422, "facts_metric_count", "Stage 0 facts must contain 37 metrics")
        metric_ids: list[str] = []
        dimensions = {"traffic": 0, "conversion": 0, "product": 0}
        for metric in metrics:
            if not isinstance(metric, dict) or not isinstance(metric.get("id"), str):
                raise WorkspaceAPIError(422, "facts_metric_invalid", "metric entry is invalid")
            metric_id = metric["id"]
            if not METRIC_ID_RE.fullmatch(metric_id):
                raise WorkspaceAPIError(422, "facts_metric_id", "metric ID is invalid")
            metric_ids.append(metric_id)
            dimension = metric.get("dimension")
            if dimension not in dimensions:
                raise WorkspaceAPIError(422, "facts_dimension", "metric dimension is invalid")
            dimensions[dimension] += 1
        if len(set(metric_ids)) != 37:
            raise WorkspaceAPIError(422, "facts_metric_unique", "metric IDs must be unique")
        if dimensions != {"traffic": 12, "conversion": 10, "product": 15}:
            raise WorkspaceAPIError(422, "facts_dimension_count", "metric dimensions must be 12/10/15")
        catalog = facts.get("metric_catalog")
        if not isinstance(catalog, dict) or catalog.get("metric_count") != 37:
            raise WorkspaceAPIError(422, "facts_catalog_count", "metric catalog count must be 37")

    @staticmethod
    def _validate_attempt_receipt(artifact_id: str, value: Any) -> None:
        if not isinstance(value, dict):
            raise WorkspaceAPIError(422, "attempt_receipt_invalid", f"{artifact_id} must be an object")
        if value.get("status") not in {"completed", "succeeded"}:
            raise WorkspaceAPIError(422, "attempt_not_successful", f"{artifact_id} is not successful")
        self_test = value.get("self_test")
        if not isinstance(self_test, dict):
            raise WorkspaceAPIError(
                422,
                "attempt_self_test_missing",
                f"{artifact_id} self-test must be an object",
            )
        if self_test.get("status") != "passed" or self_test.get("unresolved_issues") != []:
            raise WorkspaceAPIError(422, "attempt_self_test_failed", f"{artifact_id} self-test failed")

    def _preflight_seal(
        self,
        run: Mapping[str, Any],
        artifacts: Sequence[Mapping[str, Any]],
    ) -> dict[str, Mapping[str, Any]]:
        artifacts_by_id = {str(item["artifact_id"]): item for item in artifacts}
        missing = []
        for spec in self.registry.static.values():
            if spec.required and spec.writer == "dolphin" and spec.artifact_id not in artifacts_by_id:
                missing.append(spec.artifact_id)
        receipt_ids: list[str] = []
        for pattern in self.registry.required_attempt_receipts:
            matches = sorted(item for item in artifacts_by_id if pattern.fullmatch(item))
            if not matches:
                missing.append(pattern.pattern)
            else:
                receipt_ids.append(matches[-1])
        if missing:
            raise WorkspaceAPIError(
                409,
                "seal_artifacts_missing",
                "required artifacts are missing",
                details={"artifact_ids": sorted(missing)},
            )
        self._verify_indexed_files(run, artifacts)
        self._validate_facts(run, self._load_json_artifact(run, artifacts_by_id, "data_layer_facts"))
        for receipt_id in receipt_ids:
            self._validate_attempt_receipt(
                receipt_id,
                self._load_json_artifact(run, artifacts_by_id, receipt_id),
            )
        delivery = self._load_json_artifact(run, artifacts_by_id, "orchestrator_delivery_manifest")
        if not isinstance(delivery, dict):
            raise WorkspaceAPIError(422, "delivery_manifest_invalid", "delivery manifest must be an object")
        expected = {
            "run_id": run["run_id"],
            "business_date": run["business_date"],
            "incarnation_id": run["incarnation_id"],
            "platform_release_sha256": run["platform_release_sha256"],
            "platform_release": run["platform_release"],
        }
        for key, value in expected.items():
            if delivery.get(key) != value:
                raise WorkspaceAPIError(409, "delivery_release_binding", f"delivery manifest {key} differs")
        return artifacts_by_id

    def _generate_seal_artifacts(
        self,
        connection: sqlite3.Connection,
        run: Mapping[str, Any],
        sealed_at: str,
    ) -> None:
        run_state = {
            "schema_version": "1.0",
            "run_id": run["run_id"],
            "business_date": run["business_date"],
            "incarnation_id": run["incarnation_id"],
            "status": "sealed",
            "platform_release_sha256": run["platform_release_sha256"],
            "created_at": run["created_at"],
            "sealed_at": sealed_at,
        }
        self._record_server_artifact(
            connection,
            run=run,
            artifact_id="run_state",
            content=_pretty_json_bytes(run_state),
            media_type="application/json",
        )
        artifacts = self.store.list_artifacts(run["run_id"], connection=connection)
        visible_source = [
            self._artifact_projection(item, self.registry.resolve(item["artifact_id"]))
            for item in artifacts
            if item["artifact_id"] not in {"orchestrator_workspace_index", "orchestrator_archive_manifest"}
        ]
        ids = {str(item["artifact_id"]) for item in artifacts}
        workspace_index = {
            "schema_version": "1.0",
            "workspace_version": self.registry.workspace_version,
            "run_id": run["run_id"],
            "business_date": run["business_date"],
            "incarnation_id": run["incarnation_id"],
            "status": "sealed",
            "platform_release_sha256": run["platform_release_sha256"],
            "platform_release": run["platform_release"],
            "sealed_at": sealed_at,
            "stage_statuses": self._stage_statuses(ids),
            "artifacts": visible_source,
        }
        self._record_server_artifact(
            connection,
            run=run,
            artifact_id="orchestrator_workspace_index",
            content=_pretty_json_bytes(workspace_index),
            media_type="application/json",
        )
        artifacts = self.store.list_artifacts(run["run_id"], connection=connection)
        manifest_records = [
            {
                "id": item["artifact_id"],
                "path": item["relative_path"],
                "sha256": item["sha256"],
                "bytes": item["bytes"],
                "media_type": item["media_type"],
            }
            for item in artifacts
            if item["artifact_id"] != "orchestrator_archive_manifest"
        ]
        archive_manifest = {
            "schema_version": "1.0",
            "workspace_version": self.registry.workspace_version,
            "run_id": run["run_id"],
            "business_date": run["business_date"],
            "incarnation_id": run["incarnation_id"],
            "platform_release_sha256": run["platform_release_sha256"],
            "platform_release": run["platform_release"],
            "sealed_at": sealed_at,
            "artifact_count": len(manifest_records),
            "artifact_set_sha256": _sha256(_canonical_json_bytes(manifest_records)),
            "artifacts": manifest_records,
        }
        self._record_server_artifact(
            connection,
            run=run,
            artifact_id="orchestrator_archive_manifest",
            content=_pretty_json_bytes(archive_manifest),
            media_type="application/json",
        )

    def _archive_workspace(
        self,
        run: Mapping[str, Any],
        artifacts: Sequence[Mapping[str, Any]],
    ) -> Path:
        source = self._workspace_path(run)
        target = self._archive_path(run)
        if target.exists():
            if target.is_symlink() or not target.is_dir():
                raise WorkspaceAPIError(409, "archive_residue", "archive target is invalid")
            for artifact in artifacts:
                spec = self.registry.resolve(str(artifact["artifact_id"]))
                path = self._target_path(target, spec.relative_path)
                if not path.is_file() or len(path.read_bytes()) != artifact["bytes"] or _sha256(path.read_bytes()) != artifact["sha256"]:
                    raise WorkspaceAPIError(409, "archive_hash_mismatch", "existing archive differs")
            return target
        temporary = self.history_root / f".{run['business_date']}.{uuid.uuid4().hex}.tmp"
        if temporary.resolve().parent != self.history_root:
            raise WorkspaceAPIError(500, "archive_path_escape", "temporary archive escapes history")
        try:
            temporary.mkdir(parents=False, exist_ok=False)
            for root_name in ("input", "context", "result"):
                source_root = source / root_name
                if source_root.exists():
                    shutil.copytree(source_root, temporary / root_name, symlinks=False)
            for artifact in artifacts:
                spec = self.registry.resolve(str(artifact["artifact_id"]))
                path = self._target_path(temporary, spec.relative_path)
                content = path.read_bytes()
                if len(content) != artifact["bytes"] or _sha256(content) != artifact["sha256"]:
                    raise WorkspaceAPIError(409, "archive_hash_mismatch", "archive copy hash differs")
            temporary.rename(target)
            return target
        except BaseException:
            if temporary.exists() and temporary.resolve().parent == self.history_root:
                shutil.rmtree(temporary)
            raise

    def _sealed_response(self, run: Mapping[str, Any]) -> dict[str, Any]:
        manifest = self.store.get_artifact(run["run_id"], "orchestrator_archive_manifest")
        if manifest is None:
            raise WorkspaceAPIError(409, "sealed_manifest_missing", "sealed manifest is missing")
        return {
            **self._run_response(run),
            "checkpoint_commit": run["checkpoint_commit"],
            "archive_manifest_sha256": manifest["sha256"],
            "sealed_at": run["sealed_at"],
        }

    def seal_workspace(
        self,
        run_id: str,
        *,
        incarnation_id: str,
        release_sha256: str,
        delivery_manifest_sha256: str,
    ) -> dict[str, Any]:
        with self._lock:
            run = self._run_or_404(run_id)
            self._authorize(run, incarnation_id, release_sha256)
            if not SHA256_RE.fullmatch(delivery_manifest_sha256):
                raise WorkspaceAPIError(
                    422,
                    "delivery_manifest_sha256_invalid",
                    "delivery_manifest_sha256 must be a lowercase SHA-256",
                )
            delivery_artifact = self.store.get_artifact(
                run_id,
                "orchestrator_delivery_manifest",
            )
            if delivery_artifact is None:
                raise WorkspaceAPIError(
                    409,
                    "delivery_manifest_missing",
                    "orchestrator_delivery_manifest has not been created",
                )
            if not hmac.compare_digest(
                str(delivery_artifact["sha256"]),
                delivery_manifest_sha256,
            ):
                raise WorkspaceAPIError(
                    409,
                    "delivery_manifest_hash_mismatch",
                    "delivery manifest SHA does not match the indexed artifact",
                )
            if run["status"] == "sealed":
                artifacts = self.store.list_artifacts(run_id)
                self._verify_indexed_files(run, artifacts)
                if not worktree_is_clean(self._workspace_path(run)):
                    raise WorkspaceAPIError(409, "sealed_worktree_dirty", "sealed worktree is not clean")
                self._archive_workspace(run, artifacts)
                return self._sealed_response(run)
            if run["status"] not in {"open", "sealing"}:
                raise WorkspaceAPIError(409, "workspace_not_sealable", "workspace cannot be sealed")
            artifacts = self.store.list_artifacts(run_id)
            self._preflight_seal(run, artifacts)
            if run["status"] == "open":
                seal_started_at = _now_shanghai()
                with self.store.transaction() as connection:
                    current = self._run_or_404(run_id, connection=connection)
                    self._authorize(current, incarnation_id, release_sha256)
                    if current["status"] != "open":
                        raise WorkspaceAPIError(409, "workspace_state_changed", "workspace state changed")
                    self.store.update_run(
                        connection,
                        run_id,
                        status="sealing",
                        seal_started_at=seal_started_at,
                        error_code=None,
                        error_message=None,
                    )
                    self.store.append_event(
                        connection,
                        run_id=run_id,
                        business_date=current["business_date"],
                        incarnation_id=current["incarnation_id"],
                        event_type="workspace_sealing",
                        occurred_at=seal_started_at,
                        payload={"platform_release_sha256": release_sha256},
                    )
                run = self._run_or_404(run_id)
            sealed_at = str(run["seal_started_at"] or _now_shanghai())
            try:
                with self.store.transaction() as connection:
                    current = self._run_or_404(run_id, connection=connection)
                    self._generate_seal_artifacts(connection, current, sealed_at)
                run = self._run_or_404(run_id)
                artifacts = self.store.list_artifacts(run_id)
                self._verify_indexed_files(run, artifacts)
                checkpoint = checkpoint_worktree(
                    self._workspace_path(run),
                    business_date=run["business_date"],
                )
                archive = self._archive_workspace(run, artifacts)
                with self.store.transaction() as connection:
                    current = self._run_or_404(run_id, connection=connection)
                    self.store.update_run(
                        connection,
                        run_id,
                        status="sealed",
                        checkpoint_commit=checkpoint,
                        archive_path=f"history/{run['business_date']}",
                        sealed_at=sealed_at,
                        error_code=None,
                        error_message=None,
                    )
                    self.store.append_event(
                        connection,
                        run_id=run_id,
                        business_date=current["business_date"],
                        incarnation_id=current["incarnation_id"],
                        event_type="workspace_sealed",
                        occurred_at=_now_shanghai(),
                        payload={"checkpoint_commit": checkpoint, "archive": archive.name},
                    )
                return self._sealed_response(self._run_or_404(run_id))
            except WorkspaceAPIError as exc:
                with self.store.transaction() as connection:
                    if self.store.get_run(run_id, connection=connection) is not None:
                        self.store.update_run(
                            connection,
                            run_id,
                            status="error",
                            error_code=exc.code,
                            error_message=exc.message[:500],
                        )
                raise
            except (GitWorkspaceError, StateStoreError, sqlite3.Error, OSError) as exc:
                with self.store.transaction() as connection:
                    if self.store.get_run(run_id, connection=connection) is not None:
                        self.store.update_run(
                            connection,
                            run_id,
                            status="error",
                            error_code="seal_failed",
                            error_message=str(exc)[:500],
                        )
                raise WorkspaceAPIError(500, "seal_failed", str(exc)) from exc

    def delete_workspace(
        self,
        run_id: str,
        *,
        incarnation_id: str,
        release_sha256: str,
    ) -> dict[str, Any]:
        with self._lock:
            run = self._run_or_404(run_id)
            self._authorize(run, incarnation_id, release_sha256)
            if run["status"] not in {"sealed", "error", "deleting"}:
                raise WorkspaceAPIError(
                    409,
                    "active_delete_forbidden",
                    "active workspace deletion requires a future cancel-ack protocol",
                )
            with self.store.transaction() as connection:
                current = self._run_or_404(run_id, connection=connection)
                self._authorize(current, incarnation_id, release_sha256)
                if current["status"] != "deleting":
                    active = self.store.get_active_run(connection=connection)
                    if active is not None and active["run_id"] != run_id:
                        raise WorkspaceAPIError(
                            409,
                            "active_workspace_exists",
                            "another workspace is active; deletion cannot acquire the repository lock",
                            details={"run_id": active["run_id"]},
                        )
                    self.store.update_run(
                        connection,
                        run_id,
                        status="deleting",
                        error_code=None,
                        error_message=None,
                    )
                    self.store.append_event(
                        connection,
                        run_id=run_id,
                        business_date=current["business_date"],
                        incarnation_id=current["incarnation_id"],
                        event_type="workspace_deleting",
                        occurred_at=_now_shanghai(),
                        payload={"previous_status": current["status"]},
                    )
            run = self._run_or_404(run_id)
            archive = self._archive_path(run)
            try:
                if archive.exists():
                    if archive.resolve().parent != self.history_root or archive.is_symlink():
                        raise WorkspaceAPIError(409, "archive_residue", "archive path is unsafe")
                    shutil.rmtree(archive)
                remove_daily_worktree(
                    self.project_root,
                    business_date=run["business_date"],
                    run_id=run_id,
                    branch=run["branch_name"],
                    worktree_path=self._workspace_path(run),
                )
                worktree = self._workspace_path(run)
                if (
                    worktree.exists()
                    or archive.exists()
                    or registered_worktree(self.project_root, worktree)
                    or branch_exists(self.project_root, run["branch_name"])
                ):
                    raise WorkspaceAPIError(409, "delete_residue", "workspace deletion left residue")
                occurred_at = _now_shanghai()
                with self.store.transaction() as connection:
                    current = self._run_or_404(run_id, connection=connection)
                    self.store.append_event(
                        connection,
                        run_id=run_id,
                        business_date=current["business_date"],
                        incarnation_id=current["incarnation_id"],
                        event_type="workspace_deleted",
                        occurred_at=occurred_at,
                        payload={"platform_release_sha256": current["platform_release_sha256"]},
                    )
                    self.store.delete_run(connection, run_id)
                return {
                    "deleted": True,
                    "run_id": run_id,
                    "business_date": run["business_date"],
                    "incarnation_id": incarnation_id,
                    "deleted_at": occurred_at,
                }
            except WorkspaceAPIError:
                raise
            except (GitWorkspaceError, StateStoreError, sqlite3.Error, OSError) as exc:
                with self.store.transaction() as connection:
                    if self.store.get_run(run_id, connection=connection) is not None:
                        self.store.update_run(
                            connection,
                            run_id,
                            error_code="delete_failed",
                            error_message=str(exc)[:500],
                        )
                raise WorkspaceAPIError(500, "delete_failed", str(exc)) from exc


__all__ = ["ArtifactRegistry", "ArtifactSpec", "WorkspaceAPIError", "WorkspaceService"]
