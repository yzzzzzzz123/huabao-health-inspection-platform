"""Read-only verification helpers for sealed business-only archives."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path, PurePosixPath
from typing import Any


DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
ARTIFACT_ID_RE = re.compile(r"^[a-z][a-z0-9_]{0,127}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SCRIPT_DIR = Path(__file__).resolve().parent
SERVER_COMPONENT_NAME = "huabao-worktree-server"
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from state_store import (  # noqa: E402
    StateStore,
    StateStoreError,
    canonical_json,
    resolve_server_runtime_root,
)


class ArchiveError(RuntimeError):
    pass


def _is_link_or_reparse(path: Path) -> bool:
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        return False
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    attributes = getattr(metadata, "st_file_attributes", 0)
    return path.is_symlink() or bool(reparse_flag and attributes & reparse_flag)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_descendant(root: Path, relative_path: str) -> Path:
    root_lexical = Path(os.path.abspath(os.fspath(root)))
    if _is_link_or_reparse(root_lexical):
        raise ArchiveError("archive root is redirected")
    resolved_root = root_lexical.resolve()
    if resolved_root != root_lexical:
        raise ArchiveError("archive root is redirected")
    current = resolved_root
    for part in PurePosixPath(relative_path).parts:
        current = current / part
        if os.path.lexists(current) and _is_link_or_reparse(current):
            raise ArchiveError("archive path is redirected")
    target = current.resolve(strict=False)
    try:
        target.relative_to(resolved_root)
    except ValueError as exc:
        raise ArchiveError("archive path escapes archive root") from exc
    return target


def _server_runtime_root(repository_root: Path) -> Path:
    root_lexical = Path(os.path.abspath(os.fspath(repository_root)))
    try:
        if root_lexical.name == SERVER_COMPONENT_NAME:
            return resolve_server_runtime_root(
                root_lexical.parent,
                server_root=root_lexical,
            )
        return resolve_server_runtime_root(root_lexical)
    except StateStoreError as exc:
        raise ArchiveError(str(exc)) from exc


def archive_root(repository_root: Path, business_date: str) -> Path:
    if not DATE_RE.fullmatch(business_date):
        raise ArchiveError("business_date must be YYYY-MM-DD")
    history_lexical = _server_runtime_root(repository_root) / "history"
    if (
        not os.path.lexists(history_lexical)
        or not history_lexical.is_dir()
        or _is_link_or_reparse(history_lexical)
        or history_lexical.resolve() != history_lexical
    ):
        raise ArchiveError("history root is unavailable or redirected")
    history = history_lexical.resolve()
    target = history / business_date
    if os.path.lexists(target) and _is_link_or_reparse(target):
        raise ArchiveError("archive date root is redirected")
    if target.parent != history or target.resolve(strict=False) != target:
        raise ArchiveError("archive path escapes history root")
    return target


def verify_archive(repository_root: Path, business_date: str) -> dict[str, Any]:
    server_root = _server_runtime_root(repository_root)
    root = archive_root(server_root, business_date)
    manifest_path = _safe_descendant(
        root,
        "context/00-orchestrator/archive-manifest.json",
    )
    if not manifest_path.is_file() or _is_link_or_reparse(manifest_path):
        raise ArchiveError("archive manifest is missing")
    try:
        manifest_bytes = manifest_path.read_bytes()
        manifest = json.loads(manifest_bytes.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ArchiveError("archive manifest is invalid") from exc
    run_id = f"hi-{business_date}"
    store = StateStore(server_root)
    run = store.get_run(run_id)
    indexed_manifest = store.get_artifact(run_id, "orchestrator_archive_manifest")
    if (
        run is None
        or run.get("status") != "sealed"
        or run.get("archive_path")
        != f"{SERVER_COMPONENT_NAME}/history/{business_date}"
        or indexed_manifest is None
    ):
        raise ArchiveError("archive has no sealed SQLite identity")
    manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
    if (
        indexed_manifest.get("sha256") != manifest_sha256
        or indexed_manifest.get("bytes") != len(manifest_bytes)
    ):
        raise ArchiveError("archive manifest differs from the SQLite index")
    expected_identity = {
        "workspace_version": run["workspace_version"],
        "run_id": run_id,
        "business_date": business_date,
        "incarnation_id": run["incarnation_id"],
        "platform_release_sha256": run["platform_release_sha256"],
        "platform_release": run["platform_release"],
        "sealed_at": run["sealed_at"],
    }
    if not isinstance(manifest, dict) or any(
        manifest.get(key) != value for key, value in expected_identity.items()
    ):
        raise ArchiveError("archive manifest identity differs")
    records = manifest.get("artifacts")
    if not isinstance(records, list):
        raise ArchiveError("archive manifest artifacts are invalid")
    if manifest.get("artifact_count") != len(records):
        raise ArchiveError("archive manifest artifact_count differs")
    if manifest.get("artifact_set_sha256") != hashlib.sha256(
        (canonical_json(records) + "\n").encode("utf-8")
    ).hexdigest():
        raise ArchiveError("archive manifest artifact set hash differs")
    checked = 0
    artifact_ids: set[str] = set()
    record_paths: set[str] = set()
    for record in records:
        if not isinstance(record, dict) or set(record) != {
            "id",
            "path",
            "sha256",
            "bytes",
            "media_type",
        }:
            raise ArchiveError("archive artifact record is invalid")
        artifact_id = record.get("id")
        relative_path = record.get("path")
        if (
            not isinstance(artifact_id, str)
            or ARTIFACT_ID_RE.fullmatch(artifact_id) is None
            or artifact_id in artifact_ids
            or not isinstance(relative_path, str)
            or relative_path in record_paths
            or not isinstance(record.get("bytes"), int)
            or record["bytes"] < 0
            or not isinstance(record.get("media_type"), str)
            or not record["media_type"]
            or not isinstance(record.get("sha256"), str)
            or SHA256_RE.fullmatch(record["sha256"]) is None
        ):
            raise ArchiveError("archive artifact record identity is invalid")
        artifact_ids.add(artifact_id)
        record_paths.add(relative_path)
        pure = PurePosixPath(relative_path)
        if pure.is_absolute() or ".." in pure.parts or pure.parts[0] not in {
            "input",
            "context",
            "result",
        }:
            raise ArchiveError("archive artifact path is unsafe")
        path = _safe_descendant(root, relative_path)
        if not path.is_file() or _is_link_or_reparse(path):
            raise ArchiveError(f"archive artifact is missing: {relative_path}")
        if path.stat().st_size != record.get("bytes") or _sha256(path) != record.get("sha256"):
            raise ArchiveError(f"archive artifact hash differs: {relative_path}")
        checked += 1
    actual_paths: set[str] = set()
    for top in ("input", "context", "result"):
        folder = _safe_descendant(root, top)
        if not folder.exists():
            continue
        for current, directories, filenames in os.walk(folder, followlinks=False):
            current_path = Path(current)
            for directory in list(directories):
                if _is_link_or_reparse(current_path / directory):
                    raise ArchiveError("archive contains a redirected directory")
            for filename in filenames:
                path = current_path / filename
                if _is_link_or_reparse(path):
                    raise ArchiveError("archive contains a redirected file")
                actual_paths.add(path.relative_to(root).as_posix())
    manifest_relative = manifest_path.relative_to(root).as_posix()
    if actual_paths != record_paths | {manifest_relative}:
        raise ArchiveError("archive files differ from the manifest set")
    return {
        "ok": True,
        "business_date": business_date,
        "run_id": run_id,
        "artifact_count": checked,
        "artifact_set_sha256": manifest["artifact_set_sha256"],
        "archive_manifest_sha256": manifest_sha256,
        "platform_release_sha256": run["platform_release_sha256"],
    }


__all__ = ["ArchiveError", "archive_root", "verify_archive"]
