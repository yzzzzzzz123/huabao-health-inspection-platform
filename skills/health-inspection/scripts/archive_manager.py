"""Read-only verification helpers for sealed business-only archives."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path, PurePosixPath
from typing import Any


DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


class ArchiveError(RuntimeError):
    pass


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def archive_root(project_root: Path, business_date: str) -> Path:
    if not DATE_RE.fullmatch(business_date):
        raise ArchiveError("business_date must be YYYY-MM-DD")
    history = (project_root.resolve() / "history").resolve()
    target = (history / business_date).resolve()
    if target.parent != history:
        raise ArchiveError("archive path escapes history root")
    return target


def verify_archive(project_root: Path, business_date: str) -> dict[str, Any]:
    root = archive_root(project_root, business_date)
    manifest_path = root / "context" / "00-orchestrator" / "archive-manifest.json"
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise ArchiveError("archive manifest is missing")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ArchiveError("archive manifest is invalid") from exc
    if not isinstance(manifest, dict) or manifest.get("business_date") != business_date:
        raise ArchiveError("archive manifest identity differs")
    records = manifest.get("artifacts")
    if not isinstance(records, list):
        raise ArchiveError("archive manifest artifacts are invalid")
    checked = 0
    for record in records:
        if not isinstance(record, dict) or not isinstance(record.get("path"), str):
            raise ArchiveError("archive artifact record is invalid")
        pure = PurePosixPath(record["path"])
        if pure.is_absolute() or ".." in pure.parts or pure.parts[0] not in {
            "input",
            "context",
            "result",
        }:
            raise ArchiveError("archive artifact path is unsafe")
        path = root / Path(*pure.parts)
        if not path.is_file() or path.is_symlink():
            raise ArchiveError(f"archive artifact is missing: {record['path']}")
        if path.stat().st_size != record.get("bytes") or _sha256(path) != record.get("sha256"):
            raise ArchiveError(f"archive artifact hash differs: {record['path']}")
        checked += 1
    return {
        "ok": True,
        "business_date": business_date,
        "run_id": manifest.get("run_id"),
        "artifact_count": checked,
        "platform_release_sha256": manifest.get("platform_release_sha256"),
    }


__all__ = ["ArchiveError", "archive_root", "verify_archive"]
