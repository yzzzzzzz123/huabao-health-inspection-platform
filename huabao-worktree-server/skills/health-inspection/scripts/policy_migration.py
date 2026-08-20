"""One-time, fail-closed import of the legacy workbench policy state.

This trusted maintenance CLI is the only code allowed to read the legacy Git
root.  Runtime services consume only the server-owned SQLite store populated by
``WorkbenchPolicyStore.import_state``.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import math
import os
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from pathlib import Path
from typing import Any, Mapping, Sequence


SCRIPT_DIR = Path(__file__).resolve().parent
SERVER_ROOT = SCRIPT_DIR.parents[2]
REPOSITORY_ROOT = SERVER_ROOT.parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from workbench_policy_store import (  # noqa: E402
    WorkbenchPolicyStore,
    WorkbenchPolicyStoreError,
)


LEGACY_PROJECT_NAME = "huabao-new-energy-ai-growth-copilot"
LEGACY_EXPECTED_HEAD = "63ef013a003aad3057cc732105d45da16a4cd301"
POLICY_RELATIVE_ROOT = Path(".git/huabao-health-inspection-index/policies")
FIXTURE_RELATIVE_ROOT = Path("shared/data/fixtures")
FIXTURE_NAMES = ("traffic.json", "conversion.json", "product.json")
VERSION_NAME_RE = re.compile(r"^v1\.(0|[1-9][0-9]*)\.json$")
SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
DIMENSIONS = ("traffic", "conversion", "product")
MAX_SOURCE_FILE_BYTES = 8 * 1024 * 1024
MAX_SOURCE_BUNDLE_BYTES = 32 * 1024 * 1024


class MigrationError(RuntimeError):
    """A safe-to-report migration boundary failure."""


@dataclass(frozen=True)
class SourceSnapshot:
    files: dict[str, bytes]
    file_sha256: dict[str, str]
    bundle_sha256: str


@dataclass(frozen=True)
class ImportBundle:
    versions: list[dict[str, Any]]
    draft: dict[str, Any]
    launch_selection: list[dict[str, Any]]
    legacy_display_rules: list[dict[str, Any]]
    legacy_scoring_config: dict[str, Any]
    legacy_schedule: dict[str, str]


def _is_redirect(path: Path) -> bool:
    if path.is_symlink():
        return True
    is_junction = getattr(path, "is_junction", None)
    return bool(is_junction is not None and is_junction())


def _same_path(left: Path, right: Path) -> bool:
    return os.path.normcase(os.fspath(left)) == os.path.normcase(os.fspath(right))


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _require_regular_directory(path: Path, *, label: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise MigrationError(f"{label} is unavailable") from exc
    if _is_redirect(path) or not stat.S_ISDIR(metadata.st_mode):
        raise MigrationError(f"{label} must be a regular non-redirected directory")


def _require_regular_file(path: Path, *, label: str) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise MigrationError(f"{label} is unavailable") from exc
    if _is_redirect(path) or not stat.S_ISREG(metadata.st_mode):
        raise MigrationError(f"{label} must be a regular non-redirected file")
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise MigrationError(f"{label} cannot be resolved") from exc
    lexical = Path(os.path.abspath(os.fspath(path)))
    if not _same_path(lexical, resolved):
        raise MigrationError(f"{label} cannot traverse a redirect")
    return metadata


def _validate_regular_tree(root: Path, *, label: str) -> None:
    """Reject links, junctions and special files anywhere in one source tree."""

    _require_regular_directory(root, label=label)
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            entries = list(os.scandir(directory))
        except OSError as exc:
            raise MigrationError(f"{label} cannot be enumerated") from exc
        for entry in entries:
            path = Path(entry.path)
            if _is_redirect(path) or entry.is_symlink():
                raise MigrationError(f"{label} contains a redirected entry")
            try:
                if entry.is_dir(follow_symlinks=False):
                    _require_regular_directory(path, label=label)
                    pending.append(path)
                elif entry.is_file(follow_symlinks=False):
                    _require_regular_file(path, label=label)
                else:
                    raise MigrationError(f"{label} contains a special entry")
            except OSError as exc:
                raise MigrationError(f"{label} changed during enumeration") from exc


def _resolve_source_root(value: str) -> Path:
    requested = Path(value).expanduser()
    if not requested.is_absolute():
        raise MigrationError("source-root must be an explicit absolute path")
    lexical = Path(os.path.abspath(os.fspath(requested)))
    try:
        source_root = requested.resolve(strict=True)
    except OSError as exc:
        raise MigrationError("source-root is unavailable") from exc
    if not _same_path(lexical, source_root):
        raise MigrationError("source-root cannot traverse a redirect")
    _require_regular_directory(source_root, label="source-root")
    if source_root.name != LEGACY_PROJECT_NAME:
        raise MigrationError("source-root is not the fixed legacy project root")

    target_root = REPOSITORY_ROOT.resolve(strict=True)
    if (
        _same_path(source_root, target_root)
        or _is_within(target_root, source_root)
        or _is_within(source_root, target_root)
    ):
        raise MigrationError("source-root and target-root must be independent")

    _require_regular_directory(source_root / ".git", label="source Git directory")
    _require_regular_directory(
        source_root / POLICY_RELATIVE_ROOT,
        label="source policy directory",
    )
    _require_regular_directory(
        source_root / FIXTURE_RELATIVE_ROOT,
        label="source fixture directory",
    )
    return source_root


def _git_environment() -> dict[str, str]:
    environment = dict(os.environ)
    environment["GIT_OPTIONAL_LOCKS"] = "0"
    denied = {
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_COMMON_DIR",
        "GIT_CEILING_DIRECTORIES",
        "GIT_CONFIG",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_SYSTEM",
    }
    for key in tuple(environment):
        if key in denied or key.startswith("GIT_CONFIG_KEY_") or key.startswith(
            "GIT_CONFIG_VALUE_"
        ):
            environment.pop(key, None)
    environment.pop("GIT_CONFIG_COUNT", None)
    return environment


def _git_output(source_root: Path, *arguments: str) -> str:
    executable = shutil.which("git")
    if executable is None:
        raise MigrationError("Git is unavailable")
    git_path = Path(executable).resolve(strict=True)
    _require_regular_file(git_path, label="Git executable")
    try:
        completed = subprocess.run(
            [os.fspath(git_path), "-C", os.fspath(source_root), *arguments],
            cwd=os.fspath(source_root),
            env=_git_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
            check=False,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise MigrationError("Git identity verification failed") from exc
    if completed.returncode != 0:
        raise MigrationError("Git identity verification failed")
    try:
        output = completed.stdout.decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError as exc:
        raise MigrationError("Git identity output is invalid") from exc
    if not output or "\n" in output or "\r" in output:
        raise MigrationError("Git identity output is invalid")
    return output


def _verify_git_identity(source_root: Path, expected_head: str) -> str:
    if expected_head != LEGACY_EXPECTED_HEAD or SHA1_RE.fullmatch(expected_head) is None:
        raise MigrationError("expected-head must equal the approved legacy commit")
    top_level_text = _git_output(source_root, "rev-parse", "--show-toplevel")
    try:
        top_level = Path(top_level_text).resolve(strict=True)
    except OSError as exc:
        raise MigrationError("Git top-level identity is invalid") from exc
    if not _same_path(top_level, source_root):
        raise MigrationError("source-root is not the Git top-level")

    common_text = _git_output(source_root, "rev-parse", "--git-common-dir")
    common_candidate = Path(common_text)
    if not common_candidate.is_absolute():
        common_candidate = source_root / common_candidate
    try:
        common_dir = common_candidate.resolve(strict=True)
    except OSError as exc:
        raise MigrationError("Git common directory identity is invalid") from exc
    if not _same_path(common_dir, (source_root / ".git").resolve(strict=True)):
        raise MigrationError("legacy policy source must use its own .git directory")
    _require_regular_directory(common_dir, label="Git common directory")

    actual_head = _git_output(source_root, "rev-parse", "--verify", "HEAD^{commit}")
    if SHA1_RE.fullmatch(actual_head) is None or actual_head != expected_head:
        raise MigrationError("legacy Git HEAD does not match expected-head")
    return actual_head


def _source_files(source_root: Path) -> list[tuple[str, Path]]:
    policy_root = source_root / POLICY_RELATIVE_ROOT
    versions_root = policy_root / "versions"
    fixtures_root = source_root / FIXTURE_RELATIVE_ROOT
    _validate_regular_tree(policy_root, label="source policy tree")
    _validate_regular_tree(fixtures_root, label="source fixture tree")
    _require_regular_directory(versions_root, label="source policy versions")

    version_entries: list[tuple[int, Path]] = []
    try:
        raw_version_entries = list(versions_root.iterdir())
    except OSError as exc:
        raise MigrationError("source policy versions cannot be enumerated") from exc
    for path in raw_version_entries:
        match = VERSION_NAME_RE.fullmatch(path.name)
        if match is None:
            raise MigrationError("source policy versions contain an unexpected entry")
        _require_regular_file(path, label="source policy version")
        version_entries.append((int(match.group(1)), path))
    version_entries.sort(key=lambda item: item[0])
    if not version_entries or [item[0] for item in version_entries] != list(
        range(len(version_entries))
    ):
        raise MigrationError("source policy versions must be continuous from v1.0")

    try:
        fixture_entries = {path.name: path for path in fixtures_root.iterdir()}
    except OSError as exc:
        raise MigrationError("source fixtures cannot be enumerated") from exc
    if set(fixture_entries) != set(FIXTURE_NAMES):
        raise MigrationError("source fixtures must contain the fixed three files")

    selected: list[tuple[str, Path]] = []
    for relative in ("draft.json", "launch-selection.jsonl"):
        path = policy_root / relative
        _require_regular_file(path, label="source policy state")
        selected.append((path.relative_to(source_root).as_posix(), path))
    for _, path in version_entries:
        selected.append((path.relative_to(source_root).as_posix(), path))
    for name in FIXTURE_NAMES:
        path = fixture_entries[name]
        _require_regular_file(path, label="source fixture")
        selected.append((path.relative_to(source_root).as_posix(), path))
    return sorted(selected, key=lambda item: item[0])


def _read_regular_bytes(path: Path, *, label: str) -> bytes:
    before = _require_regular_file(path, label=label)
    if before.st_size > MAX_SOURCE_FILE_BYTES:
        raise MigrationError(f"{label} exceeds the migration size limit")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise MigrationError(f"{label} cannot be opened safely") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise MigrationError(f"{label} is not a regular file")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_SOURCE_FILE_BYTES:
                raise MigrationError(f"{label} exceeds the migration size limit")
            chunks.append(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    identity_opened = (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
    identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if identity_before != identity_opened or identity_opened != identity_after:
        raise MigrationError(f"{label} changed while it was read")
    _require_regular_file(path, label=label)
    return b"".join(chunks)


def _bundle_hash(files: Mapping[str, bytes]) -> str:
    digest = hashlib.sha256()
    for relative_path in sorted(files):
        name = relative_path.encode("utf-8", errors="strict")
        payload = files[relative_path]
        digest.update(len(name).to_bytes(8, "big"))
        digest.update(name)
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)
    return digest.hexdigest()


def _snapshot_once(source_root: Path) -> SourceSnapshot:
    files: dict[str, bytes] = {}
    total = 0
    for relative_path, path in _source_files(source_root):
        payload = _read_regular_bytes(path, label="source migration file")
        total += len(payload)
        if total > MAX_SOURCE_BUNDLE_BYTES:
            raise MigrationError("source migration bundle exceeds the size limit")
        files[relative_path] = payload
    hashes = {name: hashlib.sha256(payload).hexdigest() for name, payload in files.items()}
    return SourceSnapshot(files=files, file_sha256=hashes, bundle_sha256=_bundle_hash(files))


def _require_same_snapshot(reference: SourceSnapshot, candidate: SourceSnapshot) -> None:
    if (
        reference.file_sha256 != candidate.file_sha256
        or reference.files.keys() != candidate.files.keys()
        or reference.bundle_sha256 != candidate.bundle_sha256
    ):
        raise MigrationError("legacy policy source changed during migration")
    for name, payload in reference.files.items():
        if candidate.files[name] != payload:
            raise MigrationError("legacy policy source changed during migration")


def _stable_snapshot(source_root: Path, expected_head: str) -> SourceSnapshot:
    _verify_git_identity(source_root, expected_head)
    first = _snapshot_once(source_root)
    second = _snapshot_once(source_root)
    _require_same_snapshot(first, second)
    _verify_git_identity(source_root, expected_head)
    return first


def _verify_source_again(
    source_root: Path,
    expected_head: str,
    reference: SourceSnapshot,
) -> None:
    _verify_git_identity(source_root, expected_head)
    _require_same_snapshot(reference, _snapshot_once(source_root))


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise MigrationError("source JSON contains a duplicate key")
        value[key] = item
    return value


def _reject_non_finite(value: str) -> Any:
    raise MigrationError(f"source JSON contains an unsupported number: {value}")


def _load_json(payload: bytes, *, label: str) -> Any:
    try:
        text = payload.decode("utf-8", errors="strict")
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_finite,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MigrationError(f"{label} is not strict UTF-8 JSON") from exc


def _load_json_object(payload: bytes, *, label: str) -> dict[str, Any]:
    value = _load_json(payload, label=label)
    if not isinstance(value, dict):
        raise MigrationError(f"{label} must be a JSON object")
    return value


def _load_selection(payload: bytes) -> list[dict[str, Any]]:
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise MigrationError("launch-selection is not strict UTF-8") from exc
    events: list[dict[str, Any]] = []
    for line in text.splitlines():
        if not line.strip():
            raise MigrationError("launch-selection contains a blank record")
        try:
            value = json.loads(
                line,
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=_reject_non_finite,
            )
        except json.JSONDecodeError as exc:
            raise MigrationError("launch-selection contains invalid JSON") from exc
        if not isinstance(value, dict):
            raise MigrationError("launch-selection records must be objects")
        events.append(value)
    return events


def _finite_float(value: Any, *, field: str) -> float:
    if value is None:
        return 0.0
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise MigrationError(f"{field} must be numeric")
    result = float(value)
    if not math.isfinite(result):
        raise MigrationError(f"{field} must be finite")
    return result


def _threshold_fields(rule_type: Any) -> tuple[str, str]:
    if rule_type == "lower_bound":
        return ("yellow_min", "green_min")
    if rule_type == "upper_bound":
        return ("green_max", "yellow_max")
    raise MigrationError("legacy rule type is unsupported")


def _rounded_number(value: float, precision: int) -> int | float:
    try:
        rounded = Decimal(str(value)).quantize(
            Decimal(1).scaleb(-precision),
            rounding=ROUND_HALF_UP,
        )
    except (InvalidOperation, ValueError) as exc:
        raise MigrationError("legacy threshold cannot be rounded") from exc
    return int(rounded) if precision == 0 else float(rounded)


def _fixture_metrics(snapshot: SourceSnapshot) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for name in FIXTURE_NAMES:
        relative = (FIXTURE_RELATIVE_ROOT / name).as_posix()
        fixture = _load_json_object(snapshot.files[relative], label="source fixture")
        metrics = fixture.get("metrics")
        if not isinstance(metrics, list):
            raise MigrationError("source fixture metrics must be an array")
        for raw in metrics:
            if not isinstance(raw, dict):
                raise MigrationError("source fixture metric must be an object")
            metric_id = raw.get("id")
            if not isinstance(metric_id, str) or metric_id in result:
                raise MigrationError("source fixtures contain an invalid metric identity")
            _finite_float(raw.get("current"), field="fixture current")
            result[metric_id] = raw
    return result


def _legacy_display_rules(
    legacy_version: Mapping[str, Any],
    fixtures: Mapping[str, Mapping[str, Any]],
) -> list[dict[str, Any]]:
    raw_rules = legacy_version.get("rules")
    if not isinstance(raw_rules, list) or len(raw_rules) != 37:
        raise MigrationError("legacy v1.0 must contain exactly 37 rules")
    rules: list[dict[str, Any]] = []
    identifiers: set[str] = set()
    positions: set[int] = set()
    for raw in raw_rules:
        if not isinstance(raw, Mapping):
            raise MigrationError("legacy v1.0 rule must be an object")
        rule = copy.deepcopy(dict(raw))
        metric_id = rule.get("metric_id")
        position = rule.get("position")
        precision = rule.get("precision")
        if not isinstance(metric_id, str) or metric_id in identifiers:
            raise MigrationError("legacy v1.0 metric identity is invalid")
        if isinstance(position, bool) or not isinstance(position, int) or position in positions:
            raise MigrationError("legacy v1.0 metric position is invalid")
        if isinstance(precision, bool) or not isinstance(precision, int) or not 0 <= precision <= 9:
            raise MigrationError("legacy v1.0 metric precision is invalid")
        fixture = fixtures.get(metric_id)
        if fixture is None:
            raise MigrationError("legacy v1.0 and source fixtures are not aligned")
        baseline = _finite_float(rule.get("baseline"), field="legacy baseline")
        current = _finite_float(fixture.get("current"), field="fixture current")
        anchor = abs(baseline) if baseline != 0 else abs(current) if current != 0 else 1.0
        if rule.get("rule_type") == "upper_bound":
            values: Sequence[float] = (anchor * 1.1, anchor * 1.3)
            if baseline == 0 or current == 0:
                warning = Decimal(str(anchor * 0.1)).quantize(
                    Decimal(1).scaleb(-precision),
                    rounding=ROUND_HALF_UP,
                )
                values = (0.0, max(1.0, float(warning)))
            if metric_id == "HI-011":
                values = (70.0, 80.0)
        elif rule.get("rule_type") == "lower_bound":
            values = (anchor * 0.75, anchor * 0.9)
            if metric_id == "HI-001":
                values = (700.0, 900.0)
        else:
            raise MigrationError("legacy v1.0 rule type is invalid")
        fields = _threshold_fields(rule.get("rule_type"))
        rule["thresholds"] = {
            field: _rounded_number(value, precision)
            for field, value in zip(fields, values)
        }
        rule["classification_enabled"] = True
        rule["evaluation_status"] = "evaluated"
        if metric_id == "HI-030":
            rule["evaluation_status"] = "partially_evaluated"
            rule["special_anomaly_branch"] = "zero_revenue_positive_ad_spend"
        identifiers.add(metric_id)
        positions.add(position)
        rules.append(rule)
    expected_ids = {f"HI-{number:03d}" for number in range(1, 38)}
    if identifiers != expected_ids or positions != set(range(1, 38)) or identifiers != set(fixtures):
        raise MigrationError("legacy v1.0 and source fixtures must cover HI-001 through HI-037")
    rules.sort(key=lambda item: int(item["position"]))
    by_id = {str(item["metric_id"]): item for item in rules}
    if by_id["HI-001"]["thresholds"] != {"yellow_min": 700, "green_min": 900}:
        raise MigrationError("legacy HI-001 display thresholds are inconsistent")
    if by_id["HI-011"]["thresholds"] != {"green_max": 70.0, "yellow_max": 80.0}:
        raise MigrationError("legacy HI-011 display thresholds are inconsistent")
    return rules


def _equal_integer_percentages(keys: Sequence[str]) -> dict[str, int]:
    if not keys:
        raise MigrationError("scoring group cannot be empty")
    quotient, remainder = divmod(100, len(keys))
    return {
        key: quotient + (1 if index < remainder else 0)
        for index, key in enumerate(keys)
    }


def _legacy_scoring(rules: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    metric_weights: dict[str, int] = {}
    dimension_bands: dict[str, dict[str, int]] = {}
    for dimension in DIMENSIONS:
        identifiers = [
            str(rule["metric_id"])
            for rule in rules
            if rule.get("dimension") == dimension
        ]
        metric_weights.update(_equal_integer_percentages(identifiers))
        dimension_bands[dimension] = {"yellow_min": 60, "green_min": 80}
    scoring = {
        "dimension_weight_percentages": _equal_integer_percentages(DIMENSIONS),
        "metric_weight_percentages": metric_weights,
        "band_thresholds": {"yellow_min": 60, "green_min": 80},
        "dimension_band_thresholds": dimension_bands,
    }
    if scoring["dimension_weight_percentages"] != {
        "traffic": 34,
        "conversion": 33,
        "product": 33,
    }:
        raise MigrationError("legacy default dimension scoring is inconsistent")
    return scoring


def _parse_bundle(snapshot: SourceSnapshot) -> ImportBundle:
    version_prefix = (POLICY_RELATIVE_ROOT / "versions").as_posix() + "/"
    version_paths: list[tuple[int, str]] = []
    for relative in snapshot.files:
        if not relative.startswith(version_prefix):
            continue
        match = VERSION_NAME_RE.fullmatch(relative.removeprefix(version_prefix))
        if match is None:
            raise MigrationError("source policy version name is invalid")
        version_paths.append((int(match.group(1)), relative))
    version_paths.sort()
    if [item[0] for item in version_paths] != list(range(len(version_paths))):
        raise MigrationError("source policy version sequence is incomplete")
    versions: list[dict[str, Any]] = []
    for ordinal, relative in version_paths:
        document = _load_json_object(snapshot.files[relative], label="source policy version")
        if document.get("version") != f"v1.{ordinal}" or document.get("ordinal") != ordinal:
            raise MigrationError("source policy version identity is inconsistent")
        versions.append(document)
    if not versions or versions[0].get("mode") != "legacy":
        raise MigrationError("source v1.0 must be the immutable legacy baseline")

    draft_relative = (POLICY_RELATIVE_ROOT / "draft.json").as_posix()
    selection_relative = (POLICY_RELATIVE_ROOT / "launch-selection.jsonl").as_posix()
    draft = _load_json_object(snapshot.files[draft_relative], label="source policy draft")
    events = _load_selection(snapshot.files[selection_relative])
    fixtures = _fixture_metrics(snapshot)
    display_rules = _legacy_display_rules(versions[0], fixtures)
    return ImportBundle(
        versions=versions,
        draft=draft,
        launch_selection=events,
        legacy_display_rules=display_rules,
        legacy_scoring_config=_legacy_scoring(display_rules),
        legacy_schedule={"time": "09:00"},
    )


def _database_paths() -> tuple[Path, tuple[Path, ...]]:
    state_root = REPOSITORY_ROOT / ".huabao"
    if state_root.exists():
        _require_regular_directory(state_root, label="target policy state directory")
    else:
        state_root.mkdir(mode=0o700)
        _require_regular_directory(state_root, label="target policy state directory")
    if state_root.resolve(strict=True).parent != REPOSITORY_ROOT.resolve(strict=True):
        raise MigrationError("target policy state escaped the monorepo root")
    database = state_root / "workbench-policy.sqlite3"
    related = (
        database,
        Path(os.fspath(database) + "-wal"),
        Path(os.fspath(database) + "-shm"),
    )
    return database, related


def _reserve_empty_database(database: Path, related: Sequence[Path]) -> None:
    if any(path.exists() or path.is_symlink() for path in related):
        raise MigrationError("target workbench policy store is not empty")
    flags = os.O_CREAT | os.O_EXCL | os.O_RDWR | getattr(os, "O_BINARY", 0)
    try:
        descriptor = os.open(database, flags, 0o600)
    except FileExistsError as exc:
        raise MigrationError("target workbench policy store is not empty") from exc
    except OSError as exc:
        raise MigrationError("target workbench policy store cannot be reserved") from exc
    else:
        os.close(descriptor)


def _remove_created_database(related: Sequence[Path]) -> None:
    state_root = (REPOSITORY_ROOT / ".huabao").resolve(strict=True)
    for path in reversed(tuple(related)):
        if not path.exists() and not path.is_symlink():
            continue
        lexical = Path(os.path.abspath(os.fspath(path)))
        if lexical.parent != state_root:
            raise MigrationError("target database cleanup escaped the monorepo root")
        _require_regular_file(path, label="created target database file")
        path.unlink()


def _import_legacy(source_value: str, expected_head: str) -> dict[str, Any]:
    source_root = _resolve_source_root(source_value)
    snapshot = _stable_snapshot(source_root, expected_head)
    bundle = _parse_bundle(snapshot)
    _verify_source_again(source_root, expected_head, snapshot)

    database, related = _database_paths()
    _reserve_empty_database(database, related)
    imported = False
    try:
        store = WorkbenchPolicyStore(REPOSITORY_ROOT, database_path=database)
        overview = store.import_state(
            bundle.versions,
            bundle.draft,
            bundle.launch_selection,
            replace_if_empty=True,
            trusted_source_sha256=snapshot.bundle_sha256,
            legacy_display_rules=bundle.legacy_display_rules,
            legacy_scoring_config=bundle.legacy_scoring_config,
            legacy_schedule=bundle.legacy_schedule,
        )
        imported = True
        _verify_source_again(source_root, expected_head, snapshot)
        summary = _read_status(database)
        expected_summary = {
            "versions": len(bundle.versions),
            "draft_revision": int(bundle.draft["draft_revision"]),
            "metric_count": 37,
            "bundle_sha": snapshot.bundle_sha256,
        }
        if summary != expected_summary:
            raise MigrationError("target policy import verification failed")
        if int(overview.get("published_version_count", -1)) != len(bundle.versions):
            raise MigrationError("target policy import count is inconsistent")
        return summary
    except BaseException:
        if imported or database.exists():
            _remove_created_database(related)
        raise


def _read_status(database: Path | None = None) -> dict[str, Any]:
    selected = database or (REPOSITORY_ROOT / ".huabao" / "workbench-policy.sqlite3")
    if _is_redirect(selected):
        raise MigrationError("target workbench policy database must not be a link")
    if not selected.exists():
        return {
            "versions": 0,
            "draft_revision": None,
            "metric_count": 0,
            "bundle_sha": None,
        }
    _require_regular_file(selected, label="target workbench policy database")
    uri = f"file:{selected.as_posix()}?mode=ro"
    try:
        connection = sqlite3.connect(uri, uri=True, timeout=5.0, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only = ON")
        connection.execute("PRAGMA trusted_schema = OFF")
        connection.execute("BEGIN")
        tables = {
            str(row["name"])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
        required = {"metadata", "policy_state", "policy_versions", "selection_events"}
        if not required.issubset(tables):
            raise MigrationError("target workbench policy database schema is incomplete")
        versions = int(
            connection.execute("SELECT COUNT(*) FROM policy_versions").fetchone()[0]
        )
        draft_row = connection.execute(
            "SELECT draft_revision FROM policy_state WHERE singleton = 1"
        ).fetchone()
        catalog_row = connection.execute(
            "SELECT value FROM metadata WHERE key = 'metric_catalog'"
        ).fetchone()
        bundle_row = connection.execute(
            "SELECT value FROM metadata WHERE key = 'migration_source_sha256'"
        ).fetchone()
        if draft_row is None or catalog_row is None:
            raise MigrationError("target workbench policy database is not initialized")
        catalog = json.loads(str(catalog_row["value"]))
        if not isinstance(catalog, list):
            raise MigrationError("target workbench policy catalog is invalid")
        bundle_sha = str(bundle_row["value"]) if bundle_row is not None else None
        if bundle_sha is not None and SHA256_RE.fullmatch(bundle_sha) is None:
            raise MigrationError("target migration bundle identity is invalid")
        connection.rollback()
        return {
            "versions": versions,
            "draft_revision": int(draft_row["draft_revision"]),
            "metric_count": len(catalog),
            "bundle_sha": bundle_sha,
        }
    except sqlite3.Error as exc:
        raise MigrationError("target workbench policy database cannot be read") from exc
    finally:
        if "connection" in locals():
            connection.close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Import or inspect the server-owned workbench policy store"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    importer = subparsers.add_parser("import-legacy")
    importer.add_argument("--source-root", required=True)
    importer.add_argument("--expected-head", required=True)
    subparsers.add_parser("status")
    return parser


def _print_summary(value: Mapping[str, Any]) -> None:
    safe = {
        "versions": value.get("versions"),
        "draft_revision": value.get("draft_revision"),
        "metric_count": value.get("metric_count"),
        "bundle_sha": value.get("bundle_sha"),
    }
    print(json.dumps(safe, ensure_ascii=False, sort_keys=True, separators=(",", ":")))


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        if arguments.command == "import-legacy":
            summary = _import_legacy(arguments.source_root, arguments.expected_head)
        else:
            summary = _read_status()
        _print_summary(summary)
        return 0
    except (MigrationError, WorkbenchPolicyStoreError, KeyError, ValueError, TypeError) as exc:
        message = str(exc).replace("\r", " ").replace("\n", " ")
        print(f"policy migration failed: {message}", file=sys.stderr)
        return 1
    except Exception:
        print("policy migration failed: internal_error", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
