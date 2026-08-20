"""Strict, secret-free runtime contract for the Workspace Server.

The tracked ``shared/.env`` file is parsed as data.  It is never sourced or
evaluated by a shell.  Dolphin releases must be explicitly registered here
before a workspace can bind them.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, MutableMapping
from urllib.parse import urlsplit


ENV_RELATIVE_PATH = Path("shared/.env")
ENV_SCHEMA_VERSION = "1.0"
WORKSPACE_VERSION = "2.0"
RELEASE_FIELDS = (
    "platform",
    "application_id",
    "release_version",
    "workflow_version",
    "skill_bundle_sha256",
    "schema_bundle_sha256",
)
_KEY_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
_VERSION_RE = re.compile(r"^v[1-9][0-9]*\.[0-9]+\.[0-9]+$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_RELEASE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_ALLOWED_ENV_KEYS = frozenset(
    {
        "HUABAO_WORKSPACE_ENV_SCHEMA_VERSION",
        "HUABAO_WORKSPACE_HOST",
        "HUABAO_WORKSPACE_PORT",
        "HUABAO_WORKSPACE_MAX_JSON_BYTES",
        "HUABAO_DOLPHIN_DISPATCH_URL",
        "HUABAO_DOLPHIN_RELEASE_ALLOWLIST_JSON",
        "HUABAO_DINGTALK_ACCESS_TOKEN",
        "HUABAO_DINGTALK_SIGNING_SECRET",
        "HUABAO_DINGTALK_AT_MOBILES",
        "HUABAO_DINGTALK_AT_ALL",
    }
)


class RuntimeEnvironmentError(RuntimeError):
    """The tracked environment contract is absent, malformed, or unsafe."""


def _canonical_json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def parse_env_file(path: Path) -> dict[str, str]:
    """Parse a bounded ``KEY=VALUE`` file without interpolation or evaluation."""

    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise RuntimeEnvironmentError(f"environment contract is unreadable: {path}") from exc
    if len(raw) > 256 * 1024:
        raise RuntimeEnvironmentError("environment contract exceeds 256 KiB")
    if b"\x00" in raw:
        raise RuntimeEnvironmentError("environment contract contains NUL bytes")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RuntimeEnvironmentError("environment contract must be UTF-8") from exc

    result: dict[str, str] = {}
    for number, original in enumerate(text.splitlines(), start=1):
        line = original.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export ") or "=" not in line:
            raise RuntimeEnvironmentError(f"invalid .env syntax on line {number}")
        key, value = line.split("=", 1)
        key = key.strip()
        if not _KEY_RE.fullmatch(key):
            raise RuntimeEnvironmentError(f"invalid .env key on line {number}")
        if key not in _ALLOWED_ENV_KEYS:
            raise RuntimeEnvironmentError(f"unregistered .env key: {key}")
        if key in result:
            raise RuntimeEnvironmentError(f"duplicate .env key: {key}")
        if value != value.strip():
            raise RuntimeEnvironmentError(f"whitespace around .env value is forbidden: {key}")
        result[key] = value
    return result


@dataclass(frozen=True, slots=True)
class DolphinRelease:
    release_id: str
    platform: str
    application_id: str
    release_version: str
    workflow_version: str
    skill_bundle_sha256: str
    schema_bundle_sha256: str

    def platform_release_core(self) -> dict[str, str]:
        return {field: getattr(self, field) for field in RELEASE_FIELDS}

    def registration(self) -> dict[str, str]:
        return {"release_id": self.release_id, **self.platform_release_core()}

    @property
    def registration_sha256(self) -> str:
        return hashlib.sha256(_canonical_json_bytes(self.registration())).hexdigest()


@dataclass(frozen=True, slots=True)
class WorkspaceRuntimeConfig:
    project_root: Path
    host: str
    port: int
    max_json_bytes: int
    dolphin_dispatch_url: str | None
    releases: tuple[DolphinRelease, ...]

    def release_by_id(self, release_id: str) -> DolphinRelease:
        for release in self.releases:
            if release.release_id == release_id:
                return release
        raise RuntimeEnvironmentError(f"Dolphin release is not registered: {release_id}")

    def match_platform_release(self, value: Mapping[str, Any]) -> DolphinRelease:
        keys = set(value)
        allowed = set(RELEASE_FIELDS) | {"bound_at"}
        if not keys.issubset(allowed) or not set(RELEASE_FIELDS).issubset(keys):
            raise RuntimeEnvironmentError(
                "platform_release must contain exactly the six registered fields and optional bound_at"
            )
        core = {field: value.get(field) for field in RELEASE_FIELDS}
        if not all(isinstance(item, str) for item in core.values()):
            raise RuntimeEnvironmentError("platform_release values must be strings")
        for release in self.releases:
            if core == release.platform_release_core():
                return release
        raise RuntimeEnvironmentError("platform_release does not match a registered Dolphin release")

    def public_projection(self) -> dict[str, Any]:
        releases = []
        for release in self.releases:
            releases.append(
                {
                    **release.registration(),
                    "registration_sha256": release.registration_sha256,
                }
            )
        default_release = self.releases[0].registration()
        return {
            "service": "huabao-worktree-server",
            "environment_schema_version": ENV_SCHEMA_VERSION,
            "workspace_version": WORKSPACE_VERSION,
            "timezone": "Asia/Shanghai",
            "currency": "CNY",
            "dimensions": ["traffic", "conversion", "product"],
            "dolphin_dispatch_url": self.dolphin_dispatch_url,
            "registered_platform_release": default_release,
            "releases": releases,
        }


def _validate_release(raw: Any, index: int) -> DolphinRelease:
    if not isinstance(raw, dict):
        raise RuntimeEnvironmentError(f"release allowlist item {index} must be an object")
    expected = {"release_id", *RELEASE_FIELDS}
    if set(raw) != expected:
        raise RuntimeEnvironmentError(
            f"release allowlist item {index} must contain exactly {sorted(expected)}"
        )
    if not all(isinstance(raw[key], str) and raw[key] for key in expected):
        raise RuntimeEnvironmentError(f"release allowlist item {index} values must be strings")
    if not _RELEASE_ID_RE.fullmatch(raw["release_id"]):
        raise RuntimeEnvironmentError(f"release allowlist item {index} has invalid release_id")
    if raw["platform"] != "dolphin-ai":
        raise RuntimeEnvironmentError("only platform=dolphin-ai is allowed")
    if raw["application_id"] != "huabao-health-inspection":
        raise RuntimeEnvironmentError("unexpected Dolphin application_id")
    for field in ("release_version", "workflow_version"):
        if not _VERSION_RE.fullmatch(raw[field]):
            raise RuntimeEnvironmentError(f"invalid {field}: {raw[field]}")
    for field in ("skill_bundle_sha256", "schema_bundle_sha256"):
        if not _SHA256_RE.fullmatch(raw[field]):
            raise RuntimeEnvironmentError(f"invalid {field}")
    return DolphinRelease(**{key: raw[key] for key in ("release_id", *RELEASE_FIELDS)})


def load_workspace_config(project_root: Path) -> WorkspaceRuntimeConfig:
    project_root = project_root.resolve()
    values = parse_env_file(project_root / ENV_RELATIVE_PATH)
    if values.get("HUABAO_WORKSPACE_ENV_SCHEMA_VERSION") != ENV_SCHEMA_VERSION:
        raise RuntimeEnvironmentError("unsupported HUABAO_WORKSPACE_ENV_SCHEMA_VERSION")

    host = values.get("HUABAO_WORKSPACE_HOST", "127.0.0.1")
    if host not in {"127.0.0.1", "::1", "localhost"}:
        raise RuntimeEnvironmentError("Workspace Server must bind to loopback")
    try:
        port = int(values.get("HUABAO_WORKSPACE_PORT", "8765"))
        max_json_bytes = int(values.get("HUABAO_WORKSPACE_MAX_JSON_BYTES", "262144"))
    except ValueError as exc:
        raise RuntimeEnvironmentError("port and max JSON bytes must be integers") from exc
    if not 1024 <= port <= 65535:
        raise RuntimeEnvironmentError("Workspace Server port is outside 1024..65535")
    if not 4096 <= max_json_bytes <= 4 * 1024 * 1024:
        raise RuntimeEnvironmentError("max JSON bytes is outside 4 KiB..4 MiB")

    dispatch = values.get("HUABAO_DOLPHIN_DISPATCH_URL", "") or None
    if dispatch is not None:
        parsed = urlsplit(dispatch)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise RuntimeEnvironmentError("HUABAO_DOLPHIN_DISPATCH_URL must be http(s)")
        if parsed.username or parsed.password or parsed.fragment:
            raise RuntimeEnvironmentError("dispatch URL may not embed credentials or fragments")

    encoded = values.get("HUABAO_DOLPHIN_RELEASE_ALLOWLIST_JSON")
    if encoded is None:
        raise RuntimeEnvironmentError("Dolphin release allowlist is missing")
    try:
        raw_releases = json.loads(encoded)
    except json.JSONDecodeError as exc:
        raise RuntimeEnvironmentError("Dolphin release allowlist is invalid JSON") from exc
    if not isinstance(raw_releases, list) or not raw_releases:
        raise RuntimeEnvironmentError("Dolphin release allowlist must be a non-empty array")
    if len(raw_releases) > 32:
        raise RuntimeEnvironmentError("Dolphin release allowlist exceeds 32 releases")
    releases = tuple(_validate_release(value, index) for index, value in enumerate(raw_releases))
    release_ids = [release.release_id for release in releases]
    if len(release_ids) != len(set(release_ids)):
        raise RuntimeEnvironmentError("Dolphin release_id values must be unique")
    registrations = [release.registration_sha256 for release in releases]
    if len(registrations) != len(set(registrations)):
        raise RuntimeEnvironmentError("duplicate Dolphin release registrations are forbidden")
    return WorkspaceRuntimeConfig(
        project_root=project_root,
        host=host,
        port=port,
        max_json_bytes=max_json_bytes,
        dolphin_dispatch_url=dispatch,
        releases=releases,
    )


def load_project_env(project_root: Path, *, role: str = "server") -> dict[str, str]:
    """Compatibility entry point used by trusted supervisor utilities."""

    del role
    values = parse_env_file(project_root.resolve() / ENV_RELATIVE_PATH)
    load_workspace_config(project_root)
    return values


def project_venv_child_env(
    project_root: Path,
    *,
    base_env: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Return a sanitized direct-argv child environment.

    This helper does not activate a virtual environment.  It only points PATH at
    the repository-local interpreter when one exists and removes Python process
    injection variables.
    """

    root = project_root.resolve()
    result: MutableMapping[str, str] = dict(base_env or os.environ)
    for key in (
        "VIRTUAL_ENV",
        "PYTHONHOME",
        "PYTHONPATH",
        "PYTHONUSERBASE",
        "PYTHONSTARTUP",
    ):
        result.pop(key, None)
    scripts = root / "shared" / ".venv" / ("Scripts" if os.name == "nt" else "bin")
    if scripts.is_dir():
        current = result.get("PATH", "")
        result["PATH"] = str(scripts) + (os.pathsep + current if current else "")
        result["VIRTUAL_ENV"] = str(root / "shared" / ".venv")
    result["PYTHONNOUSERSITE"] = "1"
    result["PYTHONUTF8"] = "1"
    return dict(result)


def python_version_is_supported() -> bool:
    return sys.version_info >= (3, 11)
