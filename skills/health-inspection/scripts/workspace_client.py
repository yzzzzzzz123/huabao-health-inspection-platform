"""Strict Artifact-ID client for the Huabao Worktree Server.

The client never accepts a server path. Every workspace read or write is
addressed by a contract artifact ID and bound to one immutable incarnation and
platform release.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import date
from hashlib import sha256
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen


ARTIFACT_ID_RE = re.compile(r"^[a-z][a-z0-9_]{1,127}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
RUN_ID_RE = re.compile(r"^hi-\d{4}-\d{2}-\d{2}$")
PLATFORM_RELEASE_FIELDS = {
    "platform",
    "application_id",
    "release_version",
    "workflow_version",
    "skill_bundle_sha256",
    "schema_bundle_sha256",
    "bound_at",
}
MAX_RESPONSE_BYTES = 32 * 1024 * 1024


class WorkspaceClientError(RuntimeError):
    """Base error for a fail-closed Workspace API operation."""


class WorkspaceConflictError(WorkspaceClientError):
    """The requested immutable operation conflicts with server state."""


class WorkspaceNotFoundError(WorkspaceClientError):
    """A workspace or artifact does not exist."""


class WorkspaceTransportError(WorkspaceClientError):
    """The Workspace API could not be reached or returned invalid transport data."""


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _sha256(value: bytes) -> str:
    return sha256(value).hexdigest()


def _validate_business_date(value: str) -> str:
    parsed = date.fromisoformat(value)
    if parsed.isoformat() != value:
        raise WorkspaceClientError("business_date must use YYYY-MM-DD")
    return value


def _validate_artifact_id(value: str) -> str:
    if ARTIFACT_ID_RE.fullmatch(value) is None:
        raise WorkspaceClientError(f"invalid artifact ID: {value!r}")
    return value


def _strict_platform_release(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != PLATFORM_RELEASE_FIELDS:
        raise WorkspaceClientError(
            "platform_release must contain exactly the seven binding fields"
        )
    release = dict(value)
    if release["platform"] != "dolphin-ai":
        raise WorkspaceClientError("unexpected platform binding")
    if release["application_id"] != "huabao-health-inspection":
        raise WorkspaceClientError("unexpected application binding")
    for key in ("release_version", "workflow_version"):
        if re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", str(release[key])) is None:
            raise WorkspaceClientError(f"invalid {key}")
    for key in ("skill_bundle_sha256", "schema_bundle_sha256"):
        if SHA256_RE.fullmatch(str(release[key])) is None:
            raise WorkspaceClientError(f"invalid {key}")
    if not isinstance(release["bound_at"], str) or not release["bound_at"]:
        raise WorkspaceClientError("platform_release.bound_at is required")
    return release


@dataclass(frozen=True)
class WorkspaceAccessBinding:
    """Minimum persisted secret binding required to read one workspace."""

    run_id: str
    incarnation_id: str
    platform_release_sha256: str

    @classmethod
    def create(
        cls,
        *,
        run_id: str,
        incarnation_id: str,
        platform_release_sha256: str,
    ) -> "WorkspaceAccessBinding":
        if RUN_ID_RE.fullmatch(run_id) is None:
            raise WorkspaceClientError("invalid run_id")
        if (
            not incarnation_id
            or len(incarnation_id) > 200
            or "\r" in incarnation_id
            or "\n" in incarnation_id
        ):
            raise WorkspaceClientError("invalid workspace incarnation_id")
        if SHA256_RE.fullmatch(platform_release_sha256) is None:
            raise WorkspaceClientError("invalid platform release SHA-256")
        return cls(
            run_id=run_id,
            incarnation_id=incarnation_id,
            platform_release_sha256=platform_release_sha256,
        )

    def headers(self) -> dict[str, str]:
        return {
            "X-Workspace-Incarnation": self.incarnation_id,
            "X-Platform-Release-SHA256": self.platform_release_sha256,
        }


@dataclass(frozen=True)
class WorkspaceBinding:
    run_id: str
    business_date: str
    incarnation_id: str
    platform_release_sha256: str
    platform_release: dict[str, Any]
    status: str
    workspace_version: str

    @classmethod
    def from_payload(cls, payload: Any) -> "WorkspaceBinding":
        if not isinstance(payload, dict):
            raise WorkspaceClientError("workspace response must be an object")
        run_id = str(payload.get("run_id") or "")
        business_date = _validate_business_date(
            str(payload.get("business_date") or "")
        )
        if RUN_ID_RE.fullmatch(run_id) is None or run_id != f"hi-{business_date}":
            raise WorkspaceClientError("workspace run identity is invalid")
        incarnation_id = str(payload.get("incarnation_id") or "")
        if not incarnation_id:
            raise WorkspaceClientError("workspace incarnation_id is missing")
        release = _strict_platform_release(payload.get("platform_release"))
        release_sha = str(payload.get("platform_release_sha256") or "")
        if (
            SHA256_RE.fullmatch(release_sha) is None
            or release_sha != _sha256(_canonical_bytes(release))
        ):
            raise WorkspaceClientError("workspace platform release hash is invalid")
        version = payload.get("workspace_version")
        if version != "2.0":
            raise WorkspaceClientError("workspace_version must be exactly '2.0'")
        status = str(payload.get("status") or "")
        if not status:
            raise WorkspaceClientError("workspace status is missing")
        return cls(
            run_id=run_id,
            business_date=business_date,
            incarnation_id=incarnation_id,
            platform_release_sha256=release_sha,
            platform_release=release,
            status=status,
            workspace_version=version,
        )

    def headers(self) -> dict[str, str]:
        return {
            "X-Workspace-Incarnation": self.incarnation_id,
            "X-Platform-Release-SHA256": self.platform_release_sha256,
        }


@dataclass(frozen=True)
class ArtifactMetadata:
    artifact_id: str
    sha256: str
    bytes: int
    media_type: str
    ui_visible: bool

    @classmethod
    def from_payload(cls, value: Any) -> "ArtifactMetadata":
        if not isinstance(value, dict):
            raise WorkspaceClientError("artifact metadata must be an object")
        artifact_id = _validate_artifact_id(str(value.get("id") or ""))
        digest = str(value.get("sha256") or "")
        if SHA256_RE.fullmatch(digest) is None:
            raise WorkspaceClientError(f"{artifact_id}: invalid artifact SHA-256")
        length = value.get("bytes")
        if isinstance(length, bool) or not isinstance(length, int) or length < 0:
            raise WorkspaceClientError(f"{artifact_id}: invalid artifact byte count")
        media_type = str(value.get("media_type") or "")
        if not media_type:
            raise WorkspaceClientError(f"{artifact_id}: media_type is missing")
        return cls(
            artifact_id=artifact_id,
            sha256=digest,
            bytes=length,
            media_type=media_type,
            ui_visible=bool(value.get("ui_visible")),
        )


class WorkspaceClient:
    def __init__(self, base_url: str, *, timeout: float = 20.0) -> None:
        parsed = urlsplit(base_url)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.netloc
            or parsed.query
            or parsed.fragment
        ):
            raise WorkspaceClientError("workspace URL must be an HTTP(S) origin")
        if timeout <= 0 or timeout > 120:
            raise WorkspaceClientError("timeout must be within (0, 120] seconds")
        self.base_url = base_url.rstrip("/")
        self.timeout = float(timeout)

    def _request(
        self,
        method: str,
        path: str,
        *,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
        expected: set[int],
    ) -> tuple[int, dict[str, str], bytes]:
        request_headers = {
            "Accept": "application/json",
            "User-Agent": "huabao-dolphin-workspace-client/1.0",
            **(headers or {}),
        }
        request = Request(
            f"{self.base_url}{path}",
            data=body,
            headers=request_headers,
            method=method,
        )
        try:
            with urlopen(request, timeout=self.timeout) as response:
                payload = response.read(MAX_RESPONSE_BYTES + 1)
                status = int(response.status)
                response_headers = {
                    key.lower(): value for key, value in response.headers.items()
                }
        except HTTPError as exc:
            payload = exc.read(1024 * 1024)
            message = payload.decode("utf-8", errors="replace").strip()
            if exc.code in {409, 412}:
                raise WorkspaceConflictError(
                    f"Workspace API conflict ({exc.code}): {message}"
                ) from exc
            if exc.code == 404:
                raise WorkspaceNotFoundError(
                    f"Workspace API resource not found: {path}"
                ) from exc
            raise WorkspaceClientError(
                f"Workspace API rejected {method} {path} ({exc.code}): {message}"
            ) from exc
        except (URLError, TimeoutError, OSError) as exc:
            raise WorkspaceTransportError(
                f"Workspace API transport failed for {method} {path}: {exc}"
            ) from exc
        if len(payload) > MAX_RESPONSE_BYTES:
            raise WorkspaceTransportError("Workspace API response exceeds 32 MiB")
        if status not in expected:
            raise WorkspaceClientError(
                f"Workspace API returned unexpected status {status}"
            )
        return status, response_headers, payload

    @staticmethod
    def _json(payload: bytes) -> dict[str, Any]:
        try:
            value = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise WorkspaceTransportError(
                "Workspace API returned invalid UTF-8 JSON"
            ) from exc
        if not isinstance(value, dict):
            raise WorkspaceTransportError("Workspace API JSON must be an object")
        return value

    def create_workspace(
        self,
        *,
        business_date: str,
        platform_release: dict[str, Any],
    ) -> tuple[WorkspaceBinding, dict[str, Any]]:
        _validate_business_date(business_date)
        request_release = dict(platform_release)
        request_release.pop("bound_at", None)
        expected_fields = PLATFORM_RELEASE_FIELDS - {"bound_at"}
        if set(request_release) != expected_fields:
            raise WorkspaceClientError(
                "create release must contain the six client-owned release fields"
            )
        body = _canonical_bytes(
            {
                "business_date": business_date,
                "platform_release": request_release,
            }
        )
        _, _, raw = self._request(
            "POST",
            "/api/workspaces",
            body=body,
            headers={"Content-Type": "application/json; charset=utf-8"},
            expected={200, 201},
        )
        payload = self._json(raw)
        return WorkspaceBinding.from_payload(payload), payload

    def get_workspace(
        self,
        run_id: str,
        *,
        binding: WorkspaceBinding | WorkspaceAccessBinding,
    ) -> tuple[WorkspaceBinding, dict[str, ArtifactMetadata], dict[str, Any]]:
        if RUN_ID_RE.fullmatch(run_id) is None:
            raise WorkspaceClientError("invalid run_id")
        if run_id != binding.run_id:
            raise WorkspaceClientError("workspace URL and binding run_id differ")
        _, _, raw = self._request(
            "GET",
            f"/api/workspaces/{quote(run_id, safe='')}",
            headers=binding.headers(),
            expected={200},
        )
        payload = self._json(raw)
        actual = WorkspaceBinding.from_payload(payload)
        if (
            actual.run_id != binding.run_id
            or actual.incarnation_id != binding.incarnation_id
            or actual.platform_release_sha256
            != binding.platform_release_sha256
        ):
            raise WorkspaceConflictError("workspace binding changed")
        raw_artifacts = payload.get("artifacts") or []
        values = (
            list(raw_artifacts.values())
            if isinstance(raw_artifacts, dict)
            else raw_artifacts
        )
        if not isinstance(values, list):
            raise WorkspaceTransportError("workspace artifacts must be a list or map")
        artifacts: dict[str, ArtifactMetadata] = {}
        for item in values:
            metadata = ArtifactMetadata.from_payload(item)
            if metadata.artifact_id in artifacts:
                raise WorkspaceTransportError("duplicate artifact metadata")
            artifacts[metadata.artifact_id] = metadata
        return actual, artifacts, payload

    def get_artifact(
        self,
        binding: WorkspaceBinding,
        artifact_id: str,
        *,
        expected_sha256: str | None = None,
    ) -> tuple[bytes, str]:
        artifact_id = _validate_artifact_id(artifact_id)
        _, headers, payload = self._request(
            "GET",
            (
                f"/api/workspaces/{quote(binding.run_id, safe='')}/artifacts/"
                f"{quote(artifact_id, safe='')}"
            ),
            headers=binding.headers(),
            expected={200},
        )
        digest = _sha256(payload)
        declared = (
            headers.get("x-content-sha256")
            or headers.get("etag", "").strip('"')
            or digest
        )
        if SHA256_RE.fullmatch(declared) is None or declared != digest:
            raise WorkspaceTransportError(
                f"{artifact_id}: response hash does not match its bytes"
            )
        if expected_sha256 is not None and digest != expected_sha256:
            raise WorkspaceConflictError(
                f"{artifact_id}: artifact hash differs from expected binding"
            )
        return payload, headers.get("content-type", "application/octet-stream")

    def get_json(
        self,
        binding: WorkspaceBinding,
        artifact_id: str,
        *,
        expected_sha256: str | None = None,
    ) -> Any:
        payload, _ = self.get_artifact(
            binding,
            artifact_id,
            expected_sha256=expected_sha256,
        )
        try:
            return json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise WorkspaceTransportError(
                f"{artifact_id}: artifact is not valid UTF-8 JSON"
            ) from exc

    def put_artifact(
        self,
        binding: WorkspaceBinding,
        artifact_id: str,
        payload: bytes,
        *,
        media_type: str,
    ) -> ArtifactMetadata:
        artifact_id = _validate_artifact_id(artifact_id)
        if not isinstance(payload, bytes):
            raise WorkspaceClientError("artifact payload must be bytes")
        if not media_type or "\r" in media_type or "\n" in media_type:
            raise WorkspaceClientError("invalid artifact media type")
        digest = _sha256(payload)
        path = (
            f"/api/workspaces/{quote(binding.run_id, safe='')}/artifacts/"
            f"{quote(artifact_id, safe='')}"
        )
        headers = {
            **binding.headers(),
            "Content-Type": media_type,
            "If-None-Match": "*",
            "X-Content-SHA256": digest,
            "Accept": "application/json",
        }
        try:
            _, _, raw = self._request(
                "PUT",
                path,
                body=payload,
                headers=headers,
                expected={200, 201},
            )
        except WorkspaceConflictError:
            existing, existing_type = self.get_artifact(binding, artifact_id)
            if _sha256(existing) != digest:
                raise
            return ArtifactMetadata(
                artifact_id=artifact_id,
                sha256=digest,
                bytes=len(existing),
                media_type=existing_type.split(";", 1)[0],
                ui_visible=False,
            )
        response = self._json(raw)
        metadata_value = response.get("artifact", response)
        metadata = ArtifactMetadata.from_payload(metadata_value)
        if (
            metadata.artifact_id != artifact_id
            or metadata.sha256 != digest
            or metadata.bytes != len(payload)
        ):
            raise WorkspaceTransportError(
                f"{artifact_id}: server receipt does not bind uploaded bytes"
            )
        return metadata

    def put_json(
        self,
        binding: WorkspaceBinding,
        artifact_id: str,
        value: Any,
    ) -> ArtifactMetadata:
        payload = json.dumps(
            value,
            ensure_ascii=False,
            indent=2,
        ).encode("utf-8") + b"\n"
        return self.put_artifact(
            binding,
            artifact_id,
            payload,
            media_type="application/json; charset=utf-8",
        )

    def put_text(
        self,
        binding: WorkspaceBinding,
        artifact_id: str,
        value: str,
        *,
        media_type: str = "text/markdown; charset=utf-8",
    ) -> ArtifactMetadata:
        return self.put_artifact(
            binding,
            artifact_id,
            value.encode("utf-8"),
            media_type=media_type,
        )

    def seal(
        self,
        binding: WorkspaceBinding,
        *,
        delivery_manifest_sha256: str,
    ) -> dict[str, Any]:
        if SHA256_RE.fullmatch(delivery_manifest_sha256) is None:
            raise WorkspaceClientError("invalid delivery manifest SHA-256")
        body = _canonical_bytes(
            {"delivery_manifest_sha256": delivery_manifest_sha256}
        )
        _, _, raw = self._request(
            "POST",
            f"/api/workspaces/{quote(binding.run_id, safe='')}/seal",
            body=body,
            headers={
                **binding.headers(),
                "Content-Type": "application/json; charset=utf-8",
            },
            expected={200, 201},
        )
        return self._json(raw)

    def delete(self, binding: WorkspaceBinding) -> dict[str, Any]:
        _, _, raw = self._request(
            "DELETE",
            f"/api/workspaces/{quote(binding.run_id, safe='')}",
            headers=binding.headers(),
            expected={200},
        )
        return self._json(raw)


__all__ = [
    "ArtifactMetadata",
    "WorkspaceAccessBinding",
    "WorkspaceBinding",
    "WorkspaceClient",
    "WorkspaceClientError",
    "WorkspaceConflictError",
    "WorkspaceNotFoundError",
    "WorkspaceTransportError",
]
