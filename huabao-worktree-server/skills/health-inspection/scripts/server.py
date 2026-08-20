"""Loopback-only stdlib HTTP server for the Huabao Workspace API."""

from __future__ import annotations

import argparse
import json
import re
import sys
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Mapping, Sequence
from urllib.parse import parse_qs, unquote, urlsplit


SCRIPT_DIR = Path(__file__).resolve().parent
SERVER_ROOT = SCRIPT_DIR.parents[2]
REPOSITORY_ROOT = SERVER_ROOT.parent
if str(SERVER_ROOT) not in sys.path:
    sys.path.insert(0, str(SERVER_ROOT))
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from shared.runtime_env import RuntimeEnvironmentError, load_workspace_config  # noqa: E402
from workbench_compat import (  # noqa: E402
    config_projection,
    health_policy_projection,
    health_policy_version_detail,
    health_policy_versions,
    heatmap,
    inspection_schedule_projection,
    policy_delete_projection,
    policy_draft_projection,
    policy_in_use_versions,
    policy_selection_projection,
    policy_version_projection,
    run_log,
    runs_page,
    snapshot,
)
from workbench_policy_store import (  # noqa: E402
    PolicyConflictError,
    PolicyImmutableError,
    PolicyInUseError,
    PolicyNotFoundError,
    PolicyStore,
    PolicyStoreError,
    PolicyValidationError,
)
from workspace_api import (  # noqa: E402
    WorkspaceAPIError,
    WorkspaceService,
    ensure_public_text_safe,
)


RUN_ID_RE = re.compile(r"^hi-\d{4}-\d{2}-\d{2}$")
ARTIFACT_ID_RE = re.compile(r"^[a-z][a-z0-9_]{0,127}$")
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})
DELIVERY_RECONCILE_INTERVAL_SECONDS = 300.0
DRAFT_ETAG_RE = re.compile(r'^"draft-([1-9][0-9]*)"$')
POLICY_METRIC_MAX_BYTES = 16 * 1024
POLICY_SCORING_MAX_BYTES = 128 * 1024
POLICY_SCHEDULE_MAX_BYTES = 4 * 1024
POLICY_PUBLISH_MAX_BYTES = 8 * 1024
POLICY_SELECT_MAX_BYTES = 1024
LEGACY_DELETE_ERROR_MESSAGES = {
    "invalid_delete_request_id": "删除请求标识无效，请刷新后重试",
    "invalid_query": "删除请求参数无效，请刷新后重试",
    "invalid_url": "删除请求地址无效，请刷新后重试",
    "workbench_origin_required": "删除请求必须来自当前工作台",
    "workbench_origin_mismatch": "删除请求来源与当前工作台不一致",
    "transfer_encoding_forbidden": "删除请求格式不受支持，请刷新后重试",
    "request_body_forbidden": "删除请求不能携带内容，请刷新后重试",
    "workspace_not_found": "该运行已不存在，请刷新运行记录",
    "active_delete_forbidden": "运行仍在执行中，尚未收到安全取消确认，不能删除",
    "active_workspace_exists": "另一运行仍占用控制锁，暂时不能删除",
    "stale_delete_request": "该删除请求属于此前的运行实例，请刷新后重试",
    "archive_residue": "归档路径状态异常，已停止删除",
    "delete_residue": "删除后仍有残留，运行已保留为待清理状态",
    "delete_failed": "级联删除失败，运行已保留为待清理状态",
}
LEGACY_ERROR_MESSAGES = {
    "invalid_query": "请求参数无效，请刷新后重试",
    "invalid_url": "请求地址无效，请刷新后重试",
    "transfer_encoding_forbidden": "请求格式不受支持，请刷新后重试",
    "request_body_forbidden": "该请求不能携带内容，请刷新后重试",
    "legacy_write_unavailable": "可信 Dolphin Workflow 接口尚未配置，该操作暂时不可用",
    "policy_store_unavailable": "系统配置存储暂时不可用，请稍后重试",
}


class DeliveryReconciler:
    """Server-owned, credential-isolated completion-delivery compensator."""

    def __init__(
        self,
        service: WorkspaceService,
        *,
        interval_seconds: float = DELIVERY_RECONCILE_INTERVAL_SECONDS,
    ) -> None:
        self.service = service
        self.interval_seconds = interval_seconds
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._run,
            name="huabao-dingtalk-reconciler",
            daemon=True,
        )

    def start(self) -> None:
        self._thread.start()
        self.wake()

    def wake(self) -> None:
        self._wake.set()

    def close(self) -> None:
        self._stop.set()
        self._wake.set()
        self._thread.join(timeout=30.0)

    def _run(self) -> None:
        while not self._stop.is_set():
            self._wake.wait(self.interval_seconds)
            self._wake.clear()
            if self._stop.is_set():
                return
            try:
                workspaces = self.service.list_workspaces()
            except Exception:
                continue
            for workspace in workspaces:
                if self._stop.is_set():
                    return
                if workspace.get("status") != "sealed":
                    continue
                try:
                    self.service.reconcile_completed_delivery(str(workspace["run_id"]))
                except Exception:
                    # Completion remains authoritative. Receipt state decides
                    # whether a later scan may safely compensate.
                    continue


class WorkspaceHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        address: tuple[str, int],
        service: WorkspaceService,
        delivery_reconciler: DeliveryReconciler,
        policy_store: PolicyStore | None = None,
    ) -> None:
        self.service = service
        self.delivery_reconciler = delivery_reconciler
        self.policy_store = policy_store or PolicyStore(service.project_root)
        super().__init__(address, WorkspaceRequestHandler)

    def handle_error(self, request: Any, client_address: Any) -> None:
        error = sys.exc_info()[1]
        if isinstance(error, (BrokenPipeError, ConnectionResetError)):
            return
        super().handle_error(request, client_address)


class WorkspaceRequestHandler(BaseHTTPRequestHandler):
    server: WorkspaceHTTPServer
    protocol_version = "HTTP/1.1"
    server_version = "HuabaoWorkspace/2.0"

    def log_message(self, format_string: str, *arguments: Any) -> None:
        # Standard request line and status only. Request headers and bodies are
        # deliberately excluded because they include workspace capabilities.
        super().log_message(format_string, *arguments)

    def _security_headers(self) -> None:
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
            "connect-src 'self' http: https:; object-src 'none'; base-uri 'none'",
        )

    def _send_bytes(
        self,
        status: int,
        body: bytes,
        *,
        content_type: str,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        try:
            self.send_response(status)
            self._security_headers()
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            if headers:
                for key, value in headers.items():
                    self.send_header(key, value)
            self.end_headers()
            self.close_connection = True
            if self.command != "HEAD":
                self.wfile.write(body)
        except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError):
            # A browser may cancel a stale polling response after opening a
            # newer snapshot request. The response is already irrelevant to
            # that client and must not be reclassified/logged as a server 500.
            self.close_connection = True

    def _send_json(self, status: int, value: Any, *, headers: Mapping[str, str] | None = None) -> None:
        body = (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode(
            "utf-8"
        )
        self._send_bytes(
            status,
            body,
            content_type="application/json; charset=utf-8",
            headers=headers,
        )

    def _send_error(self, error: WorkspaceAPIError) -> None:
        self._send_json(error.status, error.as_dict())

    @staticmethod
    def _policy_api_error(error: PolicyStoreError) -> WorkspaceAPIError:
        if isinstance(error, PolicyNotFoundError):
            status = HTTPStatus.NOT_FOUND
        elif isinstance(
            error,
            (PolicyConflictError, PolicyImmutableError, PolicyInUseError),
        ):
            status = HTTPStatus.CONFLICT
        elif isinstance(error, PolicyValidationError):
            status = HTTPStatus.UNPROCESSABLE_ENTITY
        else:
            status = HTTPStatus.SERVICE_UNAVAILABLE
        code = getattr(error, "code", "policy_store_unavailable")
        if status == HTTPStatus.SERVICE_UNAVAILABLE:
            code = "policy_store_unavailable"
        return WorkspaceAPIError(int(status), str(code), str(error))

    def _send_policy_error(self, error: PolicyStoreError) -> None:
        self._send_error(self._policy_api_error(error))

    def _is_legacy_workbench_request(self) -> bool:
        path = urlsplit(self.path).path
        return (
            path == "/api/runs"
            or path.startswith("/api/runs/")
            or path == "/api/health-policy"
            or path.startswith("/api/health-policy/")
            or path == "/api/inspection-schedule"
        )

    def _send_workbench_error(self, error: WorkspaceAPIError) -> None:
        delete_request = (
            self.command == "DELETE"
            and urlsplit(self.path).path.startswith("/api/runs/")
        )
        messages = LEGACY_DELETE_ERROR_MESSAGES if delete_request else LEGACY_ERROR_MESSAGES
        message = messages.get(
            error.code,
            (
                "删除失败，请刷新运行记录后重试"
                if delete_request
                else "操作失败，请刷新页面后重试"
            )
            if error.status >= 500
            else (
                "当前运行不能删除，请刷新后重试"
                if delete_request
                else error.message
            ),
        )
        self._send_json(error.status, {"error": message, "type": error.code})

    def _segments(self, *, allow_query: bool = False) -> list[str]:
        parsed = urlsplit(self.path)
        if (parsed.query and not allow_query) or parsed.fragment:
            raise WorkspaceAPIError(400, "invalid_url", "query strings and fragments are not supported")
        try:
            segments = [unquote(item, errors="strict") for item in parsed.path.split("/") if item]
        except UnicodeDecodeError as exc:
            raise WorkspaceAPIError(400, "invalid_url", "URL path encoding is invalid") from exc
        if any("/" in item or "\\" in item or "\x00" in item or item in {".", ".."} for item in segments):
            raise WorkspaceAPIError(400, "invalid_url", "URL path segment is invalid")
        return segments

    def _query(self) -> dict[str, list[str]]:
        parsed = urlsplit(self.path)
        try:
            return parse_qs(
                parsed.query,
                keep_blank_values=True,
                strict_parsing=True,
                max_num_fields=32,
            )
        except ValueError as exc:
            raise WorkspaceAPIError(400, "invalid_query", "query string is invalid") from exc

    @staticmethod
    def _reject_query(query: Mapping[str, Sequence[str]]) -> None:
        if query:
            raise WorkspaceAPIError(400, "invalid_url", "query strings are not supported for this route")

    @staticmethod
    def _legacy_write_unavailable(resource: str) -> None:
        raise WorkspaceAPIError(
            503,
            "legacy_write_unavailable",
            f"{resource} is read-only until the trusted Dolphin Gateway and storage contract are deployed",
        )

    def _require_same_origin_workbench_request(self) -> None:
        host_values = self.headers.get_all("Host") or []
        origin_values = self.headers.get_all("Origin") or []
        if len(host_values) != 1 or len(origin_values) != 1:
            raise WorkspaceAPIError(
                403,
                "workbench_origin_required",
                "destructive workbench requests require one Host and Origin header",
            )
        try:
            host = urlsplit(f"//{host_values[0]}")
            origin = urlsplit(origin_values[0])
            bound_port = int(self.server.server_address[1])
            host_port = host.port or (80 if origin.scheme == "http" else None)
            origin_port = origin.port or (80 if origin.scheme == "http" else None)
        except (TypeError, ValueError) as exc:
            raise WorkspaceAPIError(
                403,
                "workbench_origin_mismatch",
                "workbench origin is invalid",
            ) from exc
        host_name = (host.hostname or "").lower()
        origin_name = (origin.hostname or "").lower()
        if (
            origin.scheme != "http"
            or host.username is not None
            or host.password is not None
            or origin.username is not None
            or origin.password is not None
            or host_name not in LOOPBACK_HOSTS
            or origin_name != host_name
            or host_port != bound_port
            or origin_port != bound_port
            or host.path
            or host.query
            or host.fragment
            or origin.path
            or origin.query
            or origin.fragment
        ):
            raise WorkspaceAPIError(
                403,
                "workbench_origin_mismatch",
                "workbench origin does not match the loopback server",
            )

    def _content_length(self, *, maximum: int) -> int:
        if self.headers.get("Transfer-Encoding"):
            raise WorkspaceAPIError(400, "transfer_encoding_forbidden", "chunked requests are forbidden")
        values = self.headers.get_all("Content-Length") or []
        if len(values) != 1:
            raise WorkspaceAPIError(
                400 if values else 411,
                "ambiguous_content_length" if values else "content_length_required",
                "exactly one Content-Length header is required",
            )
        raw = values[0]
        if not raw.isdigit():
            raise WorkspaceAPIError(411, "content_length_required", "Content-Length is required")
        length = int(raw)
        if length > maximum:
            raise WorkspaceAPIError(413, "request_too_large", "request body exceeds maximum")
        return length

    def _read_json(
        self,
        *,
        allow_empty: bool = False,
        maximum: int | None = None,
    ) -> Any:
        limit = min(
            int(maximum or self.server.service.config.max_json_bytes),
            int(self.server.service.config.max_json_bytes),
        )
        length = self._content_length(maximum=limit)
        if length == 0 and allow_empty:
            return {}
        media_type = self.headers.get("Content-Type", "").partition(";")[0].strip().lower()
        if media_type != "application/json":
            raise WorkspaceAPIError(415, "json_required", "Content-Type must be application/json")
        body = self.rfile.read(length)
        if len(body) != length:
            raise WorkspaceAPIError(400, "request_truncated", "request body was truncated")
        try:
            return json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise WorkspaceAPIError(400, "invalid_json", "request body must be UTF-8 JSON") from exc

    @staticmethod
    def _policy_object(
        value: Any,
        *,
        fields: frozenset[str],
        resource: str,
    ) -> dict[str, Any]:
        if not isinstance(value, dict) or set(value) != fields:
            raise WorkspaceAPIError(
                422,
                "invalid_policy_request",
                f"{resource} body must contain exactly: {', '.join(sorted(fields))}",
            )
        return value

    def _draft_revision(self, request: Mapping[str, Any]) -> int:
        values = self.headers.get_all("If-Match") or []
        if not values:
            raise WorkspaceAPIError(
                428,
                "draft_precondition_required",
                "If-Match with the current draft ETag is required",
            )
        if len(values) != 1:
            raise WorkspaceAPIError(
                400,
                "invalid_draft_precondition",
                "If-Match may be supplied only once",
            )
        match = DRAFT_ETAG_RE.fullmatch(values[0].strip())
        if match is None:
            raise WorkspaceAPIError(
                400,
                "invalid_draft_precondition",
                'If-Match must use the exact form "draft-N"',
            )
        revision = request.get("draft_revision")
        if isinstance(revision, bool) or not isinstance(revision, int) or revision < 1:
            raise WorkspaceAPIError(
                422,
                "invalid_policy_request",
                "draft_revision must be a positive integer",
            )
        if int(match.group(1)) != revision:
            raise WorkspaceAPIError(
                409,
                "draft_revision_mismatch",
                "If-Match and draft_revision disagree",
            )
        return revision

    def _require_empty_body(self) -> None:
        if self.headers.get("Transfer-Encoding"):
            raise WorkspaceAPIError(
                400,
                "transfer_encoding_forbidden",
                "chunked requests are forbidden",
            )
        values = self.headers.get_all("Content-Length") or []
        if len(values) > 1 or (values and values[0] != "0"):
            raise WorkspaceAPIError(
                400,
                "request_body_forbidden",
                "this request does not accept a body",
            )

    def _binding(self) -> tuple[str, str]:
        return (
            self.headers.get("X-Workspace-Incarnation", ""),
            self.headers.get("X-Platform-Release-SHA256", ""),
        )

    @staticmethod
    def _route_identity(segments: Sequence[str]) -> tuple[str, str | None]:
        if len(segments) < 3 or segments[:2] != ["api", "workspaces"]:
            raise WorkspaceAPIError(404, "route_not_found", "route does not exist")
        run_id = segments[2]
        if not RUN_ID_RE.fullmatch(run_id):
            raise WorkspaceAPIError(404, "workspace_not_found", "workspace does not exist")
        artifact_id = None
        if len(segments) == 5 and segments[3] == "artifacts":
            artifact_id = segments[4]
            if not ARTIFACT_ID_RE.fullmatch(artifact_id):
                raise WorkspaceAPIError(404, "artifact_not_registered", "artifact ID is not registered")
        return run_id, artifact_id

    def do_HEAD(self) -> None:  # noqa: N802
        self.do_GET()

    def do_GET(self) -> None:  # noqa: N802
        try:
            segments = self._segments(allow_query=True)
            query = self._query()
            if not segments:
                self._reject_query(query)
                html = SERVER_ROOT / "huabao-new-energy-ai.html"
                if html.is_file():
                    body = html.read_bytes()
                else:
                    body = (
                        "<!doctype html><html lang='zh-CN'><meta charset='utf-8'>"
                        "<title>华宝健康巡检</title><body><h1>Workspace Server</h1></body></html>"
                    ).encode("utf-8")
                self._send_bytes(HTTPStatus.OK, body, content_type="text/html; charset=utf-8")
                return
            if segments == ["favicon.ico"]:
                self._reject_query(query)
                self._send_bytes(HTTPStatus.NO_CONTENT, b"", content_type="image/x-icon")
                return
            if segments == ["api", "health"]:
                self._reject_query(query)
                self._send_json(
                    HTTPStatus.OK,
                    {"ok": True, "service": "huabao-worktree-server", "workspace_version": "2.0"},
                )
                return
            if segments == ["api", "config"]:
                self._reject_query(query)
                self._send_json(
                    HTTPStatus.OK,
                    config_projection(self.server.service, self.server.policy_store),
                )
                return
            if segments == ["api", "runs", "heatmap"]:
                unknown = set(query) - {"year", "policy_version"}
                if unknown:
                    raise WorkspaceAPIError(
                        400,
                        "invalid_query",
                        f"unsupported heatmap query parameter: {sorted(unknown)[0]}",
                    )
                years = query.get("year", [])
                policy_versions = query.get("policy_version", [])
                if len(years) != 1 or len(policy_versions) > 1:
                    raise WorkspaceAPIError(
                        400,
                        "invalid_query",
                        "heatmap requires one year and at most one policy_version",
                    )
                self._send_json(
                    HTTPStatus.OK,
                    heatmap(
                        self.server.service,
                        years[0],
                        policy_versions[0] if policy_versions else None,
                    ),
                )
                return
            if segments == ["api", "runs"]:
                self._send_json(HTTPStatus.OK, runs_page(self.server.service, query))
                return
            if len(segments) == 4 and segments[:2] == ["api", "runs"]:
                self._reject_query(query)
                run_id = segments[2]
                if not RUN_ID_RE.fullmatch(run_id):
                    raise WorkspaceAPIError(404, "run_not_found", "run does not exist")
                if segments[3] == "snapshot":
                    self._send_json(HTTPStatus.OK, snapshot(self.server.service, run_id))
                    return
                if segments[3] == "log":
                    self._send_json(HTTPStatus.OK, run_log(self.server.service, run_id))
                    return
                if segments[3] == "events":
                    # The compatibility workbench opens EventSource only for
                    # live progress. Dolphin dispatch is fail-closed here, so
                    # verify the identity and end the stream immediately.
                    run_log(self.server.service, run_id)
                    self._send_bytes(
                        HTTPStatus.NO_CONTENT,
                        b"",
                        content_type="text/event-stream; charset=utf-8",
                    )
                    return
            if segments == ["api", "inspection-schedule"]:
                self._reject_query(query)
                self._send_json(
                    HTTPStatus.OK,
                    inspection_schedule_projection(
                        self.server.service,
                        self.server.policy_store,
                    ),
                )
                return
            if segments == ["api", "health-policy"]:
                unknown = set(query) - {"run_id"}
                run_ids = query.get("run_id", [])
                if unknown or len(run_ids) > 1:
                    raise WorkspaceAPIError(
                        400,
                        "invalid_query",
                        "health-policy accepts at most one run_id query parameter",
                    )
                self._send_json(
                    HTTPStatus.OK,
                    health_policy_projection(
                        self.server.service,
                        run_ids[0] if run_ids and run_ids[0] else None,
                        self.server.policy_store,
                    ),
                )
                return
            if segments == ["api", "health-policy", "versions"]:
                self._send_json(
                    HTTPStatus.OK,
                    health_policy_versions(
                        self.server.service,
                        query,
                        self.server.policy_store,
                    ),
                )
                return
            if len(segments) == 4 and segments[:3] == ["api", "health-policy", "versions"]:
                self._reject_query(query)
                self._send_json(
                    HTTPStatus.OK,
                    health_policy_version_detail(
                        self.server.service,
                        segments[3],
                        self.server.policy_store,
                    ),
                )
                return
            if segments == ["api", "workspaces"]:
                self._reject_query(query)
                summaries = [
                    {
                        "run_id": item["run_id"],
                        "business_date": item["business_date"],
                        "status": item["status"],
                        "workspace_version": item["workspace_version"],
                    }
                    for item in self.server.service.list_workspaces()
                ]
                self._send_json(HTTPStatus.OK, {"workspaces": summaries})
                return
            self._reject_query(query)
            run_id, artifact_id = self._route_identity(segments)
            if len(segments) == 4 and segments[3] == "projection":
                self._send_json(
                    HTTPStatus.OK,
                    self.server.service.get_workbench_projection(run_id),
                )
                return
            if len(segments) == 3:
                incarnation, release_sha = self._binding()
                self._send_json(
                    HTTPStatus.OK,
                    self.server.service.get_workspace(
                        run_id,
                        incarnation_id=incarnation,
                        release_sha256=release_sha,
                    ),
                )
                return
            if artifact_id is not None:
                incarnation, release_sha = self._binding()
                content, media_type, metadata = self.server.service.get_artifact(
                    run_id,
                    artifact_id,
                    incarnation_id=incarnation,
                    release_sha256=release_sha,
                )
                self._send_bytes(
                    HTTPStatus.OK,
                    content,
                    content_type=media_type + ("; charset=utf-8" if media_type.startswith("text/") else ""),
                    headers={
                        "ETag": f'"{metadata["sha256"]}"',
                        "X-Artifact-ID": metadata["id"],
                        "X-Artifact-SHA256": metadata["sha256"],
                        "X-Content-SHA256": metadata["sha256"],
                    },
                )
                return
            raise WorkspaceAPIError(404, "route_not_found", "route does not exist")
        except WorkspaceAPIError as exc:
            if self._is_legacy_workbench_request():
                self._send_workbench_error(exc)
            else:
                self._send_error(exc)
        except PolicyStoreError as exc:
            if self._is_legacy_workbench_request():
                self._send_workbench_error(self._policy_api_error(exc))
            else:
                self._send_policy_error(exc)
        except Exception:
            error = WorkspaceAPIError(
                500,
                "internal_error",
                "Workspace Server encountered an internal error",
            )
            if self._is_legacy_workbench_request():
                self._send_workbench_error(error)
            else:
                self._send_error(error)

    def do_POST(self) -> None:  # noqa: N802
        try:
            segments = self._segments()
            if segments[:2] == ["api", "runs"]:
                self._legacy_write_unavailable("legacy run mutation")
            if segments == ["api", "health-policy", "publish"]:
                request = self._policy_object(
                    self._read_json(maximum=POLICY_PUBLISH_MAX_BYTES),
                    fields=frozenset(
                        {"draft_revision", "activation_mode", "effective_at", "note"}
                    ),
                    resource="policy publish",
                )
                if isinstance(request["note"], str):
                    ensure_public_text_safe(request["note"], source="policy publish note")
                with self.server.service.admission_lock():
                    response = self.server.policy_store.publish(
                        request["draft_revision"],
                        request["activation_mode"],
                        request["effective_at"],
                        request["note"],
                    )
                self._send_json(
                    HTTPStatus.CREATED,
                    policy_version_projection(response),
                    headers={"Location": f'/api/health-policy/versions/{response["version"]}'},
                )
                return
            if (
                len(segments) == 5
                and segments[:3] == ["api", "health-policy", "versions"]
                and segments[4] == "select"
            ):
                request = self._read_json(
                    allow_empty=True,
                    maximum=POLICY_SELECT_MAX_BYTES,
                )
                if request != {}:
                    raise WorkspaceAPIError(
                        422,
                        "invalid_policy_request",
                        "policy version selection body must be an empty object",
                    )
                with self.server.service.admission_lock():
                    response = self.server.policy_store.select_version(segments[3])
                self._send_json(
                    HTTPStatus.OK,
                    policy_selection_projection(response),
                )
                return
            if segments[:2] == ["api", "health-policy"] or segments == [
                "api",
                "inspection-schedule",
            ]:
                self._legacy_write_unavailable("legacy policy mutation")
            if segments == ["api", "workspaces"]:
                request = self._read_json()
                if not isinstance(request, dict):
                    raise WorkspaceAPIError(400, "invalid_request", "request must be a JSON object")
                response = self.server.service.create_workspace(request)
                self._send_json(
                    HTTPStatus.CREATED,
                    response,
                    headers={"Location": f"/api/workspaces/{response['run_id']}"},
                )
                return
            run_id, artifact_id = self._route_identity(segments)
            if artifact_id is None and len(segments) == 4 and segments[3] == "seal":
                request = self._read_json()
                if not isinstance(request, dict) or set(request) != {"delivery_manifest_sha256"}:
                    raise WorkspaceAPIError(
                        422,
                        "invalid_seal_request",
                        "seal body must contain exactly delivery_manifest_sha256",
                    )
                manifest_sha = request["delivery_manifest_sha256"]
                if not isinstance(manifest_sha, str):
                    raise WorkspaceAPIError(
                        422,
                        "invalid_seal_request",
                        "delivery_manifest_sha256 must be a string",
                    )
                incarnation, release_sha = self._binding()
                response = self.server.service.seal_workspace(
                    run_id,
                    incarnation_id=incarnation,
                    release_sha256=release_sha,
                    delivery_manifest_sha256=manifest_sha,
                )
                self.server.delivery_reconciler.wake()
                self._send_json(HTTPStatus.OK, response)
                return
            raise WorkspaceAPIError(404, "route_not_found", "route does not exist")
        except WorkspaceAPIError as exc:
            if self._is_legacy_workbench_request():
                self._send_workbench_error(exc)
            else:
                self._send_error(exc)
        except PolicyStoreError as exc:
            if self._is_legacy_workbench_request():
                self._send_workbench_error(self._policy_api_error(exc))
            else:
                self._send_policy_error(exc)
        except Exception:
            error = WorkspaceAPIError(
                500,
                "internal_error",
                "Workspace Server encountered an internal error",
            )
            if self._is_legacy_workbench_request():
                self._send_workbench_error(error)
            else:
                self._send_error(error)

    def do_PUT(self) -> None:  # noqa: N802
        try:
            segments = self._segments()
            if (
                len(segments) == 5
                and segments[:4] == ["api", "health-policy", "draft", "metrics"]
            ):
                request = self._policy_object(
                    self._read_json(maximum=POLICY_METRIC_MAX_BYTES),
                    fields=frozenset({"draft_revision", "description", "thresholds"}),
                    resource="policy metric",
                )
                revision = self._draft_revision(request)
                if isinstance(request["description"], str):
                    ensure_public_text_safe(
                        request["description"],
                        source="policy metric description",
                    )
                response = self.server.policy_store.save_metric(
                    segments[4],
                    revision,
                    request["description"],
                    request["thresholds"],
                )
                projected = policy_draft_projection(response)
                self._send_json(
                    HTTPStatus.OK,
                    projected,
                    headers={"ETag": f'"draft-{projected["draft_revision"]}"'},
                )
                return
            if segments == ["api", "health-policy", "draft", "scoring"]:
                request = self._policy_object(
                    self._read_json(maximum=POLICY_SCORING_MAX_BYTES),
                    fields=frozenset({"draft_revision", "scoring_config"}),
                    resource="policy scoring",
                )
                revision = self._draft_revision(request)
                response = self.server.policy_store.save_scoring(
                    revision,
                    request["scoring_config"],
                )
                projected = policy_draft_projection(response)
                self._send_json(
                    HTTPStatus.OK,
                    projected,
                    headers={"ETag": f'"draft-{projected["draft_revision"]}"'},
                )
                return
            if segments in (
                ["api", "health-policy", "draft", "schedule"],
                ["api", "inspection-schedule"],
            ):
                request = self._policy_object(
                    self._read_json(maximum=POLICY_SCHEDULE_MAX_BYTES),
                    fields=frozenset({"draft_revision", "time"}),
                    resource="policy schedule",
                )
                revision = self._draft_revision(request)
                response = self.server.policy_store.save_schedule(
                    request["time"],
                    revision,
                )
                projected = policy_draft_projection(response)
                self._send_json(
                    HTTPStatus.OK,
                    projected,
                    headers={"ETag": f'"draft-{projected["draft_revision"]}"'},
                )
                return
            if segments[:2] == ["api", "health-policy"] or segments == [
                "api",
                "inspection-schedule",
            ]:
                self._legacy_write_unavailable("legacy policy mutation")
            if segments[:2] == ["api", "runs"]:
                self._legacy_write_unavailable("legacy run mutation")
            run_id, artifact_id = self._route_identity(segments)
            if artifact_id is None:
                raise WorkspaceAPIError(404, "route_not_found", "route does not exist")
            spec = self.server.service.registry.resolve(artifact_id)
            length = self._content_length(maximum=spec.max_bytes)
            content = self.rfile.read(length)
            if len(content) != length:
                raise WorkspaceAPIError(400, "request_truncated", "artifact body was truncated")
            incarnation, release_sha = self._binding()
            response = self.server.service.put_artifact(
                run_id,
                artifact_id,
                incarnation_id=incarnation,
                release_sha256=release_sha,
                content_type=self.headers.get("Content-Type", ""),
                content=content,
                content_sha256=self.headers.get("X-Content-SHA256", ""),
                if_none_match=self.headers.get("If-None-Match", ""),
            )
            self._send_json(HTTPStatus.CREATED if response["created"] else HTTPStatus.OK, response)
        except WorkspaceAPIError as exc:
            if self._is_legacy_workbench_request():
                self._send_workbench_error(exc)
            else:
                self._send_error(exc)
        except PolicyStoreError as exc:
            if self._is_legacy_workbench_request():
                self._send_workbench_error(self._policy_api_error(exc))
            else:
                self._send_policy_error(exc)
        except Exception:
            error = WorkspaceAPIError(
                500,
                "internal_error",
                "Workspace Server encountered an internal error",
            )
            if self._is_legacy_workbench_request():
                self._send_workbench_error(error)
            else:
                self._send_error(error)

    def do_DELETE(self) -> None:  # noqa: N802
        legacy_workbench_request = self._is_legacy_workbench_request()
        try:
            segments = self._segments(allow_query=True)
            query = self._query()
            if segments[:2] == ["api", "runs"]:
                self._require_same_origin_workbench_request()
                if len(segments) != 3 or not RUN_ID_RE.fullmatch(segments[2]):
                    raise WorkspaceAPIError(404, "workspace_not_found", "workspace does not exist")
                if set(query) != {"delete_request_id"} or len(query["delete_request_id"]) != 1:
                    raise WorkspaceAPIError(
                        422,
                        "invalid_delete_request_id",
                        "exactly one delete_request_id query parameter is required",
                    )
                self._require_empty_body()
                response = self.server.service.delete_workspace_from_workbench(
                    segments[2],
                    delete_request_id=query["delete_request_id"][0],
                )
                self._send_json(HTTPStatus.OK, response)
                return
            if len(segments) == 4 and segments[:3] == [
                "api",
                "health-policy",
                "versions",
            ]:
                self._reject_query(query)
                self._require_empty_body()
                with self.server.service.admission_lock():
                    response = self.server.policy_store.delete_version(
                        segments[3],
                        in_use_versions=policy_in_use_versions(self.server.service),
                    )
                self._send_json(
                    HTTPStatus.OK,
                    policy_delete_projection(response),
                )
                return
            if segments[:2] == ["api", "health-policy"] or segments == [
                "api",
                "inspection-schedule",
            ]:
                self._legacy_write_unavailable("legacy policy deletion")
            self._reject_query(query)
            run_id, artifact_id = self._route_identity(segments)
            if artifact_id is not None or len(segments) != 3:
                raise WorkspaceAPIError(404, "route_not_found", "route does not exist")
            self._require_empty_body()
            incarnation, release_sha = self._binding()
            response = self.server.service.delete_workspace(
                run_id,
                incarnation_id=incarnation,
                release_sha256=release_sha,
            )
            self._send_json(HTTPStatus.OK, response)
        except WorkspaceAPIError as exc:
            if legacy_workbench_request:
                self._send_workbench_error(exc)
            else:
                self._send_error(exc)
        except PolicyStoreError as exc:
            if legacy_workbench_request:
                self._send_workbench_error(self._policy_api_error(exc))
            else:
                self._send_policy_error(exc)
        except Exception:
            error = WorkspaceAPIError(
                500,
                "internal_error",
                "Workspace Server encountered an internal error",
            )
            if legacy_workbench_request:
                self._send_workbench_error(error)
            else:
                self._send_error(error)

    def do_OPTIONS(self) -> None:  # noqa: N802
        self.send_response(HTTPStatus.NO_CONTENT)
        self._security_headers()
        self.send_header("Allow", "GET, HEAD, POST, PUT, DELETE, OPTIONS")
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Huabao stdlib Workspace Server")
    subparsers = parser.add_subparsers(dest="command", required=True)
    serve = subparsers.add_parser("serve", help="start the loopback HTTP server")
    serve.add_argument("--host")
    serve.add_argument("--port", type=int)
    subparsers.add_parser("config", help="validate and print public configuration")
    subparsers.add_parser("list", help="list workspaces")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        if arguments.command == "config":
            load_workspace_config(SERVER_ROOT)
            service = WorkspaceService(REPOSITORY_ROOT, server_root=SERVER_ROOT)
            print(json.dumps(service.get_config(), ensure_ascii=False, indent=2, sort_keys=True))
            return 0
        service = WorkspaceService(REPOSITORY_ROOT, server_root=SERVER_ROOT)
        if arguments.command == "list":
            print(json.dumps({"workspaces": service.list_workspaces()}, ensure_ascii=False, indent=2))
            return 0
        host = arguments.host or service.config.host
        port = arguments.port or service.config.port
        if host not in LOOPBACK_HOSTS:
            raise RuntimeEnvironmentError("HTTP server may bind only to loopback")
        delivery_reconciler = DeliveryReconciler(service)
        policy_store = service.policy_store
        httpd = WorkspaceHTTPServer(
            (host, port),
            service,
            delivery_reconciler,
            policy_store,
        )
        delivery_reconciler.start()
        print(f"Huabao Workspace Server listening on http://{host}:{port}", flush=True)
        try:
            httpd.serve_forever(poll_interval=0.5)
        except KeyboardInterrupt:
            pass
        finally:
            httpd.server_close()
            delivery_reconciler.close()
        return 0
    except (RuntimeEnvironmentError, WorkspaceAPIError, PolicyStoreError, OSError) as exc:
        print(
            json.dumps(
                {"ok": False, "error": type(exc).__name__, "message": str(exc)},
                ensure_ascii=False,
            ),
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
