"""Loopback-only stdlib HTTP server for the Huabao Workspace API."""

from __future__ import annotations

import argparse
import json
import re
import sys
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Mapping, Sequence
from urllib.parse import unquote, urlsplit


SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from shared.runtime_env import RuntimeEnvironmentError, load_workspace_config  # noqa: E402
from workspace_api import WorkspaceAPIError, WorkspaceService  # noqa: E402


RUN_ID_RE = re.compile(r"^hi-\d{4}-\d{2}-\d{2}$")
ARTIFACT_ID_RE = re.compile(r"^[a-z][a-z0-9_]{0,127}$")
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})


class WorkspaceHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], service: WorkspaceService) -> None:
        self.service = service
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

    def _segments(self) -> list[str]:
        parsed = urlsplit(self.path)
        if parsed.query or parsed.fragment:
            raise WorkspaceAPIError(400, "invalid_url", "query strings and fragments are not supported")
        try:
            segments = [unquote(item, errors="strict") for item in parsed.path.split("/") if item]
        except UnicodeDecodeError as exc:
            raise WorkspaceAPIError(400, "invalid_url", "URL path encoding is invalid") from exc
        if any("/" in item or "\\" in item or "\x00" in item or item in {".", ".."} for item in segments):
            raise WorkspaceAPIError(400, "invalid_url", "URL path segment is invalid")
        return segments

    def _content_length(self, *, maximum: int) -> int:
        if self.headers.get("Transfer-Encoding"):
            raise WorkspaceAPIError(400, "transfer_encoding_forbidden", "chunked requests are forbidden")
        raw = self.headers.get("Content-Length")
        if raw is None or not raw.isdigit():
            raise WorkspaceAPIError(411, "content_length_required", "Content-Length is required")
        length = int(raw)
        if length > maximum:
            raise WorkspaceAPIError(413, "request_too_large", "request body exceeds maximum")
        return length

    def _read_json(self, *, allow_empty: bool = False) -> Any:
        length = self._content_length(maximum=self.server.service.config.max_json_bytes)
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
            segments = self._segments()
            if not segments:
                html = PROJECT_ROOT / "huabao-new-energy-ai.html"
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
                self._send_bytes(HTTPStatus.NO_CONTENT, b"", content_type="image/x-icon")
                return
            if segments == ["api", "health"]:
                self._send_json(
                    HTTPStatus.OK,
                    {"ok": True, "service": "huabao-worktree-server", "workspace_version": "2.0"},
                )
                return
            if segments == ["api", "config"]:
                self._send_json(HTTPStatus.OK, self.server.service.get_config())
                return
            if segments == ["api", "workspaces"]:
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
            run_id, artifact_id = self._route_identity(segments)
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
            self._send_error(exc)
        except Exception:
            self._send_error(
                WorkspaceAPIError(500, "internal_error", "Workspace Server encountered an internal error")
            )

    def do_POST(self) -> None:  # noqa: N802
        try:
            segments = self._segments()
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
                self._send_json(HTTPStatus.OK, response)
                return
            raise WorkspaceAPIError(404, "route_not_found", "route does not exist")
        except WorkspaceAPIError as exc:
            self._send_error(exc)
        except Exception:
            self._send_error(
                WorkspaceAPIError(500, "internal_error", "Workspace Server encountered an internal error")
            )

    def do_PUT(self) -> None:  # noqa: N802
        try:
            segments = self._segments()
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
            self._send_error(exc)
        except Exception:
            self._send_error(
                WorkspaceAPIError(500, "internal_error", "Workspace Server encountered an internal error")
            )

    def do_DELETE(self) -> None:  # noqa: N802
        try:
            segments = self._segments()
            run_id, artifact_id = self._route_identity(segments)
            if artifact_id is not None or len(segments) != 3:
                raise WorkspaceAPIError(404, "route_not_found", "route does not exist")
            if self.headers.get("Content-Length") not in {None, "0"}:
                raise WorkspaceAPIError(400, "delete_body_forbidden", "DELETE body is forbidden")
            incarnation, release_sha = self._binding()
            response = self.server.service.delete_workspace(
                run_id,
                incarnation_id=incarnation,
                release_sha256=release_sha,
            )
            self._send_json(HTTPStatus.OK, response)
        except WorkspaceAPIError as exc:
            self._send_error(exc)
        except Exception:
            self._send_error(
                WorkspaceAPIError(500, "internal_error", "Workspace Server encountered an internal error")
            )

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
            config = load_workspace_config(PROJECT_ROOT)
            service = WorkspaceService(PROJECT_ROOT)
            print(json.dumps(service.get_config(), ensure_ascii=False, indent=2, sort_keys=True))
            return 0
        service = WorkspaceService(PROJECT_ROOT)
        if arguments.command == "list":
            print(json.dumps({"workspaces": service.list_workspaces()}, ensure_ascii=False, indent=2))
            return 0
        host = arguments.host or service.config.host
        port = arguments.port or service.config.port
        if host not in LOOPBACK_HOSTS:
            raise RuntimeEnvironmentError("HTTP server may bind only to loopback")
        httpd = WorkspaceHTTPServer((host, port), service)
        print(f"Huabao Workspace Server listening on http://{host}:{port}", flush=True)
        try:
            httpd.serve_forever(poll_interval=0.5)
        except KeyboardInterrupt:
            pass
        finally:
            httpd.server_close()
        return 0
    except (RuntimeEnvironmentError, WorkspaceAPIError, OSError) as exc:
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
