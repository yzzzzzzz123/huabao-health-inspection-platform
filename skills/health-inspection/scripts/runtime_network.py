"""Fail-closed runtime-network discovery and readiness checks.

The trusted Supervisor is the only component allowed to discover host proxy
settings.  Agent and Broker children merely inherit the sanitized, in-memory
environment; proxy addresses are never persisted into run artifacts.
"""

from __future__ import annotations

import os
import re
import shutil
import socket
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, MutableMapping
from urllib.error import HTTPError, URLError
from urllib.parse import SplitResult, urlsplit, urlunsplit
from urllib.request import ProxyHandler, Request, build_opener


RUNTIME_PROXY_ENV = "HUABAO_RUNTIME_PROXY"
RUNTIME_CONNECTIVITY_PROBE_URL = "https://chatgpt.com/"
RUNTIME_CONNECTIVITY_TIMEOUT_SECONDS = 5.0
RUNTIME_CONNECTIVITY_CACHE_SECONDS = 30.0
RUNTIME_CONNECTIVITY_STABILIZATION_DELAYS_SECONDS = (
    1.0,
    2.0,
    4.0,
    4.0,
    4.0,
    4.0,
    4.0,
    4.0,
    4.0,
)
RUNTIME_CONNECTIVITY_RETRYABLE_ERRORS = frozenset(
    {
        "codex_auth_check_failed",
        "codex_auth_check_timeout",
        "network_unreachable",
        "runtime_endpoint_unavailable",
    }
)
_PROXY_ENV_KEYS = (
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
    "ALL_PROXY",
    "all_proxy",
)
_MANAGED_PROXY_KEYS = (
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
)
_WINDOWS_PROXY_COMMAND = (
    "$settings = Get-ItemProperty -LiteralPath "
    "'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings'; "
    "if (($settings.ProxyEnable -eq 1) -and $settings.ProxyServer) { "
    "[Console]::Out.Write([string]$settings.ProxyServer) }"
)


class RuntimeConnectivityError(RuntimeError):
    """Raised before launch when the model runtime cannot be reached."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(
            f"模型运行环境当前不可用（{reason}）；本次未启动新的模型调用，"
            "请恢复网络或代理后重试"
        )


_STATE_LOCK = threading.RLock()
_STATE: dict[str, Any] = {
    "proxy_configured": False,
    "proxy_source": "none",
    "proxy_discovery_error": None,
    "connectivity_ready": None,
    "connectivity_error": "not_checked",
    "connectivity_checked_at": None,
    "connectivity_checked_monotonic": 0.0,
    "connectivity_gate_attempts": 0,
    "connectivity_recovered_after_retry": False,
}
_MANAGED_PROXY_URL: str | None = None


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _is_wsl() -> bool:
    if os.name == "nt":
        return False
    if os.environ.get("WSL_INTEROP") or os.environ.get("WSL_DISTRO_NAME"):
        return True
    try:
        release = Path("/proc/sys/kernel/osrelease").read_text(
            encoding="utf-8",
            errors="replace",
        )
    except OSError:
        return False
    return "microsoft" in release.lower()


def _select_windows_proxy(raw_value: str) -> str:
    """Select the HTTPS-capable entry from WinINet's ProxyServer value."""

    value = raw_value.strip()
    if not value:
        return ""
    if ";" not in value and "=" not in value:
        return value
    entries: dict[str, str] = {}
    for item in value.split(";"):
        key, separator, candidate = item.partition("=")
        if separator and candidate.strip():
            entries[key.strip().lower()] = candidate.strip()
    return entries.get("https") or entries.get("http") or ""


def _normalize_proxy_url(value: str) -> str:
    candidate = value.strip()
    if not candidate:
        return ""
    if "://" not in candidate:
        candidate = f"http://{candidate}"
    parsed = urlsplit(candidate)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("unsupported_proxy_scheme")
    if not parsed.hostname:
        raise ValueError("proxy_host_missing")
    try:
        parsed.port
    except ValueError as exc:
        raise ValueError("proxy_port_invalid") from exc
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ValueError("proxy_url_invalid")
    return urlunsplit(
        SplitResult(
            parsed.scheme.lower(),
            parsed.netloc,
            "",
            "",
            "",
        )
    )


def _wsl_default_gateway() -> str:
    ip_command = shutil.which("ip")
    if ip_command:
        try:
            completed = subprocess.run(
                [ip_command, "-4", "route", "show", "default"],
                capture_output=True,
                text=True,
                check=False,
                timeout=3,
            )
        except (OSError, subprocess.TimeoutExpired):
            completed = None
        if completed is not None and completed.returncode == 0:
            match = re.search(
                r"(?:^|\s)via\s+([0-9]+(?:\.[0-9]+){3})(?:\s|$)",
                completed.stdout,
            )
            if match:
                return match.group(1)
    try:
        resolv_conf = Path("/etc/resolv.conf").read_text(
            encoding="utf-8",
            errors="replace",
        )
    except OSError:
        return ""
    match = re.search(
        r"^nameserver\s+([0-9]+(?:\.[0-9]+){3})\s*$",
        resolv_conf,
        re.MULTILINE,
    )
    return match.group(1) if match else ""


def _bridge_wsl_loopback_proxy(proxy_url: str) -> str:
    parsed = urlsplit(proxy_url)
    if parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        return proxy_url
    gateway = _wsl_default_gateway()
    if not gateway:
        raise ValueError("wsl_gateway_unavailable")
    userinfo = parsed.netloc.rsplit("@", 1)[0] if "@" in parsed.netloc else ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    netloc = f"{gateway}:{port}"
    if userinfo:
        netloc = f"{userinfo}@{netloc}"
    return urlunsplit(
        SplitResult(parsed.scheme, netloc, "", "", "")
    )


def _windows_user_proxy() -> str:
    executable = shutil.which("powershell.exe") or shutil.which("pwsh.exe")
    if not executable:
        return ""
    try:
        completed = subprocess.run(
            [
                executable,
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                _WINDOWS_PROXY_COMMAND,
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=4,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    if completed.returncode != 0:
        return ""
    return _select_windows_proxy(completed.stdout)


def _merge_no_proxy(environ: MutableMapping[str, str]) -> None:
    required = ("127.0.0.1", "localhost", "::1")
    for key in ("NO_PROXY", "no_proxy"):
        existing = [
            item.strip()
            for item in environ.get(key, "").split(",")
            if item.strip()
        ]
        lowered = {item.lower() for item in existing}
        existing.extend(item for item in required if item.lower() not in lowered)
        environ[key] = ",".join(existing)


def configure_runtime_proxy(
    environ: MutableMapping[str, str] | None = None,
    *,
    rediscover: bool = False,
) -> dict[str, Any]:
    """Configure one authoritative proxy in memory, without exposing its URL."""

    global _MANAGED_PROXY_URL
    values = os.environ if environ is None else environ
    with _STATE_LOCK:
        if _STATE["proxy_source"] != "none" and not rediscover:
            return runtime_network_status()

        source = "none"
        discovery_error: str | None = None
        raw_proxy = values.get(RUNTIME_PROXY_ENV, "").strip()
        if _MANAGED_PROXY_URL and raw_proxy == _MANAGED_PROXY_URL:
            raw_proxy = ""
        if raw_proxy:
            source = "explicit"
        else:
            for key in _PROXY_ENV_KEYS:
                candidate = values.get(key, "").strip()
                if candidate and candidate != _MANAGED_PROXY_URL:
                    raw_proxy = candidate
                    source = "environment"
                    break
        if not raw_proxy and (os.name == "nt" or _is_wsl()):
            raw_proxy = _windows_user_proxy()
            if raw_proxy:
                source = "windows_user_proxy"

        proxy_url = ""
        if raw_proxy:
            try:
                proxy_url = _normalize_proxy_url(raw_proxy)
                if source == "windows_user_proxy" and _is_wsl():
                    proxy_url = _bridge_wsl_loopback_proxy(proxy_url)
            except ValueError as exc:
                discovery_error = str(exc)
                source = "invalid"

        if proxy_url:
            values[RUNTIME_PROXY_ENV] = proxy_url
            for key in _MANAGED_PROXY_KEYS:
                values[key] = proxy_url
            _merge_no_proxy(values)
            _MANAGED_PROXY_URL = proxy_url
        elif _MANAGED_PROXY_URL:
            for key in (RUNTIME_PROXY_ENV, *_MANAGED_PROXY_KEYS):
                if values.get(key) == _MANAGED_PROXY_URL:
                    values.pop(key, None)
            _MANAGED_PROXY_URL = None

        _STATE.update(
            {
                "proxy_configured": bool(proxy_url),
                "proxy_source": source,
                "proxy_discovery_error": discovery_error,
            }
        )
        return runtime_network_status()


def _codex_runtime_available(environ: Mapping[str, str]) -> str | None:
    executable = shutil.which("codex")
    if not executable:
        return "codex_cli_missing"
    try:
        completed = subprocess.run(
            [executable, "login", "status"],
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
            env=dict(environ),
        )
    except subprocess.TimeoutExpired:
        return "codex_auth_check_timeout"
    except OSError:
        return "codex_auth_check_failed"
    return None if completed.returncode == 0 else "codex_auth_unavailable"


def _probe_connectivity(proxy_url: str) -> tuple[bool, str | None]:
    proxy_map = {"http": proxy_url, "https": proxy_url} if proxy_url else {}
    opener = build_opener(ProxyHandler(proxy_map))
    request = Request(
        RUNTIME_CONNECTIVITY_PROBE_URL,
        headers={"User-Agent": "huabao-health-inspection-readiness/1.0"},
        method="HEAD",
    )
    try:
        with opener.open(
            request,
            timeout=RUNTIME_CONNECTIVITY_TIMEOUT_SECONDS,
        ) as response:
            status = int(getattr(response, "status", 200))
    except HTTPError as exc:
        status = int(exc.code)
    except (URLError, TimeoutError, socket.timeout, OSError):
        return False, "network_unreachable"
    if 200 <= status < 500 and status not in {407, 408, 425, 429}:
        return True, None
    if status == 407:
        return False, "proxy_authentication_required"
    if status == 429:
        return False, "runtime_rate_limited"
    return False, "runtime_endpoint_unavailable"


def refresh_runtime_connectivity(
    *,
    force: bool = False,
    environ: MutableMapping[str, str] | None = None,
) -> dict[str, Any]:
    """Refresh the bounded readiness projection used by the launch gate."""

    values = os.environ if environ is None else environ
    configure_runtime_proxy(values)
    with _STATE_LOCK:
        age = time.monotonic() - float(
            _STATE.get("connectivity_checked_monotonic", 0.0)
        )
        if (
            not force
            and _STATE.get("connectivity_ready") is not None
            and age < RUNTIME_CONNECTIVITY_CACHE_SECONDS
        ):
            return runtime_network_status()
        discovery_error = _STATE.get("proxy_discovery_error")
        proxy_source = str(_STATE.get("proxy_source") or "none")
        proxy_url = values.get(RUNTIME_PROXY_ENV, "").strip()

    if discovery_error:
        ready, error = False, str(discovery_error)
    else:
        runtime_error = _codex_runtime_available(values)
        if runtime_error:
            ready, error = False, runtime_error
        else:
            ready, error = _probe_connectivity(proxy_url)

    # A WSL host proxy or gateway may have changed while the service stayed up.
    # Rediscover it once after a failed probe, then perform one bounded retry.
    if not ready and proxy_source == "windows_user_proxy":
        configure_runtime_proxy(values, rediscover=True)
        with _STATE_LOCK:
            discovery_error = _STATE.get("proxy_discovery_error")
            proxy_url = values.get(RUNTIME_PROXY_ENV, "").strip()
        if not discovery_error:
            ready, error = _probe_connectivity(proxy_url)

    with _STATE_LOCK:
        _STATE.update(
            {
                "connectivity_ready": ready,
                "connectivity_error": error,
                "connectivity_checked_at": _utc_now(),
                "connectivity_checked_monotonic": time.monotonic(),
            }
        )
        return runtime_network_status()


def require_runtime_connectivity(*, force: bool = True) -> dict[str, Any]:
    """Require a stable launch path, absorbing only bounded transient outages.

    One readiness round already rediscovers and rechecks a Windows user proxy.
    A short host-proxy interruption can outlive that immediate retry, so the
    launch gate performs a bounded sequence of additional forced rounds with
    backoff for explicit transient errors. Authentication,
    proxy-authentication, rate limits, invalid configuration, and unknown
    failures remain fail-closed.
    """

    status = refresh_runtime_connectivity(force=force)
    attempts = 1
    initial_error = str(status.get("runtime_connectivity_error") or "unknown")
    for delay in RUNTIME_CONNECTIVITY_STABILIZATION_DELAYS_SECONDS:
        if status["runtime_connectivity_ready"] is True:
            break
        error = str(status.get("runtime_connectivity_error") or "unknown")
        if error not in RUNTIME_CONNECTIVITY_RETRYABLE_ERRORS:
            break
        time.sleep(delay)
        status = refresh_runtime_connectivity(force=True)
        attempts += 1

    recovered = (
        attempts > 1
        and status["runtime_connectivity_ready"] is True
        and initial_error in RUNTIME_CONNECTIVITY_RETRYABLE_ERRORS
    )
    with _STATE_LOCK:
        _STATE.update(
            {
                "connectivity_gate_attempts": attempts,
                "connectivity_recovered_after_retry": recovered,
            }
        )
        status = runtime_network_status()
    if status["runtime_connectivity_ready"] is not True:
        raise RuntimeConnectivityError(
            str(status.get("runtime_connectivity_error") or "unknown")
        )
    return status


def runtime_network_status() -> dict[str, Any]:
    """Return only safe diagnostics; proxy addresses and credentials stay hidden."""

    with _STATE_LOCK:
        return {
            "runtime_proxy_configured": bool(_STATE["proxy_configured"]),
            "runtime_proxy_source": str(_STATE["proxy_source"]),
            "runtime_connectivity_ready": _STATE["connectivity_ready"],
            "runtime_connectivity_error": _STATE["connectivity_error"],
            "runtime_connectivity_checked_at": _STATE[
                "connectivity_checked_at"
            ],
            "runtime_connectivity_gate_attempts": int(
                _STATE["connectivity_gate_attempts"]
            ),
            "runtime_connectivity_recovered_after_retry": bool(
                _STATE["connectivity_recovered_after_retry"]
            ),
        }
