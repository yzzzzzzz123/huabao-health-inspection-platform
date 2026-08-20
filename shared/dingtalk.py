"""Shared, credential-isolated DingTalk delivery for completed Huabao reports."""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import stat
import subprocess
import sys
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from http.client import HTTPException
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from shared.audit import (  # noqa: E402
    canonical_json,
    sha256_bytes,
    sha256_json,
    utc_now,
    write_json,
)
from shared.runtime_env import (  # noqa: E402
    RuntimeEnvironmentError,
    load_project_env,
    project_venv_child_env,
)


CREDENTIAL_ENV_PREFIX = "HUABAO_DINGTALK_"
ACCESS_TOKEN_ENV = f"{CREDENTIAL_ENV_PREFIX}ACCESS_TOKEN"
SIGNING_SECRET_ENV = f"{CREDENTIAL_ENV_PREFIX}SIGNING_SECRET"
AT_MOBILES_ENV = f"{CREDENTIAL_ENV_PREFIX}AT_MOBILES"
AT_ALL_ENV = f"{CREDENTIAL_ENV_PREFIX}AT_ALL"
DINGTALK_ENDPOINT = "https://oapi.dingtalk.com/robot/send"
REPORT_ARTIFACT_ID = "daily-report-markdown"
REPORT_RELATIVE_PATH = "result/05-reporter/daily-report.md"
REPORT_JSON_ARTIFACT_ID = "daily-report-json"
REPORT_JSON_RELATIVE_PATH = "result/05-reporter/daily-report.json"
MAX_MESSAGE_BYTES = 18_000
MAX_REPORT_CHUNK_BYTES = 16_500
MIN_PART_INTERVAL_SECONDS = 3.2
DEFAULT_TIMEOUT_SECONDS = 15.0
DINGTALK_ADAPTER_VERSION = "2.0"
RECEIPT_SCHEMA_VERSION = "2.0"
DIRECT_TERMINATION_ALERT_SCHEMA_VERSION = "1.0"
DIRECT_TERMINATION_CLASSIFICATIONS = frozenset(
    {"environment_configuration", "infrastructure_configuration"}
)
CHANNEL_LOCK_NAME = ".dingtalk-channel.lock"
CHANNEL_RATE_FILE = "channel-rate.json"
_EXPLICIT_CHILD_SECRET_ENV_NAMES = frozenset(
    {
        "ANTHROPIC_API_KEY",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SHARED_CREDENTIALS_FILE",
        "AZURE_OPENAI_API_KEY",
        "CODEX_ACCESS_TOKEN",
        "DATABASE_URL",
        "DOCKER_AUTH_CONFIG",
        "DOCKER_CONFIG",
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "GIT_ASKPASS",
        "GOOGLE_API_KEY",
        "KUBECONFIG",
        "NETRC",
        "NPM_CONFIG_USERCONFIG",
        "NPM_TOKEN",
        "OPENAI_API_KEY",
        "PGPASSWORD",
        "PIP_EXTRA_INDEX_URL",
        "PIP_INDEX_URL",
        "REDIS_URL",
        "SENTRY_AUTH_TOKEN",
        "SSH_ASKPASS",
        "SSH_AUTH_SOCK",
        "UV_INDEX_URL",
    }
)
_CHILD_SECRET_ENV_SUFFIXES = (
    "_API_KEY",
    "_TOKEN",
    "_SECRET",
    "_PASSWORD",
    "_PRIVATE_KEY",
    "_CREDENTIALS",
)
_HUABAO_SECRET_MARKERS = (
    "API_KEY",
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "PRIVATE_KEY",
    "CREDENTIALS",
)


class DingTalkDeliveryError(RuntimeError):
    """A safe, credential-free DingTalk delivery failure."""

    def __init__(self, message: str, *, uncertain: bool = False) -> None:
        super().__init__(message)
        self.uncertain = uncertain


def _lock_file(handle: Any, *, blocking: bool) -> None:
    """Acquire one-byte Windows locks or POSIX advisory locks uniformly."""

    handle.seek(0, os.SEEK_END)
    if handle.tell() == 0:
        handle.write(b"0")
        handle.flush()
    if os.name == "nt":
        import msvcrt

        while True:
            try:
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                return
            except OSError:
                if not blocking:
                    raise
                time.sleep(0.05)
    else:
        import fcntl

        flags = fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB)
        fcntl.flock(handle.fileno(), flags)


def _unlock_file(handle: Any) -> None:
    if os.name == "nt":
        import msvcrt

        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
    else:
        import fcntl

        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


@dataclass(frozen=True)
class DingTalkConfig:
    access_token: str
    signing_secret: str
    at_mobiles: tuple[str, ...]
    at_all: bool


@dataclass(frozen=True)
class ReportArtifact:
    worktree: Path
    run_id: str
    business_date: str
    completed_at: str
    path: Path
    sha256: str
    markdown: str
    delivery_request: dict[str, Any]


@dataclass(frozen=True)
class DeliveryPlan:
    destination_id: str
    sha256: str
    payload_sha256: tuple[str, ...]


def _truthy(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


def sanitized_child_env(
    environ: Mapping[str, str] | None = None,
    *,
    project_root: Path | str | None = None,
) -> dict[str, str]:
    """Remove host secrets before starting any Agent, Broker, or Worker child.

    The Codex CLI keeps non-secret runtime context such as ``PATH``, ``HOME``
    and proxy variables, but must authenticate from its own login store rather
    than inherited API keys or bearer tokens.  When ``project_root`` is given,
    the remaining environment is additionally bound to that linked worktree's
    private Python environment; no activated host or sibling virtualenv is
    inherited.
    """

    values = os.environ if environ is None else environ

    def sensitive(key: str) -> bool:
        normalized = key.upper()
        return bool(
            normalized.startswith(CREDENTIAL_ENV_PREFIX)
            or normalized in _EXPLICIT_CHILD_SECRET_ENV_NAMES
            or normalized.endswith(_CHILD_SECRET_ENV_SUFFIXES)
            or (
                normalized.startswith("HUABAO_")
                and any(marker in normalized for marker in _HUABAO_SECRET_MARKERS)
            )
        )

    sanitized = {
        key: value
        for key, value in values.items()
        if not sensitive(key)
    }
    if project_root is not None:
        for key in (
            "VIRTUAL_ENV",
            "PYTHONHOME",
            "PYTHONPATH",
            "PYTHONUSERBASE",
            "PYTHONSTARTUP",
        ):
            sanitized.pop(key, None)
        return project_venv_child_env(project_root, base_env=sanitized)
    return sanitized


def _parse_mobiles(value: str) -> tuple[str, ...]:
    mobiles = tuple(item.strip() for item in value.split(",") if item.strip())
    invalid = [item for item in mobiles if not re.fullmatch(r"\+?[0-9]{6,20}", item)]
    if invalid:
        raise DingTalkDeliveryError(
            f"{AT_MOBILES_ENV} 只能包含逗号分隔的手机号，发现 {len(invalid)} 个无效值"
        )
    return mobiles


def load_config(environ: Mapping[str, str] | None = None) -> DingTalkConfig:
    values = os.environ if environ is None else environ
    access_token = values.get(ACCESS_TOKEN_ENV, "").strip()
    if not access_token:
        raise DingTalkDeliveryError(f"未配置 {ACCESS_TOKEN_ENV}")
    if any(character.isspace() for character in access_token):
        raise DingTalkDeliveryError(f"{ACCESS_TOKEN_ENV} 格式无效")
    return DingTalkConfig(
        access_token=access_token,
        signing_secret=values.get(SIGNING_SECRET_ENV, "").strip(),
        at_mobiles=_parse_mobiles(values.get(AT_MOBILES_ENV, "")),
        at_all=_truthy(values.get(AT_ALL_ENV, "")),
    )


def config_status(environ: Mapping[str, str] | None = None) -> dict[str, Any]:
    values = os.environ if environ is None else environ
    configured = bool(values.get(ACCESS_TOKEN_ENV, "").strip())
    result: dict[str, Any] = {
        "channel": "dingtalk_custom_robot",
        "trigger": "reporter_requested_automatic_after_finalize",
        "configured": configured,
        "signed": bool(values.get(SIGNING_SECRET_ENV, "").strip()),
        "credential_storage": "environment_only",
    }
    if configured:
        try:
            config = load_config(values)
        except DingTalkDeliveryError as exc:
            result["valid"] = False
            result["configuration_error"] = str(exc)
        else:
            result["valid"] = True
            result["at_mobiles_count"] = len(config.at_mobiles)
            result["at_all"] = config.at_all
    else:
        result["valid"] = False
    return result


def _read_json_document(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    try:
        payload = path.read_bytes()
    except OSError as exc:
        raise DingTalkDeliveryError(f"无法读取{label}（{type(exc).__name__}）") from None
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise DingTalkDeliveryError(f"{label}不是有效 UTF-8 JSON") from None
    if not isinstance(value, dict):
        raise DingTalkDeliveryError(f"{label}顶层必须是 JSON object")
    return value, payload


def _require_clean_worktree(root: Path) -> None:
    try:
        completed = subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=all"],
            cwd=root,
            env=sanitized_child_env(),
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise DingTalkDeliveryError(
            f"无法复核完成态 Git 状态（{type(exc).__name__}）"
        ) from None
    if completed.returncode != 0:
        raise DingTalkDeliveryError("无法复核完成态 Git 状态")
    if completed.stdout.strip():
        raise DingTalkDeliveryError("完成态 worktree 已发生未封存改动，拒绝发送")


def _require_completed_report(worktree: Path) -> ReportArtifact:
    root = worktree.expanduser().resolve()
    if not root.is_dir():
        raise DingTalkDeliveryError("运行 worktree 不存在")

    state_path = root / "context" / "run.json"
    manifest_path = root / "result" / "00-orchestrator" / "delivery-manifest.json"
    report_json_path = root / REPORT_JSON_RELATIVE_PATH
    if (
        not state_path.is_file()
        or not manifest_path.is_file()
        or not report_json_path.is_file()
    ):
        raise DingTalkDeliveryError("运行尚未生成完成态和交付清单")

    state, _state_bytes = _read_json_document(state_path, "运行状态")
    manifest, _manifest_bytes = _read_json_document(manifest_path, "交付清单")
    if state.get("status") != "completed" or manifest.get("status") != "completed":
        raise DingTalkDeliveryError("只有已完成运行的最终报告可以发送到钉钉")
    if manifest.get("whitelist_check") != "passed":
        raise DingTalkDeliveryError("交付清单尚未通过运行文件白名单检查")
    if manifest.get("run_id") != state.get("run_id"):
        raise DingTalkDeliveryError("运行状态与交付清单的 run_id 不一致")
    if manifest.get("business_date") != state.get("business_date"):
        raise DingTalkDeliveryError("运行状态与交付清单的业务日期不一致")
    artifacts = manifest.get("artifacts", [])
    if not isinstance(artifacts, list):
        raise DingTalkDeliveryError("交付清单 artifacts 格式无效")

    def require_artifact(artifact_id: str, relative_path: str) -> dict[str, Any]:
        matches = [
            item
            for item in artifacts
            if isinstance(item, dict) and item.get("artifact_id") == artifact_id
        ]
        if len(matches) != 1:
            raise DingTalkDeliveryError(f"交付清单中的 {artifact_id} 必须唯一")
        artifact = matches[0]
        if artifact.get("path") != relative_path:
            raise DingTalkDeliveryError(f"{artifact_id} 路径不符合固定合同")
        return artifact

    artifact = require_artifact(REPORT_ARTIFACT_ID, REPORT_RELATIVE_PATH)
    report_json_artifact = require_artifact(
        REPORT_JSON_ARTIFACT_ID,
        REPORT_JSON_RELATIVE_PATH,
    )

    report_path = (root / REPORT_RELATIVE_PATH).resolve()
    if root not in report_path.parents or not report_path.is_file():
        raise DingTalkDeliveryError("每日管理报告文件不存在或路径越界")
    resolved_report_json_path = report_json_path.resolve()
    if root not in resolved_report_json_path.parents or not report_json_path.is_file():
        raise DingTalkDeliveryError("Stage 5 业务 JSON 不存在或路径越界")

    try:
        report_bytes = report_path.read_bytes()
        report_json_bytes = report_json_path.read_bytes()
    except OSError as exc:
        raise DingTalkDeliveryError(
            f"无法读取 Stage 5 正式报告（{type(exc).__name__}）"
        ) from None
    report_sha256 = sha256_bytes(report_bytes)
    report_json_sha256 = sha256_bytes(report_json_bytes)
    if (
        len(report_bytes) != artifact.get("bytes")
        or report_sha256 != artifact.get("sha256")
    ):
        raise DingTalkDeliveryError("每日管理报告哈希与交付清单不一致")
    if (
        len(report_json_bytes) != report_json_artifact.get("bytes")
        or report_json_sha256 != report_json_artifact.get("sha256")
    ):
        raise DingTalkDeliveryError("Stage 5 业务 JSON 哈希与交付清单不一致")

    final_validation = manifest.get("final_validation")
    if (
        not isinstance(final_validation, dict)
        or final_validation.get("final_validation_passed") is not True
        or final_validation.get("file_whitelist_passed") is not True
        or final_validation.get("worktree_clean") is not True
        or manifest.get("approved_projection_sha256")
        != sha256_json(final_validation)
    ):
        raise DingTalkDeliveryError("交付清单没有可复核的通过态终审投影")
    projected_artifacts = final_validation.get("artifact_hashes")
    if not isinstance(projected_artifacts, list):
        raise DingTalkDeliveryError("终审投影缺少 artifact 哈希")
    for expected in (artifact, report_json_artifact):
        projected = [
            item
            for item in projected_artifacts
            if isinstance(item, dict)
            and item.get("artifact_id") == expected.get("artifact_id")
        ]
        if len(projected) != 1 or any(
            projected[0].get(key) != expected.get(key)
            for key in ("path", "bytes", "sha256")
        ):
            raise DingTalkDeliveryError("正式报告与终审 artifact 投影不一致")

    try:
        report_json = json.loads(report_json_bytes.decode("utf-8"))
        markdown = report_bytes.decode("utf-8")
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise DingTalkDeliveryError("Stage 5 正式报告编码或 JSON 格式无效") from None
    if not isinstance(report_json, dict):
        raise DingTalkDeliveryError("Stage 5 业务 JSON 顶层必须是 object")
    delivery_request = report_json.get("delivery_request")
    if delivery_request != {
        "channel": "dingtalk_custom_robot",
        "mode": "automatic_after_finalize",
        "send": True,
    }:
        raise DingTalkDeliveryError("Stage 5 Reporter 未声明固定的钉钉自动投递请求")
    if not markdown.strip():
        raise DingTalkDeliveryError("每日管理报告为空")

    run_id = str(state.get("run_id", ""))
    if not re.fullmatch(r"hi-[0-9]{4}-[0-9]{2}-[0-9]{2}", run_id):
        raise DingTalkDeliveryError("运行 ID 不符合每日巡检合同")
    business_date = str(state.get("business_date", ""))
    if (
        report_json.get("run_id") != run_id
        or report_json.get("business_date") != business_date
        or report_json.get("stage") != "reporter"
        or report_json.get("status") != "completed"
    ):
        raise DingTalkDeliveryError("Stage 5 业务 JSON 与完成态运行身份不一致")
    completed_at = str(state.get("completed_at") or "").strip()
    if not completed_at:
        raise DingTalkDeliveryError("完成态缺少 completed_at，无法建立幂等投递身份")
    _require_clean_worktree(root)
    return ReportArtifact(
        worktree=root,
        run_id=run_id,
        business_date=business_date,
        completed_at=completed_at,
        path=report_path,
        sha256=report_sha256,
        markdown=markdown,
        delivery_request=delivery_request,
    )


def _split_utf8(value: str, limit: int) -> list[str]:
    if limit < 4:
        raise ValueError("UTF-8 chunk limit is too small")
    chunks: list[str] = []
    current: list[str] = []
    current_bytes = 0
    for character in value:
        size = len(character.encode("utf-8"))
        if current and current_bytes + size > limit:
            chunks.append("".join(current))
            current = []
            current_bytes = 0
        current.append(character)
        current_bytes += size
    if current:
        chunks.append("".join(current))
    return chunks


def split_markdown(markdown: str, limit: int = MAX_REPORT_CHUNK_BYTES) -> list[str]:
    if limit < 256:
        raise ValueError("Markdown chunk limit is too small")
    chunks: list[str] = []
    current: list[str] = []
    current_bytes = 0
    for line in markdown.splitlines(keepends=True):
        line_bytes = len(line.encode("utf-8"))
        if line_bytes > limit:
            if current:
                chunks.append("".join(current))
                current = []
                current_bytes = 0
            chunks.extend(_split_utf8(line, limit))
            continue
        if current and current_bytes + line_bytes > limit:
            chunks.append("".join(current))
            current = []
            current_bytes = 0
        current.append(line)
        current_bytes += line_bytes
    if current:
        chunks.append("".join(current))
    return chunks or [markdown]


def build_payloads(
    report: ReportArtifact,
    *,
    at_mobiles: tuple[str, ...] = (),
    at_all: bool = False,
) -> list[dict[str, Any]]:
    chunks = split_markdown(report.markdown)
    title = f"华宝健康巡检 {report.business_date}"
    payloads: list[dict[str, Any]] = []
    for index, chunk in enumerate(chunks, start=1):
        heading = (
            f"### {title}\n\n"
            f"> 完整报告第 {index}/{len(chunks)} 部分 · Stage 5 Reporter 自动投递\n\n"
        )
        text = heading + chunk
        if len(text.encode("utf-8")) > MAX_MESSAGE_BYTES:
            raise DingTalkDeliveryError("钉钉 Markdown 分片超过安全大小限制")
        payloads.append(
            {
                "msgtype": "markdown",
                "markdown": {"title": title, "text": text},
                "at": {"atMobiles": list(at_mobiles), "isAtAll": at_all},
            }
        )
    return payloads


def _delivery_plan(
    config: DingTalkConfig,
    payloads: list[dict[str, Any]],
) -> DeliveryPlan:
    destination_id = sha256_bytes(
        f"dingtalk-custom-robot\0{config.access_token}".encode("utf-8")
    )
    payload_sha256 = tuple(
        sha256_bytes(canonical_json(payload).encode("utf-8"))
        for payload in payloads
    )
    plan_sha256 = sha256_json(
        {
            "adapter_version": DINGTALK_ADAPTER_VERSION,
            "channel": "dingtalk_custom_robot",
            "destination_id": destination_id,
            "payload_sha256": list(payload_sha256),
            "part_count": len(payloads),
        }
    )
    return DeliveryPlan(
        destination_id=destination_id,
        sha256=plan_sha256,
        payload_sha256=payload_sha256,
    )


def _signed_url(config: DingTalkConfig, *, timestamp_ms: int | None = None) -> str:
    query: dict[str, str] = {"access_token": config.access_token}
    if config.signing_secret:
        timestamp = str(
            int(time.time() * 1000) if timestamp_ms is None else timestamp_ms
        )
        string_to_sign = f"{timestamp}\n{config.signing_secret}".encode("utf-8")
        digest = hmac.new(
            config.signing_secret.encode("utf-8"),
            string_to_sign,
            digestmod=hashlib.sha256,
        ).digest()
        query["timestamp"] = timestamp
        query["sign"] = base64.b64encode(digest).decode("ascii")
    return f"{DINGTALK_ENDPOINT}?{urlencode(query)}"


def _safe_api_message(value: Any) -> str:
    text = str(value or "未知错误")
    text = "".join(character for character in text if character.isprintable())
    return text[:240]


def _post_payload(
    config: DingTalkConfig,
    payload: dict[str, Any],
    *,
    opener: Callable[..., Any],
    timeout: float,
) -> None:
    request = Request(
        _signed_url(config),
        data=json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode(
            "utf-8"
        ),
        headers={
            "Content-Type": "application/json; charset=utf-8",
            "User-Agent": "huabao-health-inspection/1.0",
        },
        method="POST",
    )
    try:
        with opener(request, timeout=timeout) as response:
            raw = response.read(64 * 1024)
    except HTTPError as exc:
        try:
            raw = exc.read(64 * 1024)
        except Exception:
            raw = b""
        try:
            detail = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            detail = {}
        message = _safe_api_message(
            detail.get("errmsg") if isinstance(detail, dict) else None
        )
        raise DingTalkDeliveryError(
            f"钉钉机器人 HTTP {exc.code}：{message}"
        ) from None
    except (TimeoutError, URLError, OSError, HTTPException) as exc:
        raise DingTalkDeliveryError(
            f"钉钉机器人网络请求未确认完成（{type(exc).__name__}）",
            uncertain=True,
        ) from None
    except Exception as exc:
        raise DingTalkDeliveryError(
            f"钉钉机器人请求发生未知中断（{type(exc).__name__}）",
            uncertain=True,
        ) from None

    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise DingTalkDeliveryError(
            "钉钉机器人返回了无法确认的响应",
            uncertain=True,
        ) from None
    if not isinstance(value, dict) or str(value.get("errcode")) != "0":
        code = value.get("errcode") if isinstance(value, dict) else "unknown"
        message = _safe_api_message(
            value.get("errmsg") if isinstance(value, dict) else None
        )
        raise DingTalkDeliveryError(f"钉钉机器人拒绝发送（{code}）：{message}")


def _resolve_receipt_root(
    state_root: Path | None,
    *,
    worktree: Path,
) -> Path:
    try:
        worktree_root = worktree.expanduser().resolve(strict=True)
    except OSError as exc:
        raise DingTalkDeliveryError(
            f"运行 worktree 不可用（{type(exc).__name__}）"
        ) from None
    if not worktree_root.is_dir():
        raise DingTalkDeliveryError("运行 worktree 不存在")
    root = worktree_root / ".runtime" / "dingtalk"
    if state_root is not None:
        supplied_root = state_root.expanduser()
        if not supplied_root.is_absolute():
            supplied_root = Path.cwd() / supplied_root
        if os.path.abspath(supplied_root) != os.path.abspath(root):
            raise DingTalkDeliveryError(
                "钉钉 receipt 只能保存在当前日期 worktree 的 .runtime/dingtalk 中"
            )
    _prepare_receipt_root(root, worktree=worktree_root)
    return root


def _prepare_receipt_root(root: Path, *, worktree: Path) -> None:
    """Create the fixed receipt directory without following symlink components."""

    expected = worktree / ".runtime" / "dingtalk"
    if os.path.abspath(root) != os.path.abspath(expected):
        raise DingTalkDeliveryError(
            "钉钉 receipt 只能保存在当前日期 worktree 的 .runtime/dingtalk 中"
        )
    current = worktree
    for component in (".runtime", "dingtalk"):
        current = current / component
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            try:
                current.mkdir(mode=0o700)
                metadata = current.lstat()
            except OSError as exc:
                raise DingTalkDeliveryError(
                    f"无法创建钉钉 receipt 目录（{type(exc).__name__}）"
                ) from None
        except OSError as exc:
            raise DingTalkDeliveryError(
                f"无法检查钉钉 receipt 目录（{type(exc).__name__}）"
            ) from None
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise DingTalkDeliveryError("钉钉 receipt 目录不是可信普通目录")
        try:
            current.chmod(0o700, follow_symlinks=False)
        except (NotImplementedError, OSError) as exc:
            raise DingTalkDeliveryError(
                f"无法收紧钉钉 receipt 目录权限（{type(exc).__name__}）"
            ) from None


def _require_receipt_key(receipt_key: str) -> None:
    if re.fullmatch(r"[a-f0-9]{64}", receipt_key) is None:
        raise DingTalkDeliveryError("钉钉 receipt key 无效", uncertain=True)


def _lstat_regular_or_missing(path: Path, label: str) -> os.stat_result | None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise DingTalkDeliveryError(
            f"无法检查{label}（{type(exc).__name__}）",
            uncertain=True,
        ) from None
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise DingTalkDeliveryError(f"{label}不是可信普通文件", uncertain=True)
    return metadata


def _assert_receipt_root(root: Path) -> None:
    """Recheck fixed parent components immediately before receipt I/O."""

    if root.name != "dingtalk" or root.parent.name != ".runtime":
        raise DingTalkDeliveryError("钉钉 receipt 根目录身份无效", uncertain=True)
    for path in (root.parent, root):
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise DingTalkDeliveryError(
                f"无法检查钉钉 receipt 根目录（{type(exc).__name__}）",
                uncertain=True,
            ) from None
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise DingTalkDeliveryError("钉钉 receipt 根目录不是可信普通目录", uncertain=True)


def _receipt_key(report: ReportArtifact) -> str:
    identity = f"{report.run_id}\n{report.completed_at}\n{report.sha256}"
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


def _receipt_path(root: Path, receipt_key: str) -> Path:
    _require_receipt_key(receipt_key)
    return root / f"{receipt_key}.json"


def _load_receipt(root: Path, receipt_key: str) -> dict[str, Any]:
    _assert_receipt_root(root)
    path = _receipt_path(root, receipt_key)
    if _lstat_regular_or_missing(path, "钉钉投递 receipt") is None:
        return {}
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                raise DingTalkDeliveryError(
                    "钉钉投递 receipt 不是可信普通文件",
                    uncertain=True,
                )
            payload = handle.read()
        value = json.loads(payload.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise DingTalkDeliveryError("钉钉投递 receipt 已损坏", uncertain=True) from None
    if not isinstance(value, dict):
        raise DingTalkDeliveryError("钉钉投递 receipt 格式无效", uncertain=True)
    return value


def _validate_receipt(
    receipt: dict[str, Any],
    *,
    report: ReportArtifact,
    receipt_key: str,
) -> set[int]:
    if receipt.get("schema_version") != RECEIPT_SCHEMA_VERSION:
        raise DingTalkDeliveryError("钉钉投递 receipt 版本无法安全恢复", uncertain=True)
    expected_identity = {
        "channel": "dingtalk_custom_robot",
        "run_id": report.run_id,
        "business_date": report.business_date,
        "completed_at_source": report.completed_at,
        "report_sha256": report.sha256,
        "receipt_key": receipt_key,
    }
    if any(receipt.get(key) != value for key, value in expected_identity.items()):
        raise DingTalkDeliveryError("钉钉投递 receipt 身份与完成态报告不一致", uncertain=True)
    part_count = receipt.get("part_count")
    payload_hashes = receipt.get("payload_sha256")
    sent_values = receipt.get("sent_parts")
    if (
        not isinstance(part_count, int)
        or part_count < 1
        or not isinstance(payload_hashes, list)
        or len(payload_hashes) != part_count
        or any(re.fullmatch(r"[a-f0-9]{64}", str(item)) is None for item in payload_hashes)
        or re.fullmatch(r"[a-f0-9]{64}", str(receipt.get("destination_id", "")))
        is None
        or re.fullmatch(r"[a-f0-9]{64}", str(receipt.get("delivery_plan_sha256", "")))
        is None
        or not isinstance(sent_values, list)
    ):
        raise DingTalkDeliveryError("钉钉投递 receipt 的分片计划无效", uncertain=True)
    if (
        any(not isinstance(item, int) or not 1 <= item <= part_count for item in sent_values)
        or len(set(sent_values)) != len(sent_values)
    ):
        raise DingTalkDeliveryError("钉钉投递 receipt 的已发送分片无效", uncertain=True)
    uncertain_part = receipt.get("uncertain_part")
    if uncertain_part is not None and (
        not isinstance(uncertain_part, int) or not 1 <= uncertain_part <= part_count
    ):
        raise DingTalkDeliveryError("钉钉投递 receipt 的不确定分片无效", uncertain=True)
    in_flight = receipt.get("in_flight")
    if in_flight is not None:
        if (
            not isinstance(in_flight, dict)
            or set(in_flight) != {"part", "attempt_id", "started_at"}
            or not isinstance(in_flight.get("part"), int)
            or not 1 <= in_flight["part"] <= part_count
            or re.fullmatch(r"[a-f0-9]{32}", str(in_flight.get("attempt_id", "")))
            is None
            or not str(in_flight.get("started_at", "")).strip()
        ):
            raise DingTalkDeliveryError("钉钉投递 receipt 的 in-flight 状态无效", uncertain=True)
    sent_parts = set(sent_values)
    if receipt.get("completed_at") and len(sent_parts) != part_count:
        raise DingTalkDeliveryError("钉钉投递 receipt 的完成状态不一致", uncertain=True)
    return sent_parts


def _write_receipt(root: Path, receipt_key: str, value: dict[str, Any]) -> None:
    try:
        _assert_receipt_root(root)
        path = _receipt_path(root, receipt_key)
        _lstat_regular_or_missing(path, "钉钉投递 receipt")
        write_json(path, value)
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise DingTalkDeliveryError("钉钉投递 receipt 落盘类型无效", uncertain=True)
        path.chmod(0o600, follow_symlinks=False)
    except DingTalkDeliveryError:
        raise
    except OSError as exc:
        raise DingTalkDeliveryError(
            f"无法持久化钉钉投递状态（{type(exc).__name__}）"
        ) from None


def _archive_receipt(root: Path, receipt_key: str) -> None:
    _assert_receipt_root(root)
    path = _receipt_path(root, receipt_key)
    if _lstat_regular_or_missing(path, "钉钉投递 receipt") is None:
        return
    archive = root / (
        f"{receipt_key}.superseded-{int(time.time() * 1000)}.json"
    )
    try:
        if archive.lstat():
            raise DingTalkDeliveryError("钉钉投递归档目标已存在", uncertain=True)
    except FileNotFoundError:
        pass
    except DingTalkDeliveryError:
        raise
    except OSError as exc:
        raise DingTalkDeliveryError(
            f"无法检查钉钉投递归档（{type(exc).__name__}）"
        ) from None
    try:
        os.replace(path, archive)
        metadata = archive.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise DingTalkDeliveryError("钉钉投递归档类型无效", uncertain=True)
        archive.chmod(0o600, follow_symlinks=False)
    except DingTalkDeliveryError:
        raise
    except OSError as exc:
        raise DingTalkDeliveryError(
            f"无法归档旧钉钉投递计划（{type(exc).__name__}）"
        ) from None


@contextmanager
def _delivery_lock(root: Path, receipt_key: str) -> Iterator[None]:
    _assert_receipt_root(root)
    _require_receipt_key(receipt_key)
    lock_path = root / f".{receipt_key}.lock"
    _lstat_regular_or_missing(lock_path, "钉钉投递锁")
    flags = os.O_RDWR | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(lock_path, flags, 0o600)
    except OSError as exc:
        raise DingTalkDeliveryError(
            f"无法打开钉钉投递锁（{type(exc).__name__}）",
            uncertain=True,
        ) from None
    with os.fdopen(descriptor, "a+b") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise DingTalkDeliveryError("钉钉投递锁不是可信普通文件", uncertain=True)
        os.fchmod(handle.fileno(), 0o600)
        try:
            _lock_file(handle, blocking=False)
        except OSError:
            raise DingTalkDeliveryError("该报告正在由另一个进程发送") from None
        try:
            yield
        finally:
            _unlock_file(handle)


@contextmanager
def _channel_lock(root: Path) -> Iterator[None]:
    _assert_receipt_root(root)
    lock_path = root / CHANNEL_LOCK_NAME
    _lstat_regular_or_missing(lock_path, "钉钉通道锁")
    flags = os.O_RDWR | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(lock_path, flags, 0o600)
    except OSError as exc:
        raise DingTalkDeliveryError(
            f"无法打开钉钉通道锁（{type(exc).__name__}）",
            uncertain=True,
        ) from None
    with os.fdopen(descriptor, "a+b") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise DingTalkDeliveryError("钉钉通道锁不是可信普通文件", uncertain=True)
        os.fchmod(handle.fileno(), 0o600)
        _lock_file(handle, blocking=True)
        try:
            yield
        finally:
            _unlock_file(handle)


def _delivery_lock_is_held(root: Path, receipt_key: str) -> bool:
    try:
        _assert_receipt_root(root)
    except DingTalkDeliveryError:
        return True
    lock_path = root / f".{receipt_key}.lock"
    try:
        metadata = _lstat_regular_or_missing(lock_path, "钉钉投递锁")
    except DingTalkDeliveryError:
        return True
    if metadata is None:
        return False
    try:
        flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(lock_path, flags)
        with os.fdopen(descriptor, "r+b") as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                return True
            try:
                _lock_file(handle, blocking=False)
            except OSError:
                return True
            _unlock_file(handle)
    except OSError:
        return False
    return False


def _wait_for_channel_slot(
    root: Path,
    *,
    sleeper: Callable[[float], None],
    clock: Callable[[], float],
) -> None:
    _assert_receipt_root(root)
    path = root / CHANNEL_RATE_FILE
    now = clock()
    last_attempt = 0.0
    metadata = _lstat_regular_or_missing(path, "钉钉通道限流状态")
    if metadata is not None:
        try:
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(path, flags)
            with os.fdopen(descriptor, "rb") as handle:
                if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                    raise DingTalkDeliveryError(
                        "钉钉通道限流状态不是可信普通文件",
                        uncertain=True,
                    )
                value = json.loads(handle.read().decode("utf-8"))
            last_attempt = float(value["last_attempt_epoch_seconds"])
        except (
            OSError,
            UnicodeDecodeError,
            ValueError,
            TypeError,
            KeyError,
            json.JSONDecodeError,
        ):
            last_attempt = now
    remaining = MIN_PART_INTERVAL_SECONDS - max(0.0, now - last_attempt)
    if remaining > 0:
        sleeper(remaining)
    try:
        _lstat_regular_or_missing(path, "钉钉通道限流状态")
        write_json(
            path,
            {
                "schema_version": "1.0",
                "channel": "dingtalk_custom_robot",
                "last_attempt_epoch_seconds": clock(),
                "updated_at": utc_now(),
            },
        )
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise DingTalkDeliveryError(
                "钉钉通道限流状态落盘类型无效",
                uncertain=True,
            )
        path.chmod(0o600, follow_symlinks=False)
    except DingTalkDeliveryError:
        raise
    except OSError as exc:
        raise DingTalkDeliveryError(
            f"无法持久化钉钉机器人限流状态（{type(exc).__name__}）"
        ) from None


def _new_receipt(
    report: ReportArtifact,
    *,
    receipt_key: str,
    plan: DeliveryPlan,
) -> dict[str, Any]:
    now = utc_now()
    return {
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "adapter_version": DINGTALK_ADAPTER_VERSION,
        "channel": "dingtalk_custom_robot",
        "run_id": report.run_id,
        "business_date": report.business_date,
        "completed_at_source": report.completed_at,
        "report_sha256": report.sha256,
        "receipt_key": receipt_key,
        "requested_by": "reporter_agent",
        "delivery_mode": "automatic_after_finalize",
        "destination_id": plan.destination_id,
        "delivery_plan_sha256": plan.sha256,
        "payload_sha256": list(plan.payload_sha256),
        "part_count": len(plan.payload_sha256),
        "sent_parts": [],
        "in_flight": None,
        "uncertain_part": None,
        "last_error_type": None,
        "last_error": None,
        "created_at": now,
        "updated_at": now,
        "completed_at": None,
    }


def _plan_matches(receipt: dict[str, Any], plan: DeliveryPlan) -> bool:
    return (
        receipt.get("adapter_version") == DINGTALK_ADAPTER_VERSION
        and receipt.get("destination_id") == plan.destination_id
        and receipt.get("delivery_plan_sha256") == plan.sha256
        and receipt.get("payload_sha256") == list(plan.payload_sha256)
        and receipt.get("part_count") == len(plan.payload_sha256)
    )


def delivery_status(
    worktree: Path,
    *,
    state_root: Path | None = None,
) -> dict[str, Any]:
    status = config_status()
    result: dict[str, Any] = {
        **status,
        "available": False,
        "status": "unavailable",
        "sent_part_count": 0,
    }
    try:
        report = _require_completed_report(worktree)
    except DingTalkDeliveryError as exc:
        result["unavailable_reason"] = str(exc)
        return result

    receipt_key = _receipt_key(report)
    try:
        receipt_root = _resolve_receipt_root(
            state_root,
            worktree=report.worktree,
        )
        receipt = _load_receipt(receipt_root, receipt_key)
    except DingTalkDeliveryError as exc:
        result.update(
            {
                "available": True,
                "status": "uncertain" if exc.uncertain else "failed",
                "report_sha256": report.sha256,
                "receipt_key": receipt_key,
                "error": str(exc),
            }
        )
        return result

    if not receipt:
        result.update(
            {
                "available": True,
                "status": "not_sent",
                "report_sha256": report.sha256,
                "receipt_key": receipt_key,
                "part_count": len(build_payloads(report)),
            }
        )
        return result
    try:
        sent_parts = _validate_receipt(
            receipt,
            report=report,
            receipt_key=receipt_key,
        )
    except DingTalkDeliveryError as exc:
        result.update(
            {
                "available": True,
                "status": "uncertain",
                "report_sha256": report.sha256,
                "receipt_key": receipt_key,
                "error": str(exc),
            }
        )
        return result

    payload_count = int(receipt["part_count"])
    sent_count = len(sent_parts)
    plan_changed = False
    if status.get("configured") and status.get("valid"):
        try:
            config = load_config()
            current_payloads = build_payloads(
                report,
                at_mobiles=config.at_mobiles,
                at_all=config.at_all,
            )
            plan_changed = not _plan_matches(
                receipt,
                _delivery_plan(config, current_payloads),
            )
        except DingTalkDeliveryError:
            plan_changed = True

    in_flight = receipt.get("in_flight")
    uncertain_part = receipt.get("uncertain_part")
    last_error = receipt.get("last_error")
    delivery_state = "not_sent"
    if plan_changed and sent_count != payload_count:
        delivery_state = "blocked"
        last_error = "钉钉目标或分片计划已变化，必须显式创建新投递"
    elif in_flight:
        delivery_state = (
            "sending"
            if _delivery_lock_is_held(receipt_root, receipt_key)
            else "uncertain"
        )
        if delivery_state == "uncertain":
            last_error = "上次进程在网络结果落盘前结束，请先到钉钉群核对"
    elif uncertain_part:
        delivery_state = "uncertain"
    elif sent_count == payload_count:
        delivery_state = "sent"
    elif last_error:
        delivery_state = "failed"
    elif sent_count:
        delivery_state = "partial"
    result.update(
        {
            "available": True,
            "status": delivery_state,
            "report_sha256": report.sha256,
            "receipt_key": receipt_key,
            "part_count": payload_count,
            "sent_part_count": sent_count,
            "sent_at": receipt.get("completed_at"),
            "updated_at": receipt.get("updated_at"),
            "error": last_error,
            "plan_changed": plan_changed,
        }
    )
    return result


def send_completed_report(
    worktree: Path,
    *,
    dry_run: bool = False,
    force: bool = False,
    new_delivery: bool = False,
    state_root: Path | None = None,
    opener: Callable[..., Any] = urlopen,
    sleeper: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.time,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    report = _require_completed_report(worktree)
    if dry_run:
        payloads = build_payloads(report)
        return {
            "status": "dry_run",
            "run_id": report.run_id,
            "business_date": report.business_date,
            "report_sha256": report.sha256,
            "report_bytes": len(report.markdown.encode("utf-8")),
            "part_count": len(payloads),
            "max_message_bytes": max(
                len(item["markdown"]["text"].encode("utf-8")) for item in payloads
            ),
            "network_requests": 0,
        }

    config = load_config()
    payloads = build_payloads(
        report,
        at_mobiles=config.at_mobiles,
        at_all=config.at_all,
    )
    plan = _delivery_plan(config, payloads)
    receipt_root = _resolve_receipt_root(state_root, worktree=report.worktree)
    receipt_key = _receipt_key(report)
    with _channel_lock(receipt_root):
        with _delivery_lock(receipt_root, receipt_key):
            try:
                receipt = _load_receipt(receipt_root, receipt_key)
            except DingTalkDeliveryError:
                if not new_delivery or not _receipt_path(
                    receipt_root, receipt_key
                ).is_file():
                    raise
                _archive_receipt(receipt_root, receipt_key)
                receipt = {}

            sent_parts: set[int] = set()
            if receipt:
                sent_parts = _validate_receipt(
                    receipt,
                    report=report,
                    receipt_key=receipt_key,
                )
                if not _plan_matches(receipt, plan):
                    if not new_delivery:
                        raise DingTalkDeliveryError(
                            "钉钉目标或分片计划已变化；请显式使用 --new-delivery"
                        )
                    _archive_receipt(receipt_root, receipt_key)
                    receipt = {}
                    sent_parts = set()
                elif new_delivery:
                    _archive_receipt(receipt_root, receipt_key)
                    receipt = {}
                    sent_parts = set()
            if not receipt:
                receipt = _new_receipt(
                    report,
                    receipt_key=receipt_key,
                    plan=plan,
                )

            in_flight = receipt.get("in_flight")
            if in_flight:
                if not force:
                    receipt["in_flight"] = None
                    receipt["uncertain_part"] = int(in_flight["part"])
                    receipt["last_error_type"] = "InterruptedDelivery"
                    receipt["last_error"] = (
                        "上次进程在网络结果落盘前结束，请先到钉钉群核对"
                    )
                    receipt["updated_at"] = utc_now()
                    _write_receipt(receipt_root, receipt_key, receipt)
                    raise DingTalkDeliveryError(
                        "上次发送结果不确定；请先在钉钉核对，再用 --force 恢复",
                        uncertain=True,
                    )
                receipt["in_flight"] = None
                receipt["uncertain_part"] = int(in_flight["part"])

            uncertain_part = receipt.get("uncertain_part")
            if uncertain_part and not force:
                raise DingTalkDeliveryError(
                    "上次发送结果不确定；请先在钉钉核对，再用 --force 恢复",
                    uncertain=True,
                )
            if force:
                receipt["uncertain_part"] = None
                receipt["last_error_type"] = None
                receipt["last_error"] = None
                receipt["updated_at"] = utc_now()
                _write_receipt(receipt_root, receipt_key, receipt)

            if len(sent_parts) == len(payloads):
                return {
                    "status": "already_sent",
                    "run_id": report.run_id,
                    "business_date": report.business_date,
                    "report_sha256": report.sha256,
                    "delivery_plan_sha256": plan.sha256,
                    "part_count": len(payloads),
                    "sent_part_count": len(sent_parts),
                    "completed_at": receipt.get("completed_at"),
                }

            pending = [
                (index, payload)
                for index, payload in enumerate(payloads, start=1)
                if index not in sent_parts
            ]
            for index, payload in pending:
                _wait_for_channel_slot(
                    receipt_root,
                    sleeper=sleeper,
                    clock=clock,
                )
                receipt["in_flight"] = {
                    "part": index,
                    "attempt_id": uuid.uuid4().hex,
                    "started_at": utc_now(),
                }
                receipt["updated_at"] = utc_now()
                _write_receipt(receipt_root, receipt_key, receipt)
                try:
                    _post_payload(config, payload, opener=opener, timeout=timeout)
                except DingTalkDeliveryError as exc:
                    receipt["in_flight"] = None
                    receipt["uncertain_part"] = index if exc.uncertain else None
                    receipt["last_error_type"] = type(exc).__name__
                    receipt["last_error"] = str(exc)
                    receipt["updated_at"] = utc_now()
                    try:
                        _write_receipt(receipt_root, receipt_key, receipt)
                    except DingTalkDeliveryError:
                        raise DingTalkDeliveryError(
                            "网络请求后无法持久化状态，发送结果不确定",
                            uncertain=True,
                        ) from None
                    raise

                sent_parts.add(index)
                receipt["sent_parts"] = sorted(sent_parts)
                receipt["in_flight"] = None
                receipt["uncertain_part"] = None
                receipt["last_error_type"] = None
                receipt["last_error"] = None
                receipt["updated_at"] = utc_now()
                if len(sent_parts) == len(payloads):
                    receipt["completed_at"] = receipt["updated_at"]
                try:
                    _write_receipt(receipt_root, receipt_key, receipt)
                except DingTalkDeliveryError:
                    raise DingTalkDeliveryError(
                        "钉钉已响应成功但 receipt 未落盘，发送结果不确定",
                        uncertain=True,
                    ) from None

            return {
                "status": "sent",
                "run_id": report.run_id,
                "business_date": report.business_date,
                "report_sha256": report.sha256,
                "delivery_plan_sha256": plan.sha256,
                "part_count": len(payloads),
                "sent_part_count": len(sent_parts),
                "completed_at": receipt.get("completed_at"),
            }


def deliver_report_automatically(
    worktree: Path,
    *,
    state_root: Path | None = None,
    opener: Callable[..., Any] = urlopen,
    sleeper: Callable[[float], None] = time.sleep,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Reconcile one safe delivery without ever failing the completed inspection."""

    try:
        current = delivery_status(worktree, state_root=state_root)
        if not (
            current.get("available")
            and current.get("configured")
            and current.get("valid")
            and current.get("status") in {"not_sent", "partial"}
        ):
            return {
                **current,
                "automatic_action": "skipped",
            }
        return send_completed_report(
            worktree,
            state_root=state_root,
            opener=opener,
            sleeper=sleeper,
            timeout=timeout,
        )
    except Exception as exc:
        try:
            current = delivery_status(worktree, state_root=state_root)
        except Exception:
            current = {
                "status": (
                    "uncertain"
                    if isinstance(exc, DingTalkDeliveryError) and exc.uncertain
                    else "failed"
                )
            }
        safe_error = (
            str(exc)
            if isinstance(exc, DingTalkDeliveryError)
            else f"钉钉自动投递内部错误（{type(exc).__name__}）"
        )
        return {
            **current,
            "automatic_action": "failed_safely",
            "requested_by": "reporter_agent",
            "delivery_mode": "automatic_after_finalize",
            "error": current.get("error") or safe_error,
        }


def _direct_termination_alert_identity(worktree: Path) -> tuple[Path, dict[str, str]]:
    """Read only the bounded, non-secret identity of one terminal failure."""

    try:
        root = worktree.expanduser().resolve(strict=True)
    except OSError as exc:
        raise DingTalkDeliveryError(
            f"无法读取直接终止运行（{type(exc).__name__}）"
        ) from None
    git_pointer = root / ".git"
    if (
        not root.is_dir()
        or not git_pointer.is_file()
        or git_pointer.is_symlink()
    ):
        raise DingTalkDeliveryError("直接终止预警只接受日期 linked worktree")
    state_path = root / "context" / "run.json"
    if not state_path.is_file() or state_path.is_symlink():
        raise DingTalkDeliveryError("直接终止运行缺少可信状态")
    state, _ = _read_json_document(state_path, "直接终止运行状态")
    error = state.get("error")
    if not isinstance(error, dict):
        raise DingTalkDeliveryError("运行状态不属于直接终止配置故障")
    classification = str(error.get("classification") or "")
    if (
        state.get("status") != "failed"
        or classification not in DIRECT_TERMINATION_CLASSIFICATIONS
        or error.get("terminal_policy") != "direct_termination"
    ):
        raise DingTalkDeliveryError("运行状态不属于直接终止配置故障")
    run_id = str(state.get("run_id") or "")
    business_date = str(state.get("business_date") or "")
    if not re.fullmatch(r"hi-[0-9]{4}-[0-9]{2}-[0-9]{2}", run_id):
        raise DingTalkDeliveryError("直接终止运行 ID 无效")
    if run_id != f"hi-{business_date}":
        raise DingTalkDeliveryError("直接终止运行身份不一致")
    failed_stage = str(state.get("failed_stage") or "bootstrap")
    if re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", failed_stage) is None:
        raise DingTalkDeliveryError("直接终止 Stage 身份无效")
    incarnation_id = str(state.get("incarnation_id") or "")
    identity = {
        "run_id": run_id,
        "business_date": business_date,
        "failed_stage": failed_stage,
        "classification": classification,
        "terminal_policy": "direct_termination",
        "incarnation_id_sha256": hashlib.sha256(
            incarnation_id.encode("utf-8")
        ).hexdigest(),
    }
    return root, identity


def _direct_termination_alert_payload(
    identity: Mapping[str, str],
    *,
    at_mobiles: tuple[str, ...] = (),
    at_all: bool = False,
) -> dict[str, Any]:
    classification_label = {
        "environment_configuration": "环境配置",
        "infrastructure_configuration": "基础设施配置",
    }[identity["classification"]]
    text = "\n".join(
        (
            "# ⚠️ 华宝健康巡检已直接终止",
            "",
            f"- 运行：{identity['run_id']}",
            f"- 业务日期：{identity['business_date']}",
            f"- 终止阶段：{identity['failed_stage']}",
            f"- 故障分类：{classification_label}",
            "- 处置：控制面已挂断，不提供 Stage 断点恢复",
            "",
            "> 预警不包含异常原文、文件路径、环境变量值或任何凭据。",
        )
    )
    return {
        "msgtype": "markdown",
        "markdown": {
            "title": f"华宝巡检终止 · {identity['business_date']}",
            "text": text,
        },
        "at": {
            "atMobiles": list(at_mobiles),
            "isAtAll": bool(at_all),
        },
    }


def _direct_termination_receipt_key(identity: Mapping[str, str]) -> str:
    return sha256_json(
        {
            "kind": "direct_termination_alert",
            **dict(identity),
        }
    )


def _validate_direct_termination_receipt(
    receipt: dict[str, Any],
    *,
    identity: Mapping[str, str],
    receipt_key: str,
) -> None:
    expected = {
        "schema_version": DIRECT_TERMINATION_ALERT_SCHEMA_VERSION,
        "adapter_version": DINGTALK_ADAPTER_VERSION,
        "channel": "dingtalk_custom_robot",
        "alert_kind": "direct_termination",
        "run_id": identity["run_id"],
        "business_date": identity["business_date"],
        "failed_stage": identity["failed_stage"],
        "classification": identity["classification"],
        "incarnation_id_sha256": identity["incarnation_id_sha256"],
        "receipt_key": receipt_key,
    }
    if any(receipt.get(key) != value for key, value in expected.items()):
        raise DingTalkDeliveryError("直接终止预警 receipt 身份不一致", uncertain=True)
    for key in ("destination_id", "delivery_plan_sha256", "payload_sha256"):
        if re.fullmatch(r"[a-f0-9]{64}", str(receipt.get(key, ""))) is None:
            raise DingTalkDeliveryError("直接终止预警 receipt 计划无效", uncertain=True)
    if receipt.get("status") not in {"sending", "sent", "failed", "uncertain"}:
        raise DingTalkDeliveryError("直接终止预警 receipt 状态无效", uncertain=True)
    in_flight = receipt.get("in_flight")
    if in_flight is not None and (
        not isinstance(in_flight, dict)
        or set(in_flight) != {"attempt_id", "started_at"}
        or re.fullmatch(r"[a-f0-9]{32}", str(in_flight.get("attempt_id", "")))
        is None
        or not str(in_flight.get("started_at", "")).strip()
    ):
        raise DingTalkDeliveryError("直接终止预警 receipt 发送状态无效", uncertain=True)
    if receipt.get("status") == "sent" and (
        in_flight is not None or not str(receipt.get("sent_at") or "").strip()
    ):
        raise DingTalkDeliveryError("直接终止预警 receipt 完成状态无效", uncertain=True)


def _direct_termination_alert_base() -> dict[str, Any]:
    return {
        **config_status(),
        "trigger": "trusted_supervisor_after_direct_termination",
        "requested_by": "trusted_supervisor",
        "delivery_mode": "automatic_on_direct_termination",
        "sent": False,
    }


def direct_termination_alert_status(
    worktree: Path,
    *,
    state_root: Path | None = None,
) -> dict[str, Any]:
    """Return a credential-free direct-termination alert projection."""

    result = _direct_termination_alert_base()
    try:
        root, identity = _direct_termination_alert_identity(worktree)
    except DingTalkDeliveryError as exc:
        return {
            **result,
            "available": False,
            "status": "not_applicable",
            "unavailable_reason": str(exc),
        }
    result.update(
        {
            "available": True,
            "run_id": identity["run_id"],
            "business_date": identity["business_date"],
            "failed_stage": identity["failed_stage"],
            "classification": identity["classification"],
        }
    )
    receipt_key = _direct_termination_receipt_key(identity)
    try:
        receipt_root = _resolve_receipt_root(state_root, worktree=root)
        receipt = _load_receipt(receipt_root, receipt_key)
    except DingTalkDeliveryError as exc:
        return {
            **result,
            "status": "uncertain" if exc.uncertain else "failed",
            "receipt_key": receipt_key,
            "error": str(exc),
        }
    if receipt:
        try:
            _validate_direct_termination_receipt(
                receipt,
                identity=identity,
                receipt_key=receipt_key,
            )
        except DingTalkDeliveryError as exc:
            return {
                **result,
                "status": "uncertain",
                "receipt_key": receipt_key,
                "error": str(exc),
            }
        if receipt.get("status") == "sent":
            return {
                **result,
                "status": "sent",
                "sent": True,
                "receipt_key": receipt_key,
                "updated_at": receipt.get("updated_at"),
                "sent_at": receipt.get("sent_at"),
            }
    if not result.get("configured"):
        return {
            **result,
            "status": "not_configured",
            "automatic_action": "skipped",
            "receipt_key": receipt_key,
            "prior_receipt_status": receipt.get("status") if receipt else None,
        }
    if not result.get("valid"):
        return {
            **result,
            "status": "configuration_error",
            "automatic_action": "skipped",
            "receipt_key": receipt_key,
            "prior_receipt_status": receipt.get("status") if receipt else None,
        }
    if not receipt:
        return {
            **result,
            "status": "not_sent",
            "receipt_key": receipt_key,
            "manual_recovery_available": False,
        }
    try:
        config = load_config()
        payload = _direct_termination_alert_payload(
            identity,
            at_mobiles=config.at_mobiles,
            at_all=config.at_all,
        )
        plan = _delivery_plan(config, [payload])
    except DingTalkDeliveryError as exc:
        return {
            **result,
            "status": "uncertain" if exc.uncertain else "configuration_error",
            "receipt_key": receipt_key,
            "error": str(exc),
        }
    if (
        receipt.get("destination_id") != plan.destination_id
        or receipt.get("delivery_plan_sha256") != plan.sha256
        or receipt.get("payload_sha256") != plan.payload_sha256[0]
    ):
        return {
            **result,
            "status": "blocked",
            "receipt_key": receipt_key,
            "error": "钉钉目标或预警计划已变化，拒绝自动重发",
            "recorded_delivery_plan_sha256": receipt.get(
                "delivery_plan_sha256"
            ),
            "current_delivery_plan_sha256": plan.sha256,
            "manual_recovery_available": True,
        }
    status = str(receipt["status"])
    if status == "sending" and not _delivery_lock_is_held(receipt_root, receipt_key):
        status = "uncertain"
    return {
        **result,
        "status": status,
        "sent": status == "sent",
        "receipt_key": receipt_key,
        "updated_at": receipt.get("updated_at"),
        "sent_at": receipt.get("sent_at"),
        "error": receipt.get("last_error"),
        "current_delivery_plan_sha256": plan.sha256,
        "manual_recovery_available": status in {
            "sending",
            "uncertain",
            "failed",
        },
    }


def send_direct_termination_alert(
    worktree: Path,
    *,
    state_root: Path | None = None,
    opener: Callable[..., Any] = urlopen,
    sleeper: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.time,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    force: bool = False,
    expected_receipt_key: str | None = None,
    expected_delivery_plan_sha256: str | None = None,
) -> dict[str, Any]:
    """Send one sanitized, idempotent alert from a trusted Supervisor only.

    Automatic calls never retry an ambiguous or failed receipt.  A human may
    recover only by explicitly binding ``--force`` to both the displayed
    receipt key and the currently projected delivery-plan hash after checking
    the DingTalk group.
    """

    if not force and (
        expected_receipt_key is not None
        or expected_delivery_plan_sha256 is not None
    ):
        raise DingTalkDeliveryError("直接终止预警恢复绑定只能与 force 同时使用")
    if force:
        if re.fullmatch(r"[a-f0-9]{64}", str(expected_receipt_key or "")) is None:
            raise DingTalkDeliveryError("人工恢复缺少有效 receipt key")
        if re.fullmatch(
            r"[a-f0-9]{64}",
            str(expected_delivery_plan_sha256 or ""),
        ) is None:
            raise DingTalkDeliveryError("人工恢复缺少有效 delivery-plan SHA-256")

    current = direct_termination_alert_status(worktree, state_root=state_root)
    if current.get("status") in {"not_configured", "configuration_error"}:
        if force:
            raise DingTalkDeliveryError("人工恢复前必须先完成有效钉钉通道配置")
        return current
    if not current.get("available"):
        if force:
            raise DingTalkDeliveryError("当前运行不具备直接终止预警恢复条件")
        return current
    if current.get("status") == "sent" and not force:
        return {**current, "status": "already_sent", "sent": True}
    if (
        not force
        and current.get("status") in {"sending", "uncertain", "blocked", "failed"}
    ):
        return {**current, "automatic_action": "skipped"}

    root, identity = _direct_termination_alert_identity(worktree)
    config = load_config()
    payload = _direct_termination_alert_payload(
        identity,
        at_mobiles=config.at_mobiles,
        at_all=config.at_all,
    )
    plan = _delivery_plan(config, [payload])
    receipt_key = _direct_termination_receipt_key(identity)
    if force and expected_receipt_key != receipt_key:
        raise DingTalkDeliveryError("人工恢复 receipt key 与当前运行身份不一致")
    if force and expected_delivery_plan_sha256 != plan.sha256:
        raise DingTalkDeliveryError("人工恢复计划已漂移，请重新读取状态并核对群后再确认")
    receipt_root = _resolve_receipt_root(state_root, worktree=root)
    now = utc_now()
    receipt: dict[str, Any] = {
        "schema_version": DIRECT_TERMINATION_ALERT_SCHEMA_VERSION,
        "adapter_version": DINGTALK_ADAPTER_VERSION,
        "channel": "dingtalk_custom_robot",
        "alert_kind": "direct_termination",
        "run_id": identity["run_id"],
        "business_date": identity["business_date"],
        "failed_stage": identity["failed_stage"],
        "classification": identity["classification"],
        "incarnation_id_sha256": identity["incarnation_id_sha256"],
        "receipt_key": receipt_key,
        "requested_by": (
            "trusted_supervisor_manual_recovery"
            if force
            else "trusted_supervisor"
        ),
        "delivery_mode": (
            "manual_force_after_group_review"
            if force
            else "automatic_on_direct_termination"
        ),
        "destination_id": plan.destination_id,
        "delivery_plan_sha256": plan.sha256,
        "payload_sha256": plan.payload_sha256[0],
        "status": "sending",
        "in_flight": None,
        "last_error_type": None,
        "last_error": None,
        "created_at": now,
        "updated_at": now,
        "sent_at": None,
    }
    try:
        with _channel_lock(receipt_root):
            with _delivery_lock(receipt_root, receipt_key):
                existing = _load_receipt(receipt_root, receipt_key)
                if existing:
                    _validate_direct_termination_receipt(
                        existing,
                        identity=identity,
                        receipt_key=receipt_key,
                    )
                    if existing.get("status") == "sent":
                        return {
                            **direct_termination_alert_status(
                                root,
                                state_root=state_root,
                            ),
                            "status": "already_sent",
                            "sent": True,
                        }
                    if not force and existing.get("status") in {
                        "sending",
                        "uncertain",
                        "failed",
                    }:
                        return {
                            **current,
                            "status": (
                                "uncertain"
                                if existing.get("status") == "sending"
                                else str(existing.get("status"))
                            ),
                            "automatic_action": "skipped",
                        }
                    if (
                        existing.get("destination_id") != plan.destination_id
                        or existing.get("delivery_plan_sha256") != plan.sha256
                        or existing.get("payload_sha256") != plan.payload_sha256[0]
                    ):
                        if force:
                            _archive_receipt(receipt_root, receipt_key)
                            receipt["recovery_of_status"] = str(
                                existing.get("status")
                            )
                            existing = {}
                        else:
                            return {
                                **current,
                                "status": "blocked",
                                "automatic_action": "skipped",
                                "error": "钉钉目标或预警计划已变化，拒绝自动重发",
                            }
                    elif force:
                        receipt["recovery_of_status"] = str(
                            existing.get("status")
                        )
                    if existing:
                        receipt["created_at"] = existing.get("created_at") or now
                elif force:
                    raise DingTalkDeliveryError(
                        "当前没有可人工恢复的直接终止预警 receipt"
                    )
                receipt["in_flight"] = {
                    "attempt_id": uuid.uuid4().hex,
                    "started_at": utc_now(),
                }
                receipt["updated_at"] = utc_now()
                _write_receipt(receipt_root, receipt_key, receipt)
                _wait_for_channel_slot(
                    receipt_root,
                    sleeper=sleeper,
                    clock=clock,
                )
                try:
                    _post_payload(config, payload, opener=opener, timeout=timeout)
                except DingTalkDeliveryError as exc:
                    receipt["status"] = "uncertain" if exc.uncertain else "failed"
                    receipt["in_flight"] = None
                    receipt["last_error_type"] = type(exc).__name__
                    receipt["last_error"] = str(exc)
                    receipt["updated_at"] = utc_now()
                    _write_receipt(receipt_root, receipt_key, receipt)
                    return {
                        **current,
                        "status": receipt["status"],
                        (
                            "manual_recovery_action"
                            if force
                            else "automatic_action"
                        ): "failed_safely",
                        "receipt_key": receipt_key,
                        "error": str(exc),
                    }
                receipt["status"] = "sent"
                receipt["in_flight"] = None
                receipt["last_error_type"] = None
                receipt["last_error"] = None
                receipt["updated_at"] = utc_now()
                receipt["sent_at"] = receipt["updated_at"]
                try:
                    _write_receipt(receipt_root, receipt_key, receipt)
                except DingTalkDeliveryError:
                    return {
                        **current,
                        "status": "uncertain",
                        (
                            "manual_recovery_action"
                            if force
                            else "automatic_action"
                        ): "failed_safely",
                        "receipt_key": receipt_key,
                        "error": "钉钉已响应成功但预警 receipt 未落盘，发送结果不确定",
                    }
    except DingTalkDeliveryError as exc:
        return {
            **current,
            "status": "uncertain" if exc.uncertain else "failed",
            (
                "manual_recovery_action"
                if force
                else "automatic_action"
            ): "failed_safely",
            "receipt_key": receipt_key,
            "error": str(exc),
        }
    return {
        **current,
        "status": "sent",
        "sent": True,
        (
            "manual_recovery_action"
            if force
            else "automatic_action"
        ): "sent",
        "receipt_key": receipt_key,
        "sent_at": receipt["sent_at"],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worktree", type=Path, required=True)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--new-delivery", action="store_true")
    args = parser.parse_args()
    try:
        # The direct adapter is a trusted CLI boundary.  It may retain secrets
        # already supplied by its parent process, while the tracked file is
        # still required to be secret-free and can provide only safe defaults.
        load_project_env(PROJECT_ROOT, role="dingtalk_cli")
        result = send_completed_report(
            args.worktree,
            dry_run=args.dry_run,
            force=args.force,
            new_delivery=args.new_delivery,
        )
    except (DingTalkDeliveryError, RuntimeEnvironmentError) as exc:
        print(
            json.dumps(
                {"status": "failed", "error": str(exc)},
                ensure_ascii=False,
            ),
            file=sys.stderr,
        )
        raise SystemExit(1) from exc
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
