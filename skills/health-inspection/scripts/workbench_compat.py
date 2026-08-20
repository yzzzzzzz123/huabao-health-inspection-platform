"""Safe projections for the established HuaBao operations workbench.

The production workbench predates the artifact-ID Workspace API.  This module
adapts the new, contract-bound state into that UI's existing response shapes.
Frozen run context is always resolved through :class:`WorkspaceService`,
verified against the SQLite index and artifact registry, and checked against
the workspace identity before projection.  Editable policy facts come only
from the server-owned :class:`WorkbenchPolicyStore`; no function accepts an
arbitrary filesystem path.
"""

from __future__ import annotations

import calendar
import copy
import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from datetime import date, timedelta
from typing import Any

from workbench_policy_store import PolicyStore
from workspace_api import (
    STAGE_NAMES,
    STAGE_OUTPUTS,
    WorkspaceAPIError,
    WorkspaceService,
    ensure_public_text_safe,
    safe_public_projection,
)


_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_POLICY_VERSION_RE = re.compile(r"^v[1-9][0-9]*\.(?:0|[1-9][0-9]*)$")
_STATUS_LABELS = {
    "preparing": "准备中",
    "pending": "待执行",
    "queued": "排队中",
    "running": "执行中",
    "completed": "已完成",
    "failed": "失败",
    "human_takeover_required": "需要人工接管",
}
_STAGE_OUTPUT_IDS: dict[str, str | None] = {
    "data_operator": "data_layer_facts",
    "inspector": "inspector_inspection_json",
    "diagnostician": "diagnostician_diagnosis_json",
    "advisor": "advisor_action_plan_json",
    "auditor": "auditor_audit_json",
    "reporter": "reporter_daily_report_json",
}
_STAGE_AGENT_NAMES = {
    "data_operator": "data_operator_agent",
    "inspector": "inspector_agent",
    "diagnostician": "diagnostician_agent",
    "advisor": "advisor_agent",
    "auditor": "auditor_agent",
    "reporter": "reporter_agent",
}
_DELIVERABLES = {
    "inspector": ("inspector_inspection_md", "巡检结果", "inspection.md"),
    "diagnostician": (
        "diagnostician_diagnosis_md",
        "诊断结果",
        "diagnosis.md",
    ),
    "advisor": ("advisor_action_plan_md", "行动方案", "action-plan.md"),
    "auditor": ("auditor_audit_md", "风险审核", "audit.md"),
    "reporter": (
        "reporter_daily_report_md",
        "每日管理报告",
        "daily-report.md",
    ),
}
_SCOPE = {
    "scope_id": "huabao-site-health-inspection",
    "country_code": "ALL",
    "site_name": "华宝新能站内健康巡检",
    "timezone": "Asia/Shanghai",
    "currency": "CNY",
    "dimensions": ["traffic", "conversion", "product"],
}
_PUBLIC_JSON_FIELDS: dict[str, frozenset[str]] = {
    "data_layer_facts": frozenset(
        {
            "schema_version",
            "run_id",
            "business_date",
            "scope",
            "data_quality",
            "data_provenance",
            "metric_catalog",
            "health",
            "health_policy",
            "metrics",
            "anomalies",
            "evidence_ids",
            "calculated_at",
        }
    ),
    "data_layer_health_policy": frozenset(
        {
            "schema_version",
            "version",
            "effective_at",
            "activation_mode",
            "mode",
            "inspection_schedule",
            "rules",
            "scoring_config",
            "sha256",
            "created_at",
            "activated_at",
            "note",
            "previous_sha256",
        }
    ),
    "inspector_inspection_json": frozenset(
        {
            "schema_version",
            "run_id",
            "business_date",
            "stage",
            "status",
            "summary",
            "dimension_summary",
            "ranked_anomalies",
            "cases",
            "dismissed_anomaly_ids",
        }
    ),
    "diagnostician_diagnosis_json": frozenset(
        {
            "schema_version",
            "run_id",
            "business_date",
            "stage",
            "status",
            "summary",
            "diagnoses",
        }
    ),
    "advisor_action_plan_json": frozenset(
        {
            "schema_version",
            "run_id",
            "business_date",
            "stage",
            "status",
            "summary",
            "actions",
            "not_recommended",
        }
    ),
    "auditor_audit_json": frozenset(
        {
            "schema_version",
            "run_id",
            "business_date",
            "stage",
            "status",
            "summary",
            "logic_reviews",
            "effect_reviews",
            "contradictions",
        }
    ),
    "reporter_daily_report_json": frozenset(
        {
            "schema_version",
            "run_id",
            "business_date",
            "stage",
            "status",
            "headline",
            "executive_summary",
            "data_provenance",
            "health_score",
            "health_assessment",
            "management_priorities",
            "key_anomalies",
            "recommended_actions",
            "unsupported_actions",
            "effect_reviews",
            "decision_bottleneck",
            "delivery_request",
        }
    ),
}
_PUBLIC_POLICY_BINDING_FIELDS = frozenset(
    {"version", "sha256", "effective_at", "activation_mode", "mode"}
)
_PUBLIC_POLICY_RULE_FIELDS = frozenset(
    {
        "metric_id",
        "position",
        "dimension",
        "dimension_label",
        "name",
        "description",
        "frequency",
        "primary_output",
        "format",
        "precision",
        "favorable",
        "source",
        "baseline",
        "rule_type",
        "threshold_fields",
        "legacy_evaluation_status",
        "legacy_alert_rule",
        "thresholds",
        "classification_enabled",
        "evaluation_status",
        "special_anomaly_branch",
    }
)
_PUBLIC_CONFIG_FIELDS = frozenset(
    {
        "service",
        "environment_schema_version",
        "workspace_version",
        "timezone",
        "currency",
        "dimensions",
        "registered_platform_release",
        "releases",
        "artifact_contract_sha256",
    }
)
_PUBLIC_DINGTALK_FIELDS = frozenset(
    {
        "channel",
        "trigger",
        "configured",
        "signed",
        "valid",
        "configuration_error",
        "at_mobiles_count",
        "at_all",
    }
)
_PUBLIC_POLICY_DRAFT_FIELDS = frozenset(
    {
        "schema_version",
        "draft_revision",
        "base_version",
        "base_sha256",
        "updated_at",
        "rules",
        "scoring_config",
        "inspection_schedule",
    }
)
_PUBLIC_POLICY_VERSION_FIELDS = frozenset(
    {
        "schema_version",
        "version",
        "ordinal",
        "mode",
        "activation_mode",
        "created_at",
        "effective_at",
        "activated_at",
        "note",
        "previous_sha256",
        "rules",
        "scoring_config",
        "inspection_schedule",
        "inspection_time",
        "sha256",
        "status",
        "selected_for_next_run",
        "launch_selection_mode",
        "run_usage_count",
        "run_usage",
        "identity_conflict_count",
        "identity_conflicts",
        "deletable",
        "delete_block_reason",
    }
)
_PUBLIC_POLICY_OVERVIEW_FIELDS = frozenset(
    {
        "schema_version",
        "metric_count",
        "metric_catalog",
        "effective_version",
        "published_version_count",
        "next_version",
        "launch_selection",
        "draft",
        "draft_etag",
        "draft_changes",
        "draft_scoring_changes",
        "draft_schedule_change",
        "draft_change_count",
        "selected_run",
        "metric_context",
        "frozen_policy",
        "read_only",
        "write_operations",
    }
)
_PUBLIC_POLICY_DETAIL_FIELDS = frozenset(
    {
        "version",
        "previous_version",
        "changes",
        "scoring_changes",
        "schedule_change",
        "change_count",
        "rules",
        "scoring_config",
        "inspection_schedule",
        "metric_count",
        "run_usage_count",
        "run_usage",
        "identity_conflict_count",
        "identity_conflicts",
        "deletable",
        "delete_block_reason",
    }
)
_PUBLIC_POLICY_USAGE_FIELDS = frozenset(
    {"run_id", "business_date", "status", "storage_type", "policy_sha256"}
)
_PUBLIC_POLICY_SELECTION_FIELDS = frozenset(
    {
        "selected",
        "mode",
        "selected_version",
        "selected_sha256",
        "selected_at",
        "selection_revision",
    }
)
_PUBLIC_POLICY_DELETE_FIELDS = frozenset(
    {
        "deleted",
        "version",
        "sha256",
        "version_count",
        "next_version",
        "draft_revision",
        "launch_selection_cleared",
    }
)
_PUBLIC_SCHEDULE_FIELDS = frozenset(
    {
        "schema_version",
        "timezone",
        "cadence",
        "activation_rule",
        "configured",
        "status",
        "etag",
        "active",
        "pending",
        "next_trigger_at",
        "automatic_dispatch_enabled",
        "disabled_reason",
        "draft_revision",
    }
)


def _query_value(query: Mapping[str, Any] | None, key: str) -> str | None:
    if not query or key not in query:
        return None
    value = query[key]
    if isinstance(value, (list, tuple)):
        if not value:
            return None
        if len(value) != 1:
            raise WorkspaceAPIError(
                400,
                "duplicate_query_parameter",
                "query parameters may be supplied only once",
            )
        value = value[0]
    return str(value) if value is not None else None


def _query_values(query: Mapping[str, Any] | None, key: str) -> list[str]:
    if not query or key not in query:
        return []
    value = query[key]
    values = value if isinstance(value, (list, tuple)) else [value]
    if len(values) != 1:
        raise WorkspaceAPIError(
            400,
            "duplicate_query_parameter",
            "query parameters may be supplied only once",
        )
    return [str(item) for item in values if item is not None]


def _strict_query(
    query: Mapping[str, Any] | None,
    *,
    allowed: frozenset[str],
) -> None:
    if not query:
        return
    if any(not isinstance(key, str) for key in query) or not set(query).issubset(allowed):
        raise WorkspaceAPIError(
            400,
            "invalid_query",
            "query contains an unsupported parameter",
        )
    for value in query.values():
        values = value if isinstance(value, (list, tuple)) else [value]
        if len(values) != 1:
            raise WorkspaceAPIError(
                400,
                "duplicate_query_parameter",
                "query parameters may be supplied only once",
            )


def _canonical_date(value: str, *, field: str = "business_date") -> str:
    try:
        canonical = date.fromisoformat(value).isoformat()
    except ValueError as exc:
        raise WorkspaceAPIError(422, f"invalid_{field}", f"{field} must be YYYY-MM-DD") from exc
    if canonical != value:
        raise WorkspaceAPIError(422, f"invalid_{field}", f"{field} must be canonical")
    return canonical


def _legacy_status(value: Any) -> str:
    status = str(value or "pending")
    return {
        "open": "running",
        "sealing": "running",
        "sealed": "completed",
        "error": "failed",
        "deleting": "failed",
    }.get(status, status)


def _strict_json(content: bytes, *, artifact_id: str) -> Any:
    try:
        return json.loads(
            content.decode("utf-8"),
            parse_constant=lambda token: (_ for _ in ()).throw(ValueError(token)),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise WorkspaceAPIError(
            409,
            "workbench_artifact_invalid",
            f"{artifact_id} is not strict UTF-8 JSON",
        ) from exc


def _run(service: WorkspaceService, run_id: str) -> dict[str, Any]:
    # The private lookup is appropriate inside the service process and applies
    # the same canonical run-ID gate as the public Workspace API.
    return service._run_or_404(run_id)  # noqa: SLF001


def _verify_document_identity(
    document: Mapping[str, Any],
    run: Mapping[str, Any],
    *,
    artifact_id: str,
) -> None:
    expected = {
        "run_id": run["run_id"],
        "business_date": run["business_date"],
        "incarnation_id": run["incarnation_id"],
        "platform_release_sha256": run["platform_release_sha256"],
    }
    for key, expected_value in expected.items():
        if key in document and document[key] != expected_value:
            raise WorkspaceAPIError(
                409,
                "workbench_artifact_binding",
                f"{artifact_id} {key} differs from the workspace identity",
            )


def _json_artifact(
    service: WorkspaceService,
    run: Mapping[str, Any],
    artifact_id: str,
    *,
    required: bool = False,
) -> dict[str, Any] | None:
    if service.store.get_artifact(str(run["run_id"]), artifact_id) is None:
        if required:
            raise WorkspaceAPIError(
                409,
                "workbench_artifact_missing",
                f"required artifact is missing: {artifact_id}",
            )
        return None
    content, media_type, metadata = service.get_artifact(
        str(run["run_id"]),
        artifact_id,
        incarnation_id=str(run["incarnation_id"]),
        release_sha256=str(run["platform_release_sha256"]),
    )
    if media_type != "application/json" or metadata.get("media_type") != media_type:
        raise WorkspaceAPIError(
            409,
            "workbench_artifact_media_type",
            f"{artifact_id} must be application/json",
        )
    if hashlib.sha256(content).hexdigest() != metadata.get("sha256"):
        # WorkspaceService already checks this.  Repeating it here makes the
        # compatibility boundary explicit and independently fail closed.
        raise WorkspaceAPIError(
            409,
            "workbench_artifact_hash_mismatch",
            f"{artifact_id} hash differs from its verified metadata",
        )
    value = _strict_json(content, artifact_id=artifact_id)
    if not isinstance(value, dict):
        raise WorkspaceAPIError(
            409,
            "workbench_artifact_invalid",
            f"{artifact_id} must contain a JSON object",
        )
    _verify_document_identity(value, run, artifact_id=artifact_id)
    allowed_fields = _PUBLIC_JSON_FIELDS.get(artifact_id)
    if allowed_fields is None:
        raise WorkspaceAPIError(
            409,
            "workbench_artifact_not_public",
            "artifact is not registered for a public business projection",
        )
    return safe_public_projection(
        value,
        allowed_keys=allowed_fields,
        source=artifact_id,
    )


def _text_artifact(
    service: WorkspaceService,
    run: Mapping[str, Any],
    artifact_id: str,
) -> str | None:
    if service.store.get_artifact(str(run["run_id"]), artifact_id) is None:
        return None
    content, media_type, metadata = service.get_artifact(
        str(run["run_id"]),
        artifact_id,
        incarnation_id=str(run["incarnation_id"]),
        release_sha256=str(run["platform_release_sha256"]),
    )
    if media_type not in {"text/markdown", "text/plain"}:
        raise WorkspaceAPIError(
            409,
            "workbench_artifact_media_type",
            f"{artifact_id} must be text",
        )
    if hashlib.sha256(content).hexdigest() != metadata.get("sha256"):
        raise WorkspaceAPIError(
            409,
            "workbench_artifact_hash_mismatch",
            f"{artifact_id} hash differs from its verified metadata",
        )
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise WorkspaceAPIError(
            409,
            "workbench_artifact_invalid",
            f"{artifact_id} must be UTF-8 text",
        ) from exc
    return ensure_public_text_safe(text, source=artifact_id)


def _ndjson_artifact(
    service: WorkspaceService,
    run: Mapping[str, Any],
    artifact_id: str,
) -> list[dict[str, Any]]:
    if service.store.get_artifact(str(run["run_id"]), artifact_id) is None:
        return []
    content, media_type, metadata = service.get_artifact(
        str(run["run_id"]),
        artifact_id,
        incarnation_id=str(run["incarnation_id"]),
        release_sha256=str(run["platform_release_sha256"]),
    )
    if media_type != "application/x-ndjson":
        raise WorkspaceAPIError(
            409,
            "workbench_artifact_media_type",
            f"{artifact_id} must be NDJSON",
        )
    if hashlib.sha256(content).hexdigest() != metadata.get("sha256"):
        raise WorkspaceAPIError(
            409,
            "workbench_artifact_hash_mismatch",
            f"{artifact_id} hash differs from its verified metadata",
        )
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise WorkspaceAPIError(
            409,
            "workbench_artifact_invalid",
            f"{artifact_id} must be UTF-8 NDJSON",
        ) from exc
    values: list[dict[str, Any]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        value = _strict_json(line.encode("utf-8"), artifact_id=artifact_id)
        if not isinstance(value, dict):
            raise WorkspaceAPIError(
                409,
                "workbench_artifact_invalid",
                f"{artifact_id} line {line_number} must be an object",
            )
        _verify_document_identity(value, run, artifact_id=artifact_id)
        values.append(value)
    return values


def _public(value: Any) -> Any:
    """Deep-copy a projection while removing write-capability identities."""

    if isinstance(value, Mapping):
        return {
            str(key): _public(item)
            for key, item in value.items()
            if str(key) != "incarnation_id"
        }
    if isinstance(value, (list, tuple)):
        return [_public(item) for item in value]
    return copy.deepcopy(value)


def _catalog_generation(service: WorkspaceService) -> int:
    events = service.store.list_events()
    return max((int(item.get("sequence") or 0) for item in events), default=0)


def _policy_binding(
    service: WorkspaceService,
    run: Mapping[str, Any],
    *,
    facts: Mapping[str, Any] | None = None,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    facts_value = facts or _json_artifact(service, run, "data_layer_facts") or {}
    raw_binding = facts_value.get("health_policy")
    binding = (
        {
            key: copy.deepcopy(raw_binding[key])
            for key in _PUBLIC_POLICY_BINDING_FIELDS
            if isinstance(raw_binding, dict) and key in raw_binding
        }
        if isinstance(raw_binding, dict)
        else {}
    )
    policy = _json_artifact(service, run, "data_layer_health_policy")
    if policy is not None:
        policy_sha = str(policy.get("sha256") or "")
        binding_sha = str(binding.get("sha256") or "")
        if policy_sha and not _SHA256_RE.fullmatch(policy_sha):
            raise WorkspaceAPIError(
                409,
                "workbench_policy_hash_invalid",
                "frozen health policy SHA-256 is invalid",
            )
        if binding_sha and policy_sha and binding_sha != policy_sha:
            raise WorkspaceAPIError(
                409,
                "workbench_policy_binding",
                "facts and frozen health policy SHA-256 differ",
            )
        for key in ("version", "effective_at", "activation_mode"):
            if key in binding and key in policy and binding[key] != policy[key]:
                raise WorkspaceAPIError(
                    409,
                    "workbench_policy_binding",
                    f"facts and frozen health policy {key} differ",
                )
        if not binding:
            binding = {
                key: policy.get(key)
                for key in ("version", "sha256", "effective_at", "activation_mode", "mode")
            }
    if not binding:
        binding = {
            "version": "v1.0",
            "sha256": "",
            "effective_at": None,
            "activation_mode": "scheduled",
            "mode": "legacy",
        }
    binding_version = str(binding.get("version") or "")
    binding_sha = str(binding.get("sha256") or "")
    if _POLICY_VERSION_RE.fullmatch(binding_version) is None:
        raise WorkspaceAPIError(
            409,
            "workbench_policy_binding",
            "frozen health policy version is invalid",
        )
    if binding_sha and _SHA256_RE.fullmatch(binding_sha) is None:
        raise WorkspaceAPIError(
            409,
            "workbench_policy_hash_invalid",
            "frozen health policy SHA-256 is invalid",
        )
    return binding, policy


def _latest_run(service: WorkspaceService) -> dict[str, Any] | None:
    runs = service.store.list_runs()
    return max(runs, key=lambda item: str(item["business_date"])) if runs else None


def _facts_history(
    service: WorkspaceService,
    current_run: Mapping[str, Any],
) -> list[dict[str, Any]]:
    current_date = date.fromisoformat(str(current_run["business_date"]))
    minimum = current_date - timedelta(days=30)
    snapshots: list[dict[str, Any]] = []
    for candidate in service.store.list_runs():
        candidate_date = date.fromisoformat(str(candidate["business_date"]))
        if not minimum <= candidate_date <= current_date:
            continue
        facts = _json_artifact(service, candidate, "data_layer_facts")
        if facts is not None:
            snapshots.append(facts)
    snapshots.sort(key=lambda item: str(item["business_date"]))
    return snapshots


def _dashboard(
    service: WorkspaceService,
    run: Mapping[str, Any],
    facts: Mapping[str, Any] | None,
) -> dict[str, Any]:
    if not facts:
        return {
            "status": "pending",
            "run_id": run["run_id"],
            "business_date": run["business_date"],
            "message": "经营指标正在由 Stage 0 载入并校验。",
        }
    metrics = [dict(item) for item in facts.get("metrics", []) if isinstance(item, dict)]
    policy_binding, _policy = _policy_binding(service, run, facts=facts)
    history = _facts_history(service, run)
    history_by_metric: dict[str, list[dict[str, Any]]] = {}
    health_history: list[dict[str, Any]] = []
    component_history: dict[str, list[dict[str, Any]]] = {
        "traffic": [],
        "conversion": [],
        "product": [],
    }
    for historical in history:
        historical_date = str(historical["business_date"])
        historical_policy = historical.get("health_policy")
        historical_policy = historical_policy if isinstance(historical_policy, dict) else {}
        historical_health = historical.get("health")
        historical_health = historical_health if isinstance(historical_health, dict) else {}
        score = historical_health.get("score")
        if isinstance(score, (int, float)) and not isinstance(score, bool):
            health_history.append(
                {
                    "date": historical_date,
                    "label": historical_date[5:].replace("-", "/"),
                    "value": score,
                    "band": historical_health.get("band"),
                    "policy_version": historical_policy.get("version", "v1.0"),
                    "band_thresholds": (
                        historical_health.get("scoring", {}).get("band_thresholds", {})
                        if isinstance(historical_health.get("scoring"), dict)
                        else {}
                    ),
                }
            )
        for component in historical_health.get("components", []):
            if not isinstance(component, dict):
                continue
            dimension = str(component.get("dimension") or "")
            if dimension in component_history and isinstance(
                component.get("score"), (int, float)
            ):
                component_history[dimension].append(
                    {
                        "date": historical_date,
                        "label": historical_date[5:].replace("-", "/"),
                        "value": component["score"],
                        "band": component.get("assessment_status"),
                        "policy_version": historical_policy.get("version", "v1.0"),
                        "band_thresholds": component.get("band_thresholds", {}),
                    }
                )
        for metric in historical.get("metrics", []):
            if not isinstance(metric, dict) or not metric.get("id"):
                continue
            value = metric.get("value")
            if not isinstance(value, (int, float)) or isinstance(value, bool):
                continue
            history_by_metric.setdefault(str(metric["id"]), []).append(
                {
                    "date": historical_date,
                    "label": historical_date[5:].replace("-", "/"),
                    "value": value,
                    "health_band": metric.get("health_band") or (
                        "red" if metric.get("status") == "abnormal" else "green"
                        if metric.get("status") == "normal"
                        else None
                    ),
                    "status": metric.get("status"),
                    "policy_version": historical_policy.get("version", "v1.0"),
                    "policy_rule": (
                        metric.get("technical", {}).get("health_policy_rule")
                        if isinstance(metric.get("technical"), dict)
                        else None
                    ),
                }
            )
    for metric in metrics:
        metric_id = str(metric.get("id") or "")
        metric["history"] = history_by_metric.get(metric_id, [])
        metric.setdefault("policy_version", policy_binding.get("version", "v1.0"))
        if "health_band" not in metric:
            metric["health_band"] = (
                "red" if metric.get("status") == "abnormal" else "green"
                if metric.get("status") == "normal"
                else None
            )
        metric["history_window"] = {
            "unit": "calendar_month",
            "count": 1,
            "label": "近1个月",
            "start_date": (date.fromisoformat(str(run["business_date"])) - timedelta(days=30)).isoformat(),
            "end_date": run["business_date"],
            "inclusive": True,
        }
    health = copy.deepcopy(facts.get("health") or {})
    health["history"] = health_history
    health["history_window"] = {
        "unit": "calendar_month",
        "count": 1,
        "label": "近1个月",
        "start_date": (date.fromisoformat(str(run["business_date"])) - timedelta(days=30)).isoformat(),
        "end_date": run["business_date"],
        "inclusive": True,
    }
    components = []
    for source in health.get("components", []):
        if not isinstance(source, dict):
            continue
        component = dict(source)
        dimension = str(component.get("dimension") or "")
        component["history"] = component_history.get(dimension, [])
        component["history_window"] = dict(health["history_window"])
        components.append(component)
    health["components"] = components
    counts = {
        "total": len(metrics),
        "day": sum(item.get("frequency") == "day" for item in metrics),
        "week": sum(item.get("frequency") == "week" for item in metrics),
        "month": sum(item.get("frequency") == "month" for item in metrics),
        "abnormal": sum(item.get("status") == "abnormal" for item in metrics),
        "normal": sum(item.get("status") == "normal" for item in metrics),
        "observed": sum(item.get("status") == "observed" for item in metrics),
        "attention": sum(item.get("health_band") == "yellow" for item in metrics),
        "evaluated": sum(item.get("evaluation_status") == "evaluated" for item in metrics),
        "partially_evaluated": sum(
            item.get("evaluation_status") == "partially_evaluated" for item in metrics
        ),
        "monitor_only": sum(item.get("evaluation_status") == "monitor_only" for item in metrics),
    }
    counts["rule_covered"] = counts["evaluated"] + counts["partially_evaluated"]
    period_titles = {
        "day": ("日度运营巡检", "当日同口径", "日度口径"),
        "week": ("周度运营巡检", "上一自然周同口径", "周度口径"),
        "month": ("月度运营巡检", "上一自然月同口径", "月度口径"),
    }
    periods: dict[str, Any] = {}
    components_by_dimension = {
        str(item.get("dimension")): item for item in components if isinstance(item, dict)
    }
    assessment = health.get("assessment") if isinstance(health.get("assessment"), dict) else {}
    for frequency, (title, comparison, range_label) in period_titles.items():
        period_metrics = [item for item in metrics if item.get("frequency") == frequency]
        dimension_kpis: dict[str, list[dict[str, Any]]] = {}
        for dimension in ("traffic", "conversion", "product"):
            dimension_metrics = [item for item in period_metrics if item.get("dimension") == dimension]
            dimension_kpis[dimension] = [
                {
                    "metric_id": item.get("id"),
                    "label": item.get("name"),
                    "value": item.get("value"),
                    "format": item.get("format", "number"),
                    "decimals": item.get("decimals", 0),
                    "favorable": item.get("favorable", "stable"),
                    "trend": (
                        item.get("trend", {}).get("change_pct", 0)
                        if isinstance(item.get("trend"), dict)
                        else 0
                    ),
                    "trend_unit": "%",
                }
                for item in dimension_metrics[:3]
            ]
        periods[frequency] = {
            "title": title,
            "range": f"{run['business_date']} · {range_label}",
            "window": f"截至 {run['business_date']} 的冻结业务窗口",
            "comparison": comparison,
            "cutoff": facts.get("data_quality", {}).get("cutoff", facts.get("calculated_at")),
            "expected_count": len(period_metrics),
            "evaluated_count": sum(
                item.get("evaluation_status") == "evaluated" for item in period_metrics
            ),
            "partially_evaluated_count": sum(
                item.get("evaluation_status") == "partially_evaluated"
                for item in period_metrics
            ),
            "monitor_only_count": sum(
                item.get("evaluation_status") == "monitor_only" for item in period_metrics
            ),
            "rule_covered_count": sum(
                item.get("evaluation_status") in {"evaluated", "partially_evaluated"}
                for item in period_metrics
            ),
            "abnormal_count": sum(item.get("status") == "abnormal" for item in period_metrics),
            "attention_count": sum(item.get("health_band") == "yellow" for item in period_metrics),
            "normal_count": sum(item.get("status") == "normal" for item in period_metrics),
            "data_completeness_ratio": facts.get("data_quality", {}).get(
                "completeness_ratio", 0
            ),
            "health": {
                **health,
                "components": [
                    components_by_dimension.get(dimension, {"dimension": dimension})
                    for dimension in ("traffic", "conversion", "product")
                ],
                "assessment": assessment,
            },
            "dimension_kpis": dimension_kpis,
            "note": (
                f"37 项指标均已接入；本次冻结 {policy_binding.get('version', 'v1.0')}，"
                f"完整判定 {int(assessment.get('evaluated_count') or 0)} 项，"
                f"特殊分支判定 {int(assessment.get('partially_evaluated_count') or 0)} 项，"
                f"持续监测 {int(assessment.get('monitor_only_count') or 0)} 项。"
            ),
        }
    return {
        "status": "ready",
        "run_id": run["run_id"],
        "business_date": run["business_date"],
        "calculated_at": facts.get("calculated_at"),
        "counts": counts,
        "health": health,
        "data_quality": copy.deepcopy(facts.get("data_quality") or {}),
        "data_provenance": copy.deepcopy(facts.get("data_provenance") or {}),
        "health_policy": policy_binding,
        "periods": periods,
        "metrics": metrics,
    }


def _safe_recent_events(
    service: WorkspaceService,
    run: Mapping[str, Any],
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    event_names = {
        "stage_completed": "stage.completed",
        "stage_failed": "stage.failed",
    }
    stage_numbers = {stage: index for index, stage in enumerate(STAGE_NAMES)}
    for item in _ndjson_artifact(service, run, "orchestrator_events"):
        raw_type = str(item.get("event") or "")
        stage = str(item.get("stage") or "") or None
        event_type = event_names.get(raw_type, raw_type.replace("_", ".") or "run.event")
        if raw_type == "stage_completed" and stage:
            message = f"Stage {stage_numbers.get(stage, 0)} {stage} 已通过门禁并晋升正式产物。"
        elif raw_type == "stage_failed" and stage:
            message = f"Stage {stage_numbers.get(stage, 0)} {stage} 未通过门禁。"
        else:
            message = "巡检控制面已记录受控状态变化。"
        result.append(
            {
                "seq": len(result) + 1,
                "timestamp": item.get("at") or run.get("created_at"),
                "type": event_type,
                "stage": stage,
                "message": message,
            }
        )
    store_event_messages = {
        "workspace_created": "每日隔离工作区已创建并绑定平台版本。",
        "workspace_sealing": "最终交付门禁通过，工作区正在封存。",
        "workspace_sealed": "运行已完成 Git checkpoint、归档与哈希校验。",
    }
    for item in service.store.list_events(run_id=str(run["run_id"])):
        event_type = str(item.get("event_type") or "")
        if event_type not in store_event_messages:
            continue
        result.append(
            {
                "seq": len(result) + 1,
                "timestamp": item.get("occurred_at"),
                "type": event_type.replace("_", "."),
                "stage": None,
                "message": store_event_messages[event_type],
            }
        )
    result.sort(key=lambda item: (str(item.get("timestamp") or ""), int(item["seq"])))
    for sequence, item in enumerate(result, start=1):
        item["seq"] = sequence
    event_fields = frozenset({"seq", "timestamp", "type", "stage", "message"})
    return [
        safe_public_projection(
            item,
            allowed_keys=event_fields,
            source="workbench_event_projection",
        )
        for item in result
    ]


def _stage_projection(
    service: WorkspaceService,
    run: Mapping[str, Any],
    workbench: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    # ``get_workbench_projection`` already verified the complete SQLite index
    # against registry paths and on-disk bytes, but intentionally exposes only
    # UI-visible artifact metadata. Stage completion therefore uses the private
    # in-process index and re-reads every expected formal output; internal
    # intelligence/evidence artifact IDs never cross the public boundary.
    artifacts = service.store.list_artifacts(str(run["run_id"]))
    artifact_by_id = {
        str(item.get("artifact_id")): item
        for item in artifacts
        if isinstance(item.get("artifact_id"), str)
    }
    if len(artifact_by_id) != len(artifacts):
        raise WorkspaceAPIError(
            409,
            "workbench_artifact_index_invalid",
            "verified workbench artifact projection contains duplicate IDs",
        )
    artifact_ids = set(artifact_by_id)
    stage_statuses = {
        stage: _legacy_status(status)
        for stage, status in dict(workbench.get("stage_statuses") or {}).items()
    }
    stages: dict[str, Any] = {}
    audits: dict[str, Any] = {}
    for stage in STAGE_NAMES:
        attempts = {
            match.group(1)
            for artifact_id in artifact_ids
            for match in [re.fullmatch(rf"{re.escape(stage)}_attempt_(00[1-3])_attempt", artifact_id)]
            if match is not None
        }
        expected_outputs = STAGE_OUTPUTS[stage]
        verified_outputs: dict[str, dict[str, Any]] = {}
        for artifact_id in expected_outputs:
            if artifact_id not in artifact_ids:
                continue
            _content, _media_type, metadata = service.get_artifact(
                str(run["run_id"]),
                artifact_id,
                incarnation_id=str(run["incarnation_id"]),
                release_sha256=str(run["platform_release_sha256"]),
            )
            indexed = artifact_by_id[artifact_id]
            if (
                metadata.get("id") != indexed.get("artifact_id")
                or metadata.get("sha256") != indexed.get("sha256")
                or metadata.get("bytes") != indexed.get("bytes")
                or metadata.get("media_type") != indexed.get("media_type")
            ):
                raise WorkspaceAPIError(
                    409,
                    "workbench_artifact_index_invalid",
                    "formal stage artifact differs from the verified projection",
                )
            verified_outputs[artifact_id] = metadata
        verified = len(verified_outputs) == len(expected_outputs)
        status = "completed" if verified else stage_statuses.get(stage, "pending")
        if status == "completed" and not verified:
            status = "in_progress"
        stages[stage] = {
            "status": status,
            "attempts": len(attempts),
            "business_attempts": len(attempts),
            "replacement_generation": 0,
            "verified": verified,
        }
        output_id = _STAGE_OUTPUT_IDS[stage]
        output_artifact = verified_outputs.get(output_id) if output_id else None
        audits[stage] = {
            "verified": verified,
            "custom_agent": _STAGE_AGENT_NAMES[stage],
            "attempt": len(attempts) or None,
            "child_thread_id": "",
            "context_packet_bytes": None,
            "context_packet_sha256": None,
            "output_sha256": output_artifact.get("sha256") if output_artifact else None,
            "exact_output_match": verified,
            "root_non_collaboration_tool_calls": 0,
            "child_tool_calls": 0,
            "child_tool_successes": 0,
            "child_tool_unavailable": 0,
            "child_tool_calls_verified": True,
            "agent_decision_count": None,
            "evidence_tool_names": [],
            "validation": {"status": "passed"} if verified else {},
        }
    return stages, audits


def _public_dingtalk_config(service: WorkspaceService) -> dict[str, Any]:
    raw = service.get_config().get("dingtalk")
    raw = raw if isinstance(raw, dict) else {}
    selected = {key: raw[key] for key in _PUBLIC_DINGTALK_FIELDS if key in raw}
    return safe_public_projection(
        selected,
        allowed_keys=_PUBLIC_DINGTALK_FIELDS,
        source="dingtalk_configuration_status",
    )


def _dingtalk_projection(service: WorkspaceService, run: Mapping[str, Any]) -> dict[str, Any]:
    configured = _public_dingtalk_config(service)
    completed = _legacy_status(run.get("status")) == "completed"
    return {
        **configured,
        "available": completed,
        "status": "not_sent",
        "sent": False,
        "sent_count": 0,
        "part_count": 0,
        "automatic_action": "waiting_for_credentials" if not configured.get("configured") else "pending",
    }


def config_projection(service: WorkspaceService) -> dict[str, Any]:
    """Return the legacy UI bootstrap contract without secret material."""

    raw_config = service.get_config()
    base = safe_public_projection(
        {
            key: raw_config[key]
            for key in _PUBLIC_CONFIG_FIELDS
            if key in raw_config
        },
        allowed_keys=_PUBLIC_CONFIG_FIELDS,
        source="workspace_public_configuration",
    )
    dingtalk = _public_dingtalk_config(service)
    latest = _latest_run(service)
    policy_binding: dict[str, Any] | None = None
    metric_count = 37
    if latest is not None:
        facts = _json_artifact(service, latest, "data_layer_facts")
        if facts is not None:
            policy_binding, _policy = _policy_binding(service, latest, facts=facts)
            catalog = facts.get("metric_catalog")
            if isinstance(catalog, dict):
                metric_count = int(catalog.get("metric_count") or metric_count)
    dispatch_configured = bool(raw_config.get("dolphin_dispatch_url"))
    result = {
        **base,
        "schema_version": "1.0",
        "scope": _SCOPE,
        "health_dimensions": ["traffic", "conversion", "product"],
        "metric_counts": {"total": metric_count, "traffic": 12, "conversion": 10, "product": 15},
        "health_policy_gate": {
            "selection": "registered_dolphin_release_and_frozen_run_policy",
            "freeze": "immutable_for_entire_run",
            "status": "ready" if policy_binding else "unavailable",
            **(policy_binding or {}),
            "metric_count": metric_count,
        },
        "agent_service": {
            "provider": "dolphin-ai",
            "dispatch_configured": dispatch_configured,
            "status": "ready" if dispatch_configured else "deployment_gateway_required",
            "fixed_agent_count": 7,
        },
        "dolphin_dispatch_configured": dispatch_configured,
        "runtime": {
            "status": "ready",
            "workspace_api": "artifact_id_only",
            "worktree_storage": "git_linked_worktree",
            "control_mode": "read_only_workbench_projection",
        },
        "model": "dolphin-hosted",
        "reasoning_effort": "managed_by_dolphin",
        "context_policy_version": "bounded-stage-packets-v1",
        "worktree_layout": "one-daily-linked-worktree-v1",
        "run_cardinality": "one_per_business_date",
        "concurrent_run_policy": "single_active_daily_workflow",
        "max_concurrent_runs": 1,
        "rerun_policy": "delete_daily_run_first",
        "run_trigger": "manual_via_workspace_api;automatic_disabled_until_gateway",
        "scheduled_run_timezone": "Asia/Shanghai",
        "stage_sequence": list(STAGE_NAMES),
        "fixed_agent_count": 7,
        "fixed_agent_roles": ["orchestrator", *STAGE_NAMES],
        "max_attempts_per_stage": 3,
        "external_business_execution": False,
        "dingtalk_report_delivery": dingtalk,
        "dingtalk_direct_termination_alert": {
            **dingtalk,
            "trigger": "trusted_supervisor_after_direct_termination",
        },
        "runtime_connectivity_ready": dispatch_configured,
        "runtime_connectivity_error": (
            None if dispatch_configured else "Dolphin deployment gateway is not configured"
        ),
    }
    return _public(result)


def _run_summary(service: WorkspaceService, run: Mapping[str, Any]) -> dict[str, Any]:
    facts = _json_artifact(service, run, "data_layer_facts")
    report = _json_artifact(service, run, "reporter_daily_report_json")
    health = facts.get("health") if isinstance(facts, dict) else {}
    health = health if isinstance(health, dict) else {}
    components = health.get("components") if isinstance(health.get("components"), list) else []
    dimension_scores = {
        str(item.get("dimension")): item.get("score")
        for item in components
        if isinstance(item, dict) and item.get("dimension") in {"traffic", "conversion", "product"}
    }
    policy_binding, _policy = _policy_binding(service, run, facts=facts or {})
    status = _legacy_status(run.get("status"))
    updated_at = run.get("sealed_at") or run.get("seal_started_at") or run.get("created_at")
    anomaly_count = len(facts.get("anomalies", [])) if isinstance(facts, dict) else 0
    score = health.get("score")
    return {
        "run_id": run["run_id"],
        "business_date": run["business_date"],
        "status": status,
        "status_label": _STATUS_LABELS.get(status, status),
        "created_at": run.get("created_at"),
        "updated_at": updated_at,
        "completed_at": run.get("sealed_at"),
        "control_plane_active": bool(run.get("active")),
        "history_frozen": status == "completed",
        "storage_type": "history" if status == "completed" else "worktree",
        "archive_status": "completed" if status == "completed" else "none",
        "archived": status == "completed",
        "catalog_revision": len(service.store.list_artifacts(str(run["run_id"]))),
        "snapshot_version": len(service.store.list_artifacts(str(run["run_id"]))),
        "snapshot_etag": hashlib.sha256(
            f"{run['run_id']}:{updated_at}:{len(service.store.list_artifacts(str(run['run_id'])))}".encode("utf-8")
        ).hexdigest(),
        "health_score": score if isinstance(score, (int, float)) and not isinstance(score, bool) else None,
        "health_band": health.get("band"),
        "dimension_scores": dimension_scores,
        "policy_version": policy_binding.get("version", "v1.0"),
        "policy_sha256": policy_binding.get("sha256"),
        "band_thresholds": (
            health.get("scoring", {}).get("band_thresholds", {"yellow_min": 60, "green_min": 80})
            if isinstance(health.get("scoring"), dict)
            else {"yellow_min": 60, "green_min": 80}
        ),
        "red_attention_count": anomaly_count,
        "summary": {
            "health_score": score,
            "health_band": health.get("band"),
            "metric_count": len(facts.get("metrics", [])) if isinstance(facts, dict) else 0,
            "anomaly_count": anomaly_count,
            "headline": report.get("headline") if report else None,
        },
        "scope": _SCOPE,
    }


def runs_page(
    service: WorkspaceService,
    query: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Project the legacy ``GET /api/runs`` page (14 records maximum)."""

    _strict_query(
        query,
        allowed=frozenset(
            {"limit", "cursor", "business_dates", "business_date", "policy_version"}
        ),
    )
    raw_limit = _query_value(query, "limit") or "14"
    try:
        limit = int(raw_limit)
    except ValueError as exc:
        raise WorkspaceAPIError(422, "invalid_run_limit", "limit must be an integer") from exc
    if limit != 14:
        raise WorkspaceAPIError(422, "invalid_run_limit", "run pages contain exactly 14 records")
    if _query_value(query, "cursor"):
        raise WorkspaceAPIError(422, "unsupported_cursor", "cursor pagination is not needed by this bounded catalog")
    exact_dates = {_canonical_date(item) for item in _query_values(query, "business_dates")}
    single_date = _query_value(query, "business_date")
    if single_date and exact_dates:
        raise WorkspaceAPIError(
            422,
            "invalid_run_filter",
            "business_date cannot be combined with business_dates",
        )
    if single_date:
        single_date = _canonical_date(single_date)
    policy_version = _query_value(query, "policy_version")
    runs = []
    for run in service.store.list_runs():
        if exact_dates and str(run["business_date"]) not in exact_dates:
            continue
        if single_date and str(run["business_date"]) > single_date:
            continue
        projected = _run_summary(service, run)
        if policy_version and projected.get("policy_version") != policy_version:
            continue
        runs.append(projected)
    total = len(runs)
    runs = runs[:limit]
    return _public(
        {
            "runs": runs,
            "next_cursor": None,
            "previous_cursor": None,
            "total_count": total,
            "catalog_generation": _catalog_generation(service),
            "policy_version_options": _policy_options_from_summaries(
                [_run_summary(service, run) for run in service.store.list_runs()]
            ),
        }
    )


def _policy_options_from_summaries(runs: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for run in runs:
        version = str(run.get("policy_version") or "v1.0")
        counts[version] = counts.get(version, 0) + 1
    return [
        {"policy_version": version, "run_count": counts[version]}
        for version in sorted(counts, reverse=True)
    ]


def _heatmap_overview(runs: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    ordered_dates = sorted(date.fromisoformat(str(item["business_date"])) for item in runs)
    completed_dates = sorted(
        date.fromisoformat(str(item["business_date"]))
        for item in runs
        if item.get("status") == "completed"
    )
    completed_set = set(completed_dates)
    longest = current = active = 0
    previous: date | None = None
    for item in completed_dates:
        active = active + 1 if previous and item == previous + timedelta(days=1) else 1
        longest = max(longest, active)
        previous = item
    if ordered_dates and ordered_dates[-1] in completed_set:
        cursor = ordered_dates[-1]
        while cursor in completed_set:
            current += 1
            cursor -= timedelta(days=1)
    scored = [item for item in runs if isinstance(item.get("health_score"), (int, float))]
    bands = {"green": 0, "yellow": 0, "red": 0}
    for item in scored:
        score = float(item["health_score"])
        thresholds = item.get("band_thresholds") if isinstance(item.get("band_thresholds"), dict) else {}
        yellow = float(thresholds.get("yellow_min", 60))
        green = float(thresholds.get("green_min", 80))
        bands["green" if score >= green else "yellow" if score >= yellow else "red"] += 1
    dimension_averages = []
    for dimension in ("traffic", "conversion", "product"):
        values = [
            float(item["dimension_scores"][dimension])
            for item in runs
            if isinstance(item.get("dimension_scores"), dict)
            and isinstance(item["dimension_scores"].get(dimension), (int, float))
        ]
        if values:
            dimension_averages.append(
                {"dimension": dimension, "score": round(sum(values) / len(values), 2), "run_count": len(values)}
            )
    peak = max(scored, key=lambda item: (float(item["health_score"]), str(item["business_date"]))) if scored else None
    lowest = min(scored, key=lambda item: (float(item["health_score"]), str(item["business_date"]))) if scored else None
    return {
        "run_days": len(ordered_dates),
        "completed_days": len(completed_dates),
        "longest_streak_days": longest,
        "current_streak_days": current,
        "latest_run_date": ordered_dates[-1].isoformat() if ordered_dates else None,
        "latest_run_completed": bool(ordered_dates and ordered_dates[-1] in completed_set),
        "peak_health": ({"score": peak["health_score"], "business_date": peak["business_date"]} if peak else None),
        "lowest_health": ({"score": lowest["health_score"], "business_date": lowest["business_date"]} if lowest else None),
        "healthiest_dimension": max(dimension_averages, key=lambda item: item["score"]) if dimension_averages else None,
        "least_healthy_dimension": min(dimension_averages, key=lambda item: item["score"]) if dimension_averages else None,
        "dimension_averages": dimension_averages,
        "health_band_days": bands,
    }


def heatmap(
    service: WorkspaceService,
    year: int | str,
    policy_version: str | None = None,
) -> dict[str, Any]:
    """Project the legacy calendar heatmap from verified run artifacts."""

    try:
        requested_year = int(year)
        date(requested_year, 1, 1)
    except (TypeError, ValueError) as exc:
        raise WorkspaceAPIError(422, "invalid_heatmap_year", "year is invalid") from exc
    if policy_version == "all":
        policy_version = None
    all_summaries = [_run_summary(service, run) for run in service.store.list_runs()]
    runs = [
        item
        for item in all_summaries
        if date.fromisoformat(str(item["business_date"])).year == requested_year
        and (not policy_version or item.get("policy_version") == policy_version)
    ]
    runs.sort(key=lambda item: str(item["business_date"]))
    compact_keys = (
        "run_id",
        "business_date",
        "status",
        "status_label",
        "updated_at",
        "control_plane_active",
        "history_frozen",
        "storage_type",
        "archive_status",
        "archived",
        "catalog_revision",
        "snapshot_version",
        "snapshot_etag",
        "health_score",
        "health_band",
        "dimension_scores",
        "policy_version",
        "band_thresholds",
        "red_attention_count",
    )
    compact_runs = [{key: item.get(key) for key in compact_keys} for item in runs]
    return _public(
        {
            "schema_version": "1.0",
            "year": requested_year,
            "days_in_year": 366 if calendar.isleap(requested_year) else 365,
            "mode": "calendar_year",
            "selected_policy_version": policy_version,
            "run_count": len(compact_runs),
            "overview": _heatmap_overview(compact_runs),
            "runs": compact_runs,
            "catalog_generation": _catalog_generation(service),
            "policy_version_options": _policy_options_from_summaries(all_summaries),
        }
    )


def snapshot(service: WorkspaceService, run_id: str) -> dict[str, Any]:
    """Build the legacy workbench snapshot from verified, bounded artifacts."""

    run = _run(service, run_id)
    base = service.get_workbench_projection(run_id)
    facts = _json_artifact(service, run, "data_layer_facts")
    inspection = _json_artifact(service, run, "inspector_inspection_json") or {}
    diagnosis = _json_artifact(service, run, "diagnostician_diagnosis_json") or {}
    action_plan = _json_artifact(service, run, "advisor_action_plan_json") or {}
    audit = _json_artifact(service, run, "auditor_audit_json") or {}
    report = _json_artifact(service, run, "reporter_daily_report_json") or {}
    workbench_stage_statuses = base.get("stage_statuses") or {}
    stages, stage_audits = _stage_projection(service, run, base)
    stage_outputs = {
        "data_operator": facts or {},
        "inspector": inspection,
        "diagnostician": diagnosis,
        "advisor": action_plan,
        "auditor": audit,
        "reporter": report,
    }
    deliverables: dict[str, Any] = {}
    for stage, (artifact_id, title, filename) in _DELIVERABLES.items():
        markdown = _text_artifact(service, run, artifact_id)
        if markdown is not None:
            deliverables[stage] = {
                "title": title,
                "filename": filename,
                "artifact_id": artifact_id,
                "markdown": markdown,
            }
    policy_binding, _policy = _policy_binding(service, run, facts=facts or {})
    status = _legacy_status(run.get("status"))
    updated_at = run.get("sealed_at") or run.get("seal_started_at") or run.get("created_at")
    actions = [dict(item) for item in action_plan.get("actions", []) if isinstance(item, dict)]
    implementation_states = [
        {
            "action_id": item.get("action_id"),
            "action_type": item.get("action_type", "review_only"),
            "status": "available",
            "button_enabled": False,
            "read_only_reason": "兼容工作台仅展示；备注写入未接入 Workspace API",
            "note_log": None,
        }
        for item in actions
    ]
    summary = {
        "headline": report.get("headline") or (
            base.get("ui_snapshot", {}).get("headline")
            if isinstance(base.get("ui_snapshot"), dict)
            else None
        ),
        "health_score": (facts or {}).get("health", {}).get("score"),
        "health_band": (facts or {}).get("health", {}).get("band"),
        "metric_count": len((facts or {}).get("metrics", [])),
        "anomaly_count": len(inspection.get("ranked_anomalies", [])),
        "action_count": len(actions),
        "effect_review_count": len(audit.get("effect_reviews", [])),
        "red_attention_count": len((facts or {}).get("anomalies", [])),
    }
    detail = {
        "schema_version": "1.1",
        "run_id": run["run_id"],
        "business_date": run["business_date"],
        "policy_version": policy_binding.get("version", "v1.0"),
        "policy_sha256": policy_binding.get("sha256"),
        "policy_effective_at": policy_binding.get("effective_at"),
        "policy_activation_mode": policy_binding.get("activation_mode", "scheduled"),
        "status": status,
        "current_stage": None if status == "completed" else next(
            (stage for stage in STAGE_NAMES if _legacy_status(workbench_stage_statuses.get(stage)) != "completed"),
            None,
        ),
        "failed_stage": None,
        "human_takeover_required": False,
        "stages": stages,
        "summary": summary,
        "error": None,
        "created_at": run.get("created_at"),
        "updated_at": updated_at,
        "completed_at": run.get("sealed_at"),
        "resumed_from_stage": None,
        "scope": _SCOPE,
        "status_label": _STATUS_LABELS.get(status, status),
        "stage_statuses": {stage: stages[stage]["status"] for stage in STAGE_NAMES},
        "stage_audits": stage_audits,
        "stage_outputs": stage_outputs,
        "stage_deliverables": deliverables,
        "dingtalk_delivery": _dingtalk_projection(service, run),
        "dingtalk_failure_alert": {"status": "not_applicable", "sent": False},
        "orchestrator_thread_id": None,
        "orchestrator": {
            "status": "completed" if status == "completed" else "active",
            "thread_id": None,
            "control_mode": "hosted_dolphin_orchestration",
        },
        "context_policy_version": "bounded-stage-packets-v1",
        "advisor_actions": actions,
        "logic_reviews": [dict(item) for item in audit.get("logic_reviews", []) if isinstance(item, dict)],
        "action_implementation_states": implementation_states,
        "manual_adjustment_summary": {
            "total_count": sum(item.get("action_type") == "manual_adjustment" for item in actions),
            "available_count": 0,
            "logged_count": 0,
        },
        "action_note_summary": {"total_count": len(actions), "available_count": 0, "logged_count": 0},
        "effect_reviews": [dict(item) for item in audit.get("effect_reviews", []) if isinstance(item, dict)],
        "intelligence_ledger": None,
        "code_execution_ledger": {
            "stage_count": sum(stage["status"] == "completed" for stage in stages.values()),
            "source": "verified_workspace_artifact_index",
        },
        "storage_type": "history" if status == "completed" else "worktree",
        "archive_status": "completed" if status == "completed" else "none",
        "snapshot_version": len(base.get("artifacts", [])),
        "catalog_revision": len(base.get("artifacts", [])),
        "worktree": {
            "name": "daily",
            "date": run["business_date"],
            "branch": f"run/health-inspection/daily/{run['business_date']}",
            "snapshot_commit": run.get("checkpoint_commit"),
            "environment_snapshot_status": "reproducible",
        },
        "control_plane_active": bool(run.get("active")),
        "orchestrator_recovery_pending": False,
        "direct_termination": False,
        "manual_recovery_allowed": False,
        "history_frozen": status == "completed",
        "archived": status == "completed",
    }
    recent_events = _safe_recent_events(service, run)
    log = _run_log_from_parts(run, detail, recent_events)
    etag = hashlib.sha256(
        json.dumps(
            {
                "run_id": run["run_id"],
                "status": run["status"],
                "sealed_at": run.get("sealed_at"),
                "artifacts": [(item["id"], item["sha256"]) for item in base.get("artifacts", [])],
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    return _public(
        {
            "schema_version": "1.0",
            "run_id": run["run_id"],
            "detail": detail,
            "operating_dashboard": _dashboard(service, run, facts),
            "recent_events": recent_events,
            "log_summary": log,
            "snapshot_version": len(base.get("artifacts", [])),
            "snapshot_etag": etag,
            "snapshot_updated_at": updated_at,
            "catalog_revision": len(base.get("artifacts", [])),
            "catalog_generation": _catalog_generation(service),
            "history_frozen": status == "completed",
            "storage_type": detail["storage_type"],
            "archive_status": detail["archive_status"],
            "archived": detail["archived"],
        }
    )


def _run_log_from_parts(
    run: Mapping[str, Any],
    detail: Mapping[str, Any],
    events: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    status = str(detail.get("status") or _legacy_status(run.get("status")))
    lines = [
        f"华宝新能站内健康巡检 · {run['business_date']}",
        f"运行：{run['run_id']} · 状态：{_STATUS_LABELS.get(status, status)}",
        "",
    ]
    for item in events:
        timestamp = str(item.get("timestamp") or "-")
        stage = str(item.get("stage") or "run")
        lines.append(f"[{timestamp}] [{stage}] {item.get('message') or item.get('type')}")
    return {
        "status": status,
        "status_label": _STATUS_LABELS.get(status, status),
        "terminal": status in {"completed", "failed", "human_takeover_required"},
        "event_count": len(events),
        "line_count": len(lines),
        "last_seq": int(events[-1]["seq"]) if events else 0,
        "latest_event_seq": int(events[-1]["seq"]) if events else 0,
        "updated_at": run.get("sealed_at") or run.get("seal_started_at") or run.get("created_at"),
        "text": "\n".join(lines),
        "raw_log_count": 0,
        "raw_logs": [],
        "large_logs_on_demand": False,
        "safety_projection": "summary_only_no_raw_response",
    }


def run_log(service: WorkspaceService, run_id: str) -> dict[str, Any]:
    """Return the legacy log response without raw model or evidence content."""

    run = _run(service, run_id)
    status = _legacy_status(run.get("status"))
    detail = {"status": status}
    return _public(_run_log_from_parts(run, detail, _safe_recent_events(service, run)))


def _next_version(version: str) -> str:
    match = _POLICY_VERSION_RE.fullmatch(version)
    if match is None:
        return "v1.1"
    major, minor = version[1:].split(".", 1)
    return f"v{major}.{int(minor) + 1}"


def _policy_rule_projection(rule: Mapping[str, Any]) -> dict[str, Any]:
    projected = safe_public_projection(
        {key: rule[key] for key in _PUBLIC_POLICY_RULE_FIELDS if key in rule},
        allowed_keys=_PUBLIC_POLICY_RULE_FIELDS,
        source="health_policy_rule",
    )
    projected.setdefault("description", str(rule.get("name") or rule.get("metric_id") or "指标"))
    projected.setdefault("rule_type", "monitor_only")
    projected.setdefault("threshold_fields", [])
    projected.setdefault("thresholds", {})
    return projected


def _policy_rules_projection(rules: Any) -> list[dict[str, Any]]:
    if not isinstance(rules, list):
        return []
    return [
        _policy_rule_projection(item)
        for item in rules
        if isinstance(item, Mapping)
    ]


def policy_draft_projection(draft: Mapping[str, Any]) -> dict[str, Any]:
    """Apply the explicit public contract to one mutable draft response."""

    selected = {
        key: copy.deepcopy(draft[key])
        for key in _PUBLIC_POLICY_DRAFT_FIELDS
        if key in draft
    }
    selected["rules"] = _policy_rules_projection(selected.get("rules"))
    return safe_public_projection(
        selected,
        allowed_keys=_PUBLIC_POLICY_DRAFT_FIELDS,
        source="workbench_policy_draft",
    )


def policy_version_projection(
    document: Mapping[str, Any],
    *,
    run_usage: Sequence[Mapping[str, Any]] | None = None,
    deletable: bool | None = None,
) -> dict[str, Any]:
    """Apply the explicit public contract to one immutable version view."""

    selected = {
        key: copy.deepcopy(document[key])
        for key in _PUBLIC_POLICY_VERSION_FIELDS
        if key in document
    }
    if "rules" in selected:
        selected["rules"] = _policy_rules_projection(selected["rules"])
    for field, count_field in (
        ("run_usage", "run_usage_count"),
        ("identity_conflicts", "identity_conflict_count"),
    ):
        if field in selected:
            values = selected[field] if isinstance(selected[field], list) else []
            selected[field] = [
                safe_public_projection(
                    {key: item[key] for key in _PUBLIC_POLICY_USAGE_FIELDS if key in item},
                    allowed_keys=_PUBLIC_POLICY_USAGE_FIELDS,
                    source=f"workbench_policy_{field}",
                )
                for item in values
                if isinstance(item, Mapping)
            ]
            selected[count_field] = len(selected[field])
    if run_usage is not None:
        selected["run_usage"] = [
            safe_public_projection(
                {key: item[key] for key in _PUBLIC_POLICY_USAGE_FIELDS if key in item},
                allowed_keys=_PUBLIC_POLICY_USAGE_FIELDS,
                source="workbench_policy_run_usage",
            )
            for item in run_usage
        ]
        selected["run_usage_count"] = len(selected["run_usage"])
    if deletable is not None:
        selected["deletable"] = deletable
        selected["delete_block_reason"] = (
            None if deletable else "已有日期 worktree 使用该版本，请先删除对应运行"
        )
    return safe_public_projection(
        selected,
        allowed_keys=_PUBLIC_POLICY_VERSION_FIELDS,
        source="workbench_policy_version",
    )


def policy_selection_projection(value: Mapping[str, Any]) -> dict[str, Any]:
    selected = {
        key: copy.deepcopy(value[key])
        for key in _PUBLIC_POLICY_SELECTION_FIELDS
        if key in value
    }
    return safe_public_projection(
        selected,
        allowed_keys=_PUBLIC_POLICY_SELECTION_FIELDS,
        source="workbench_policy_selection",
    )


def policy_delete_projection(value: Mapping[str, Any]) -> dict[str, Any]:
    selected = {
        key: copy.deepcopy(value[key])
        for key in _PUBLIC_POLICY_DELETE_FIELDS
        if key in value
    }
    return safe_public_projection(
        selected,
        allowed_keys=_PUBLIC_POLICY_DELETE_FIELDS,
        source="workbench_policy_delete",
    )


def _scoring_from_facts(facts: Mapping[str, Any]) -> dict[str, Any]:
    health = facts.get("health") if isinstance(facts.get("health"), dict) else {}
    scoring = health.get("scoring") if isinstance(health.get("scoring"), dict) else {}
    return {
        "dimension_weight_percentages": copy.deepcopy(
            scoring.get("dimension_weight_percentages")
            or {"traffic": 34, "conversion": 33, "product": 33}
        ),
        "metric_weight_percentages": copy.deepcopy(scoring.get("metric_weight_percentages") or {}),
        "band_thresholds": copy.deepcopy(
            scoring.get("band_thresholds") or {"yellow_min": 60, "green_min": 80}
        ),
        "dimension_band_thresholds": copy.deepcopy(
            scoring.get("dimension_band_thresholds")
            or {
                "traffic": {"yellow_min": 60, "green_min": 80},
                "conversion": {"yellow_min": 60, "green_min": 80},
                "product": {"yellow_min": 60, "green_min": 80},
            }
        ),
    }


def _policy_run_usage(service: WorkspaceService) -> list[dict[str, Any]]:
    """Return verified, immutable version+SHA workspace bindings."""

    usage: list[dict[str, Any]] = []
    for run in service.store.list_runs():
        facts = _json_artifact(service, run, "data_layer_facts")
        if facts is None:
            continue
        binding, _policy = _policy_binding(service, run, facts=facts)
        version = str(binding["version"])
        sha256 = str(binding.get("sha256") or "")
        if _SHA256_RE.fullmatch(sha256) is None:
            raise WorkspaceAPIError(
                409,
                "workbench_policy_binding",
                "frozen health policy binding lacks an exact SHA-256 identity",
            )
        usage.append(
            {
                "version": version,
                "sha256": sha256,
                "run_id": run["run_id"],
                "business_date": run["business_date"],
                "status": _legacy_status(run.get("status")),
                "storage_type": "history" if run.get("status") == "sealed" else "worktree",
                "policy_sha256": sha256,
            }
        )
    usage.sort(
        key=lambda item: (
            str(item["version"]),
            str(item["sha256"]),
            str(item["business_date"]),
            str(item["run_id"]),
        )
    )
    return usage


def policy_in_use_versions(service: WorkspaceService) -> list[dict[str, Any]]:
    """Return exact version+SHA bindings for the destructive-delete gate."""

    return _policy_run_usage(service)


def _policy_documents(service: WorkspaceService) -> list[dict[str, Any]]:
    documents: dict[tuple[str, str], dict[str, Any]] = {}
    for run in service.store.list_runs():
        facts = _json_artifact(service, run, "data_layer_facts")
        if facts is None:
            continue
        binding, policy = _policy_binding(service, run, facts=facts)
        version = str(binding.get("version") or "v1.0")
        sha256 = str(binding.get("sha256") or "")
        key = (version, sha256)
        usage = {
            "run_id": run["run_id"],
            "business_date": run["business_date"],
            "status": _legacy_status(run.get("status")),
            "storage_type": "history" if run.get("status") == "sealed" else "worktree",
        }
        if key not in documents:
            raw_rules = policy.get("rules", []) if policy else []
            documents[key] = {
                "schema_version": "1.0",
                "version": version,
                "ordinal": 1,
                "mode": binding.get("mode") or (policy or {}).get("mode") or "legacy",
                "activation_mode": binding.get("activation_mode") or "scheduled",
                "created_at": binding.get("effective_at"),
                "effective_at": binding.get("effective_at"),
                "activated_at": binding.get("effective_at"),
                "note": "Dolphin 运行冻结的只读健康政策",
                "previous_sha256": None,
                "rules": [_policy_rule_projection(item) for item in raw_rules if isinstance(item, dict)],
                "scoring_config": _scoring_from_facts(facts),
                "inspection_schedule": copy.deepcopy(
                    (policy or {}).get("inspection_schedule") or {"time": "09:00"}
                ),
                "inspection_time": str(
                    ((policy or {}).get("inspection_schedule") or {}).get("time") or "09:00"
                ),
                "sha256": sha256,
                "status": "effective",
                "selected_for_next_run": False,
                "deletable": False,
                "delete_block_reason": "Dolphin 冻结政策仅供兼容工作台只读展示",
                "run_usage": [],
            }
        documents[key]["run_usage"].append(usage)
    result = list(documents.values())
    result.sort(key=lambda item: (str(item["effective_at"] or ""), str(item["version"])))
    for index, item in enumerate(result, start=1):
        item["ordinal"] = index
        item["run_usage_count"] = len(item["run_usage"])
    return result


def inspection_schedule_projection(
    service: WorkspaceService,
    policy_store: PolicyStore | None = None,
) -> dict[str, Any]:
    """Expose the policy clock while keeping automatic launch fail closed."""

    if policy_store is not None:
        overview = policy_store.overview()
        draft = overview["draft"]
        effective = overview.get("effective_version")
        active = None
        if isinstance(effective, Mapping):
            schedule = effective.get("inspection_schedule")
            schedule = schedule if isinstance(schedule, Mapping) else {}
            active = {
                "time": schedule.get("time"),
                "policy_version": effective.get("version"),
                "policy_sha256": effective.get("sha256"),
                "activation_mode": effective.get("activation_mode"),
                "effective_at": effective.get("effective_at"),
                "activated_at": effective.get("effective_at"),
            }
        draft_schedule = draft.get("inspection_schedule")
        draft_schedule = draft_schedule if isinstance(draft_schedule, Mapping) else {}
        pending = None
        active_time = active.get("time") if active else None
        if draft_schedule.get("time") != active_time:
            pending = {
                "time": draft_schedule.get("time"),
                "draft_revision": draft.get("draft_revision"),
                "base_version": draft.get("base_version"),
            }
        projection = {
            "schema_version": "1.0",
            "timezone": "Asia/Shanghai",
            "cadence": "daily",
            "activation_rule": "published_policy_version",
            "configured": bool(overview.get("published_version_count")),
            "status": "disabled",
            "etag": f'"inspection-schedule-draft-{draft["draft_revision"]}"',
            "active": active,
            "pending": pending,
            "next_trigger_at": None,
            "automatic_dispatch_enabled": False,
            "disabled_reason": "可信自动调度尚未接入；保存只更新统一政策草稿",
            "draft_revision": draft["draft_revision"],
        }
        return safe_public_projection(
            projection,
            allowed_keys=_PUBLIC_SCHEDULE_FIELDS,
            source="workbench_inspection_schedule",
        )

    documents = _policy_documents(service)
    current = documents[-1] if documents else None
    active = None
    if current:
        active = {
            "time": current["inspection_time"],
            "policy_version": current["version"],
            "policy_sha256": current["sha256"],
            "activation_mode": current["activation_mode"],
            "effective_at": current["effective_at"],
            "activated_at": current["activated_at"],
        }
    identity = f"{active.get('policy_version') if active else 'none'}-{active.get('time') if active else 'none'}"
    return _public(
        {
            "schema_version": "1.0",
            "timezone": "Asia/Shanghai",
            "cadence": "daily",
            "activation_rule": "deployment_gateway_required",
            "configured": False,
            "status": "disabled",
            "etag": f'"inspection-schedule-read-only-{identity}"',
            "active": active,
            "pending": None,
            "next_trigger_at": None,
            "automatic_dispatch_enabled": False,
            "disabled_reason": "可信 Dolphin Gateway 尚未配置，自动调度保持 fail closed",
        }
    )


def health_policy_projection(
    service: WorkspaceService,
    run_id: str | None = None,
    policy_store: PolicyStore | None = None,
) -> dict[str, Any]:
    """Return editable policy facts plus one verified frozen run context."""

    if policy_store is not None:
        overview = policy_store.overview()
        selected = _run(service, run_id) if run_id else _latest_run(service)
        facts = _json_artifact(service, selected, "data_layer_facts") if selected else None
        frozen = (
            _json_artifact(service, selected, "data_layer_health_policy")
            if selected
            else None
        )
        selected_run = None
        metric_context: dict[str, Any] = {}
        if selected and facts:
            binding, frozen = _policy_binding(service, selected, facts=facts)
            selected_run = {
                "run_id": selected["run_id"],
                "business_date": selected["business_date"],
                "status": _legacy_status(selected.get("status")),
                **binding,
            }
            for item in facts.get("metrics", []):
                if isinstance(item, dict) and item.get("id"):
                    metric_context[str(item["id"])] = {
                        key: copy.deepcopy(item.get(key))
                        for key in (
                            "value",
                            "baseline",
                            "baseline_value",
                            "history",
                            "source",
                            "status",
                            "health_band",
                            "evaluation_status",
                            "trend",
                            "value_provenance",
                        )
                    }
        projection = {
            key: copy.deepcopy(overview[key])
            for key in _PUBLIC_POLICY_OVERVIEW_FIELDS
            if key in overview
        }
        projection["draft"] = policy_draft_projection(overview["draft"])
        projection["metric_catalog"] = [
            _policy_rule_projection(item)
            for item in overview.get("metric_catalog", [])
            if isinstance(item, Mapping)
        ]
        if isinstance(overview.get("effective_version"), Mapping):
            projection["effective_version"] = policy_version_projection(
                overview["effective_version"]
            )
        if isinstance(overview.get("launch_selection"), Mapping):
            projection["launch_selection"] = policy_selection_projection(
                overview["launch_selection"]
            )
        projection.update(
            {
                "selected_run": selected_run,
                "metric_context": metric_context,
                "frozen_policy": (
                    policy_version_projection(frozen)
                    if isinstance(frozen, Mapping)
                    else None
                ),
                "read_only": False,
                "write_operations": "server_owned_policy_only",
            }
        )
        return safe_public_projection(
            projection,
            allowed_keys=_PUBLIC_POLICY_OVERVIEW_FIELDS,
            source="workbench_health_policy",
        )

    selected = _run(service, run_id) if run_id else _latest_run(service)
    documents = _policy_documents(service)
    current = documents[-1] if documents else None
    facts = _json_artifact(service, selected, "data_layer_facts") if selected else None
    policy = _json_artifact(service, selected, "data_layer_health_policy") if selected else None
    rules = (
        [_policy_rule_projection(item) for item in policy.get("rules", []) if isinstance(item, dict)]
        if policy
        else []
    )
    scoring = _scoring_from_facts(facts or {})
    schedule = copy.deepcopy((policy or {}).get("inspection_schedule") or {"time": "09:00"})
    version = str((current or {}).get("version") or "v1.0")
    draft = {
        "schema_version": "1.0",
        "draft_revision": 1,
        "base_version": version,
        "rules": rules,
        "scoring_config": scoring,
        "inspection_schedule": schedule,
        "read_only": True,
    }
    metric_catalog = [
        {
            "metric_id": item.get("metric_id"),
            "position": item.get("position"),
            "dimension": item.get("dimension"),
            "name": item.get("name"),
            "description": item.get("description"),
            "frequency": item.get("frequency"),
            "format": item.get("format"),
            "precision": item.get("precision", 0),
            "favorable": item.get("favorable", "stable"),
        }
        for item in rules
    ]
    selected_run = None
    metric_context: dict[str, Any] = {}
    if selected and facts:
        binding, frozen = _policy_binding(service, selected, facts=facts)
        selected_run = {
            "run_id": selected["run_id"],
            "business_date": selected["business_date"],
            "status": _legacy_status(selected.get("status")),
            **binding,
        }
        for item in facts.get("metrics", []):
            if isinstance(item, dict) and item.get("id"):
                metric_context[str(item["id"])] = {
                    key: copy.deepcopy(item.get(key))
                    for key in (
                        "value",
                        "baseline",
                        "baseline_value",
                        "history",
                        "source",
                        "status",
                        "health_band",
                        "evaluation_status",
                        "trend",
                        "value_provenance",
                    )
                }
    return _public(
        {
            "schema_version": "1.0",
            "draft": draft,
            "draft_etag": '"draft-1"',
            "metric_catalog": metric_catalog,
            "draft_changes": [],
            "draft_scoring_changes": [],
            "draft_schedule_change": None,
            "draft_change_count": 0,
            "published_version_count": len(documents),
            "effective_version": current,
            "next_version": _next_version(version),
            "launch_selection": None,
            "selected_run": selected_run,
            "metric_context": metric_context,
            "frozen_policy": current,
            "read_only": True,
            "write_operations": "fail_closed",
        }
    )


def health_policy_versions(
    service: WorkspaceService,
    query: Mapping[str, Any] | None = None,
    policy_store: PolicyStore | None = None,
) -> dict[str, Any]:
    """Return the immutable version list with verified workspace usage."""

    _strict_query(query, allowed=frozenset({"status", "keyword"}))
    status = _query_value(query, "status")
    keyword = (_query_value(query, "keyword") or "").strip().casefold()
    if policy_store is not None:
        usage = _policy_run_usage(service)
        versions = policy_store.list_versions(
            status,
            keyword,
            in_use_versions=usage,
        )
        return safe_public_projection(
            {
                "versions": [
                    policy_version_projection(item)
                    for item in versions
                ]
            },
            allowed_keys=frozenset({"versions"}),
            source="workbench_policy_versions",
        )
    versions = _policy_documents(service)
    if status:
        versions = [item for item in versions if item.get("status") == status]
    if keyword:
        versions = [
            item
            for item in versions
            if keyword in str(item.get("version") or "").casefold()
            or keyword in str(item.get("note") or "").casefold()
        ]
    return _public({"versions": versions})


def health_policy_version_detail(
    service: WorkspaceService,
    version: str,
    policy_store: PolicyStore | None = None,
) -> dict[str, Any]:
    """Return one immutable version, deterministic diffs and run usage."""

    if _POLICY_VERSION_RE.fullmatch(version) is None:
        raise WorkspaceAPIError(404, "policy_version_not_found", "health policy version does not exist")
    if policy_store is not None:
        usage_bindings = _policy_run_usage(service)
        detail = policy_store.version_detail(version)
        version_view = next(
            (
                item
                for item in policy_store.list_versions(in_use_versions=usage_bindings)
                if item.get("version") == version
            ),
            None,
        )
        if version_view is None:
            raise WorkspaceAPIError(
                404,
                "policy_version_not_found",
                "health policy version does not exist",
            )
        usage = (
            version_view.get("run_usage")
            if isinstance(version_view.get("run_usage"), list)
            else []
        )
        conflicts = (
            version_view.get("identity_conflicts")
            if isinstance(version_view.get("identity_conflicts"), list)
            else []
        )
        projection = {
            key: copy.deepcopy(detail[key])
            for key in _PUBLIC_POLICY_DETAIL_FIELDS
            if key in detail
        }
        projection["version"] = policy_version_projection({**detail["version"], **version_view})
        projection["rules"] = _policy_rules_projection(detail.get("rules"))
        projection["run_usage"] = [
            safe_public_projection(
                {key: item[key] for key in _PUBLIC_POLICY_USAGE_FIELDS if key in item},
                allowed_keys=_PUBLIC_POLICY_USAGE_FIELDS,
                source="workbench_policy_run_usage",
            )
            for item in usage
        ]
        projection["run_usage_count"] = len(usage)
        projection["identity_conflicts"] = [
            safe_public_projection(
                {key: item[key] for key in _PUBLIC_POLICY_USAGE_FIELDS if key in item},
                allowed_keys=_PUBLIC_POLICY_USAGE_FIELDS,
                source="workbench_policy_identity_conflict",
            )
            for item in conflicts
            if isinstance(item, Mapping)
        ]
        projection["identity_conflict_count"] = len(projection["identity_conflicts"])
        projection["deletable"] = bool(version_view.get("deletable"))
        projection["delete_block_reason"] = version_view.get("delete_block_reason")
        return safe_public_projection(
            projection,
            allowed_keys=_PUBLIC_POLICY_DETAIL_FIELDS,
            source="workbench_policy_version_detail",
        )
    documents = _policy_documents(service)
    selected = next((item for item in documents if item.get("version") == version), None)
    if selected is None:
        raise WorkspaceAPIError(404, "policy_version_not_found", "health policy version does not exist")
    return _public(
        {
            **selected,
            "version_document": selected,
            "changes": [],
            "scoring_changes": [],
            "schedule_change": None,
            "read_only": True,
        }
    )


__all__ = [
    "config_projection",
    "health_policy_projection",
    "health_policy_version_detail",
    "health_policy_versions",
    "heatmap",
    "inspection_schedule_projection",
    "policy_delete_projection",
    "policy_draft_projection",
    "policy_in_use_versions",
    "policy_selection_projection",
    "policy_version_projection",
    "run_log",
    "runs_page",
    "snapshot",
]
