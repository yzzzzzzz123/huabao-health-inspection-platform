"""Build immutable taskbooks and bounded Stage packets in memory."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from shared.audit import sha256_json  # noqa: E402
from shared.models import FIXED_SCOPE, METRIC_COVERAGE, STAGE_BY_KEY  # noqa: E402
from policy_store import policy_runtime_gate_projection  # noqa: E402
from validator import collect_evidence_refs, validate_document  # noqa: E402


OBJECTIVES = {
    "inspector": "聚类全部确定性异常并严格分区，给出调查优先级。",
    "diagnostician": "为每个异常 case 检验竞争性假设并给出有证据边界的诊断。",
    "advisor": "把诊断转化为仅核查或人工调整建议，闭合指标与验收口径。",
    "auditor": "审核全部建议的逻辑链，并解释当日精确到期的异常回看。",
    "reporter": "形成管理优先级、正式建议、待补证项和固定投递请求。",
}

CONSTRAINTS = {
    "inspector": [
        "不得重算指标、健康分或确定性异常。",
        "cases[].anomaly_ids 必须严格分区全部异常且每个异常只出现一次。",
        "必须通过 case_anomaly_partition_contract 自测。",
    ],
    "diagnostician": [
        "每个 Inspector case 恰好对应一个 diagnosis。",
        "至少提出两个竞争性假设；证据不足时保留不确定性。",
        "不得把相关性直接写成因果。",
    ],
    "advisor": [
        "action_type 只能是 review_only 或 manual_adjustment。",
        "review_only 不得包含调整字段。",
        "manual_adjustment 必须闭合异常、诊断、指标、内容、方向和验收标准。",
    ],
    "auditor": [
        "logic_reviews 必须覆盖全部建议。",
        "effect_reviews 只覆盖 packet 中精确到期的确定性投影。",
        "回看变化不得直接宣称因果。",
    ],
    "reporter": [
        "只能把审核支持的建议列为正式建议。",
        "effect_reviews 必须逐字节语义等值于 Auditor 结果。",
        "delivery_request 固定为自动完成态钉钉投递并通过同名自测。",
    ],
}


def build_daily_taskbook(
    *,
    binding: dict[str, Any],
    policy: dict[str, Any],
) -> str:
    release = binding["platform_release"]
    return (
        "# 华宝新能每日健康巡检任务书\n\n"
        f"- run_id: {binding['run_id']}\n"
        f"- business_date: {binding['business_date']}\n"
        f"- incarnation_id: {binding['incarnation_id']}\n"
        f"- platform_release_sha256: {binding['platform_release_sha256']}\n"
        f"- release_version: {release['release_version']}\n"
        f"- workflow_version: {release['workflow_version']}\n"
        f"- health_policy: {policy['version']} / {policy['sha256']}\n\n"
        "固定范围：华宝新能站内、Asia/Shanghai、CNY，且只包含流量、"
        "转化、商品三个维度。\n\n"
        "总控按 Stage 0 到 Stage 5 的验收结果推进。所有工作区文件仅通过"
        " Workspace API 的 artifact ID 读写；模型不得访问服务器路径、"
        "Git、SQLite、通知凭据或网络投递能力。\n"
    )


def build_taskbook_manifest(
    *,
    binding: dict[str, Any],
    policy: dict[str, Any],
    daily_taskbook: str,
) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "run_id": binding["run_id"],
        "business_date": binding["business_date"],
        "incarnation_id": binding["incarnation_id"],
        "platform_release_sha256": binding["platform_release_sha256"],
        "platform_release": binding["platform_release"],
        "policy_sha256": policy["sha256"],
        "daily_taskbook_sha256": hashlib.sha256(
            daily_taskbook.encode("utf-8")
        ).hexdigest(),
    }


def build_data_operator_packet(
    *,
    run_id: str,
    business_date: str,
    policy: dict[str, Any],
    platform_release_sha256: str,
) -> dict[str, Any]:
    gate = policy_runtime_gate_projection(policy)
    packet = {
        "schema_version": "2.0",
        "run_id": run_id,
        "business_date": business_date,
        "stage": "data_operator",
        "scope": FIXED_SCOPE,
        "task": (
            "依次调度 data_layer、calculate、detect、validate，核验 37 项输出、"
            "规则覆盖与证据目录，不改写业务数字。"
        ),
        "connector_request": {
            "mode": "fixture_read_only",
            "business_date": business_date,
            "timezone": "Asia/Shanghai",
        },
        "expected_coverage": {
            "metric_count": METRIC_COVERAGE["total"],
            "frequency": METRIC_COVERAGE["frequency"],
            "dimension": METRIC_COVERAGE["dimension"],
            "evaluation": gate["evaluation"],
        },
        "command_plan": [
            {
                "order": 1,
                "command": "data_layer",
                "input": "frozen connector request",
                "output": "data_layer_source",
            },
            {
                "order": 2,
                "command": "calculate",
                "input": "data_layer_source + data_layer_health_policy",
                "output": "calculated projection",
            },
            {
                "order": 3,
                "command": "detect",
                "input": "calculated projection",
                "output": "data_layer_facts + data_layer_evidence_catalog",
            },
            {
                "order": 4,
                "command": "validate",
                "input": "all Stage 0 projections",
                "output": "data_layer_manifest",
            },
        ],
        "policy_summary": gate,
        "constraints": [
            "不得心算、补造或改写任何指标值。",
            "37 项顺序、维度覆盖、评估状态和显式规则必须通过确定性校验。",
            "完整证据正文只保存在 evidence catalog 一次。",
        ],
        "hashes": {
            "health_policy_sha256": policy["sha256"],
            "platform_release_sha256": platform_release_sha256,
        },
    }
    validate_document(packet, "data-operator-packet.schema.json")
    return packet


def _metric_projection(facts: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "id": item["id"],
            "name": item["name"],
            "dimension": item["dimension"],
            "value": item["value"],
            "baseline_value": item.get("baseline_value"),
            "status": item["status"],
            "evaluation_status": item["evaluation_status"],
            "format": item.get("format", "number"),
            "favorable": item.get("favorable", "stable"),
            "evidence_refs": item["evidence_refs"],
        }
        for item in facts["metrics"]
    ]


def _upstream_projection(
    stage: str,
    upstream: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    if stage == "inspector":
        return {}
    if stage == "diagnostician":
        return {"inspection": upstream["inspector"]}
    if stage == "advisor":
        return {"diagnosis": upstream["diagnostician"]}
    if stage == "auditor":
        return {
            "inspection": upstream["inspector"],
            "diagnosis": upstream["diagnostician"],
            "action_plan": upstream["advisor"],
        }
    return {
        "inspection": upstream["inspector"],
        "diagnosis": upstream["diagnostician"],
        "action_plan": upstream["advisor"],
        "audit": upstream["auditor"],
    }


def build_stage_packet(
    *,
    stage: str,
    facts: dict[str, Any],
    evidence_catalog: dict[str, Any],
    upstream: dict[str, dict[str, Any]],
    policy: dict[str, Any],
    due_effect_reviews: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    if stage not in STAGE_BY_KEY:
        raise ValueError(f"unsupported Stage: {stage}")
    evidence_index = [
        {
            "evidence_id": item["evidence_id"],
            "kind": item["kind"],
            "title": item["title"],
            "source": item["source"],
            "scope": item["scope"],
            "observed_at": item["observed_at"],
        }
        for item in evidence_catalog.get("evidence", [])
    ]
    facts_projection: dict[str, Any] = {
        "health": facts["health"],
        "data_provenance": facts["data_provenance"],
        "metrics": _metric_projection(facts),
        "anomalies": facts["anomalies"],
    }
    if stage == "auditor":
        facts_projection["due_effect_reviews"] = list(due_effect_reviews or [])
    upstream_projection = _upstream_projection(stage, upstream)
    referenced = collect_evidence_refs(
        {
            "facts": facts_projection,
            "upstream": upstream_projection,
        }
    )
    if referenced:
        evidence_index = [
            item for item in evidence_index if item["evidence_id"] in referenced
        ]
    packet = {
        "schema_version": "1.0",
        "run_id": facts["run_id"],
        "business_date": facts["business_date"],
        "stage": stage,
        "scope": facts["scope"],
        "task": OBJECTIVES[stage],
        "facts_projection": facts_projection,
        "upstream_projection": upstream_projection,
        "evidence_index": evidence_index,
        "policy_summary": policy_runtime_gate_projection(policy),
        "constraints": CONSTRAINTS[stage],
        "hashes": {
            "facts_sha256": sha256_json(facts),
            "evidence_catalog_sha256": sha256_json(evidence_catalog),
            "health_policy_sha256": policy["sha256"],
            "upstream_projection_sha256": sha256_json(upstream_projection),
        },
    }
    validate_document(packet, "packet.schema.json")
    return packet


def build_child_taskbook(stage: str, packet: dict[str, Any]) -> str:
    spec = STAGE_BY_KEY[stage]
    constraints = "\n".join(f"- {item}" for item in packet["constraints"])
    return (
        f"# {spec['agent']} 任务书\n\n"
        f"运行：{packet['run_id']} / {packet['business_date']}\n\n"
        f"目标：{packet['task']}\n\n"
        "## 强制边界\n\n"
        f"{constraints}\n\n"
        "只输出一个 JSON envelope，顶层必须严格包含 business 与 "
        "intelligence。不得访问 Workspace API、服务器路径或其他 Stage 的"
        "原始响应。\n"
    )


def packet_summary(packet: dict[str, Any]) -> dict[str, Any]:
    return {
        "run_id": packet["run_id"],
        "business_date": packet["business_date"],
        "stage": packet["stage"],
        "anomaly_count": len(packet["facts_projection"].get("anomalies", [])),
        "evidence_count": len(packet["evidence_index"]),
        "packet_sha256": sha256_json(packet),
    }


__all__ = [
    "build_child_taskbook",
    "build_daily_taskbook",
    "build_data_operator_packet",
    "build_stage_packet",
    "build_taskbook_manifest",
    "packet_summary",
]
