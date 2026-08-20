"""Dolphin Agent response adapter plus a deterministic local fixture backend."""

from __future__ import annotations

import json
import re
import sys
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol


SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from shared.audit import sha256_json, utc_now  # noqa: E402
from shared.models import STAGE_BY_KEY  # noqa: E402
from validator import validate_envelope  # noqa: E402


class AgentRunnerError(RuntimeError):
    """A hosted response is missing, malformed, or fails a Stage gate."""


class HostedResponseRequired(AgentRunnerError):
    """Production mode needs a Dolphin-hosted response for this Stage."""


class AgentRunFailure(AgentRunnerError):
    """Preserve the request and raw hosted response when validation fails."""

    def __init__(
        self,
        message: str,
        *,
        request: dict[str, Any],
        raw_response: Any,
    ) -> None:
        super().__init__(message)
        self.request = request
        self.raw_response = raw_response


class AgentBackend(Protocol):
    name: str

    def complete(
        self,
        *,
        stage: str,
        request: dict[str, Any],
    ) -> Any:
        """Return the platform response or one strict Stage envelope."""


@dataclass(frozen=True)
class AgentRunResult:
    stage: str
    backend: str
    request: dict[str, Any]
    raw_response: Any
    envelope: dict[str, Any]
    request_sha256: str
    response_sha256: str
    completed_at: str
    controlled_bindings: dict[str, Any]

    def attempt_projection(self, *, attempt: int) -> dict[str, Any]:
        projection = {
            "schema_version": "1.0",
            "stage": self.stage,
            "agent": STAGE_BY_KEY[self.stage]["agent"],
            "attempt": attempt,
            "backend": self.backend,
            "status": "completed",
            "request_sha256": self.request_sha256,
            "response_sha256": self.response_sha256,
            "completed_at": self.completed_at,
            "self_test": deepcopy(self.envelope["intelligence"]["self_test"]),
        }
        if self.controlled_bindings:
            projection["controlled_bindings"] = deepcopy(
                self.controlled_bindings
            )
        return projection


def normalize_hosted_response(response: Any) -> dict[str, Any]:
    value = response
    if isinstance(value, dict) and set(value) == {"business", "intelligence"}:
        return value
    if isinstance(value, dict):
        for key in ("output", "response", "text"):
            if key in value:
                value = value[key]
                break
        else:
            content = value.get("content")
            if isinstance(content, list):
                text_blocks = [
                    str(item.get("text"))
                    for item in content
                    if isinstance(item, dict)
                    and item.get("type") in {"text", "output_text"}
                    and isinstance(item.get("text"), str)
                ]
                if len(text_blocks) == 1:
                    value = text_blocks[0]
    if isinstance(value, str):
        text = value.strip()
        fenced = re.fullmatch(
            r"\x60{3}(?:json)?\s*(.*?)\s*\x60{3}",
            text,
            re.DOTALL,
        )
        if fenced is not None:
            text = fenced.group(1)
        try:
            value = json.loads(text)
        except json.JSONDecodeError as exc:
            raise AgentRunnerError("Dolphin response is not valid JSON") from exc
    if not isinstance(value, dict) or set(value) != {"business", "intelligence"}:
        raise AgentRunnerError(
            "Dolphin response must resolve to a strict business/intelligence envelope"
        )
    return value


class DolphinHostedBackend:
    """Accept responses already produced by Dolphin managed Agent nodes."""

    name = "dolphin"

    def __init__(self, responses: dict[str, Any] | None = None) -> None:
        self.responses = dict(responses or {})

    def complete(self, *, stage: str, request: dict[str, Any]) -> Any:
        del request
        if stage not in self.responses:
            raise HostedResponseRequired(
                f"Dolphin hosted response is required for Stage {stage}"
            )
        return self.responses[stage]


def _decision(
    *,
    stage: str,
    selected: str,
    evidence_refs: list[str],
    confidence: float = 0.8,
) -> dict[str, Any]:
    return {
        "decision_id": f"DEC-{stage.upper()}-001",
        "decision_type": "stage_conclusion",
        "question": f"{stage} 应如何处理本阶段已验证输入？",
        "selected": selected,
        "alternatives_considered": ["保留不确定性并移交人工复核"],
        "evidence_refs": evidence_refs,
        "rationale": "结论仅使用 packet 中的确定性事实与已验证上游投影。",
        "confidence": confidence,
        "uncertainty": "冻结演示数据不能替代真实生产数据。",
        "human_handoff": "业务人员仅需复核建议，不由系统自动执行。",
    }


def _intelligence(
    *,
    stage: str,
    summary: str,
    evidence_refs: list[str],
    extra_checks: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    checks = [
        {
            "name": "identity_contract",
            "status": "passed",
            "summary": "运行、日期、Stage 与 Agent 身份一致。",
        },
        {
            "name": "evidence_reference_contract",
            "status": "passed",
            "summary": "仅引用 packet 索引内证据。",
        },
        {
            "name": "scope_contract",
            "status": "passed",
            "summary": "固定站内三维范围未扩张。",
        },
        *(extra_checks or []),
    ]
    return {
        "agent": STAGE_BY_KEY[stage]["agent"],
        "stage": stage,
        "analysis_summary": summary,
        "self_test": {
            "status": "passed",
            "checks": checks,
            "unresolved_issues": [],
        },
        "decisions": [
            _decision(
                stage=stage,
                selected=summary,
                evidence_refs=evidence_refs[:8],
            )
        ],
        "evidence_assessments": [
            {
                "evidence_id": evidence_id,
                "assessment": "与本阶段结论直接相关，保留来源边界。",
                "reliability": "high",
            }
            for evidence_id in evidence_refs[:8]
        ],
        "confidence_updates": [],
        "human_handoffs": [],
    }


def _evidence_union(items: list[dict[str, Any]]) -> list[str]:
    result: list[str] = []
    for item in items:
        for evidence_id in item.get("evidence_refs", []):
            if evidence_id not in result:
                result.append(str(evidence_id))
    return result


def _fixture_inspector(request: dict[str, Any]) -> dict[str, Any]:
    packet = request["packet"]
    facts = packet["facts_projection"]
    anomalies = list(facts["anomalies"])
    by_dimension: dict[str, list[dict[str, Any]]] = {
        "traffic": [],
        "conversion": [],
        "product": [],
    }
    for anomaly in anomalies:
        by_dimension[str(anomaly["dimension"])].append(anomaly)
    ranked: list[dict[str, Any]] = []
    cases: list[dict[str, Any]] = []
    rank = 1
    for dimension in ("traffic", "conversion", "product"):
        group = by_dimension[dimension]
        if not group:
            continue
        cluster_id = f"CL-{dimension.upper()}-001"
        for anomaly in group:
            ranked.append(
                {
                    "rank": rank,
                    "anomaly_id": anomaly["anomaly_id"],
                    "dimension": dimension,
                    "severity": "P0",
                    "summary": anomaly["summary"],
                    "confidence": 0.92,
                    "evidence_refs": list(anomaly["evidence_refs"]),
                    "cluster_id": cluster_id,
                }
            )
            rank += 1
        cases.append(
            {
                "case_id": f"CASE-{dimension.upper()}-001",
                "cluster_id": cluster_id,
                "title": f"{dimension} 维度异常调查",
                "anomaly_ids": [item["anomaly_id"] for item in group],
                "priority": "P0",
                "investigation_worthy": True,
                "diagnosis_questions": [
                    "异常是否由单一来源变化解释？",
                    "现有证据是否排除了采集或同步偏差？",
                ],
                "evidence_refs": _evidence_union(group),
                "data_gaps": ["真实生产接口尚未接入，需复核冻结输入代表性。"],
            }
        )
    components = facts["health"]["components"]
    business = {
        "schema_version": "1.0",
        "run_id": packet["run_id"],
        "business_date": packet["business_date"],
        "stage": "inspector",
        "status": "completed",
        "summary": f"严格分区 {len(anomalies)} 个确定性异常，形成 {len(cases)} 个 case。",
        "dimension_summary": [
            {
                "dimension": item["dimension"],
                "score": item["score"],
                "status": item["assessment_status"],
                "assessment": (
                    f"该维度含 {item['triggered_count']} 个 P0 确定性异常。"
                ),
            }
            for item in components
        ],
        "ranked_anomalies": ranked,
        "cases": cases,
        "dismissed_anomaly_ids": [],
    }
    refs = _evidence_union(anomalies)
    intelligence = _intelligence(
        stage="inspector",
        summary="全部确定性异常已严格分区并排序。",
        evidence_refs=refs,
        extra_checks=[
            {
                "name": "case_anomaly_partition_contract",
                "status": "passed",
                "summary": "总引用数、唯一引用数与确定性异常数完全一致。",
            }
        ],
    )
    return {"business": business, "intelligence": intelligence}


def _fixture_diagnostician(request: dict[str, Any]) -> dict[str, Any]:
    packet = request["packet"]
    inspection = packet["upstream_projection"]["inspection"]
    diagnoses: list[dict[str, Any]] = []
    for index, case in enumerate(inspection["cases"], start=1):
        refs = list(case["evidence_refs"])
        diagnosis_id = f"DIAG-{index:03d}"
        diagnoses.append(
            {
                "diagnosis_id": diagnosis_id,
                "case_id": case["case_id"],
                "anomaly_id": case["anomaly_ids"][0],
                "anomaly_ids": list(case["anomaly_ids"]),
                "conclusion_summary": "现有证据支持业务状态变化，但仍需排除采集偏差。",
                "root_cause": "最可信解释为指标对应业务链路发生同步或表现偏移。",
                "confidence": 0.72,
                "hypotheses": [
                    {
                        "hypothesis_id": f"HYP-{index:03d}-A",
                        "statement": "业务链路状态变化是主要解释。",
                        "status": "supported",
                        "confidence": 0.72,
                        "evidence_refs": refs,
                        "reason": "指标快照与相关证据方向一致。",
                    },
                    {
                        "hypothesis_id": f"HYP-{index:03d}-B",
                        "statement": "采集或同步偏差完全解释了异常。",
                        "status": "weakened",
                        "confidence": 0.28,
                        "evidence_refs": refs,
                        "reason": "当前存在交叉来源证据，但冻结输入仍不能完全排除偏差。",
                    },
                ],
                "confirmed_facts": [
                    {
                        "statement": "对应异常由确定性规则触发。",
                        "evidence_refs": refs,
                    }
                ],
                "contradictions": [],
                "data_gaps": ["需要生产系统复核同一观察窗口。"],
                "evidence_refs": refs,
            }
        )
    refs = _evidence_union(diagnoses)
    business = {
        "schema_version": "1.0",
        "run_id": packet["run_id"],
        "business_date": packet["business_date"],
        "stage": "diagnostician",
        "status": "completed",
        "summary": f"完成 {len(diagnoses)} 个 case 的竞争假设检验。",
        "diagnoses": diagnoses,
    }
    return {
        "business": business,
        "intelligence": _intelligence(
            stage="diagnostician",
            summary="每个 case 均保留竞争假设与证据边界。",
            evidence_refs=refs,
        ),
    }


def _owner(dimension: str) -> str:
    return {
        "traffic": "站内运营",
        "conversion": "转化运营",
        "product": "商品运营",
    }.get(dimension, "站内运营")


def _fixture_advisor(request: dict[str, Any]) -> dict[str, Any]:
    packet = request["packet"]
    diagnoses = packet["upstream_projection"]["diagnosis"]["diagnoses"]
    anomalies = {
        item["anomaly_id"]: item
        for item in packet["facts_projection"]["anomalies"]
    }
    metrics = {
        item["id"]: item for item in packet["facts_projection"]["metrics"]
    }
    actions: list[dict[str, Any]] = []
    for index, diagnosis in enumerate(diagnoses, start=1):
        anomaly_ids = list(diagnosis["anomaly_ids"])
        target_ids = list(dict.fromkeys(anomaly_ids))
        dimension = anomalies[anomaly_ids[0]]["dimension"]
        manual = len(diagnoses) > 1 and index % 2 == 0
        action: dict[str, Any] = {
            "action_id": f"ACT-{index:03d}",
            "diagnosis_id": diagnosis["diagnosis_id"],
            "anomaly_ids": anomaly_ids,
            "target_metric_ids": target_ids,
            "title": (
                f"人工校正 {target_ids[0]} 对应配置"
                if manual
                else f"复核 {target_ids[0]} 数据与业务状态"
            ),
            "action_type": "manual_adjustment" if manual else "review_only",
            "description": (
                "由责任人核对证据后执行可逆的小范围人工配置调整。"
                if manual
                else "核对同窗口生产数据、采集状态与业务记录，不执行自动调整。"
            ),
            "owner": _owner(str(dimension)),
            "collaborators": ["数据支持"],
            "priority": "P0",
            "expected_benefit": "缩小异常原因范围并形成可验证的下一步。",
            "dependencies": ["业务人员确认生产数据"],
            "time_window": "下一个业务日复核，并在第 7 日观察持续性。",
            "reversible": True,
            "acceptance_criteria": [
                f"{target_ids[0]} 的同口径生产数据完成复核并记录结论。"
            ],
            "evidence_refs": list(diagnosis["evidence_refs"]),
        }
        if manual:
            improvements = []
            for metric_id in target_ids:
                favorable = str(metrics[metric_id].get("favorable") or "stable")
                direction = {
                    "higher": "increase",
                    "lower": "decrease",
                    "stable": "stabilize",
                }.get(favorable, "stabilize")
                improvements.append(
                    {
                        "metric_id": metric_id,
                        "direction": direction,
                        "description": f"{metric_id} 朝健康方向变化。",
                    }
                )
            action.update(
                {
                    "adjustment_content": (
                        "只在人工确认后修改对应业务配置；保留变更前值以便回退。"
                    ),
                    "expected_improvement": improvements,
                    "observation_metrics": {
                        "next_day": target_ids,
                        "day_7": target_ids,
                    },
                }
            )
        actions.append(action)
    refs = _evidence_union(actions)
    business = {
        "schema_version": "2.0",
        "run_id": packet["run_id"],
        "business_date": packet["business_date"],
        "stage": "advisor",
        "status": "completed",
        "summary": f"形成 {len(actions)} 条仅核查或人工调整建议。",
        "actions": actions,
        "not_recommended": [
            {
                "proposal": "由系统自动修改业务配置",
                "reason": "超出只建议、不执行的安全边界。",
                "alternative": "由责任人在复核证据后手工执行可逆调整。",
            }
        ],
    }
    return {
        "business": business,
        "intelligence": _intelligence(
            stage="advisor",
            summary="建议类型与字段边界已闭合。",
            evidence_refs=refs,
        ),
    }


def _fixture_auditor(request: dict[str, Any]) -> dict[str, Any]:
    packet = request["packet"]
    actions = packet["upstream_projection"]["action_plan"]["actions"]
    reviews: list[dict[str, Any]] = []
    for index, action in enumerate(actions, start=1):
        reviews.append(
            {
                "review_id": f"REV-{index:03d}",
                "action_id": action["action_id"],
                "diagnosis_id": action["diagnosis_id"],
                "anomaly_ids": list(action["anomaly_ids"]),
                "target_metric_ids": list(action["target_metric_ids"]),
                "verdict": (
                    "supported"
                    if action["action_type"] == "review_only"
                    else "supported_with_caveats"
                ),
                "anomaly_support": "确定性异常与证据引用存在。",
                "diagnosis_explanation": "诊断保留了竞争假设和不确定性。",
                "causality_assessment": "只能说明相关变化，不能直接宣称因果。",
                "recommendation_alignment": "建议与诊断及指标方向闭合。",
                "id_closure": "异常、诊断、建议和指标 ID 一致。",
                "manual_adjustment_assessment": (
                    "不适用，建议仅核查。"
                    if action["action_type"] == "review_only"
                    else "调整为人工、可逆且含验收标准。"
                ),
                "rationale": "逻辑链完整，执行仍受人工确认约束。",
                "caveats": ["冻结演示输入不等同于生产数据。"],
                "evidence_refs": list(action["evidence_refs"]),
            }
        )
    due = packet["facts_projection"].get("due_effect_reviews", [])
    effect_reviews: list[dict[str, Any]] = []
    for projection in due:
        review = dict(projection)
        review.setdefault("conclusion", "insufficient_data")
        review.setdefault("sustained_assessment", "当前窗口不足以判断持续性。")
        review.setdefault("data_sufficiency", "仅使用确定性回看投影。")
        review.setdefault("interpretation", "观察到的是回看期变化。")
        review.setdefault(
            "attribution_limit",
            "该结论仅描述回看期变化，不能直接宣称因果。",
        )
        effect_reviews.append(review)
    refs = _evidence_union(reviews)
    business = {
        "schema_version": "2.0",
        "run_id": packet["run_id"],
        "business_date": packet["business_date"],
        "stage": "auditor",
        "status": "completed",
        "summary": f"审核 {len(reviews)} 条建议并解释 {len(effect_reviews)} 条到期回看。",
        "logic_reviews": reviews,
        "effect_reviews": effect_reviews,
        "contradictions": [],
    }
    return {
        "business": business,
        "intelligence": _intelligence(
            stage="auditor",
            summary="建议逻辑链已完整覆盖，回看不作因果归因。",
            evidence_refs=refs,
        ),
    }


def _fixture_reporter(request: dict[str, Any]) -> dict[str, Any]:
    packet = request["packet"]
    upstream = packet["upstream_projection"]
    facts = packet["facts_projection"]
    inspection = upstream["inspection"]
    diagnosis = upstream["diagnosis"]
    action_plan = upstream["action_plan"]
    audit = upstream["audit"]
    diagnoses_by_anomaly: dict[str, dict[str, Any]] = {}
    for item in diagnosis["diagnoses"]:
        for anomaly_id in item["anomaly_ids"]:
            diagnoses_by_anomaly[anomaly_id] = item
    anomaly_by_id = {
        item["anomaly_id"]: item for item in inspection["ranked_anomalies"]
    }
    action_by_id = {
        item["action_id"]: item for item in action_plan["actions"]
    }
    review_by_id = {
        item["action_id"]: item for item in audit["logic_reviews"]
    }
    recommended: list[dict[str, Any]] = []
    unsupported: list[dict[str, Any]] = []
    for action_id, action in action_by_id.items():
        review = review_by_id[action_id]
        if review["verdict"] in {"supported", "supported_with_caveats"}:
            item = {
                "action_id": action_id,
                "title": action["title"],
                "action_type": action["action_type"],
                "owner": action["owner"],
                "priority": action["priority"],
                "audit_verdict": review["verdict"],
                "implementation_status": (
                    "not_applicable"
                    if action["action_type"] == "review_only"
                    else "manual_execution"
                ),
                "target_metric_ids": list(action["target_metric_ids"]),
                "acceptance_criteria": list(action["acceptance_criteria"]),
            }
            if action["action_type"] == "manual_adjustment":
                item["adjustment_content"] = action["adjustment_content"]
            recommended.append(item)
        else:
            unsupported.append(
                {
                    "action_id": action_id,
                    "title": action["title"],
                    "audit_verdict": "unsupported",
                    "reason": review["rationale"],
                    "needed_evidence": list(review["caveats"]),
                }
            )
    health = facts["health"]
    assessment = health["assessment"]
    priorities = []
    for rank, action in enumerate(recommended, start=1):
        source = action_by_id[action["action_id"]]
        priorities.append(
            {
                "rank": rank,
                "title": action["title"],
                "why_now": "对应 P0 异常已完成诊断与审核。",
                "related_ids": [
                    source["anomaly_ids"][0],
                    source["diagnosis_id"],
                    source["action_id"],
                ],
                "owner": action["owner"],
                "decision_needed": "确认按建议复核或人工执行，并记录业务备注。",
            }
        )
    key_anomalies = []
    for anomaly_id, anomaly in anomaly_by_id.items():
        diagnosed = diagnoses_by_anomaly[anomaly_id]
        key_anomalies.append(
            {
                "anomaly_id": anomaly_id,
                "summary": anomaly["summary"],
                "diagnosis": diagnosed["conclusion_summary"],
                "evidence_refs": list(anomaly["evidence_refs"]),
            }
        )
    business = {
        "schema_version": "3.0",
        "run_id": packet["run_id"],
        "business_date": packet["business_date"],
        "stage": "reporter",
        "status": "completed",
        "headline": f"站内健康巡检完成：总分 {health['score']}。",
        "executive_summary": (
            f"三维评分已完成，识别 {len(key_anomalies)} 个 P0 异常，"
            f"形成 {len(recommended)} 条经审核建议。数据来源仍为冻结演示输入。"
        ),
        "data_provenance": facts["data_provenance"],
        "health_score": health["score"],
        "health_assessment": {
            "band": health["band"],
            "rated_band": health["rated_band"],
            "provisional": health["provisional"],
            "scoring_status": health["scoring"]["status"],
            "scoring_source": health["scoring"]["source"],
            "scoring_confirmed": health["scoring"]["confirmed"],
            **assessment,
        },
        "management_priorities": priorities,
        "key_anomalies": key_anomalies,
        "recommended_actions": recommended,
        "unsupported_actions": unsupported,
        "effect_reviews": [],
        "decision_bottleneck": (
            "需业务责任人确认生产数据复核与人工执行安排。"
            if priorities
            else "本期无待决建议。"
        ),
        "delivery_request": {
            "channel": "dingtalk_custom_robot",
            "mode": "automatic_after_finalize",
            "send": True,
        },
    }
    refs = _evidence_union(key_anomalies)
    intelligence = _intelligence(
        stage="reporter",
        summary="管理优先级已闭合，固定投递请求已声明。",
        evidence_refs=refs,
        extra_checks=[
            {
                "name": "delivery_request_contract",
                "status": "passed",
                "summary": "固定三字段与受控投递合同严格等值。",
            }
        ],
    )
    return {"business": business, "intelligence": intelligence}


FIXTURE_BUILDERS = {
    "inspector": _fixture_inspector,
    "diagnostician": _fixture_diagnostician,
    "advisor": _fixture_advisor,
    "auditor": _fixture_auditor,
    "reporter": _fixture_reporter,
}


class FixtureBackend:
    """Deterministic local-only backend used to exercise the full contract."""

    name = "fixture"

    def complete(self, *, stage: str, request: dict[str, Any]) -> Any:
        try:
            builder = FIXTURE_BUILDERS[stage]
        except KeyError as exc:
            raise AgentRunnerError(f"fixture does not support Stage {stage}") from exc
        return builder(request)


def run_agent(
    *,
    stage: str,
    backend: AgentBackend,
    taskbook: str,
    packet: dict[str, Any],
    facts: dict[str, Any],
    evidence_catalog: dict[str, Any],
    upstream: dict[str, dict[str, Any]],
) -> AgentRunResult:
    if stage not in STAGE_BY_KEY:
        raise AgentRunnerError(f"unsupported Stage: {stage}")
    request = build_agent_request(
        stage=stage,
        taskbook=taskbook,
        packet=packet,
    )
    raw_response: Any = None
    controlled_bindings: dict[str, Any] = {}
    try:
        raw_response = backend.complete(stage=stage, request=request)
        envelope = normalize_hosted_response(raw_response)
        if stage == "reporter":
            raw_slot = envelope.get("business", {}).get("effect_reviews")
            if raw_slot != []:
                raise AgentRunnerError(
                    "Reporter must submit an empty effect_reviews binding slot"
                )
            audit = upstream.get("auditor")
            if not isinstance(audit, dict) or not isinstance(
                audit.get("effect_reviews"), list
            ):
                raise AgentRunnerError(
                    "Reporter requires promoted Auditor effect_reviews"
                )
            bound_reviews = deepcopy(audit["effect_reviews"])
            binding = {
                "source_stage": "auditor",
                "source_field": "effect_reviews",
                "item_count": len(bound_reviews),
                "sha256": sha256_json(bound_reviews),
            }
            envelope = deepcopy(envelope)
            envelope["business"]["effect_reviews"] = bound_reviews
            envelope["intelligence"]["controlled_bindings"] = {
                "effect_reviews": binding
            }
            controlled_bindings = {"effect_reviews": binding}
        business, intelligence = validate_envelope(
            stage=stage,
            envelope=envelope,
            facts=facts,
            evidence_catalog=evidence_catalog,
            upstream=upstream,
            packet=packet,
        )
    except Exception as exc:
        if isinstance(exc, AgentRunFailure):
            raise
        raise AgentRunFailure(
            str(exc),
            request=request,
            raw_response=raw_response,
        ) from exc
    validated = {"business": business, "intelligence": intelligence}
    return AgentRunResult(
        stage=stage,
        backend=backend.name,
        request=request,
        raw_response=raw_response,
        envelope=validated,
        request_sha256=sha256_json(request),
        response_sha256=sha256_json(validated),
        completed_at=utc_now(),
        controlled_bindings=controlled_bindings,
    )


def build_agent_request(
    *,
    stage: str,
    taskbook: str,
    packet: dict[str, Any],
) -> dict[str, Any]:
    if stage not in STAGE_BY_KEY:
        raise AgentRunnerError(f"unsupported Stage: {stage}")
    return {
        "schema_version": "1.0",
        "agent": STAGE_BY_KEY[stage]["agent"],
        "stage": stage,
        "taskbook": taskbook,
        "packet": packet,
        "output_contract": {
            "top_level_fields": ["business", "intelligence"],
            "business_schema": STAGE_BY_KEY[stage]["schema"],
            "intelligence_schema": "intelligence.schema.json",
        },
    }


__all__ = [
    "AgentBackend",
    "AgentRunFailure",
    "AgentRunResult",
    "AgentRunnerError",
    "DolphinHostedBackend",
    "FixtureBackend",
    "HostedResponseRequired",
    "build_agent_request",
    "normalize_hosted_response",
    "run_agent",
]
