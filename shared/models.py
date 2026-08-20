"""Shared contracts for the Huabao site health-inspection runtime."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Literal


Dimension = Literal["traffic", "conversion", "product"]
Frequency = Literal["day", "week", "month"]

FIXED_SCOPE = {
    "scope_id": "huabao-site-health-inspection",
    "country_code": "ALL",
    "country_name": "全站",
    "site_name": "华宝新能站内健康巡检",
    "timezone": "Asia/Shanghai",
    "currency": "CNY",
    "dimensions": ["traffic", "conversion", "product"],
}

DIMENSION_LABELS = {
    "traffic": "流量健康",
    "conversion": "转化健康",
    "product": "商品健康",
}

METRIC_COVERAGE: dict[str, Any] = {
    "total": 37,
    "frequency": {"day": 18, "week": 10, "month": 9},
    "dimension": {"traffic": 12, "conversion": 10, "product": 15},
}

# Keep every model-facing input ceiling proportional to the established
# contract while allowing the complete, uncompressed taskbooks and bounded
# projections to reach the Agents.  Non-context limits (outputs, evidence
# storage, Broker stdout, Git snapshots, and notifications) are intentionally
# independent from this multiplier.
AGENT_CONTEXT_LIMIT_MULTIPLIER = 5
CHILD_TASKBOOK_LIMIT_BYTES = 8 * 1024 * AGENT_CONTEXT_LIMIT_MULTIPLIER
ORCHESTRATOR_DAILY_TASKBOOK_LIMIT_BYTES = (
    32 * 1024 * AGENT_CONTEXT_LIMIT_MULTIPLIER
)
ORCHESTRATOR_SKILL_LIMIT_BYTES = 16 * 1024 * AGENT_CONTEXT_LIMIT_MULTIPLIER
ORCHESTRATOR_AGENTS_LIMIT_BYTES = 24 * 1024 * AGENT_CONTEXT_LIMIT_MULTIPLIER
ORCHESTRATOR_RUN_STATE_LIMIT_BYTES = 16 * 1024 * AGENT_CONTEXT_LIMIT_MULTIPLIER
ORCHESTRATOR_MEMORY_LIMIT_BYTES = 12 * 1024 * AGENT_CONTEXT_LIMIT_MULTIPLIER
ORCHESTRATOR_BROKER_RESULT_LIMIT_BYTES = (
    16 * 1024 * AGENT_CONTEXT_LIMIT_MULTIPLIER
)
ORCHESTRATOR_RUN_PROJECTION_LIMIT_BYTES = (
    12 * 1024 * AGENT_CONTEXT_LIMIT_MULTIPLIER
)
ORCHESTRATOR_PROMPT_LIMIT_BYTES = 64 * 1024 * AGENT_CONTEXT_LIMIT_MULTIPLIER
REPLACEMENT_INSTRUCTION_LIMIT_BYTES = 4 * 1024 * AGENT_CONTEXT_LIMIT_MULTIPLIER
REPLACEMENT_INSTRUCTION_MAX_CHARACTERS = 4000 * AGENT_CONTEXT_LIMIT_MULTIPLIER

DATA_OPERATOR_STAGE: dict[str, Any] = {
    "number": 0,
    "key": "data_operator",
    "event_key": "data-layer",
    "folder": "00-data-layer",
    "agent": "data_operator_agent",
    "schema": "data-operation.schema.json",
    "packet_limit": 8 * 1024 * AGENT_CONTEXT_LIMIT_MULTIPLIER,
}

# Stage 1-5 packets contain bounded business projections rather than raw
# evidence bodies. Keep a single accident ceiling that is large enough for the
# complete 37-metric anomaly path (including downstream diagnoses/actions), so
# normal high-anomaly days do not fail merely because their compact projection
# is larger than the old per-stage 16/32 KB defaults.
AGENT_PACKET_LIMIT = 256 * 1024 * AGENT_CONTEXT_LIMIT_MULTIPLIER

STAGES: tuple[dict[str, Any], ...] = (
    {
        "number": 1,
        "key": "inspector",
        "folder": "01-inspector",
        "agent": "inspector_agent",
        "business_file": "inspection.json",
        "markdown_file": "inspection.md",
        "schema": "inspection.schema.json",
        # Inspector receives the complete deterministic anomaly projection.
        "packet_limit": AGENT_PACKET_LIMIT,
    },
    {
        "number": 2,
        "key": "diagnostician",
        "folder": "02-diagnostician",
        "agent": "diagnostician_agent",
        "business_file": "diagnosis.json",
        "markdown_file": "diagnosis.md",
        "schema": "diagnosis.schema.json",
        "packet_limit": AGENT_PACKET_LIMIT,
    },
    {
        "number": 3,
        "key": "advisor",
        "folder": "03-advisor",
        "agent": "advisor_agent",
        "business_file": "action-plan.json",
        "markdown_file": "action-plan.md",
        "schema": "action-plan.schema.json",
        "packet_limit": AGENT_PACKET_LIMIT,
    },
    {
        "number": 4,
        "key": "auditor",
        "folder": "04-auditor",
        "agent": "auditor_agent",
        "business_file": "audit.json",
        "markdown_file": "audit.md",
        "schema": "audit.schema.json",
        "packet_limit": AGENT_PACKET_LIMIT,
    },
    {
        "number": 5,
        "key": "reporter",
        "folder": "05-reporter",
        "agent": "reporter_agent",
        "business_file": "daily-report.json",
        "markdown_file": "daily-report.md",
        "schema": "daily-report.schema.json",
        "packet_limit": AGENT_PACKET_LIMIT,
    },
)

STAGE_BY_KEY = {stage["key"]: stage for stage in STAGES}
AGENT_STAGES: tuple[dict[str, Any], ...] = (DATA_OPERATOR_STAGE, *STAGES)
AGENT_STAGE_BY_KEY = {stage["key"]: stage for stage in AGENT_STAGES}


@dataclass(frozen=True)
class MetricSnapshot:
    id: str
    name: str
    dimension: Dimension
    frequency: Frequency
    metric: str
    value: float
    baseline_value: float | None
    status: Literal["normal", "abnormal", "observed", "unavailable"]
    evaluation_status: Literal["evaluated", "partially_evaluated", "monitor_only"]
    value_provenance: str
    severity: str
    source: str
    definition: str
    baseline: str
    threshold: str
    judgement: str
    format: str
    decimals: int
    favorable: str
    history: list[dict[str, Any]]
    trend: dict[str, Any]
    outputs: dict[str, Any]
    technical: dict[str, Any]
    evidence_refs: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Evidence:
    evidence_id: str
    kind: str
    title: str
    source: str
    scope: str
    observed_at: str
    payload: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class AnomalyCandidate:
    anomaly_id: str
    rule_id: str
    metric_id: str
    dimension: Dimension
    severity: str
    summary: str
    evidence_refs: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
