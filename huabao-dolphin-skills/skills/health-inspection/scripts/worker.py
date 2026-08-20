"""Execute one approved Dolphin business Stage through the Workspace API."""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parents[2]
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from shared.audit import sha256_json, utc_now  # noqa: E402
from shared.models import STAGE_BY_KEY  # noqa: E402
from agent_runner import (  # noqa: E402
    AgentBackend,
    AgentRunFailure,
    AgentRunResult,
    DolphinHostedBackend,
    build_agent_request,
    run_agent,
)
from calculate import calculate  # noqa: E402
from data_layer import acquire  # noqa: E402
from detect import detect  # noqa: E402
from packet_builder import (  # noqa: E402
    build_child_taskbook,
    build_data_operator_packet,
    build_stage_packet,
)
from renderer import render  # noqa: E402
from validator import validate_envelope, validate_stage0  # noqa: E402
from workspace_client import (  # noqa: E402
    ArtifactMetadata,
    WorkspaceBinding,
    WorkspaceClient,
    WorkspaceNotFoundError,
)


BUSINESS_ARTIFACTS = {
    "inspector": ("inspector_inspection_json", "inspector_inspection_md"),
    "diagnostician": (
        "diagnostician_diagnosis_json",
        "diagnostician_diagnosis_md",
    ),
    "advisor": ("advisor_action_plan_json", "advisor_action_plan_md"),
    "auditor": ("auditor_audit_json", "auditor_audit_md"),
    "reporter": ("reporter_daily_report_json", "reporter_daily_report_md"),
}


@dataclass(frozen=True)
class Stage0Result:
    source: dict[str, Any]
    policy: dict[str, Any]
    facts: dict[str, Any]
    evidence_catalog: dict[str, Any]
    manifest: dict[str, Any]
    receipt: dict[str, Any]
    attempt: int


@dataclass(frozen=True)
class StageResult:
    stage: str
    packet: dict[str, Any]
    taskbook: str
    business: dict[str, Any]
    intelligence: dict[str, Any]
    markdown: str
    run: AgentRunResult | None
    attempt: int


def _jsonl(values: list[dict[str, Any]]) -> str:
    return "".join(
        json.dumps(item, ensure_ascii=False, separators=(",", ":")) + "\n"
        for item in values
    )


def _put_attempt(
    *,
    client: WorkspaceClient,
    binding: WorkspaceBinding,
    stage: str,
    attempt: int,
    request: Any,
    raw_response: Any,
    attempt_projection: dict[str, Any],
    cli_events: list[dict[str, Any]],
    artifacts: dict[str, str],
    stdout_text: str | None = None,
    stderr_text: str | None = None,
) -> None:
    prefix = f"{stage}_attempt_{attempt:03d}"
    client.put_json(binding, f"{prefix}_request", request)
    client.put_json(binding, f"{prefix}_response_raw", raw_response)
    client.put_json(binding, f"{prefix}_attempt", attempt_projection)
    client.put_text(
        binding,
        f"{prefix}_events",
        _jsonl(
            [
                {
                    "event": (
                        "attempt_completed"
                        if attempt_projection.get("status") == "completed"
                        else "attempt_failed"
                    ),
                    "stage": stage,
                    "attempt": attempt,
                    "at": attempt_projection.get("completed_at", utc_now()),
                }
            ]
        ),
        media_type="application/x-ndjson; charset=utf-8",
    )
    client.put_text(
        binding,
        f"{prefix}_cli",
        _jsonl(cli_events),
        media_type="application/x-ndjson; charset=utf-8",
    )
    client.put_json(
        binding,
        f"{prefix}_artifacts",
        {
            "schema_version": "1.0",
            "stage": stage,
            "attempt": attempt,
            "artifacts": artifacts,
        },
    )
    if stdout_text is not None:
        client.put_text(
            binding,
            f"{prefix}_stdout",
            stdout_text,
            media_type="text/plain; charset=utf-8",
        )
    if stderr_text is not None:
        client.put_text(
            binding,
            f"{prefix}_stderr",
            stderr_text,
            media_type="text/plain; charset=utf-8",
        )


def _try_json(
    client: WorkspaceClient,
    binding: WorkspaceBinding,
    artifact_id: str,
    metadata: dict[str, ArtifactMetadata],
) -> dict[str, Any] | None:
    item = metadata.get(artifact_id)
    if item is None:
        return None
    return client.get_json(
        binding,
        artifact_id,
        expected_sha256=item.sha256,
    )


def _attempt_slot(
    *,
    client: WorkspaceClient,
    binding: WorkspaceBinding,
    stage: str,
    metadata: dict[str, ArtifactMetadata],
) -> tuple[int, dict[str, Any] | None]:
    for attempt in range(1, 4):
        prefix = f"{stage}_attempt_{attempt:03d}"
        marker = metadata.get(f"{prefix}_attempt")
        if marker is not None:
            value = client.get_json(
                binding,
                f"{prefix}_attempt",
                expected_sha256=marker.sha256,
            )
            if value.get("status") == "completed":
                return attempt, value
            if value.get("status") != "failed":
                raise RuntimeError(f"{prefix} has an invalid status")
            continue
        if any(key.startswith(prefix) for key in metadata):
            return attempt, None
        return attempt, None
    raise RuntimeError(f"{stage} exhausted the three-attempt limit")


def _data_taskbook(packet: dict[str, Any]) -> str:
    return (
        "# data_operator_agent 任务书\n\n"
        f"运行：{packet['run_id']} / {packet['business_date']}\n\n"
        "只调度 packet 中四个白名单确定性步骤。不得改写指标、评分、规则、"
        "异常或证据；不得访问服务器路径、Git、SQLite 或通知能力。\n"
    )


def execute_stage0(
    *,
    client: WorkspaceClient,
    binding: WorkspaceBinding,
    policy: dict[str, Any],
    metadata: dict[str, ArtifactMetadata],
    data_operator_response: dict[str, Any] | None = None,
    backend_name: str = "fixture_conformance",
) -> Stage0Result:
    existing_manifest = _try_json(
        client,
        binding,
        "data_layer_manifest",
        metadata,
    )
    if existing_manifest is not None:
        required = {
            name: _try_json(client, binding, name, metadata)
            for name in (
                "data_layer_source",
                "data_layer_health_policy",
                "data_layer_facts",
                "data_layer_evidence_catalog",
                "data_operator_attempt_001_response_raw",
                "data_operator_attempt_001_attempt",
            )
        }
        if any(value is None for value in required.values()):
            raise RuntimeError("completed Stage 0 is missing a bound artifact")
        actual_policy = required["data_layer_health_policy"]
        if actual_policy != policy:
            raise RuntimeError("existing Stage 0 policy differs from current binding")
        attempt_marker = required["data_operator_attempt_001_attempt"]
        if (
            attempt_marker.get("status") != "completed"
            or attempt_marker.get("self_test", {}).get("status") != "passed"
            or attempt_marker.get("self_test", {}).get("unresolved_issues")
        ):
            raise RuntimeError("existing Stage 0 attempt receipt is not successful")
        if (
            data_operator_response is not None
            and required["data_operator_attempt_001_response_raw"]
            != data_operator_response
        ):
            raise RuntimeError(
                "existing Data Operator response differs from hosted replay"
            )
        validate_stage0(
            run_id=binding.run_id,
            business_date=binding.business_date,
            policy=policy,
            source=required["data_layer_source"],
            facts=required["data_layer_facts"],
            evidence_catalog=required["data_layer_evidence_catalog"],
            receipt=required["data_operator_attempt_001_response_raw"],
            manifest=existing_manifest,
        )
        return Stage0Result(
            source=required["data_layer_source"],
            policy=policy,
            facts=required["data_layer_facts"],
            evidence_catalog=required["data_layer_evidence_catalog"],
            manifest=existing_manifest,
            receipt=required["data_operator_attempt_001_response_raw"],
            attempt=1,
        )

    packet = build_data_operator_packet(
        run_id=binding.run_id,
        business_date=binding.business_date,
        policy=policy,
        platform_release_sha256=binding.platform_release_sha256,
    )
    taskbook = _data_taskbook(packet)
    source = acquire(business_date=binding.business_date)
    calculated = calculate(source, policy)
    facts, evidence_catalog = detect(calculated, run_id=binding.run_id)
    checks = [
        {
            "name": "metric_coverage_contract",
            "status": "passed",
            "summary": "37 项指标及三维顺序完整。",
        },
        {
            "name": "policy_binding_contract",
            "status": "passed",
            "summary": "评分和规则均来自冻结政策。",
        },
        {
            "name": "evidence_catalog_contract",
            "status": "passed",
            "summary": "证据正文单点保存且引用闭合。",
        },
        {
            "name": "command_plan_contract",
            "status": "passed",
            "summary": "仅执行四个白名单确定性步骤。",
        },
    ]
    generated_receipt = {
        "schema_version": "2.0",
        "run_id": binding.run_id,
        "business_date": binding.business_date,
        "stage": "data_operator",
        "agent": "data_operator_agent",
        "status": "completed",
        "summary": "37 项指标、规则覆盖、异常与证据目录已完成确定性校验。",
        "command_plan": [
            "data_layer",
            "calculate",
            "detect",
            "validate",
        ],
        "self_test": {
            "status": "passed",
            "checks": checks,
            "unresolved_issues": [],
        },
        "failure": None,
    }
    receipt = (
        dict(data_operator_response)
        if data_operator_response is not None
        else generated_receipt
    )
    manifest = {
        "schema_version": "1.0",
        "run_id": binding.run_id,
        "business_date": binding.business_date,
        "integrity": "passed",
        "coverage": {
            "metric_count": 37,
            "dimension": facts["metric_catalog"]["dimension_counts"],
            "frequency": facts["metric_catalog"]["frequency_counts"],
            "evaluation": facts["health"]["assessment"],
        },
        "artifacts": {
            "data_layer_source": sha256_json(source),
            "data_layer_health_policy": sha256_json(policy),
            "data_layer_facts": sha256_json(facts),
            "data_layer_evidence_catalog": sha256_json(evidence_catalog),
        },
    }
    validate_stage0(
        run_id=binding.run_id,
        business_date=binding.business_date,
        policy=policy,
        source=source,
        facts=facts,
        evidence_catalog=evidence_catalog,
        receipt=receipt,
        manifest=manifest,
    )
    client.put_text(binding, "data_layer_taskbook", taskbook)
    client.put_json(binding, "data_layer_packet", packet)
    client.put_json(binding, "data_layer_source", source)
    client.put_json(binding, "data_layer_facts", facts)
    client.put_json(binding, "data_layer_evidence_catalog", evidence_catalog)
    completed_at = str(binding.platform_release["bound_at"])
    attempt_projection = {
        "schema_version": "1.0",
        "stage": "data_operator",
        "agent": "data_operator_agent",
        "attempt": 1,
        "backend": backend_name,
        "status": "completed",
        "request_sha256": sha256_json(packet),
        "response_sha256": sha256_json(receipt),
        "completed_at": completed_at,
        "self_test": receipt["self_test"],
    }
    cli_events = [
        {
            "order": index,
            "command": command,
            "status": "passed",
            "at": completed_at,
        }
        for index, command in enumerate(
            ("data_layer", "calculate", "detect", "validate"),
            start=1,
        )
    ]
    _put_attempt(
        client=client,
        binding=binding,
        stage="data_operator",
        attempt=1,
        request=packet,
        raw_response=receipt,
        attempt_projection=attempt_projection,
        cli_events=cli_events,
        artifacts=manifest["artifacts"],
        stdout_text="",
        stderr_text="",
    )
    client.put_json(binding, "data_layer_manifest", manifest)
    return Stage0Result(
        source=source,
        policy=policy,
        facts=facts,
        evidence_catalog=evidence_catalog,
        manifest=manifest,
        receipt=receipt,
        attempt=1,
    )


def execute_agent_stage(
    *,
    client: WorkspaceClient,
    binding: WorkspaceBinding,
    stage: str,
    backend: AgentBackend,
    stage0: Stage0Result,
    upstream: dict[str, dict[str, Any]],
    metadata: dict[str, ArtifactMetadata],
    due_effect_reviews: list[dict[str, Any]] | None = None,
) -> StageResult:
    if stage not in BUSINESS_ARTIFACTS:
        raise ValueError(f"unsupported Stage: {stage}")
    json_id, markdown_id = BUSINESS_ARTIFACTS[stage]
    intelligence_id = f"{stage}_intelligence"
    packet_id = f"{stage}_packet"
    taskbook_id = f"{stage}_taskbook"
    expected_packet = build_stage_packet(
        stage=stage,
        facts=stage0.facts,
        evidence_catalog=stage0.evidence_catalog,
        upstream=upstream,
        policy=stage0.policy,
        due_effect_reviews=due_effect_reviews,
    )
    expected_taskbook = build_child_taskbook(stage, expected_packet)
    existing_packet = _try_json(client, binding, packet_id, metadata)
    if existing_packet is not None and existing_packet != expected_packet:
        raise RuntimeError(f"{stage} packet differs from the frozen inputs")
    packet = existing_packet or expected_packet
    if existing_packet is None:
        client.put_json(binding, packet_id, packet)
    taskbook_item = metadata.get(taskbook_id)
    if taskbook_item is not None:
        taskbook_bytes, _ = client.get_artifact(
            binding,
            taskbook_id,
            expected_sha256=taskbook_item.sha256,
        )
        taskbook = taskbook_bytes.decode("utf-8")
        if taskbook != expected_taskbook:
            raise RuntimeError(f"{stage} taskbook differs from its packet")
    else:
        taskbook = expected_taskbook
        client.put_text(binding, taskbook_id, taskbook)

    existing_business = _try_json(client, binding, json_id, metadata)
    existing_intelligence = _try_json(
        client,
        binding,
        intelligence_id,
        metadata,
    )
    if existing_business is not None and existing_intelligence is not None:
        completed_attempt, completed_marker = _attempt_slot(
            client=client,
            binding=binding,
            stage=stage,
            metadata=metadata,
        )
        if (
            completed_marker is None
            or completed_marker.get("status") != "completed"
        ):
            raise RuntimeError(f"{stage} formal result has no completed attempt")
        validate_envelope(
            stage=stage,
            envelope={
                "business": existing_business,
                "intelligence": existing_intelligence,
            },
            facts=stage0.facts,
            evidence_catalog=stage0.evidence_catalog,
            upstream=upstream,
            packet=packet,
        )
        expected_markdown = render(stage, existing_business)
        markdown_item = metadata.get(markdown_id)
        if markdown_item is None:
            client.put_text(binding, markdown_id, expected_markdown)
            markdown = expected_markdown
        else:
            markdown_bytes, _ = client.get_artifact(
                binding,
                markdown_id,
                expected_sha256=markdown_item.sha256,
            )
            markdown = markdown_bytes.decode("utf-8")
            if markdown != expected_markdown:
                raise RuntimeError(f"{stage} Markdown differs from business JSON")
        return StageResult(
            stage=stage,
            packet=packet,
            taskbook=taskbook,
            business=existing_business,
            intelligence=existing_intelligence,
            markdown=markdown,
            run=None,
            attempt=completed_attempt,
        )

    attempt, attempt_marker = _attempt_slot(
        client=client,
        binding=binding,
        stage=stage,
        metadata=metadata,
    )
    prefix = f"{stage}_attempt_{attempt:03d}"
    raw_item = metadata.get(f"{prefix}_response_raw")
    actual_backend = backend
    if raw_item is not None:
        raw_response = client.get_json(
            binding,
            f"{prefix}_response_raw",
            expected_sha256=raw_item.sha256,
        )
        actual_backend = DolphinHostedBackend({stage: raw_response})
    elif attempt_marker is not None:
        raise RuntimeError(f"{prefix} is completed but its raw response is missing")
    try:
        result = run_agent(
            stage=stage,
            backend=actual_backend,
            taskbook=taskbook,
            packet=packet,
            facts=stage0.facts,
            evidence_catalog=stage0.evidence_catalog,
            upstream=upstream,
        )
    except AgentRunFailure as exc:
        fixed_at = str(binding.platform_release["bound_at"])
        raw_failure = (
            exc.raw_response
            if exc.raw_response is not None
            else {"error": type(exc.__cause__).__name__, "message": str(exc)}
        )
        failed_projection = {
            "schema_version": "1.0",
            "stage": stage,
            "agent": STAGE_BY_KEY[stage]["agent"],
            "attempt": attempt,
            "backend": "validated_agent_response",
            "status": "failed",
            "request_sha256": sha256_json(exc.request),
            "response_sha256": sha256_json(raw_failure),
            "completed_at": fixed_at,
            "error": str(exc),
            "self_test": {
                "status": "failed",
                "checks": [],
                "unresolved_issues": [str(exc)],
            },
        }
        _put_attempt(
            client=client,
            binding=binding,
            stage=stage,
            attempt=attempt,
            request=exc.request,
            raw_response=raw_failure,
            attempt_projection=failed_projection,
            cli_events=[],
            artifacts={},
        )
        raise
    business = result.envelope["business"]
    intelligence = result.envelope["intelligence"]
    markdown = render(stage, business)
    fixed_projection = {
        **result.attempt_projection(attempt=attempt),
        "backend": "validated_agent_response",
        "completed_at": str(binding.platform_release["bound_at"]),
    }
    _put_attempt(
        client=client,
        binding=binding,
        stage=stage,
        attempt=attempt,
        request=result.request,
        raw_response=result.raw_response,
        attempt_projection=fixed_projection,
        cli_events=[],
        artifacts={
            json_id: sha256_json(business),
            intelligence_id: sha256_json(intelligence),
        },
    )
    if existing_business is not None and existing_business != business:
        raise RuntimeError(f"{stage} partial business output differs from replay")
    if existing_intelligence is not None and existing_intelligence != intelligence:
        raise RuntimeError(f"{stage} partial intelligence differs from replay")
    client.put_json(binding, json_id, business)
    client.put_text(binding, markdown_id, markdown)
    client.put_json(binding, intelligence_id, intelligence)
    return StageResult(
        stage=stage,
        packet=packet,
        taskbook=taskbook,
        business=business,
        intelligence=intelligence,
        markdown=markdown,
        run=result,
        attempt=attempt,
    )


__all__ = [
    "BUSINESS_ARTIFACTS",
    "Stage0Result",
    "StageResult",
    "execute_agent_stage",
    "execute_stage0",
]
