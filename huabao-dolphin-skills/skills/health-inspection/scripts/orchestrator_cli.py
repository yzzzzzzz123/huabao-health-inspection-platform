"""Dolphin Stage 0-5 orchestration over the Artifact-ID Workspace API."""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import date
from pathlib import Path
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parents[2]
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from shared.audit import sha256_file, sha256_json  # noqa: E402
from shared.models import STAGES  # noqa: E402
from action_history import (  # noqa: E402
    build_due_effect_reviews,
    validate_run_context,
)
from agent_runner import DolphinHostedBackend, FixtureBackend  # noqa: E402
from packet_builder import (  # noqa: E402
    build_daily_taskbook,
    build_taskbook_manifest,
)
from policy_store import validate_frozen_policy  # noqa: E402
from worker import execute_agent_stage, execute_stage0  # noqa: E402
from workspace_client import (  # noqa: E402
    WorkspaceAccessBinding,
    WorkspaceBinding,
    WorkspaceClient,
    WorkspaceClientError,
    WorkspaceConflictError,
)


DEFAULT_WORKSPACE_URL = "http://127.0.0.1:8765"
DEFAULT_RELEASE_VERSION = "v1.0.0"
DEFAULT_WORKFLOW_VERSION = "v1.0.0"
STAGE_ORDER = [
    "data_operator",
    "inspector",
    "diagnostician",
    "advisor",
    "auditor",
    "reporter",
]
IGNORED_PARTS = {
    ".git",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
}


def _validate_date(value: str) -> str:
    parsed = date.fromisoformat(value)
    if parsed.isoformat() != value:
        raise ValueError("business date must use YYYY-MM-DD")
    return value


def _release_files() -> list[Path]:
    roots = [
        PROJECT_ROOT / "shared",
        PROJECT_ROOT / "skills" / "health-inspection",
        PROJECT_ROOT / "dolphin" / "agents",
        PROJECT_ROOT / "dolphin" / "workflows",
    ]
    result: list[Path] = []
    for root in roots:
        for path in root.rglob("*"):
            if (
                path.is_file()
                and not path.is_symlink()
                and not any(part in IGNORED_PARTS for part in path.parts)
                and path.suffix not in {".pyc", ".pyo"}
            ):
                result.append(path)
    return sorted(set(result), key=lambda item: item.relative_to(PROJECT_ROOT).as_posix())


def _bundle_hash(paths: list[Path]) -> str:
    manifest = [
        {
            "path": path.relative_to(PROJECT_ROOT).as_posix(),
            "bytes": path.stat().st_size,
            "sha256": sha256_file(path),
        }
        for path in paths
    ]
    return sha256_json(manifest)


def build_release(
    *,
    release_version: str = DEFAULT_RELEASE_VERSION,
    workflow_version: str = DEFAULT_WORKFLOW_VERSION,
) -> dict[str, Any]:
    files = _release_files()
    schema_root = (
        PROJECT_ROOT
        / "skills"
        / "health-inspection"
        / "contracts"
        / "schemas"
    )
    schema_files = [
        path for path in files if schema_root in path.parents
    ]
    return {
        "platform": "dolphin-ai",
        "application_id": "huabao-health-inspection",
        "release_version": release_version,
        "workflow_version": workflow_version,
        "skill_bundle_sha256": _bundle_hash(files),
        "schema_bundle_sha256": _bundle_hash(schema_files),
    }


def _binding_dict(binding: WorkspaceBinding) -> dict[str, Any]:
    return {
        "run_id": binding.run_id,
        "business_date": binding.business_date,
        "incarnation_id": binding.incarnation_id,
        "platform_release_sha256": binding.platform_release_sha256,
        "platform_release": binding.platform_release,
        "status": binding.status,
        "workspace_version": binding.workspace_version,
    }


def _release_matches(
    existing: dict[str, Any],
    requested: dict[str, Any],
) -> bool:
    return all(existing.get(key) == value for key, value in requested.items())


def _create_or_resume(
    *,
    client: WorkspaceClient,
    business_date: str,
    release: dict[str, Any],
    resume: bool,
    incarnation_id: str | None,
    platform_release_sha256: str | None,
) -> tuple[WorkspaceBinding, dict[str, Any]]:
    if resume:
        if not incarnation_id or not platform_release_sha256:
            raise ValueError(
                "--resume requires --incarnation-id and "
                "--platform-release-sha256"
            )
        access = WorkspaceAccessBinding.create(
            run_id=f"hi-{business_date}",
            incarnation_id=incarnation_id,
            platform_release_sha256=platform_release_sha256,
        )
        binding, _, payload = client.get_workspace(
            access.run_id,
            binding=access,
        )
        if not _release_matches(binding.platform_release, release):
            raise WorkspaceConflictError(
                "existing workspace is bound to a different Dolphin release"
            )
        return binding, payload
    if incarnation_id or platform_release_sha256:
        raise ValueError("resume binding options require --resume")
    return client.create_workspace(
        business_date=business_date,
        platform_release=release,
    )


def _hosted_responses(args: argparse.Namespace) -> dict[str, Any]:
    if args.backend != "dolphin":
        return {}
    if args.hosted_responses_json:
        raw = args.hosted_responses_json
    elif args.hosted_responses:
        raw = args.hosted_responses.read_text(encoding="utf-8")
    else:
        raw = os.environ.get("DOLPHIN_HOSTED_RESPONSES_JSON", "")
    if not raw:
        return {}
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("hosted responses must be a Stage-keyed JSON object")
    unknown = set(value) - {
        "orchestrator",
        "data_operator",
        *{item["key"] for item in STAGES},
    }
    if unknown:
        raise ValueError(f"unknown hosted response Stages: {sorted(unknown)}")
    return value


def _ensure_bootstrap(
    *,
    client: WorkspaceClient,
    binding: WorkspaceBinding,
) -> tuple[WorkspaceBinding, dict[str, Any], dict[str, Any]]:
    binding, artifacts, payload = client.get_workspace(
        binding.run_id,
        binding=binding,
    )
    release_item = artifacts.get("platform_release")
    if release_item is not None:
        release_artifact = client.get_json(
            binding,
            "platform_release",
            expected_sha256=release_item.sha256,
        )
        if release_artifact != binding.platform_release:
            raise RuntimeError("server platform_release artifact differs from binding")
    existing_policy = artifacts.get("data_layer_health_policy")
    if existing_policy is None:
        raise RuntimeError(
            "workspace is missing the Server-owned frozen health-policy artifact"
        )
    frozen = client.get_json(
        binding,
        "data_layer_health_policy",
        expected_sha256=existing_policy.sha256,
    )
    if not isinstance(frozen, dict):
        raise RuntimeError("workspace frozen health-policy artifact must be an object")
    policy = validate_frozen_policy(frozen)
    taskbook = build_daily_taskbook(
        binding=_binding_dict(binding),
        policy=policy,
    )
    taskbook_manifest = build_taskbook_manifest(
        binding=_binding_dict(binding),
        policy=policy,
        daily_taskbook=taskbook,
    )
    client.put_text(binding, "orchestrator_daily_taskbook", taskbook)
    client.put_json(binding, "orchestrator_taskbook_manifest", taskbook_manifest)
    return binding, payload, policy


def _ensure_thread(
    *,
    client: WorkspaceClient,
    binding: WorkspaceBinding,
    backend_name: str,
) -> None:
    projection = {
        "schema_version": "1.0",
        "run_id": binding.run_id,
        "business_date": binding.business_date,
        "incarnation_id": binding.incarnation_id,
        "backend": backend_name,
        "thread_id": f"{backend_name}:{binding.incarnation_id}",
        "platform_release_sha256": binding.platform_release_sha256,
        "created_at": binding.platform_release["bound_at"],
        "contains_credentials": False,
    }
    _, artifacts, _ = client.get_workspace(binding.run_id, binding=binding)
    existing = artifacts.get("orchestrator_thread")
    if existing is not None:
        actual = client.get_json(
            binding,
            "orchestrator_thread",
            expected_sha256=existing.sha256,
        )
        if actual != projection:
            raise WorkspaceConflictError(
                "existing Orchestrator thread differs from requested backend"
            )
    else:
        client.put_json(binding, "orchestrator_thread", projection)


def _load_due_effect_reviews(
    *,
    client: WorkspaceClient,
    binding: WorkspaceBinding,
    current_facts: dict[str, Any],
) -> list[dict[str, Any]]:
    _, artifacts, _ = client.get_workspace(binding.run_id, binding=binding)
    item = artifacts.get("run_context")
    if item is None:
        raise RuntimeError("server-owned run_context artifact is required")
    run_context = client.get_json(
        binding,
        "run_context",
        expected_sha256=item.sha256,
    )
    if not isinstance(run_context, dict):
        raise RuntimeError("run_context must be a JSON object")
    historical_runs = validate_run_context(
        run_context=run_context,
        expected_binding={
            "run_id": binding.run_id,
            "business_date": binding.business_date,
            "incarnation_id": binding.incarnation_id,
            "platform_release_sha256": binding.platform_release_sha256,
        },
    )
    return build_due_effect_reviews(
        current_facts=current_facts,
        historical_runs=historical_runs,
    )


def _finalize(
    *,
    client: WorkspaceClient,
    binding: WorkspaceBinding,
    stage0: Any,
    stage_results: dict[str, Any],
) -> dict[str, Any]:
    fixed_at = str(binding.platform_release["bound_at"])
    binding, metadata, workspace = client.get_workspace(
        binding.run_id,
        binding=binding,
    )
    existing = metadata.get("orchestrator_delivery_manifest")
    if existing is not None:
        manifest = client.get_json(
            binding,
            "orchestrator_delivery_manifest",
            expected_sha256=existing.sha256,
        )
        seal = client.seal(
            binding,
            delivery_manifest_sha256=existing.sha256,
        )
        return {
            "manifest": manifest,
            "manifest_sha256": existing.sha256,
            "seal": seal,
        }

    intelligence_ledger = {
        "schema_version": "1.0",
        "run_id": binding.run_id,
        "business_date": binding.business_date,
        "stages": [
            {
                "stage": stage,
                "agent": result.intelligence["agent"],
                "summary": result.intelligence["analysis_summary"],
                "self_test": result.intelligence["self_test"]["status"],
                "sha256": sha256_json(result.intelligence),
            }
            for stage, result in stage_results.items()
        ],
    }
    execution_ledger = {
        "schema_version": "1.0",
        "run_id": binding.run_id,
        "business_date": binding.business_date,
        "backend_stages": [
            {
                "stage": "data_operator",
                "status": "completed",
                "attempt": stage0.attempt,
                "backend": "deterministic_code",
            },
            *[
                {
                    "stage": stage,
                    "status": "completed",
                    "attempt": result.attempt,
                    "backend": "validated_agent_response",
                }
                for stage, result in stage_results.items()
            ],
        ],
    }
    report = stage_results["reporter"].business
    ui_snapshot = {
        "schema_version": "1.0",
        "run_id": binding.run_id,
        "business_date": binding.business_date,
        "status": "awaiting_seal",
        "platform_release_sha256": binding.platform_release_sha256,
        "headline": report["headline"],
        "executive_summary": report["executive_summary"],
        "health_score": report["health_score"],
        "health_assessment": report["health_assessment"],
        "management_priorities": report["management_priorities"],
        "key_anomalies": report["key_anomalies"],
        "recommended_actions": report["recommended_actions"],
        "effect_reviews": report["effect_reviews"],
        "decision_bottleneck": report["decision_bottleneck"],
    }
    memory = {
        "schema_version": "1.0",
        "run_id": binding.run_id,
        "facts": {
            "facts_sha256": sha256_json(stage0.facts),
            "policy_sha256": stage0.policy["sha256"],
            "platform_release_sha256": binding.platform_release_sha256,
        },
        "completed_stages": STAGE_ORDER,
        "current_stage": None,
        "decisions": [
            {
                "stage": stage,
                "summary": result.intelligence["analysis_summary"],
            }
            for stage, result in stage_results.items()
        ],
        "pending": [],
        "updated_at": fixed_at,
    }
    events = [
        {
            "event": "stage_completed",
            "stage": stage,
            "run_id": binding.run_id,
            "at": fixed_at,
        }
        for stage in STAGE_ORDER
    ]
    notes = [
        {
            "action_id": action["action_id"],
            "action_type": action["action_type"],
            "note": "",
            "status": "awaiting_business_note",
        }
        for action in stage_results["advisor"].business["actions"]
    ]
    client.put_json(binding, "orchestrator_intelligence_ledger", intelligence_ledger)
    client.put_json(binding, "orchestrator_execution_ledger", execution_ledger)
    client.put_json(binding, "orchestrator_ui_snapshot", ui_snapshot)
    client.put_json(binding, "orchestrator_memory", memory)
    client.put_text(
        binding,
        "orchestrator_events",
        "".join(
            json.dumps(item, ensure_ascii=False, separators=(",", ":")) + "\n"
            for item in events
        ),
        media_type="application/x-ndjson; charset=utf-8",
    )
    client.put_text(
        binding,
        "orchestrator_action_implementation",
        "".join(
            json.dumps(item, ensure_ascii=False, separators=(",", ":")) + "\n"
            for item in notes
        ),
        media_type="application/x-ndjson; charset=utf-8",
    )
    client.put_json(
        binding,
        "orchestrator_log_summary",
        {
            "schema_version": "1.0",
            "run_id": binding.run_id,
            "business_date": binding.business_date,
            "stage_count": 6,
            "failed_stage_count": 0,
            "generated_at": fixed_at,
        },
    )
    _, metadata, _ = client.get_workspace(binding.run_id, binding=binding)
    manifest = {
        "schema_version": "1.0",
        "run_id": binding.run_id,
        "business_date": binding.business_date,
        "incarnation_id": binding.incarnation_id,
        "platform_release_sha256": binding.platform_release_sha256,
        "platform_release": binding.platform_release,
        "status": "awaiting_seal",
        "artifacts": [
            {
                "id": item.artifact_id,
                "sha256": item.sha256,
                "bytes": item.bytes,
                "media_type": item.media_type,
                "ui_visible": item.ui_visible,
            }
            for item in sorted(
                metadata.values(),
                key=lambda artifact: artifact.artifact_id,
            )
            if item.artifact_id
            not in {
                "orchestrator_delivery_manifest",
                "orchestrator_workspace_index",
                "orchestrator_archive_manifest",
            }
        ],
        "final_validation": {
            "stage0_integrity": stage0.manifest["integrity"],
            "completed_stages": STAGE_ORDER,
            "delivery_request": report["delivery_request"],
        },
        "created_at": fixed_at,
    }
    receipt = client.put_json(
        binding,
        "orchestrator_delivery_manifest",
        manifest,
    )
    seal = client.seal(
        binding,
        delivery_manifest_sha256=receipt.sha256,
    )
    return {
        "manifest": manifest,
        "manifest_sha256": receipt.sha256,
        "seal": seal,
    }


def _orchestrator_actions(hosted: dict[str, Any]) -> list[dict[str, Any]]:
    value = hosted.get("orchestrator")
    if isinstance(value, dict) and set(value) == {"actions"}:
        value = value["actions"]
    if not isinstance(value, list) or not value:
        raise ValueError(
            "production backend requires a non-empty Orchestrator action list"
        )
    actions: list[dict[str, Any]] = []
    allowed_actions = {
        "dispatch_data_operator",
        "dispatch",
        "observe",
        "retry",
        "relaunch_agent",
        "replace_instruction",
        "finalize",
        "human_takeover",
    }
    for index, item in enumerate(value, start=1):
        if not isinstance(item, dict):
            raise ValueError(f"Orchestrator action {index} must be an object")
        if not {"action", "stage"}.issubset(item):
            raise ValueError(
                f"Orchestrator action {index} must declare action and stage"
            )
        if set(item) - {"action", "stage", "rationale", "instruction"}:
            raise ValueError(f"Orchestrator action {index} has unknown fields")
        action = item["action"]
        stage = item["stage"]
        if action not in allowed_actions or stage not in STAGE_ORDER:
            raise ValueError(f"Orchestrator action {index} is outside the contract")
        if "rationale" in item and not isinstance(item["rationale"], str):
            raise ValueError(f"Orchestrator action {index} rationale must be text")
        if "instruction" in item and not isinstance(item["instruction"], str):
            raise ValueError(f"Orchestrator action {index} instruction must be text")
        actions.append(dict(item))
    return actions


def _run_fixture_conformance(
    *,
    args: argparse.Namespace,
    client: WorkspaceClient,
    binding: WorkspaceBinding,
    policy: dict[str, Any],
) -> dict[str, Any]:
    backend = FixtureBackend()
    binding, metadata, _ = client.get_workspace(binding.run_id, binding=binding)
    stage0 = execute_stage0(
        client=client,
        binding=binding,
        policy=policy,
        metadata=metadata,
        backend_name="fixture_conformance",
    )
    due_effect_reviews = _load_due_effect_reviews(
        client=client,
        binding=binding,
        current_facts=stage0.facts,
    )
    if args.stop_after == "data_operator":
        return {
            **_binding_dict(binding),
            "stopped_after": "data_operator",
            "sealed": False,
            "execution_mode": "fixture_conformance",
        }
    upstream: dict[str, dict[str, Any]] = {}
    results: dict[str, Any] = {}
    for stage in [item["key"] for item in STAGES]:
        binding, metadata, _ = client.get_workspace(
            binding.run_id,
            binding=binding,
        )
        result = execute_agent_stage(
            client=client,
            binding=binding,
            stage=stage,
            backend=backend,
            stage0=stage0,
            upstream=upstream,
            metadata=metadata,
            due_effect_reviews=(
                due_effect_reviews if stage == "auditor" else []
            ),
        )
        results[stage] = result
        upstream[stage] = result.business
        if args.stop_after == stage:
            return {
                **_binding_dict(binding),
                "stopped_after": stage,
                "sealed": False,
                "execution_mode": "fixture_conformance",
            }
    finalized = _finalize(
        client=client,
        binding=binding,
        stage0=stage0,
        stage_results=results,
    )
    sealed_binding = WorkspaceBinding.from_payload(finalized["seal"])
    return {
        **_binding_dict(sealed_binding),
        "sealed": True,
        "execution_mode": "fixture_conformance",
        "delivery_manifest_sha256": finalized["manifest_sha256"],
        "seal": finalized["seal"],
    }


def _run_hosted_orchestration(
    *,
    args: argparse.Namespace,
    client: WorkspaceClient,
    binding: WorkspaceBinding,
    policy: dict[str, Any],
    hosted: dict[str, Any],
) -> dict[str, Any]:
    actions = _orchestrator_actions(hosted)
    data_operator_response = hosted.get("data_operator")
    if not isinstance(data_operator_response, dict):
        raise ValueError(
            "production backend requires a strict Data Operator response object"
        )
    backend = DolphinHostedBackend(hosted)
    accepted: list[str] = []
    pending_stage: str | None = None
    pending_result: Any = None
    stage0: Any = None
    due_effect_reviews: list[dict[str, Any]] = []
    upstream: dict[str, dict[str, Any]] = {}
    results: dict[str, Any] = {}

    for turn, decision in enumerate(actions, start=1):
        action = str(decision["action"])
        stage = str(decision["stage"])
        expected_stage = (
            STAGE_ORDER[len(accepted)]
            if len(accepted) < len(STAGE_ORDER)
            else "reporter"
        )
        if action == "human_takeover":
            return {
                **_binding_dict(binding),
                "sealed": False,
                "status": "human_takeover",
                "stage": stage,
                "turn": turn,
                "execution_mode": "dolphin_orchestrated",
            }
        if action == "observe":
            if pending_stage != stage or pending_result is None:
                raise RuntimeError(
                    "observe must accept the immediately preceding Stage result"
                )
            accepted.append(stage)
            if stage != "data_operator":
                results[stage] = pending_result
                upstream[stage] = pending_result.business
            pending_stage = None
            pending_result = None
            if args.stop_after == stage:
                return {
                    **_binding_dict(binding),
                    "stopped_after": stage,
                    "sealed": False,
                    "execution_mode": "dolphin_orchestrated",
                }
            continue
        if action == "finalize":
            if stage != "reporter" or pending_stage is not None:
                raise RuntimeError("finalize must target an observed Reporter result")
            if accepted != STAGE_ORDER or stage0 is None:
                raise RuntimeError("finalize requires all six observed Stages")
            finalized = _finalize(
                client=client,
                binding=binding,
                stage0=stage0,
                stage_results=results,
            )
            sealed_binding = WorkspaceBinding.from_payload(finalized["seal"])
            return {
                **_binding_dict(sealed_binding),
                "sealed": True,
                "execution_mode": "dolphin_orchestrated",
                "orchestrator_turns": turn,
                "delivery_manifest_sha256": finalized["manifest_sha256"],
                "seal": finalized["seal"],
            }
        if pending_stage is not None:
            raise RuntimeError("Orchestrator must observe before another dispatch")
        if stage != expected_stage:
            raise RuntimeError(
                f"Orchestrator attempted {stage}; expected {expected_stage}"
            )
        if stage == "data_operator":
            if action not in {"dispatch_data_operator", "retry"}:
                raise RuntimeError("Data Operator requires dispatch_data_operator")
            binding, metadata, _ = client.get_workspace(
                binding.run_id,
                binding=binding,
            )
            stage0 = execute_stage0(
                client=client,
                binding=binding,
                policy=policy,
                metadata=metadata,
                data_operator_response=data_operator_response,
                backend_name="dolphin_hosted",
            )
            due_effect_reviews = _load_due_effect_reviews(
                client=client,
                binding=binding,
                current_facts=stage0.facts,
            )
            pending_result = stage0
        else:
            if action not in {
                "dispatch",
                "retry",
                "relaunch_agent",
                "replace_instruction",
            }:
                raise RuntimeError(f"{stage} requires a dispatch action")
            if stage0 is None:
                raise RuntimeError("Stage 0 must be observed before business Stages")
            binding, metadata, _ = client.get_workspace(
                binding.run_id,
                binding=binding,
            )
            pending_result = execute_agent_stage(
                client=client,
                binding=binding,
                stage=stage,
                backend=backend,
                stage0=stage0,
                upstream=upstream,
                metadata=metadata,
                due_effect_reviews=(
                    due_effect_reviews if stage == "auditor" else []
                ),
            )
        pending_stage = stage
    raise RuntimeError("Orchestrator action list ended before finalize")


def run_command(args: argparse.Namespace) -> dict[str, Any]:
    business_date = _validate_date(args.business_date)
    release = build_release(
        release_version=args.release_version,
        workflow_version=args.workflow_version,
    )
    client = WorkspaceClient(args.workspace_url, timeout=args.timeout)
    binding, _ = _create_or_resume(
        client=client,
        business_date=business_date,
        release=release,
        resume=args.resume,
        incarnation_id=args.incarnation_id,
        platform_release_sha256=args.platform_release_sha256,
    )
    binding, _, policy = _ensure_bootstrap(
        client=client,
        binding=binding,
    )
    hosted = _hosted_responses(args)
    _ensure_thread(
        client=client,
        binding=binding,
        backend_name=args.backend,
    )
    if args.backend == "fixture":
        return _run_fixture_conformance(
            args=args,
            client=client,
            binding=binding,
            policy=policy,
        )
    return _run_hosted_orchestration(
        args=args,
        client=client,
        binding=binding,
        policy=policy,
        hosted=hosted,
    )


def config_projection() -> dict[str, Any]:
    release = build_release()
    return {
        "application": "huabao-health-inspection",
        "runtime": {
            "python": ">=3.11",
            "dependencies": "stdlib-only",
            "workspace_protocol": "artifact-id-only",
            "workspace_version": "2.0",
            "default_workspace_url": DEFAULT_WORKSPACE_URL,
        },
        "scope": {
            "site": "华宝新能站内",
            "timezone": "Asia/Shanghai",
            "currency": "CNY",
            "dimensions": ["traffic", "conversion", "product"],
            "metric_count": 37,
        },
        "agents": [
            "orchestrator_agent",
            "data_operator_agent",
            *[item["agent"] for item in STAGES],
        ],
        "backends": {
            "production": "Dolphin Orchestrator action loop plus hosted Agent responses",
            "fixture": "fixed-order local conformance harness only",
        },
        "forbidden_direct_dependencies": [
            "Git",
            "worktree paths",
            "SQLite",
            "DingTalk",
            "runtime_env",
        ],
        "release": release,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("config", help="print the pure Dolphin runtime contract")
    release_parser = subparsers.add_parser(
        "release",
        help="calculate the six client-owned platform release fields",
    )
    release_parser.add_argument(
        "--release-version",
        default=DEFAULT_RELEASE_VERSION,
    )
    release_parser.add_argument(
        "--workflow-version",
        default=DEFAULT_WORKFLOW_VERSION,
    )
    run_parser = subparsers.add_parser(
        "run",
        help="create or resume one Stage 0-5 workspace run",
    )
    run_parser.add_argument("--business-date", required=True)
    run_parser.add_argument(
        "--workspace-url",
        default=os.environ.get("HUABAO_WORKSPACE_API_URL", DEFAULT_WORKSPACE_URL),
    )
    run_parser.add_argument(
        "--backend",
        choices=("dolphin", "fixture"),
        default="dolphin",
    )
    run_parser.add_argument("--hosted-responses", type=Path)
    run_parser.add_argument("--hosted-responses-json")
    run_parser.add_argument("--resume", action="store_true")
    run_parser.add_argument("--incarnation-id")
    run_parser.add_argument("--platform-release-sha256")
    run_parser.add_argument(
        "--stop-after",
        choices=STAGE_ORDER,
    )
    run_parser.add_argument("--release-version", default=DEFAULT_RELEASE_VERSION)
    run_parser.add_argument("--workflow-version", default=DEFAULT_WORKFLOW_VERSION)
    run_parser.add_argument("--timeout", type=float, default=20.0)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    try:
        if args.command == "config":
            result = config_projection()
        elif args.command == "release":
            result = build_release(
                release_version=args.release_version,
                workflow_version=args.workflow_version,
            )
        else:
            result = run_command(args)
    except (ValueError, WorkspaceClientError, RuntimeError) as exc:
        print(
            json.dumps(
                {
                    "ok": False,
                    "error": type(exc).__name__,
                    "message": str(exc),
                },
                ensure_ascii=False,
            ),
            file=sys.stderr,
        )
        raise SystemExit(2) from exc
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
