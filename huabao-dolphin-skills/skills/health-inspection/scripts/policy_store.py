"""Pure health-policy validation and bounded runtime projections.

Policy version selection, activation claims, scheduling, and durable storage
belong to the Worktree Server. Dolphin receives or creates one immutable policy
artifact and uses only the projections defined here.
"""

from __future__ import annotations

import json
import re
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from shared.audit import sha256_json  # noqa: E402
from shared.models import METRIC_COVERAGE  # noqa: E402


METRIC_DESCRIPTION_MAX_LENGTH = 500
ACTIVATION_MODES = {"scheduled", "next_inspection"}
POLICY_MODES = {"legacy", "thresholds"}
VERSION_RE = re.compile(r"^v1\.[0-9]+$")
METRIC_ID_RE = re.compile(r"^HI-[0-9]{3}$")


class PolicyValidationError(ValueError):
    """A frozen policy does not satisfy the Dolphin runtime contract."""


def policy_activation_mode(document: Mapping[str, Any]) -> str:
    mode = str(document.get("activation_mode") or "scheduled")
    if mode not in ACTIVATION_MODES:
        raise PolicyValidationError(
            "activation_mode must be scheduled or next_inspection"
        )
    return mode


def _rules(document: Mapping[str, Any]) -> list[dict[str, Any]]:
    value = document.get("rules")
    if not isinstance(value, list) or len(value) != METRIC_COVERAGE["total"]:
        raise PolicyValidationError("frozen policy must contain exactly 37 rules")
    rules = [dict(item) for item in value if isinstance(item, Mapping)]
    if len(rules) != len(value):
        raise PolicyValidationError("every policy rule must be an object")
    ids = [str(item.get("metric_id") or "") for item in rules]
    catalog = json.loads(
        (PROJECT_ROOT / "shared" / "data" / "metric_catalog.json").read_text(
            encoding="utf-8"
        )
    )
    expected_ids = [str(item["id"]) for item in catalog.get("metrics", [])]
    if (
        ids != expected_ids
        or len(set(ids)) != METRIC_COVERAGE["total"]
        or any(METRIC_ID_RE.fullmatch(item) is None for item in ids)
    ):
        raise PolicyValidationError(
            "policy rules must follow the unique HI-001 through HI-037 order"
        )
    for rule in rules:
        description = rule.get("description")
        if (
            not isinstance(description, str)
            or not description.strip()
            or len(description.strip()) > METRIC_DESCRIPTION_MAX_LENGTH
        ):
            raise PolicyValidationError(
                f"{rule.get('metric_id')}: invalid metric description"
            )
        if rule.get("dimension") not in METRIC_COVERAGE["dimension"]:
            raise PolicyValidationError(
                f"{rule.get('metric_id')}: invalid metric dimension"
            )
        status = rule.get("evaluation_status", "monitor_only")
        if status not in {"evaluated", "partially_evaluated", "monitor_only"}:
            raise PolicyValidationError(
                f"{rule.get('metric_id')}: invalid evaluation_status"
            )
    return rules


def validate_frozen_policy(document: Mapping[str, Any]) -> dict[str, Any]:
    value = dict(document)
    if value.get("schema_version") != "1.0":
        raise PolicyValidationError("unsupported policy schema")
    if VERSION_RE.fullmatch(str(value.get("version") or "")) is None:
        raise PolicyValidationError("invalid policy version")
    if value.get("mode") not in POLICY_MODES:
        raise PolicyValidationError("policy mode must be legacy or thresholds")
    policy_activation_mode(value)
    schedule = value.get("inspection_schedule")
    if (
        not isinstance(schedule, Mapping)
        or set(schedule) != {"time"}
        or re.fullmatch(
            r"(?:[01][0-9]|2[0-3]):[0-5][0-9]",
            str(schedule.get("time")),
        )
        is None
    ):
        raise PolicyValidationError("inspection_schedule.time must use HH:mm")
    rules = _rules(value)
    if value["mode"] == "thresholds":
        for rule in rules:
            if rule.get("rule_type") not in {"lower_bound", "upper_bound"}:
                raise PolicyValidationError(
                    f"{rule['metric_id']}: threshold rule_type is required"
                )
            if not isinstance(rule.get("thresholds"), Mapping):
                raise PolicyValidationError(
                    f"{rule['metric_id']}: thresholds are required"
                )
    recorded = str(value.get("sha256") or "")
    unhashed = dict(value)
    unhashed.pop("sha256", None)
    if recorded != sha256_json(unhashed):
        raise PolicyValidationError("frozen policy SHA-256 is invalid")
    return value


def policy_evaluation_coverage(document: Mapping[str, Any]) -> dict[str, int]:
    mode = str(document.get("mode") or "")
    rules = _rules(document)
    counts = {
        "evaluated": 0,
        "partially_evaluated": 0,
        "monitor_only": 0,
    }
    active = 0
    for rule in rules:
        status = str(rule.get("evaluation_status") or "monitor_only")
        counts[status] += 1
        if mode == "thresholds":
            active += int(rule.get("classification_enabled") is True)
        else:
            active += int(bool(rule.get("legacy_alert_rule")))
    return {
        **counts,
        "rule_covered": counts["evaluated"] + counts["partially_evaluated"],
        "active_rules": active,
    }


def policy_runtime_gate_projection(
    document: Mapping[str, Any],
) -> dict[str, Any]:
    value = validate_frozen_policy(document)
    mode = str(value["mode"])
    return {
        "version": str(value["version"]),
        "sha256": str(value["sha256"]),
        "effective_at": str(value["effective_at"]),
        "activation_mode": policy_activation_mode(value),
        "mode": mode,
        "inspection_schedule": dict(value["inspection_schedule"]),
        "evaluation": policy_evaluation_coverage(value),
        "scoring": {
            "status": "configured",
            "source": (
                "frozen_health_policy_thresholds"
                if mode == "thresholds"
                else "production_scoring_contract"
            ),
            "confirmed": True,
        },
    }


def build_default_frozen_policy() -> dict[str, Any]:
    """Build the bundled v1.0 policy for the first release and fixture E2E."""

    catalog_path = PROJECT_ROOT / "shared" / "data" / "metric_catalog.json"
    runtime_path = PROJECT_ROOT / "shared" / "data" / "metric_runtime_policy.json"
    catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
    runtime = json.loads(runtime_path.read_text(encoding="utf-8"))
    runtime_by_id = {
        str(item["id"]): dict(item) for item in runtime.get("metrics", [])
    }
    fixture_by_id: dict[str, dict[str, Any]] = {}
    fixture_root = PROJECT_ROOT / "shared" / "data" / "fixtures"
    for name in ("traffic", "conversion", "product"):
        block = json.loads((fixture_root / f"{name}.json").read_text(encoding="utf-8"))
        fixture_by_id.update(
            {str(item["id"]): dict(item) for item in block.get("metrics", [])}
        )
    rules: list[dict[str, Any]] = []
    for metric in catalog.get("metrics", []):
        metric_id = str(metric["id"])
        runtime_metric = runtime_by_id.get(metric_id)
        if runtime_metric is None:
            raise PolicyValidationError(f"{metric_id}: runtime metadata is missing")
        fixture_metric = fixture_by_id.get(metric_id)
        if fixture_metric is None:
            raise PolicyValidationError(f"{metric_id}: fixture metadata is missing")
        rules.append(
            {
                "metric_id": metric_id,
                "position": int(metric["position"]),
                "dimension": str(metric["dimension"]),
                "name": str(metric["name"]),
                "description": str(metric["definition"]).strip(),
                "frequency": str(runtime_metric["frequency"]),
                "primary_output": str(runtime_metric["primary_output"]),
                "output_keys": list(runtime_metric["output_keys"]),
                "source": str(fixture_metric["source"]),
                "format": str(fixture_metric.get("format") or "number"),
                "precision": int(fixture_metric.get("decimals") or 0),
                "favorable": str(fixture_metric.get("favorable") or "stable"),
                "evaluation_status": str(
                    runtime_metric.get("evaluation_status") or "monitor_only"
                ),
                "legacy_evaluation_status": str(
                    runtime_metric.get("evaluation_status") or "monitor_only"
                ),
                "legacy_alert_rule": runtime_metric.get("active_alert_rule"),
            }
        )
    value: dict[str, Any] = {
        "schema_version": "1.0",
        "version": "v1.0",
        "effective_at": "2026-01-01T00:00:00+08:00",
        "activation_mode": "scheduled",
        "mode": "legacy",
        "inspection_schedule": {"time": "09:00"},
        "rules": rules,
    }
    value["sha256"] = sha256_json(value)
    return validate_frozen_policy(value)


__all__ = [
    "METRIC_DESCRIPTION_MAX_LENGTH",
    "PolicyValidationError",
    "build_default_frozen_policy",
    "policy_activation_mode",
    "policy_evaluation_coverage",
    "policy_runtime_gate_projection",
    "validate_frozen_policy",
]
