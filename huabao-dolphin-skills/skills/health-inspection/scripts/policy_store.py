"""Pure health-policy validation and bounded runtime projections.

Policy version selection, activation claims, scheduling, durable storage, and
runtime-policy materialization belong to the Worktree Server. Dolphin only
reads and validates the immutable workspace artifact, then uses the bounded
projections defined here.
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
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


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
    published_sha256 = value.get("published_sha256")
    if (
        not isinstance(published_sha256, str)
        or SHA256_RE.fullmatch(published_sha256) is None
    ):
        raise PolicyValidationError(
            "published policy SHA-256 must be 64 lowercase hexadecimal characters"
        )
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
    recorded = value.get("sha256")
    if not isinstance(recorded, str) or SHA256_RE.fullmatch(recorded) is None:
        raise PolicyValidationError(
            "runtime policy SHA-256 must be 64 lowercase hexadecimal characters"
        )
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
        status = str(
            rule.get(
                "evaluation_status"
                if mode == "thresholds"
                else "legacy_evaluation_status"
            )
            or "monitor_only"
        )
        if status not in counts:
            raise PolicyValidationError(
                f"{rule['metric_id']}: invalid policy evaluation coverage status"
            )
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
        "published_sha256": str(value["published_sha256"]),
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


__all__ = [
    "METRIC_DESCRIPTION_MAX_LENGTH",
    "PolicyValidationError",
    "policy_activation_mode",
    "policy_evaluation_coverage",
    "policy_runtime_gate_projection",
    "validate_frozen_policy",
]
