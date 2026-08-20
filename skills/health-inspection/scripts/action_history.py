"""Pure +1/+6 anomaly review projections from one API-supplied run context."""

from __future__ import annotations

import re
from datetime import date, timedelta
from typing import Any

from shared.audit import sha256_json


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
RUN_ID_RE = re.compile(r"^hi-(\d{4}-\d{2}-\d{2})$")


def _metric_map(facts: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {str(item["id"]): dict(item) for item in facts.get("metrics", [])}


def due_review_window(source_date: str, observed_date: str) -> str | None:
    interval = (
        date.fromisoformat(observed_date) - date.fromisoformat(source_date)
    ).days
    return {1: "next_day", 6: "day_7"}.get(interval)


def validate_run_context(
    *,
    run_context: dict[str, Any],
    expected_binding: dict[str, str],
) -> list[dict[str, Any]]:
    """Validate the server-owned bounded history projection and return its rows."""

    required_binding = (
        "run_id",
        "business_date",
        "incarnation_id",
        "platform_release_sha256",
    )
    if run_context.get("schema_version") != "1.0":
        raise ValueError("run_context schema_version must be 1.0")
    if run_context.get("workspace_version") != "2.0":
        raise ValueError("run_context workspace_version must be 2.0")
    for key in required_binding:
        if run_context.get(key) != expected_binding[key]:
            raise ValueError(f"run_context binding mismatch: {key}")
    scope = run_context.get("scope")
    if not isinstance(scope, dict) or scope.get("timezone") != "Asia/Shanghai":
        raise ValueError("run_context scope must bind Asia/Shanghai")
    if scope.get("currency") != "CNY" or scope.get("dimensions") != [
        "traffic",
        "conversion",
        "product",
    ]:
        raise ValueError("run_context scope differs from the fixed business scope")

    current_date = date.fromisoformat(expected_binding["business_date"])
    query = run_context.get("historical_query")
    if not isinstance(query, dict):
        raise ValueError("run_context historical_query must be an object")
    expected_dates = [
        (current_date - timedelta(days=1)).isoformat(),
        (current_date - timedelta(days=6)).isoformat(),
    ]
    if (
        query.get("schema_version") != "1.0"
        or query.get("timezone") != "Asia/Shanghai"
        or query.get("maximum_date_identities") != 7
        or query.get("trigger_offsets_days") != [1, 6]
        or query.get("queried_business_dates") != expected_dates
    ):
        raise ValueError("run_context historical_query differs from the bounded contract")

    historical_runs = run_context.get("historical_runs")
    if not isinstance(historical_runs, list) or len(historical_runs) > 7:
        raise ValueError("run_context historical_runs exceeds the seven-date boundary")
    seen: set[tuple[str, str, str]] = set()
    for item in historical_runs:
        if not isinstance(item, dict):
            raise ValueError("historical run projection must be an object")
        source_run_id = item.get("source_run_id")
        source_date = item.get("source_business_date")
        match = RUN_ID_RE.fullmatch(str(source_run_id))
        if match is None or match.group(1) != source_date:
            raise ValueError("historical run identity is invalid")
        expected_window = due_review_window(str(source_date), current_date.isoformat())
        expected_age = {"next_day": 1, "day_7": 6}.get(expected_window)
        if (
            expected_window is None
            or item.get("review_window") != expected_window
            or item.get("age_days") != expected_age
        ):
            raise ValueError("historical run age/window binding is invalid")
        for key in (
            "platform_release_sha256",
            "archive_manifest_sha256",
            "facts_sha256",
        ):
            if SHA256_RE.fullmatch(str(item.get(key))) is None:
                raise ValueError(f"historical run has invalid {key}")
        facts = item.get("facts")
        if (
            not isinstance(facts, dict)
            or facts.get("run_id") != source_run_id
            or facts.get("business_date") != source_date
        ):
            raise ValueError("historical facts identity is invalid")
        action_plan = item.get("action_plan")
        action_plan_sha = item.get("action_plan_sha256")
        if (action_plan is None) != (action_plan_sha is None):
            raise ValueError("historical action plan and SHA must be both present or null")
        if action_plan is not None:
            if not isinstance(action_plan, dict) or SHA256_RE.fullmatch(
                str(action_plan_sha)
            ) is None:
                raise ValueError("historical action plan projection is invalid")
            if (
                action_plan.get("run_id") != source_run_id
                or action_plan.get("business_date") != source_date
            ):
                raise ValueError("historical action plan identity is invalid")
        identity = (str(source_run_id), str(source_date), str(expected_window))
        if identity in seen:
            raise ValueError("historical run projection contains a duplicate")
        seen.add(identity)
    return historical_runs


def _expected_direction(
    *,
    action_plan: dict[str, Any] | None,
    anomaly_id: str,
    metric_id: str,
) -> str:
    directions: list[str] = []
    if action_plan is not None:
        for action in action_plan.get("actions", []):
            if anomaly_id not in action.get("anomaly_ids", []):
                continue
            for item in action.get("expected_improvement", []):
                if item.get("metric_id") == metric_id:
                    direction = item.get("direction")
                    if direction in {"increase", "decrease", "stabilize"}:
                        directions.append(direction)
    return directions[0] if directions and len(set(directions)) == 1 else "stabilize"


def _alignment(direction: str, change: float | None) -> str:
    if change is None or direction == "stabilize":
        return "insufficient_data"
    if change == 0:
        return "unchanged"
    aligned = (direction == "increase" and change > 0) or (
        direction == "decrease" and change < 0
    )
    return "aligned" if aligned else "opposed"


def build_due_effect_reviews(
    *,
    current_facts: dict[str, Any],
    historical_runs: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Build deterministic review facts without scanning history or storage."""

    if len(historical_runs) > 7:
        raise ValueError("historical projection exceeds the seven-date boundary")
    current_date = str(current_facts["business_date"])
    current_metrics = _metric_map(current_facts)
    current_anomalies = {
        item["anomaly_id"] for item in current_facts.get("anomalies", [])
    }
    reviews: list[dict[str, Any]] = []
    for historical in historical_runs:
        source_date = str(historical["source_business_date"])
        window = due_review_window(source_date, current_date)
        if (
            window is None
            or historical.get("review_window") != window
            or historical.get("age_days") != {"next_day": 1, "day_7": 6}[window]
        ):
            raise ValueError("historical review window is inconsistent")
        source_facts = historical["facts"]
        source_metrics = _metric_map(source_facts)
        action_plan = historical.get("action_plan")
        for anomaly in source_facts.get("anomalies", []):
            metric_id = str(anomaly["metric_id"])
            baseline = source_metrics.get(metric_id)
            current = current_metrics.get(metric_id)
            if baseline is None or current is None:
                continue
            baseline_value = baseline.get("value")
            current_value = current.get("value")
            absolute_change = (
                round(float(current_value) - float(baseline_value), 4)
                if isinstance(current_value, (int, float))
                and isinstance(baseline_value, (int, float))
                else None
            )
            percentage_change = (
                round(absolute_change / abs(float(baseline_value)) * 100, 4)
                if absolute_change is not None and float(baseline_value) != 0
                else None
            )
            direction = _expected_direction(
                action_plan=action_plan,
                anomaly_id=str(anomaly["anomaly_id"]),
                metric_id=metric_id,
            )
            alignment = _alignment(direction, absolute_change)
            projection = {
                "review_key": (
                    f"{historical['source_run_id']}:{anomaly['anomaly_id']}:{window}"
                ),
                "source_run_id": historical["source_run_id"],
                "source_business_date": source_date,
                "anomaly_id": anomaly["anomaly_id"],
                "anomaly_title": anomaly["summary"],
                "review_window": window,
                "scheduled_review_date": current_date,
                "observed_business_date": current_date,
                "actual_interval_days": {"next_day": 1, "day_7": 6}[window],
                "baseline_observed_date": source_date,
                "metric_comparisons": [
                    {
                        "metric_id": metric_id,
                        "metric_name": current["name"],
                        "format": current.get("format", "number"),
                        "expected_direction": direction,
                        "baseline": {
                            "business_date": source_date,
                            "value": baseline_value,
                            "status": baseline["status"],
                            "anomaly_active": True,
                        },
                        "next_day": None,
                        "current": {
                            "business_date": current_date,
                            "value": current_value,
                            "status": current["status"],
                            "anomaly_active": anomaly["anomaly_id"]
                            in current_anomalies,
                        },
                        "absolute_change": absolute_change,
                        "percentage_change": percentage_change,
                        "direction_aligned": (
                            True
                            if alignment == "aligned"
                            else False if alignment == "opposed" else None
                        ),
                    }
                ],
                "anomaly_state": (
                    "persistent"
                    if anomaly["anomaly_id"] in current_anomalies
                    else "resolved"
                ),
                "direction_alignment": alignment,
                "deterministic_data_status": (
                    "sufficient" if absolute_change is not None else "insufficient"
                ),
            }
            projection["projection_sha256"] = sha256_json(projection)
            reviews.append(projection)
    return reviews


__all__ = [
    "build_due_effect_reviews",
    "due_review_window",
    "validate_run_context",
]
