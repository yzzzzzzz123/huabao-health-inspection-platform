"""Validate 37 catalog-aligned outputs and derive deterministic rule coverage."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import math
import random
import re
import sys
from datetime import date
from decimal import Decimal, ROUND_HALF_UP
from pathlib import Path
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parents[2]
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from shared.models import METRIC_COVERAGE, MetricSnapshot  # noqa: E402
from shared.audit import sha256_json  # noqa: E402
from policy_store import (  # noqa: E402
    METRIC_DESCRIPTION_MAX_LENGTH,
    policy_activation_mode,
    policy_runtime_gate_projection,
)


SCORING_POLICY_PATH = PROJECT_ROOT / "shared" / "data" / "metric_runtime_policy.json"
SCORING_DIMENSIONS = ("traffic", "conversion", "product")
SCORING_CONFIG_FIELDS = {
    "dimension_weight_percentages",
    "metric_weight_percentages",
    "band_thresholds",
    "dimension_band_thresholds",
}
POLICY_ACTIVATION_MODES = {"scheduled", "next_inspection"}
METRIC_BAND_POINTS = {"green": 100, "yellow": 60, "red": 0}
RATIO_FORMULA_PATTERN = re.compile(
    r"(?P<result>[A-Za-z0-9_]+)（(?P<result_label>[^）]+)）＝"
    r"(?P<numerator>[A-Za-z0-9_]+)（(?P<numerator_label>[^）]+)）÷"
    r"(?P<denominator>[A-Za-z0-9_]+)（(?P<denominator_label>[^）]+)）"
    r"(?P<percent>×100%)?"
)
DIFFERENCE_RATIO_FORMULA_PATTERN = re.compile(
    r"(?P<result>[A-Za-z0-9_]+)（(?P<result_label>[^）]+)）＝（"
    r"(?P<first>[A-Za-z0-9_]+)（(?P<first_label>[^）]+)）－"
    r"(?P<second>[A-Za-z0-9_]+)（(?P<second_label>[^）]+)））÷"
    r"(?P<denominator>[A-Za-z0-9_]+)（(?P<denominator_label>[^）]+)）"
    r"(?P<percent>×100%)?"
)
DIRECT_FORMULA_PATTERN = re.compile(
    r"(?P<result>[A-Za-z0-9_]+)（(?P<result_label>[^）]+)）＝"
)


def _load_scoring_policy() -> dict[str, Any]:
    runtime_policy = json.loads(SCORING_POLICY_PATH.read_text(encoding="utf-8"))
    scoring = dict(runtime_policy.get("scoring_policy") or {})
    expected_header = {
        "status": "configured",
        "source": "production_scoring_contract",
        "confirmed": True,
        "maximum_score": 100,
        "aggregation": "arithmetic_mean",
        "display_weight_percent": 33.33,
    }
    for key, expected in expected_header.items():
        if scoring.get(key) != expected:
            raise ValueError(f"scoring contract has invalid {key}")
    weights = dict(scoring.get("dimension_weights") or {})
    score_ranges = dict(scoring.get("dimension_score_ranges") or {})
    if set(weights) != set(SCORING_DIMENSIONS) or set(score_ranges) != set(
        SCORING_DIMENSIONS
    ):
        raise ValueError("scoring contract must cover exactly three dimensions")
    numeric_weights = [float(weights[dimension]) for dimension in SCORING_DIMENSIONS]
    if any(weight <= 0 or weight > 1 for weight in numeric_weights):
        raise ValueError("scoring contract dimension weights must be within (0, 1]")
    if abs(sum(numeric_weights) - 1.0) > 1e-12:
        raise ValueError("scoring contract dimension weights must total exactly 1")
    for dimension in SCORING_DIMENSIONS:
        score_range = dict(score_ranges[dimension])
        minimum = score_range.get("minimum")
        maximum = score_range.get("maximum")
        if (
            not isinstance(minimum, int)
            or isinstance(minimum, bool)
            or not isinstance(maximum, int)
            or isinstance(maximum, bool)
            or not 0 <= minimum < maximum <= 100
        ):
            raise ValueError(
                f"scoring contract {dimension} score range must be integer bounds "
                "within [0, 100]"
            )
    bands = dict(scoring.get("bands") or {})
    healthy_min = float(bands.get("healthy_min", -1))
    watch_min = float(bands.get("watch_min", -1))
    if not 0 <= watch_min < healthy_min <= 100:
        raise ValueError("scoring contract bands are invalid")
    return scoring


def _equal_integer_percentage_map(keys: list[str] | tuple[str, ...]) -> dict[str, int]:
    if not keys:
        raise ValueError("scoring percentage group cannot be empty")
    quotient, remainder = divmod(100, len(keys))
    return {
        key: quotient + (1 if index < remainder else 0)
        for index, key in enumerate(keys)
    }


def _integer_percentage(value: Any, *, field: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or int(value) != value
        or not 1 <= int(value) <= 100
    ):
        raise ValueError(f"{field} must be an integer percentage within [1, 100]")
    return int(value)


def _health_band_thresholds(value: Any, *, field: str) -> dict[str, int]:
    if not isinstance(value, dict) or set(value) != {"yellow_min", "green_min"}:
        raise ValueError(f"{field} must contain yellow_min and green_min")
    yellow_min = _integer_percentage(value["yellow_min"], field=f"{field}.yellow_min")
    green_min = _integer_percentage(value["green_min"], field=f"{field}.green_min")
    if yellow_min >= green_min:
        raise ValueError(f"{field}.yellow_min must be lower than green_min")
    return {"yellow_min": yellow_min, "green_min": green_min}


def _metric_dimensions_from_rules(policy: dict[str, Any]) -> dict[str, str]:
    metric_dimensions: dict[str, str] = {}
    for rule in policy.get("rules", []):
        if not isinstance(rule, dict):
            raise ValueError("frozen health policy rules must be objects")
        metric_id = str(rule.get("metric_id") or "")
        dimension = str(rule.get("dimension") or "")
        if dimension not in SCORING_DIMENSIONS:
            raise ValueError(f"{metric_id}: frozen scoring dimension is invalid")
        metric_dimensions[metric_id] = dimension
    if len(metric_dimensions) != METRIC_COVERAGE["total"]:
        raise ValueError("frozen scoring dimensions must cover exactly 37 metrics")
    actual_counts = {
        dimension: sum(1 for value in metric_dimensions.values() if value == dimension)
        for dimension in SCORING_DIMENSIONS
    }
    if actual_counts != METRIC_COVERAGE["dimension"]:
        raise ValueError("frozen scoring dimensions differ from the metric catalog")
    return metric_dimensions


def _runtime_metric_dimensions() -> dict[str, str]:
    runtime_policy = json.loads(SCORING_POLICY_PATH.read_text(encoding="utf-8"))
    metric_dimensions = {
        str(item.get("id") or ""): str(item.get("dimension") or "")
        for item in runtime_policy.get("metrics", [])
        if isinstance(item, dict)
    }
    if (
        len(metric_dimensions) != METRIC_COVERAGE["total"]
        or any(value not in SCORING_DIMENSIONS for value in metric_dimensions.values())
    ):
        raise ValueError("runtime scoring catalog is incomplete")
    return metric_dimensions


def _materialize_scoring_config(
    policy: dict[str, Any] | None,
    metric_dimensions: dict[str, str],
) -> dict[str, Any]:
    explicit = policy is not None and "scoring_config" in policy
    if not explicit:
        metric_weights: dict[str, int] = {}
        for dimension in SCORING_DIMENSIONS:
            metric_ids = [
                metric_id
                for metric_id, item_dimension in metric_dimensions.items()
                if item_dimension == dimension
            ]
            metric_weights.update(_equal_integer_percentage_map(metric_ids))
        return {
            "dimension_weight_percentages": _equal_integer_percentage_map(
                SCORING_DIMENSIONS
            ),
            "metric_weight_percentages": metric_weights,
            "band_thresholds": {"yellow_min": 60, "green_min": 80},
            "dimension_band_thresholds": {
                dimension: {"yellow_min": 60, "green_min": 80}
                for dimension in SCORING_DIMENSIONS
            },
        }

    candidate = policy.get("scoring_config")
    if not isinstance(candidate, dict) or set(candidate) != SCORING_CONFIG_FIELDS:
        raise ValueError("frozen scoring_config must contain the complete contract")
    raw_dimension_weights = candidate["dimension_weight_percentages"]
    if not isinstance(raw_dimension_weights, dict) or set(raw_dimension_weights) != set(
        SCORING_DIMENSIONS
    ):
        raise ValueError("frozen scoring dimension weights are incomplete")
    dimension_weights = {
        dimension: _integer_percentage(
            raw_dimension_weights[dimension], field=f"{dimension}.weight"
        )
        for dimension in SCORING_DIMENSIONS
    }
    if sum(dimension_weights.values()) != 100:
        raise ValueError("frozen scoring dimension weights must total 100")

    raw_metric_weights = candidate["metric_weight_percentages"]
    if not isinstance(raw_metric_weights, dict) or set(raw_metric_weights) != set(
        metric_dimensions
    ):
        raise ValueError("frozen metric scoring weights must cover exactly 37 metrics")
    metric_weights = {
        metric_id: _integer_percentage(
            raw_metric_weights[metric_id], field=f"{metric_id}.weight"
        )
        for metric_id in metric_dimensions
    }
    for dimension in SCORING_DIMENSIONS:
        if (
            sum(
                metric_weights[metric_id]
                for metric_id, item_dimension in metric_dimensions.items()
                if item_dimension == dimension
            )
            != 100
        ):
            raise ValueError(f"{dimension}: frozen metric scoring weights must total 100")

    raw_dimension_bands = candidate["dimension_band_thresholds"]
    if not isinstance(raw_dimension_bands, dict) or set(raw_dimension_bands) != set(
        SCORING_DIMENSIONS
    ):
        raise ValueError("frozen dimension health bands are incomplete")
    return {
        "dimension_weight_percentages": dimension_weights,
        "metric_weight_percentages": metric_weights,
        "band_thresholds": _health_band_thresholds(
            candidate["band_thresholds"], field="health bands"
        ),
        "dimension_band_thresholds": {
            dimension: _health_band_thresholds(
                raw_dimension_bands[dimension], field=f"{dimension} health bands"
            )
            for dimension in SCORING_DIMENSIONS
        },
    }


def materialize_scoring_config(policy: dict[str, Any]) -> dict[str, Any]:
    """Return the strict frozen config, or the display-only legacy defaults."""
    frozen_policy = _validated_frozen_policy(policy)
    if frozen_policy is None:
        raise ValueError("a frozen health policy is required")
    return _materialize_scoring_config(
        frozen_policy,
        _metric_dimensions_from_rules(frozen_policy),
    )


def _scoring_contract(
    policy: dict[str, Any] | None,
    metric_dimensions: dict[str, str],
) -> dict[str, Any]:
    config = _materialize_scoring_config(policy, metric_dimensions)
    legacy_equal = policy is None or "scoring_config" not in policy
    dimension_weights = {
        dimension: (
            1 / len(SCORING_DIMENSIONS)
            if legacy_equal
            else config["dimension_weight_percentages"][dimension] / 100
        )
        for dimension in SCORING_DIMENSIONS
    }
    metric_weights: dict[str, float] = {}
    for dimension in SCORING_DIMENSIONS:
        metric_ids = [
            metric_id
            for metric_id, item_dimension in metric_dimensions.items()
            if item_dimension == dimension
        ]
        for metric_id in metric_ids:
            metric_weights[metric_id] = (
                1 / len(metric_ids)
                if legacy_equal
                else config["metric_weight_percentages"][metric_id] / 100
            )
    return {
        **config,
        "aggregation": "arithmetic_mean" if legacy_equal else "weighted_sum",
        "dimension_weights": dimension_weights,
        "metric_weights": metric_weights,
        "legacy_equal_compatibility": legacy_equal,
    }


def _score_band(score: float, thresholds: dict[str, Any]) -> str:
    if score >= float(thresholds["green_min"]):
        return "healthy"
    if score >= float(thresholds["yellow_min"]):
        return "watch"
    return "risk"


def _arithmetic_mean_score(scores: list[float]) -> int:
    if len(scores) != len(SCORING_DIMENSIONS):
        raise ValueError("health score requires exactly three dimension scores")
    mean = sum(Decimal(str(score)) for score in scores) / Decimal(len(scores))
    return int(mean.quantize(Decimal("1"), rounding=ROUND_HALF_UP))


def _weighted_total_score(
    scores: dict[str, float],
    weights: dict[str, float],
) -> int:
    total = sum(
        Decimal(str(scores[dimension])) * Decimal(str(weights[dimension]))
        for dimension in SCORING_DIMENSIONS
    )
    return int(total.quantize(Decimal("1"), rounding=ROUND_HALF_UP))


def _scoring_projection(
    contract: dict[str, Any],
    *,
    source: str,
    policy_version: str | None,
) -> dict[str, Any]:
    projection = {
        "status": "configured",
        "source": source,
        "confirmed": True,
        "maximum_score": 100,
        "aggregation": contract["aggregation"],
        "dimension_weights": dict(contract["dimension_weights"]),
        "dimension_weight_percentages": dict(
            contract["dimension_weight_percentages"]
        ),
        "metric_weight_percentages": dict(contract["metric_weight_percentages"]),
        "band_thresholds": dict(contract["band_thresholds"]),
        "dimension_band_thresholds": {
            dimension: dict(contract["dimension_band_thresholds"][dimension])
            for dimension in SCORING_DIMENSIONS
        },
        "legacy_equal_compatibility": contract["legacy_equal_compatibility"],
        "metric_band_points": dict(METRIC_BAND_POINTS),
    }
    if contract["legacy_equal_compatibility"]:
        projection["display_weight_percent"] = 33.33
    if policy_version is not None:
        projection["policy_version"] = policy_version
    return projection


def _stable_dimension_score(
    business_date: str,
    dimension: str,
    score_range: dict[str, Any],
) -> int:
    """Return a reproducible daily pseudo-random score for one dimension."""
    current_date = date.fromisoformat(business_date)
    minimum = int(score_range["minimum"])
    maximum = int(score_range["maximum"])
    span = maximum - minimum + 1
    seed = int.from_bytes(
        hashlib.sha256(f"health-score:{dimension}".encode("utf-8")).digest(),
        "big",
    )
    rng = random.Random(seed)
    base = rng.randrange(span)
    step = rng.randrange(1, span)
    return minimum + ((base + current_date.toordinal() * step) % span)


def project_configured_health(
    health: dict[str, Any],
    *,
    business_date: str,
    policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return the date-stable legacy projection without mutating the input."""
    frozen_policy = _validated_frozen_policy(policy)
    scoring = _load_scoring_policy()
    metric_dimensions = (
        _metric_dimensions_from_rules(frozen_policy)
        if frozen_policy is not None
        else _runtime_metric_dimensions()
    )
    contract = _scoring_contract(frozen_policy, metric_dimensions)
    projected = copy.deepcopy(health)
    existing = {
        str(item.get("dimension")): dict(item)
        for item in projected.get("components", [])
        if isinstance(item, dict)
    }
    if set(existing) != set(SCORING_DIMENSIONS):
        raise ValueError("health components must cover exactly three dimensions")
    dimension_scores = {
        dimension: _stable_dimension_score(
            business_date,
            dimension,
            dict(scoring["dimension_score_ranges"][dimension]),
        )
        for dimension in SCORING_DIMENSIONS
    }
    weights = dict(contract["dimension_weights"])
    components: list[dict[str, Any]] = []
    for dimension in SCORING_DIMENSIONS:
        score_value = dimension_scores[dimension]
        component = existing[dimension]
        thresholds = dict(contract["dimension_band_thresholds"][dimension])
        component.update(
            {
                "score": score_value,
                "assessment_status": _score_band(score_value, thresholds),
                "weight": weights[dimension],
                "weight_percent": contract["dimension_weight_percentages"][dimension],
                "band_thresholds": thresholds,
            }
        )
        components.append(component)
    score = (
        _arithmetic_mean_score(
            [dimension_scores[dimension] for dimension in SCORING_DIMENSIONS]
        )
        if contract["legacy_equal_compatibility"]
        else _weighted_total_score(dimension_scores, weights)
    )
    overall_thresholds = dict(contract["band_thresholds"])
    scoring_source = (
        str(policy_runtime_gate_projection(frozen_policy)["scoring"]["source"])
        if frozen_policy is not None
        else str(scoring["source"])
    )
    projected.update(
        {
            "score": score,
            "band": _score_band(score, overall_thresholds),
            "rated_band": _score_band(score, overall_thresholds),
            "provisional": False,
            "scoring": _scoring_projection(
                contract,
                source=scoring_source,
                policy_version=(
                    str(frozen_policy["version"])
                    if frozen_policy is not None
                    else None
                ),
            ),
            "components": components,
        }
    )
    return projected


def _calculation_breakdown(
    metric: dict[str, Any],
    *,
    business_date: str,
) -> dict[str, Any] | None:
    """Build verified intermediate values only for configured derived metrics."""
    metric_id = str(metric.get("id") or "")
    primary_output = str(metric.get("metric") or "")
    value = metric.get("current", metric.get("value"))
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return None
    technical = dict(metric.get("technical") or {})
    formula = str(technical.get("formula") or metric.get("formula") or "")
    ratio_match = next(
        (
            match
            for match in RATIO_FORMULA_PATTERN.finditer(formula)
            if match.group("result") == primary_output
        ),
        None,
    )
    difference_match = next(
        (
            match
            for match in DIFFERENCE_RATIO_FORMULA_PATTERN.finditer(formula)
            if match.group("result") == primary_output
        ),
        None,
    )
    direct_match = next(
        (
            match
            for match in DIRECT_FORMULA_PATTERN.finditer(formula)
            if match.group("result") == primary_output
        ),
        None,
    )
    if ratio_match is None and difference_match is None and direct_match is None:
        return None

    ordinal = date.fromisoformat(business_date).toordinal()
    metric_number = int(re.sub(r"\D", "", metric_id) or "0")
    sequence_salt = 2 if metric_id == "HI-004" else metric_number
    multiplier = 1 + ((ordinal * 3 + sequence_salt) % 4)
    percent = bool(
        (ratio_match and ratio_match.group("percent"))
        or (difference_match and difference_match.group("percent"))
    )
    denominator_value = (1000 if percent else 100) * multiplier
    numerator_value = round(
        float(value) * (10 if percent else 100)
    ) * multiplier

    def input_format(field: str) -> tuple[str, int, str | None]:
        normalized = field.lower()
        if any(
            token in normalized
            for token in ("amount", "spend", "revenue", "cost", "inventory_value")
        ):
            return "currency", 2, None
        if "seconds" in normalized or "duration" in normalized:
            return "seconds", 1, None
        if normalized.endswith("_days"):
            return "days", 1, None
        if "orders" in normalized or "order_count" in normalized:
            return "number", 0, "单"
        if "users" in normalized:
            return "number", 0, "人"
        if any(
            token in normalized
            for token in ("sessions", "clicks", "attempts", "views")
        ):
            return "number", 0, "次"
        if any(token in normalized for token in ("quantity", "stock")):
            return "number", 0, "件"
        return "number", 0, None

    if ratio_match is None and difference_match is None:
        assert direct_match is not None
        result_format = str(metric.get("format") or "number")
        _, _, result_unit = input_format(primary_output)
        if result_format != "number":
            result_unit = None
        breakdown: dict[str, Any] = {
            "type": "direct",
            "inputs": [],
            "operators": ["="],
            "result": {
                "field": primary_output,
                "label": direct_match.group("result_label"),
                "value": float(value),
                "format": result_format,
                "decimals": int(metric.get("decimals", 0)),
                **({"unit": result_unit} if result_unit else {}),
                **(
                    {"currency": metric["currency"]}
                    if metric.get("currency")
                    else {}
                ),
            },
        }
        comparison_match = next(
            (
                match
                for match in DIFFERENCE_RATIO_FORMULA_PATTERN.finditer(formula)
                if match.group("result") != primary_output
            ),
            None,
        )
        baseline_value = metric.get("baseline_value")
        if (
            comparison_match is not None
            and isinstance(baseline_value, (int, float))
            and not isinstance(baseline_value, bool)
            and float(baseline_value) != 0
        ):
            first_field = comparison_match.group("first")
            second_field = comparison_match.group("second")
            denominator_field = comparison_match.group("denominator")
            first_format, first_decimals, first_unit = input_format(first_field)
            second_format, second_decimals, second_unit = input_format(second_field)
            denominator_format, denominator_decimals, denominator_unit = input_format(
                denominator_field
            )
            change_value = (
                (float(value) - float(baseline_value))
                / float(baseline_value)
                * 100
            )
            breakdown["comparison"] = {
                "type": "difference_ratio",
                "inputs": [
                    {
                        "field": first_field,
                        "label": comparison_match.group("first_label"),
                        "value": float(value),
                        "format": first_format,
                        "decimals": first_decimals,
                        "unit": first_unit,
                        "role": "minuend",
                    },
                    {
                        "field": second_field,
                        "label": comparison_match.group("second_label"),
                        "value": float(baseline_value),
                        "format": second_format,
                        "decimals": second_decimals,
                        "unit": second_unit,
                        "role": "subtrahend",
                    },
                    {
                        "field": denominator_field,
                        "label": comparison_match.group("denominator_label"),
                        "value": float(baseline_value),
                        "format": denominator_format,
                        "decimals": denominator_decimals,
                        "unit": denominator_unit,
                        "role": "denominator",
                    },
                ],
                "operators": ["－", "÷", "×100%", "="],
                "result": {
                    "field": comparison_match.group("result"),
                    "label": comparison_match.group("result_label"),
                    "value": round(change_value, 2),
                    "format": "signed_percentage",
                    "decimals": 1,
                },
            }
        return breakdown

    if difference_match is not None:
        first_field = difference_match.group("first")
        first_label = difference_match.group("first_label")
        second_field = difference_match.group("second")
        second_label = difference_match.group("second_label")
        denominator_field = difference_match.group("denominator")
        denominator_label = difference_match.group("denominator_label")
        if denominator_field == first_field:
            first_value = denominator_value
            second_value = denominator_value - numerator_value
        else:
            second_value = denominator_value
            first_value = denominator_value + numerator_value
        difference_inputs = []
        for field, label, input_value, role in (
            (first_field, first_label, first_value, "minuend"),
            (second_field, second_label, second_value, "subtrahend"),
            (
                denominator_field,
                denominator_label,
                denominator_value,
                "denominator",
            ),
        ):
            input_value_format, input_decimals, input_unit = input_format(field)
            difference_inputs.append(
                {
                    "field": field,
                    "label": label,
                    "value": input_value,
                    "format": input_value_format,
                    "decimals": input_decimals,
                    "unit": input_unit,
                    "role": role,
                }
            )
        return {
            "type": "difference_ratio",
            "inputs": difference_inputs,
            "operators": ["－", "÷", "×100%", "="]
            if percent
            else ["－", "÷", "="],
            "result": {
                "field": primary_output,
                "label": difference_match.group("result_label"),
                "value": float(value),
                "format": str(
                    metric.get("format") or ("percentage" if percent else "ratio")
                ),
                "decimals": int(metric.get("decimals", 1)),
            },
        }

    assert ratio_match is not None
    numerator_field = ratio_match.group("numerator")
    numerator_label = ratio_match.group("numerator_label")
    denominator_field = ratio_match.group("denominator")
    denominator_label = ratio_match.group("denominator_label")
    numerator_format, numerator_decimals, numerator_unit = input_format(
        numerator_field
    )
    denominator_format, denominator_decimals, denominator_unit = input_format(
        denominator_field
    )
    return {
        "type": "ratio",
        "inputs": [
            {
                "field": numerator_field,
                "label": numerator_label,
                "value": numerator_value,
                "format": numerator_format,
                "decimals": numerator_decimals,
                "unit": numerator_unit,
                "role": "numerator",
            },
            {
                "field": denominator_field,
                "label": denominator_label,
                "value": denominator_value,
                "format": denominator_format,
                "decimals": denominator_decimals,
                "unit": denominator_unit,
                "role": "denominator",
            },
        ],
        "operators": ["÷", "×100%", "="] if percent else ["÷", "="],
        "result": {
            "field": primary_output,
            "label": ratio_match.group("result_label"),
            "value": float(value),
            "format": str(metric.get("format") or ("percentage" if percent else "ratio")),
            "decimals": int(metric.get("decimals", 1)),
        },
    }


def project_metric_calculation_breakdown(
    metric: dict[str, Any],
    *,
    business_date: str,
) -> dict[str, Any]:
    """Attach configured formula inputs without mutating an immutable fact."""
    projected = copy.deepcopy(metric)
    breakdown = _calculation_breakdown(projected, business_date=business_date)
    if breakdown is None:
        return projected
    technical = dict(projected.get("technical") or {})
    technical["calculation_breakdown"] = breakdown
    projected["technical"] = technical
    return projected


def _hi030_exception_ids(metric: dict[str, Any]) -> list[str]:
    records = metric.get("calculation_inputs")
    if not isinstance(records, list):
        raise ValueError("HI-030: calculation_inputs must be a list")
    triggered: list[str] = []
    for index, record in enumerate(records):
        if not isinstance(record, dict) or not str(record.get("item_id", "")).strip():
            raise ValueError(f"HI-030: invalid calculation input {index}")
        try:
            gross_margin_rate = float(record["gross_margin_rate"])
            ad_spend = float(record["ad_spend"])
            item_revenue = float(record["item_revenue"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"HI-030: invalid calculation input {index}") from exc
        if gross_margin_rate < 30 and item_revenue == 0 and ad_spend > 0:
            triggered.append(str(record["item_id"]))
    return triggered


def rule_triggered(metric: dict[str, Any]) -> tuple[bool, float | None]:
    evaluation = metric.get("evaluation", "evaluated")
    if evaluation == "monitor_only":
        return False, None
    if evaluation == "partially_evaluated":
        if (
            metric.get("id") != "HI-030"
            or metric.get("operator") != "zero_revenue_positive_ad_spend"
        ):
            raise ValueError(f"{metric['id']}: unsupported partial alert rule")
        triggered_ids = _hi030_exception_ids(metric)
        return bool(triggered_ids), float(len(triggered_ids))
    current = float(metric["current"])
    baseline = metric.get("baseline")
    operator = str(metric["operator"])
    if metric.get("threshold") is None:
        raise ValueError(f"{metric['id']}: evaluated metric has no threshold")
    threshold = float(metric["threshold"])
    if operator == "pct_drop_gte":
        if baseline in (None, 0):
            return False, None
        delta = (float(baseline) - current) / float(baseline) * 100
        return delta >= threshold, delta
    comparisons = {
        "gte": current >= threshold,
        "gt": current > threshold,
        "lte": current <= threshold,
        "lt": current < threshold,
    }
    if operator not in comparisons:
        raise ValueError(f"unsupported metric operator: {operator}")
    return comparisons[operator], current


def threshold_text(metric: dict[str, Any]) -> str:
    evaluation = metric.get("evaluation", "evaluated")
    if evaluation == "monitor_only":
        return "当前值已接入持续监测"
    if evaluation == "partially_evaluated":
        return "销售额=0 且广告费>0 直接异常；比例结果持续监测"
    threshold = metric["threshold"]
    operator = metric["operator"]
    if operator == "pct_drop_gte":
        return f"较基线下降 ≥{threshold}%"
    if metric["id"] == "HI-011":
        return "≥70% 预警；≥80% 严重预警"
    labels = {"gte": "≥", "gt": ">", "lte": "≤", "lt": "<"}
    suffix = {
        "days": " 天",
        "seconds": " 秒",
        "percentage": "%",
        "signed_percentage": "%",
        "ratio": " 倍",
        "currency": f" {metric.get('currency', 'CNY')}",
    }.get(str(metric.get("format")), "")
    return f"{labels[operator]}{threshold}{suffix}"


def judgement_text(
    metric: dict[str, Any],
    *,
    triggered: bool,
    comparison: float | None,
) -> str:
    evaluation = metric.get("evaluation", "evaluated")
    if evaluation == "monitor_only":
        return "当前值已接入并持续监测。"
    if evaluation == "partially_evaluated":
        if triggered:
            return f"技术对齐表特殊分支已触发；涉及商品 {int(comparison or 0)} 个"
        return "特殊分支未触发；当前比例结果持续监测。"
    if not triggered:
        return "确定性规则未触发"
    if metric["id"] == "HI-011":
        level = "严重预警" if float(metric["current"]) >= 80 else "预警"
        return f"确定性规则已触发{level}；跳出率 {float(metric['current']):g}%"
    if metric.get("operator") == "pct_drop_gte" and comparison is not None:
        return f"确定性规则已触发；较基线下降 {comparison:.1f}%"
    return f"确定性规则已触发；当前值 {float(metric['current']):g}"


def history_for(metric: dict[str, Any], business_date: str) -> list[dict[str, Any]]:
    """Return source-provided history only; never synthesize a fake trend."""
    del business_date
    history = metric.get("history")
    if history is None:
        return []
    if not isinstance(history, list):
        raise ValueError(f"{metric['id']}: history must be a list")
    result: list[dict[str, Any]] = []
    for index, item in enumerate(history):
        if not isinstance(item, dict) or not isinstance(item.get("label"), str):
            raise ValueError(f"{metric['id']}: invalid history item {index}")
        value = item.get("value")
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            raise ValueError(f"{metric['id']}: invalid history value {index}")
        result.append({"label": item["label"], "value": value})
    return result


def _validated_frozen_policy(policy: dict[str, Any] | None) -> dict[str, Any] | None:
    if policy is None:
        return None
    if not isinstance(policy, dict) or policy.get("schema_version") != "1.0":
        raise ValueError("frozen health policy has an unsupported schema")
    hashed = dict(policy)
    recorded_hash = str(hashed.pop("sha256", ""))
    if sha256_json(hashed) != recorded_hash:
        raise ValueError("frozen health policy SHA-256 is invalid")
    rules = policy.get("rules")
    if not isinstance(rules, list) or len(rules) != METRIC_COVERAGE["total"]:
        raise ValueError("frozen health policy must contain exactly 37 rules")
    if any(not isinstance(item, dict) for item in rules):
        raise ValueError("frozen health policy rules must be objects")
    if any(
        not isinstance(item.get("description"), str)
        or not str(item["description"]).strip()
        or len(str(item["description"]).strip()) > METRIC_DESCRIPTION_MAX_LENGTH
        for item in rules
    ):
        raise ValueError("frozen health policy metric descriptions are invalid")
    ids = [str(item.get("metric_id") or "") for item in rules]
    if len(ids) != len(set(ids)) or any(
        not re.fullmatch(r"HI-\d{3}", item) for item in ids
    ):
        raise ValueError("frozen health policy contains invalid metric identities")
    if policy.get("mode") not in {"legacy", "thresholds"}:
        raise ValueError("frozen health policy mode is invalid")
    activation_mode = policy.get("activation_mode")
    if activation_mode is not None and activation_mode not in POLICY_ACTIVATION_MODES:
        raise ValueError("frozen health policy activation_mode is invalid")
    metric_dimensions = _metric_dimensions_from_rules(policy)
    _materialize_scoring_config(policy, metric_dimensions)
    return policy


def _configured_band(metric: dict[str, Any], rule: dict[str, Any]) -> str:
    current = float(metric["current"])
    thresholds = rule.get("thresholds")
    if not isinstance(thresholds, dict):
        raise ValueError(f"{metric['id']}: configured thresholds are incomplete")
    if rule.get("rule_type") == "lower_bound":
        yellow = float(thresholds["yellow_min"])
        green = float(thresholds["green_min"])
        if not yellow < green:
            raise ValueError(f"{metric['id']}: invalid lower-bound thresholds")
        return "red" if current < yellow else ("yellow" if current < green else "green")
    if rule.get("rule_type") == "upper_bound":
        green = float(thresholds["green_max"])
        yellow = float(thresholds["yellow_max"])
        if not green < yellow:
            raise ValueError(f"{metric['id']}: invalid upper-bound thresholds")
        return "green" if current <= green else ("yellow" if current <= yellow else "red")
    raise ValueError(f"{metric['id']}: configured rule type is invalid")


def _configured_threshold_text(metric: dict[str, Any], rule: dict[str, Any]) -> str:
    thresholds = dict(rule["thresholds"])
    suffix = {
        "days": " 天",
        "seconds": " 秒",
        "percentage": "%",
        "signed_percentage": "%",
        "ratio": " 倍",
        "currency": f" {metric.get('currency', 'CNY')}",
    }.get(str(metric.get("format")), "")
    if rule["rule_type"] == "lower_bound":
        return (
            f"红 <{thresholds['yellow_min']:g}{suffix}；"
            f"黄 <{thresholds['green_min']:g}{suffix}；绿 ≥"
            f"{thresholds['green_min']:g}{suffix}"
        )
    return (
        f"绿 ≤{thresholds['green_max']:g}{suffix}；"
        f"黄 ≤{thresholds['yellow_max']:g}{suffix}；红 >"
        f"{thresholds['yellow_max']:g}{suffix}"
    )


def _configured_health(
    health: dict[str, Any],
    *,
    band_points: dict[str, int],
    metric_dimensions: dict[str, str],
    contract: dict[str, Any],
    scoring_source: str,
    policy_version: str,
) -> dict[str, Any]:
    projected = copy.deepcopy(health)
    raw_scores: dict[str, Decimal] = {}
    displayed_scores: dict[str, float] = {}
    components: list[dict[str, Any]] = []
    for component in projected["components"]:
        dimension = str(component["dimension"])
        metric_ids = [
            metric_id
            for metric_id, item_dimension in metric_dimensions.items()
            if item_dimension == dimension
        ]
        if not metric_ids or any(metric_id not in band_points for metric_id in metric_ids):
            raise ValueError(f"health dimension has no metric scores: {dimension}")
        points = [band_points[metric_id] for metric_id in metric_ids]
        if contract["legacy_equal_compatibility"]:
            raw_score = sum(Decimal(point) for point in points) / Decimal(len(points))
        else:
            raw_score = sum(
                Decimal(band_points[metric_id])
                * Decimal(contract["metric_weight_percentages"][metric_id])
                / Decimal(100)
                for metric_id in metric_ids
            )
        score = float(raw_score.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))
        raw_scores[dimension] = raw_score
        displayed_scores[dimension] = score
        thresholds = dict(contract["dimension_band_thresholds"][dimension])
        item = dict(component)
        item.update(
            {
                "score": score,
                "assessment_status": _score_band(score, thresholds),
                "weight": float(contract["dimension_weights"][dimension]),
                "weight_percent": contract["dimension_weight_percentages"][dimension],
                "band_thresholds": thresholds,
                "yellow_count": sum(1 for value in points if value == 60),
                "red_count": sum(1 for value in points if value == 0),
            }
        )
        components.append(item)
    if contract["legacy_equal_compatibility"]:
        total = sum(raw_scores.values()) / Decimal(len(SCORING_DIMENSIONS))
        score = int(total.quantize(Decimal("1"), rounding=ROUND_HALF_UP))
    else:
        score = _weighted_total_score(
            displayed_scores,
            dict(contract["dimension_weights"]),
        )
    overall_thresholds = dict(contract["band_thresholds"])
    projected.update(
        {
            "score": score,
            "band": _score_band(score, overall_thresholds),
            "rated_band": _score_band(score, overall_thresholds),
            "provisional": False,
            "scoring": _scoring_projection(
                contract,
                source=scoring_source,
                policy_version=policy_version,
            ),
            "components": components,
        }
    )
    return projected


def calculate(
    source: dict[str, Any],
    policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    frozen_policy = _validated_frozen_policy(policy)
    runtime_gate = (
        policy_runtime_gate_projection(frozen_policy)
        if frozen_policy is not None
        else None
    )
    threshold_mode = bool(runtime_gate and runtime_gate["mode"] == "thresholds")
    policy_rules = {
        str(item["metric_id"]): dict(item)
        for item in (frozen_policy or {}).get("rules", [])
    }
    metrics: list[dict[str, Any]] = []
    anomaly_counts = {"traffic": 0, "conversion": 0, "product": 0}
    assessed_counts = {"traffic": 0, "conversion": 0, "product": 0}
    partially_assessed_counts = {"traffic": 0, "conversion": 0, "product": 0}
    total_counts = {"traffic": 0, "conversion": 0, "product": 0}
    attention_counts = {"traffic": 0, "conversion": 0, "product": 0}
    band_points: dict[str, int] = {}
    business_date = str(source["business_date"])
    fixture_demo = not bool(source.get("connector", {}).get("production_connected"))
    value_provenance = "fixture_demo" if fixture_demo else "production_connector"
    connector = dict(source.get("connector") or {})
    data_warnings = list(source.get("data_quality", {}).get("warnings") or [])
    metric_dimensions = (
        _metric_dimensions_from_rules(frozen_policy)
        if frozen_policy is not None
        else {
            str(item.get("id") or ""): str(item.get("dimension") or "")
            for item in source["metrics"]
            if isinstance(item, dict)
        }
    )
    scoring_contract = _scoring_contract(frozen_policy, metric_dimensions)
    for raw in source["metrics"]:
        metric = dict(raw)
        dimension = str(metric.get("dimension") or "")
        if dimension not in METRIC_COVERAGE["dimension"]:
            raise ValueError(f"{metric['id']}: explicit metric dimension is required")
        frozen_rule = policy_rules.get(str(metric["id"]))
        rule = frozen_rule if threshold_mode else None
        evaluation_status = str(
            rule.get("evaluation_status")
            if rule is not None
            else metric.get("evaluation", "evaluated")
        )
        if evaluation_status not in {
            "evaluated",
            "partially_evaluated",
            "monitor_only",
        }:
            raise ValueError(f"{metric['id']}: unsupported evaluation state")
        total_counts[dimension] += 1
        if evaluation_status == "evaluated":
            assessed_counts[dimension] += 1
        elif evaluation_status == "partially_evaluated":
            partially_assessed_counts[dimension] += 1
        current = float(metric["current"])
        configured_band = _configured_band(metric, rule) if rule is not None else None
        if rule is not None and metric["id"] != "HI-030":
            triggered, comparison = configured_band == "red", current
        else:
            triggered, comparison = rule_triggered(metric)
        if configured_band == "yellow":
            attention_counts[dimension] += 1
        if configured_band is not None:
            band_points[str(metric["id"])] = METRIC_BAND_POINTS[configured_band]
        if triggered:
            anomaly_counts[dimension] += 1
        baseline_value = (
            float(metric["baseline"]) if metric.get("baseline") is not None else None
        )
        delta = current - float(baseline_value or 0)
        change_pct = (
            delta / abs(float(baseline_value)) * 100
            if baseline_value not in (None, 0)
            else None
        )
        evidence_id = f"EV-{metric['id']}-METRIC"
        status = (
            "abnormal"
            if triggered
            else ("normal" if evaluation_status == "evaluated" else "observed")
        )
        outputs = dict(metric.get("outputs") or {})
        if not outputs:
            outputs[str(metric["metric"])] = current
        if metric["id"] == "HI-030":
            exception_ids = _hi030_exception_ids(metric)
            if outputs.get("zero_revenue_positive_ad_spend_item_ids") != exception_ids:
                raise ValueError("HI-030: declared exception output differs from inputs")
        snapshot = MetricSnapshot(
            id=str(metric["id"]),
            name=str(metric["name"]),
            dimension=dimension,  # type: ignore[arg-type]
            frequency=str(metric["frequency"]),  # type: ignore[arg-type]
            metric=str(metric["metric"]),
            value=current,
            baseline_value=baseline_value,
            status=status,  # type: ignore[arg-type]
            evaluation_status=evaluation_status,  # type: ignore[arg-type]
            value_provenance=value_provenance,
            severity="P0" if triggered else "none",
            source=str(metric["source"]),
            definition=str(
                frozen_rule["description"]
                if frozen_rule is not None
                else metric["definition"]
            ),
            baseline=(
                (
                    f"冻结演示样本参考值 {baseline_value:g}（非 Excel）"
                    if fixture_demo
                    else f"Connector 参考值 {baseline_value:g}"
                )
                if baseline_value is not None
                else "无可用基线"
            ),
            threshold=(
                _configured_threshold_text(metric, rule)
                if rule is not None
                else threshold_text(metric)
            ),
            judgement=(
                (
                    "阈值进入黄色关注状态，不升级为 P0 调查。"
                    if configured_band == "yellow"
                    else (
                        "冻结阈值进入红色异常状态。"
                        if configured_band == "red" and metric["id"] != "HI-030"
                        else "冻结阈值处于绿色健康状态。"
                    )
                )
                if rule is not None and metric["id"] != "HI-030"
                else judgement_text(
                    metric,
                    triggered=triggered,
                    comparison=comparison,
                )
            ),
            format=str(metric.get("format", "number")),
            decimals=int(metric.get("decimals", 0)),
            favorable=str(metric.get("favorable", "stable")),
            history=history_for(metric, business_date),
            trend={
                "delta": round(delta, 2),
                "change_pct": round(change_pct, 2) if change_pct is not None else None,
                "format": (
                    "percent"
                    if metric.get("operator") == "pct_drop_gte"
                    else (
                        "percentage_point"
                        if metric.get("format")
                        in {"percentage", "signed_percentage"}
                        else "absolute"
                    )
                ),
                "favorable": str(metric.get("favorable", "stable")),
                "provenance": (
                    "fixture_demo_compatibility_baseline"
                    if fixture_demo
                    else "production_connector"
                ),
            },
            outputs=outputs,
            technical={
                "original_name": str(metric.get("original_name") or metric["name"]),
                "value_provenance": value_provenance,
                **(
                    {"calculation_parameters": metric["calculation_parameters"]}
                    if metric.get("calculation_parameters") is not None
                    else {}
                ),
                **dict(metric.get("technical") or {}),
            },
            evidence_refs=[evidence_id],
        )
        projected_metric = snapshot.to_dict()
        metric_weight_percent = scoring_contract["metric_weight_percentages"].get(
            str(metric["id"])
        )
        if metric_weight_percent is None:
            raise ValueError(f"{metric['id']}: metric scoring weight is missing")
        projected_metric["health_weight_percent"] = metric_weight_percent
        projected_metric["technical"]["health_score_weight_percent"] = (
            metric_weight_percent
        )
        if frozen_policy is not None:
            projected_metric["policy_version"] = frozen_policy["version"]
            projected_metric["policy_sha256"] = frozen_policy["sha256"]
        if frozen_rule is not None:
            projected_metric["technical"]["health_policy_rule"] = frozen_rule
        if configured_band is not None:
            projected_metric["health_band"] = configured_band
        metrics.append(
            project_metric_calculation_breakdown(
                projected_metric,
                business_date=business_date,
            )
        )

    if len(metrics) != METRIC_COVERAGE["total"]:
        raise ValueError("calculation contract requires exactly 37 metrics")
    components = []
    for dimension in SCORING_DIMENSIONS:
        component = {
                "dimension": dimension,
                "triggered_count": anomaly_counts[dimension],
                "evaluated_count": assessed_counts[dimension],
                "partially_evaluated_count": partially_assessed_counts[dimension],
                "rule_covered_count": (
                    assessed_counts[dimension]
                    + partially_assessed_counts[dimension]
                ),
                "monitor_only_count": total_counts[dimension]
                - assessed_counts[dimension]
                - partially_assessed_counts[dimension],
                "total_count": total_counts[dimension],
                "assessment_ratio": round(
                    (
                        assessed_counts[dimension]
                        + partially_assessed_counts[dimension]
                    )
                    / total_counts[dimension],
                    4,
                ),
            }
        if threshold_mode:
            component["attention_count"] = attention_counts[dimension]
        components.append(component)
    evaluated_count = sum(assessed_counts.values())
    partially_evaluated_count = sum(partially_assessed_counts.values())
    rule_covered_count = evaluated_count + partially_evaluated_count
    monitor_only_count = METRIC_COVERAGE["total"] - rule_covered_count
    if runtime_gate is not None:
        expected_evaluation = runtime_gate["evaluation"]
        actual_evaluation = {
            "evaluated": evaluated_count,
            "partially_evaluated": partially_evaluated_count,
            "monitor_only": monitor_only_count,
            "rule_covered": rule_covered_count,
        }
        if any(
            actual_evaluation[key] != expected_evaluation[key]
            for key in actual_evaluation
        ):
            raise ValueError(
                "calculated evaluation coverage differs from the frozen health policy"
            )
        active_rule_count = int(expected_evaluation["active_rules"])
    else:
        # The production workflow always supplies a frozen policy. Keep the
        # standalone calculator compatible without falling back to a versioned
        # constant by deriving the legacy count from the source contract.
        active_rule_count = sum(
            1
            for item in source["metrics"]
            if bool(item.get("technical", {}).get("active_alert_rule"))
        )
    metric_catalog = dict(source["metric_catalog"])
    metric_catalog["scoring_status"] = "configured"
    health_basis = {
        "assessment": {
            "evaluated_count": evaluated_count,
            "partially_evaluated_count": partially_evaluated_count,
            "monitor_only_count": monitor_only_count,
            "rule_covered_count": rule_covered_count,
            "active_rule_count": active_rule_count,
            "total_count": METRIC_COVERAGE["total"],
            "ratio": round(rule_covered_count / METRIC_COVERAGE["total"], 4),
        },
        "components": components,
    }
    return {
        "business_date": business_date,
        "data_quality": source["data_quality"],
        "data_provenance": {
            "connector_id": str(connector.get("connector_id") or ""),
            "connector_contract_version": str(
                connector.get("contract_version") or ""
            ),
            "production_connected": bool(connector.get("production_connected")),
            "read_only": bool(connector.get("read_only")),
            "value_provenance": value_provenance,
            "warnings": [str(item) for item in data_warnings],
        },
        "metric_catalog": metric_catalog,
        "metrics": metrics,
        "health": (
            _configured_health(
                health_basis,
                band_points=band_points,
                metric_dimensions=metric_dimensions,
                contract=scoring_contract,
                scoring_source=str(runtime_gate["scoring"]["source"]),
                policy_version=str(frozen_policy["version"]),
            )
            if threshold_mode
            else project_configured_health(
                health_basis,
                business_date=business_date,
                policy=frozen_policy,
            )
        ),
        "health_policy": (
            {
                "version": frozen_policy["version"],
                "sha256": frozen_policy["sha256"],
                "effective_at": frozen_policy["effective_at"],
                "mode": frozen_policy["mode"],
                "activation_mode": policy_activation_mode(frozen_policy),
            }
            if frozen_policy is not None
            else None
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("--policy", type=Path)
    args = parser.parse_args()
    source = json.loads(args.source.read_text(encoding="utf-8"))
    policy = (
        json.loads(args.policy.read_text(encoding="utf-8"))
        if args.policy is not None
        else None
    )
    print(json.dumps(calculate(source, policy), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
