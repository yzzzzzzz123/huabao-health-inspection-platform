"""Fixture implementation of the same contract future APIs will implement."""

from __future__ import annotations

import hashlib
import json
import random
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

from .base import ConnectorMetadata
from ...models import METRIC_COVERAGE


def _catalog_manifest(catalog: dict[str, Any]) -> dict[str, Any]:
    """Return the release-stable catalog identity without a workbook dependency."""

    return {
        "schema_version": catalog.get("schema_version"),
        "metric_count": catalog.get("metric_count"),
        "dimension_counts": catalog.get("dimension_counts"),
        "metrics": [
            {
                "id": item.get("id"),
                "position": item.get("position"),
                "dimension": item.get("dimension"),
            }
            for item in catalog.get("metrics", [])
        ],
    }


def _canonical_sha256(value: Any) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


_VALUE_RANGES: dict[str, tuple[float, float]] = {
    "HI-001": (720, 1450),
    "HI-002": (-18, 18),
    "HI-003": (420, 950),
    "HI-004": (78, 99),
    "HI-005": (38, 72),
    "HI-006": (140, 420),
    "HI-007": (260, 720),
    "HI-008": (18, 42),
    "HI-009": (48, 72),
    "HI-010": (720, 1600),
    "HI-011": (52, 86),
    "HI-012": (-18, 18),
    "HI-013": (8, 22),
    "HI-014": (68, 92),
    "HI-015": (1.5, 9.5),
    "HI-016": (1.2, 4.2),
    "HI-017": (2.8, 6.4),
    "HI-018": (1.5, 8),
    "HI-019": (1.8, 5.5),
    "HI-020": (1.5, 5),
    "HI-021": (28, 58),
    "HI-022": (0, 12),
    "HI-023": (40, 360),
    "HI-024": (0, 8),
    "HI-025": (0, 10),
    "HI-026": (0, 6),
    "HI-027": (0, 7),
    "HI-028": (0, 6),
    "HI-029": (2.5, 7),
    "HI-030": (4, 18),
    "HI-031": (60, 240),
    "HI-032": (4, 18),
    "HI-033": (0, 8),
    "HI-034": (0, 10),
    "HI-035": (1.2, 4.5),
    "HI-036": (48, 96),
    "HI-037": (8000, 75000),
}


# Daily values remain date-stable and pseudo-random, while this seven-day cycle
# guarantees that the frozen connector exercises both evidence boundaries used
# by the business workflow.  The profile describes source evidence quality; it
# never dictates a diagnosis or suggestion type to an Agent.
_TRAFFIC_EVIDENCE_PROFILE_BY_WEEKDAY = {
    # Tuesday is the closed-loop scenario used to exercise a bounded,
    # reversible manual adjustment and its +1 / +6 effect reviews.
    1: "reconciled_paid_campaign_state",
    # Saturday keeps the contrasting evidence-incomplete boundary covered.
    5: "unreconciled_multi_channel_change",
}


def _traffic_evidence_profile(business_date: str) -> str:
    return _TRAFFIC_EVIDENCE_PROFILE_BY_WEEKDAY.get(
        date.fromisoformat(business_date).weekday(),
        "sampled_channel_change",
    )


def _apply_traffic_coverage_profile(
    sample: dict[str, Any],
    business_date: str,
) -> None:
    """Keep random daily values while guaranteeing bounded HI-001 coverage."""
    if str(sample["id"]) != "HI-001":
        return
    profile = _traffic_evidence_profile(business_date)
    sample["snapshot_evidence_profile"] = profile
    if profile == "reconciled_paid_campaign_state":
        baseline = int(
            _sample_number(
                business_date,
                "HI-001",
                "coverage.reconciled.baseline",
                1200,
                1400,
                0,
            )
        )
        drop_rate = float(
            _sample_number(
                business_date,
                "HI-001",
                "coverage.reconciled.drop_rate",
                35,
                40,
                1,
            )
        )
        sample["baseline"] = baseline
        sample["current"] = round(baseline * (1 - drop_rate / 100))
    elif profile == "unreconciled_multi_channel_change":
        baseline = int(
            _sample_number(
                business_date,
                "HI-001",
                "coverage.unreconciled.baseline",
                1100,
                1400,
                0,
            )
        )
        drop_rate = float(
            _sample_number(
                business_date,
                "HI-001",
                "coverage.unreconciled.drop_rate",
                30,
                34,
                1,
            )
        )
        sample["baseline"] = baseline
        sample["current"] = round(baseline * (1 - drop_rate / 100))


def _rng(business_date: str, metric_id: str, field_path: str) -> random.Random:
    seed = hashlib.sha256(
        f"{business_date}:{metric_id}:{field_path}".encode("utf-8")
    ).digest()
    return random.Random(int.from_bytes(seed, "big"))


def _sample_number(
    business_date: str,
    metric_id: str,
    field_path: str,
    lower: float,
    upper: float,
    decimals: int,
) -> int | float:
    scale = 10**decimals
    lower_units = round(lower * scale)
    upper_units = round(upper * scale)
    span = upper_units - lower_units + 1
    if span <= 1:
        return (
            int(lower_units)
            if decimals == 0
            else round(lower_units / scale, decimals)
        )
    field_seed = hashlib.sha256(
        f"{metric_id}:{field_path}".encode("utf-8")
    ).digest()
    base = int.from_bytes(field_seed[:16], "big") % span
    step = 1 + int.from_bytes(field_seed[16:], "big") % (span - 1)
    if span > 20 and step < span // 10:
        step += span // 3
    offset = (base + date.fromisoformat(business_date).toordinal() * step) % span
    value = lower_units + offset
    return int(value) if decimals == 0 else round(value / scale, decimals)


def _metric_value(
    sample: dict[str, Any],
    business_date: str,
    field_path: str,
) -> int | float:
    metric_id = str(sample["id"])
    lower, upper = _VALUE_RANGES[metric_id]
    return _sample_number(
        business_date,
        metric_id,
        field_path,
        lower,
        upper,
        int(sample.get("decimals", 0)),
    )


def _percentage_partition(
    *,
    business_date: str,
    metric_id: str,
    field_path: str,
    fixed_first: float,
    remaining_count: int,
) -> list[float]:
    remainder = round(100.0 - fixed_first, 1)
    generator = _rng(business_date, metric_id, field_path)
    weights = [generator.uniform(0.6, 1.4) for _ in range(remaining_count)]
    result: list[float] = []
    allocated = 0.0
    for index, weight in enumerate(weights):
        if index == remaining_count - 1:
            value = round(remainder - allocated, 1)
        else:
            value = round(remainder * weight / sum(weights), 1)
            allocated = round(allocated + value, 1)
        result.append(value)
    return result


def _randomize_outputs(sample: dict[str, Any], business_date: str) -> None:
    metric_id = str(sample["id"])
    current = sample["current"]
    baseline = sample["baseline"]
    outputs = sample.get("outputs")
    if not isinstance(outputs, dict):
        return

    if metric_id == "HI-001":
        outputs["total_sessions"] = current
        outputs["traffic_change_rate"] = round(
            (float(current) - float(baseline)) / float(baseline) * 100, 1
        )
        outputs["country_breakdown"][0]["total_sessions"] = current
    elif metric_id == "HI-008":
        rows = outputs["channel_session_share"]
        shares = _percentage_partition(
            business_date=business_date,
            metric_id=metric_id,
            field_path="outputs.channel_session_share",
            fixed_first=float(current),
            remaining_count=len(rows) - 1,
        )
        rows[0]["value"] = current
        for row, share in zip(rows[1:], shares, strict=True):
            row["value"] = share
    elif metric_id == "HI-009":
        rows = outputs["device_session_share"]
        shares = _percentage_partition(
            business_date=business_date,
            metric_id=metric_id,
            field_path="outputs.device_session_share",
            fixed_first=float(current),
            remaining_count=len(rows) - 1,
        )
        rows[0]["value"] = current
        for row, share in zip(rows[1:], shares, strict=True):
            row["value"] = share
    elif metric_id == "HI-010":
        rows = outputs["landing_page_sessions"]
        first = _sample_number(
            business_date,
            metric_id,
            "outputs.landing_page_sessions.0.sessions",
            float(current) * 0.55,
            float(current) * 0.72,
            0,
        )
        rows[0]["sessions"] = first
        rows[1]["sessions"] = int(current) - int(first)
    elif metric_id == "HI-012":
        rows = outputs["source_session_change_rate"]
        rows[0]["value"] = current
        for index, row in enumerate(rows[1:], start=1):
            row["value"] = _sample_number(
                business_date,
                metric_id,
                f"outputs.source_session_change_rate.{index}.value",
                -16,
                16,
                1,
            )
    elif metric_id == "HI-014":
        outputs["checkout_completion_rate"] = current
        outputs["checkout_abandonment_rate"] = round(100 - float(current), 1)
        outputs["cart_to_checkout_rate"] = _sample_number(
            business_date,
            metric_id,
            "outputs.cart_to_checkout_rate",
            58,
            84,
            1,
        )
    elif metric_id == "HI-015":
        outputs["payment_failure_rate"] = current
        for key in ("gateway_failure_rate", "payment_method_failure_rate"):
            for index, row in enumerate(outputs[key]):
                row["value"] = _sample_number(
                    business_date,
                    metric_id,
                    f"outputs.{key}.{index}.value",
                    max(0.2, float(current) - 1.8),
                    min(15, float(current) + 1.8),
                    1,
                )
        reason_rows = outputs["failure_reason_share"]
        first_reason = _sample_number(
            business_date,
            metric_id,
            "outputs.failure_reason_share.0.value",
            45,
            72,
            1,
        )
        reason_shares = _percentage_partition(
            business_date=business_date,
            metric_id=metric_id,
            field_path="outputs.failure_reason_share",
            fixed_first=float(first_reason),
            remaining_count=len(reason_rows) - 1,
        )
        reason_rows[0]["value"] = first_reason
        for row, share in zip(reason_rows[1:], reason_shares, strict=True):
            row["value"] = share
    elif metric_id == "HI-036":
        outputs["checkout_duration_p95_seconds"] = current
        outputs["checkout_sample_count"] = _sample_number(
            business_date,
            metric_id,
            "outputs.checkout_sample_count",
            250,
            1200,
            0,
        )
    elif metric_id == "HI-019":
        rows = outputs["item_metrics"]
        for index, row in enumerate(rows):
            purchase_rate = (
                current
                if index == 0
                else _sample_number(
                    business_date,
                    metric_id,
                    f"outputs.item_metrics.{index}.item_purchase_rate",
                    1.3,
                    5.2,
                    1,
                )
            )
            row["item_purchase_rate"] = purchase_rate
            row["item_add_to_cart_rate"] = _sample_number(
                business_date,
                metric_id,
                f"outputs.item_metrics.{index}.item_add_to_cart_rate",
                max(4.0, float(purchase_rate) + 2),
                min(18, float(purchase_rate) + 8),
                1,
            )
            row["item_view_sessions"] = _sample_number(
                business_date,
                metric_id,
                f"outputs.item_metrics.{index}.item_view_sessions",
                90,
                420,
                0,
            )
    elif metric_id == "HI-020":
        rows = outputs["paid_channel_order_rate"]
        rows[0]["value"] = current
        for index, row in enumerate(rows[1:], start=1):
            row["value"] = _sample_number(
                business_date,
                metric_id,
                f"outputs.paid_channel_order_rate.{index}.value",
                1,
                5,
                1,
            )
    elif metric_id == "HI-023":
        outputs["out_of_stock_campaign_sessions"] = current
        rows = outputs["item_breakdown"]
        rows[0]["sessions"] = current
        rows[0]["sellable_stock_quantity"] = 0
    elif metric_id == "HI-029":
        rows = outputs["high_margin_revenue_per_ad_spend"]
        rows[0]["value"] = current
        for index, row in enumerate(rows[1:], start=1):
            row["value"] = _sample_number(
                business_date,
                metric_id,
                f"outputs.high_margin_revenue_per_ad_spend.{index}.value",
                2.2,
                7.2,
                1,
            )
    elif metric_id == "HI-030":
        records = sample["calculation_inputs"]
        first_revenue = _sample_number(
            business_date,
            metric_id,
            "calculation_inputs.0.item_revenue",
            350,
            1100,
            0,
        )
        first_spend = round(float(first_revenue) * float(current) / 100, 2)
        records[0].update(
            {
                "gross_margin_rate": _sample_number(
                    business_date,
                    metric_id,
                    "calculation_inputs.0.gross_margin_rate",
                    18,
                    29,
                    1,
                ),
                "ad_spend": first_spend,
                "item_revenue": first_revenue,
            }
        )
        trigger_special_branch = (
            _rng(business_date, metric_id, "calculation_inputs.1.trigger").random()
            < 0.35
        )
        records[1].update(
            {
                "gross_margin_rate": _sample_number(
                    business_date,
                    metric_id,
                    "calculation_inputs.1.gross_margin_rate",
                    18,
                    29,
                    1,
                ),
                "ad_spend": (
                    _sample_number(
                        business_date,
                        metric_id,
                        "calculation_inputs.1.ad_spend",
                        10,
                        90,
                        2,
                    )
                    if trigger_special_branch
                    else 0
                ),
                "item_revenue": 0,
            }
        )
        rows = outputs["low_margin_ad_spend_share"]
        rows[0]["value"] = current
        rows[1]["value"] = None
        rows[1]["reason"] = (
            "zero_revenue_positive_ad_spend"
            if trigger_special_branch
            else "zero_revenue_without_positive_ad_spend"
        )
        outputs["zero_revenue_positive_ad_spend_item_ids"] = (
            [str(records[1]["item_id"])] if trigger_special_branch else []
        )
    elif metric_id == "HI-031":
        rows = outputs["new_item_first_7d_sessions"]
        rows[0]["sessions"] = current
        for index, row in enumerate(rows[1:], start=1):
            row["sessions"] = _sample_number(
                business_date,
                metric_id,
                f"outputs.new_item_first_7d_sessions.{index}.sessions",
                40,
                220,
                0,
            )
    elif metric_id == "HI-032":
        rows = outputs["hot_item_available_days"]
        rows[0]["days"] = current
        for index, row in enumerate(rows[1:], start=1):
            row["days"] = _sample_number(
                business_date,
                metric_id,
                f"outputs.hot_item_available_days.{index}.days",
                2,
                18,
                1,
            )
    elif metric_id == "HI-035":
        outputs["inventory_turnover_times_180d"] = current
        outputs["sell_through_rate_180d"] = _sample_number(
            business_date,
            metric_id,
            "outputs.sell_through_rate_180d",
            35,
            82,
            1,
        )
    elif metric_id == "HI-037":
        item_count = int(
            _sample_number(
                business_date,
                metric_id,
                "outputs.slow_moving_item_count",
                1,
                8,
                0,
            )
        )
        outputs["slow_moving_inventory_value"] = {
            "amount": current,
            "currency": "CNY",
        }
        outputs["slow_moving_item_count"] = item_count
        outputs["slow_moving_item_ids"] = [
            f"SKU-SLOW-{index:03d}" for index in range(1, item_count + 1)
        ]


def _randomize_metric(sample: dict[str, Any], business_date: str) -> dict[str, Any]:
    metric_id = str(sample["id"])
    if metric_id not in _VALUE_RANGES:
        raise ValueError(f"daily value range is not configured: {metric_id}")
    randomized = json.loads(json.dumps(sample))
    randomized["current"] = _metric_value(randomized, business_date, "current")
    randomized["baseline"] = _metric_value(randomized, business_date, "baseline")
    _apply_traffic_coverage_profile(randomized, business_date)
    _randomize_outputs(randomized, business_date)
    return randomized


@dataclass(frozen=True)
class FixtureConnector:
    fixture_root: Path
    metadata: ConnectorMetadata = ConnectorMetadata(
        connector_id="huabao-site-daily-snapshot",
        contract_version="daily-health-input-v2",
        read_only=True,
        production_connected=False,
    )

    def _paths(self) -> tuple[Path, ...]:
        return tuple(self.fixture_root / f"{name}.json" for name in ("traffic", "conversion", "product"))

    def _catalog_path(self) -> Path:
        return self.fixture_root.parent / "metric_catalog.json"

    def _runtime_policy_path(self) -> Path:
        return self.fixture_root.parent / "metric_runtime_policy.json"

    def healthcheck(self) -> dict[str, Any]:
        paths = (*self._paths(), self._catalog_path(), self._runtime_policy_path())
        return {
            "status": "ready" if all(path.is_file() for path in paths) else "blocked",
            "connector_id": self.metadata.connector_id,
            "read_only": True,
            "files": [path.name for path in paths],
        }

    def fetch(self, *, business_date: str) -> dict[str, Any]:
        datetime.fromisoformat(business_date)
        blocks = [json.loads(path.read_text(encoding="utf-8")) for path in self._paths()]
        catalog = json.loads(self._catalog_path().read_text(encoding="utf-8"))
        runtime_policy = json.loads(
            self._runtime_policy_path().read_text(encoding="utf-8")
        )
        catalog_metrics = list(catalog.get("metrics", []))
        catalog_by_id = {str(item["id"]): item for item in catalog_metrics}
        runtime_metrics = list(runtime_policy.get("metrics", []))
        runtime_by_id = {str(item["id"]): item for item in runtime_metrics}
        if (
            catalog.get("metric_count") != METRIC_COVERAGE["total"]
            or catalog.get("dimension_counts") != METRIC_COVERAGE["dimension"]
            or len(catalog_by_id) != METRIC_COVERAGE["total"]
        ):
            raise ValueError("metric catalog coverage differs from the 37-metric contract")
        catalog_sha = str(catalog.get("source", {}).get("sha256", ""))
        manifest_sha = _canonical_sha256(_catalog_manifest(catalog))
        expected_manifest_sha = str(
            runtime_policy.get("metric_catalog_manifest_sha256") or ""
        )
        if manifest_sha != expected_manifest_sha:
            raise ValueError(
                "metric_catalog.json canonical manifest differs from runtime policy"
            )
        if (
            runtime_policy.get("workbook_catalog_sha256") != catalog_sha
            or len(runtime_by_id) != METRIC_COVERAGE["total"]
        ):
            raise ValueError("metric runtime policy differs from the workbook catalog")
        if [item["id"] for item in runtime_metrics] != [
            item["id"] for item in catalog_metrics
        ]:
            raise ValueError("metric runtime policy must follow workbook catalog order")
        dimensions = [block.get("dimension") for block in blocks]
        if dimensions != ["traffic", "conversion", "product"]:
            raise ValueError("fixture dimensions must be traffic, conversion, product in order")
        metrics: list[dict[str, Any]] = []
        sources: dict[str, dict[str, str]] = {}
        for block in blocks:
            dimension = str(block["dimension"])
            for sample in block.get("metrics", []):
                sample = _randomize_metric(sample, business_date)
                snapshot_evidence_profile = sample.pop(
                    "snapshot_evidence_profile",
                    None,
                )
                metric_id = str(sample.get("id"))
                specification = catalog_by_id.get(metric_id)
                runtime = runtime_by_id.get(metric_id)
                if specification is None or runtime is None:
                    raise ValueError(f"fixture metric is absent from catalog: {metric_id}")
                if specification.get("dimension") != dimension:
                    raise ValueError(f"fixture metric dimension drift: {metric_id}")
                if (
                    runtime.get("dimension") != dimension
                    or sample.get("frequency") != runtime.get("frequency")
                    or sample.get("metric") != runtime.get("primary_output")
                    or sample.get("evaluation") != runtime.get("evaluation_status")
                ):
                    raise ValueError(f"fixture runtime policy drift: {metric_id}")
                sample_outputs = sample.get("outputs")
                actual_output_keys = (
                    set(sample_outputs)
                    if isinstance(sample_outputs, dict) and sample_outputs
                    else {str(sample.get("metric"))}
                )
                if actual_output_keys != set(runtime.get("output_keys", [])):
                    raise ValueError(f"fixture output contract drift: {metric_id}")
                merged = dict(sample)
                merged.update(
                    {
                        "dimension": dimension,
                        "name": specification["name"],
                        "original_name": specification["original_name"],
                        "definition": specification["definition"],
                        "technical": {
                            "catalog_version": catalog["schema_version"],
                            "catalog_position": specification["position"],
                            "output_description": specification["output_description"],
                            "core_fields": specification["core_fields"],
                            "data_method": specification["data_method"],
                            "formula": specification["formula"],
                            "business_confirmation": specification[
                                "business_confirmation"
                            ],
                            "it_confirmation": specification["it_confirmation"],
                            "primary_output": runtime["primary_output"],
                            "output_keys": runtime["output_keys"],
                            "runtime_evaluation_status": runtime[
                                "evaluation_status"
                            ],
                            "active_alert_rule": runtime["active_alert_rule"],
                            **(
                                {
                                    "snapshot_evidence_profile": (
                                        snapshot_evidence_profile
                                    )
                                }
                                if snapshot_evidence_profile is not None
                                else {}
                            ),
                            "frequency_policy": runtime_policy["frequency_policy"],
                            "scoring_policy": runtime_policy["scoring_policy"],
                        },
                    }
                )
                metrics.append(merged)
            for source in block.get("source_info", []):
                sources[str(source["source_id"])] = dict(source)
        metric_ids = [str(item.get("id")) for item in metrics]
        expected_ids = [str(item["id"]) for item in catalog_metrics]
        if metric_ids != expected_ids or len(set(metric_ids)) != METRIC_COVERAGE["total"]:
            raise ValueError("fixture contract must follow the 37-row catalog order")
        cutoff = datetime.fromisoformat(business_date).replace(
            hour=3,
            minute=55,
            tzinfo=ZoneInfo("Asia/Shanghai"),
        )
        return {
            "schema_version": "1.0",
            "business_date": business_date,
            "scope_id": "huabao-site-health-inspection",
            "connector": {
                "connector_id": self.metadata.connector_id,
                "contract_version": self.metadata.contract_version,
                "read_only": self.metadata.read_only,
                "production_connected": self.metadata.production_connected,
            },
            "data_quality": {
                "status": "ready",
                "completeness_ratio": 1.0,
                "cutoff": cutoff.isoformat(),
                "warnings": [],
                "sources": list(sources.values()),
            },
            "metric_catalog": {
                "schema_version": catalog["schema_version"],
                "source": catalog["source"],
                "metric_count": catalog["metric_count"],
                "dimension_counts": catalog["dimension_counts"],
                "frequency_counts": METRIC_COVERAGE["frequency"],
                "frequency_provenance": "legacy_v1_compatibility",
                "frequency_confirmed": False,
                "runtime_policy_sha256": hashlib.sha256(
                    self._runtime_policy_path().read_bytes()
                ).hexdigest(),
                "catalog_manifest_sha256": manifest_sha,
                "scoring_status": "configured",
            },
            "metrics": metrics,
        }


def create_connector(fixture_root: Path) -> FixtureConnector:
    return FixtureConnector(fixture_root=fixture_root)
