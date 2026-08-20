"""Create anomaly candidates and the unique evidence catalog from calculations."""

from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo


RELATED_EVIDENCE: dict[str, list[dict[str, Any]]] = {
    "HI-011": [
        {
            "evidence_id": "EV-PAGE-DEVICE-BOUNCE",
            "kind": "segment_comparison",
            "title": "移动端跳出高于桌面端",
            "source": "GA4",
            "scope": "华宝新能站内 / all landing pages",
            "payload": {"mobile_bounce_rate": 78, "desktop_bounce_rate": 65},
        },
        {
            "evidence_id": "EV-PDP-LCP",
            "kind": "site_performance",
            "title": "商品详情页 LCP 偏慢",
            "source": "Site Monitoring",
            "scope": "华宝新能站内 / PDP",
            "payload": {"pdp_lcp_seconds": 4.2, "recommended_max_seconds": 2.5},
        },
    ],
    "HI-016": [
        {
            "evidence_id": "EV-MOBILE-FUNNEL",
            "kind": "segment_comparison",
            "title": "移动端 CVR 下降而桌面端稳定",
            "source": "GA4 + OMS",
            "scope": "华宝新能站内 / device",
            "payload": {
                "mobile_order_conversion_rate": 2.0,
                "mobile_baseline": 2.6,
                "desktop_order_conversion_rate": 4.5,
                "desktop_baseline": 4.0,
            },
        }
    ],
    "HI-023": [
        {
            "evidence_id": "EV-STOCK-AD-EXPOSURE",
            "kind": "cross_source",
            "title": "缺货 SKU 仍承接广告点击",
            "source": "ERP + Ads",
            "scope": "SKU-001",
            "payload": {
                "sellable_stock_quantity": 0,
                "out_of_stock_campaign_sessions": 200,
                "estimated_wasted_spend_cny": 180,
            },
        },
        {
            "evidence_id": "EV-STOCK-SYNC-LAG",
            "kind": "system_state",
            "title": "库存同步延迟",
            "source": "ERP + CMS",
            "scope": "SKU-001",
            "payload": {"inventory_sync_delay_minutes": 325},
        },
    ],
}


def _session_partition(
    total: int,
    *,
    paid_share: float,
    organic_share: float,
) -> dict[str, int]:
    paid = round(total * paid_share)
    organic = round(total * organic_share)
    return {
        "paid": paid,
        "organic": organic,
        "direct_and_referral": total - paid - organic,
    }


def _hi001_related_evidence(metric: dict[str, Any]) -> list[dict[str, Any]]:
    current = round(float(metric["value"]))
    baseline = round(float(metric.get("baseline_value") or 0))
    profile = str(
        metric.get("technical", {}).get(
            "snapshot_evidence_profile",
            "sampled_channel_change",
        )
    )
    if profile != "reconciled_paid_campaign_state":
        current_channels = _session_partition(
            current,
            paid_share=0.62,
            organic_share=0.25,
        )
        baseline_channels = _session_partition(
            baseline,
            paid_share=0.59,
            organic_share=0.27,
        )
        return [
            {
                "evidence_id": "EV-TRAFFIC-CHANNEL-MIX",
                "kind": "segment_comparison",
                "title": "渠道流量变动与总会话量已对账",
                "source": "GA4 + Ads + Search Console",
                "scope": "华宝新能站内 / paid, organic, direct and referral",
                "payload": {
                    "metric_total_sessions": {
                        "current": current,
                        "baseline": baseline,
                    },
                    "channel_sessions": {
                        "current": current_channels,
                        "baseline": baseline_channels,
                    },
                    "reconciliation": {
                        "current_channel_total": sum(current_channels.values()),
                        "current_difference": 0,
                        "baseline_channel_total": sum(baseline_channels.values()),
                        "baseline_difference": 0,
                        "comparison_window_aligned": True,
                        "timezone": "Asia/Shanghai",
                    },
                    "root_cause_controls": {
                        "campaign_configuration_audit": "not_available",
                        "cross_source_join_coverage_percent": 82,
                    },
                },
            }
        ]

    current_paid = round(current * 0.38)
    organic = round(current * 0.36)
    direct_and_referral = current - current_paid - organic
    lost_campaign_sessions = baseline - current
    baseline_paid = current_paid + lost_campaign_sessions
    current_channels = {
        "paid": current_paid,
        "organic": organic,
        "direct_and_referral": direct_and_referral,
    }
    baseline_channels = {
        "paid": baseline_paid,
        "organic": organic,
        "direct_and_referral": direct_and_referral,
    }
    return [
        {
            "evidence_id": "EV-TRAFFIC-CHANNEL-RECONCILIATION",
            "kind": "cross_source_reconciliation",
            "title": "总会话下降已完整对账到付费渠道",
            "source": "GA4 + Ads + Search Console",
            "scope": "华宝新能站内 / aligned daily comparison window",
            "payload": {
                "metric_total_sessions": {
                    "current": current,
                    "baseline": baseline,
                },
                "channel_sessions": {
                    "current": current_channels,
                    "baseline": baseline_channels,
                },
                "reconciliation": {
                    "current_channel_total": sum(current_channels.values()),
                    "current_difference": 0,
                    "baseline_channel_total": sum(baseline_channels.values()),
                    "baseline_difference": 0,
                    "paid_channel_change": current_paid - baseline_paid,
                    "total_session_change": current - baseline,
                    "comparison_window_aligned": True,
                    "timezone": "Asia/Shanghai",
                    "cross_source_join_coverage_percent": 100,
                },
            },
        },
        {
            "evidence_id": "EV-ADS-CAMPAIGN-STATE-DRIFT",
            "kind": "system_state",
            "title": "核心付费活动意外暂停且存在已登记的可逆目标态",
            "source": "Ads configuration audit + campaign registry",
            "scope": "campaign HB-CORE-SEARCH",
            "payload": {
                "campaign_id": "HB-CORE-SEARCH",
                "current_serving_state": "paused",
                "registered_expected_state": "enabled",
                "previous_known_good_state": "enabled",
                "state_change_timing": "before_current_observation_window",
                "authorized_change_request_count": 0,
                "owner_verification": "unexpected_pause_confirmed",
                "campaign_sessions": {
                    "current": 0,
                    "baseline": lost_campaign_sessions,
                },
                "unaffected_paid_sessions": {
                    "current": current_paid,
                    "baseline": current_paid,
                },
                "recovery_boundary": {
                    "reversible": True,
                    "target_state": "enabled",
                    "scope": "campaign serving state only",
                },
            },
        },
        {
            "evidence_id": "EV-TRAFFIC-COLLECTION-CONTROL",
            "kind": "data_quality_control",
            "title": "流量采集与跨源映射控制项全部通过",
            "source": "GA4 ingestion monitor + Ads export monitor",
            "scope": "华宝新能站内 / aligned daily comparison window",
            "payload": {
                "ga4_ingestion_complete": True,
                "ads_export_complete": True,
                "session_definition_consistent": True,
                "comparison_window_aligned": True,
                "duplicate_filter_check": "passed",
                "cross_source_join_coverage_percent": 100,
            },
        },
    ]


def _related_evidence(metric: dict[str, Any]) -> list[dict[str, Any]]:
    if metric["id"] == "HI-001":
        return _hi001_related_evidence(metric)
    return RELATED_EVIDENCE.get(metric["id"], [])


def detect(calculated: dict[str, Any], *, run_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
    business_date = str(calculated["business_date"])
    observed_at = datetime.fromisoformat(business_date).replace(
        hour=3,
        minute=55,
        tzinfo=ZoneInfo("Asia/Shanghai"),
    ).isoformat()
    evidence: list[dict[str, Any]] = []
    anomalies: list[dict[str, Any]] = []
    for metric in calculated["metrics"]:
        evidence_id = metric["evidence_refs"][0]
        related_evidence = _related_evidence(metric)
        evidence.append(
            {
                "evidence_id": evidence_id,
                "kind": "metric_snapshot",
                "title": f"{metric['id']} · {metric['name']}",
                "source": metric["source"],
                "scope": "华宝新能站内健康巡检",
                "observed_at": observed_at,
                "payload": {
                    "metric_id": metric["id"],
                    "metric": metric["metric"],
                    "value": metric["value"],
                    "baseline_value": metric["baseline_value"],
                    "status": metric["status"],
                    "health_band": metric.get("health_band"),
                    "evaluation_status": metric["evaluation_status"],
                    "value_provenance": metric["value_provenance"],
                    "threshold": metric["threshold"],
                    "outputs": metric["outputs"],
                    "history": metric["history"],
                },
            }
        )
        for extra in related_evidence:
            record = dict(extra)
            record["observed_at"] = observed_at
            if not any(item["evidence_id"] == record["evidence_id"] for item in evidence):
                evidence.append(record)
        if metric["status"] == "abnormal":
            refs = [evidence_id] + [
                item["evidence_id"] for item in related_evidence
            ]
            anomalies.append(
                {
                    "anomaly_id": metric["id"],
                    "rule_id": metric["id"],
                    "metric_id": metric["id"],
                    "dimension": metric["dimension"],
                    "severity": "P0",
                    "summary": f"{metric['name']}：{metric['judgement']}",
                    "evidence_refs": refs,
                }
            )
    catalog = {
        "schema_version": "1.0",
        "run_id": run_id,
        "business_date": business_date,
        "evidence": evidence,
    }
    facts = {
        "schema_version": "2.0",
        "run_id": run_id,
        "business_date": business_date,
        "scope": {
            "scope_id": "huabao-site-health-inspection",
            "country_code": "ALL",
            "site_name": "华宝新能站内健康巡检",
            "timezone": "Asia/Shanghai",
            "currency": "CNY",
        },
        "data_quality": calculated["data_quality"],
        "data_provenance": calculated["data_provenance"],
        "metric_catalog": calculated["metric_catalog"],
        "health": calculated["health"],
        "health_policy": calculated.get("health_policy"),
        "metrics": calculated["metrics"],
        "anomalies": anomalies,
        "evidence_ids": [item["evidence_id"] for item in evidence],
        # The same frozen business-date input must produce the same facts hash on
        # recovery. Runtime execution time belongs in attempt/context metadata,
        # not in the deterministic business facts document.
        "calculated_at": observed_at,
    }
    return facts, catalog


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("calculated", type=Path)
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()
    value = json.loads(args.calculated.read_text(encoding="utf-8"))
    facts, catalog = detect(value, run_id=args.run_id)
    print(json.dumps({"facts": facts, "evidence_catalog": catalog}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
