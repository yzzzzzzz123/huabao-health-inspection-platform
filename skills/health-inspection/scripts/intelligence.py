"""Build bounded decision and execution ledgers from promoted projections."""

from __future__ import annotations

from typing import Any

from shared.audit import sha256_json, utc_now


def build_ledgers(
    *,
    run_id: str,
    business_date: str,
    stages: dict[str, dict[str, Any]],
) -> tuple[dict[str, Any], dict[str, Any]]:
    intelligence_rows = []
    execution_rows = []
    for stage, value in stages.items():
        business = value["business"]
        intelligence = value["intelligence"]
        intelligence_rows.append(
            {
                "stage": stage,
                "agent": intelligence["agent"],
                "analysis_summary": intelligence["analysis_summary"],
                "self_test": intelligence["self_test"]["status"],
                "decision_count": len(intelligence["decisions"]),
                "business_sha256": sha256_json(business),
                "intelligence_sha256": sha256_json(intelligence),
            }
        )
        execution_rows.append(
            {
                "stage": stage,
                "status": business["status"],
                "verified": True,
            }
        )
    generated_at = utc_now()
    return (
        {
            "schema_version": "1.0",
            "run_id": run_id,
            "business_date": business_date,
            "generated_at": generated_at,
            "stages": intelligence_rows,
        },
        {
            "schema_version": "1.0",
            "run_id": run_id,
            "business_date": business_date,
            "generated_at": generated_at,
            "stages": execution_rows,
        },
    )


__all__ = ["build_ledgers"]
