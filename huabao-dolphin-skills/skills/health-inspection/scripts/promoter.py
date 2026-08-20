"""Promote one validated in-memory Agent envelope into formal projections."""

from __future__ import annotations

from typing import Any

from renderer import render
from validator import validate_envelope


def promote(
    *,
    stage: str,
    envelope: dict[str, Any],
    facts: dict[str, Any],
    evidence_catalog: dict[str, Any],
    upstream: dict[str, dict[str, Any]],
    packet: dict[str, Any],
) -> dict[str, Any]:
    business, intelligence = validate_envelope(
        stage=stage,
        envelope=envelope,
        facts=facts,
        evidence_catalog=evidence_catalog,
        upstream=upstream,
        packet=packet,
    )
    return {
        "business": business,
        "intelligence": intelligence,
        "markdown": render(stage, business),
    }


__all__ = ["promote"]
