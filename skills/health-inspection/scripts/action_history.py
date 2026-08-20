"""Compatibility facade for the SQLite tamper-evident control-event chain."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from state_store import StateStore


def verify_action_history(project_root: Path) -> dict[str, Any]:
    return StateStore(project_root).verify_integrity()


def list_action_history(project_root: Path, *, run_id: str | None = None) -> list[dict[str, Any]]:
    return StateStore(project_root).list_events(run_id=run_id)


__all__ = ["list_action_history", "verify_action_history"]
