"""Compatibility facade for the SQLite tamper-evident control-event chain."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from state_store import StateStore, resolve_server_runtime_root


SERVER_COMPONENT_NAME = "huabao-worktree-server"


def _runtime_root(repository_root: Path) -> Path:
    requested = Path(repository_root)
    if requested.name == SERVER_COMPONENT_NAME:
        return resolve_server_runtime_root(requested.parent, server_root=requested)
    return resolve_server_runtime_root(requested)


def verify_action_history(repository_root: Path) -> dict[str, Any]:
    return StateStore(_runtime_root(repository_root)).verify_integrity()


def list_action_history(
    repository_root: Path,
    *,
    run_id: str | None = None,
) -> list[dict[str, Any]]:
    return StateStore(_runtime_root(repository_root)).list_events(run_id=run_id)


__all__ = ["list_action_history", "verify_action_history"]
