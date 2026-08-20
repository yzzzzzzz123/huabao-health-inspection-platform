"""Small read-only workspace context projection helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from workspace_api import WorkspaceService


def workspace_context(project_root: Path, run_id: str) -> dict[str, Any]:
    """Return the bounded metadata projection; never return filesystem paths."""

    return WorkspaceService(project_root).get_workspace(run_id)


__all__ = ["workspace_context"]
