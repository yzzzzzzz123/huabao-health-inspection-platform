"""Small read-only workspace context projection helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from workspace_api import WorkspaceService


SERVER_COMPONENT_NAME = "huabao-worktree-server"


def workspace_context(repository_root: Path, run_id: str) -> dict[str, Any]:
    """Return the bounded metadata projection; never return filesystem paths."""

    requested = repository_root.resolve()
    if requested.name == SERVER_COMPONENT_NAME:
        server_root = requested
        git_root = requested.parent
    else:
        git_root = requested
        server_root = git_root / SERVER_COMPONENT_NAME
    return WorkspaceService(git_root, server_root=server_root).get_workspace(run_id)


__all__ = ["workspace_context"]
