"""Safe Git snapshot and linked-worktree operations plus maintenance CLI."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Mapping, Sequence


SCRIPT_DIR = Path(__file__).resolve().parent
SERVER_ROOT = SCRIPT_DIR.parents[2]
REPOSITORY_ROOT = SERVER_ROOT.parent
SERVER_COMPONENT_NAME = "huabao-worktree-server"
if str(SERVER_ROOT) not in sys.path:
    sys.path.insert(0, str(SERVER_ROOT))
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))


RUN_ID_RE = re.compile(r"^hi-(?P<date>\d{4}-\d{2}-\d{2})$")
BRANCH_RE = re.compile(r"^run/health-inspection/daily/(?P<date>\d{4}-\d{2}-\d{2})$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40,64}$")


class GitWorkspaceError(RuntimeError):
    """A direct-argv Git operation failed or escaped the repository contract."""


def _is_link_or_reparse(path: Path) -> bool:
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        return False
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    attributes = getattr(metadata, "st_file_attributes", 0)
    return path.is_symlink() or bool(reparse_flag and attributes & reparse_flag)


def _git_environment(extra: Mapping[str, str] | None = None) -> dict[str, str]:
    result = dict(os.environ)
    for key in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"):
        result.pop(key, None)
    result.update(
        {
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_AUTHOR_NAME": "Huabao Workspace Server",
            "GIT_AUTHOR_EMAIL": "workspace-server@invalid.local",
            "GIT_COMMITTER_NAME": "Huabao Workspace Server",
            "GIT_COMMITTER_EMAIL": "workspace-server@invalid.local",
        }
    )
    if extra:
        result.update(extra)
    return result


def run_git(
    project_root: Path,
    arguments: Sequence[str],
    *,
    check: bool = True,
    env: Mapping[str, str] | None = None,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    command = ["git", "-C", str(project_root.resolve()), *arguments]
    try:
        completed = subprocess.run(
            command,
            cwd=project_root.resolve(),
            env=_git_environment(env),
            input=input_text,
            capture_output=True,
            text=True,
            shell=False,
            check=False,
        )
    except (OSError, ValueError) as exc:
        raise GitWorkspaceError("unable to execute Git with direct argv") from exc
    if check and completed.returncode != 0:
        message = (completed.stderr or completed.stdout or "Git command failed").strip()
        raise GitWorkspaceError(message[:1000])
    return completed


def ensure_git_root(project_root: Path) -> None:
    root = project_root.resolve()
    completed = run_git(root, ["rev-parse", "--show-toplevel"], check=False)
    if completed.returncode != 0:
        raise GitWorkspaceError("Huabao platform directory is not a Git repository")
    try:
        reported = Path(completed.stdout.strip()).resolve()
    except OSError as exc:
        raise GitWorkspaceError("Git returned an invalid repository root") from exc
    if reported != root:
        raise GitWorkspaceError("repository_root must be the exact Huabao monorepo Git root")
    dot_git = root / ".git"
    if (
        not dot_git.is_dir()
        or _is_link_or_reparse(dot_git)
    ):
        raise GitWorkspaceError("Workspace Server must run from the primary monorepo worktree")
    absolute_git_dir = run_git(root, ["rev-parse", "--absolute-git-dir"])
    common_git_dir = run_git(
        root,
        ["rev-parse", "--path-format=absolute", "--git-common-dir"],
    )
    try:
        git_dir = Path(absolute_git_dir.stdout.strip()).resolve()
        common_dir = Path(common_git_dir.stdout.strip()).resolve()
    except OSError as exc:
        raise GitWorkspaceError("Git returned an invalid common directory") from exc
    expected_git_dir = dot_git.resolve()
    if git_dir != expected_git_dir or common_dir != expected_git_dir:
        raise GitWorkspaceError("Workspace Server cannot run from a linked or bare worktree")


def current_head(project_root: Path) -> str | None:
    completed = run_git(
        project_root,
        ["rev-parse", "--verify", "HEAD^{commit}"],
        check=False,
    )
    if completed.returncode != 0:
        return None
    value = completed.stdout.strip().lower()
    if not COMMIT_RE.fullmatch(value):
        raise GitWorkspaceError("Git HEAD is not a valid commit ID")
    return value


def branch_exists(project_root: Path, branch: str) -> bool:
    if not BRANCH_RE.fullmatch(branch):
        raise GitWorkspaceError("branch is outside the daily run namespace")
    completed = run_git(
        project_root,
        ["show-ref", "--verify", "--quiet", f"refs/heads/{branch}"],
        check=False,
    )
    return completed.returncode == 0


def list_linked_worktrees(project_root: Path) -> list[dict[str, Any]]:
    ensure_git_root(project_root)
    completed = run_git(project_root, ["worktree", "list", "--porcelain"])
    result: list[dict[str, Any]] = []
    current: dict[str, Any] = {}
    for line in completed.stdout.splitlines() + [""]:
        if not line:
            if current:
                result.append(current)
                current = {}
            continue
        key, _, value = line.partition(" ")
        if key in {"bare", "detached", "locked", "prunable"} and not value:
            current[key] = True
        elif key == "branch" and value.startswith("refs/heads/"):
            current[key] = value.removeprefix("refs/heads/")
        else:
            current[key] = value
    return result


def registered_worktree(project_root: Path, worktree_path: Path) -> bool:
    target = worktree_path.resolve()
    for item in list_linked_worktrees(project_root):
        raw = item.get("worktree")
        if isinstance(raw, str) and Path(raw).resolve() == target:
            return True
    return False


def validate_daily_identity(
    project_root: Path,
    *,
    business_date: str,
    run_id: str,
    branch: str,
    worktree_path: Path,
) -> None:
    match = RUN_ID_RE.fullmatch(run_id)
    branch_match = BRANCH_RE.fullmatch(branch)
    if match is None or match.group("date") != business_date:
        raise GitWorkspaceError("run_id does not match business_date")
    if branch_match is None or branch_match.group("date") != business_date:
        raise GitWorkspaceError("branch does not match business_date")
    root = project_root.resolve()
    namespace_lexical = root / SERVER_COMPONENT_NAME / "worktrees"
    if (
        not os.path.lexists(namespace_lexical)
        or _is_link_or_reparse(namespace_lexical)
        or not namespace_lexical.is_dir()
    ):
        raise GitWorkspaceError("daily worktree namespace is unsafe")
    expected = namespace_lexical / business_date
    candidate = Path(os.path.abspath(os.fspath(worktree_path)))
    if candidate != expected or expected.parent != namespace_lexical:
        raise GitWorkspaceError("worktree path is outside the daily namespace")
    if os.path.lexists(candidate) and _is_link_or_reparse(candidate):
        raise GitWorkspaceError("daily worktree path is redirected")


def create_isolated_snapshot(project_root: Path, *, business_date: str) -> str:
    """Snapshot tracked, dirty, and non-ignored untracked source without touching main index."""

    root = project_root.resolve()
    ensure_git_root(root)
    descriptor, index_name = tempfile.mkstemp(prefix="huabao-git-index-", suffix=".tmp")
    os.close(descriptor)
    index_path = Path(index_name)
    index_path.unlink(missing_ok=True)
    environment = {"GIT_INDEX_FILE": str(index_path)}
    try:
        parent = current_head(root)
        if parent is None:
            run_git(root, ["read-tree", "--empty"], env=environment)
        else:
            run_git(root, ["read-tree", parent], env=environment)
        run_git(root, ["add", "-A", "--", "."], env=environment)
        tree = run_git(root, ["write-tree"], env=environment).stdout.strip().lower()
        if not COMMIT_RE.fullmatch(tree):
            raise GitWorkspaceError("Git did not return a valid tree object")
        arguments = ["commit-tree", tree]
        if parent is not None:
            arguments.extend(["-p", parent])
        commit = run_git(
            root,
            arguments,
            env=environment,
            input_text=f"Workspace source snapshot for {business_date}\n",
        ).stdout.strip().lower()
        if not COMMIT_RE.fullmatch(commit):
            raise GitWorkspaceError("Git did not return a valid snapshot commit")
        return commit
    finally:
        index_path.unlink(missing_ok=True)
        lock_path = Path(str(index_path) + ".lock")
        lock_path.unlink(missing_ok=True)


def create_linked_worktree(
    project_root: Path,
    *,
    business_date: str,
    run_id: str,
    branch: str,
    worktree_path: Path,
) -> str:
    root = project_root.resolve()
    validate_daily_identity(
        root,
        business_date=business_date,
        run_id=run_id,
        branch=branch,
        worktree_path=worktree_path,
    )
    if os.path.lexists(worktree_path) or registered_worktree(root, worktree_path):
        raise GitWorkspaceError("daily worktree already exists")
    if branch_exists(root, branch):
        raise GitWorkspaceError("daily branch already exists")
    worktree_path.parent.mkdir(parents=True, exist_ok=True)
    snapshot = create_isolated_snapshot(root, business_date=business_date)
    run_git(
        root,
        ["worktree", "add", "-b", branch, str(worktree_path.resolve()), snapshot],
    )
    if not registered_worktree(root, worktree_path) or not branch_exists(root, branch):
        raise GitWorkspaceError("Git did not register the daily worktree completely")
    return snapshot


def worktree_is_clean(worktree_path: Path) -> bool:
    completed = run_git(
        worktree_path,
        ["status", "--porcelain=v1", "--untracked-files=all"],
    )
    return completed.stdout == ""


def checkpoint_worktree(worktree_path: Path, *, business_date: str) -> str:
    root = worktree_path.resolve()
    run_git(root, ["add", "-A", "--", "input", "context", "result"])
    staged = run_git(root, ["diff", "--cached", "--quiet"], check=False)
    if staged.returncode not in {0, 1}:
        raise GitWorkspaceError("unable to inspect staged workspace changes")
    if staged.returncode == 1:
        run_git(
            root,
            [
                "-c",
                "user.name=Huabao Workspace Server",
                "-c",
                "user.email=workspace-server@invalid.local",
                "commit",
                "--no-gpg-sign",
                "-m",
                f"Seal health inspection {business_date}",
            ],
        )
    commit = current_head(root)
    if commit is None:
        raise GitWorkspaceError("sealed worktree has no checkpoint commit")
    if not worktree_is_clean(root):
        raise GitWorkspaceError("sealed worktree is not Git clean")
    return commit


def remove_daily_worktree(
    project_root: Path,
    *,
    business_date: str,
    run_id: str,
    branch: str,
    worktree_path: Path,
) -> None:
    root = project_root.resolve()
    validate_daily_identity(
        root,
        business_date=business_date,
        run_id=run_id,
        branch=branch,
        worktree_path=worktree_path,
    )
    if _is_link_or_reparse(worktree_path):
        raise GitWorkspaceError("daily worktree path is redirected; refusing deletion")
    target = worktree_path.resolve()
    registration = next(
        (
            item
            for item in list_linked_worktrees(root)
            if isinstance(item.get("worktree"), str)
            and Path(str(item["worktree"])).resolve() == target
        ),
        None,
    )
    if registration is not None:
        if registration.get("branch") != branch:
            raise GitWorkspaceError("daily worktree registration is bound to another branch")
        run_git(root, ["worktree", "remove", "--force", str(worktree_path.resolve())])
    elif os.path.lexists(worktree_path):
        raise GitWorkspaceError("unregistered daily directory remains; refusing recursive deletion")
    if branch_exists(root, branch):
        run_git(root, ["branch", "-D", "--", branch])
    run_git(root, ["worktree", "prune"])
    if os.path.lexists(worktree_path) or registered_worktree(root, worktree_path):
        raise GitWorkspaceError("daily worktree residue remains after deletion")
    if branch_exists(root, branch):
        raise GitWorkspaceError("daily branch residue remains after deletion")


def _json_output(value: Any) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Huabao Workspace Server maintenance CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("config", help="validate and print the secret-free configuration")
    subparsers.add_parser("list", help="list durable workspaces and Git registrations")
    show = subparsers.add_parser("show", help="show one workspace")
    show.add_argument("run_id")
    integrity = subparsers.add_parser("integrity", help="verify SQLite and event hash chain")
    integrity.set_defaults(command="integrity")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        if arguments.command == "config":
            from shared.runtime_env import load_workspace_config

            _json_output(load_workspace_config(SERVER_ROOT).public_projection())
            return 0
        from workspace_api import WorkspaceService

        service = WorkspaceService(REPOSITORY_ROOT, server_root=SERVER_ROOT)
        if arguments.command == "list":
            _json_output(
                {
                    "workspaces": service.list_workspaces(),
                    "git_worktrees": list_linked_worktrees(REPOSITORY_ROOT),
                }
            )
        elif arguments.command == "show":
            _json_output(service.get_workspace(arguments.run_id))
        elif arguments.command == "integrity":
            _json_output(service.store.verify_integrity())
        return 0
    except Exception as exc:  # CLI boundary
        _json_output({"ok": False, "error": type(exc).__name__, "message": str(exc)})
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
