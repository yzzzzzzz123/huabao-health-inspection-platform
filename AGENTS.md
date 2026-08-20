# Huabao Worktree Server

This repository is the trusted deterministic storage and lifecycle boundary for
Huabao health-inspection workspaces. It is an independent Git root. It does not
contain or execute Dolphin agents, prompts, schemas, business calculation code,
or workflow scheduling decisions.

## Fixed scope

- Business timezone: `Asia/Shanghai`.
- Currency: `CNY`.
- Dimensions: traffic, conversion, and product only.
- Daily identity: `hi-YYYY-MM-DD`, `worktrees/YYYY-MM-DD`, and
  `run/health-inspection/daily/YYYY-MM-DD`.
- At most one non-terminal workspace may exist at a time and at most one
  workspace may exist for a business date.
- Python is `>=3.11` and runtime dependencies are standard-library only.

## Trust boundary

- Public Workspace APIs accept a registered artifact ID, never a server path.
- Dolphin releases must be pre-registered in the tracked, secret-free
  `shared/.env` allowlist.
- The server creates `platform-release.json`; clients cannot create or replace
  it. The file contains exactly the seven release fields defined by the API.
- Dolphin artifacts are create-once. A byte-identical retry is idempotent; a
  different retry fails with HTTP 409.
- Workspace-detail GET, artifact GET/PUT, seal, and delete require the matching incarnation and
  platform-release SHA headers.
- `input`, `context`, and `result` must equal the artifact registry at seal.
  Links, undeclared files, missing files, and hash drift fail closed.
- Seal creates server-owned workspace/archive manifests, checkpoints the daily
  branch, verifies Git clean, and copies only business runtime files to
  `history/YYYY-MM-DD`.
- Delete first closes writes, then removes the exact archive, Git worktree,
  daily branch, and SQLite run. Any residue keeps the run in deleting state.

## Editing and verification

- Never write into the Dolphin repository or the legacy source repository.
- Do not add runtime dependencies or a second environment file.
- Do not create a `tests/` directory; use system-temporary smoke fixtures.
- Use direct argv and `shell=False` for Git/Python subprocesses.
- After changes run compileall, `server.py config`, `worktree_cli.py list`,
  `state_store_cli.py integrity`, and `git diff --check`.
