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
- The tracked HTML remains byte-aligned with the established Huabao business
  workbench. Its legacy read routes are server-built, hash-verified projections
  only; they omit workspace capabilities, paths, raw responses and evidence
  bodies. Health-policy draft, schedule and version mutations use the
  server-owned SQLite policy store with optimistic revision checks. Version
  occupancy is an exact version-plus-SHA identity; logical deletion retains a
  hash-chained tombstone, and `next_inspection` never activates without a
  durable runtime claim. The workbench may delete a terminal `sealed` or
  `error` daily run through a server-owned binding lookup; the response never
  exposes that binding. Run creation, retry, action-note mutation, and
  active-run deletion remain fail closed until their trusted Dolphin dispatch,
  cancel-ack and note contracts exist.
- `input`, `context`, and `result` must equal the artifact registry at seal.
  Links, undeclared files, missing files, and hash drift fail closed.
- Seal creates server-owned workspace/archive manifests, checkpoints the daily
  branch, verifies Git clean, and copies only business runtime files to
  `history/YYYY-MM-DD`.
- Seal verifies that the Dolphin delivery manifest exactly binds the sorted
  pre-seal artifact set. The delivery manifest excludes itself and server-only
  seal manifests; `run_state` changing from `open` to `sealed` is the only
  permitted hash transition before the final workspace/archive snapshots.
- A server-owned background reconciler wakes after seal, at startup, and on a
  bounded interval. It may automatically continue only `not_sent` or `partial`
  DingTalk receipts; an uncertain network result requires explicit trusted-CLI
  recovery and never changes the authoritative sealed state.
- Delete first closes writes, then removes the exact archive, Git worktree,
  daily branch, and SQLite run. Any residue keeps the run in deleting state.

## Editing and verification

- Never write into the Dolphin repository or the legacy source repository.
- Do not add runtime dependencies or a second environment file.
- Do not create a `tests/` directory; use system-temporary smoke fixtures.
- Use direct argv and `shell=False` for Git/Python subprocesses.
- After changes run compileall, `server.py config`, `worktree_cli.py list`,
  `state_store_cli.py integrity`, and `git diff --check`.
