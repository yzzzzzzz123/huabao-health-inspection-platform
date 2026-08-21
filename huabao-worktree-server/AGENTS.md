# Huabao Worktree Server

This component is the trusted deterministic storage and lifecycle boundary for
Huabao health-inspection workspaces. It lives under the single parent monorepo
Git root; it is an independently deployable service, not an independent Git
repository. The sibling Dolphin component owns agents, prompts, schemas,
business calculation code, and workflow decisions.

## Fixed scope

- Business timezone: `Asia/Shanghai`.
- Currency: `CNY`.
- Dimensions: traffic, conversion, and product only.
- Daily identity: `hi-YYYY-MM-DD`, Server-relative `worktrees/YYYY-MM-DD`, and
  `run/health-inspection/daily/YYYY-MM-DD`.
- The physical worktree path resolves from the parent monorepo root as
  `huabao-worktree-server/worktrees/YYYY-MM-DD`. That dated directory itself is
  the root of a complete parent-monorepo linked worktree containing both
  component trees; it is not a Server-only checkout or nested Git repository.
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
  Server-relative `history/YYYY-MM-DD`.
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

## Source, runtime, and deployment boundary

- Git objects, refs, worktree registrations, snapshot commits and branches are
  rooted in the parent monorepo and its single `.git` common dir. Server-owned
  application state is rooted here instead: `.huabao/` for SQLite/control
  state, `worktrees/` for complete-monorepo dated linked worktrees, and
  `history/` for sealed business archives. Parent-root directories with those
  names are neither authoritative nor valid fallbacks.
- Runtime `.runtime/`, `input/`, `context/`, and `result/` live at each dated
  linked-worktree root, for example `worktrees/YYYY-MM-DD/.runtime/`; do not
  nest them again inside that snapshot's Server component directory.
- Upgrading from the former parent-root runtime layout requires a stopped-service,
  controlled migration of SQLite state and stored workspace/archive bindings
  into this component. If both old and new runtime roots contain state, fail
  closed; never choose one silently, merge databases heuristically, or replace
  existing state with a newly initialized empty database.
- A Server deployment must retain a full monorepo checkout or controlled mirror
  on the host. Packaging only this directory is unsupported because the Server
  must create full-project linked worktrees.
- Dolphin may be packaged and uploaded independently from the sibling component,
  but its release hashes must bind the same immutable source snapshot.

## Editing and verification

- Do not change the sibling Dolphin component for a Server-only change. A true
  cross-component contract change must update both components in one monorepo
  commit. Never write into the legacy source repository.
- Do not add runtime dependencies or a second environment file.
- Do not create a `tests/` directory; use system-temporary smoke fixtures.
- Use direct argv and `shell=False` for Git/Python subprocesses.
- After changes run compileall, `server.py config`, `worktree_cli.py list`,
  `state_store_cli.py integrity`, and `git diff --check`.
