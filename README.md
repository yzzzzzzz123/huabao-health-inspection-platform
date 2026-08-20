# Huabao Worktree Server

The Worktree Server is the trusted half of the split Huabao health-inspection
platform. Dolphin owns agents, taskbooks, prompts, schemas, business Python,
and the Stage 0-5 workflow. This repository owns the HTML shell, Workspace API,
daily Git linked worktrees, SQLite identity/state, sealing, long-term business
archives, scheduling infrastructure, and filesystem/security boundaries.

## Migration provenance

The initial mechanical baseline was taken from legacy source HEAD
`63ef013a003aad3057cc732105d45da16a4cd301`. It represents the frozen bytes of
the working tree at migration time; it does **not** claim that the legacy
working tree was clean or byte-identical to that commit. The initial baseline
content SHA-256 is
`c224aa3a00e9a362f3597d68c1dc5365c207945cb323522c7fcf284d2c11a059`.

The server implementation in this repository is subsequently maintained as an
independent Git history. The legacy repository is not a runtime dependency and
must remain untouched.

## Runtime contract

- Python `>=3.11`, standard library only.
- Loopback HTTP binding only (default `127.0.0.1:8765`).
- One tracked environment contract: `shared/.env`.
- One SQLite control-plane index: `.huabao/workspace-state.sqlite3` (ignored).
- Daily worktrees: `worktrees/YYYY-MM-DD` (ignored by the main worktree).
- Sealed business archives: `history/YYYY-MM-DD` (ignored by Git).

Every daily worktree also contains ignored machine-local directories
`.runtime/environment` and `.runtime/dingtalk/{receipts,locks}`. The
`environment/venv.json` receipt records that Agent execution is hosted by
Dolphin, so an Agent virtual environment is not materialized in the Server
worktree; the trusted Server process itself remains Python `>=3.11`
standard-library only. These files never enter Git or the business archive.

Completion delivery is reconciled by a server-owned background worker after
seal, at service startup, and every five minutes. It validates the sealed
workspace/index/archive chain before reading the Stage 5 Markdown. Missing
credentials leave the report in `not_sent`; partial receipts may continue,
while uncertain network results require explicit trusted-CLI recovery and are
never retried automatically. Real DingTalk delivery still requires deployment
secrets and a production endpoint check.

`shared/.env` contains no real credentials. Before accepting a release, the
server requires an exact match against
`HUABAO_DOLPHIN_RELEASE_ALLOWLIST_JSON`. Its bundle hashes must exactly match
the tracked Dolphin package manifest and the locally recomputed release.

Automatic daily scheduling and browser dispatch remain fail-closed until a
trusted Dolphin Gateway supplies readiness, idempotent dispatch, durable job
status/heartbeat, and cancel acknowledgement. `inspection_schedule.py` is the
Asia/Shanghai clock-policy helper only; the Server deliberately does not start
it while `HUABAO_DOLPHIN_DISPATCH_URL` is empty. This avoids creating an
orphaned daily worktree or claiming a workflow that cannot be supervised.

## API

Start locally:

```text
python -I skills/health-inspection/scripts/server.py serve
```

Public endpoints:

```text
GET    /api/config
GET    /api/workspaces
POST   /api/workspaces
GET    /api/workspaces/{run_id}
GET    /api/workspaces/{run_id}/artifacts/{artifact_id}
PUT    /api/workspaces/{run_id}/artifacts/{artifact_id}
POST   /api/workspaces/{run_id}/seal
DELETE /api/workspaces/{run_id}
```

Workspace creation accepts exactly one release form:

```json
{"business_date":"2026-08-21","release_id":"v1.0.0"}
```

or:

```json
{
  "business_date": "2026-08-21",
  "platform_release": {
    "platform": "dolphin-ai",
    "application_id": "huabao-health-inspection",
    "release_version": "v1.0.0",
    "workflow_version": "v1.0.0",
    "skill_bundle_sha256": "<64 lowercase hex>",
    "schema_bundle_sha256": "<64 lowercase hex>"
  }
}
```

An optional input `bound_at` is ignored and replaced by the server. The written
`input/00-orchestrator/platform-release.json` contains exactly:

```text
platform, application_id, release_version, workflow_version,
skill_bundle_sha256, schema_bundle_sha256, bound_at
```

Creation returns `run_id`, `business_date`, `incarnation_id`,
`platform_release_sha256`, the seven-field `platform_release`, `status`, and
`workspace_version`.

The server-owned `run_context` artifact freezes the new run identity and the
only historical business projection Dolphin may consume. Its
`historical_query` records the bounded lookup contract (at most seven date
identities and exact offsets `1` and `6`), while `historical_runs` contains
only due, sealed source runs. Each entry binds the source run/date, review
window, platform-release SHA, archive-manifest SHA, facts bytes and SHA, and an
optional action plan plus SHA. Before creation returns, the Server revalidates
the archived manifest and artifact bytes against SQLite. Dolphin reads this
projection through artifact ID `run_context`; it never scans `history/`.

Workspace-detail GET, artifact GET/PUT, seal, and delete calls require:

```text
X-Workspace-Incarnation: <incarnation_id>
X-Platform-Release-SHA256: <platform_release_sha256>
```

PUT uses raw bytes, the registered `Content-Type`, and
`If-None-Match: *`. It also requires `X-Content-SHA256` with the lowercase
SHA-256 of the exact request bytes; the server compares it in constant time.
Only IDs in
`skills/health-inspection/contracts/worktree-file-contract.json` are accepted.
There is no API that accepts or resolves an arbitrary path.

Seal accepts exactly:

```json
{"delivery_manifest_sha256":"<indexed orchestrator_delivery_manifest SHA-256>"}
```

The delivery manifest itself must bind the run ID, business date, incarnation,
seven-field platform release, and platform-release SHA. Seal also requires the
37 Stage 0 metrics (12 traffic, 10 conversion, 15 product), one successful
attempt receipt per Stage, all registered Stage 1-5 outputs, and every required
orchestrator artifact. Every selected receipt must declare `status` as exactly
`completed` or `succeeded`, and must include
`self_test: {"status":"passed","unresolved_issues":[]}`.

The server also compares the delivery manifest's sorted artifact records with
the complete indexed pre-seal set. The delivery manifest excludes itself and
the two manifests that only the server can create during sealing. After that
check, `run_state` makes its sole permitted lifecycle transition from `open` to
`sealed`; the server-owned workspace index binds that sealed set, and the
archive manifest binds the index plus every other final artifact while
excluding only itself. This staged chain avoids self-reference while keeping
the one server-owned hash transition explicit and auditable.

Active workspaces cannot be deleted because this split has no Dolphin
cancel/heartbeat ownership protocol. Deletion is accepted only for `sealed`,
`error`, or an idempotently resumed `deleting` workspace and returns success
only after the exact worktree, branch, SQLite identity, and archive are gone.

## Maintenance commands

```text
python -I skills/health-inspection/scripts/server.py config
python -I skills/health-inspection/scripts/worktree_cli.py list
python -I skills/health-inspection/scripts/state_store_cli.py integrity
```

The root worktree may contain tracked, dirty, and non-ignored untracked source.
Workspace creation snapshots those bytes through an isolated Git index and
`commit-tree`; it does not alter the main index or main branch.
