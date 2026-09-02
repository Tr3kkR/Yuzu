- **Per-device concurrency enforcement is now real (ADR-1007).** `concurrency: per-device` on an
  instruction definition — the default, and the mode 191 shipped definitions actually use — now
  prevents the same definition from running twice concurrently on the same device for the common
  case, enforced server-side via a race-free Postgres claim table, for dispatch that names the
  definition (`POST /api/instructions/:id/execute`, a schedule, or a workflow step) — a raw
  MCP/REST command, or an explicit Broadcast/all-fleet dispatch, is not gated. A claim is bounded
  by a flat one-hour timeout and is renewed by a dedicated agent-core keepalive thread (not plugin
  cooperation, which proved unreliable for a quiet, long-running action) — see ADR-1007 for the
  full mechanism. Previously `concurrency_mode` was stored and displayed but never consulted at
  dispatch time. The other four documented modes
  (`per-definition`, `per-set`, `global:<N>`, and the non-standard `global`/`global-singleton`
  values some shipped catalog definitions use) remain unenforced — see `docs/yaml-dsl-spec.md`
  §12 for the corrected model. `POST /api/directory/sync` now returns `409` when a sync is already
  in progress (previously: no re-entrancy guard at all — two concurrent calls could interleave
  writes with no error). A genuine concurrent-call race in `DirectorySync::sync_entra` is now
  guarded instead of silently allowed. The dead `ConcurrencyManager` class (never wired to
  anything) is removed. **`GET /api/v1/execution-statistics/agents` (capability 1.9) no longer
  counts a still-running execution as a completed success** — a pre-existing classifier gap
  (`exit_code` defaults to 0 on the wire until a real terminal response sets it) that this same
  release's keepalive turned from rare into routine for any longer-running command; success/failure
  counts for in-flight executions now correctly exclude them instead of double-counting.
