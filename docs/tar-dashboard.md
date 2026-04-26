# TAR Dashboard — Operator Page Design

**Status:** Design (PR-A.A shipped 2026-04-26: page shell + retention-paused list + Scan / Re-enable; purge action and persistence deferred. See `docs/roadmap.md` Phase 15.)
**Audience:** Server engineers, dashboard UI engineers, TAR plugin maintainers
**Owners:** `architect` (page architecture), `plugin-developer` (TAR action surface), `security-guardian` (SQL execution surface), `docs-writer` (DSL + REST docs)
**Related:** `docs/scope-walking-design.md` (the cross-cutting result-set primitive this page consumes), `docs/yuzu-guardian-design-v1.1.md` (the agent tamper-resistance pillar that the process tree viewer's data quality depends on), `agents/plugins/tar/` (the data plane).

---

## 1. Why a dedicated TAR page

The Timeline Activity Record (TAR) plugin is one of the **highest-leverage operator surfaces** in Yuzu — it answers the "what happened on this machine" question that drives forensics, compliance, and reactive IR. Today it is reachable only via the generic instruction-launch flow and the `/fragments/tar-sql` HTMX fragment embedded in another page; the surface area is large but the affordances are scattered. Operators repeatedly asked "where do I go to *do TAR*" — the answer needs to be a single dashboard page.

The page is also the home for two new affordances that did not have anywhere to live:

1. **Retention-paused source list** — the operator-facing view of `<source>_enabled=false` per device, born from issue #539. Without it, an operator who disabled `process_enabled` on a device for forensic preservation has no aggregate view of which boxes are accumulating non-aging data.
2. **Process tree viewer** — reconstructed from `process_live` plus a seed snapshot taken at agent install / first start (see §6). Forensic timeline of every process born under a parent, walked back to PID 1.

The page is also the surface where **scope walking** (per `docs/scope-walking-design.md`) becomes most visibly useful — the TAR SQL frame is the canonical iterative-narrowing tool, and result-set chips on this page are the operator's reasoning chain made visible.

## 2. Information architecture

```
Dashboard ──────────────────────────────────────────────────────────────────
│
├─ Devices       (existing)
├─ Inventory     (existing)
├─ Instructions  (existing)
├─ Policies      (existing)
├─ TAR           (new — this page) ─────────────────────────────────────────┐
│                                                                            │
│  /tar                                                            │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │  [Scope chip ▼]  windows-chrome-suspects · 2,798 devices · pinned │    │
│  │  ─── lineage breadcrumb (per scope-walking §8.2) ────────────────  │    │
│  └────────────────────────────────────────────────────────────────────┘    │
│  ┌─ Retention-paused sources (PR-A) ─────────────────────────────────┐    │
│  │   device              source     paused since   live rows  oldest │    │
│  │   prod-eu-1 (Linux)   process    2026-04-25      18,402   31d 4h  │    │
│  │   prod-eu-1 (Linux)   tcp        2026-04-25       4,193   31d 4h  │    │
│  │   ...                                                              │    │
│  │   [Re-enable]  [Purge data]  [Export CSV]                          │    │
│  └────────────────────────────────────────────────────────────────────┘    │
│  ┌─ TAR SQL (PR-D, scope-walking-aware) ──────────────────────────────┐   │
│  │   $TAR  > SELECT name, COUNT(*) FROM process_hourly GROUP BY name  │   │
│  │   [Run scoped to: windows-chrome-suspects]                         │   │
│  │                                                                     │   │
│  │   results... (streamed)                                             │   │
│  │   [Save as result set ▼ "chrome-procs"]                             │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│  ┌─ Process tree viewer (PR-H) ──────────────────────────────────────┐    │
│  │   device: [pick from scope ▼]                                     │    │
│  │                                                                    │    │
│  │   1   systemd                                                      │    │
│  │   ├── 234   sshd                                                   │    │
│  │   │   └── 1402  bash (user=alice)                                  │    │
│  │   │       └── 1419  python3 train.py  ← still running              │    │
│  │   ├── 412   docker                                                 │    │
│  │   │   ├── 998   containerd                                         │    │
│  │   │   └── ...                                                      │    │
│  │   ├── 814   yuzu-agent  (★ self)                                   │    │
│  │   ...                                                              │    │
│  │   Tree as observed since 2026-04-12 09:14 UTC (agent install)      │    │
│  └────────────────────────────────────────────────────────────────────┘    │
│                                                                            │
├─ Settings      (existing)                                                  │
└────────────────────────────────────────────────────────────────────────────┘
```

URL structure:

| Path | Purpose | Required permission |
|---|---|---|
| `/tar` | The page | `Infrastructure:Read` |
| `/fragments/tar/retention-paused` | HTMX fragment for the paused-sources table | `Infrastructure:Read` |
| `/fragments/tar/sql` | (existing, relocated) HTMX fragment for the SQL frame | `Infrastructure:Read` + dispatch |
| `/fragments/tar/process-tree` | HTMX fragment for the tree viewer | `Infrastructure:Read` |
| `/api/v1/tar/retention-status` | JSON: per-device per-source enabled/disabled | `Infrastructure:Read` |
| `/api/v1/tar/process-tree/{device_id}` | JSON: reconstructed tree for one device | `Infrastructure:Read` |

## 3. PR-A — Retention-paused source list

**Goal:** every device × source pair where `<source>_enabled=false`, surfaced in a sortable, filterable, exportable table, with one-click re-enable and an explicit "purge data" action gated behind a confirmation modal.

### 3.1 Data flow

The source of truth is the agent's `tar_config` table — the `<source>_enabled` keys, set by the `tar.configure` action. The server does not currently maintain a centralised "TAR config" mirror; the data path is **request-driven**:

1. Page load fans out `tar.status` (extended in PR-A to emit the four `<source>_enabled` values + the `<source>_live_rows` count + `<source>_oldest_ts` per source) to every device the page's scope resolves to. Scope is the active scope chip (default `__all__` for fresh page load).
2. Responses stream back via the standard agent-streaming pipeline.
3. Server collates into a transient in-memory table; renders as HTMX OOB swaps.
4. Empty rows (`enabled=true` for all four sources) are dropped — the table only shows the *paused* state, not the entire fleet.

This avoids a new persistent server-side mirror, which would have to be reconciled with agent state on every config change. The trade-off is a 5-15s page-load cost on a large fleet; mitigated by:
- Scope-restricted queries (the operator usually narrows first via a result set)
- Manual **Refresh** button for ad-hoc re-fan-out (automatic background refresh is planned for Phase 15.G operational hardening)
- Manual "Refresh" button for ad-hoc re-fan-out

### 3.2 Extending `tar.status`

The action's response gains four lines per source (so 16 new lines total for the 4 sources):

```
config|process_enabled|true
config|process_live_rows|18402
config|process_oldest_ts|1730000000
config|process_paused_at|0           # 0 = never; otherwise the ts when last set to false
config|tcp_enabled|false
config|tcp_live_rows|4193
config|tcp_oldest_ts|1733000000
config|tcp_paused_at|1735689600
...
```

`config|<source>_paused_at|...` is **new** — it requires the `do_configure` handler in `tar_plugin.cpp` to write this timestamp whenever it transitions a source from enabled to disabled (and clear it on the reverse). This is the operator-facing "paused since" column and is only meaningful at the server's wall-clock. Backwards-compatible — if the field is absent, the dashboard renders `—` and falls back to "unknown."

### 3.3 Re-enable action

Single-row "Re-enable" button → confirm modal → server dispatches `tar.configure` with the appropriate `<source>_enabled=true` to the named device. On success, the row drops out of the table on the next refresh; on failure the row turns yellow with the error tooltip.

Per-source independence (the #539 invariant) means re-enabling one source on a device does not touch the other three — the dispatched parameter is per-source.

### 3.4 Purge action

The "Purge data" button on a row is more dangerous than re-enable — it tells the agent to drop every row from `<source>_live`, `<source>_hourly`, `<source>_daily`, `<source>_monthly` for that source, *without* re-enabling the collector. The use case is "we paused process collection 8 weeks ago for forensic preservation; we have what we need, the disk is filling up, drop the rows but keep the collector paused."

Server dispatches a new agent action `tar.purge_source` with `{source: <name>}`. The action is gated behind a typed-confirmation modal ("type the device hostname to confirm purge of `process` data"), per the destructive-action discipline in the project root `CLAUDE.md`. Audit row: `action: tar.purge_source, principal: <session>, result: success|failure, detail_json: {device_id, source, rows_deleted}`.

### 3.5 Permissions and safety

- View-only access requires `Infrastructure:Read`.
- Re-enable requires `Infrastructure:Update` on the target device.
- Purge requires `Infrastructure:Delete` on the target device, **and** the device must currently report `<source>_enabled=false` (rejected at the server with `400 SOURCE_NOT_PAUSED` if the live status disagrees — prevents a stale row from triggering accidental purge of an actively-collecting source).

### 3.6 Tests

- Server-side: unit tests for the aggregation/render path against synthetic `tar.status` responses (paused-only, all-paused, none-paused, partial response).
- Agent-side: extends `tests/unit/test_tar_aggregator.cpp` (the suite added for #539) with a config-roundtrip test for `<source>_paused_at` write-on-disable / clear-on-enable.
- Integration: stand up the UAT stack, disable a source on a synthetic agent, confirm the row appears in the page within one refresh tick, click re-enable, confirm the row drops.

## 4. PR-D — TAR SQL frame, scope-walking-aware

The frame body is largely the existing `/fragments/tar-sql` route (`server/core/src/dashboard_routes.cpp:500`). PR-D moves it onto the new page and wires it into the result-set primitive (`docs/scope-walking-design.md`):

1. **Scope chip** in the frame header — operator picks an active result set (or a standard scope) before submitting. The dispatch resolves `from_result_set:<id>` to the device-ID set per `scope-walking-design.md` §4.
2. **"Save as result set" button** on the results pane — after a query returns, operator clicks "Save as result set," names it, and the server creates a new result set (`source_kind=tar_query`) with member IDs equal to the union of agents that returned ≥1 row. Default name is `tar-<first-five-chars-of-sql-hash>` so the operator can save without typing.
3. **Lineage breadcrumb** above the frame mirrors the active scope chip's lineage (`scope-walking-design.md` §8.2).

No changes to the `tar.sql` agent action; the change is purely server-side scope resolution + result-set persistence.

## 5. PR-H — Process tree viewer

### 5.1 Reconstruction model

Per the architectural direction set in the parent conversation:

- The agent runs from boot or first install, hardened against tampering (a separate roadmap track — see `docs/yuzu-guardian-windows-implementation-plan.md` and the open Guardian PR ladder).
- On first start, the agent runs `tar.process_tree` to produce a **seed snapshot** — every PID currently running, with PPID, name, cmdline, user, start_time. Walks `/proc` (Linux), `CreateToolhelp32Snapshot` + `Process32FirstW`/`NextW` (Windows), `proc_listallpids` + `proc_pidinfo(PROC_PIDTBSDINFO|PIDPATHINFO)` (macOS). Stored in `process_live` with a tagged `action='seed'` row per PID.
- From the seed onward, regular `collect_fast` cycles emit `action='started'` / `action='stopped'` events. These are appended to `process_live` and are the canonical mutation stream for the tree.
- At render time, the server queries `process_live` for one device's full history (or a time-bounded slice), replays the seed + events, and produces a tree JSON.

**Honesty in framing.** The tree shows "as observed since `<seed_ts>`" — usually the agent install timestamp. Parents that died before the seed cannot be recovered; their orphan children appear reparented to PID 1 (Linux) / `launchd` (macOS) / `System` (Windows) just as they would be in a live `ps`. The dashboard renders the seed timestamp prominently:

```
Tree as observed since 2026-04-12 09:14 UTC (agent install)
1,402 processes seen · 89 currently running
```

### 5.2 Idempotency of `tar.process_tree`

The action is invoked:
- **Automatically** on every agent start (idempotent — re-running just appends a fresh `seed` row set, marked with the new start's snapshot ID; the dashboard always uses the most recent seed when reconstructing).
- **On demand** via the dashboard "Re-seed" button, useful when the operator suspects the process_live event stream has drifted (e.g., long network partition, rollup race).

### 5.3 Wire surface

`tar.process_tree` action emits one `process|seed|<pid>|<ppid>|<name>|<user>|<start_ts>|<cmdline>` line per running PID at invocation time. Server-side parser writes them as a single batch into `process_live` via the typed insert path.

### 5.4 Renderer

Two server-side paths:

- `GET /api/v1/tar/process-tree/{device_id}` returns `{seed_ts, observation_window_seconds, tree: { pid: 1, children: [ ... ] }}` — the reconstructed tree.
- `GET /fragments/tar/process-tree?device=...` returns HTMX-friendly nested `<details>`/`<summary>` markup — no graph library required for v1.

Time slicing (`?as_of=<ts>` query param) replays events only up to `as_of` — used for "show me the tree at the moment of incident X." Default is "now."

### 5.5 Performance and memory

Seed size on a typical Windows server: 200-400 PIDs. Linux server: 200-1,500 PIDs. macOS desktop: 300-600 PIDs. Event volume per device per day: 10K-200K (a noisy CI box can do 500K+).

The reconstruction is O(events_in_window) per device. For a 30-day window on a 200K-events/day box, that's 6M events — too slow to replay at every page load. Mitigations:

- Server-side per-device LRU cache of the most recent reconstruction (5-min TTL).
- Time-bucketed checkpoints in `process_live` — a periodic background task writes a `__checkpoint__` row with the live tree state every 24h, so a query for "now" only replays since the most recent checkpoint.
- Hard limit on the rendered tree: 50K nodes, then truncate with "Tree exceeds render limit; narrow with `?as_of` or `?root_pid`."

### 5.6 Permissions

`Infrastructure:Read` to view. The tree exposes per-process cmdline which can carry secrets (passwords on the command line, API tokens in env vars rendered into cmdline). The renderer applies the **same redaction patterns** the TAR plugin already uses (`agents/plugins/tar/src/tar_plugin.cpp` `load_redaction_patterns`) before serialisation. Audit row on every fetch: `action: tar.process_tree.read, detail_json: {device_id, as_of, node_count}`.

## 6. Permissions matrix

| Surface | Required | Notes |
|---|---|---|
| `/tar` page load | `Infrastructure:Read` | Same as Devices/Inventory pages |
| Retention-paused list view | `Infrastructure:Read` | |
| Re-enable | `Infrastructure:Update` | Per-device check |
| Purge | `Infrastructure:Delete` | Per-device check + typed confirmation modal |
| TAR SQL submit | `Infrastructure:Read` (today) → may tighten later | The current grant is read-only because TAR SQL is bounded to the agent's own DB and is parameter-checked SELECT-only |
| Save SQL result as result set | `Infrastructure:Read` + result-set creation quota | Per scope-walking-design §3.3 |
| Process tree view | `Infrastructure:Read` | With redaction pass |
| Re-seed process tree | `Infrastructure:Update` | Dispatches `tar.process_tree` to one device |

## 7. Observability

Per `docs/observability-conventions.md`:

| Metric | Type | Labels |
|---|---|---|
| `yuzu_tar_dashboard_view_total` | counter | `frame` (retention/sql/tree), `result` |
| `yuzu_tar_retention_paused_devices` | gauge | `source` |
| `yuzu_tar_purge_total` | counter | `source`, `result` |
| `yuzu_tar_process_tree_render_seconds` | histogram | `node_count_bucket` |
| `yuzu_tar_process_tree_seed_age_seconds` | gauge | `device_id` (only top-N noisiest) |

Audit actions: `tar.status.scan` (operator-triggered Scan fleet — emitted by PR-A.A), `tar.source.reenable` (operator-triggered Re-enable on a row — emitted by PR-A.A), `tar.source.purge` (operator-triggered purge — Phase 15.A.next), `tar.process_tree.read` (Phase 15.H), `tar.process_tree.reseed` (Phase 15.H). All carry `device_id` and `source` in `detail` where applicable.

## 8. Cross-references

- `docs/scope-walking-design.md` — the result-set primitive consumed throughout this page
- `docs/yuzu-guardian-design-v1.1.md` — agent tamper-resistance, foundational to the process tree's data quality claim
- `docs/yuzu-guardian-windows-implementation-plan.md` — Windows-first hardening PR ladder
- `agents/plugins/tar/src/tar_aggregator.cpp` — the #539 retention pause that the retention-paused list surfaces
- `agents/plugins/tar/src/tar_plugin.cpp` — the action surface (`tar.status`, `tar.configure`, future `tar.process_tree`, `tar.purge_source`)
- `server/core/src/dashboard_routes.cpp` — the existing TAR SQL fragment to be relocated and extended
- `docs/data-architecture.md` — error code taxonomy, audit envelope conventions
- `docs/yaml-dsl-spec.md` — DSL surface (gains `fromResultSet:` per scope-walking-design §7)

## 9. Sequencing

| PR | Scope | Status |
|---|---|---|
| PR-A | Page shell + retention-paused list (this doc §3) | **Shipped** PR-A.A (paused_at extension + dashboard page + retention-paused list). Purge action (§3.4) deferred. |
| PR-B | Result-set store + REST API (`scope-walking-design.md` PR-B) | Pending |
| PR-C | Scope chip + sidebar + breadcrumb (`scope-walking-design.md` PR-C) | Pending |
| PR-D | TAR SQL frame migrated and scope-walking-aware (this doc §4) | Pending |
| PR-E | DSL `fromResultSet:` (`scope-walking-design.md` PR-E) | Pending |
| PR-F | Reference IR walkthrough integration test (`scope-walking-design.md` PR-F) | Pending |
| PR-G | Operational hardening (live re-eval, GC, metrics) | Pending |
| PR-H | Process tree viewer (this doc §5) | Pending — waits on agent service-install hardening readiness |

## 10. Open questions

- Should the retention-paused list also surface `<source>_enabled=true` devices that have *zero* recent rows (silent collector failure)? Useful for SRE but visually noisy in IR; defer to PR-G.
- The "Purge data" action should ideally be replaced by an "Export then purge" flow that puts the rows into a signed evidence bundle before deletion — a SOC 2 CC7.2 evidence requirement. Defer to a follow-up issue once the retention-paused list ships.
- Multi-device re-enable (select-many in the table, single click "Re-enable selected") is an obvious affordance once the table has rows; ship in PR-A only if the single-row path is solid.
