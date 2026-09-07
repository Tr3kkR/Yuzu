# P24 → integrator handoff: app_usage docs splice-ins

This package (P24) owns only new files (`docs/user-manual/app-usage.md`,
`changelog.d/7.2-app-usage.added.md`, this file, and the follow-up issue text).
The five hotspot files below are out of this package's scope — verbatim rows for
the integrator to splice in, each grounded against the integrated code as of
`de614b6cc` (see `docs/user-manual/app-usage.md` for the full sourcing).

**Splice these rows only after P26 is integrated** — check
`kCascadeStoreCount = 6` in
`tests/unit/server/test_agent_decommission.cpp` and a single
`scoped_perm_fn_(req, res, "Decommission", "Delete", agent_id)` in
`server/core/src/sle_routes.cpp`.

## 1. `docs/user-manual/tar.md`

### 1a. Configuration table — new row, immediately after `removable_lookback_seconds` (:119, right after the existing `removable_enabled`/`removable_lookback_seconds` pair)

```markdown
| `usage_enabled` | `true` / `false` | **`true`** | Toggle the derived app-usage fold (`usage` source → `$Usage_Live`/`$Usage_Daily`): pairs `process_live` started/stopped events into per-executable runs (`run_usage_fold`, no collector of its own — see `tar-implementer.md` §8). **On by default** — joining `power`/`removable` as a works-council-class source that ships enabled (see `power_enabled` above for what "first" does and does not mean here). What a device runs and when is a presence/working-hours proxy even though `usage` carries no user column of its own (open runs record a `user` field, folded into a `distinct_users` count on write). Unlike `power`/`removable`, the fold ships LIVE in this release — there is no separate "collector lands later" step and no retrospective backfill: coverage begins at the first tick after enablement or upgrade (`usage_coverage_since`, forward-only). Set to `false` to opt out; existing `usage_daily`/`usage_live` rows stay queryable until they age out (31-day `usage_daily` retention; the fold's own 20000-run open-run cap on `usage_live`, `capped` closures accounted in `expired_runs`). |
```

### 1b. Intro amendment (:9)

Current text (What TAR captures, second paragraph) says `power` and `removable`
"are the first sources whose configuration ships *enabled* ... but **neither
collects anything yet**". `usage` (Wave 7) also ships enabled by default, but
**unlike** `power`/`removable` its fold is live from day one — it must not be
folded into the "neither collects anything yet" sentence. Insert a new sentence
immediately after that one:

```markdown
**usage** (Wave 7) also ships enabled by default alongside them, but — unlike power/removable — its fold is live in this release: it derives per-executable run history from the always-on `process` source starting at enablement, with no separate collector to land later.
```

## 2. `docs/enterprise-readiness-soc2-first-customer.md`

### 2a. Agent-side edge warehouse table (§ "Agent-side edge warehouse (`tar.db`, per device — federated, ADR-0004)") — new row, after the `Removable media (Wave 6)` row

```markdown
| App usage (Wave 7) | `$Usage_Live` / `$Usage_Daily` | **Usage-class / behavioral-adjacent telemetry** — per-executable run-count/duration derived from `process` start/stop pairing, plus a per-day `distinct_users` COUNT (no user name persisted). **No pid, command line, or user name in any output.** Reveals which applications run on a device and when → **works-council co-determination-relevant**, same basis as `$Power_Live`/`$Removable_Live`. Live from day one — no retrospective backfill; coverage begins at the first tick after enablement. | **On by default** (`usage_enabled=true`) — joining `power`/`removable` as works-council-class sources shipping enabled; `process`/`tcp`/`service`/`user`/`perf` are already default-on as machine-scope operational telemetry. | 31 d (`usage_daily`); `usage_live` bounded by the fold's own 20 000-run open-run cap (`capped` closures accounted in `expired_runs`), not the table's generic row-count backstop | `usage_enabled` |
```

### 2b. Server-side PostgreSQL stores table (§ "Data Inventory — server-side PostgreSQL stores") — new row, modeled directly on the existing `app_perf_daily_store` row

```markdown
| Application usage, centralized (PR7.2) | `app_usage_store` (`usage_state`, `agent_last_used`) | **Usage-class telemetry** — per-device, per-executable first/last-seen plus a trailing-30-day run-count/total-seconds window, derived on the agent from TAR's `usage_daily` fold via the read-only `app_usage` plugin and centralized by the `app_usage` daily-sync source. **Names-only (`exe_key`) — no pid, command line, or user attribution.** Reveals which applications ran on a device and how much, device-attributable via `agent_id` → **works-council co-determination-relevant** (capability to monitor; BetrVG §87(1)(6)) and personal data under GDPR if treated as such on personally-assigned devices. Read only via `GET /api/v1/forensics/agents/{id}/app-usage` / MCP `get_agent_app_usage`, gated on the scoped `Forensics:Read` securable and audited per access (`app_usage.agent.view`). | Current-state per agent — each sync full-replaces the window (hash-skip over the raw synced blob suppresses re-send while nothing changes); no independent server-side time-based reaper of its own. | Per-agent state is replaced, not accumulated, so there is no server-side aging to reap. **Whole-device purge is WIRED** (ADR-0024, Wave 7 PR7.2) — `AppUsageStore::delete_agent` is the sixth store fanned by the `AgentDecommission` cascade behind the audited **`DELETE /api/v1/sle/agents/{id}`** route, gated on the per-device-scoped `Decommission:Delete` securable (not `Forensics:Delete` — `Forensics` governs this store's READ route only). The store's two-table (`usage_state` + `agent_last_used`) single-transaction delete means it can never be half-erased inside one decommission attempt. **Row-level / per-subject DSAR (Art. 17) erasure remains unwired** — the cascade is whole-device only (#1666). | **`usage_enabled=false`** on the agent (no `usage` fold data → nothing to sync) **and** `--inventory-disable` / `YUZU_AGENT_INVENTORY_DISABLE` (the daily-sync master switch). |
```

## 3. `.claude/routed-concerns.md`

New row, modeled on the existing `power_health set_power_plan` row (:45):

```markdown
| **`app_usage` plugin + TAR `usage` source** — a read-only forensics-gated view (`Forensics` securable, admin-or-approval, single-target) over a DERIVED fold, not a capture source: `run_usage_fold` (transactional, high-water-mark based with its own gap check against `process_live`'s row-cap prune) pairs process start/stop events into per-executable runs — it is not a `CursorSource` and has no collector of its own. Two things a reader must not mistake for gaps: `distinct_users` on a `summary`/`last_used` row is a plain `COUNT(DISTINCT user)`, never a user name or list; and `foreground` is permanently `UNAVAILABLE`/constrained by design (per-session focus-time attribution is not captured by this source on any platform, reserved for the user-context-bridge roadmap). The server-side `app_usage_store` IS in the agent-decommission cascade — its sixth store, erased by a whole-device `DELETE /api/v1/sle/agents/{id}` behind the promoted `Decommission:Delete` securable (Administrator + a targeted ITServiceOwner grant, Wave 7 PR7.2), in the same single-transaction, per-store-committed-status contract as the other five. | `docs/user-manual/app-usage.md` | any change to `agents/plugins/app_usage/`, `agents/plugins/tar/src/tar_usage.*`, `plugin_action_catalogue_app_usage.hpp`, `server/core/src/app_usage_*`, or the `Forensics`/`Decommission` seeds in `rbac_store.cpp` / their `kRbacSecurables` mirror in `mcp_server.cpp`. **Loaded by:** `security-guardian`+`cpp-safety` (fold gap arithmetic, hash-skip ingest); `architect` (`Forensics`/`Decommission:Delete` securables, single-target gate); `consistency-auditor` (securable-count + decommission cascade store count); `docs-writer` (user manual, SOC 2 inventory, routed-concerns row itself). |
```

## 4. `docs/user-manual/README.md`

New index row, immediately after the existing `TAR` row (:37):

```markdown
| [App Usage](app-usage.md) | Read-only, machine-scope application run-time inventory derived from TAR's `usage` fold — per-executable run counts/durations, gated behind the `Forensics` securable |
```

## 5. `docs/tar-implementer.md` §8

Append to the end of §8 ("Adding a capture source"), after its existing steps:

```markdown
**`usage` is not an example of this pattern.** It is a DERIVED source (a fold over
`process_live`, `tar_usage.cpp`/`tar_usage.hpp`) — no `enumerate_<source>()`, no
`compute_<source>_events()` diff, no collector `.cpp` of its own. It still gets a
`CaptureSourceDef` row in `build_sources()` (step 5) so the schema/`$Name_Tier`
translation/queryable-table allowlist machinery applies uniformly, but a new
capture source should follow the numbered steps above, not `tar_usage.*`.
```
