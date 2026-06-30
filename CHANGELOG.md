# Changelog

All notable changes to Yuzu are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **`/auto` VERIFY — before/after application-performance evidence (UAT non-functional).** A third
  stage on the `/auto` page (after ASSESS pre-flight and ACT deploy): did upgrading an app from one
  version to the next change how the **same machines** perform? The shift is computed **per machine,
  paired** — each device's own baseline-version window vs its own candidate-version window (read from
  the shipped per-device B1 store, the window anchored to that machine's transition, **not** to
  "today" — so a staggered rollout still pairs), then the per-machine deltas are aggregated. A fleet
  baseline-vs-candidate diff would be confounded by different populations; pairing on the machine
  holds it fixed. A machine that ran only one version in-window is **excluded and counted**, never
  imputed. **Evidential only — there is no verdict, no threshold, no pass/fail**: the tool reports the
  measured shift (CPU/working-set before→after means, the median per-machine delta, p95 across
  machines) and the up/flat/down split; the operator (or an AI colleague over MCP) judges. There is
  **no cohort floor** — real canaries are 2–3 devices, so a floor would gut the feature; a sub-floor
  paired set is flagged *indicative*, never suppressed, and the read is **audited**
  (`dex.app_perf.compare`, operational) — accountability standing in for the suppression a floor
  would give. Surfaces (all `GuaranteedState:Read`): REST `GET /api/v1/dex/perf/compare`, MCP
  `compare_app_perf_versions`, and the `/auto` dashboard VERIFY stage (aggregate cards + distribution
  + an audited per-machine drill). Pure engine `app_perf_compare` (reducer + `compare` split so a
  later *live* candidate plugs the same slot); B1 cohort read `app_perf_cohort_reader` (agent_id
  preserved). The per-machine pairs are a **dashboard-only** audited drill
  (`dex.app_perf.compare.drill`); REST/MCP expose only the identity-free aggregate.
  Deferred: a REST audited-fail-closed per-machine drill, per-version crashes/hangs (the
  central crash-store join), live measure-right-after-deploy (fan-out procperf), and the
  deploy→verify cohort auto-fill.
- **Idle (inactivity) session timeout (`--session-inactivity-secs`, SOC 2 CC6.3).** Operator dashboard
  cookie sessions can now be invalidated after a configurable period of inactivity — a **sliding**
  window that resets on each authenticated request, *under* the existing absolute 8h session lifetime.
  Wires the previously-reserved `sessions.last_activity_at` column end-to-end (enforced in
  `AuthManager::validate_session`; best-effort throttled `auth.db` mirror via
  `AuthDB::touch_session_activity`). **Default 0 = disabled** (opt-in; existing deployments unaffected;
  recommended `900` = 15 min). Scope is cookie sessions only — **API tokens and MCP tokens are never
  idle-timed-out**, and OIDC users re-authenticate via SSO. `YUZU_SESSION_INACTIVITY_SECS`. Closes
  `/auth-and-authz` gap-matrix P1 #8. See `docs/auth-architecture.md` "Inactivity session timeout".

- **Hardened authentication mode (`--auth-mode=sso-only`) + break-glass account (SOC 2 CC6.3/CC6.6).**
  Local-password login can be disabled fleet-wide so only OIDC SSO mints a session
  (`--auth-mode=sso-only` / `YUZU_AUTH_MODE`). A rejected local login returns the same generic 401 as a
  bad password (no enumeration/mode oracle) and is counted via `yuzu_auth_local_disabled_total` (metric,
  not a per-attempt audit row). A single `--break-glass-user` is exempt **only while armed**, armed
  out-of-band via the host CLI `yuzu-server --break-glass-arm` (auto-expiring, default 24h via
  `--break-glass-window-secs`; audited `auth.breakglass.armed`, attributed to the kernel OS identity).
  Mandatory MFA is enforced fail-closed at boot and at login (an un-enrolled break-glass login is
  hard-denied `403`, never offered enrollment). Use is audited at `Severity::kCritical`
  (`auth.breakglass.login` / `auth.breakglass.denied`) + metric `yuzu_auth_break_glass_login_total`.
  AuthDB migration v4 adds a nullable `users.break_glass_armed_until` column (additive, data-safe).
  **Opt-in: existing deployments default to `standard` and are unaffected.** Enabling `sso-only`
  **refuses to start** without `--oidc-issuer` configured and (if set) a `--break-glass-user` that
  exists and has MFA enrolled — configure OIDC and pre-enroll the break-glass account before
  restarting. See `docs/auth-architecture.md` "Hardened mode", `docs/user-manual/upgrading.md`, and the
  `docs/ops-runbooks/auth-db-recovery.md` break-glass arm runbook. Closes `/auth-and-authz` P0 #3.
- **`/auto` deploy — stage + execute an upgrade on a pre-flight go-cohort.** The `/auto` page
  gains an ACT stage after the ASSESS (pre-flight) stage: as soon as a pre-flight run has a
  go-cohort (≥1 device in bucket go / warn-only — the run need not be complete; the button
  appears with the first cleared device and the count grows mid-run), **Deploy go-cohort**
  stages an installer (download + SHA-256 verify) and then executes it on the devices cleared
  at click time, tracking a per-device stage→execute state machine. A re-deploy of the same run
  excludes devices an earlier deployment already installed (cross-deployment execute-once).
  Pre-flight completion is now event-driven (the result self-poll completes a run the moment its
  cohort settles, not on the up-to-60s background-runner tick). Built on the existing `content_dist` plugin (`stage` /
  `execute_staged`); no new agent code. Born-on-Postgres `DeploymentRunStore` (schema
  `deployment_run_store`) persists the artifact spec, the frozen cohort, and each device's
  step. The result is **aggregate-first** (a KPI strip + progress bar headline the counts;
  the per-device list is problem-first and render-capped) so it reads at fleet scale. Driven
  by an operator today; the engine (`deployment::advance`) is HTTP-agnostic so an agentic
  worker can drive the same path via MCP later. **Safety:** the execute step MUTATES, so —
  unlike the read-only pre-flight checks — it is dispatched **at most once per device**
  (`claim_for_exec` commits `staged→executing` before the command leaves the server; this
  run-once guarantee survives concurrent advances and a server restart), and execute-once is
  also enforced **across deployments** by a create-time resume guard (a partial unique index +
  `find_running_for_run`) so re-clicking Deploy re-attaches to the in-flight run instead of
  re-installing. Every advance **re-authorizes** against the operator's current visible set
  (`devices_fn(viewer) ∩ cohort`); a device the operator has lost scope to is skipped, never run.
  Slice-1 *liveness* is page-driven (no background runner): a closed/timed-out page pauses the
  deployment durably and is resumed by re-opening it. A human `confirm()` gates the deploy. RBAC:
  `SoftwareDeployment:Read` opens the config; the result poll needs `Read`+`Execute` (it advances
  the engine); create needs `Infrastructure:Read`+`Execute`; delete needs `Execute`; owner-scoped;
  operational `deployment.{create,advance,delete}` audit. URL-only on `/auto` (not a new nav tab).
- **Inventory dashboard (`/inventory`).** A point-and-click view over the daily-sync
  installed-software data (ADR-0016). Three tabs: **Software** (the fleet software list —
  title, publisher, install count, distinct versions, with an installs-per-version drill),
  **Devices** (a thin, offline-survivable device list sourced from the persisted endpoint
  state + the live registry; click a device for its installed software), and **Find software**
  (which devices run a given title). The catalogue/version counts are served from a
  **precomputed rollup** (`catalog_rollup` / `version_rollup` / `catalog_rollup_meta`,
  refreshed hourly by a background `SoftwareCatalogRollup` thread, keep-last-good on
  failure) so page reads never run a full-table `GROUP BY` — the underlying data changes
  only on the daily sync. The KPI strip shows an "updated N ago" stamp and a "building"
  state before the first refresh. Gated on the existing `Inventory:Read` (per-device
  reads use the management-group-scoped gate); fleet-wide catalogue/find counts are not yet
  management-group scoped (ADR-0017 confinement inert under the global gate — caveated in the
  UI). On store degradation the authoritative reads (Software/Find/per-device-software) show an
  "unavailable" banner, never an empty table (ADR-0016 §7); the fail-soft device roster may show an
  empty list during a database incident (its empty-state copy says so). New audit verbs
  `inventory.software.{catalog,versions}`, `inventory.device.software`, and `inventory.devices` (the
  Devices roster read — set-and-proceed); `inventory.software.query` (pre-existing on the REST
  endpoint) is now also emitted by the dashboard Find tab and documented.
  New nav item + command-palette entry.
- **DEX app-performance over time — per-device drill dashboard UI.** The per-device app-perf
  history (REST `GET /api/v1/dex/devices/{id}/app-perf`, shipped in slice 2) now has a dashboard
  surface: an "Application performance over time" panel on the `/device` DEX drill, beside the
  live Top-applications query. It reads the **central** B1 store (no live device query, no
  `Execute` permission — a read-only operator can open it), groups each application with its
  **versions** as sub-rows, and renders a per-`(app, version)` CPU-over-time sparkline plus the
  window's sample-weighted avg / peak CPU and working set, so a per-version regression on one
  device reads straight off adjacent rows. Behavioural PII: per-device-scoped
  `GuaranteedState:Read` + the **same `dex.device.app_perf.view`** audit verb as the REST drill,
  under the dashboard set-and-proceed posture (sets `Sec-Audit-Failed` but still renders, distinct
  from the REST fail-closed surface). A new pure reduction `app_perf_device_summaries` (in the
  shared `dex_app_perf_model`) feeds the renderer; REST stays raw daily rows; still **no MCP twin**
  (the fail-closed contract can't be expressed on MCP). Deferred: the per-version crashes/hangs
  join (a separate central crash-store join on `(name, version)`).
- **DEX app-performance over time (slice 2) — the operator read surface.** The B1/B2 stores
  below are now readable. REST (all `GuaranteedState:Read`): `GET /api/v1/dex/perf/apps` (the
  picker — apps with retained data), `GET /api/v1/dex/perf/app?app=&version=` (fleet trend, per
  `(version, day)`), `GET /api/v1/dex/perf/group?group_id=&app=&version=` (one management group's
  on-the-fly trend), and the per-device `GET /api/v1/dex/devices/{id}/app-perf`. MCP twins
  (read-only): `list_dex_perf_apps`, `get_dex_app_perf`, `get_dex_group_app_perf` (the per-device
  drill has no MCP twin; its dashboard panel is in the entry above). Dashboard: a picker + per-version trend on the DEX
  Performance tab, fleet-wide or scoped to a group via a selector. One shared pure transform
  (`app_perf_fleet_trend`/`app_perf_group_trend`/`app_perf_version_summaries`) feeds REST, MCP and
  the dashboard so they cannot disagree. **Privacy:** both the fleet AND group aggregates suppress
  any `(version, day)` point below `kDexCohortFloor` (10) devices to a count only — a sub-floor
  aggregate singles out an individual even without an `agent_id`; percentiles are
  bucket-resolution (`lower_bound`/"≥" when in the open top bucket) and withheld (`hist_stale`)
  for a row under a superseded histogram scheme. The per-device drill is behavioural PII — scoped
  to the caller's management group and audited fail-closed (`dex.device.app_perf.view`; 503 +
  `Sec-Audit-Failed` if the audit row can't persist). Aggregate reads are not individually audited
  (cohort posture). Group trend reads B1 (≤31 days); fleet trend reads B2 (≤180 days); per-app
  sampling stays opt-in (`procperf_enabled`, off by default), so data appears only after the first
  completed UTC midnight on an opted-in device. Deferred: per-version crashes/hangs join and a
  device-drill MCP tool. (The per-device drill's dashboard UI shipped — see the entry above.)
- **DEX app-performance over time (B1) — per-device daily app-version perf, centralized.**
  New daily-sync source `app_perf` (agent) rolls the on-device `procperf_hourly` warehouse up to
  per-`(app, version, day)` daily summaries — sample-weighted CPU/working-set, max-of-max peaks,
  the last 2 completed UTC days per cycle — and ships them over the existing `ReportInventory`
  transport as a new `plugin_data` key (no proto change, no gateway regen). New born-on-Postgres
  `AppPerfDailyStore` (schema `app_perf_daily_store`, 31-day retention, plain table + per-agent
  prune) persists them via a shared ingest seam wired identically on the direct `ReportInventory`
  and gateway `ProxyInventory` paths, so fleet questions like "which devices ran v124 and how did
  it perform" become answerable without federating to every endpoint. Version is canonicalized at
  ingest (the same `canon_version` the stability side uses) so perf joins app stability by
  `(app, version)`. Hash-less (perf changes daily → always full); scope is resource-significant
  (procperf top-N) app-versions, not a full app census. Windows-fed today (procperf is
  Windows-only); gated by `procperf_enabled` + the `--inventory-disable` daily-sync master switch.
  Its read surface (per-device drill + group trend) shipped in slice 2 — see the entry above.
- **DEX app-performance over time (B2) — fleet-aggregate trend substrate.** New born-on-Postgres
  `AppPerfFleetStore` (schema `app_perf_fleet_store`, 180-day retention) holds one row per
  `(app, version, UTC day)`: fleet device-count, exact CPU/working-set sums + maxima, and a
  fixed-bucket histogram of per-device daily values (CPU low-end-weighted, working-set log-scale)
  so true fleet percentiles (p50/p95) are computable over the long window without storing
  per-device rows. Built from B1 by `AppPerfRollup` — the ADR-0012 cross-store query owner — as one
  server-side `INSERT … SELECT … ON CONFLICT` per day (histogram via `COUNT(*) FILTER` over
  half-open buckets; no per-device data crosses the wire), driven by an hourly background thread
  that re-rolls a 4-day trailing window (idempotent; absorbs late-arriving B1) and prunes beyond
  180 days. Full version grain (coarsen to major.minor on read). Histogram boundaries are frozen
  (`hist_version` stamps the scheme); derived percentiles are bucket-resolution approximations.
  Its read surface (fleet trend + picker, REST/MCP/dashboard) shipped in slice 2 — see the entry
  above. The aggregate carries no `agent_id`, and sub-floor `(version, day)` points are suppressed
  to a count only on read — no per-device attribution, no singling-out.
- **Pre-flight readiness page (`/auto`).** New dashboard page for operator-initiated go/no-go checks
  across a scoped device cohort before a fleet change. Checks: application version (min/max), OS version
  floor, OS architecture, minimum free disk, and pending-reboot status — grouped per device
  (Pass / Failed / Warn-only / Incomplete) with a run-level summary. Runs persist in a new born-on-Postgres
  `PreflightRunStore` (schema `preflight_run_store`) for 14 days and are owner-scoped (an operator sees only
  their own runs; the result read is owner-scoped at the store seam, so another operator's run is
  indistinguishable from not-found). A background runner re-dispatches the read-only checks to devices that
  reconnect within the run window. Audit verbs: `preflight.run` (gates `Infrastructure:Read` + `Execution:Execute`)
  and `preflight.run.delete` (gates `Execution:Execute`). Reached by URL — not a nav tab.
- **`disk_space` agent plugin — cross-platform free-space probe.** New plugin (Windows/Linux/macOS),
  single `free` action: returns total bytes, free bytes, and percent used for a volume (`path` param;
  default `C:\` / `/`). Free is quota-aware caller headroom (`FreeBytesAvailableToCaller` on Windows,
  `f_bavail` on POSIX). Content definition `crossplatform.storage.free`.
- **Device page — live Disk space card.** New card on the device "Get live info" lens dispatches
  `disk_space/free` on demand; per-volume table with a colour-coded usage bar (>=90% used or <5 GiB
  free = red, matching the `storage.low` DEX threshold). Audit verb `device.live.disk`.
- **REST endpoint for fleet-wide installed-software inventory (ADR-0016 follow-on).**
  `GET /api/v1/inventory/software` exposes the typed `SoftwareInventoryStore` over REST
  (gated on `Inventory:Read`), the agentic-first sibling of the `query_installed_software`
  MCP tool. Filter by `name` / `agent_id` (omit both for a fleet scan); `limit` capped at
  1000 with `result_truncated_by_cap` when more rows exist. A per-agent management-group
  drop filter is applied — out-of-scope devices are dropped and counted in `devices_omitted`
  (a positive value means matching software exists outside your scope, **not** "absent
  fleet-wide") — but this confinement is **not yet verified effective** under the global
  `Inventory:Read` gate (ADR-0017; see `docs/user-manual/inventory.md` §Scope),
  with a distinct scope-denied audit row. On store degradation it returns `503` (an A4
  error envelope), **never** an empty `200`, so a vulnerability query cannot read a
  transient Postgres outage as "installed nowhere" (ADR-0016 §7 authoritative reads). A
  software dashboard / per-device drill-down remain planned follow-ons.
- **Agent daily-sync framework + installed-software inventory in Postgres (ADR-0016).** The agent now
  pushes endpoint state to the server on a per-source daily cadence over `ReportInventory`, starting
  with **installed software** (machine-wide scope; no per-user/PII). It is kind to the network at
  fleet scale: each endpoint spreads its sync by a stable per-agent phase offset (no lockstep), and
  when a source's content is unchanged since the last successful sync it sends only a **content hash**
  instead of the full list (hash-skip); the server replies `need_full` to force a resend on a cold
  cache, with a weekly full-floor as a backstop. Installed software lands in a new born-on-Postgres
  **`SoftwareInventoryStore`** (normalized rows — portable SQL, no JSONB — so fleet-wide queries
  like "which devices run X" are first-class), via a shared ingest seam wired identically on the
  direct and gateway paths. Reads are gated on a new **`Inventory` RBAC securable** (`Inventory:Read`).
  Reuses the existing `installed_apps` plugin (Windows/Linux/macOS) in-process — no new collector.
  Hardened for fleet-scale resilience: a per-source blob cap sized below the gRPC message ceiling,
  exponential agent-side backoff on consecutive `need_full` resends (so a server cold-cache or store
  outage cannot drive a flat-cadence full-resend storm), a `yuzu_inventory_ingest_total{source,outcome}`
  metric, and the store wired into both `/readyz` and `/healthz`. Readable now via the
  **`query_installed_software` MCP tool** (`Inventory:Read`, filter by name/agent, management-group
  scoped so an operator sees only their own devices) — distinct from the generic `query_inventory`
  tools, and via **`GET /api/v1/inventory/software`** (REST; see the separate entry above). A
  software dashboard is a planned follow-on. A deploy-time opt-out
  (**`--inventory-disable`** / `YUZU_AGENT_INVENTORY_DISABLE`) disables collection entirely for
  privacy-sensitive / works-council jurisdictions. Inventory fields are sanitized to valid UTF-8
  (invalid bytes → U+FFFD) and truncated on codepoint boundaries — byte-coordinated between agent and
  server — so a non-UTF-8 registry string can never trigger a PostgreSQL TEXT-reject resend loop;
  concurrent full-replaces for one agent are serialized with a transaction-scoped advisory lock (no
  row/hash divergence); a transient empty collection is skipped rather than wiping stored inventory;
  an over-cap blob raises a dedicated `dropped`-outcome alert (it never self-heals); and
  `query_installed_software` reports `devices_omitted` so a scoped caller can distinguish "outside my
  scope" from "not installed". **Reads are authoritative** (ADR-0016 §7): `query_installed_software`
  returns a JSON-RPC error — never a silent `success` with empty rows — when the Postgres store is
  degraded (pool/query failure), so a fleet vulnerability query can never read a transient backend
  hiccup as "installed nowhere". An ingest report carrying an implausibly large source map is rejected
  wholesale, and concurrent-replace serialization uses a 64-bit advisory-lock key.

### Security

- **Response/execution reads fail closed on a corrupt/load-failed `rbac.db`; per-agent
  management-group scope-filter foundation added (#1634, PARTIAL — the gate change that makes
  management-group scoping effective for normal operators is NOT in this change and remains open
  under #1634).** The response readers (MCP `query_responses` + `aggregate_responses`, REST
  `GET /executions/{id}/visualization`, and the legacy `GET /api/responses/{id}` / `/aggregate` /
  `/export`) gained a per-agent management-group filter, routed through ONE predicate
  (`response_agent_in_scope` → `check_scoped_permission`) gated on `rbac_enforcement_in_effect`.

  **What this fixes today (the real, observable change):** under a **corrupt or load-failed
  `rbac.db`**, `require_permission`'s legacy fallback opens READ to any authenticated principal, so
  these readers previously returned the **whole fleet's** responses to anyone. They now fail
  **closed** (zero rows), matching the #1498 device-visibility posture. A transient response-store
  read error while resolving scope likewise fails closed — surfaced as `503` (REST aggregate) / a
  JSON-RPC internal error (`aggregate_responses`), never success-with-empty-totals (agentic-first A4
  failure-vs-empty).

  **What this does NOT yet do (important — no false sense of security):** under **normal RBAC
  operation the filter is inert.** A holder of global `Response:Read` passes the gate and
  `check_scoped_permission`'s global step then admits every agent (filter is a no-op → sees all);
  a management-group-confined operator is `403`'d by the global `require_permission` gate **before**
  the filter runs. So this does **not** bound a normal operator's responses to their management
  groups and does **not** close the cross-operator read #1634 describes. Achieving that requires a
  new admit-then-filter **gate** for fan-out/list reads (admit an operator holding the permission via
  *any* management group, then filter) — a systemic change that also affects `/api/agents`,
  `/devices`, the dashboard `/fragments/results/…` family, and the shipped #1550, and is tracked as
  the remaining work under **#1634**. This change is the filter foundation that gate will build on.

  Also included: each scope-drop is auditable (`aggregate_responses` → distinct `result=denied` +
  `audit_persisted:false` on a gap; visualization → `scope_dropped=N` on its
  `execution.visualization.fetch` success audit; legacy `/api/responses/*` → a `response.read`
  `result=denied` audit, `detail=scope_dropped=<N> surface=<…>`); `ResponseStore::aggregate` takes a
  dedicated scope parameter (off the shared `ResponseQuery`, so the row-path readers can't be handed
  a silently-ignored scope); `distinct_agent_ids` returns `optional` (a store-read error is distinct
  from a genuinely-empty result); and `aggregate`/`distinct_agent_ids` own their statements via
  `SqliteStmt` RAII.

- **Inventory freshness gauge is now immune to agent clock skew (#1685, ADR-0016).** The
  `yuzu_inventory_stale_agents` gauge counts agents whose installed-software inventory has not synced
  within the staleness window. It was fed by `inventory_state.last_seen`, stamped from the
  **agent-supplied** `collected_at` — so the gauge compared a server-side threshold (`now − 2d`)
  against an agent clock. A future-skewed or hostile agent could pin `last_seen` ahead of now and
  **never count as stale**, hiding a disappeared endpoint; a >2d past-skewed agent counted as stale
  while actively syncing. `last_seen`/`first_seen` are now the **server receipt time**, so both sides
  of the comparison are on one clock. `collected_at` stays on the wire for a future content-age signal
  but drives no persisted timestamp. A one-time data backfill clamps any pre-fix row whose `last_seen`
  or `first_seen` was written into the future back down to now, so a previously-hidden dark endpoint
  re-enters the freshness window. No schema change — the column had no other consumer.

- **Behavioural-data audit failures are now surfaced uniformly across every per-device / per-signal
  route (#1647, CC7.2 / CC6.1).** A per-person behavioural read whose access-audit row silently
  failed to persist (audit DB locked/full, or a `bad_alloc`-class throw) could previously look like
  a clean, audited read. Every such route now routes through one shared helper
  (`server/core/src/rest_audit.hpp`) that captures the `AuditFn` result behind a `try/catch` (the
  throw arm was previously silent on several routes), logs the gap, and surfaces it per surface:
  - **Dashboard fragments** (`/fragments/device/dex`, `/fragments/device/guardian`, and the `/dex`
    drill-downs) set the `Sec-Audit-Failed: true` response header and **still render** — a transient
    audit hiccup must not blank the operator's lens. The two `/fragments/device/*` lenses previously
    **discarded** the result entirely; they now match the long-documented set-and-proceed contract.
  - **REST** (`GET /api/v1/dex/devices/{id}`, `/api/v1/dex/signals/{obs_type}`,
    `/api/v1/guaranteed-state/events?agent_id=`, and
    `/api/v1/guaranteed-state/device-compliance`) **fails closed** with
    `503` + `Sec-Audit-Failed: true` and serves no PII.
  - **MCP** `get_dex_signal_detail` previously discarded the result; it now carries
    `audit_persisted:false` in the tool result (set-and-proceed, no JSON-RPC header channel),
    matching the `query_responses` / `revoke_certificate` convention.

  Alert on `Sec-Audit-Failed: true` (or `audit_persisted:false`) from any surface as a SOC 2 CC7.2
  evidence-gap signal.

- **Behavioural dispatch-audit sites routed through the shared chokepoint for catch-arm parity
  (#1647 follow-up).** The remaining per-device/per-signal routes that still called the `AuditFn`
  raw — `device.live.*` (`/fragments/device/live/run`), `dex.device.perf.query` /
  `dex.device.procperf.query`, and the `tar_tree_routes` dispatch/read sites
  (`tar.process_tree.{read,detail}`, `tar.dns.read`, `tar.arp.read`, `tar.sources.{read,configure}`)
  — now go through `detail::emit_behavioral_audit` in `server/core/src/rest_audit.hpp`. A throwing
  `audit_fn` (`bad_alloc`-class) is caught and logged instead of escaping the handler (httplib would
  have turned it into a `500`). Each route keeps its existing **dispatch/set-and-proceed** posture
  (no read-PII route became a `503`). The `tar_tree_routes` sites previously **discarded** the audit
  bool and set no header; they now surface `Sec-Audit-Failed: true` on a dropped/throwing audit row,
  matching the migrated sibling routes. No audit verbs changed.

- **MCP `query_responses` gained a per-agent management-group filter (#1550) — but it is INERT
  under the global gate and does NOT yet isolate operators; see the #1634 entry above.** The tool
  previously gated only flat `Response:Read` and then returned **any** execution's response rows
  (`dispatched_by` was display-only, never an access check). A per-agent filter through the
  `check_scoped_permission` chokepoint was added — HOWEVER, as the #1634 entry documents, the reader
  still gates on the **global** `Response:Read`, and `check_scoped_permission`'s global step then
  admits every agent for a global holder, so under normal RBAC operation **no rows are dropped** and
  a caller does **not** see only their groups' rows. It does **not** close the cross-operator read;
  its only active effect today is failing **closed** (zero rows) on a corrupt `rbac.db`. Effective
  isolation needs the admit-then-filter gate change tracked under #1634. Out-of-scope rows, when
  dropped (the corrupt-store path), are audited `result=denied` (with the distinct dropped-agent
  count); the `denied` row's persistence failure surfaces `audit_persisted:false`. RBAC-off →
  legacy-open (no filter), matching `require_scoped_permission`. The filter runs after
  the 1000-row cap, so a result that hit the cap before filtering carries
  `result_truncated_by_cap:true` — collectors must not treat `count<limit` as "done"; complete
  collection of >1000-row executions is the keyset-pagination follow-up (#1634). *(The same
  per-agent filter is now also on `aggregate_responses`, the REST visualization reader, and the
  legacy `/api/responses/*` readers — but see the #1634 entry above for the important caveat that
  this filter, INCLUDING `query_responses`', is currently **inert under the global `Response:Read`
  gate** (a normal holder sees all agents) and its only active effect is failing **closed** on a
  corrupt `rbac.db`; effective management-group scoping needs the #1634 gate change. Still flat —
  and **fail-OPEN on a corrupt `rbac.db`** (no filter at all) — are the dashboard `/fragments/results/…`
  family and the workflow executions-drawer reader (tracked under #1634, same UP-1 class). Service-scoped
  tokens are scoped by the token creator's RBAC, not the service tag.)*

- **DEX per-device endpoints: audit-fail-closed + A4 denial enrichment.** `GET /api/v1/dex/devices/{id}`,
  `POST /api/v1/dex/devices/{id}/live`, `GET /api/v1/guaranteed-state/events` (agent-scoped),
  and `GET /api/v1/dex/signals/{obs_type}` now return `503` + `Sec-Audit-Failed: true` and
  withhold behavioral PII — or, for `/live`, do **not** dispatch the probe — when the SOC 2
  CC7.2 audit row cannot persist. The prior behavior silently served data (or dispatched) with
  an evidence gap. `/live` now audits **pre-dispatch** (`result=requested`, was the
  post-dispatch `result=dispatched`); the `detail` carries `cid=<correlation_id>` as the join
  key. The two per-device endpoints (`/dex/devices/{id}`, `/live`) echo `X-Correlation-Id`
  (the agent-scoped `events` / `signals` siblings carry a server-side `spdlog::warn` instead).
  `401`/`403` denial bodies from
  `require_scoped_permission` now carry `correlation_id` + a structured `permission`
  (`SecurableType:Operation`) A4 field. Dashboard DEX PII drill-downs + perf/procperf dispatch
  panels set `Sec-Audit-Failed: true` on audit failure but continue to render (HTML surface —
  a transient audit hiccup must not blank the dashboard, unlike the fail-closed REST endpoints).
  **Behavior change for API consumers:** an audit-store outage now yields `503` where it
  previously returned `200`; automation should treat `Sec-Audit-Failed: true` as "retry after
  the audit subsystem recovers."

### Changed

- **TAR `tar.configure` now advertises every per-source enable toggle and the software
  tuning params in its discovery schema.** `perf_enabled`, `procperf_enabled`,
  `netqual_enabled`, `module_enabled`, and `software_enabled` (plus `software_interval`)
  were already accepted by the agent but missing from the
  build-embedded `crossplatform.tar.configure` definition, so an agentic worker could not
  discover or tune them (notably the enable toggle for the opt-in, off-by-default
  `software` source). No runtime behaviour change — the params were always honoured; they
  are now discoverable. (Docs note that `perf_interval_seconds`, by contrast, is read at
  trigger registration and is not a `tar.configure` param — use `perf_enabled` to stop
  perf collection at runtime.)
- **`win_str.hpp` relocated to `agents/shared/` + the #1681 de-dup sweep completed.** The shared
  Windows wide<->UTF-8 helper moved from `agents/plugins/shared/` to a new `agents/shared/` sibling
  leaf so agent-**core** can reach it without inverting the core-depends-on-plugins direction. The
  agent-core files (`process_enum`, `dex_observer`, `guard_registry`, `guard_service`,
  `trigger_engine`; `guard_file`'s dead copy removed) and the remaining plugins (`processes`,
  `device_identity`, `filesystem`, `hardware`, `ioc`, `content_dist`, `disk_space`,
  `tar_dns_collector`, `tar_proc_etw`, `tar_proc_perf`, `tar_arp_collector`) now delegate to
  `yuzu::win::{to_wide,from_wide,reg_sz_to_utf8}`. `temp_file` (caller-buffer contract) and
  `installed_apps` (interior-NUL semantic divergence) deliberately retain their own copies.
  Behaviour-preserving; no user-facing change.
- **Inventory ingest observability polish (#1686).** Three independent refinements from the #1683
  governance run. (1) A shared-SDK `histogram(name, [labels,] buckets)` overload lets a histogram be
  created with custom bucket boundaries; `yuzu_inventory_ingest_duration_seconds` and
  `yuzu_pg_acquire_wait_seconds` now use a bucket set extended into the 10-60s range so the saturation
  tail no longer collapses into `+Inf` (the slow-ingest alert reads a real bucket rather than the
  `+Inf`-minus-`le=10` complement). A `yuzu:inventory_ingest_duration_seconds:p99` Prometheus
  **recording rule** (per `source`/`phase`, `[10m]` window matching the slow-ingest alert) ships
  alongside, precomputing the now-resolvable tail quantile the extended buckets make meaningful.
  (2) The per-site read-degrade WARN sampler is now episode-relative: a new outage after a quiet gap
  re-logs its leading edge instead of staying silent until the next hundredth occurrence because
  process-lifetime sampling already spent its "1st" on an earlier, recovered outage (the
  `yuzu_inventory_read_degrade_total` counter is unaffected — log fidelity only). (3) Issue-ref tokens
  (`(#NNNN)`) were stripped from metric HELP text, which is customer-visible on `/metrics` / Grafana.
  The deterministic stuck-`need_full` per-agent signal is deferred pending a real-fleet IO baseline.

- **Installed-software inventory ingest is batched, and the ingest/read paths are now observable
  (#1664/#1675).** `SoftwareInventoryStore` applies a full payload in a single
  `INSERT … SELECT … unnest($1::text[], …)` statement instead of up to 20 000 single-row inserts,
  collapsing the per-agent connection-hold and `statement_timeout` exposure that, under a cold-cache
  `need_full` herd, could saturate the shared Postgres pool and flip healthy agents touched→full.
  New series make the path measurable: `yuzu_inventory_ingest_duration_seconds{source,phase}` (the
  pooled-connection + transaction hold time, split `full` vs `hash_only`), `yuzu_inventory_read_degrade_total{reason}`
  (an authoritative read that degraded rather than returning a silent empty — otherwise invisible
  since `/readyz` stays green under pure saturation; the per-site WARN is now sampled to avoid
  flooding the log at agentic fan-out), `yuzu_inventory_stale_agents{source}` (a freshness gauge,
  fed by an execution-bounded count so it can never stall the revocation-teardown sweep it shares a
  thread with), and `yuzu_inventory_stale_count_unavailable_total` (a freeze-detector so a held gauge
  is distinguishable from a genuine low). New `YuzuInventoryReadDegraded`, `YuzuInventoryIngestSlow`,
  and `YuzuInventoryStaleCountUnavailable` alert rules ship active in the `yuzu-inventory` group;
  `YuzuInventoryStaleAgents` ships disabled (no fleet-size-independent threshold — enable after
  baselining, see `docs/user-manual/inventory.md`).

- **BREAKING — the server now runs on PostgreSQL (ADR-0006/0007).** The server constructs a
  shared connection pool at startup and **fails closed** (refuses to boot, exits non-zero) when
  `--postgres-dsn` / `YUZU_POSTGRES_DSN` is unset or the database is unreachable — there is no
  SQLite fallback for the server (the agent stays SQLite). The bundled `yuzu-postgres` image
  and the `YUZU_POSTGRES_DSN` wiring in every server compose were added in prior releases; this
  release is the cut-over that makes the server *require* them. **Operator action:** provision a
  reachable PostgreSQL (the bundled image, a managed instance, or
  `scripts/install-server-postgres.sh`) and set `YUZU_POSTGRES_DSN` before upgrading. See
  `docs/user-manual/server-admin.md` → "PostgreSQL substrate".

### Fixed

- **PostgreSQL substrate container refused to boot on PostgreSQL 18 (#1739).** Every bundled
  Docker Compose mounted the `postgres-data` volume at `/var/lib/postgresql/data` (the pre-18
  `PGDATA` path). The `postgres:18` image stores data in a version-pinned subdirectory
  (`/var/lib/postgresql/18/docker`) and treats a volume mounted at the legacy path as an
  un-migrated upgrade, so the container exited 1 in a restart loop and the `server` service
  (which `depends_on` the postgres healthcheck) never started (docker-library/postgres#1259).
  The volume is now mounted at the PG18-recommended parent `/var/lib/postgresql` across all
  eight affected composes (including the base `docker-compose.yml` the original report missed),
  the two reference composes' non-working `PGDATA: /var/lib/postgresql/data` override has been
  removed (PGDATA is left at the image default), and the Compose Wizard generator
  (`tools/compose-wizard/`, a packaged release asset) now emits the parent mount and the
  correct "PostgreSQL 18" label. Unreleased — postgres is a `dev`-only feature with no
  `Dockerfile.postgres` at v0.12.0, so no shipped release is affected.
  **Dev/UAT upgrade note:** an operator who already ran one of these stacks before this fix
  has a pre-18 cluster at the volume root that PG18 cannot read in place; on first boot under
  the new mount PostgreSQL silently re-initialises an empty cluster at `…/18/docker` and the
  old data is orphaned (not destroyed) inside the same volume. Since the substrate carries no
  production data yet, discard just the stale Postgres volume before the first PG18 boot —
  `docker compose down` then `docker volume rm <project>_postgres-data` (or
  `<project>_postgres-uat-data` for full-UAT). **Do not** use `docker compose down -v`: it
  also removes `server-data` and the reference compose's `certs` volume (the per-install CA +
  leaf certs), which would force the entire fleet to re-enroll.
- **DEX Catalogue now credits the full Linux signal coverage (was 7, now 17 types).** The per-OS
  coverage map (`dex_obs_platforms`) that colours the Catalogue's "monitored / not collected on
  Linux" badges was frozen at the original 7-type conservative set from before the Linux
  kernel/sysfs collectors existed — the collectors landed without the map being updated in the same
  change. A Linux fleet's Catalogue therefore showed `perf.disk_latency_high`, `hw.cpu_throttled`,
  `service.hung`, `os.time_unsynced`, `os.bugcheck`, `os.dirty_shutdown`, `disk.error`,
  `fs.corruption`, `hw.error`, and `process.hung` as *not collected* even though the agent emits
  them — via `poll_perf` (the `/proc` CPU/memory/diskstats breach trio), the sysfs CPU-throttle
  poll, and the journald poll whose kernel-transport lines are classified by `dex_linux_kmsg`. The
  map is now authoritative at 17 types, so those families render as monitored on any connected
  Linux agent. macOS coverage (16) was already correct and is unchanged. No agent change, no data
  change — Catalogue display only; the drift-net test now pins the map to the emitted set on both
  platforms.
- **Doc honesty: retract over-claimed management-group list-view confinement (ADR-0017 / #1716).**
  `GET /api/v1/inventory/software`, MCP `query_installed_software`, and the TAR retention-paused
  list carry a per-agent management-group drop filter that is **not yet effective** under the
  *global* `Inventory:Read` / `Infrastructure:Read` gate (a confined operator is denied at the gate;
  a global operator's filter is a no-op). Docs, the SOC 2 / CAIQ CC6.1 evidence, the capability map,
  and the relevant code comments are corrected to "designed, not yet verified — per-device
  confinement only"; ADR-0016 gains an appended Update note (immutable original preserved). The
  responses surface logic fix is a separate ladder (#1634 / #1718 PR-B); its docs and code comments
  are annotated here with the same caveat. No behavior change.
- **Installed-software inventory now preserves non-ASCII app names on Windows (#1662).** The
  `installed_apps` plugin read the registry uninstall keys via the ANSI `Reg*A` APIs, which return
  strings in the system code page (cp1252 on Western installs), not UTF-8. The plugin's defensive
  UTF-8 scrub then replaced the resulting invalid bytes with `?` (`Café` → `Caf?`), so any app or
  publisher with a non-ASCII name was corrupted in the output — and, now that the names land in the
  typed `SoftwareInventoryStore`, broke the flagship exact-match query `WHERE name = $1`. The plugin
  now reads via the wide `Reg*W` APIs and converts UTF-16 → UTF-8 with `WideCharToMultiByte(CP_UTF8)`
  (the same idiom the `registry`/`processes` plugins already use), so names like `Café Ñoño 日本語`
  round-trip intact. Affects both machine-scope registry read paths (`list`, `query`). The ingest seam's UTF-8 scrub remains as
  defence-in-depth (and still covers the Linux/macOS subprocess paths, whose output encoding is
  unknown). No proto/wire change.

- **Sibling inventory plugins now read non-ASCII registry strings as UTF-8 (#1682), via a shared
  helper (#1681).** Four plugins read the registry with the ANSI `Reg*A` APIs and carried the same
  cp1252 mojibake as #1662 on any non-ASCII value: `vuln_scan` (the installed-apps enumerate path —
  the same shape as the pre-#1662 `installed_apps`, including a `RegEnumKeyExA` key-name enumeration —
  plus `config_checks.hpp`), `os_info` (the OS `ProductName` / edition strings), `sccm` (the SCCM
  client version), and `windows_updates` (the WSUS `WUServer` URL). Every read whose value lands in a
  stored or fleet-queryable surface now uses the wide `Reg*W` APIs + `WideCharToMultiByte(CP_UTF8)`;
  presence-only checks that never decode a value string (e.g. the `windows_updates` reboot-pending
  probes) are deliberately left on `Reg*A` since they carry no encoding. The `vuln_scan` path also
  picks up the full #1662 hardening (WCHAR-count `RegEnumKeyExW` and RAII handle closing). The
  `to_wide` / `from_wide` / `reg_sz_to_utf8` converters now have a canonical home in a single
  Windows-only header `agents/shared/win_str.hpp` (`namespace yuzu::win`, header-only so each
  plugin still compiles its own copy and build isolation is preserved). The plugins that carried a
  **named** wide<->UTF-8 helper are migrated to it: the four siblings above, plus a **de-dup migration**
  of `registry`, `wmi`, `services`, `interaction`, `tar_module_etw` (the trio / mixed local copies) and
  `network_config`, `procfetch`, `sockwho`, `users`, `wifi`, `tar_service_collector`, `tar_user_collector`
  (the `process_enum`-style `wide_to_utf8`). Most switch via a `using` declaration (the local name
  coincided); `wmi` (`from_bstr`) and `tar_module_etw` (`std::string`/`std::wstring` signatures) keep thin
  delegating shims. This is a **partial** consolidation — **not** every conversion site: other plugins
  (`processes`, `device_identity`, `filesystem`, `hardware`, `ioc`, `content_dist`, and the
  `tar_dns_collector`/`tar_proc_etw`/`tar_proc_perf`/`tar_arp_collector` siblings) and several agent-**core**
  files (`process_enum`, `dex_observer`, `guard_file`, `guard_registry`, `guard_service`, `temp_file`,
  `trigger_engine`) still carry their own named or inline conversions; a comprehensive sweep is a tracked
  follow-up, and `installed_apps` keeps its copy (its #1662 fix is already on `dev`). `reg_sz_to_utf8` stops at the
  first NUL (correct `REG_SZ` / `REG_EXPAND_SZ` semantics — a deliberate hardening over the
  `installed_apps` copy, which strips trailing NULs only), so a malformed interior NUL yields a clean
  prefix instead of silently truncating the whole output line at the SDK's `const char*` boundary. The
  four simple readers close their key **before** the allocating UTF-8 conversion, so a `std::bad_alloc`
  cannot leak the `HKEY`. Deterministic unit coverage (`tests/unit/test_win_str_utils.cpp`): round-trip,
  trailing-NUL strip, embedded-NUL stop, non-`wchar_t`-multiple size, 512-`wchar_t` no-terminator,
  lone-surrogate → U+FFFD, null/empty. No proto/wire change. (Verified on Windows: unit tests + a
  per-plugin MSVC compile, and an end-to-end smoke inside the Hyper-V agent VM that seeded a non-ASCII
  `DisplayName` "Café Ñoño 日本語" under `HKCU\…\Uninstall` and confirmed it round-tripped byte-exact
  UTF-8 through the real `RegEnumKeyExW` + `reg_sz_to_utf8` read path.)

- **Guardian Windows service guards now report `guard.compliant` on the compliant edge.**
  A `service-running` / `service-stopped` guard watching a steadily-compliant service
  previously short-circuited silently and never emitted `guard.compliant`, so the
  per-(agent, rule) compliance census read "pending" indefinitely for that guard — a
  compliant service could never show as compliant (on the dashboard or the per-device
  REST read). The `registry` and `file` guards already emitted the compliant edge; the
  Windows `service` guard was the outlier and is now aligned. No proto/wire change; the
  compliant-edge classifier is extracted as a pure, cross-platform, unit-tested helper
  (`service_classify_edge`) to pin the behaviour against regression. The Linux systemd
  service guard remains observe-only on the compliant edge (parity deferred).

### Added

- **TAR — software install/uninstall capture source (`$Software`).** A new TAR
  warehouse source records application **installed / removed / upgraded** events over
  time by diffing the installed-software inventory on a dedicated hourly trigger
  (`tar.software`; tune the cadence via `software_interval`, `0`–86400 s). On Windows it
  captures **machine-scope only** (HKLM Uninstall 64-bit + WOW6432Node) installs — no
  per-user enumeration, no Windows profile names, and **no user identity / no PII**.
  Tiers: `$Software_Live` (5000 rows) →
  `$Software_Daily` (31 d) → `$Software_Monthly` (12 mo), with per-`name`
  install/remove/upgrade counts. **The source is off by default** (opt-in) — an operator
  enables it per host with `tar.configure software_enabled=true`. Even though the
  machine-scope data carries no user identity (device asset-management /
  vulnerability-relevance data, like Services and User sessions), a brand-new capture
  source ships disabled out of caution so a host only collects it once the operator has
  decided to; enabling or disabling re-baselines the source so neither emits a spurious
  install/remove storm. Names, versions, and publisher only
  — no command lines or usage data. The first
  scan on a host **seeds the baseline silently** so an `installed` event always means
  "installed now". `tar.status` reports a `software_last_run_ts` heartbeat. **On upgrade,
  `tar.status` gains a `software_*` block plus the `software_interval_seconds` /
  `software_last_run_ts` lines
  — update any field-count parsing.** Linux (dpkg/rpm) and macOS (pkgutil) collectors are a fast-follow — the
  `$Software_*` tables are queryable but empty there until then. Disabling the source
  (`software_enabled=false`) is **atomic with the collector** — it holds the same
  `software_collect_mu_` the collector takes and the collector re-checks the flag under
  that lock, so a disable racing an in-flight scan can never insert events from the paused
  window or leave a stale baseline (no ghost install/remove/upgrade events on re-enable;
  same #538 contract as the other snapshot-diff sources). `SystemComponent` entries are
  read as `REG_DWORD` (their canonical type) so system components/patches are correctly
  excluded, and `software` rows are reachable from the legacy `tar.query`/`tar.export`
  typed paths as well as `tar.sql`. Enumeration is bounded by a per-cycle entry cap
  (`kSoftwareEntryCap`, warns once on truncation) so a bloated/corrupt registry cannot grow
  the tick unbounded, and same-name dedup compares versions **numerically** (so `10.0`
  outranks `9.0` — a lexicographic compare previously suppressed real upgrades). `tar.snapshot`
  now collects the source too. See `docs/user-manual/tar.md` and the data-handling
  classification in `docs/enterprise-readiness-soc2-first-customer.md`.
- **DEX: wave-4 reliability signals — power, driver, and service health (Windows).**
  Seven new signal types (Windows event catalogue 103→110, server display catalogue
  107→114), all real-record-pinned from a live HP ZBook Firefly 14 G8:
  `os.modern_standby_exit` (Kernel-Power 507 — deep-idle/DRIPS residency %; fires on
  every resume, scores as benign by default), `network.adapter_driver_dump`
  (Netwtw10 7025 — Intel Wi-Fi D3 dump; **vendor-coupled to Intel Wi-Fi**),
  `hw.driver_load_failed` (Kernel-PnP 219 — driver failed to load; distinct from
  device-start-fail 411), `hw.battery_error` (Kernel-Power 521 — faulted/abandoned
  batteries only; benign battery-count changes self-suppress), `service.unresponsive`
  (SCM 7011 — runtime control-timeout; params reversed vs 7022, so it is its own
  type), `service.shutdown_failed` (SCM 7043 — unclean service shutdown), and
  `network.adapter_reset` (NDIS 10317 — **vendor-neutral** NIC fatal/reset, the
  generic complement to the Intel-specific dump). `os.power_loss` (Kernel-Power 41)
  is **enhanced** (not new): `PowerButtonTimestamp` now discriminates a held power
  button (hard-hang recovery / manual power-off) from a sudden supply loss. Adds a
  `SignalObservation::suppress` primitive (an extractor can veto a matched benign
  event). Full signal table in `docs/dex-signal-catalog.md` Wave 4.

- **DEX: per-event observation detail panel.** Clicking any row in a device's DEX
  signal history loads a detail panel showing every captured projection field for
  that one event (subject, reason, symbolic name, component, metric, platform,
  exact timestamp, event ID). Fields already in the store — no agent or wire change.
  Per-device-scoped (`GuaranteedState:Read`), bound to the event's own device (a
  foreign event ID returns an opaque 200 placeholder, indistinguishable from a
  missing event), and audit-logged (`dex.observation.view`,
  recording the obs_type for works-council countability).

- **DEX: Applications lens (Apps tab).** A new top-level DEX tab ranks fleet
  applications by reliability signals (crashes and hangs, keyed on the process
  image), each row drilling to the existing per-app blast-radius view. Built on the
  existing `dex_top_apps` aggregation — no new agent collection. The DEX sub-nav is
  now **Overview · Apps · Catalogue · Health score · Trends · Performance · Network**.

- **Guardian — name-anchored, device-applicable compliance REST.**
  New `GET /api/v1/guaranteed-state/device-compliance?baseline={name}&agent_id={id}`
  looks a Baseline up by **name** (a stable constant such as `ServiceNow Compliance`, not
  a churning `baseline_id`) and returns the Guards **actually applicable to the device**
  each with the device's last reported verdict (`compliant` | `drifted` | `errored` |
  `pending`), plus counts and a `last_updated` freshness stamp. One Baseline carries a
  **superset** of Guards, each scoped via `scope_expr`, so the push arms a different
  subset per machine; the endpoint returns the `deployed_snapshot` intersected with the
  Guards the device has reported, so an out-of-scope Guard is **absent** (not `pending`)
  and two machines querying the same Baseline name legitimately see different Guards.
  `total_guards` is that applicable count. A not-yet-deployed Baseline returns
  `deployed:false` with empty guards (consumer renders "No Baseline Deployed"), and
  member edits appear only after a re-deploy. A *deployed* Baseline returning
  `total_guards:0` with `last_updated:null` is **not assessable** (the device is
  offline / newly-enrolled, or every Guard is out of its scope), **not compliant** — a
  CMDB consumer must cross-reference device liveness and never render `0/0` as green.
  Designed for embedding Guardian compliance into an external CMDB / ITSM CI record
  (e.g. ServiceNow).
  Authorization is **per-device-scoped `GuaranteedState:Read`** (a global grant passes
  fleet-wide; a management-group-scoped principal must hold `Read` via a group the
  device is in — a previously group-scoped token now gets `403` for out-of-scope
  devices, where a flat global check would have passed them; global tokens are
  unaffected). Audited `guardian.device.view` on access (denials audited at the auth
  layer as `auth.scoped_permission_required`). A behavioural-PII read, so it **fails
  closed**: if the `guardian.device.view` audit row cannot persist it returns `503` +
  `Sec-Audit-Failed: true` and **withholds** the compliance body (parity with
  `GET /api/v1/dex/devices/{id}`, governance #1549) — the `503` is returned before the
  `404`, so an audit outage never reveals baseline existence without durable evidence
  (CC7.2). **Behaviour change for API consumers:** an audit-store outage now yields
  `503` where this unreleased route previously returned `200`; on the fleet-polled
  CMDB path a *sustained* outage 503s every poll fleet-wide (no degraded-serve
  fallback). Both query params are required, length-capped (`256` /
  `auth::kMaxAgentIdLength`), and rejected if they contain control characters
  (bytes `< 0x20`) → `400`; the `400`/`404`/`503` bodies use the A4 envelope
  (`correlation_id`), while the `403` is the auth/RBAC layer's denial body (not the A4
  envelope; exact shape varies by denial reason — RBAC vs service-scope).
  The response carries a machine-readable **`assessable`** flag (`false` for a draft
  Baseline or a deployed Baseline this device has reported no applicable Guard against —
  the consumer must not compute a `0/0` compliance %) and **`snapshot_total`** (the
  Baseline's full deployed-member superset, an upper bound on coverage). **Caution:** the
  report-driven denominator can *over-estimate* compliance on a partial report (an
  in-scope-but-unreported Guard is absent, not `pending`), so consumers must not gate on
  `compliant/total_guards` until the per-device `scope_expr` computed denominator lands
  (deferred). `X-Correlation-Id` is set on every response (parity with the
  `dex.device.view` siblings); a guard reported with an unrecognized verdict token keeps
  its real `updated_at` (no longer suppressed); a baseline-store *fault* returns a
  retryable `503` (not the `404` a CMDB would read as "delete this CI") on a transient
  fault; and the guard-name lookup chunks its `IN`-list so a Baseline larger than
  `SQLITE_MAX_VARIABLE_NUMBER` still resolves every name. A `YuzuAuditPersistFailures`
  Prometheus alert (`docs/prometheus/yuzu-alerts.yml`) now fires when behavioural-data
  routes 503 fleet-wide on an audit-store outage.
- **TAR-styled live device snapshot ("Get live info", expanded).** The per-device
  page's **Get live info** button now returns a full live system snapshot — a KPI strip
  (uptime, process / service / connection / user counts) over a grid of collapsible,
  uniformly-sized, scrollable cards with an **Expand all / Collapse all** control and a
  per-card **pop-out** for a larger view. Each card is a separate live read-only dispatch
  through the existing Execute-gated, audit-logged chokepoint: **Processes** (a parent→
  child tree with the SHA-256 of each on-disk image and live network connections joined
  by PID, suspicious parent→child spawns flagged), **Services**, **Adapters & IP**,
  **ARP** (Windows), **DNS cache** (Windows), **Listening ports**, **Active connections**,
  **Logged-in users**, and a read-only **Capture sources** view (which TAR warehouse
  sources are capturing locally; configuration stays on the TAR page). Two new agent
  actions: `processes/list_tree` (adds parent PID for tree reconstruction) and
  `network_config/arp` (Windows `GetIpNetTable2`) — these ship with agents built from
  this release onward; an older agent renders an empty Processes-tree / ARP card (it
  returns an `unknown action` response, so upgrade the agent to populate those cards). Each card has its own
  `device.live.<kind>` audit verb so usage-class reads (process tree, connections, users,
  DNS cache) stay separately countable for works-council. ARP and DNS-cache are
  Windows-only; on other platforms those cards render an honest "not available on this OS"
  note. Requires `Execution:Execute` + `GuaranteedState:Read`, scoped to the device. The
  previous flat "Running processes" panel (`kind=processes`) is **retained** for
  REST/scripted callers; the dashboard now dispatches `kind=process_tree`. REST/scripted
  callers reach `kind=uptime|processes` only — the 9-card grid is dashboard-only pending
  the A1 JSON backfill (#1649). See `docs/user-manual/device-management.md`.
- **ARP + DNS capture sources (TAR, ADR-0015) — Windows.** Two new **opt-in**
  (`default_enabled=false`) TAR capture sources: `arp` (host ARP / neighbour table
  via `GetIpNetTable2` → `$ARP_Live`/`$ARP_Hourly`) and `dns` (device DNS
  resolver-cache state via `DnsGetCacheDataTable` → `$DNS_Live`/`$DNS_Hourly` —
  device-level, **no per-process attribution**; DNS is usage-class PII, enabling is
  audited). Queryable via `tar.sql`, the `query`/`export` actions (`type: arp|dns`),
  and the `crossplatform.tar.recent_arp`/`recent_dns` canned instructions; toggled
  via `crossplatform.tar.configure` (`arp_enabled`/`dns_enabled`) or the new **/tar
  "Capture sources" frame** (staged-then-push guardrail + category filter). The
  process-tree pane gains device-level **DNS-cache + ARP-table panels**
  (audit verbs `tar.dns.read`/`tar.arp.read`). Linux/macOS collectors are planned
  (schema registered, queryable-empty) and recorded per-OS in
  `docs/os-capability-matrix.md`. The Windows agent links `dnsapi`; the resolver-cache
  read combines `DNS_QUERY_NO_WIRE_QUERY` with the additional cache-read flag required
  to surface cached records on current Windows 10/11 builds.
- **MCP `query_responses` closes the dispatch→collect loop by `execution_id`.** The tool now
  accepts an `execution_id` argument (routed to `ResponseStore::query_by_execution`) so an
  agentic worker that dispatched via `execute_instruction` can collect exactly that run's
  responses — exact-correlation, no cross-execution bleed — instead of the definition-wide
  `instruction_id` collect. At least one of `execution_id`/`instruction_id` is now required (was
  `instruction_id`-only); when both are given, `execution_id` wins. Each returned row now echoes
  its `execution_id`. The advertised `status` filter is corrected to `integer` in the tool schema
  (the handler always read it as the `CommandResponse` status enum; the prior `string` declaration
  was wrong), and `limit` is now clamped to `[1,1000]` (a negative limit previously bound as an
  unbounded SQLite `LIMIT -1`, and `limit:0` returned zero rows a worker could misread as "done").
  Foundation for fleet-scale agentic fan-out across tens of thousands of devices. *(Scope: `limit`
  caps a page at 1000 rows; correct collection of executions that fan out to more than 1000 devices
  is a keyset-pagination follow-up — offset paging is deliberately not exposed, as it skips/dupes
  rows while responses are still arriving. The sibling `aggregate_responses` tool still keys on
  `instruction_id` only; an `execution_id` aggregate is a follow-up. MCP-first: the streaming REST
  surface `GET /api/v1/events?execution_id=` already exists; a non-streaming polling REST collect
  by `execution_id` is a deferred follow-up slice.)*
- **Sampled authentication-log evidence export (SOC 2 CC7.2).** New
  `GET /api/v1/audit/auth-sample?from=&to=&limit=` returns a pseudo-random
  sample of authentication-surface audit events (action prefixes `auth.`,
  `mfa.`, `session.`) over an optional epoch-seconds window — a representative
  sample for auditor evidence rather than the latest-N. Gated on `AuditLog:Read`
  (not admin-only, so a read-only auditor role can pull evidence without full
  admin — separation of duties), and the export is itself audited as
  `audit.auth_sample.exported`. Backed by two new `AuditQuery` knobs
  (`action_prefixes` OR-group filter + `random_sample` ordering); discoverable
  in the OpenAPI spec (A2). Closes the P0 auth gap "sampled auth-log evidence
  export".
- **Guardian ingest-drop counter.** New `/metrics` counter
  `yuzu_server_guardian_events_dropped_total` counts cumulative Guardian events dropped at
  ingest on an `event_id` PK/UNIQUE conflict (redelivery, an agent `event_seq_` reset, clock
  skew, or a forged-id pre-claim). `> 0` distinguishes "no drift observed" from "drift observed
  but silently discarded" (CC7.3 evidence). Sits alongside
  `yuzu_server_guardian_events_{total,written_total,reaped_total}`. (#1414)

- **Offline hosts stay visible on the fleet map.** A new born-on-Postgres store
  (`endpoint_state`) records each agent's last-known identity + last-seen on every heartbeat, so
  a host that drops out of the in-memory 60 s topology cache renders **stale-flagged** on
  `/viz/fleet` instead of vanishing. New pool observability on `/metrics`
  (`yuzu_pg_pool_{in_use,open,size}`, `yuzu_pg_connect_failed_total`,
  `yuzu_pg_acquire_timeout_total`, `yuzu_pg_unhealthy_discard_total`,
  `yuzu_pg_acquire_wait_seconds`) and a live pool probe + the new store join the `/readyz`
  readiness conjunction.

- **Shared device pages.** New dashboard pages `/devices` (searchable fleet list with an OS
  filter, online status, and per-device DEX score) and `/device?id=` (the per-device entity
  page, reachable from any dashboard, with **Device info / DEX / Guardian** lens tabs). The
  fleet list now requires `Infrastructure:Read` (parity with `/api/agents`, via the same
  `get_visible_agents_json` provider — closing the prior any-authenticated-operator access);
  every per-device route — page, info, the DEX/Guardian lenses, and the live pull — is
  additionally scoped to the device's management group via `require_scoped_permission`, so an
  operator cannot open, read, or live-query a device outside their scope. The DEX and Guardian
  lenses render per-device behavioral/compliance data
  with audit-on-open (`dex.device.view`, `guardian.device.view`). The fleet list and a single
  page open score only the rows they render — opening one device no longer scores the whole
  fleet. The list shows currently-connected devices only (no offline/status filter yet). The
  **DEX dashboard's per-device drills** the device DEX lens links to (`/fragments/dex/device`
  + its `/perf`/`/procperf` live panels) are scoped the same way, and the DEX device-id lists
  (overview top-devices, per-signal/per-app affected-devices, per-device perf) no longer
  enumerate agents outside the operator's management scope. (Fleet **aggregates** — rate
  denominators, score histograms — remain fleet-wide statistics.)
- **"Get live info" on the device page.** Dispatches read-only instructions to the agent on
  demand (not the 30s heartbeat): **Uptime** (`os_info/uptime`) and a **running-process list**
  (`processes/list_hashed`) showing the **SHA-256 of each process's on-disk executable**, with
  a first-10 preview and client-side search. Requires `Execution:Execute` scoped to the
  device's management group (a device outside your scope cannot be live-queried); each dispatch
  is individually audit-logged (`device.live.uptime`, `device.live.processes`) with the
  usage-class read kept separately countable for works-council access audit.
- **REST: agentic-first per-device DEX endpoints.** `GET /api/v1/dex/devices/{id}` — the
  per-device DEX read model (score + signal summary), the machine-readable equivalent of the
  dashboard DEX lens; `GuaranteedState:Read` scoped to the device, audited `dex.device.view`,
  off-enum `window` rejected `400`. `POST /api/v1/dex/devices/{id}/live?kind=uptime|processes` —
  the machine-readable "Get live info": dispatches a read-only instruction now and returns the
  result synchronously (~20s). **POST, not GET** (it dispatches a command — a side effect);
  `GuaranteedState:Read` + `Execution:Execute` scoped to the device; audited per kind
  (`device.live.uptime` / `device.live.processes`, audited `result=requested` pre-dispatch — see
  the Security entry above; the dashboard "Get live info" emitter still audits post-dispatch
  `result=dispatched`, a tracked alignment follow-up). Concurrent live polls
  are capped server-wide (over-budget → `429`); offline → `503`, timeout → `504`, device error
  → `502`, all with `retry_after_ms` where applicable.
- **`processes/list_hashed` plugin action** (all platforms): `proc|pid|name|sha256|path`. The
  executable path is resolved from the OS kernel (Windows `QueryFullProcessImageNameW`, Linux
  `/proc/<pid>/exe`, macOS `proc_pidpath`) — not the spoofable argv[0] — and the on-disk image
  is hashed via the shared `sha256_file` (bounded at 512 MiB, deduped by path).
- **DEX Catalogue is coverage-first.** A signal family/type now lights when a connected
  platform **collects** it — not only when it fired — with per-family "N of M monitored", a
  0–100 family health score, and an **OS filter** that persists across the family and per-type
  drill-downs. Types no connected platform collects read as *not collected*, never as healthy.

- **Linux server DEX: systemd unit-health signals from the journal.** The Linux DEX
  collector now emits `service.hung` (a `WatchdogSec` timeout — the existing
  unit-failed journal entry routed by `UNIT_RESULT="watchdog"`, since a watchdog kill
  is a hang, not a crash; one entry, no double-emit) and `os.time_unsynced` (chrony's
  "Can't synchronise: no selectable sources" / large-step markers, via a low-volume
  `SYSLOG_IDENTIFIER=chronyd` query clause; the raw message, which carries NTP source
  IPs, is never shipped). `service.hung` is verified through the agent's emit on a real
  watchdog timeout. Reused obs_types need no live-render change; the per-OS coverage map
  `dex_obs_platforms` (`dex_routes.cpp`) gains the new Linux types. Linux DEX coverage is now 17 signals.
  (`service.dependency_failed` is deferred — no `MESSAGE_ID`, and the root failure is
  already captured as `service.crashed`.)

- **Linux server DEX: `/proc` + `/sys` performance/hardware state polls.** The Linux
  DEX collector now also emits `perf.disk_latency_high` (per-I/O service time / iostat
  `await` over the whole physical disks, from `/proc/diskstats` — completing the
  Windows cpu/mem/disk perf trio on Linux, same `dex_perf_breach` hysteresis + 25 ms
  threshold) and `hw.cpu_throttled` (a poll-and-latch on the `/sys`
  `core_throttle_count` thermal-throttle counters, the Windows Kernel-Processor-Power
  37 analogue). New pure parsers `parse_diskstats`/`disk_await_ms`/`is_whole_disk`
  (`dex_linux_proc`) and `parse_throttle_count` (new `dex_linux_sysfs.cpp`); field
  positions verified against a real box. Reused obs_types (no live-render change; the
  per-OS coverage map gains them); this slice adds 2 (Linux 13→15, building on the
  kernel-reliability slice below; the systemd unit-health entry above reaches 17).

- **Linux server DEX: kernel-reliability signals from the journal.** The Linux DEX
  collector's journald reader now also classifies `_TRANSPORT=kernel` ring-buffer
  lines (free text, no `MESSAGE_ID`) via anchored substring markers in a new pure
  `dex_linux_kmsg.cpp`, emitting on **existing** obs_types (no live-render change; the
  per-OS coverage map gains them):
  `os.bugcheck` (a fatal `Kernel panic - not syncing` only — survivable Oops/
  soft-lockup deliberately not mapped, to keep the BSOD-equivalent rate honest),
  `os.dirty_shutdown` (ext4/xfs journal-recovery at mount = the prior shutdown was
  unclean), `disk.error` (block-layer / buffer I/O error, subject = backing device),
  `fs.corruption` (ext4/xfs/btrfs metadata error, subject = device), `hw.error`
  (machine-check / `[Hardware Error]`), and `process.hung` (the hung-task watchdog).
  Markers for `disk.error`, `fs.corruption` and `os.dirty_shutdown` are pinned to
  records live-captured on a real systemd-259 box via safe error injection (and
  `disk.error` verified through the agent's emit on a real injected error); panic, MCE and
  hung-task use the documented kernel format strings. Only infra-safe fields leave
  the device (device / comm / short reason) — the raw kernel `MESSAGE` is never
  shipped (`[dex][linux][kmsg][privacy]` pins). Linux server DEX coverage grows from
  7 to 13 reused signals, all in the same `/dex` display groups.
- **Live-query bundles — one instruction → several plugin actions on one device,
  collated (ADR-0011).** New `POST /api/v1/bundles` (dispatch, `Execution:Execute`,
  returns `202 {bundle_id, agent_id, expected}`) + `GET /api/v1/bundles/{id}`
  (collate, `Response:Read`, returns `{complete, received, succeeded, expected,
  steps[]}` in request order), with MCP parity via the `execute_bundle` /
  `get_bundle_result` tools. Collapses the N round-trips of refreshing one device
  (e.g. a ServiceNow CI sync) to a single dispatch plus a poll. The server expands
  the bundle into N ordinary plugin commands under one `bundle-…` correlation id
  and fans them out **async** (a slow step never withholds the others); **the agent
  is unchanged** — it never sees a "bundle". `bundle_id` is deliberately not an
  `execution_id` (a bundle is not a tracked execution; it is not in the live
  executions drawer). `complete` means terminal, **not** success — check
  `succeeded == expected` (an all-offline bundle completes with `succeeded=0`). Each
  step emits its own `bundle.<plugin>.<action>` device-access audit
  (`target_type=Agent`), so a bundle is exactly as auditable as the N executions it
  replaces; collate enforces an ownership guard (a non-owner gets the same 404 as an
  unknown id). Observable via `yuzu_bundle_{dispatched,collated,manifests,evictions}`
  metrics plus a `yuzu_bundle_dispatch_duration_seconds` histogram (labelled by
  surface). v1 bundle state is per-surface and in-memory; a
  durable Postgres manifest for HA + cross-surface collation is a committed
  follow-up (ADR-0011).
- **`$Module` Windows image-load collector (TAR, M2).** The `$Module` source now
  populates on Windows: a dedicated ETW session on Microsoft-Windows-Kernel-Process
  (IMAGE keyword, image load/unload) captures DLL / driver image loads, with the
  code-signing verdict resolved at drain (WinVerifyTrust + publisher extraction,
  cached by file+mtime) and the loaded-image directory scrubbed of user-profile
  prefixes before storage. Opt-in (`module_enabled`, default off; enabling takes
  effect on the next collection tick — no restart). Signing uses the local
  Authenticode chain **without online CRL/OCSP revocation checking** (no per-load
  network I/O), so a revoked driver may read as `signed`; authoritative
  revoked/blocked detection is the M3 CodeIntegrity overlay. A minimal edge
  risk-filter keeps every unsigned / invalid / revoked / kernel / blocked load at
  full fidelity and dedups + caps normally-signed loads per drain. `tar.status` reports
  `module_capture_method` + `module_stream_dropped`. macOS (Endpoint Security) and
  Linux (auditd kernel modules) collectors follow in M4/M5/M6. See
  `docs/tar-module-loads.md`.
- **`$Module` image-load warehouse source — schema foundation (TAR, M1).**
  Registers four queryable tables (`$Module_Live`, `$Module_Hourly`,
  `$Module_Daily`, `$Module_Monthly`) in the TAR warehouse: process/driver
  image-load activity (module name + directory + code-signing verdict) — the
  DLL-search-order-hijack / injection / BYOVD forensic surface that `$Process`
  cannot answer. **Queryable via `tar.sql` now, empty until a collector lands**
  (M2 Windows ETW, M4/M5 macOS Endpoint Security, M6 Linux auditd kernel-module);
  opt-in (`module_enabled`, default off). The process-stream ring is promoted to
  a reusable `EventRing<T>` template (no behaviour change for the `process`
  source), and `run_aggregation` is now data-driven over the capture-source
  registry so a newly-registered source's rollups can no longer be silently
  omitted. Design + PR ladder: `docs/tar-module-loads.md`.
- **Gap-free process start/stop capture via Endpoint Security on macOS (TAR).**
  The TAR `process` source on macOS now feeds from the Endpoint Security
  `NOTIFY_EXEC`/`NOTIFY_EXIT` stream (was a 60-second `KERN_PROC_ALL` sysctl
  poll), reaching Windows-ETW parity: short-lived processes the poll missed are
  captured, with accurate timestamps, ppid, image name, and owning user from the
  audit token (names-only — no command line). Requires a **full Xcode SDK** build
  (the Command Line Tools SDK omits `EndpointSecurity.framework`), the
  `com.apple.developer.endpoint-security.client` entitlement, and root; the agent
  automatically **falls back to the sysctl poll** when any of these is absent, and
  **self-heals** to the poll if the ES client goes silent for an extended period
  (a NOTIFY-only client has no liveness API — the idle threshold is deliberately
  long to avoid abandoning a healthy stream on a quiet host). The active path is
  reported by `tar.status` as `process_capture_method` (`endpoint_security` or
  `polling`), alongside two drop counters — `process_stream_dropped` (userspace
  ring overflow) and `process_stream_kernel_dropped` (Endpoint Security `seq_num`
  gaps). The ES handler is `noexcept` and drops malformed / zero-pid / zero-ts
  events, mirroring the ETW peer. **Boot gap:** processes that start *and* exit
  before the agent opens its ES session are not captured — macOS has no
  AutoLogger-equivalent backfill. **Fork gap:** the stream subscribes
  `NOTIFY_EXEC`/`NOTIFY_EXIT` only, so a fork-without-exec child is invisible until
  it exits (`NOTIFY_FORK` capture deferred, #1455). Both collectors now share a
  cross-platform `ProcStreamCollector` interface. See `docs/user-manual/tar.md` and
  `docs/darwin-compat.md`. **Not yet active in shipped builds:** the Apple
  entitlement and the codesign/notarization release pipeline are pending
  (#1455), so current macOS agents transparently use the **sysctl poll** until
  that lands — confirm the live path per device via `process_capture_method` in
  `tar.status` (`endpoint_security` = streaming, `polling` = fallback).

- **Linux server DEX: `os.uptime_report` (uptime/reboot heartbeat).** The Linux DEX
  collector now emits the hourly `os.uptime_report` scalar (uptime seconds, from
  `/proc/uptime`) — the cross-platform reboot/uptime signal (Windows EventLog 6013 /
  macOS boottime equivalent), reusing the same observation builder for an identical
  shape across OSes. Unprivileged, reused obs_type → no server change.

- **Linux server DEX: reliability signals from the systemd journal.** The Linux
  DEX collector now reads the journal on a slow cadence (`journalctl --after-cursor
  -o json`, cursor-checkpointed) and emits, on the **existing** obs_types,
  `service.crashed` (a unit failed — the systemd "Failed with result" / unit-failed
  journal messages),
  `process.crashed` (a `systemd-coredump` entry — `SD_MESSAGE_COREDUMP`; coverage
  depends on systemd-coredump being the active core handler), and `memory.exhausted`
  (the kernel OOM-killer). Only safe fields leave the device — process comm, unit
  name, signal/result code, never the raw message — and a flapping unit/process is
  collapsed by a per-`(type, subject)` debounce. No new dependency: `journalctl` is
  a runtime shell-out (no libsystemd), the source no-ops on non-systemd hosts, and
  the agent account already has `systemd-journal`/`adm` read access. Reusing the
  existing obs_types means a Linux server lights up the same `/dex` buckets as
  Windows/macOS with no server change; obeys the same `--dex-disable` kill switch.

- **Windows network-quality collection.** The agent now emits network facts on
  Windows, not only Linux: device throughput via `GetIfTable2` and a system-wide
  interval retransmit rate via `GetTcpStatisticsEx` (fed through the same
  `RetransWindow` ΔΣretrans/ΔΣsegs model as Linux). RTT stays unimplemented on
  Windows — per-connection smoothed RTT needs ESTATS
  (`GetPerTcpConnectionEStats`: enable + admin + overhead), a deferred slice. Two
  honest caveats: the Windows retransmit counter is **system-wide** (no
  per-interface TCP MIB, so it includes loopback) and is **measurement-first,
  unvalidated on Windows** (the netem separation-under-loss test was Linux-only).
  The `/network` dashboard now populates on a Windows-only fleet, and Windows
  throughput reaches the `yuzu_fleet_net_*` gauges. The net gauges carry an `os`
  label (per-OS, never blended). The Windows **retransmit** rate is system-wide,
  biased low, and not yet loss-validated, so it is **withheld from the
  `yuzu_fleet_net_retrans_pct` gauge** (it still shows on the `/network` page +
  REST, caveated) until #1465 validates it — the gauge carries loss-validated OSes
  only (Linux today). The `os` gauge label is **allowlisted** to the values a real
  agent emits (`windows`/`linux`/`darwin`, else `other`) so an agent-controlled tag
  can't spray unbounded series (the same raw-tag exposure on
  `yuzu_fleet_agents_by_arch`/`by_version` is tracked in #1472). See
  `docs/user-manual/network.md` and `docs/user-manual/metrics.md`.
- **OS capability matrix (`docs/os-capability-matrix.md`).** A per-capability ×
  per-OS snapshot of what the agent collects/enforces on Windows, Linux, and
  macOS, each row citing its in-code source of truth — so a platform gap (such as
  the previously Linux-only network collector) is visible in one place. Flags the
  durable follow-up: generate the matrix from the existing machine-readable per-OS
  metadata (`tar_schema_registry` `OsSupportStatus`, guard support arrays, the DEX
  signal catalogue) rather than hand-maintaining it.

- **Cohort-vs-cohort performance comparison on `/dex` (F2c).** The Performance
  tab's cohort benchmarking compared each cohort against the whole fleet; it now
  also does the direct **A-vs-B** diff (e.g. `image_type` vanilla vs layered, or
  `model` X vs Y) — closing the cohort-vs-cohort half of the benchmarking gap. A
  "Compare two cohorts" section with two cohort pickers auto-loads the top-two
  comparison; each metric shows both cohorts' p50 plus the delta (A relative to
  B). Pure render-time over existing heartbeat state — **zero new storage**, no
  Postgres. New `GET /api/v1/dex/perf/cohort-diff?key=&a=&b=` + MCP
  `get_dex_perf_cohort_diff` (both `GuaranteedState:Read`, A1 parity with the
  rest of the `/dex/perf` surface). The *fleet-per-app* benchmark view (per-app
  perf across the fleet) was deferred at the time of this entry — it has since
  **shipped** as DEX app-performance-over-time (B1/B2 + the slice-2 read surface;
  see the `[Unreleased]` entries), reading the retained Postgres aggregate rather
  than the federated device drill. See `docs/user-manual/dex.md` and
  `docs/user-manual/rest-api.md`.

- **Network quality dashboard (`/network`).** A new **Network** view — a sub-view
  under DEX (the Network tab in the DEX sub-nav, also reachable directly at
  `/network`), not a standalone top-level nav item — surfaces fleet-wide TCP
  network quality measured continuously on each endpoint from kernel counters (no
  packet capture, no flow export) — a **device / local-link health** view. Fleet-now cards show RTT p50/p90/max, the **interval retransmit
  rate**, and device throughput. The retransmit rate is ΔΣretransmits /
  ΔΣsegments smoothed over the last few heartbeats (recent-window loss), **not**
  the lifetime ratio — empirically the lifetime ratio is diluted to noise while
  the interval delta cleanly recovers the real loss rate. **Measurement-first:**
  the page ships honest evidence and does **not** yet classify a device as
  *network-degraded* — a calibrated threshold needs real-fleet baseline data, so
  the degraded classification and the device/app co-occurrence headline it gates
  are a later slice (the model stays wired but unfed). **Linux** agents report
  via netlink `INET_DIAG` (smoothed RTT + retransmit counters) + `/proc/net/dev`
  throughput; **Windows** reports throughput + retransmit (RTT deferred — see the
  Windows entry above); **macOS emits nothing yet** (absent metrics are omitted,
  never zeroed). Device-aggregate heartbeat tags
  `yuzu.net_{rtt_p50_ms,retrans_pct,throughput_bps}` (no per-destination data;
  gated by `--dex-disable`) and Prometheus gauges
  `yuzu_fleet_net_{reporting,retrans_reporting,rtt_ms,retrans_pct,throughput_bps}`
  (`yuzu_fleet_net_retrans_reporting` is the retransmit-rate denominator;
  `yuzu_fleet_net_degraded` is dormant/absent until the classification lands).
  An opt-in per-connection warehouse tier (`netqual_enabled` TAR config →
  on-device `$NetQual_Live`, bucket-only destination class, top-N capped, Linux)
  ships as the foundation for the deferred per-destination drill; it has no
  dashboard consumer in v1. Page permission: `GuaranteedState:Read`. See
  `docs/user-manual/network.md` and `docs/user-manual/metrics.md`. Machine-readable
  JSON siblings `GET /api/v1/network/fleet` and `GET /api/v1/network/devices`
  (permission `GuaranteedState:Read`, listed in the OpenAPI spec) and MCP tools
  `get_network_fleet` / `list_network_devices` mirror the dashboard data for
  scripting and agentic access (A1 parity).
  *Note:* `yuzu.net_retrans_pct` / `yuzu_fleet_net_retrans_pct` changed meaning
  within the unreleased cycle (absolute lifetime ratio → interval delta) and
  `yuzu.net_degraded` stopped being emitted — recalibrate any dev-build
  Prometheus alerts built on the earlier 4a semantics.

- **Linux server DEX collector — `/proc` perf + `statvfs` storage signals.** Linux
  agents now emit `perf.cpu_sustained`, `perf.memory_pressure`, and `storage.low`
  into the DEX pipeline via privilege-light `/proc/stat`, `/proc/meminfo`, and
  `statvfs` reads — reusing the same obs_types, `detail_json` shape and thresholds as
  Windows/macOS, so they render in the same `/dex` display groups with zero server or
  dashboard change. Linux CPU% and commit% also feed the perf heartbeat tags
  (`yuzu.perf_*`). Observe-only; controlled by the existing `--dex-disable` /
  `YUZU_AGENT_DEX_DISABLE` flag. **Edge-privacy:** `storage.low` subjects are the
  backing-device identifier (e.g. `sda1`, or the ZFS pool) — never the mount path,
  which can carry usernames/tenant names; pinned by `[dex][privacy]` regression tests.
  **Upgrade note:** Linux agents begin emitting this telemetry on upgrade with no
  operator action (EU works-council co-determination triggers on the *capability* to
  observe); `--dex-disable` suppresses it fleet-wide.

- **Gap-free process start/stop capture via ETW on Windows (TAR).** The TAR
  `process` source now feeds from a real-time `Microsoft-Windows-Kernel-Process`
  ETW session instead of the 60 s snapshot-diff poll, so short-lived processes
  (which the poll misses entirely) are captured — with exact timestamps and exit
  codes. Same `process_live` schema and `$Process_*` query surface and the same
  `started`/`stopped` rollups — but the Windows `cmdline` column is now **empty**
  (see Breaking Changes). Events are **names-only** (no command
  line); the owning user is resolved from the process SID at start (best-effort,
  empty for processes that exit faster than the ~1 s buffer flush — the same
  limit the poll had). The poll remains the feeder on Linux/macOS and the Windows
  fallback if the ETW session cannot start. The **boot window** (processes that
  start *and* exit before the agent's live session opens) is backfilled from a
  boot **AutoLogger** — a circular, FlushTimer-enabled Kernel-Process `.etl`
  configured by `install-agent-user.ps1` (admin, install-time) and started by the
  kernel early each boot; the agent reads it directly at startup for events
  before its live session began (no session stop / no elevation — read access
  only), de-duplicated per boot. Boot-window events are names-only with no user
  (the start event carries only SessionID + integrity label; precise attribution
  would need the Security-Auditing 4688 provider). `process_live` raw cap raised
  5k→100k for the higher event rate; disk stays bounded (count rollups carry the
  long tail). `install-agent-user.ps1` is now UTF-8-BOM-encoded so Windows
  PowerShell 5.1 parses it (it has non-ASCII characters). Disabling the
  `process` source drains-and-discards the live ETW ring each cycle, so a paused
  window is never persisted on re-enable (forensic-pause contract); the
  boot-backfill replay is memory-bounded and drops corrupt-timestamp / torn
  records.
- **Boot process-capture AutoLogger wired into the Windows installer (#1425).**
  The production InnoSetup installer (`deploy/packaging/windows/yuzu-agent.iss`)
  now configures the `YuzuProcBoot` boot AutoLogger at install time — scoped to
  the `advanced` plugin component that ships `tar.dll` — and tears it down on
  uninstall: it removes the boot config, **stops the running trace session**, and
  deletes `procboot.etl`. Stopping the session is load-bearing: `Remove-AutologgerConfig`
  removes only the boot-start config and leaves a session started by an earlier
  boot running until the next reboot, holding one of the scarce (~64) system ETW
  session slots. The same stop-before-delete teardown was applied to
  `install-agent-user.ps1`'s `Remove-ProcBootAutologger` so the script and
  installer recipes stay in sync. The installer also locks the agent data dir
  `{commonappdata}\Yuzu` (and `{app}\logs`) to `admins-full system-full`: the
  prior `service-full` keyword is not a valid InnoSetup permission group and was
  silently ignored, leaving the directory — which now holds the boot trace
  `procboot.etl` (boot-process names reveal which security/EDR tools are present)
  — readable by authenticated users (matches the `yuzu-server.iss` data-dir ACL).

### Fixed

- **A4 error envelope on MCP tier-denied paths and dex-perf REST endpoints.** MCP tier-denied
  errors (read-only mode, tier policy, approval-required) now carry
  `error.data = {"correlation_id":"req-…","retry_after_ms":null,"remediation":"…"}` (the
  remediation is an actionable hint, not `null`), the dex-perf MCP validation errors
  (`get_dex_perf_cohorts`/`list_dex_perf_devices` invalid key/cohort_key/limit) carry the same
  `error.data`, and `GET /api/v1/dex/perf/{fleet,cohorts,devices}` emit the A4 error envelope on
  every 400/503 branch and an `X-Correlation-Id` response header (on success and error), matching
  the `cohort-diff` sibling. The shared REST A4 helper now always emits the spec-required nullable
  `retry_after_ms` field. **Behaviour change:** an approval-gated MCP operation on the `supervised`
  tier is now denied with `kTierDenied` (-32004) instead of `kApprovalRequired` (-32006) — A4
  reserves -32006 for an envelope carrying a pollable `approval_id` + `status_url`, which the
  unimplemented re-dispatch path (Phase 2) cannot honestly provide; the operation is still denied
  and the remediation points at the REST API / dashboard. (#1470)

- **DEX catalogue family tile labelled honestly.** The family device figure is the *largest
  single signal's* distinct-device count, not the family union (two disjoint 50-device signals
  read 50, not 100); the tile now reads "Peak signal devices / largest single signal" so the
  number and label agree. Health score unchanged. (#1374)

- **Operator/API tags beat agent self-report.** An agent's reported `scopable_tags` can no
  longer overwrite an operator- or API-set tag for the same `(agent_id, key)`, preventing a
  rogue or misconfigured agent from self-assigning into an operator-declared benchmark cohort. (#1411)

- **Guardian enforce-stop denylist extended with WdFilter and BFE.** Two Windows built-ins that
  could defeat a *listed* control indirectly — `WdFilter` (Defender's filesystem minifilter,
  stopping it blinds real-time scanning while `WinDefend` still reads as up) and `BFE` (the Base
  Filtering Engine the firewall sits on, stopping it tears down the firewall while `mpssvc`
  looks protected) — are now rejected by `dangerous_enforce_service_stop`. (#1285)

### Changed

- **TAR `process_etw_dropped` status key renamed to `process_stream_dropped`; new
  `process_stream_kernel_dropped` added.** The Windows-specific
  `process_etw_dropped` is now the cross-platform `process_stream_dropped`, and its
  meaning is pinned to **userspace ring overflow** (the drain tick fell behind) on
  both platforms. A new `process_stream_kernel_dropped` key reports
  **kernel/provider-side** drops separately — Endpoint Security `seq_num` gaps on
  macOS; 0 on Windows ETW, which exposes no per-message sequence here. Any
  Prometheus scrape rule, SIEM parser, or `tar.sql` query that referenced
  `process_etw_dropped` will find no value after upgrade — update it to
  `process_stream_dropped`.
- **Compose Wizard (`tools/compose-wizard/`) now provisions the PostgreSQL
  server substrate** (ADR-0006/0008, #1397). The browser wizard predated the
  Postgres substrate move and generated a server with no database to talk to.
  It now has a PostgreSQL section on the Data step with two deployment modes:
  **bundled** (emits a release-pinned `ghcr.io/tr3kkr/yuzu-postgres` service
  with the reference healthcheck and gates server start on
  `depends_on: condition: service_healthy`) and **external/managed** (the
  operator supplies a DSN, no local container). Either way the server gets a
  `YUZU_POSTGRES_DSN` env entry (consumed as an env var, not a CLI flag). Per
  ADR-0010 the credentials/DSN live in the generated `.env`; the compose YAML
  only references `${YUZU_POSTGRES_PASSWORD}` / `${YUZU_DB_PASSWORD}` /
  `${YUZU_POSTGRES_DSN}` so no secret is baked into it. Bundled mode enforces
  the image's distinct-credentials invariant (superuser ≠ app role) and offers
  a Web-Crypto secret generator. The wizard's default version was also bumped
  `0.10.0` → `0.12.0` so the bundled image tag resolves.
- **CI server-test legs now require a reachable PostgreSQL 16**
  (`scripts/ci/ensure-postgres.sh` exits 1 instead of warning when it cannot
  provision or authenticate one — except the documented psql-less TCP-probe
  fallback on a native cluster) — the new `[pg]`-tagged server tests for the
  Postgres substrate (#1320 PR 1) would otherwise silently skip. Local
  development is unchanged: with `YUZU_TEST_POSTGRES_DSN` unset the `[pg]`
  tests skip cleanly; when it is set but unreachable they fail. See
  `docs/ci-architecture.md` "Postgres for server tests" for the local
  one-liner.

### Breaking Changes

- **Account lockout is ON by default (`--auth-lockout-threshold=5`).** Existing
  deployments gain a new failure mode on upgrade with no config change: 5
  consecutive failed local-password logins lock an account for 15 minutes
  (returning the same generic 401 as a bad password — no "you are locked"
  message). Shared/service accounts that authenticate with a password and any
  password-rotation automation are the highest-risk targets. Recover with
  `POST /api/v1/users/{name}/unlock`, wait out the window, or disable the
  control with `--auth-lockout-threshold=0`. SSO/OIDC and API tokens are
  unaffected. See `docs/user-manual/upgrading.md` § Account lockout and the
  full feature entry under **Added** below.
- **The shipped Docker images are now TLS-by-default (PKI #1289).** The
  `yuzu-server` / `yuzu-server-chisel` and `yuzu-agent` / `yuzu-agent-chisel`
  images no longer bake `--no-tls`/`--no-https` into their default CMD, so a
  container started from the published image is **encrypted + mutually
  authenticated out of the box**: the server auto-generates a per-install CA and
  serves the dashboard over **HTTPS on 8443** (8080 becomes the HTTP→HTTPS
  redirect) and the agent/management/gateway listeners over (m)TLS; the agent
  connects to the gateway over TLS and, with no `--ca-cert`, **auto-discovers the
  install CA** at `/etc/yuzu/certs/default-ca.pem`. **Fail-closed (#1303):** if no CA
  can be pinned (no `--ca-cert` and no discoverable install CA), the agent now
  **refuses to start** (exits non-zero) instead of silently verifying against the
  system trust store — which does not trust a Yuzu self-signed CA, a fail-open MITM
  window once the gateway TLS edge is live. Pass **`--tls-system-roots`** /
  `YUZU_TLS_SYSTEM_ROOTS=1` only when the server cert chains to a public/corporate CA
  already in the system store, or `--no-tls` for dev/demo. Two operational notes: (1)
  the dashboard cert is signed by the per-install CA, so a browser shows an
  untrusted-issuer warning until you trust it (download `default-ca.pem` or `GET
  /api/v1/ca/root`); (2) for a multi-container deploy sharing one
  `/etc/yuzu/certs` volume, the server takes a new **`--cert-group <name|gid>`**
  flag (`YUZU_CERT_GROUP`) that group-shares the cert dir + the gateway leaf key
  with the `yuzu-pki` group baked into all three images, so the
  different-uid containers can read the shared certs (the CA/server/HTTPS private
  keys stay 0600 owner-only). Demo/UAT/test composes deliberately keep `--no-tls`.
  Native installs (deb/systemd, Windows installer) were already secure-by-default.
  New secure reference composes: `docker-compose.reference.yml` (single server) and
  `docker-compose.reference-gateway.yml` (server + gateway + agent). In the
  gateway topology the **privileged server→gateway command plane (`:50063`) is now
  mutual TLS** (#1314): the server presents its leaf and the gateway requires a
  CA-issued client cert, so a container with no Yuzu cert — including a compromised
  agent — can no longer push commands to the fleet over that plane (previously it
  was plaintext + unauthenticated). To run the old insecure posture, pass
  `--no-tls --no-https` explicitly. See `docs/pki-architecture.md`
  "Secure-by-default deployment".
- **Windows TAR process events no longer carry a command line (`cmdline` is
  empty).** With the Windows `process` source moving from the snapshot-diff poll
  to the ETW Kernel-Process feeder (see Added), process rows on Windows are
  names-only — the ETW start event carries no command line. Any dashboard, SIEM
  export, `tar.sql` query, or Guardian rule that read `cmdline` from
  `$Process_*` on Windows now sees an empty string. **macOS process rows are now
  names-only too — on BOTH the Endpoint Security stream and the sysctl poll** (see
  Added): the stream carries no command line, and the poll fallback (a Command Line
  Tools SDK build, or a host without the ES entitlement/root) now blanks the
  `proc_pidpath` image path it previously placed in `cmdline`. **Linux is
  unaffected** (the poll still captures command lines). This is intentional
  (works-council / data-minimization posture) and not
  reversible by configuration; `process_enabled=false` disables process capture
  entirely (stream and poll) if required. Command-line redaction patterns
  consequently have no effect on Windows process rows (there is nothing to
  redact). The boot-window AutoLogger backfill is configured by the production
  InnoSetup installer (scoped to the `advanced` component) and by the developer
  install script (`install-agent-user.ps1`); it takes effect on the next reboot
  after install. See `docs/user-manual/tar.md`
  "Upgrade note (Windows process capture → ETW)".
- **The server now generates per-install default TLS certificates on first
  boot instead of refusing to start without operator-provided certs.** A fresh
  install is encrypted and serves the HTTPS dashboard + agent/management gRPC
  with an auto-generated per-install ECDSA CA (no `--no-tls`/`--no-https`
  needed). Because the dashboard cert is signed by a per-install CA, browsers
  show an untrusted-issuer warning until the operator trusts the CA
  (`<cert-dir>/default-ca.pem`) or replaces the certs. The server warns loudly
  on six surfaces (startup banner; one-shot audit `server.default_certs_generated`;
  periodic audit `server.default_certs_in_use`; Prometheus
  `yuzu_server_default_certs_active`; `/health` `tls.default_certs_active` +
  `ca_fingerprint` + `ca_expires_at`; `/readyz` `ca_store`/`ca_root`). While on default certs the agent
  listener runs encrypted but **requests-but-does-not-require** client certs so
  a first-boot agent can bootstrap; agents then auto-enroll for a per-agent
  client certificate and upgrade to full mutual TLS (see "Per-agent mutual TLS"
  under Added). An operator-supplied agent surface keeps strict mTLS, and the
  management plane is unaffected. **Opt out with
  `--no-default-certs`** to restore the legacy refuse-to-start. New `--ca-dir`
  relocates the CA/cert directory. A surface given a cert without its key (or
  vice-versa) is now a hard startup error. See `docs/auth-architecture.md`
  "Default certificates".
- **`--mfa-enforcement=admin-only` and `--mfa-enforcement=required` now
  ENFORCE (previously a logged no-op).** PR 1/PR 2 accepted these values
  for forward-compatibility and documented them as no-ops (the server
  emitted a startup `WARN`). PR 3 wires real enforcement: an un-enrolled
  login subject to enforcement is redirected through TOTP enrollment
  (`POST /login/mfa/enroll`) before any session is minted. **An operator
  who staged `--mfa-enforcement=admin-only|required` based on the prior
  no-op documentation will hit live enforcement immediately on upgrade.**
  Before upgrading: ensure all affected accounts are enrolled, or set the
  flag back to `optional`, upgrade, then re-enable after verifying
  enrollment. The startup line for non-default modes changes from `WARN`
  (no-op) to `INFO` (enforcement active). See
  `docs/user-manual/upgrading.md` for the full pre-flight checklist,
  including the SSO `amr` requirement and single-admin guidance.
- **OIDC/SSO sessions are now MFA-gated via the IdP `amr` claim instead of
  being blanket-exempt from step-up.** An SSO session whose IdP attests a
  multi-factor login (RFC 8176 `amr` containing `mfa`/`otp`/`hwk`/`fpt`/
  `face`/`iris`/`sms`/`swk`/`tel`) clears high-risk endpoints without a
  redundant prompt and re-prompts (via re-SSO) once the assertion ages
  past `--mfa-step-up-window-secs`. An SSO session whose IdP did **not**
  attest MFA is handled symmetrically with local users: under `optional`
  (or `admin-only` for a non-admin) it passes the gate (Yuzu cannot mint a
  factor for an external identity); under `required` (or `admin-only` for
  an admin) it is gated and must re-authenticate through SSO. **If you
  enable `required`/`admin-only` with SSO, configure your IdP to assert
  `amr` and verify it pre-flight** — otherwise affected SSO users cannot
  reach high-risk endpoints (recoverable by restarting in `optional`).

- **`POST /login` now returns HTTP 202 (not 200) for MFA-enrolled users.**
  Programmatic clients (CI pipelines, automation scripts, health checks)
  that called `POST /login` and gated on `HTTP 200 + {"status":"ok"}` will
  fail silently the first time the authenticating user enrolls in TOTP MFA.
  Handle the 202 branch: read `mfa_pending_token` from the JSON body and
  POST it along with the 6-digit TOTP code (or a `XXXX-XXXX-XXXX-XXXX`
  recovery code) to `POST /login/mfa` to obtain a session cookie. Clients
  using API tokens or OIDC are unaffected.
- **Audit verb taxonomy on every new MFA emission site uses the
  `target_type="User"` (PascalCase) and `result ∈ {ok, error}` vocabulary
  from `docs/observability-conventions.md`.** SIEM and Grafana rules that
  filter on the historical lowercase `target_type="user"` + `success/failure`
  strings used by `auth.login` / `auth.oidc_login` will not match the new
  `mfa.*` rows. Existing auth.* sites remain on the historical vocabulary
  for backwards compatibility (separate tracking issue).
- **Recovery code format changed from `XXXXX-XXXXX` (50 bits) to
  `XXXX-XXXX-XXXX-XXXX` (80 bits, four base32 groups).** Codes issued by
  prior PR1 commits are no longer the canonical shape but remain valid
  until consumed or regenerated.
- **`AuthDB::remove_user` now also clears MFA enrollment state.** Soft-
  deleting a user nulls their `mfa_totp_secret`, clears `mfa_enrolled_at`,
  and DELETEs every `mfa_recovery_codes` row owned by the user — SOC 2 CC6.8
  requires credentials be revoked on termination. Any external code or
  ops tooling that relied on the prior "soft delete leaves MFA intact"
  behavior must update.

### Fixed

- **TAR configure-time validation is now OS-aware and bounded (#540, #541, #544).**
  (a) `network_capture_method` was validated against the OS-blind union of every
  platform's capture methods, so a Linux agent would accept and store the
  Windows-only `iphlpapi` (and surface it in `status`) while the collector kept
  polling — now validated against the running host's OS accept-list via the new
  `accepted_capture_methods_for_os` (#540). (b) `process_stabilization_exclusions`
  and `redaction_patterns` had no element-count or length caps (an oversized array
  degrades the per-process redaction scan), and an over-short exclusion substring
  (e.g. `"a"`) silently dropped most process events — now capped at 256 elements ×
  256 chars, and an exclusion whose EFFECTIVE substring (after stripping
  leading/trailing `*`) is shorter than 3 chars is rejected at configure **and
  dropped on the load path** — `*` does not buy a pass (`*a*` strips to core
  `a`), and the load-path floor matters because the loader re-parses the stored
  value every fast cycle, so a sub-floor value persisted before the floor existed
  (a no-tamper upgrade) or written out of band would otherwise reach the redaction
  scan and suppress events. The loaders skip non-string elements instead of
  discarding the whole set, the build-embedded `content/definitions/tar.yaml`
  discovery metadata is synced (substring not glob, OS-aware method rejection,
  the 256/256/3 limits), and the stale "glob" comments are corrected to
  "case-insensitive substring" (#541). (c) The schema-registry `kPlanned` accept-list test could
  pass vacuously; it now asserts it actually exercised at least one `kPlanned` row
  (#544). (d) **Command-line redaction is now fail-closed on every collect path.**
  `load_redaction_patterns` previously returned the safe built-in patterns only
  when the stored value was empty or a non-array; a *valid array whose elements all
  got dropped* (`[]`, `[1,2,3]`, all-over-long, or `["*"]` whose stripped core is
  empty) returned an empty set, silently disabling redaction so `password`/`token`/
  `secret` were written to `process_live` in plaintext — `collect_fast` and
  `procperf` lacked the defaults-union that `fleet_snapshot` already applied. The
  built-in defaults are now unioned inside `load_redaction_patterns` via the shared
  `ensure_redaction_defaults` helper, so an operator can ADD redaction patterns but
  can never DISABLE the baseline protection on any path. The load-path JSON parse
  also gains a 128 KiB pre-parse byte cap (a multi-MB tampered/legacy value is no
  longer fully parsed + copied every fast cycle), and the `tar.yaml` discovery
  metadata for `network_capture_method` no longer advertises the process-source
  `etw`/`endpoint_security` methods the OS-aware validator rejects (A1 parity).
- **TAR source enable/disable is now corruption-resilient and reports a strict
  state (#559, #560).** Two agent-side defects in the per-source lifecycle: (a) a
  corrupt `tar.db` was opened and trusted, and since `get_config` returns the
  caller default on a read failure, every `<source>_enabled` key read as its
  default — silently re-enabling sources an operator had paused for forensic
  preservation and defeating the #539 retention guard with no telemetry (#559);
  (b) `tar.status` echoed the raw stored enable value, so a garbage value
  (corruption, tampering, a downgrade/upgrade) was passed through instead of
  flagged, and the collect-time `!= "false"` gate treated any non-`false` value
  as enabled (#560). Fixes: `TarDatabase::open` runs `PRAGMA integrity_check` and
  quarantines a corrupt DB aside (`tar.db.corrupt-<epoch>`, with its `-wal`/`-shm`
  sidecars) before re-initialising a fresh one — failing **closed** if the corrupt
  file cannot be moved aside rather than re-opening and trusting it; `status` now
  emits a strict tri-state (`true`/`false`/`errored`); and the collect-time gate
  (`source_enabled`) and `run_retention` both gate on that same canonical
  tri-state, so a corrupt or tampered `<source>_enabled` value fails closed —
  collection stops *and* the source's rows are preserved (not pruned).
  Recovering such a source via `configure <source>_enabled=true` now also clears
  its `paused_at`: the enable/disable transition canonicalises the previous value
  before both legs, so an `errored`→`true` recovery no longer leaves a stale
  `paused_at` that made `tar.status` report a now-collecting source as paused.
- **TAR `status` no longer misrepresents the active network capture mechanism (#1528).**
  `network_capture_method` accepts and stores a pre-staged `kPlanned` method (e.g. `etw`
  on Windows, `endpoint_security` on macOS), but `collect_fast` always polls via
  `enumerate_connections()` regardless — so `status` could tell an IR analyst the agent
  was capturing via a kernel-event method when it was really polling. `do_status` now
  emits `network_capture_method_effective` (the mechanism actually in force — always
  `polling` today) alongside the configured `network_capture_method`, computed through a
  single `effective_network_capture_method()` helper in the schema registry that is the
  obvious place to wire the runtime check when a kernel-event collector lands. The
  pre-staging affordance is preserved (the configured value is still stored and reported).
  (`agents/plugins/tar/src/tar_schema_registry.{hpp,cpp}`,
  `agents/plugins/tar/src/tar_plugin.cpp`, `docs/user-manual/tar.md`,
  `content/definitions/tar.yaml`, `docs/yaml-dsl-spec.md`)
- **TAR: disabling a collector no longer races an in-flight collection cycle (#538).**
  `tar.configure <source>_enabled=false` wrote the disable flag without serialising
  against the collectors, so a `collect_fast`/`collect_slow` cycle already past its
  per-source enable check could commit one extra snapshot **after** the operator's
  "stop" — and the saved baseline was the racy snapshot. On re-enable the next cycle
  diffed against that stale baseline and emitted ghost "stopped" events for every
  process/connection/service/user that had exited during the pause, breaking the
  documented "re-enabling starts from a clean baseline" contract. The disable
  transition now (a) runs under the collectors' `collect_mu_` so it can't interleave
  mid-cycle, and (b) clears the source's snapshot-diff baseline so a later re-enable
  rebuilds from scratch. The clear happens **before** the `_enabled` flag flips and
  the flag flips only if the clear persisted: if the agent DB is momentarily busy the
  disable is refused (the source stays enabled and `configure` returns an error)
  rather than leaving a disabled source with a stale baseline. The
  source→baseline-key mapping (note `tcp`'s baseline lives under `"network"`) is
  centralised in `diff_state_key()`, used by both the collectors and the disable path
  so it cannot drift. **Operator-visible change:** the first collection cycle after a
  re-enable emits a `started` event for every entity currently running/open (an
  expected one-time rebaseline), not ghost `stopped` events. The interval samplers
  (`perf`/`procperf`) keep their previous reading in memory rather than a diff-state
  row, so the same race is closed for them too: disabling resets the in-memory
  baseline under `collect_mu_`, and `do_collect_perf`/the procperf leg re-check the
  enabled flag **after** taking the lock — so a disable racing a mid-flight sample
  commits no post-disable row, and a re-enable re-baselines instead of emitting a
  first row whose rate-average covers the entire paused window (a privacy concern on
  the opt-in, default-off `procperf` per-application source).
- **TAR `tar.status` no longer misreports opt-in capture sources as enabled.**
  The high-volume usage-class sources (`module`, `procperf`, `netqual`) are
  opt-in and ship disabled, but a fresh agent reported `<source>_enabled=true`
  on `tar.status` because every source defaulted its enabled flag to `true`.
  They now carry an explicit `CaptureSourceDef::default_enabled=false`, threaded
  through `source_enabled()`, `do_status()`, retention, and the `paused_at`
  transition from a single source of truth — so status, retention, and the
  retention-paused list all agree the source starts disabled (and the first
  `<source>_enabled=false` no longer writes a spurious `paused_at`). On upgrade,
  an agent that never set these keys now reports `<source>_enabled|false` on
  `tar.status` where it previously reported `true`; **no data collection
  changes** (collection was already gated off), so this only affects automation
  that parses `tar.status` to inventory active sources.
- **TAR retention-paused dashboard: correct rendering + DoS-resistant (#558, #560, #561).**
  The `/tar` retention-paused list had three defects: (a) a source whose
  `<source>_enabled` held a non-`"false"` value (`errored` from a corrupt/tampered
  agent DB, or any garbage) was **silently omitted** from the list — showing clean
  state for an actually-paused source; it now renders with a value-error badge
  and sorts to the top of the list (#560); (b) a pre-v0.12.0 agent that reported a source disabled without a
  `paused_at` was rendered with a bare em-dash and, worse, **sorted to the bottom**
  (the longest-paused sources sank below recently-paused ones — inverse of operator
  intent); unknown `paused_at` now sorts as oldest (top) with a
  "schema-older-than-server" badge (#558); (c) a malicious/compromised agent
  spamming many responses under one `command_id` forced the renderer to parse every
  response (200ms–3s); the renderer now dedups to the most-recent response per agent
  before parsing, bounding work to O(visible agents × sources) (#561).
- **Windows server installer locks its log-directory ACL.** `yuzu-server.iss`
  set `Permissions: service-full` on `{app}\logs`, which is not a valid
  InnoSetup permission group — ISCC silently ignores it, leaving the directory
  with default ACLs (readable by authenticated users). Now `admins-full
  system-full`, matching the installer's own data/cert directories. (The same
  invalid keyword was fixed for the agent installer in #1425 / #1436.)
- **macOS agents are no longer counted as Windows in DEX denominators.** The
  OS check used a substring match, and "darwin" contains "win" — so on mixed
  fleets every macOS agent inflated the Windows-online denominator behind the
  DEX crash-free rate and the Performance tab's Reporting card, and appeared
  in the "devices not reporting performance" drill as a phantom Windows
  device. Both sites now match the OS prefix.

### Added

- **Account lockout for failed local-password logins (SOC 2 CC6.3).** After
  `--auth-lockout-threshold` (default 5) consecutive failed `POST /login`
  attempts within `--auth-lockout-window-secs` (default 900 s) the account is
  locked; subsequent attempts return the **same generic 401** as a bad password
  (no username-enumeration / lock-state oracle, and PBKDF2 is skipped). The lock
  auto-expires after the window — it is never permanent — and a waited-out user
  regains a fresh attempt budget. An admin can clear a lock immediately via
  `POST /api/v1/users/{username}/unlock` (`UserManagement:Write`, MFA step-up;
  self-target permitted). Set `--auth-lockout-threshold=0` to disable. Env vars:
  `YUZU_AUTH_LOCKOUT_THRESHOLD` / `YUZU_AUTH_LOCKOUT_WINDOW_SECS`. New audit
  verbs `auth.lockout.applied` (once, at the threshold crossing) /
  `auth.lockout.cleared` (successful login or admin unlock); new metrics
  `yuzu_auth_lockout_applied_total` / `yuzu_auth_lockout_blocked_total`. Scope is
  local-password login only — OIDC/SSO and API tokens are unaffected.
- **Secrets-at-rest envelope encryption substrate — `SecretCodec` +
  `KekProvider` KEK wrap/unwrap seam (ADR-0010, #1320 PR 4; machinery only,
  no store writes secret columns yet).** Secret columns in PostgreSQL are
  AES-256-GCM-encrypted app-side under a fresh per-value DEK; the DEK is
  wrapped by the install's KEK, which lives behind the `KekProvider` seam
  (a dedicated interface implemented by `FileKeyProvider` alongside the CA
  `KeyProvider` contract)
  (`secrets-kek-v<N>.key`, 0600, generated on first codec init with a
  temp-fsync-rename atomic write) and never enters the database. Identity-
  bound AAD makes blobs non-relocatable across rows/columns (canonical
  length-prefixed serialization; kek_version rides the wrap layer only, so
  rotation re-wraps DEK headers without touching payloads). The `secrets`
  schema's `kek_meta` table registers non-secret KEK fingerprints; boot
  verification fails closed with distinct `kek_unresolvable` / `kek_corrupt`
  operator tokens (backup-skew and dual-server misconfigurations refuse
  loudly). KEK lifecycle: rotation (incremental, interruptible, per-row CAS),
  `oldest_kek_version_in_use` completion signal, retirement refused while a
  version is active or referenced with `retired_at` destruction evidence.
  Audit verbs `kek.generated`/`kek.rotated`/`kek.retired`/
  `secret.decrypt_failure` and per-store failure-class counters are defined
  as wiring seams — no audit events or metrics are emitted until the
  per-store migration PRs wire them. Operator guidance (the
  DB+keys-dir restore-pairing invariant, rotation, break-glass) lives in
  `docs/user-manual/server-admin.md` "Key management (secrets KEK)". The
  gated stores (`auth` TOTP, `webhooks`, `offload_targets`, OIDC client
  secret) adopt the codec as each migrates to Postgres.

- **Guardian: Linux systemd service guard (observe-only).** The
  `service-status-change` Guardian Spark now arms on Linux hosts with systemd,
  watching each unit's `ActiveState` over sd-bus (`Subscribe` + `PropertiesChanged`
  match + a bounded reconcile backstop) and emitting `drift.detected` events with
  `platform=linux`, matching the Windows SCM guard's event shape — both service
  guards are silent on the compliant edge (neither emits `guard.compliant`).
  systemd's richer `ActiveState` collapses onto the published
  `{running, stopped}` tokens with no schema change. **Observe-only in this
  release:** drift is detected and reported but not remediated — enforcement
  (mask/stop) is gated behind a forthcoming, governance-reviewed change, and an
  `enforcement_mode: enforce` rule on a Linux agent degrades to observe without
  error. Non-systemd Linux hosts (no system D-Bus) degrade gracefully: the guard
  does not arm and the rule reports unarmed rather than compliant. The watch
  reconnects automatically after a `systemctl daemon-reexec` / dbus restart.
  **Build/runtime dependency on Linux agents:** `libsystemd` — build `libsystemd-dev`
  (`systemd-devel` on RHEL/Fedora), runtime `libsystemd.so.0` (`libsystemd0` /
  `systemd-libs`). The default build (`-Dsystemd_guard=enabled`) **requires** it so the
  shipped agent always offers the guard — a build that has lost libsystemd fails loudly
  rather than silently shipping a guard-less agent; the shipped `Dockerfile.agent`,
  `Dockerfile.agent.chisel`, and the asan/tsan images install it and keep that default.
  Pass `-Dsystemd_guard=auto` (use if present) or `disabled` to build the guard as a
  no-op stub on musl/Alpine/non-systemd/minimal images that lack libsystemd.
- **DEX: per-cohort performance gauges for Prometheus/Grafana (opt-in).**
  Settings → DEX alerts gains a **cohort export tag key**: when set (empty by
  default), `/metrics` publishes `yuzu_fleet_perf_cohort_{cpu_pct,commit_pct,
  disk_lat_ms}{cohort,stat}` + `yuzu_fleet_perf_cohort_reporting{cohort}` for
  that key's cohorts, refreshed on the same sweep (and the same validation
  rules) as the existing fleet gauges. Cardinality is bounded: top 50 cohorts
  by population, the 10-device statistical floor applies, and
  `yuzu_fleet_perf_cohort_clipped` makes any capping visible rather than
  silent. Devices without the key export as `cohort="(untagged)"`. Changes
  are audit-logged (`settings.dex_alerts.cohort_export`) and persisted in
  runtime config (`dex_cohort_export_key`).
- **DEX: device drill-down performance extensions.** The `/dex` per-device
  page gains (1) **vs-fleet / vs-cohort percentile strips** — the device's
  current heartbeat CPU / memory commit / disk latency placed against the
  current fleet p50–p90 band (marker turns red above fleet p90), with its
  cohort position when the cohort meets the 10-device floor; rendered live
  from registry state, no query dispatched; and (2) a **per-application
  panel** over the device's opt-in `$ProcPerf_Hourly` edge tier (A2), behind
  its **own** "Load applications" click with its **own audit action
  `dex.device.procperf.query`** — usage-class reads stay separately countable
  from machine-health reads. App rows cross-link to the app reliability
  drill. An empty result renders the truthful message (per-app sampling is
  off by default, or no hourly rollup yet — the device's read-only query
  surface deliberately hides plugin config, so the server does not guess
  which).
- **DEX: in-product fleet performance view (`/dex` → Performance tab).** A
  fifth DEX tab answers "where do I watch fleet CPU in the product" without
  Grafana: fleet-now cards (avg/p50/p90/max + the reporting population) for
  CPU utilization, memory commit and disk I/O latency — the same numbers as
  the `yuzu_fleet_perf_*` Prometheus gauges, computed at render time over
  registry heartbeat state with **zero new storage** — plus **cohort
  benchmarking**: fleet-relative percentiles per cohort of an operator-chosen
  tag key (e.g. `model`, `image`) — fleet-relative percentile
  benchmarking. Honesty rules
  throughout: a metric nobody reported is absent (never 0), cohorts under 10
  reporting devices withhold percentiles ("n too small"), and devices without
  the chosen key appear as an explicit "(untagged)" residual. Every aggregate
  drills to the device list behind it (worst-by-metric, not-reporting,
  cohort members), and each device links on to its drill-down. The read model
  is first-class on all three surfaces: new
  `GET /api/v1/dex/perf/{fleet,cohorts,devices}` REST endpoints and three MCP
  tools (`get_dex_perf_fleet`, `get_dex_perf_cohorts`,
  `list_dex_perf_devices`), all `GuaranteedState:Read`-gated. Trend charts
  (retained history) are deliberately deferred to the Postgres-backed series
  store (F2b). Perf telemetry remains Windows-agents-only in this release;
  the population caption carries that scope.
- **DEX: alert routing + tunable blast-radius thresholds (Settings → DEX
  alerts).** Operators can now route individual DEX signal types to alerts:
  each routed observation raises an operator notification and fires a new
  **`dex.signal`** webhook/offload event (`obs_type`, `subject`, `agent_id`),
  once per device per hour per type, with a global per-minute fan-out cap.
  Nothing is routed by default. The same panel makes the fleet blast-radius
  thresholds (min devices / window / cooldown) **operator-tunable, applied
  live** — no restart (memory and fan-out bounds remain fixed; they are DoS
  posture, not policy). Routing is evaluated at the shared observation-ingest
  chokepoint, so directly-connected and gateway-routed agents are covered
  identically. Changes are audit-logged (`settings.dex_alerts.*`) and
  persisted in runtime config; router activity is observable via the
  `yuzu_server_dex_alert_*` metrics (fired / delivery_failed / suppressed /
  dropped / cooldowns_evicted / routed_types). The agent-side A3 breach
  thresholds (90 % CPU / 10 min etc.) remain fixed in this release.
- **DEX: per-application resource sampling (TAR `procperf` warehouse tier).**
  Each Windows agent now records, on the same 30 s perf tick, the **top 10
  applications by CPU and the top 10 by working set** (union, ≤ 20 rows/tick)
  into the on-device TAR edge warehouse — `$ProcPerf_Live` (7-day window) and
  `$ProcPerf_Hourly` (31-day per-app avg/max rollup). One
  `NtQuerySystemInformation` snapshot per tick: no PDH, no WMI, no per-process
  handles. Samples are aggregated per image name (12 chrome.exe processes =
  one row, `instances=12`); `cpu_pct` is the app's share of total machine
  capacity, matching Task Manager. Privacy: **image names only — never
  command lines**; TAR redaction patterns apply to the name. **Off by default**
  (`procperf_enabled=false`) — per-application data is usage-class telemetry
  subject to works-council/DPA review, distinct from device-level perf (which
  carries no per-app identity and stays on); set `procperf_enabled=true` to opt
  in, independent of the device-level sampler. Queryable via `tar.sql`.
- **TAR: warehouse tables are now ensured on every database open.** Fixes an
  upgrade bug where tables introduced by a newer release (the perf tier, and
  now procperf) were never created on a pre-existing `tar.db` — the schema DDL
  only ran on first-time migration, so upgraded agents failed those inserts
  until the database was deleted. The DDL is idempotent (`IF NOT EXISTS`) and
  now runs on each open.
- **DEX: fleet performance rollup + device perf sparklines.** Two new surfaces
  over the device perf telemetry: (1) every Windows agent ships its current
  utilization (CPU busy %, commit-charge % of limit, per-IO disk latency —
  derived over its heartbeat interval) as heartbeat tags, and the server
  aggregates the fleet into Prometheus gauges
  **`yuzu_fleet_perf_{cpu_pct,commit_pct,disk_lat_ms}{stat="avg"|"p50"|"p90"|"max"}`**
  plus **`yuzu_fleet_perf_reporting`** (the contributing population). Series go
  absent — never a fabricated zero — when nobody reports; non-finite/negative
  values from a rogue agent are rejected and percentages clamp at 100.
  (2) The `/dex` per-device drill-down gains a **device performance panel**:
  CPU / memory / disk-latency sparklines over the device's hourly warehouse
  rollups, fetched by a live read-only `$Perf_Hourly` TAR query dispatched to
  the device when you **click Load performance** (click-to-load — viewing a
  device page alone never dispatches a command; raw samples stay on-device —
  the federated model). Server-rendered SVG, no JS. Needs the device online
  and `Execution:Execute` (the panel says so honestly otherwise); each query
  is audit-logged (`dex.device.perf.query`). Agents with `--dex-disable` ship
  no perf tags.
- **DEX: sustained performance-breach alerts (Performance signal family).** The
  Windows state poller now samples CPU, commit charge, and disk service time
  every 120 s (raw kernel counters — `GetSystemTimes`, `GetPerformanceInfo`,
  `IOCTL_DISK_PERFORMANCE`; no PDH, no WMI, no shell-out) and emits a DEX
  observation when a metric stays bad for a sustained window:
  **`perf.cpu_sustained`** (≥90% busy for 10 min), **`perf.memory_pressure`**
  (commit charge ≥90% of limit for 10 min), **`perf.disk_latency_high`**
  (≥25 ms per IO for 10 min). Each fires once per episode with the window
  average as its metric and re-arms only after a sustained recovery below a
  lower exit threshold (hysteresis — a flapping metric cannot spam the feed;
  worst case ~4 observations/hour/type). The signals ride every existing alert
  surface (SSE, webhooks, blast-radius detection) and land in a new
  **"Performance"** family on the `/dex` Catalogue and Health views (display
  catalogue now 107 entries). Thresholds are fixed in this release
  (operator-configurable thresholds are the F1 follow-up). The TAR perf
  warehouse remains the historical record of the same counters; this is the
  alerting leg.
- **RDP control plugin (`rdp_control`).** New Windows-only agent plugin with
  two actions: `set_state` (enable|disable — writes `HKLM fDenyTSConnections`,
  toggles the Remote Desktop firewall rule group locale-independently via
  `INetFwPolicy2`, and starts `TermService` on enable; per-step status columns
  with `overall=ok` only when every step succeeds) and `status` (reads back all
  three gates and derives `rdp=on|off|unknown`, reporting `unknown` rather than
  `off` when a gate is unreadable). Bundled `windows.rdp.set_state` definition
  (role-gated, `endpoint-admin`) and `windows.rdp.status` (auto, question).
  Built for change-gated remote access: an ITSM system can enable RDP at the
  start of an approved change window and disable it afterward. Disable blocks
  new connections only (does not terminate active sessions). Non-Windows builds
  compile to an error-returning stub. Requires the agent service account to be
  in the local `Administrators` group (not the default install) — see
  `docs/agent-privilege-model.md`.
- **PostgreSQL deploy prerequisites — native packaging, backup/restore docs,
  UAT sidecar (#1320 PR 2; inert-but-ready, no server behavior change).**
  Three deliverables ahead of the substrate's fail-closed flip: (1) the
  provisioning helper `install-server-postgres.sh` now ships in the server
  `.deb`/`.rpm` (at `/usr/share/yuzu/scripts/`, invoked **non-fatally** from
  the package post-install hooks) and in the Linux/macOS release tarballs
  (`scripts/`); (2) operator backup/restore documentation now covers
  PostgreSQL state — `pg_dump --format=custom`/`pg_restore` procedures for
  native and Docker deployments in `docs/user-manual/server-admin.md` (new
  "PostgreSQL Substrate" section) and `upgrading.md`, including the ADR-0010
  **restore-pairing invariant** (database and `KeyProvider` keys-dir backups
  restore *together*; runbook tracked in #1341) and an explicit warning never
  to `tar` a live `postgres-data` volume; (3) the native UAT rig
  (`scripts/start-UAT.sh`) now stands up a `yuzu-postgres:local` sidecar
  container on loopback `:15433` with per-run random, distinct
  superuser/app-role credentials, exports `YUZU_POSTGRES_DSN` to the server,
  and tears the container down on `stop` — a missing docker/sidecar is a
  warning, not a failure, until the #1320 PR 3 fail-closed boot lands
  (`PG_SOFT_FAIL` flag). The rig's agent-registration poll timeout also
  rises 30s → 60s (the fleet-health gauge needs a first heartbeat + a
  recompute window — measured ~37s; the stack was healthy, the poll was
  just too tight).
- **DEX: continuous device performance sampling (TAR `perf` warehouse tier).**
  Every Windows agent now samples CPU busy %, memory used % + commit-charge %,
  per-IO disk service time (µs) + read/write throughput, and non-loopback
  network rx/tx throughput every 30 s into the on-device TAR edge warehouse
  (`$Perf_Live`, 7-day window; `$Perf_Hourly` avg/max rollup, 31-day) — raw
  samples never cross the wire (ADR-0004 federated model). Raw kernel counters
  only (`GetSystemTimes`, `GlobalMemoryStatusEx`/`GetPerformanceInfo`,
  `IOCTL_DISK_PERFORMANCE`, `GetIfTable2`); no PDH, no WMI, no shell-out. New
  `tar collect_perf` action and `configure` keys **`perf_enabled`** (default
  `true`) and **`perf_interval_seconds`** (default 30; `0` disables the trigger
  entirely). Queryable via `tar.sql`. Linux (`/proc`) and macOS
  (`host_statistics`) collectors are planned. Threshold-breach alerting shipped
  alongside (see "sustained performance-breach alerts" above); fleet rollup
  (A4) is a follow-on slice — today's data is collection + raw-SQL query +
  breach alerts, no dashboard chart yet.
- **DEX: fleet blast-radius incident alerting.** When ≥5 distinct devices report
  the same DEX signal `(obs_type, subject)` within a 15-minute sliding window,
  the server raises an operator notification (severity `warn`) and fires a new
  **`dex.blast_radius`** webhook/offload event (payload: `obs_type`, `subject`,
  `device_count`, `window_seconds`) — subscribe to auto-open ITSM incidents.
  Detection runs at the shared Guardian ingest chokepoint, so directly-connected
  and gateway-routed agents both contribute; the window uses server receipt time
  (clock-skew tolerant). Per-pair 1-hour re-alert cooldown; a global
  per-minute fan-out cap and a bounded LRU pair map keep it kind to the server
  and the ITSM sink under a correlated multi-subject incident. Metrics:
  `yuzu_server_dex_blast_radius_{incidents,fires_dropped,entries_dropped,pairs_evicted}_total`
  + `yuzu_server_dex_blast_radius_pairs_tracked`. The 5-devices / 15-min / 1-h
  defaults are now operator-tunable under Settings → DEX alerts (see the alert
  routing entry above).
- **DEX: Windows disk-space and battery-health observations.** A Windows
  state-poll collector (`dex_win_poll`) emits `storage.low` (fixed volume ≥90%
  full or <5 GiB free, 10-min cadence, via `GetDiskFreeSpaceExW`) and `hw.error`
  (battery full-charge capacity <80% of design, hourly, via `IOCTL_BATTERY`)
  on the transition into a bad state (latched; re-arms only on a valid healthy
  reading). Thresholds match the macOS IOKit poll; zero server change.
  `storage.low` and battery (`hw.error`) are now emitted on both Windows and
  macOS (final display-catalogue count for this release: see the Performance
  family entry above).
- **Network probes (`netprobe` plugin).** Active RTT, jitter, and packet-loss
  measurement to operator-chosen targets using native system calls (no
  shell-out): `network.probe.icmp` (ICMP echo — `IcmpSendEcho` on Windows,
  unprivileged ICMP datagram sockets on POSIX; on Linux gated by
  `net.ipv4.ping_group_range`, reporting `not-permitted` rather than fake loss),
  `network.probe.tcp` (connect-time RTT to a target:port, sub-millisecond,
  unprivileged everywhere — use where ICMP is dropped), and `network.probe.dns`
  (`getaddrinfo` resolution timing). Bounded at 4 targets × 10 samples × 3 s,
  sequential. Recurrence via the scheduler; results trend in the response store.
  Admin-only execution (network-reconnaissance primitive).
- **Hardware: installed-driver inventory.** New `hardware drivers` action and
  `device.hardware.drivers` definition list installed device drivers (name,
  version, date, provider, class) via `Win32_PnPSignedDriver` on Windows and
  `/proc/modules` on Linux — supports fleet queries like "devices running driver
  X older than version Y".
- **macOS DEX collector — limited, unprivileged.** The DEX observer now ships a
  macOS collector (`dex_macos_collector.cpp` + the pure parsers
  `dex_macos_{signals,oslog,iokit}.{hpp,cpp}`) using four privilege-light
  mechanisms — a kqueue `DiagnosticReports` folder-watch (`.ips`/`.diag`
  crashes/hangs/panics/jetsam), a `sysctl(KERN_BOOTTIME)` uptime scalar, an
  incremental `log show` unified-log poll, and an IOKit/system-tool poll
  (SMART/battery/disk/thermal/memory). It reuses the OS-neutral obs_types, so no
  server or dashboard change is needed beyond one macOS-only type — `storage.low`
  (disk nearly full) — bringing the catalogue to **104**. Covers ~10 of 11 DEX
  experience headings unprivileged; the Security heading (XProtect/Gatekeeper) is
  not yet shipped. Privacy is minimised at the edge (faulting-image basenames
  only, never raw log message bodies; per-type rate caps; non-finite metric
  guards). Obeys the same `--dex-disable` kill switch as Windows. Source mapping +
  the Endpoint-Security entitlement roadmap: `docs/dex-signal-catalog.md`.
- **DEX dashboard (`/dex`) — a hub plus three deep pages.** The read-only fleet-
  reliability lens over the Guardian observation catalogue is structured as a
  **hub** (measured crash-free-device % and crashes/1k-device-days, honest "—"
  when no agents report) that summarises and links into three deep pages:
  **Catalogue** (all 104 monitored signal types across 12 families — App
  reliability, Boot/start-up & shutdown, Service health, System stability,
  Hardware & storage, File system, Network, Identity & logon, Security &
  protection, Updates & installs, Policy & management, Printing — quiet types as
  real-zero rows, with per-type drill-down and an "Other" bucket for uncatalogued
  types a newer agent emits), **Health score** (a transparent, *secondary* 0–100
  composite — `100 − Σ weighted deductions` — suppressed, never fabricated, when
  no agents report), and **Trends** (cross-OS comparison cards carrying each OS's
  live signal scope, per-family sparklines, and a guard×day activity heatmap). A
  24h/7d/30d/All window selector applies to every view; per-app and per-device
  drill-downs (and the per-signal device list) are permission-gated
  (`GuaranteedState:Read`) and audit-logged on open (behavioral data). A "DEX"
  nav link is in the dashboard chrome. NO mock data anywhere: real aggregations
  or explicit "no data" placeholders.
- **DEX REST + MCP aggregation surface (`/api/v1/dex/*`, MCP `*_dex_signal*`
  tools) — agentic parity.** The DEX dashboard rollups now have machine-readable
  equivalents on both agentic planes so a worker sees the same read-model the
  dashboard does. REST: `GET /api/v1/dex/signals` (the catalogue rollup), `GET
  /api/v1/dex/scope` (per-OS signal coverage), and `GET
  /api/v1/dex/signals/{obs_type}` (one signal's subjects / OS split /
  most-affected devices / per-day trend). MCP: the matching `list_dex_signals`,
  `get_dex_signal_scope`, and `get_dex_signal_detail` read tools. All gated on
  `GuaranteedState:Read` with a `24h/7d/30d/all` `window` and a shared resolver
  so REST, MCP and the dashboard can never drift on the window vocabulary. Audit
  boundary mirrors the events endpoint across all three surfaces: the rollup and
  scope are fleet aggregates (not audited as a view); the per-signal drill-down
  returns a behavioral devices list and emits `dex.signal.view` on every call.
- **Guardian DEX — 103-signal observation catalogue (waves 1–3).** The
  slice-1 crash recorder generalized into one catalogue-driven multi-channel
  observer (`dex_signal_catalog.{hpp,cpp}` + `dex_observer.{hpp,cpp}`,
  renamed from `crash_observer`): 103 obs_types / 22 event-log channels —
  crashes (native + .NET), hangs, service failures (7 kinds), bugcheck/
  power-loss/dirty-shutdown, boot/shutdown/resume durations + per-cause
  degradation, disk SMART/controller/port-reset, NTFS + ESE corruption,
  memory exhaustion, device/TPM/CPU-throttle, Wi-Fi/DHCP/VPN/SMB/DNS/port-
  exhaustion, Entra ID token errors, Windows Hello/biometric errors, RDP
  disconnects, machine-trust/Kerberos/LSA/TLS failures, Defender health,
  BitLocker, certificate auto-enrollment, update check/download/install
  failures, MDM/Intune errors, Group Policy failures, print failures, and
  more (`docs/dex-signal-catalog.md`). Uniform `detail_json` keys mean a new
  signal needs ZERO server change. Per-type rate caps (12–120/h) bound the
  wire. **Privacy minimisation at the edge** ([privacy]-pinned tests): DNS
  query names, print document names/owners, usernames (profile/VPN/RDP/
  service-logon/restart-initiator/Defender), client addresses, user-profile
  paths, AAD message texts, and .NET stack frames are never extracted.
  Verified via real-record fixtures harvested from a live Win11 box plus a
  synthetic event-stream injection sweep (34 classic-source events through
  the real `EvtSubscribe` path; the sweep caught and fixed a case-
  sensitivity bug in provider matching). Heartbeat tags/metrics renamed:
  `yuzu_agent_dex_observer_armed`, `yuzu_fleet_agents_dex_observer_disarmed`,
  `yuzu_fleet_dex_observed_total`.
- **Guardian DEX — fleet-wide process-crash recorder (slice 1).** The agent now
  records Windows process crashes (Application event log, Event ID 1000,
  "Application Error") on managed endpoints as **ruleless** Digital Experience (DEX)
  observations, independent of any Guardian rule. It is an idle-until-crash
  `EvtSubscribe` to the Application channel — no polling, no streaming. Scope is
  Windows-only and Event-1000-only this slice (pure-.NET crashes that emit only a
  `.NET Runtime` 1026, and hosts with Windows Error Reporting disabled, are not yet
  captured). A crash is emitted through the existing Guardian event pipeline and
  distinguished by `rule_id=__observation__` (a reserved sentinel) plus
  `event_type=process.crashed` — not a category field; query it via
  `GET /api/v1/guaranteed-state/events?rule_id=__observation__`. The recorder is a
  no-op off Windows. Agents report crash-recorder arm-state and observed-crash count
  in their heartbeat; the server rolls these up into
  `yuzu_fleet_agents_dex_observer_disarmed` (Windows agents whose observer is not
  armed — failed to arm at startup or lost its subscription at runtime; `> 0` means
  reliability telemetry is silently off there) and `yuzu_fleet_dex_observed_total` (a
  resetting gauge, not a monotonic counter). [Metric names generalised from the
  earlier `*_crash_observer_disarmed` / `*_crashes_observed_total` when the crash
  recorder became the 103-signal observer — both pre-release.] A deploy-time opt-out,
  `--dex-disable` / `YUZU_AGENT_DEX_DISABLE`, collects no crash telemetry. The full executable path is
  parsed but deliberately not sent (data minimisation). See
  `docs/user-manual/guaranteed-state.md#dex-signal-observations` and the
  [DEX dashboard](docs/user-manual/dex.md) (the slice-1 recorder is now one of
  the 103 catalogued signals).
- **libpq (PostgreSQL client library) added as a build dependency on all
  platforms (#1317, ADR-0006/ADR-0008).** This is the F0 link-proof canary for
  the server's storage-substrate migration to PostgreSQL — **no product
  behavior changes and no server-side Postgres usage in this release**; the
  migration lands incrementally over future releases (advance notice:
  ADR-0006). Building from source on Linux now requires `bison` and `flex`;
  on macOS, `autoconf`/`automake`/`libtool` (Windows: none — vcpkg
  auto-acquires winflexbison). The Windows release zip gains `libpq.dll` via
  the existing vcpkg-DLL bundling.
- **Subordinate-CA — root Yuzu's internal CA in your enterprise PKI (PKI PR6,
  M2).** Export the install CA's signing request (`GET /api/v1/ca/root-csr`,
  `Security:Read`), have your enterprise root sign it as a subordinate CA, then
  import the signed intermediate + parent chain (`POST /api/v1/ca/import-chain`,
  `Security:Write`, or **Settings → Internal CA → "Subordinate this CA…"**). Once
  imported, every Yuzu-issued certificate chains to the corporate trust anchor.
  The issuing **key is unchanged** (the enterprise signs Yuzu's existing public
  key), so certificates already issued keep validating across the switch. The
  import is validated — the intermediate must be a CA, must carry **this
  install's** CA public key, and must verify to the uploaded parent chain —
  before the issuing identity is switched; the CRL is then re-published under the
  new issuer. Audited (`ca.root_csr.exported`, `ca.subordinate.imported`).
  Bring-your-own-leaf (`--cert`/`--key`/`--ca-cert` per surface) is unchanged and
  orthogonal. See `docs/pki-architecture.md` "Subordinate-CA".
- **`--cert-san` — extra Subject Alternative Names for the built-in default
  certs (PKI PR5b).** New repeatable server flag (env `YUZU_CERT_SAN`) that
  injects additional SANs into **every** auto-generated default leaf
  (`default-https` / `default-server` / `default-gateway`) on top of the base
  `localhost` / `127.0.0.1` / `::1` / `<hostname>` set. Each value is
  `dns:<name>`, `ip:<addr>`, or a bare value auto-classified by IP-literal shape;
  a single value may be comma-separated (so one `YUZU_CERT_SAN=dns:gateway,dns:server`
  works as well as repeated flags). An `ip:`-tagged value that is not an IP literal
  is dropped with a warning rather than failing the boot. This is the supported way
  to make the built-in certs valid for a deployment name a client actually dials —
  e.g. `--cert-san dns:gateway` so an agent reaching the gateway by that service
  name passes SNI hostname verification (the `default-gateway` leaf does not
  otherwise carry `DNS:gateway`). Ignored when operator certs are supplied or
  `--no-default-certs` is set; changing it does not rotate an existing cert set
  (clear the cert dir or replace the certs). See `docs/pki-architecture.md`.

- **Gateway agent-edge one-way TLS — closes the plaintext command-fan-out hop
  (PKI PR5c).** The Erlang gateway's agent listener (`:50051`) can now run
  **server-authenticated (one-way) TLS** — encrypted + gateway-authenticated, with
  **no client cert required**, so an unenrolled agent still bootstraps (CSR
  enrollment then upgrades identity at the app layer). This closes the
  fleet-RCE-risk plaintext agent↔gateway edge that PR5 had to leave open. It needed
  a 2-line patch to grpcbox v0.17.1 (which hardcodes `fail_if_no_peer_cert=true` /
  `verify=verify_peer` on every TLS listener), carried as a **vendored copy in
  `gateway/_checkouts/grpcbox`** that makes both options read from `transport_opts`
  (defaults preserve stock strict mTLS — fully backward-compatible). Enabled on the
  agent listener in `gateway/config/sys.config.prod`; the privileged mgmt listener
  deliberately does **not** use one-way TLS (it would be unauthenticated). Covered
  by a real EC one-way-TLS handshake test (certless client accepted) alongside the
  existing mTLS test (certless client rejected). 200 eunit pass; dialyzer clean.
  *(The deployed composes + the agent `--ca-cert` / CA-distribution wiring that
  turns this on live land in PR5b; see `docs/pki-architecture.md` "Gateway TLS".)*

- **Gateway TLS — upstream mutual TLS + per-agent enrollment through the gateway
  (PKI PR5).** The Erlang gateway can now speak mutual TLS to the server's
  `GatewayUpstream` listener using the CA-issued `default-gateway` leaf
  (`gateway/config/sys.config.prod` carries the canonical `{https,...}` upstream
  channel; fixes a latent bug where the old config omitted grpcbox's required
  `ssl => true` on the listener `transport_opts` and silently ran plaintext). The
  gateway's vendored proto modules — `gateway_pb` (the `ProxyRegister` marshaller),
  `management_pb`, and the agent-listener `agent_pb` — were all regenerated to
  include `csr_pem`/`issued_certificate`/`issued_ca_chain`, so the gateway-proxied
  `Register` path now **forwards** the agent CSR + issued cert verbatim — the fields
  **survive transit** through the gateway (previously gpb's self-contained modules
  silently dropped the unknown fields; `agent.proto:96` documents the trap). **This
  is plumbing only: the gateway path does not yet *sign* the forwarded CSR** —
  `ProxyRegister` has no signer wired, so a gateway-connected agent still receives an
  empty `issued_certificate` and stays on the bootstrap posture (fails closed).
  Gateway-path issuance lands in **PR5d**, which must first add agent-identity
  attestation on the unauthenticated agent↔gateway hop (the R-6 confused-deputy gate
  — a malicious gateway could otherwise swap the CSR and have the server issue a cert
  for the victim's `agent_id`, or strip `csr_pem` to downgrade the agent). Until then,
  a gateway-forwarded agent is also **not reachable by per-agent revocation** (it
  presents the shared `default-gateway` leaf upstream, not its own) — see
  `docs/pki-architecture.md`. Startup now
  logs the *actual* grpcbox TLS posture (`yuzu_gw_app:log_tls_state/0`), replacing
  a dead/`case_clause`-prone check on the advisory `tls` env, and **fails closed**
  if the upstream is TLS-but-unverified (`https` without `verify_peer` — encrypted
  yet MITM-able; override `YUZU_GW_ALLOW_UNVERIFIED_UPSTREAM=1` for dev/CI).
  **Note: the upstream mTLS lives in the `sys.config.prod` *reference* config — it
  is not yet the build default, so the shipped images/compose rigs still run
  plaintext upstream until PR5b wires the prod profile + cert volumes.** The
  **agent↔gateway
  edge stays plaintext in M1** — grpcbox forces `fail_if_no_peer_cert` on any TLS
  listener, which breaks unenrolled-agent bootstrap. **Do not expose the gateway
  agent port (`:50051`) to an untrusted network** — it is the command fan-out
  plane, so a MITM there is a fleet-RCE risk; front it with TLS termination or keep
  it on a trusted segment (see the SECURITY callout in `docs/pki-architecture.md`).
  Encrypting that hop natively is **resolved in PKI PR5c above** (one-way TLS on the
  agent listener). Covered by a new EUnit suite
  including a real EC mutual-TLS handshake. See `docs/pki-architecture.md`
  "Gateway TLS". (The compose/Dockerfile distribution flip — encrypted-by-default
  containers — is staged as PR5b; the server is already encrypted-by-default when
  run without `--no-tls`/`--no-https`.)

- **Settings → Internal CA dashboard panel (PKI PR4b).** The operator dashboard
  now has a Certificate Authority panel (Settings page, HTMX, dark-theme): the CA
  algorithm/fingerprint/expiry, one-click **Download CA certificate** + **Download
  CRL**, the issued-certificate inventory (serial, subject, purpose, expiry,
  status), and a per-certificate **Revoke** button (with an optional reason
  field) that revokes + republishes the CRL and refreshes the table in place. All
  agent-controlled fields are HTML-escaped; the panel and its revoke action are
  gated by the `Security` securable (`Read` / `Delete`), matching the REST
  surface. The cookie-authenticated dashboard revoke is **CSRF-protected**
  (Origin/Referer same-site check via a shared `origin_is_same_site` helper, also
  used by the MFA POSTs; a cross-origin attempt is refused + audited
  `csrf.denied`) — a forged revoke would otherwise be a fleet-wide-lockout DoS.
  Error responses re-render the full panel with an inline banner (no blank-panel
  swap), and the inventory shows a truncation notice past 500 certs. See
  `docs/user-manual/server-admin.md` and `docs/pki-architecture.md`.

- **Internal-CA REST surface — `/api/v1/ca/*` (PKI PR4).** Operators and
  automation can now manage the built-in CA over REST:
  `GET /api/v1/ca/root` (CA certificate PEM, **public** — trust it in a browser
  or hand it to agents), `GET /api/v1/ca/crl` (certificate revocation list, DER,
  **public**), `GET /api/v1/ca/issued` (issued-cert inventory — serial, subject,
  purpose, status, expiry; `Security:Read`), and `POST /api/v1/ca/revoke`
  (`{"serial_hex","reason"}`; `Security:Delete` — revocation takes effect
  server-side immediately and republishes the CRL). The same inventory + revoke
  operations are also exposed as **MCP tools** (`list_issued_certs` /
  `revoke_certificate`) so an agentic worker reaches the CA surface at parity with
  the dashboard/REST (governed by the standard MCP tier ladder — `revoke` is
  destructive and approval-gated like every other destructive MCP op). A revoke
  of a nonexistent/already-revoked serial is audited `result=denied` (idempotent,
  retry-safe); a CRL republish that fails to persist now honestly reports
  `crl_republished:false` (it no longer serves a freshly-built-but-unstored CRL),
  and a background freshness check re-publishes the CRL before `nextUpdate` lapses
  (and self-heals a failed startup pre-publish — no permanent `/ca/crl` 503). New
  metrics `yuzu_server_ca_cert_issued_total{purpose}`,
  `yuzu_server_ca_crl_publish_failures_total`; audit actions `ca.cert.revoked`
  (`success`/`denied`) + `ca.crl.published`. Issued-cert inventory is now indexed
  on `issued_at`. The routed reference doc `docs/pki-architecture.md` lands with
  this change. (`POST /api/v1/ca/issue` for general operator-chosen-CN signing is
  intentionally deferred — it needs a non-agent namespace so an operator-issued
  cert can't impersonate an agent; the dashboard CA panel ships in PR4b above.)
  See `docs/pki-architecture.md` "CA REST surface".

- **Per-agent mutual TLS, auto-issued at enrollment (PKI PR3).** When the
  server runs with its built-in CA (the default-cert bootstrap above) and an
  agent connects without an operator-supplied client cert, the agent now
  generates its own EC P-256 keypair + PKCS#10 CSR, sends the CSR in
  `Register` (new `RegisterRequest.csr_pem`), and the server signs a per-agent
  client leaf — `CN=<agent_id>` plus an install-scoped URI SAN
  (`yuzu://<ca-fingerprint>/agent/<agent_id>`) — returning it in
  `RegisterResponse.issued_certificate` + `issued_ca_chain`. The agent
  persists the leaf + key (key `0600`) under `--cert-dir` (default
  `<data-dir>/certs`) and reconnects presenting it, so the data plane runs as
  full mutual TLS with a cryptographic identity bound to `agent_id`. The CSR's
  own subject/SAN are ignored — identity is set by the server from the
  authenticated enrollment, never from CSR fields. The server's agent listener
  stays *request-but-don't-require* on default certs so a first-boot agent can
  bootstrap. Enforcement is **gradual** (non-breaking rollout): a provisioned
  agent must present its leaf on the data plane, while a not-yet-provisioned or
  pre-PR3 agent keeps connecting on the prior session + peer-IP binding rather
  than being rejected. Revoked agent leaves are refused at `Subscribe`,
  `Heartbeat`, `DownloadUpdate`, **and `CheckForUpdate`** (new
  `yuzu_grpc_revoked_cert_total{rpc}`), and a periodic server-side **revocation
  sweep** tears down any *already-open* `Subscribe` stream whose leaf is revoked
  after it connected (`rpc=stream_sweep`, audited `session.cert_revoked`
  `source=stream_sweep`) so revocation stops an active agent without waiting for a
  voluntary reconnect. A revoked agent also cannot silently resurrect its identity:
  `sign_agent_csr` refuses to re-issue to an `agent_id` that has a revoked,
  non-expired cert (audit `ca.cert.reissue_blocked`, metric
  `yuzu_server_ca_reissue_blocked_total`), so deleting the local key and
  re-enrolling does not bypass revocation. Every issued leaf's `notBefore` is
  backdated 5 min so a freshly-provisioned agent with a slightly-behind clock can
  still present its cert on the immediate reconnect. Issuance is counted
  (`yuzu_server_ca_cert_issued_total`) and audited (`ca.cert.issued`). New agent
  flags **`--cert-dir`** and **`--no-auto-provision-cert`** (env `YUZU_CERT_DIR`);
  leaves auto-renew at 2/3 of their lifetime (evaluated at agent start). Built
  entirely on OpenSSL 3.x — no new cryptographic primitives. **Known limitation:**
  per-agent revocation is enforced on direct-connect agents only; a
  gateway-proxied agent presents its leaf to the gateway, not the server, so
  revoking it does not by itself cut it off the data plane until the QUIC
  through-gateway-identity migration (#376) — disconnect at the gateway too. See
  `docs/auth-architecture.md` "Gateway-proxied agents: revocation scope".
  **Upgrade:** no special order is required thanks to gradual enforcement; once a
  fleet is fully provisioned, a future `--require-agent-identity` flag will be
  able to harden the data plane to reject any agent without a per-agent cert. See
  `docs/auth-architecture.md` "Per-agent mTLS".

- **Internal CA engine + `ca.db` issuance store (PKI PR1).** New pure-OpenSSL
  PKI engine (`x509_ca`: EC keygen, self-signed root, CSR signing with
  proof-of-possession, leaf issuance, CRL build, chain verify, SHA-256
  fingerprint), a `KeyProvider` seam (`FileKeyProvider`: `0600`/`O_EXCL` key
  custody, HSM/PKCS#11-ready), and the `ca.db` metadata store (`CaStore`: root,
  issued-cert inventory, CRL versions). The root **private key never enters the
  database** — only an opaque `key_ref`. Serials are normalised (uppercase,
  colon-free) at the store boundary so a later operator-supplied serial cannot
  miss `revoke()`/`is_revoked()`; CRL-number allocation is atomic
  (`publish_next_crl`, monotonic per RFC 5280 §5.2.3); the inventory carries an
  `issuer_fingerprint` provenance link to the signing root. Engine only — the
  first-boot wiring lands in PR2.
- **Guardian service guards — real-time Windows service run-state enforcement
  (PR5).** A new `service-status-change` spark with `service-running` /
  `service-stopped` assertions watches one Windows service via
  `NotifyServiceStatusChange` (kernel-notified by the SCM, ~0 ms, no polling)
  and, in `enforce` mode, drives it back to the desired state via the
  service-control API (`StartService` / `ControlService` — never `sc.exe`),
  gated by the same per-rule resilience policy as registry guards. Pending
  service states are held as transitional (no spurious drift / control loop
  during start-up); the watch is resilient to the service being deleted and
  recreated. Off-Windows the guard is a no-op (never reads as armed). The
  schema catalog (`GET /api/v1/guaranteed-state/schemas`) and the
  `derive_rule_spec` authoring validator publish the new types, bound to the
  agent's `service_support::kStates` by a schema↔handler cross-check (H2/G9).
  Enforce-*stop* is denied (and downgraded at push) for security services
  (Defender/Firewall/Security Center/Event Log), critical infrastructure
  (`RpcSs`/`DcomLaunch`), and the agent's own service, so Guardian cannot be
  turned into a security-control disabler or strand itself; enforce-*run* is
  always allowed.
  `service-disabled` (start-type config, which fires no SCM notification) is
  deliberately **not** published yet — express it as a registry guard on
  `…\Services\<name>\Start` = `4` meanwhile. Service guards are authored via
  REST / the seed rig today (like file guards); a dashboard form follows.
- **Break-glass MFA reset CLI (#1226).** `yuzu-server --mfa-reset <username>`
  clears a user's MFA enrollment and exits without starting the server —
  the documented recovery from MFA-enforcement lockout (lost device, IdP
  not asserting `amr`, sole admin who could not enroll). Unlike the manual
  SQL break-glass it replaces, it **writes an audit row**
  (`mfa.reset.breakglass`), closing the SOC 2 CC6.6 evidence gap. Requires
  no TLS/HTTPS flags. Security hardening (adversarial + cybersecurity
  review): the audit row is **mandatory and fail-closed** — `audit.db` is
  opened and verified writable *before* any MFA is cleared, and the command
  exits non-zero rather than silently clearing a second factor with no
  evidence; the audit principal is the **real OS identity**
  (`getpwuid`/`GetUserNameA`), not the forgeable `$USER`/`$USERNAME` env
  var; and the JSON status line is output-escaped. See
  `docs/ops-runbooks/auth-db-recovery.md` for the threat model and the
  `mfa.reset.breakglass` alerting hook.

- **MFA enrollment QR code (#1232).** Both MFA enrollment surfaces — the
  Settings panel and the login-time enrollment-bootstrap form — now render
  a scannable QR code (server-side inline SVG via the vendored Nayuki
  `qrcodegen`, MIT) in addition to the manual base32 secret. The `/login`
  202 `mfa_enrollment_required` response gains a `qr_svg` field (inline SVG,
  or empty string on encode failure → fall back to the text secret).
  Previously only manual key entry was possible.

- **MFA enforcement modes + login-time enrollment bootstrap + OIDC `amr`
  gating (PR 3 of the MFA ladder — ladder complete; SOC 2 CC6.6).**
  - **Enforcement.** `--mfa-enforcement=admin-only|required` (env
    `YUZU_MFA_ENFORCEMENT`) now enforces. An un-enrolled login subject to
    enforcement gets a new `POST /login` 202 variant
    `{"status":"mfa_enrollment_required","mfa_pending_token","otpauth_uri",
    "secret_base32","expires_in"}` (distinguished from the existing
    `mfa_required` challenge by `status`) and completes via the new
    **`POST /login/mfa/enroll`** (confirms the first TOTP code against a
    provisional secret, mints an MFA-verified session, returns one-time
    recovery codes). No session is minted until enrollment completes; if
    `auth_db` is unavailable under enforcement, `/login` fails **closed**
    (503) rather than minting an unprotected session. The endpoint shares
    the `is_login` per-IP rate-limit bucket + the 5-attempt-per-pending
    cap. New audit verb `mfa.enroll.required`; `mfa.enroll.verified` /
    `mfa.enroll.failed` now also fire from the login bootstrap. New
    metric label `yuzu_auth_mfa_logins_total{method="enroll"}`.
  - **Self-target guard.** `POST /api/settings/mfa/disable` refuses to
    disable an operator's own MFA while enforcement protects their role
    (`required` → all roles, `admin-only` → admins); audited as
    `mfa.disabled`/`error`, detail `blocked: mfa_enforcement=<mode>`.
  - **OIDC `amr` short-circuit.** OIDC sessions are no longer blanket-
    exempt from step-up. `/auth/callback` parses the RFC 8176 `amr` claim
    and, when it attests MFA (`amr_asserts_mfa()` allowlist: `mfa`, `otp`,
    `hwk`, `fpt`, `face`, `iris`, `sms`, `swk`, `tel` — single-factor
    `pin`/`user`/`pwd` excluded), seeds `Session::mfa_verified_at`
    anchored to the IdP `iat` in the `steady_clock` domain (NTP-step
    resistant). An OIDC session with an attested-but-stale proof is
    re-prompted via re-SSO (`challenge_url=/auth/oidc/start`); one without
    any attested MFA is treated **symmetrically with a local user** under
    the active enforcement mode — passes under `optional` (or `admin-only`
    for a non-admin), gated (re-SSO) under `required` (or `admin-only` for
    an admin). See the Breaking Changes entry above and
    `docs/user-manual/upgrading.md` for the SSO `amr` pre-flight.
    `/login/mfa/stepup` now rejects OIDC callers with a precise 400
    pointing back to SSO.
  - Tests: `test_mfa_step_up.cpp` (OIDC gating, window boundary,
    `amr_asserts_mfa` allowlist incl. single-factor exclusions),
    `test_auth_routes_mfa.cpp` (enforcement bootstrap, `/login/mfa/enroll`
    success/exhaustion/malformed/concurrent/503, cross-token replay),
    `test_settings_routes_mfa.cpp` (self-target disable guard),
    `test_oidc_provider.cpp` (`amr` parse + malformed/float `iat`
    type-guard). Docs: `docs/auth-mfa-design.md`,
    `docs/user-manual/{authentication,rest-api,server-admin,upgrading}.md`,
    `docs/ops-runbooks/auth-db-recovery.md`.

- **Guardian Baselines — the deployable unit, with baseline-gated deploy.**
  A **Baseline** is a named collection of Guards and is now the *only* deployable
  unit: a Guard reaches an agent exclusively as a member of a **deployed**
  Baseline. New `BaselineStore` (`guardian-baselines.db`): M:N member Guards, an
  included/excluded management-group assignment (reserved — targeting is deferred,
  so deploy is fleet-wide for now), and a draft → deployed lifecycle. Dashboard
  surface only (no REST API yet): create / edit / deploy / re-deploy / delete. The
  push fan-out and heartbeat reconcile source their rule set from the union of
  member Guards of deployed Baselines, taken from each Baseline's **deployed
  snapshot** (what was deployed) — so editing a deployed Baseline's members is a
  staged change that reaches agents only on a Push-gated re-deploy. New `baselines`
  row in `/healthz` + `/readyz` and a `yuzu_server_guardian_baselines_total`
  metric. Audited under `guaranteed_state.baseline.{create,update,deploy,delete}`.
- **Guardian compliance overview + per-(agent, rule) census.** A new
  `guard.compliant` event (emitted once on the transition into compliant, then
  silent) drives a pruning-immune per-(agent, rule) status table
  (`guardian_agent_rule_status`). The dashboard overview reports live fleet
  compliance — Fleet / By Guard / By Baseline coverage, a compliant/drifted/error/
  unknown proportion, a 7-day enforcement-effectiveness trend, and per-device
  drill-down — from one liveness-folded rollup (offline agents fold to unknown).
  **Platform honesty:** Guardian arms guards on Windows only today (the registry /
  file guards are agent-side no-ops on macOS and Linux), but deploy is fleet-wide,
  so connected macOS/Linux agents are reported as a distinct **"not implemented"**
  class — a fleet banner with per-platform counts, a separate census segment (in the
  compliant-share denominator, so the headline % drops when targeted Macs can't be
  enforced), and explicit per-device rows — never folded into compliant or into the
  offline "unknown" bucket. An operator can never mistake a no-op platform for an
  armed one. The REST `/status` endpoint still returns placeholder zeros; the census
  is dashboard-only for now.
- Per-Guard `prerequisites` column reserved on the Guard store (stored, not yet
  evaluated — engine-side evaluation is deferred).
- **Guardian `file-change` spark — realtime file change/deletion detection (Change B).**
  A new agent guard watches a target file via `ReadDirectoryChangesW` on its
  parent directory — kernel-notified, no polling, so detection is realtime — and
  is resilient like the registry guard (survives the parent directory and its
  whole ancestor chain being deleted and recreated; reconciles from scratch).
  Two assertions: **`file-exists`** drifts when the file's presence differs from
  `expected` (`present` → fires on delete; `absent` → tripwire, fires on create),
  and **`file-hash-equals`** drifts when content (size pre-filter + bounded
  SHA-256) differs from a baseline (`expected_hash` supplied, or captured on arm)
  — with a settle window before hashing (writes are not atomic), so a no-op
  identical rewrite is not reported as drift, and absent/oversize/unreadable are
  reported rather than silently treated as compliant. Detection-only (file-content
  remediation deferred); Windows-only (Linux/macOS later). Internally: a new
  `IGuard` interface lets the engine hold registry and file guards
  polymorphically; `sha256_file()` gained a backward-compatible bounded-read
  (`max_bytes`) to defend a hashing-DoS / TOCTOU-grow on an attacker-controlled
  path. The `/api/v1/guaranteed-state/schemas` catalog now lists `file-change` /
  `file-exists` / `file-hash-equals` (with an `expected_hash` hex-format check),
  so the discovery surface and dashboard form know them.
- **Guardian dashboard guard-create form is now functional (C3c).** The
  `/guardian` "New Guard" form was a static stub that audited every submission
  as `denied`. It now renders a structured create form for the Windows registry
  types — name, severity, enforcement mode, the `registry-value-equals`
  assertion fields, the remediation action, and a resilience-policy fieldset
  (mode + tuning params) — and actually persists the Guard. The handler builds
  the structured spec from the form fields and runs it through the **same
  `derive_rule_spec` path the REST create uses** (single source: identical
  validation + canonicalisation), so an invalid resilience policy is rejected
  with an inline banner rather than silently accepted. Success returns a
  confirmation panel plus an out-of-band guards-list refresh and a toast; the
  Guard is created unscoped (draft — device targeting is set at the Baseline).
  Audited under `guaranteed_state.rule.create`.
- **Guardian resilience-policy validation + schema discovery (C3b).** The
  structured Guard create/update path now validates and canonicalises the
  per-rule resilience policy carried in `remediation.params` (`mode`
  persist|backoff|bounded, `max_attempts`, `quiet_reset_s`, `resume_after_s`,
  `backoff_initial_ms`, `backoff_max_ms`, `event_debounce_ms`). Validation is
  lenient-in / canonical-out — only the chosen mode's load-bearing params are
  range-checked (a `persist` rule carrying stray `backoff_*` is accepted),
  values are stored canonical, and failures (e.g. Bounded `max_attempts: 0`,
  `backoff_initial_ms` > `backoff_max_ms`, overflow-prone seconds) return the A4
  error envelope. One param-spec table
  (`server/core/src/guardian_resilience_schema.{hpp,cpp}`) drives both the
  validator and the published JSON Schema, so the discovery surface and the
  validator cannot disagree; a cross-check unit test binds the table's keys to
  the agent's `resilience_keys`. New `GET /api/v1/guaranteed-state/schemas`
  returns the static type catalog (spark/assertion/remediation + resilience
  subschema + discriminated `registry-value-equals` encoding), cacheable via a
  content-derived `ETag` / `If-None-Match` (`304`). A structured `PUT` now
  re-authors the Guard (re-validating the policy) instead of silently dropping
  the blocks; the guardian create/update handlers emit the A4 envelope uniformly.
- **MFA step-up on 11 high-risk REST + Settings surfaces (PR 2 of the MFA
  ladder; SOC 2 CC6.6).** Closes the privileged-access control gap by
  re-prompting for fresh TOTP / recovery proof on session-cookie callers
  before any high-risk mutation lands. New helper `require_mfa_step_up()`
  in `server/core/src/mfa_step_up.{hpp,cpp}` evaluates the gate: api/mcp
  tokens bypass (the bearer credential is itself the step-up moment),
  OIDC/SSO sessions bypass (the identity lives in the IdP — no local
  `users` row or TOTP to step up against; **superseded in PR 3 by `amr`-claim
  gating — see the PR 3 entry above**), non-enrolled users bypass (consistent with PR1's `optional`
  enforcement model), and stale sessions (now − `mfa_verified_at` > `mfa_step_up_
  window_secs`, default 300 s) receive a 401 A4 envelope `{"error":
  {"code":401,"message":"MFA step-up required",...},"meta":{"api_version":
  "v1","mfa_step_up_required":true,"challenge_url":"/login/mfa/stepup"}}`
  plus a `mfa.step_up.required` audit row. A new route `POST
  /login/mfa/stepup` accepts an authenticated session cookie + a TOTP
  code (6 digits) or recovery code; strict-shape gate (same as PR1's
  `/login/mfa`) defeats the CPU-DoS shape oracle. Success refreshes
  `Session::mfa_verified_at` via `AuthManager::mark_session_mfa_verified`
  and emits `mfa.step_up.passed`; failure emits `mfa.step_up.failed`.
  The dashboard auto-intercepts the envelope (`htmx:responseError`) and
  prompts inline so HTMX-driven UI flows complete without operator
  context-switch. The 11 sites wired in this PR:
  - `POST /api/v1/tokens` (token mint — high-impact bearer credential)
  - `DELETE /api/v1/tokens/{id}` (token revoke)
  - `DELETE /api/v1/sessions` (admin force-logout of another principal)
  - `POST /api/v1/software-packages` (introduces executable content)
  - `POST /api/v1/software-deployments/{id}/start` (push to live agents)
  - `POST /api/v1/guaranteed-state/rules` (Guardian rule create — drives
    auto-remediation policy)
  - `PUT /api/v1/guaranteed-state/rules/{id}` (Guardian rule update)
  - `DELETE /api/v1/guaranteed-state/rules/{id}` (Guardian rule delete —
    added in Gate 4 consistency-B1 closure; removing a rule is as
    destructive as updating one)
  - `POST /api/v1/guaranteed-state/push` (Guardian rule fan-out)
  - `DELETE /api/settings/users/{username}` (destroys a principal)
  - `POST /api/settings/users/{username}/role` (promotes / demotes
    authority)
  New CLI flag `--mfa-step-up-window-secs` (default 300; 0 disables the
  gate — emit a startup `WARN`). New Prometheus metric
  `yuzu_auth_mfa_step_up_total{method,result}` (counter). Tests:
  `tests/unit/server/test_mfa_step_up.cpp` (9 cases / 108 assertions —
  every branch of the gate decision tree) + extensions to
  `tests/unit/server/test_auth_routes_mfa.cpp` (5 new cases for
  `/login/mfa/stepup`: TOTP / recovery success, no-session, missing
  code, wrong code). Docs: `docs/auth-mfa-design.md` step-up section
  marked implemented; `docs/user-manual/{authentication,rest-api}.md`
  document the new endpoint + the 401 envelope on each gated site.
  Plan note: the original plan called for 11 sites including `POST
  /api/v1/file-retrieval`; that endpoint turned out to be the
  agent-side push-back (authenticated via mTLS / device token, not a
  session cookie) so step-up does not apply. Guardian rule DELETE was
  added during governance Gate 4 to keep the destructive-Guardian
  surface uniform — final scope is 11 sites.

  The helper fails CLOSED on auth_db errors (governance Gate 4 UP-4 /
  qe Gate 3 BLOCKING fix): a `mfa_status()` failure or a row-not-found
  on the user emits a 401 with `reason=mfa_status_unavailable
  (fail-closed)` rather than silently bypassing the gate. Test:
  `test_mfa_step_up.cpp` "store error fails CLOSED" case.

- **Scope walking — composable scope from previous query results (capability §30).**
  A new per-operator **result set** primitive: a named, TTL-bounded, lineage-tracked
  set of device IDs that becomes the input scope for the next query or action.
  `server/core/src/result_set_store.{hpp,cpp}` (new `result_sets.db`, schema v1 via
  `MigrationRunner`, time-prefixed lexically-sortable `rs_<ts><rand>` ids,
  RETURNING-idiom writes per #1033, sync + async `pending → materialized` lifecycle,
  root-first lineage walk, pin/unpin, per-operator 10k quota + 50-pin caps, 5-minute
  GC sweep). REST surface under `/api/v1/result-sets` (list, direct create,
  from-inventory-query, members, lineage, pin/unpin, delete) — owner-scoped authz,
  A4 error envelope, audit on every state transition. The Scope Engine gains a third
  short-circuit kind, `from_result_set:<id>` (`scope_engine.cpp`), composable with
  attribute predicates via AND/OR/NOT and resolved per-device by
  `AgentRegistry::evaluate_scope` (threaded through all command-dispatch sites); stale
  (offline) members drop silently. A background maintenance thread materialises async
  result sets from terminal executions and runs the GC sweep; new
  `yuzu_result_sets_total` / `yuzu_result_sets_alive` / `yuzu_result_set_gc_total` /
  `yuzu_result_set_quota_rejected` metrics. New `/result-sets` dashboard page
  (`result_sets_ui.{hpp,cpp}`): sidebar of active sets, lineage breadcrumb, copyable
  `from_result_set:` scope token, CSV-import create, pin/unpin/delete — HTMX,
  server-rendered, dark-theme; nav link added across all dashboard pages. The two async
  producers (from-tar-query / from-instruction-result), the YAML `fromResultSet:` DSL
  surface, and re-eval land in follow-up PRs. Design: `docs/scope-walking-design.md`.

- **Scope walking — async result-set producers + TAR SQL frame (PR-D).** The two
  asynchronous producers now create result sets by dispatching a command and
  materialising membership once the producing execution reaches a terminal state:
  `POST /api/v1/result-sets/from-tar-query` (dispatches operator SQL to the tar
  plugin in the parent set's scope — or `__all__` — and includes every agent that
  returned ≥1 row, or all responders with `include_empty=true`) and
  `POST /api/v1/result-sets/from-instruction-result` (runs an InstructionDefinition
  and filters responders by an operator-supplied `{column,op,value|value_set}`
  matcher — the Chrome-IR hash-check step). Both follow the
  create-execution-**before**-dispatch ordering (UP2-4) and return `202` with a
  `pending` row carrying `source_execution_id`; the server maintenance thread applies
  the matcher (new `result_set_matcher.{hpp,cpp}` — `tar_rows_ge` / `any_response` /
  column-op over both the tar pipe shape and JSON array-of-objects) and flips the row
  to `materialized`. `POST /api/v1/result-sets/{id}/re-eval` re-runs an async set's
  source query as a **sibling** (shares the original's parent). Parent references
  accept a per-operator **alias** as well as the canonical `rs_` id (resolved at the
  dispatch layer where the owner is known). New `yuzu_result_sets_total{result="pending"}`
  metric path. The TAR dashboard's "Ad-hoc TAR SQL" frame (`tar_page_ui.cpp`) is now
  live: a reusable **scope chip** (your result sets + `__all__`), a SQL editor, and a
  one-click "Run & create result set" that dispatches, polls the pending set, and
  surfaces the materialised device count + copyable `from_result_set:` token — HTMX,
  server-rendered, dark-theme. The async producer routes require the command-dispatch
  callback + ExecutionTracker (threaded into `RestApiV1::register_routes`); without
  them they return `503`. Design: `docs/scope-walking-design.md` §3.1/§3.3/§6/§8.3/§10.

- **Scope walking — YAML `fromResultSet:` DSL surface (PR-E).** A `spec.scope:`
  block may now carry `fromResultSet:` (a canonical `rs_` id or a per-operator
  alias), optionally refined by a `selector:` composed with `AND`. New
  `scope_yaml.{hpp,cpp}` (with the YAML line-scanners factored out of
  `policy_store.cpp` into shared `yaml_scan.{hpp,cpp}`) parses, validates, and
  lowers the block to the existing scope-engine grammar:
  `selector.platform` → `ostype == "<value>"`, each `selector.tags` entry →
  `EXISTS tag:<name>` (presence; Yuzu tags are key=value), AND-composed with the
  `from_result_set:<ref>` atom. Validation (design §7): `fromResultSet` may not
  be combined with `assignment.managementGroups`, and requires
  `assignment.mode: static` — enforced at definition import
  (`InstructionStore::create_definition`) and policy create. `from_result_set:`
  **aliases now resolve at the dispatch layer** against the operator's owned sets
  (`resolve_scope_aliases` at the generic REST, tracked, MCP, and
  `/api/scope/estimate` paths) — previously only producer `parent_id` resolved
  aliases, so an alias in a scope silently matched nothing. An invocation-time
  resolution failure (the referenced set is absent, expired, or not owned) now
  emits an `instruction.scope_resolution_failed` audit row
  (`INSTRUCTION_SCOPE_RESOLUTION_FAILED`). Resolution stays lazy: a definition
  carrying a since-expired `fromResultSet:` is still valid YAML. Policy
  `fromResultSet:` is **rejected for now** (a result set's 1h TTL clashes with a
  continuously-evaluated policy; deferred to a follow-up with a policy owner +
  pinned-set semantics). Design: `docs/scope-walking-design.md` §7;
  `docs/yaml-dsl-spec.md` §9.3. Validation runs on **both** the create and
  update definition paths; `selector`/`fromResultSet` values are restricted to
  the scope-ident charset (no injection / unparseable output) and inline
  flow-mapping scope is rejected. The dispatch resolution-failure path emits a
  new `yuzu_scope_resolution_failed_total` metric and `result_set_store` is now
  covered by `/readyz`.

- **Compliance policies now actually evaluate (check → verdict pipeline).**
  Authored policies + fragments could be created, but nothing evaluated them —
  `PolicyStore::update_agent_status` had no caller and no trigger fired, so
  `get_fleet_compliance` / `get_compliance_summary` always read 0%. A new
  background `PolicyEvaluator` (`server/core/src/policy_evaluator.{hpp,cpp}`)
  closes the gap: on a cadence it finds enabled policies whose interval has
  elapsed, resolves scope/management-groups to agents, dispatches the fragment's
  `check` instruction (via the shared command-dispatch path), then collects each
  agent's response, evaluates the CEL `check_compliance`, and writes
  `compliant` / `non_compliant` / `unknown` / `error` per agent. Two new
  operator-gated endpoints: `POST /api/policies/{id}/evaluate` (force an
  immediate check) and `POST /api/policies/{id}/remediate` (manual, opt-in
  remediation — dispatches the fragment's `fix`, then verifies via `postCheck`;
  only available when the fragment defines a `fix` instruction, surfaced as
  `remediation_available` on the policy detail). Remediation is never automatic.
  Audit actions `policy.evaluate` / `policy.remediate`. Hardening from the
  governance pass: an empty `check_compliance` is scored `error` (never a false
  `compliant`); a fresh verdict invalidates the 60s fleet-compliance cache so it
  surfaces promptly; the evaluator's `polchk-*` correlation ids are skipped by
  the execution-tracker notifier (no phantom executions / SSE — compliance is
  not in the executions drawer); stranded `fixing` rows are reset to `unknown`
  on restart; the background dispatch never holds the evaluator lock across the
  (blocking) command dispatch; the interval is clamped to a ≥60s floor; the
  evaluation thread is exception-isolated and joined before stores tear down
  (`~ServerImpl` now calls `stop()`); caller-supplied `remediate` agent lists are
  intersected with the policy's own scope; new `yuzu_server_policy_verdicts_total`
  / `yuzu_server_policy_eval_errors_total` metrics.
- **MFA / TOTP — PR 1 of the `/auth-and-authz` skill P0 #1 ladder (SOC 2
  CC6.6).** First shippable slice of MFA: RFC 6238 TOTP self-service
  enrollment via Settings → Multi-Factor Authentication, login challenge
  after password verify, recovery codes. Step-up on high-risk endpoints
  and OIDC `amr` interop ship in subsequent PRs of the same ladder.
  - `auth.db` schema v2 migration: `users.mfa_totp_secret` (BLOB, raw 20-byte
    HMAC-SHA1 key per RFC 4226 §4 R6, at-rest protected by the existing
    0600 file mode), `users.mfa_enrolled_at`, `users.mfa_disabled_at`,
    `users.mfa_last_counter` (replay floor), `sessions.mfa_verified_at`,
    new tables `mfa_recovery_codes` (PBKDF2-SHA256 hashed, single-use)
    and `auth_kv` (provisioned empty for future encryption-at-rest).
  - New `server/core/src/totp.{hpp,cpp}` — RFC 6238 TOTP generator/verifier
    (30 s step, 6 digits, ±1 step skew with replay protection), RFC 4648
    base32 enc/dec, otpauth URI builder, CSPRNG secret and recovery-code
    generation. Tested against RFC 6238 Appendix B SHA-1 vectors.
  - `AuthDB::mfa_init_enrollment` / `mfa_verify_enrollment` /
    `mfa_verify_login_code` / `mfa_consume_recovery_code` /
    `mfa_regenerate_recovery_codes` / `mfa_disable` / `mfa_status` /
    `mfa_mark_session_stepup` — new MFA accessor surface on the existing
    AuthDB instance.
  - `AuthManager` additions: `verify_password` (creds-only check, no
    session), `create_local_session(user, role, mfa_verified)`,
    `mark_session_mfa_verified(token)`, `auth_db_ptr()` accessor.
  - `Session::mfa_verified_at` field (step-up window comparison).
  - `Config::mfa_enforcement` (`optional` | `admin-only` | `required`,
    default `optional`), `Config::mfa_step_up_window_secs` (default 300),
    `Config::mfa_login_pending_secs` (default 120). CLI flags
    `--mfa-enforcement`, `--mfa-step-up-window-secs`,
    `--mfa-login-pending-secs` (envs `YUZU_MFA_*`). PR1 honours
    `optional` semantics only; non-default values emit a startup `WARN`.
  - `POST /login` now returns HTTP 202 + `{"status":"mfa_required",
    "mfa_pending_token":"…","expires_in":N}` if the user is MFA-enrolled;
    the login page swaps to a TOTP form and posts to `POST /login/mfa`
    (TOTP code or recovery code; same endpoint). Each pending token is
    capped at 5 attempts before invalidation.
  - Settings page gains a Multi-Factor Authentication section with
    enroll / verify / regenerate / disable HTMX handlers under
    `/fragments/settings/mfa` and `/api/settings/mfa/*` (admin-only in
    PR1; per-user surface is a follow-up). All 4 mutating POSTs carry
    `Origin`/`Referer` CSRF protection via an `origin_safe` helper
    (default-port normalised, userinfo rejected, audit detail
    sanitised + 128 B capped).
  - New audit verbs: `mfa.enroll.initiated`, `mfa.enroll.verified`,
    `mfa.enroll.failed`, `mfa.disabled`, `mfa.login.required`,
    `mfa.login.verified`, `mfa.login.failed`, `mfa.recovery_codes.generated`,
    `mfa.recovery_code.used`, `csrf.denied`. Step-up verbs
    (`mfa.step_up.required`, `mfa.step_up.passed`, `mfa.step_up.failed`)
    added in PR 2.
  - Prometheus metrics: `yuzu_auth_mfa_logins_total{method,result}`,
    `yuzu_auth_mfa_pending_tokens` gauge,
    `yuzu_auth_mfa_challenges_issued_total`.
  - Docs: `docs/auth-mfa-design.md` (architecture), updated
    `docs/auth-architecture.md`, user-manual updates
    (`authentication.md`, `rest-api.md`, `server-admin.md`),
    `docs/ops-runbooks/auth-db-recovery.md` Emergency MFA disable
    break-glass procedure.
  - Tests: `tests/unit/server/test_totp.cpp` (RFC 6238 vectors, base32,
    drift / replay) and `tests/unit/server/test_mfa_store.cpp` (end-to-end
    AuthDB enroll → verify → login → recovery → disable).

### Changed

- **Guardian dashboard redesign — full-page detail, card views, and a Guard
  filter (UI only; no REST `/api/v1` change).** The Guard and Baseline detail
  views are now **full pages** (`/guardian/guard/<id>`, `/guardian/baseline/<id>`)
  replacing the detail modal. The By-Guard and By-Baseline compliance views are
  stats-forward **card lists** (not tables); By-Guard gained a **filter bar**
  (free-text search + state / severity / mode). The Fleet stat cards are now
  **clickable** (jump to the matching sub-view, pre-filtered). The Guard detail
  page's per-device rows link to the host page; the Baseline page shows its member
  Guards and recent events; the Recent Events panel has a free-text search box.
  Baseline **Edit** moved to the Baselines-section card. A CSP fix removed htmx
  `hx-on` handlers from the product UI (operators see no functional change).
- **Breaking — Guardian `enforcement_mode` is immutable after creation.**
  `PUT /api/v1/guaranteed-state/rules/{id}` with an `enforcement_mode` that
  differs from the stored value now returns `400` (`enforcement_mode is immutable
  — create a new Guard for a different mode`); a different posture (enforce vs
  audit) is a different Guard. The dashboard's per-Guard **Switch to Audit /
  Switch to Enforce** toggle is **removed**; the remaining enable/disable toggle
  is state-only (`Write`, no auto-push) and propagates on the next
  deploy/reconcile.
- **Breaking — Guards reach agents only via a deployed Baseline.** After
  upgrading from a pre-Baseline Guardian build, a Guard not in a deployed Baseline
  is silently omitted from every agent push and stops enforcing. Create a Baseline
  containing your active Guards and deploy it — see the upgrade note in
  `docs/user-manual/guaranteed-state.md`.

### Fixed

- **Guardian drift events lost during fleet-wide drift waves (#1307).** The
  agent drift path minted `event_id = "{rule_id}-{ms}-{seq}"` with no agent
  component. Because `event_seq_` is a per-agent counter that every agent starts
  at 0 and `event_id` is a global `PRIMARY KEY` on the server (insert drops on
  UNIQUE conflict), two agents drifting on the same rule in the same millisecond
  produced an identical id and the server silently kept one row and discarded the
  rest — exactly the correlated case during a bad-deploy drift wave. The id now
  folds in the agent id: `"{rule_id}-{agent_id}-{ms}-{seq}"`, so the agent_id
  segment alone guarantees cross-agent distinctness. No schema change; `event_id`
  remains an opaque primary key.
- **Token-store DB-open failure at startup now surfaces as `503 service
  unavailable` on `GET`/`POST`/`DELETE /api/v1/tokens`, never as `404`/empty
  list (#347 CH-3).** An `ApiTokenStore` whose SQLite database failed to open
  at startup (bad data dir, permissions) previously collapsed into the
  not-found path: `DELETE /api/v1/tokens/{token_id}` returned `404 token not
  found` for a storage outage and `GET /api/v1/tokens` masked it as an empty
  `200` list. The REST guards now check `is_open()`, mirroring the dashboard
  API-tokens fragment, and emit the same `service unavailable` message as
  every other store-down guard so message-grep alerting stays unified. The
  identical-404 anti-enumeration response for not-found vs not-owner is
  unchanged. Mid-request I/O errors on a connection that opened successfully
  are tracked as #1383. *Integration note:* automation that treated `404` from
  these endpoints as "token not found" must now also handle `503` as a distinct
  storage-failure signal. (The same store-availability gate is still missing on
  the device-token routes and dashboard token create/revoke — tracked as #1382.)
- **SSE channel GC no longer aborts the server (#1198).** `gc_terminal_channels()`
  destroyed each collected execution channel — and the `std::mutex` inside it —
  while a `lock_guard` still owned that mutex: the channel map held the only
  `shared_ptr`, so the erase ran the destructor synchronously and the guard then
  unlocked freed memory. On MSVC this aborted the whole server
  (`mutex.cpp(150): unlock of unowned mutex`); on every toolchain it was UB.
  Reachable from normal operator activity: any execution that completes, loses
  its SSE subscribers (executions drawer closed), and ages past the 60 s
  retention window triggered the bad path on the next publish-driven GC sweep.
  Fixed by pinning each victim with an extra `shared_ptr` and deferring
  destruction until all per-channel locks are released.
- **MCP prompt arguments are now framed as untrusted data (security, #656).**
  `prompts/get` previously interpolated caller-supplied string arguments
  (`agent_id`, `policy_id`, `principal`) directly into the generated prompt
  text, so a hostile agent hostname, policy id, or principal name could inject
  instructions the AI assistant would act on. Each string argument is now
  JSON-escaped and wrapped in `BEGIN_UNTRUSTED_MCP_ARGUMENT` /
  `END_UNTRUSTED_MCP_ARGUMENT` sentinels with an explicit data-only directive;
  the escaping keeps the value on one line so the end sentinel cannot be forged.
  These markers are part of the `prompts/get` response shape — clients that
  display prompt text will see them (see `docs/user-manual/mcp.md` →
  Prompt-injection hardening).
- **Agents enrolling *through the gateway* now receive a per-agent client
  certificate (PKI PR5d).** Previously only direct-connect enrollment issued the
  per-agent mTLS leaf — `GatewayUpstreamServiceImpl::ProxyRegister` registered the
  agent but never signed its CSR, so a gateway-routed agent retried then ran on
  the bootstrap (one-way TLS) posture without an identity cert. `ProxyRegister`
  now signs the CSR through the same `sign_agent_csr` chokepoint as the direct
  path (same CA, per-agent rate-limit, `ca_issued` inventory, and a new shared
  16 KiB CSR-size cap), and the gateway relays the issued cert to the agent
  unchanged. Note: revoking a certificate is serial-scoped (it invalidates a
  presented leaf) — to stop an agent re-enrolling/re-issuing, **deny** the agent.

- **Server container can generate its default certs on first boot (PKI PR5b).**
  `deploy/docker/Dockerfile.server` now pre-creates `/etc/yuzu/certs` and
  `chown -R`s `/etc/yuzu` to the unprivileged `yuzu` runtime user. Previously
  `/etc/yuzu` was root-owned, so the secure-by-default first-boot CA + default
  cert generation (which runs as `yuzu`) failed with a permission error in the
  container. Surfaced by the live two-host gateway boot-test.
- **MFA enrollment no longer rotates the provisional secret on re-init
  (#1227).** `mfa_init_enrollment` on a not-yet-confirmed (provisional)
  row now **reuses** the existing secret instead of minting a fresh one,
  so a second browser tab, a retried `/login` enrollment bootstrap, or a
  re-opened Settings panel no longer invalidates the QR the operator
  already scanned. The provisional secret is still reaped if abandoned;
  once enrollment is confirmed, the secret is never re-revealed. The reuse
  path carries a TOCTOU guard (adversarial + cybersecurity review): it
  re-checks the freshly-loaded row's `enrolled` flag — read in the same
  SELECT as the secret, so it is a consistent snapshot — and refuses to
  re-reveal (`MfaAlreadyEnrolled`) if a concurrent `mfa_verify_enrollment`
  confirmed the secret between the status-check and the reuse-load on the
  shared FULLMUTEX connection.

- **Login inputs no longer auto-capitalise on iOS (#1233).** The username,
  MFA-code, and enrollment-code fields on the login page — and the MFA
  verify-code field in Settings — now carry `autocapitalize="none"`,
  `autocorrect="off"`, and `spellcheck="false"`, so iOS Safari/WebKit no
  longer turns `admin` into `Admin` (usernames are case-sensitive).

- **Guardian (#1209): H1–H4 + M1–M8 backend hardening.** Dashboard toggle pushes
  only the rule's own `scope_expr` (no whole-fleet toggle storm — H1). The
  `__guard__` side-channel is classified by `plugin=__guard__` **and** empty
  `command_id`, so solicited `push_rules` replies complete their gateway
  round-trip instead of being dropped (H2). Per-guard event-sink collapse-with-
  count debounce caps event-store flooding from a competing writer (H3). The
  agent event-sink writes through a current-stream holder reset under lock, so a
  guard firing during a reconnect teardown can't write to a cancelled stream
  (H4). Dashboard data panels gated on `GuaranteedState:Read` (M1); honest
  empty-state and an unmistakable DEMO banner — no fabricated "148/148 compliant"
  rollup on a live console (M2). `enforcement_mode` reconciled to `enforce|audit`
  + the `enabled` boolean (M3). Per-agent push filtering by `os_target` +
  `scope_expr` (M4). Heartbeat-carried `policy_generation` drives a per-agent
  rate-limited server reconcile so offline-at-push agents converge on reconnect
  (M5), backed by a monotonic persisted generation counter (M6). The reconcile
  re-push is metered (`yuzu_server_guardian_reconciles_total`,
  `..._pushes_dispatched_total`, `..._policy_generation`) and audited
  (`guaranteed_state.reconcile`).
- **Guardian MVP pre-merge review hardening (PR #1220).** Three blocking review
  findings fixed before merge: (H1) **enforce-mode registry writes are gated by a
  dangerous-key denylist** — `derive_rule_spec` now refuses an
  `enforcement_mode:"enforce"` rule whose key targets a high-blast-radius
  persistence / privilege location (autorun `CurrentVersion\Run*`, Image File
  Execution Options, Winlogon, `…\Services\…`, `…\Policies\…`, SafeBoot,
  BootExecute), returning the A4 envelope (contract §6 gate; the SYSTEM-privileged
  fleet-wide write path no longer ships ungated). (H2) **the published
  `/schemas` enum, the dashboard form, and the validator now offer only the
  registry hives/value-types the agent actually decodes** — `HKCC`, `REG_BINARY`
  and `REG_MULTI_SZ` are removed (they produced perpetual false drift /
  remediation-failed); a single server-side source drives the schema enum and the
  validator, cross-checked against the agent's `registry_support` constants by a
  unit test. (#3) **the schema catalog is now discoverable on the MCP plane** —
  `get_guardian_schemas` tool + `yuzu://guardian/schemas` resource, gated
  `GuaranteedState:Read`, returning the byte-identical REST catalog (contract §4
  decision 3 / §9 G9; supersedes the #1210 deferral). Plus: server-side validation
  of spark/assertion params (rejects `max_bytes:"0"`, non-numeric numerics, bad
  hive/value_type/expected_hash); whole-string numeric parsing on the agent
  (`"123abc"` no longer parses as `123`); overflow-safe backoff doubling and
  seconds→ms conversion; and a corrected `guaranteed_state.proto` transport
  comment (`payload` bytes, not `params`/`output`).
- **Scope-walking PR-E follow-ups — policy `fromResultSet:` bypass + YAML scanner
  hardening (#1221).** Two robustness gaps from the #1215 review, both fail-closed
  before this change: (1) a **scalar** policy scope (`scope: from_result_set:rs_x`)
  slipped past the policy `fromResultSet` rejection — `extract_yaml_value` returned
  it non-empty, skipping the mapping-form check — and was stored verbatim;
  `PolicyStore::create_policy` now rejects the `from_result_set:` atom in either the
  scalar or mapping form. (2) `yaml_scan::extract_yaml_value` is now comment-aware
  (it skips keys inside whole-line and inline `#` comments, matching `yaml_has_key`),
  so a commented `# fromResultSet:` decoy can no longer be picked up; and
  `extract_yaml_section` now anchors on line-leading keys instead of an unanchored
  `find()`, so a `scope:` substring inside a description/value no longer mis-anchors
  the section walk and silently drops the whole block (which, for a policy, would
  fail **open** to a fleet-wide match). `yaml_scan.hpp` gains an
  isolate-via-`extract_yaml_section`-first security contract for the
  now-authorization-load-bearing scanners. No behaviour change for valid content.

- **`scope.selector:` policies now lower to a real scope (PR-E).** A Policy whose
  `spec.scope:` opened a `selector:` mapping was previously read by the scalar
  extractor as empty and silently stored no scope. It now lowers via the `scope_yaml`
  path (`selector.platform` → `ostype`, `selector.tags` → `EXISTS tag:`). Scalar
  `scope:` expressions are unchanged. No shipped content used the mapping form.
  **Upgrade note:** existing policy rows are not migrated, but **re-creating or
  re-importing** an operator-authored policy that used the `scope: { selector: ... }`
  mapping form will now apply the selector as a real predicate — where it previously
  matched all devices (the selector was silently ignored), it will now narrow. Review
  such policies' intended scope before re-importing. See `docs/user-manual/upgrading.md`.

- **Dashboard scope panel now visible at narrow viewports (≤1280px).** A global
  responsive rule in `server/core/static/yuzu.css` was hiding the right-hand
  agent/device selector panel (`.scope`) on any browser window 1280px wide or
  narrower — a common laptop resolution — making connected agents invisible
  until the operator widened the window past ~1400px. The rule was inherited
  from an unrelated `.main-grid` layout. Now only the optional history rail is
  hidden at that breakpoint; the scope panel reflows to a two-column layout and
  stays fully accessible. The 1281–1440px band also received grid hardening
  (`minmax(0,1fr)` middle track + `min-width:0`) so the instruction bar's
  minimum content size can no longer push the panel off-screen.

- **Scope walking — `from_result_set:` is owner-scoped end-to-end (the merge-blocking
  IDOR, review B1).** `AgentRegistry::evaluate_scope` resolved `from_result_set:<id>`
  with no owner check, so any operator with `Execution:Execute` could embed another
  operator's `rs_` id in a scope and dispatch commands to that operator's curated
  devices. The dispatching principal is now threaded into `evaluate_scope`;
  referenced sets are preloaded once via the new owner-checked
  `ResultSetStore::member_set_owned` (a set the caller does not own resolves to an
  empty membership and never matches), which also removes the per-agent under-lock
  store query (review F). Tracked dispatch paths (REST async producers, workflows,
  scheduled, MCP) recover the principal from the execution's `dispatched_by`;
  `/api/command` reads the session; server-authored policy scopes intentionally do
  not resolve `from_result_set:`. A used set is `touch`-ed so it does not GC
  mid-investigation (review I).
- **Cross-operator result-set metadata leak via `/lineage` closed (review B2).**
  Direct `POST /api/v1/result-sets` owner-checks `parent_id` before persisting the
  lineage edge, and `ResultSetStore::lineage` is owner-filtered (the walk stops at
  the first cross-owner ancestor) — a child can no longer parent onto a victim's id
  and read its name / source_kind / device_count back.
- **Result-set DoS vectors bounded (review B3, B4, K).** Fixed an infinite loop in
  `from-inventory-query` parent pagination (an aliased in/out cursor re-read page one
  forever once a parent exceeded the 5000 page size); added a `kMaxMembersPerSet` cap
  (100k) on the JSON-array and CSV-import create paths; bounded the
  `from_result_set:` scope token to 128 chars in the parser.
- **Async producers no longer orphan a destructive dispatch (review B5).** `run_async`
  does a pre-dispatch quota check and, on any post-dispatch `create_pending` failure,
  calls `mark_cancelled` and surfaces `execution_id` — matching the throw / no-agents
  paths so the execution cannot idle in `running` after agents already executed.
- **Dashboard result-set fragments stop faking success (review merged_bug_009).**
  Pin / unpin / CSV-create honour the store's `std::expected`: they audit the real
  outcome (no false `success` rows) and surface failures via a `showToast` HX-Trigger
  instead of silently re-rendering as if the action succeeded.
- **Failed result-set access is audited (review G) + observability/correctness nits.**
  Non-owner / not-found 404s emit a `result_set.access` `denied` audit row with the
  attempted id (existence-oracle trail); the maintenance thread only increments
  `yuzu_result_sets_total{result="materialized"}` on success (`materialize_failed`
  otherwise — bug_008); `gc_sweep` returns the real deleted count and logs on failure
  (D); `device_count` reflects distinct members after `INSERT OR IGNORE` dedup (L);
  `lineage` has a visited-set cycle guard (J); re-eval no longer appends ` (re-eval)`
  unboundedly (bug_014); result-set `limit` params parse via `std::from_chars` (M).
  `rs_` ids stay non-CSPRNG display identifiers per the #801 convention now that B1
  removes the bearer-reference property (review E, by design).

### Tests

- **Scope walking — YAML `fromResultSet:` DSL (PR-E).** New
  `tests/unit/server/test_scope_yaml.cpp` (`[scope][dsl]`, 15 cases): the lowering
  table (`fromResultSet`, `selector.platform` → `ostype`, `selector.tags` →
  `EXISTS tag:`, full composition), the design §7 validation rules
  (managementGroups exclusion, static-mode requirement, empty/over-long ref),
  scalar-scope backward compatibility, rule-3 load-time validity, and the
  lowered-string round-trip through `yuzu::scope::parse`.
  `test_scope_walking_authz.cpp` gains `resolve_scope_aliases` (owner alias
  rewrite, composition, `rs_` passthrough, non-owner / empty-owner no-op,
  quoted-literal skip) and `scope_refs_failing_owner_check` (absent/unowned
  flagged; owned-but-empty not flagged) coverage. `test_policy_store.cpp` pins
  `scope.selector` lowering + the policy `fromResultSet` rejection;
  `test_instruction_store.cpp` pins import validation (static accepted +
  round-trips, dynamic rejected, managementGroups rejected, scope-less
  unaffected). Governance hardening adds: the `update_definition` bypass guard,
  charset rejection (selector/ref), inline flow-mapping rejection, multi-ref
  alias rewrite + owner-check, the fail-closed unknown-id case, and a new
  `test_yaml_scan.cpp` covering the moved line-scanners (incl. adversarial
  commented-key / quoted-value-leak / prefix-collision inputs).
- **Route-level MFA test harness (closes PR1 deferred quality-engineer
  SHOULD-FIX).** Hermes Agent's red-team round on PR1 caught the
  CRITICAL `/login/mfa` pre-routing exemption bug within 30 s of live
  curl probing because the internal governance pipeline reviewed
  handlers statically without exercising the wire path. This change
  closes that gap with two new test files that drive every MFA-touching
  handler through an in-process `TestRouteSink` (TSan-clean per #438).
  - **`AuthRoutes::register_routes` dual overload**: mirrors the
    `SettingsRoutes` pattern. Existing `httplib::Server&` overload becomes
    a 2-line shim that constructs `HttplibRouteSink` and delegates to a
    new `HttpRouteSink&` overload that owns every lambda. Production
    behaviour is unchanged; tests get a TSan-safe in-process dispatch
    seam.
  - **`tests/unit/server/test_auth_routes_mfa.cpp`** — 10 cases covering
    `POST /login` (no-MFA fast-path + MFA-enrolled 202 branch + bad
    password), `POST /login/mfa` (valid TOTP, valid recovery code,
    invalid pending token, 5-attempts-cap, strict-shape gate routing
    non-6-digit to recovery, pending-token TTL expiry, atomic erase
    under concurrent submit with same valid token), and the dual audit
    emission contract (`mfa.login.verified` + `auth.login`,
    `mfa.recovery_code.used` + `auth.login`).
  - **`tests/unit/server/test_settings_routes_mfa.cpp`** — 12 cases
    covering the 5 `/api/settings/mfa/*` routes (init reveal +
    Cache-Control: no-store contract, double-init → MfaAlreadyEnrolled
    message, recovery-codes regenerate, disable atomicity, non-admin
    403), and the `origin_safe` CSRF gate (same-origin pass,
    cross-origin 403 with `csrf.denied` audit, default-port :443
    normalisation, userinfo / RFC-6454 rejection, no-Origin
    non-browser pass-through, Referer fallback).

- **Scope walking.** `tests/unit/server/test_result_set_store.cpp` — 8 cases for
  `ResultSetStore`: synchronous create/get/members, root-first lineage,
  owner-scoped alias resolution, pin/unpin + pinned-delete rejection, async
  create → materialize, touch TTL extension, GC sweep, and the per-owner quota
  counter. `tests/unit/server/test_result_sets_ui.cpp` — 7 render cases for the
  result-sets dashboard surface including an explicit XSS test (operator-supplied
  names are HTML-escaped). `tests/unit/server/test_scope_engine.cpp` — 3 added
  cases for the `from_result_set:` scope kind: bare-atom parse, composition with
  attribute predicates (AND), and per-device membership evaluation
  (member+predicate match, non-member drop). All on `TempDbFile` helpers.

- **Scope walking PR-D.** `tests/unit/server/test_result_set_matcher.cpp` — 11 cases
  for the async membership matcher (pure `(matcher, status, output)` function):
  non-success never qualifies, empty/blank → SUCCESS default, `any_response`,
  `tar_rows_ge` thresholds + tar `error|` → 0 rows, `tar_row_count` trailer +
  line-count fallback, unknown-kind conservative exclude, column ops
  (`eq`/`in`/`contains`/`exists`) over both the tar pipe shape and the JSON
  array-of-objects fallback, and the malformed-matcher fallbacks.
  `tests/unit/server/test_rest_result_sets_async.cpp` — 14 HTTP-level cases (real
  `ResultSetStore` + `ExecutionTracker`, fake recording dispatch closure):
  from-tar-query 202/pending shape + create-before-dispatch ordering, `__all__` vs
  `from_result_set:<parent>` scope, **alias pre-resolution** to canonical id,
  unknown-alias 404, `include_empty` → `any_response` matcher, missing-sql 400,
  zero-agents 503 (execution cancelled, no pending row), dispatch-throw 500,
  unwired-dispatch 503, from-instruction-result plugin/action/matcher persistence +
  unknown-instruction 404, and re-eval sibling parent / unsupported-kind 400 /
  not-found 404.

- **Scope walking — review remediation.** `tests/unit/server/test_scope_walking_authz.cpp`
  — cross-operator `evaluate_scope` authorization: the set owner resolves exactly the
  set's members, while a non-owner and an empty principal resolve nothing (the B1
  IDOR is blocked). `tests/unit/server/test_result_set_store.cpp` gains 7 cases: GC
  actually deletes expired unpinned rows and returns the count (D), per-set member cap
  (B4), `device_count` distinct-dedup (L), owner-scoped `member_set_owned` (B1),
  lineage stops at a cross-owner ancestor (B2) and terminates on a `parent_id` cycle
  (J), and >5000-member pagination terminates (B3); its lineage assertions move to
  the owner-arg `lineage`. `test_workflow_routes.cpp` updated for the principal-arg
  scope-estimate callback. (`test_scope_engine.cpp` is unchanged — its existing
  `from_result_set:` cases pass under the relaxed length-bound token validation.)

- `tests/unit/server/test_policy_evaluator.cpp` — 10 cases for the new
  `PolicyEvaluator`: compliant/non_compliant multi-agent fan-out, non-responder
  → `unknown`, plugin-failure → `error`, missing-field → `non_compliant`, CEL
  eval-error → `error`, empty-CEL → `error` (no false compliant), interval
  throttling, remediation fix→verify→compliant, remediation rejected without a
  `fix`, the 3-attempt remediation cap → `error`, and verify-dispatch-failure →
  `error`. Real stores on `TempDbFile`, a static management group for targets, a
  fake dispatch that seeds canned responses, and an injectable clock.
  visualization.** `VIZ_UAT_AGENT_MODE=cedar-vale-app bash
  scripts/start-viz-uat.sh` stands up the fictional "Cedar & Vale" company as
  three named tiers — **Envoy** (frontend) → **node.js** (app) → **Postgres**
  (db) — each co-hosting a `yuzu-agent`, so the stack renders in `/viz/fleet`
  with the presentation tier on top, app in the middle, and db at the bottom,
  joined by two persistent blue connection tubes. The node tier serves an
  8-slide impress.js (Prezi-style) deck on *"Agentic Colleagues: IT's force
  multiplier & thinking partner"*; the slide content lives in Postgres
  (`slides` table, seeded via initdb) and is read live on each request, and
  the deck is reachable at `http://localhost:8088`. The deck is styled in the
  Barony of Alyth livery (French Blue base, polished Metallic Gold + Metallic
  Silver, black depth): metallic-gold headlines with a travelling specular
  sheen, over an enigmatic dark background that is itself a *machine* — a fixed
  Victorian analytical-engine backdrop: a deterministic train of ~17
  interlocking brass/steel gears (constant tooth module so they mesh; centres at
  the pitch distance; meshing neighbours turn opposite directions with
  gear-ratio speeds — `omega·N` constant), murky/dark/blurred behind the slides,
  spread across three clusters to fill the field. Motion is a pure function of a
  single master drive angle (`public/machine.js` generates the train and drives
  it), accelerating briefly on each slide transition ("thinking harder"), atop a
  drifting French-blue nebula and edge vignette. The Barony of Alyth coat of arms,
  recolored to an engraved aged-brass medallion mounted in a riveted cog bezel
  (the ancient arms set in the machine), is fixed in the lower-left so the deck
  is seen flying beneath it during transitions. Each slide is its own steampunk
  brass plate: a distinct background texture per slide (8 ornate brass/clockwork
  panels under a dark scrim, framed in brass with gold/shadow insets) so the
  changing backdrop makes slide-to-slide movement obvious during transitions;
  body text carries a dark halo for legibility over the machinery. Each slide
  also supports an optional **moving** background: drop a `bg<N>.webm` into
  `app/public/` and the server adds a `<video class="slide-video">` for that
  slide (the JPG stays as poster + fallback), with only the active slide's clip
  playing at a time (driven off impress step events in `machine.js`) and no
  autoplay under reduced-motion — so animated steampunk backdrops can be added
  one at a time without code changes. Slides fly in dramatically via a
  big-canvas / z-dolly impress.js journey and a focus-blur snap; `data_scale` is
  `REAL` so mid-deck zooms can be fractional, and all background/entrance motion
  is `prefers-reduced-motion`-guarded. Tiers stack by their
  listener ports (Envoy :8080 → frontend, node :3000 → app, Postgres :5432 →
  db) and the tubes stay lit at idle via Envoy upstream health checks
  (frontend→app) and a pg connection-pool keepalive (app→db). All three tiers
  build on Debian trixie bases so the trixie-built agent's glibc matches.
  Artifacts under `deploy/docker/cedar-vale/`. Complements the lightweight
  `cedar-vale-local` (plain named agents) and macOS-only `cedar-vale`
  (OrbStack VM) modes. DEV/UAT ONLY — `--no-tls`, baked demo credentials.
- **viz-UAT `cedar-vale-local` mode: three named plain agents.**
  `VIZ_UAT_AGENT_MODE=cedar-vale-local` runs three `yuzu-agent` containers with
  hostnames `yuzu-frontend` / `yuzu-app` / `yuzu-db` (no real services), so
  `/viz/fleet` labels three tiers by name without needing OrbStack VMs — the
  Linux/WSL2-friendly cousin of the macOS `cedar-vale` mode.

### Fixed

- **viz-UAT: server config bind-mount must be world-readable (0644, not
  0600).** `start-viz-uat.sh` generated `yuzu-server.cfg` at mode 0600 owned by
  the operator's uid, then bind-mounted it into the server container which runs
  as uid 999 (`yuzu`) — unreadable, so the server fell through to interactive
  first-run setup, read empty stdin, and died on the password floor. The file
  is a PBKDF2-SHA256 hash (no cleartext), so 0644 is correct for a
  containerized launcher.
- **CRITICAL — `POST /login/mfa` was unreachable behind the pre-routing
  auth gate** (Hermes Agent red-team review, 2026-05-29). The exemption
  list at `server.cpp:2393` covered `/login` but not `/login/mfa`, so
  every unauthenticated POST to the MFA challenge was redirected to
  `/login` before the route handler ran — the MFA login flow was
  completely deadlocked in any deployment with the gate enabled. The
  internal governance review missed this because PR1 deferred route-
  level integration tests. Added `/login/mfa` to the exemption list
  with a comment crediting the Hermes finding.
- **HIGH — `/login/mfa` was bypassing the login-specific rate limiter**
  (Hermes Agent LOW #6 escalated by the credential-brute compounding
  effect). `is_login = req.path == "/login"` at `server.cpp:2374` did
  not match `/login/mfa`, so MFA submissions fell through to the looser
  `api_rate_limiter_` bucket. Expanded the predicate to cover both
  paths so per-IP rate-limit defence applies to both legs of credential
  auth. The per-pending-token 5-attempt cap remains as the second layer.
- **MEDIUM — CSRF protection on the five `/api/settings/mfa/*` POST
  routes** (Hermes Agent MEDIUM #2). The mutating MFA settings routes
  (`init`, `verify`, `recovery-codes`, `disable`) relied on session-
  cookie auth (`SameSite=Lax`) without `Origin` / `Referer` checks; a
  stolen cookie could be replayed cross-site to strip a victim's MFA.
  Added an `origin_safe` helper that requires `Origin` (or `Referer`
  fallback) host to match the request `Host` header on browser POSTs;
  non-browser clients (curl, automation) that omit both headers pass
  through. Mismatched host returns 403 with audit verb `csrf.denied`
  (`target_type="Endpoint"`) for SIEM correlation. Audit detail strings
  are sanitised (control + high-bit bytes stripped, each field capped at
  128 B), default ports `:443`/`:80` are normalised so a TLS-terminating
  reverse proxy that rewrites `Host` to the port-less form does not
  false-deny, and userinfo (`@`) plus fragment / query (`?`, `#`) in the
  Origin URL are rejected per RFC 6454.

  **Deferred scope (Gate 4 SHOULD S2 — known follow-up):** `origin_safe`
  is wired into the 4 mutating MFA POSTs only. 11 sibling state-changing
  Settings POSTs remain CSRF-unprotected:
  `/api/settings/users` (and `/role`), `/api/settings/api-tokens`,
  `/api/settings/plugin-signing/{upload,clear,require}`,
  `/api/settings/oidc` (and `/test`), `/api/settings/{cert-upload,
  cert-paste}`, `/api/settings/enrollment-tokens`, `/api/settings/tls`.
  These were unprotected before PR1 too — the asymmetry is documented
  here so it isn't mistaken for a regression. A follow-up PR wraps every
  admin HTMX mutation with the same helper.

### Tests

- **Integration / synthetic-UAT scripts: replace fragile log-grep assertions
  with Prometheus-metric assertions.** Phase 5 of `/test --full` run
  `1779859754-13864` surfaced a single Integration FAIL whose root cause was
  a `cat agent.log | grep -qi "register|session|connect|heartbeat"` assertion
  that silently swallowed an empty-read race (WSL2 drvfs / spdlog flush
  timing) and false-failed even though the agent had registered cleanly. An
  audit found five more sites in the same script — and two siblings in
  `scripts/start-UAT.sh` and `scripts/test/synthetic-uat-tests.sh` — using
  the same anti-pattern (generic-English substring match on volatile log
  content with no retry and no diagnostic for empty reads).
  - `scripts/integration-test.sh`: agent-registration wait loop (line 609),
    "Agent registration in logs" test (was the failing one), "Gateway sees
    agent connections", and "Server gateway-mode operation" now poll
    `yuzu_fleet_agents_healthy` / `yuzu_gw_agents_current` via a new
    `poll_metric_at_least` helper. The gateway error-pattern fallback at the
    one site with no metric substitute is hardened: empty-file → loud FAIL,
    and the grep pattern is tightened to `\\[error\\]|CRASH REPORT|=ERROR REPORT|
    badarg|Supervisor: .* terminating` so the bare word "error" inside an
    info line no longer false-positives. The latent "both branches call
    `pass`" bug in "Server gateway-mode operation" is fixed at the same
    time. Test count grew 21 → 22 because the previously-merged "gateway
    sees agent connections" + "gateway has errors" split into two clean
    assertions.
  - `scripts/start-UAT.sh`: the agent-registration wait switched from
    `grep "Registered with server"` to the same metric poll; the `/readyz`
    JSON check switched from a `grep '"ready"'` substring to a real
    `python3 -c 'json.load(...)'` parse (the old grep would have
    false-positived on responses like `{"status":"degraded",
    "note":"ready_for_disposal"}`). Session-id extraction at line 495 is
    intentionally left alone — it uses a structural regex on a stable line
    format, not generic English, and no metric or REST surface exposes
    `session_id`.
  - `scripts/test/synthetic-uat-tests.sh`: same `/readyz` JSON parse fix.
  - `poll_metric_at_least` is duplicated between `integration-test.sh` and
    `start-UAT.sh` rather than extracted to a shared lib — `start-UAT.sh`
    is operator-runnable in isolation and the helper is ~10 lines; coupling
    the two scripts to a shared file has higher carrying cost than the
    duplication.
  - Out of scope for this commit, filed as follow-up F19 (governance
    Tier-C from the prior round): the MCP / e2e-api / e2e-security
    `assert_contains` cluster and the `grep -c result-row` HTML row count
    in `start-UAT.sh` / `synthetic-uat-tests.sh` — different domain
    (JSON-vs-log), different risk model, separate PR.
  - Verified: all three scripts pass `bash -n`; `bash
    scripts/integration-test.sh` against the live UAT stack reports
    22/22 PASS; the helper passes a four-case behavioural sanity test
    (live PASS, impossible-threshold FAIL, missing-metric FAIL,
    labelled-metric PASS).

### Security

- **NAT-aware per-session peer-IP binding (#1128).** The W1.3 stolen-session
  guard (Subscribe source IP must match Register source IP) false-rejected
  legitimate direct-connect agents behind multi-egress NAT / proxy pools /
  CG-NAT / SD-WAN. Strict exact-match remains the default; two opt-in
  accommodations now downgrade a mismatch to *advisory* (audited
  `result="ok" outcome=advisory`, counted on
  `yuzu_grpc_subscribe_peer_advisory_total{event="security",reason,gateway_mode}`)
  instead of rejecting: (1) both IPs falling inside an operator-declared
  `--trusted-nat-cidr` range (`YUZU_TRUSTED_NAT_CIDR`); or (2) a matching mTLS
  client identity, which is **opt-in** via `--nat-trust-mtls-identity`
  (`YUZU_NAT_TRUST_MTLS_IDENTITY`, default off) and SAFE ONLY WITH PER-AGENT
  CLIENT CERTS — a shared fleet-wide cert would make it a session-replay
  bypass; enabling the flag now emits a `warn`-level startup banner so it is
  not silently lost in a tail-only boot log. Mismatches outside both
  accommodations still hard-reject; an empty extracted IP always rejects.
  Malformed `--trusted-nat-cidr` entries are logged and ignored at startup.
  When both accommodations are configured, mTLS-identity match takes
  precedence (the audit row + metric `reason` label record which fired). The
  advisory audit row and metric now carry a `gateway_mode` field/label
  matching the existing reject path, so SIEM rules can correlate advisory and
  reject volumes by operator-mode dimension.
- **Gateway origin-IP attribution (#1064, server side).** Audit rows on the
  gateway `ProxyRegister` path previously recorded the gateway's IP as the
  source, not the agent's (SOC 2 IR-2 mis-attribution). A new
  transport-agnostic `RegisterRequest.gateway_observed_peer` field (survives the
  planned gRPC→QUIC move) carries the agent origin IP; the server now records
  `source_ip`=agent origin and `gateway_ip`=transport peer (falling back with
  `origin_observed=false` when absent). The direct Register path ignores the
  field (a direct agent cannot forge a source IP; it is not a defence against a
  compromised gateway). **Note for gateway deployments:** until the gateway-side
  population follow-up ships, audit rows on the `ProxyRegister` path still record
  the gateway node's IP as `source_ip` (the field is not yet populated by
  today's grpcbox transport, which cannot observe the direct agent peer; the
  durable source arrives with the QUIC transport, #376). Operators relying on
  `source_ip` for IR-2 attribution on the gateway path should note this.

## [0.12.0] - 2026-05-25

### Breaking Changes

- **Gateway requires `YUZU_GW_COOKIE` before upgrade (#659).** The Erlang gateway
  now refuses to boot with the historical default distribution cookie. `.deb`/
  `.rpm` installs auto-generate a unique cookie into `/etc/yuzu/gateway.env` (via
  systemd `EnvironmentFile`); container and manual deployments **must** set
  `YUZU_GW_COOKIE` (e.g. `openssl rand -hex 32`) before starting, or override for
  dev/CI with `YUZU_GW_ALLOW_DEFAULT_COOKIE=1`. In-place upgrades that provide no
  cookie fail closed on restart. Recovery + per-node-vs-cluster guidance:
  `docs/user-manual/upgrading.md`; full reference: `docs/user-manual/gateway.md`.

### Security

- **TAR warehouse SQL — read-only sandbox + authorizer for operator queries (#760, #631).**
  The agent's `tar.sql` executor no longer relies solely on a keyword blocklist
  over a read-write SQLite handle. Untrusted operator SQL now runs on a dedicated
  **read-only** connection through a new `TarDatabase::execute_user_query`, guarded
  by a SQLite **authorizer** that permits only `SELECT`/`READ` of registry-known
  warehouse tables (plus scalar/aggregate functions) and denies writes, `ATTACH`,
  `PRAGMA`, schema-table reads, and trailing statements at prepare time — so a
  blocklist gap (e.g. `UNION` was never blocklisted) can no longer reach an
  unintended table or any write. Separately, `$table_name` translation now runs
  only **outside** string literals and comments, so the executed query is the same
  one that was validated (#631 — translation previously ran on the un-stripped
  input, diverging from the keyword check). Internal trusted reads are unaffected.
  New unit coverage drives the authorizer, the read-only handle, and the
  literal-translation fix directly. Operators who used `PRAGMA` or `sqlite_master`
  for schema discovery should switch to the `$`-prefixed warehouse table names
  (see `docs/user-manual/tar.md`). Hardens SOC 2 CC6.1 / CC8.1.

- **Gateway — refuse to boot with the default Erlang distribution cookie (#659).**
  `gateway/config/vm.args` is now `vm.args.src`, supplying the cookie from the
  `YUZU_GW_COOKIE` environment variable (e.g. `openssl rand -hex 32`). A boot
  guard (`yuzu_gw_app:check_distribution_cookie/0`) fails closed when the cookie
  is the historical default or empty once distribution is up — a known cookie is
  unauthenticated inter-node RPC / RCE for anyone who can reach EPMD (TCP 4369).
  Local dev/CI may override with `YUZU_GW_ALLOW_DEFAULT_COOKIE=1`; the UAT/CI
  compose stacks set it. `evaluate_cookie/3` is unit-tested. Hardens SOC 2
  CC6.1 / CC6.6.

- **Test tooling — `--run-id` path-traversal & terminal-injection hardening.**
  `scripts/test/test_db.py` and the `coverage`/`perf`/`sanitizer` gate scripts
  now reject an invalid `--run-id` (exit 2): the allowlist is `[A-Za-z0-9._-]`
  with the bare `.`/`..` components rejected explicitly (the regex alone matches
  both), extending the UP-9 path-validation guard. `safe_run_log_dir()` adds a
  `Path.resolve()` containment check so a malformed or legacy run id cannot make
  `--prune` escape the test-runs log root, and `display_run_id()` sanitizes
  control characters so rejection messages cannot echo raw terminal-control
  bytes. Hardens the SOC 2 change-management evidence store (CC7.2 / CC8.1);
  CH-15 / CH-17 in `tests/shell/test_pr2_gates.sh` regression-test it.

- **W1.x — enrollment-token DoS fix + mTLS-mismatch audit (#1067, #1118).**
  Both the direct-connect (`Register`) and gateway-proxy (`ProxyRegister`)
  enrollment paths now reject an admin-**denied** agent *before* consuming its
  enrollment token — previously the consume happened first, so a denied attacker
  could deplete a `max_uses=1` token and lock out the legitimate agent
  (W1.4 UP-M3). The denied rejection emits a
  `yuzu_register_denied_total{source,event="security"}` Prometheus signal
  (replacing the analytics event the early return shadowed). gRPC Subscribe mTLS
  identity-mismatch rejections now emit a
  `session.identity_mismatch` audit row (the mTLS sibling of
  `session.peer_mismatch`) out-of-lock, with a
  `yuzu_grpc_subscribe_identity_mismatch_total{event="security"}` Prometheus
  signal for SIEM routing. SOC 2 CC7.2.

- **W1.x — gRPC peer-IP strict-mode + audit symmetry (#1058, #1059, #1063,
  #1065).** `extract_peer_ip` now strict-validates IPv4/IPv6 peer strings and
  lowercases IPv6 so the Register-vs-Subscribe binding comparison (#826) is
  canonical and cannot be slipped past with a malformed body. gRPC Subscribe
  peer-mismatch rejections emit a `session.peer_mismatch` audit row (stolen-
  session signal, SOC 2 CC7.2). gRPC Register/Subscribe set
  `x-yuzu-audit-failed: true` trailing metadata when an audit row fails to
  persist, mirroring REST's `Sec-Audit-Failed`. The success-path enrollment
  audit is now captured and escalated on drop (symmetric with the denial path)
  on both the direct-agent and gateway-proxy services.

### Changed

- **Governance now requires C++ resource ownership proofs.** Gate 1
  change summaries include a Resource Ledger for C++ diffs, Gate 2
  `security-guardian` enforces RAII/scope-guard ownership at raw
  resource boundaries, and Gate 3 includes dedicated `cpp-expert`
  (language idiom, compiler portability) and `cpp-safety` (lifetime,
  C ABI, cast, thread, process, sanitizer coverage) reviewers.

- **Local release-candidate scratch docs are no longer tracked.**
  `*.local.md` / `*.local.MD` files are ignored so per-run release notes
  and review scratchpads stay local.

- **CI — `CHANGELOG order` check no longer wedges meta PRs.** Removed the
  `paths:` filter from `docs-lint.yml` so the **required** "CHANGELOG order"
  status reports on every PR to `main`/`dev`. Previously the filter meant a PR
  that didn't touch `CHANGELOG.md` (CODEOWNERS, CI, pure-code, etc.) never
  produced the required check and was blocked forever on a status that never
  arrived. The job is a ~5s file-order lint, so running it unconditionally is
  cheap.

- **CI / governance — CLA Assistant activated on `Tr3kkR/Yuzu`.** The
  `.github/workflows/cla.yml` gate is live: external contributors must sign
  the Contributor License Agreement before merge (signatures stored in the
  private `Tr3kkR/Yuzu-cla-signatures` repo; forks of Yuzu skip the gate).
  Protects the AGPL + commercial dual-license chain — unsigned external
  contributions can only ship under AGPL.

- **Governance — `CODEOWNERS` added.** `@fjarvis` is the code owner for the
  auth/identity surface (`auth*`, `rbac_*`, `oidc_*`, `api_token_*`,
  `device_token_*`, `enrollment_*`, `secure_random.*`, `auth.hpp`,
  `docs/auth-architecture.md`); GitHub auto-requests his review on matching
  PRs. Advisory for now — `require_code_owner_review` is off on the dev/main
  rulesets.

- **#1056 — `DeviceTokenValidateError::internal_error` distinguishes a
  store-internal fault from a clean miss.** A `sqlite3_prepare_v2`
  failure in `DeviceTokenStore::validate_token` was previously
  mislabelled `not_found`, polluting the not-found signal and misleading
  forensics. It now maps to a dedicated `internal_error` variant. The
  public wire response is unchanged — it still collapses to the same
  `401`/`UNAUTHENTICATED` as every other variant (no `500` differential
  to probe); only the operator-facing audit detail and the
  `yuzu_device_token_rejected_total{variant=...}` label change.

- **#1057 — `SecureRandomError::PrngFailure` renamed to `prng_failure`.**
  Aligns the enumerator with the snake_case convention used by the
  sibling auth error enums (`DeviceTokenValidateError` et al.). Internal
  symbol only; the audit-emitted `"prng_failure"` reason string was
  already snake_case, so there is no wire or audit-log change.

- **#1060 — `rejection_detail` renamed to
  `rejection_audit_detail_for_storage`.** Names the trust boundary at
  every call site: the returned string carries `bound_device_id` /
  `bound_principal_id` and must be written only to the audit store,
  never echoed onto a public surface. Internal helper only (no runtime
  behavior change).

- **#1088 — `McpServer::DispatchFn` signature gained trailing
  `execution_id` parameter.** Internal ABI on the `McpServer` class
  (header `server/core/src/mcp_server.hpp`). The typedef now matches
  `WorkflowRoutes::CommandDispatchFn` (both 6-parameter with
  `execution_id` last). Only production consumer is `server.cpp`
  (updated). Out-of-tree consumers embedding `McpServer` directly
  must update their dispatch lambdas to accept the new parameter
  (default-empty for callers that don't track executions).

### Added

- **Cedar & Vale demo environment — chiselled server, gateway, and agent images.**
  A repeatable, release-pinned sales-demo stack: `FROM scratch` chiselled Ubuntu
  26.04 images for server, gateway, and agent, a `docker-compose.demo.yml`, and
  `scripts/start-demo.sh` (build-or-pull → start → enroll N agents). Distinct
  from the viz-UAT rig; cannot run alongside it (both bind host 8080/50051). See
  `docs/demo-environment.md`.

- **Multi-arch chisel image publishing + agent-bundle delivery image.** Two new
  release jobs: `docker-publish-chisel` builds `yuzu-{server,gateway,agent}-chisel`
  multi-arch (linux/amd64 + linux/arm64 via QEMU) and `docker-publish-agent-bundle`
  publishes `yuzu-agent-bundle-chisel` — a single image carrying the agent for
  three triplets (`linux-x64`, `windows-x64`, `macos-arm64`) at one pinned
  version, assembled from the release's own signed/notarized artifacts (verified
  by SHA-256), not cross-compiled. Design partners `docker pull` it and copy out
  the right agent per endpoint OS (native installers + raw payload). All images
  are cosign-keyless-signed with SLSA provenance + CycloneDX/SPDX SBOMs.
  `scripts/check-compose-versions.sh` now gates `docker-compose.demo.yml` and
  recognises the `-chisel` repo suffix. Build/usage: `scripts/build-agent-bundle.sh`,
  `docs/agent-bundle.md`, `docs/demo-environment.md`.

- **vuln_scan — Alpine (apk) package enumeration.** `get_installed_apps()`
  enumerates installed packages on Alpine via `apk info -v`, parsing the
  `name-pkgver-rpkgrel` form. Brings Alpine to parity with the existing
  dpkg/rpm enumeration (needed for the chiselled Alpine demo/agent images).

- **#1088 R2 — `GET /api/v1/executions/{id}` final-state endpoint.**
  Companion to `GET /api/v1/events`: when the SSE subscribe returns
  410 (execution already terminal), the agentic worker calls this
  endpoint to fetch final state in one JSON round-trip. Required by
  the W5.1 410 envelope's remediation hint — UAT smoke on the #1088
  PR caught that the hint pointed at a route that didn't exist.
  Requires `Execution:Read`. Response mirrors the `Execution` struct
  field-for-field (id, definition_id, status, scope_expression,
  parameter_values, dispatched_by, dispatched_at, agents counts,
  completed_at, parent_id, rerun_of, last_error_detail). 404 on
  unknown id with A4 envelope; 503 with `retry_after_ms=5000` when
  tracker is unwired. Includes OpenAPI spec entry, X-Correlation-Id
  header, and 5 new test cases covering happy / 404 / 503 / 401 /
  403.

- **#1088 — `execution_id` in dispatch responses (closes W5.1 agentic
  handoff).** The W5.1 agentic-first workflow shipped with a broken
  handoff: dispatch via `POST /api/instructions/{id}/execute` (REST) or
  `execute_instruction` (MCP) returned only `command_id`, but the new
  `GET /api/v1/events` SSE endpoint required `execution_id` with no
  public lookup bridge. Both dispatch responses now include
  `execution_id` alongside `command_id` so an agentic worker can
  dispatch and immediately subscribe to live events without any
  out-of-band ID resolution. The full agentic dispatch-to-observe loop
  is now functional. `command_id` remains for backwards compatibility
  (legacy `query_responses` polling). On the MCP side, `execute_instruction`
  now pre-creates an `ExecutionTracker` row before dispatch — same
  pattern the REST sibling has used since PR 2.5 — and threads the
  `execution_id` through dispatch so the `command_id → execution_id`
  mapping in `AgentServiceImpl` is registered BEFORE any RPC fires
  (closes the same UP2-4 FAST-agent race the REST path already
  protects against). The `McpServer::DispatchFn` typedef gained a
  trailing `const std::string& execution_id` parameter; the
  `DashboardRoutes::DispatchFn` for the legacy `/api/command` UI is
  unaffected. Documentation updated in `docs/user-manual/mcp.md`,
  `docs/user-manual/instructions.md`, and the
  `docs/user-manual/rest-api.md` known-limitations entry on
  `GET /api/v1/events`.

- **W5.1 — `GET /api/v1/events` agentic-first JSON SSE channel.** First
  REST surface that satisfies the A3 (observability) and A4 (error
  envelope) invariants from `docs/agentic-first-principle.md`.
  Authenticated agentic workers (`Execution:Read`) can subscribe to
  per-execution live events as structured JSON envelopes
  `{execution_id, event_id, timestamp_ms, type, payload}` without
  scraping HTMX fragments or maintaining a dashboard session. Reuses
  the same `ExecutionEventBus` as the dashboard
  `/sse/executions/{id}` route — single taxonomy
  (`agent-transition`, `execution-progress`, `execution-completed`)
  plus synthetic `heartbeat`, `replay-gap`, and `events-dropped`
  envelopes that surface bus-side ring-buffer eviction and
  per-connection queue overflow rather than silently losing events.
  Replay via `Last-Event-ID` header OR `?since=<id>` query (query
  wins, bad input degrades to 0). Every 4xx/5xx response returns the
  new A4 envelope shape `{error:{code, message, correlation_id,
  retry_after_ms?, remediation?}, meta:{api_version:"v1"}}` plus an
  `X-Correlation-Id` header. The contract is testable in isolation
  via `server/core/src/rest_a4_envelope.hpp` so future MCP / discovery
  surfaces can reuse the same envelope helpers. Audit verb
  `api.v1.events.subscribe` is separate from
  `execution.live_subscribe` so SIEM filters can distinguish
  browser-tier vs agentic-worker consumers; the `Sec-Audit-Failed:
  true` response header surfaces audit-persistence failure per the
  PR #883 CC6.6 contract. Endpoint-scoped Prometheus metrics:
  `yuzu_server_sse_api_subscriptions_total{route="events"}`,
  `yuzu_server_sse_api_active{route="events"}`,
  `yuzu_server_sse_api_queue_overflow_total{route="events"}`,
  `yuzu_server_sse_api_replay_gap_total{route="events"}`. New OpenAPI
  schemas `ExecutionSseEvent` + `A4ErrorEnvelope` and a discovery
  row at `/api/v1/openapi.json`. Sprint W5.2 follows with multi-
  execution filter syntax and `Accept: application/json` content
  negotiation on `/fragments/executions`. **Multi-execution
  subscription, per-principal connection caps, the bus-level replay-
  before-subscribe race fix, and the MCP `execute_instruction`
  `execution_id` response field are tracked as follow-up issues.**

### Security

- **Defense-in-depth — plugin shell-interpolation hardening (CodeQL
  cleanup).** Two belt-and-braces fixes surfaced while triaging the
  `cpp/yuzu/plugin-command-exec-non-literal` CodeQL alerts (all 21 of
  which were confirmed false-positives and dismissed). `users` plugin:
  the Linux `local_users` action interpolated a username read from
  `/etc/passwd` into `lastlog -u {user}` without validation — now gated
  by the same `is_safe_identifier()` allowlist the macOS `dscl` paths
  already use; usernames outside `[A-Za-z0-9._-]` (e.g. AD machine
  accounts ending in `$`) report `last_logon=unknown` rather than
  running the shell-out. `certificates` plugin: `is_safe_path()` now
  also rejects space, `<`, and `>`. Neither path is operator-reachable
  (inputs come from `/etc/passwd` / `directory_iterator` over
  `/etc/ssl/certs`), so there is no functional regression on
  well-formed systems. Also excludes the pure-style
  `cpp/poorly-documented-function` CodeQL query (no security signal)
  via `query-filters`.

- **HIGH (#1073 / W7.4 sibling-gap): InstructionDefinition import
  signature enforcement is now on-by-default.** `InstructionStore`
  previously accepted unsigned YAML imports via
  `POST /api/instructions/import` without verification, leaving an
  equivalent fleet-RCE surface to the #802 product-pack gap: an
  operator with `InstructionDefinition:Write` could import a
  definition carrying an arbitrary plugin invocation that dispatched
  fleet-wide. The default is now `require_signed_definitions = true`;
  unsigned imports are rejected with `instruction-import is unsigned
  and signature enforcement is enabled (set
  --allow-unsigned-definitions / YUZU_ALLOW_UNSIGNED_DEFINITIONS=1
  to bypass)`. Operators with legacy unsigned import workflows must
  explicitly opt out via the new `--allow-unsigned-definitions` flag /
  `YUZU_ALLOW_UNSIGNED_DEFINITIONS=1` env var, which emits a startup
  `spdlog::warn` and a `server.unsigned_definitions_allowed` audit row.
  Wire format mirrors ProductPack: optional top-level `signature` +
  `publicKey` (hex) fields, signed content is the `yaml_source` field's
  bytes verbatim. The bundled-content boot seed bypasses the gate via
  the internal `import_definition_json_trusted` variant
  (authenticated by build-time binary linkage, not runtime signature).
  R1 hardening additionally adds: (a) hex-length validation BEFORE
  crypto allocation (Ed25519 signature = 128 hex chars, publicKey =
  64 hex chars — oversized fields rejected before `verify_signature`,
  closing a DoS amplification path); (b) wrong-JSON-type detection
  (`{"signature": 42}` now returns a typed 400 rather than silently
  falling into the "unsigned" branch); (c) audit coverage on EVERY
  rejection branch with `Sec-Audit-Failed: true` header + the
  `audit_emitted=false` JSON envelope field on audit-write failure
  (PR #883 SOC 2 CC7.2 evidence-chain pattern); (d) audit-row
  `target_type` normalised to PascalCase `InstructionDefinition`
  matching ProductPack's W7.4 R2 convention; (e) error-string wording
  unified with ProductPack ("content may have been tampered with").
  **This is a breaking change** — see `### Upgrade notes` below.
  Closes #1073.

- **CRITICAL (#802 / W7.4): product pack signature enforcement is now
  on-by-default.** `ProductPackStore` previously defaulted
  `require_signed_packs_` to `false`, AND the setter that would have
  enabled it was never called from anywhere in production — the flag
  was effectively unreachable. Any operator with pack-upload permission,
  or a MITM on pack delivery, could install an unsigned `ProductPack`
  containing arbitrary `InstructionDefinition` or plugin payloads that
  executed fleet-wide. The default is now `true`; unsigned packs are
  rejected at install with the error `pack '<name>' is unsigned and
  require_signed_packs is enabled`. Operators with legacy unsigned packs
  must explicitly opt out via the new `--allow-unsigned-packs` flag
  / `YUZU_ALLOW_UNSIGNED_PACKS=1` env var, which emits a startup
  `spdlog::warn` and a `server.unsigned_packs_allowed` audit row so the
  relaxed posture is recoverable from both operator logs and the audit
  store. **This is a breaking change** — see `### Upgrade notes` below.
  Closes #802.

- **HIGH-2 (PR #883 governance review): session-revocation REST surface
  now reports audit-emission outcome on the response so a silent audit
  persistence failure (locked audit DB, disk full, pipeline exception)
  cannot masquerade as 200 OK SOC 2 CC6.6 evidence.** The `AuditFn`
  callback (`std::function<…>` in `rest_api_v1.hpp`) and the underlying
  `AuditStore::log` primitive now return `bool` rather than `void`; the
  bool propagates through `AuthRoutes::audit_log` and `Server::audit_log`.
  Existing call sites that fire-and-forget continue to compile — the
  bool is just discarded. The two session-revocation handlers
  (`DELETE /api/v1/sessions` and `DELETE /api/v1/sessions/me`) now wrap
  `audit_fn` in try/catch and surface failure via:
  - `Sec-Audit-Failed: true` response header (out-of-band signal for
    SREs scraping responses or evidence integrity dashboards).
  - `audit_emitted: false` field in the success-body JSON envelope.
  The revoke side-effect still completes when audit emission fails —
  operator's "stop NOW" intent takes precedence over evidence
  integrity, and the partial-success signal lets the operator decide
  whether to retry. Closes the silent-failure gap flagged in the PR
  #883 governance review.
- **HIGH-1 (PR #883 governance review): `ApiTokenStore::validate_token`
  cache write now skipped when a revoke races our DB SELECT.** Added a
  `revoke_generation_` atomic counter bumped by `revoke_token`,
  `revoke_for_principal`, and `delete_token` before each UPDATE/DELETE.
  `validate_token` snapshots the generation before its SELECT and
  re-reads before the cache write — if it moved, we lost the race and
  do not populate the cache with the now-stale (revoked=false) view
  that would otherwise survive for up to 60 s (the
  `kTokenCacheTtl`). Belt-and-suspenders: the existing `db_mtx_`
  exclusive lock already spans SELECT through cache write and prevents
  the interleave, but the explicit generation re-check survives any
  future refactor that narrows the lock scope.

### Added

- **Per-host IPC-graph drill-down (`/viz/host/<agent_id>`).** Double-clicking
  a cube in `/viz/fleet` opens a new tab with a 2D bipartite IPC graph
  (processes + sockets, Cytoscape `cose` layout) above the existing TAR
  process tree, with cross-pane select-to-highlight and a resizable
  splitter. New REST routes `GET /api/v1/viz/host/<agent_id>/topology`
  and `GET /fragments/viz/host/<agent_id>/topology` return a
  `host_topology.v1` envelope (one `MachineNode` sliced from the fleet
  snapshot); both require `Response:Read` and honour the `--viz-disable`
  kill switch. The `/viz/host/<id>` page route is auth-gated and
  allow-lists the `agent_id` (`[A-Za-z0-9._-]`) before templating.
  Vendored Cytoscape.js 3.33.3 (MIT).
- **`tar.fleet_snapshot` connection window.** `fleet_snapshot` now merges
  connections seen recently from the `tcp_live` warehouse, not only those
  ESTABLISHED at the exact `/proc` sample instant, so short-lived flows
  reach the viz. New operator-tunable `fleet_snapshot_window_seconds`
  (default `3600`). `fleet_snapshot.v1` `schema_minor` bumps `1 → 2`
  (additive `connections[].last_seen_seconds_ago`, emitted only when
  non-zero).
- **`/viz/fleet` three-tier layout + talking-socket layer + curved tube
  wires (PR 12 of the 11-PR `/viz/fleet` 3D fleet network-topology
  ladder).** Machines now organise into three architectural Y planes:
  frontends on top, applications in the middle, databases on the
  bottom. Classification is a heuristic over listener ports (a
  curated `DB_PORTS` / `WEB_PORTS` set) and the agent's process
  category, priority `db > web > app`; tier placement is a visual
  cue only and carries no authorisation weight. **`ListenerSocket`
  grows an optional `local_addr` field** (`schema_minor` bumps
  `3 → 4`) carrying the kernel-reported bind address; the renderer
  reads it to drop loopback-only listeners (`127.0.0.0/8`, `::1`,
  including bracketed and v4-mapped-in-v6 `[::ffff:127.x]` forms)
  from the cube-surface socket ring — they're not reachable from
  other instances. **Talking-socket primitive:** each cube grows a
  ring of cool-blue dots on its BOTTOM face, one per unique
  outbound `(proto, dst_ip, dst_port)`; hover surfaces
  `talking: tcp → ip:port`. **Cross-machine wires render as
  `THREE.TubeGeometry` along a `THREE.CubicBezierCurve3` with
  vertical end-tangents** so the wire exits the source cube floor
  going straight down, runs nearly-straight through free space,
  and re-enters the destination cube ceiling going straight up
  into the listener sphere — `LineBasicMaterial.linewidth` is
  silently clamped to 1px on every shipping browser, so the
  switch to tubes is what makes the wires visible at typical
  zoom. Parallel wires fan opposite sides via a deterministic
  hash on `(srcAgentId, dst_ip:dst_port)` so two cubes both
  talking to the same destination don't trace the same arc.
  Per-field size cap of 64 bytes applies to `local_addr` and
  `remote_addr` at the parser to bound the wire payload
  regardless of agent behaviour. Test-pinned JS bundle ceiling
  raised 80 KB → 96 KB to fit the new primitives.

- **Session revocation REST surface (SOC 2 CC6.3 revocation, CC6.7
  disposition, CC6.8 termination evidence).**
  - `DELETE /api/v1/sessions?username=<name>` — admin force-logout via
    `UserManagement:Write`. Wipes cookie sessions only; API tokens are
    deliberately left intact (operator may be revoking a leaked cookie
    while leaving CI/CD automation running). `username` is validated
    via `is_valid_username` so NUL bytes / control characters / newlines
    cannot truncate the SQL bind in a way that diverges from the
    in-memory `==` compare and silently mis-targets revocation.
  - `DELETE /api/v1/sessions/me` — authenticated self-revoke "Sign out
    everywhere". Wipes cookie sessions AND revokes every API token
    belonging to the caller, so a stolen-laptop scenario kills every
    credential bearing the user's identity in one call. Sets
    `Set-Cookie: yuzu_session=; Max-Age=0` on the response so the
    client side completes the disposition. Rejected with 403 for
    MCP-tier and service-scoped tokens — those credential classes have
    no other write privilege and accepting them here would create a
    novel DoS surface against the human owner.
  - `AuthManager::invalidate_user_sessions` is now public, returns a
    `RevokeResult { count, db_persisted }`, and performs the dual-write
    explicitly. The in-memory wipe runs even on AuthDB DELETE failure
    (the operator's "stop NOW" mental model demands the active session
    die immediately), but `db_persisted=false` propagates up so the
    REST handler audits with `result="partial"` and `detail` includes
    `db_error=true`. A SOC 2 auditor reading the audit log can
    distinguish a confirmed durable revocation from a partial one
    awaiting retry/restart. Defence-in-depth: the AuthDB primitive
    `invalidate_all_sessions` itself now validates username (sibling
    primitives `add_user`, `update_role` already did).
  - `ApiTokenStore::revoke_for_principal` — new public method,
    transactionally marks every non-revoked token for a principal as
    revoked and invalidates the in-memory validate-token cache so the
    revocation takes effect within the next request, not after the
    60-second TTL.
  - Two distinct audit actions: `session.revoke_all` (admin cross-user)
    and `session.revoke_all.self` (self via either route, including
    admin self-target through the admin path; recoverable by re-auth,
    distinguishable in SIEM). Audit `target_type` is the project-wide
    PascalCase `User`. `result` is one of `success`/`partial`/`denied`.
  - New Prometheus counter
    `yuzu_auth_sessions_revoked_total{caller, result, scope}` — CC7.2
    anomaly-detection signal for "100 revokes/minute" patterns.
  - Settings → Users grows "Revoke sessions" (`btn-danger`) per non-self
    row and "Sign out everywhere" on the operator's own row, with
    `hx-confirm` blast-radius messaging that explicitly states whether
    API tokens are revoked. The admin button uses
    `hx-target="#user-section" hx-swap="innerHTML"` so the section
    re-renders cleanly after a revoke (without it, HTMX swapped the
    raw JSON into the button itself).
  - Operator runbook in `docs/user-manual/server-admin.md` ("Force-
    logging out a user (incident response)") and emergency manual-
    revocation recipe in `docs/ops-runbooks/auth-db-recovery.md`.
  - 16 unit tests in `tests/unit/server/test_rest_sessions.cpp` and 3
    direct AuthManager tests in `tests/unit/server/test_auth.cpp`
    pinning the REST contract, the dual-write semantics, the
    multi-token wipe, and idempotency.

  Self-target through the admin path is permitted (recoverable by
  re-auth) and audited as `.self`; this is a deliberately weaker
  guard than the `#397/#403` self-target guard on DELETE-user /
  role-demote, which exists to prevent admin-role self-lockout (an
  unrecoverable state).

### Changed

- **`/viz/fleet` `WEB_PORTS` trimmed** — dev-server ports (3000 etc.) no
  longer score as "web", so a node app classifies application-tier not
  frontend.
- **`/static/yuzu-viz.js` cache posture** flipped to
  `no-cache, no-store, must-revalidate` (was `max-age=86400`) — the
  renderer bundle changes every viz PR and a `max-age` silently served a
  stale renderer after a server upgrade.
- **`/viz/fleet` cube layout** moved from a single flat grid to a
  three-tier stacked layout (PR 12). Operators with bookmarked URLs
  will land on the new camera framing `(45, 60, 45)` looking at the
  middle tier (was `(35, 30, 35)` looking at origin).
- **`/api/v1/viz/fleet/topology` `schema_minor`** bumped `3 → 4`
  (additive — strict consumers pinned to `== 3` should relax to
  `>= 3`).

### Fixed

- **Agent interval triggers now fire.** `yuzu_register_trigger` /
  `yuzu_unregister_trigger` were no-op stubs — no `TriggerEngine` was
  instantiated, so `collect_fast` / `collect_slow` / `rollup` never ran
  for any plugin. The TAR warehouse `*_live` tables sat permanently empty
  in the field. The agent now owns a `TriggerEngine`, wires it into the
  plugin context before plugin init, and starts it after plugins load.
  See the upgrade note below.
- **Gateway replays agent registrations on upstream reconnect.** After an
  upstream connection drop, the gateway reconnected the transport but
  never re-proxied the agent registrations it still held, leaving a
  freshly-restarted server with an empty registry. The gateway now
  drip-replays a `ProxyRegister` per held agent on upstream recovery.
- **34 InstructionDefinitions now pass on macOS.** `procfetch` gained a
  libproc/OpenSSL macOS branch, the instructions test runner gained
  host-aware parameter synthesis and platform-aware skip (definitions
  with a `platforms:` list now emit `skip` on a non-matching host
  instead of a spurious `FAIL`).
- **Mixed-fleet split-brain in `/viz/fleet` (governance Gate 7 UP-9).**
  Once any agent pushed a snapshot, the topology was built solely from
  the pushed map and the dispatch fallback was skipped — so any
  registered agent that had *not* pushed (a pre-`tar.fleet_snapshot`
  build mid rolling-upgrade, the TAR plugin disabled, a pump wedged on
  its first cycle) silently vanished from the visualization. The store
  now emits a `stale=true` placeholder cube for every
  registered-but-unpushed agent.
- **Gateway registration-replay storm (governance Gate 7 UP-5).** An
  in-flight replay drip was restarted from scratch on every redundant
  `replay_registrations` trigger, so under packet-loss flapping the
  gateway re-proxied the whole fleet repeatedly and, at scale, never
  drained. Redundant triggers while a drip is running are now dropped;
  each outage event arms at most one full replay that runs to
  completion.

### Security

- **Gateway peer-mismatch enforcement (Sprint 1 W1.3 — closes #826).**
  Plus rejection-collapse + enriched-error-payload **infrastructure**
  for #1052 / #1053 — those issues remain OPEN; W1.4 will be the first
  consumer to exercise the new helpers and the audit/counter signals.
  - **#826 (P1 security).** `AgentServiceImpl::Subscribe` no longer skips
    peer validation when `--gateway-mode` is set. The blanket skip
    enabled session-id hijacking — an attacker on the gateway network
    segment could intercept a Register response, lift the plaintext
    `session_id` (non-mTLS deployment), and open Subscribe from an
    arbitrary IP. The new rule: Subscribe peer IP must match the
    Register peer IP, OR (under `--gateway-mode`) be a previously
    recorded trusted gateway IP. Trusted gateways are noted at
    `GatewayUpstreamServiceImpl::ProxyRegister` time **only on a
    successful enrollment branch** (round-2 hardening); the set is in-
    memory with 1h TTL + 1024-entry LRU cap + new
    `yuzu_trusted_gateway_peer_set_size` gauge. A new helper
    `extract_peer_ip` (now in `peer_ip.hpp`) normalises the gRPC peer
    encoding (`ipv4:1.2.3.4:5678`, `ipv6:[::1]:443`, `unix:/...`) so
    port-rotation between Register and Subscribe RPCs doesn't trigger
    spurious mismatches. New counter
    `yuzu_grpc_subscribe_peer_mismatch_total{gateway_mode}` lets SRE
    distinguish "agent reconnected from a new IP" (steady state) from
    "stolen session_id" (active attack). **Layered defence note:** an
    attacker who sits inside the gateway's IP space (sidecar container,
    compromised host on the same node) AND has a sniffed `session_id`
    still passes. W1.4 (atomic enrollment + session-token binding,
    #827) is the layer that closes that. Don't claim "session theft
    mitigated" from this PR alone.
  - **#1053 infrastructure (W1.4 prereq, NOT closed by W1.3).**
    `DeviceTokenStore::validate_token` now returns
    `std::expected<DeviceAuthToken, RejectedToken>` (was the bare
    enum). The new `RejectedToken` struct carries typed `error` plus
    `token_id`, `bound_device_id`, and `bound_principal_id` so the
    eventual W1.4 handler can emit a complete audit row WITHOUT a
    second SELECT (which would add latency and create a timing oracle
    distinguishing `binding_mismatch` from `not_found`). The type
    signature is now W1.4's hard predecessor — the compiler refuses to
    let the handler skip the rich-context path. **No production
    consumer exists in this PR.** Per-variant population rules in the
    `RejectedToken` docstring; `unbound_legacy` explicitly leaves
    `bound_device_id` empty because the row has no binding by
    construction.
  - **#1052 infrastructure (W1.4 prereq, NOT closed by W1.3).**
    New `device_token_rejection.hpp` defines the wire-collapse
    contract in one reviewable place: `make_public_rejection()` and
    `make_grpc_rejection_status()` return the SAME 401 /
    `UNAUTHENTICATED` envelope across every rejection variant. The
    typed variant surfaces only in `rejection_detail()` (audit-row
    `detail` field) and `rejection_metric_name()` (Prometheus counter
    name). **No production code calls these helpers in this PR**
    (`validate_token` has no caller yet). Unit tests pin the byte-
    identical envelope contract; latency-band parity (the third leg
    of the #1052 acceptance criterion) is an integration-test follow-
    up. W1.4 must wire the first consumer and verify the integration-
    level latency assertion before #1052 closes.
  - **Operator counters (DESCRIBED, not yet incremented).** Three
    high-signal device-token counter names are reserved by
    `metrics_.describe(...)` in `server.cpp` for W1.4 to start
    incrementing: `yuzu_device_token_binding_mismatch_total`
    (stolen-token impersonation in progress),
    `yuzu_device_token_unbound_legacy_total` (rotate the legacy
    any-device token), and `yuzu_device_token_revoked_attempt_total`
    (replay attempt). Plus a low-signal bucket
    `yuzu_device_token_rejected_total{variant=...}`. These will
    return 0 from `/metrics` until W1.4 wires the consumer.
- **Fleet-topology push-ingestion hardening (governance Gate 7).**
  Round of fixes to `FleetTopologyStore` push ingestion:
  - **Parser field caps (UP-1 / sec-M1).** `processes[].name`,
    `.cmdline`, `.user`, `hostname`, and the connection meta strings
    are now length-clamped at parse time (previously only the address
    fields were), so a single oversize row can no longer balloon the
    in-memory map or every `/viz/fleet/topology` response.
  - **IP-claim reclaim window (UP-3).** The IP-spoof guard is still
    first-claim-wins, but a claim whose owner has not pushed within
    five minutes is now reclaimable — an agent that crashed without a
    clean deregister no longer strands its `local_ips` forever, so a
    re-imaged host re-enrolling on the same DHCP lease is not rejected
    indefinitely.
  - **CAP-1 LRU victim by server clock (UP-4).** Cap-eviction victim
    selection now keys on the server-stamped receipt time, not the
    agent-controlled `ts`, so a hostile agent can no longer choose
    which legitimate agent gets evicted by lying about its emit time.
    Cap evictions now also emit a `topology.push.evicted_for_cap`
    audit event.
  - **Push-staleness by server clock (UP-14).** The stuck-pump
    staleness gate keys on server receipt time, so a clock-skewed
    agent cannot render itself permanently fresh.
  - **Batch-heartbeat isolation (UP-10).** A single malformed entry in
    a gateway `BatchHeartbeat` (or an exception out of the direct
    `Heartbeat` ingest) is now caught per-entry and can no longer
    abort the whole batch.
  - **Kill-switch hardening.** `--viz-disable` now also 503s the
    `/viz/fleet` and `/viz/host/<id>` page shells (previously only the
    REST/fragment endpoints), and emits a durable `server.viz_disabled`
    audit event at startup so the disabled state is provable from the
    audit store, not just process logs.

### Upgrade notes

- **BREAKING — unsigned product packs no longer install by default
  (#802 / W7.4).** Operators with unsigned packs in their environment
  will see `install` calls fail after upgrade with `pack '<name>' is
  unsigned and require_signed_packs is enabled`. Two recommended
  migration paths:
  1. **Sign the packs** (preferred) — generate an Ed25519 keypair, sign
     each pack's content with the private key, and add `signature:` +
     `publicKey:` fields to each pack's `ProductPack` document. Pack
     install then routes through the existing verify path and succeeds.
  2. **Opt out temporarily** — set `--allow-unsigned-packs` /
     `YUZU_ALLOW_UNSIGNED_PACKS=1` to restore the pre-upgrade behaviour.
     A startup `spdlog::warn` and a `server.unsigned_packs_allowed`
     audit row will be emitted on every server start so the relaxed
     posture is loud in both operator logs and the audit store.
     Remove the flag as soon as the pack-signing migration completes.

  Pre-existing installed packs are unaffected — the check fires only on
  `install_pack` (new installs / upgrades). Pack list/get/uninstall
  paths do not re-verify.

- **Interval triggers were previously non-functional.** After upgrading
  the agent daemon, registered interval triggers begin firing for the
  first time. Operators should expect the TAR `*_live` warehouse tables
  to start populating (on the first `collect_fast` cycle, default 60 s)
  and may see a small increase in per-agent CPU/IO. Any plugin that
  registered an interval trigger expecting the old no-op behaviour will
  now have that trigger fire.
- **Gateway registry ETS row and upstream state record changed shape.**
  A hot upgrade from a pre-change gateway build is not supported (no
  `code_change/3`); the documented gateway deploy path — container
  replacement — is unaffected.
- **Rolling agent upgrades and `/viz/fleet`.** During a rolling agent
  upgrade, agents on a build older than the `tar.fleet_snapshot` action
  (the push-ingestion source) appear in `/viz/fleet` as dimmed `stale`
  cubes until their agent is upgraded — they have no topology to push
  yet. This is expected, not a regression; the cubes populate fully once
  the agent is current.

### Removed

- **Origin RGB `AxesHelper`** from the `/viz/fleet` empty-scene
  scaffold (PR 12). The three-tier Y planes replace it as the
  spatial orientation cue; the gizmo was clipping through the
  bottom tier.

- **`/viz/fleet` cross-machine edges + socket-layer primitive (PR 9 of
  the 11-PR `/viz/fleet` 3D fleet network-topology ladder).** Each
  machine cube now displays a ring of cream-coloured socket spheres on
  its top face, one per listening port (e.g. `:80`, `:3000`, `:5432`),
  with a `:port` label sprite floating just above each sphere. Hover
  surfaces port + proto + owning pid + process name. ESTABLISHED
  outbound connections render as cool-blue `THREE.Line` edges from the
  source cube anchored at the destination's matching socket sphere on
  the peer cube — operators see "frontend → app:3000" as a line that
  literally lands on `:3000`. External destinations (off-fleet
  endpoints like the agent control channel) get a short grey stub line
  ending in a small ring marker; hover reveals the off-cluster
  `ip:port`. Hover order is sockets → processes → edges → cubes.
- **Push-based fleet topology ingestion (PR 10).** Agents now push
  their `tar.fleet_snapshot.v1` JSON every ~30 s via a new
  `HeartbeatRequest.fleet_snapshot_json` proto field (field 4,
  additive). Server-side `FleetTopologyStore::push_snapshot` ingests
  into a per-agent `pushed_` map keyed by session-authenticated
  agent_id; `/api/v1/viz/fleet/topology` reads from this map.
  Cache-miss latency drops from ~800 ms (full agent dispatch fan-out)
  to ~2 ms (in-process map walk). Pull-based dispatch is retained as a
  cold-start fallback. New metrics
  `yuzu_viz_topology_pushed_total{via=direct|gateway}` and
  `yuzu_viz_topology_push_parse_errors_total{via=direct|gateway}`
  count accepted and rejected pushes; new audit events
  `topology.push.first` (first push per agent per process lifetime —
  CC6.1/CC7.3 evidence) and `topology.push.rejected` (parse failure
  or IP-spoof guard).
- **`MachineNode.listeners[]` field (schema_minor `2 → 3`).** Each
  entry is a `ListenerSocket` (`proto`, `port`, optional `pid`,
  optional `process_name`). Server-side `build_snapshot()` lifts
  LISTEN-state rows from the agent's `connections[]` into this typed
  array. LISTEN rows continue to appear in `connections[]` during the
  deprecation window (see **Deprecated** below).
- **`/viz/fleet` intra-cube localhost edges (PR 8 of the 11-PR
  `/viz/fleet` 3D fleet network-topology ladder).** Faint white
  `LineSegments` (opacity `0.3`) now connect process dots inside each
  machine cube when two processes are reciprocal ends of a loopback
  TCP socket (127.0.0.1 ↔ 127.0.0.1 or ::1 ↔ ::1). The visible flow:
  Prometheus scraping node_exporter inside the same host renders as
  one line between the two dots and refreshes on each topology poll.
  Server-side `build_snapshot()` pairs reciprocal halves by exact
  4-tuple swap and writes the peer's `src_pid` into a new
  `ConnectionEdge.dst_pid` field; unmatched halves are dropped before
  serialisation. JSON `schema_minor` bumps `1 → 2` to advertise the
  additive `dst_pid` field (mirrors the `dst_agent_id`-when-non-empty
  pattern). Renderer builds a per-cube `pidToPos` Map and adds one
  `THREE.LineSegments(BufferGeometry, LineBasicMaterial({color:0xffffff,
  transparent:true, opacity:0.3}))` per paired Local edge into the
  per-cube `processGroup` — disposal is free via `clearFleet`'s
  existing `traverse(disposeNode)` walk. `Number.isFinite` guards on
  both pid endpoints before `Map.get` so a malformed agent payload
  cannot crash the render loop.

### Changed

- **`/api/v1/viz/fleet/topology` envelope `schema_minor` bumped `2 → 3`.**
  PR 9 additive evolution — adds per-`MachineNode` `listeners[]` array.
- **Hostname labels in the 3D viz render below cubes** (was above; UAT
  request 2026-05-12) so the cube top face is unoccluded for the new
  socket-sphere ring.
- **`/api/v1/viz/fleet/topology` cache-miss latency reduced ~800 ms →
  ~2 ms** under PR 10's push ingestion; steady-state stale-flicker
  eliminated.
- **`HeartbeatRequest` gained proto field 4 (`bytes fleet_snapshot_json`,
  additive).** Recommended upgrade order: server → gateway → agents.
- **`/api/v1/viz/fleet/topology` envelope `schema_minor` bumped `1 → 2`.**
  Additive evolution per the existing contract — renderers MUST ignore
  unknown keys, so consumers ignoring `schema_minor` see no break.
  Strict-validating consumers pinned to `schema_minor: 1` exactly
  should relax their validator to `minimum: 1` rather than exact-match.
  Wire change: new optional `dst_pid` (uint32) on `EdgeScope::Local`
  connection edges; non-Local edges and edges with no resolved peer
  omit the field.
- **`/api/v1/viz/fleet/topology` no longer emits unmatched `local`-scope
  connection edges.** Loopback edges where the reciprocal half is not
  visible in the same agent snapshot (race during teardown, agent's
  4096-connection cap cuts the partner, kernel-namespace asymmetry) are
  now dropped server-side before serialisation. **Integrations counting
  `connections` array length per machine as a proxy for "active IPC
  pairs" should re-baseline after upgrade** — the count will trend lower
  by the unmatched-half count, which is typically small but non-zero.

### Deprecated

- **`connections[]` entries with `state: "LISTEN"`** are now duplicated
  in the new `listeners[]` array (PR 9). For one release
  `connections[]` continues to emit LISTEN rows alongside the new
  array so consumers filtering `connections` by `state: LISTEN` are
  not broken silently. A future release will remove LISTEN entries
  from `connections[]` with a **Breaking** CHANGELOG entry; migrate
  strict consumers to read `listeners[]` now.

### Build / Dev infrastructure

- **viz-UAT compose: per-service `NO_PROXY=*` to bypass OrbStack's
  gRPC-incompatible HTTP proxy.** OrbStack injects
  `HTTP_PROXY=http://proxyproxy.orb.internal:8305` into containers; gRPC's
  HTTP/2 client honours it and 502s on cross-container traffic
  (`gateway↔server` upstream and `agent→gateway` registration). The
  fix is scoped to `deploy/docker/docker-compose.viz-uat.yml` only;
  production compose files are untouched.
- **viz-UAT: gateway port `50051` exposed to host.** Lets a `yuzu-agent`
  running *outside* the compose stack (OrbStack VM, bare metal, host
  process) register through the dev gateway. The in-container agent
  still reaches the gateway via the internal `gateway` service hostname
  and doesn't need this binding.
- **`scripts/start-viz-uat.sh` adds `VIZ_UAT_AGENT_MODE` switch.** Modes:
  `container` (default, prior behaviour, in-container agent under the
  new `in-container-agent` compose profile); `vm` (skip the in-container
  agent, print the enrollment token + host-exposed gateway address for
  running a native `yuzu-agent` on an external host — enables PR 8+
  visual demos against real loopback workloads); `none` (skip agent
  startup entirely, useful for empty-fleet renderer iteration).

### Added

- **`/viz/fleet` interior process nodes coloured by category (PR 7 of the
  11-PR `/viz/fleet` 3D fleet network-topology ladder).** Each fleet machine
  cube now contains one `SphereGeometry` dot per process reported by
  `tar.fleet_snapshot`, coloured from a fixed six-colour palette:
  system `#6e7681`, browser `#58a6ff`, database `#d29922`, web `#56d364`,
  runtime `#bc8cff`, other `#8b949e`. Categories are computed server-side
  by `classify(process_name, user)` in `process_category.hpp`; the renderer
  treats unknown / mixed-case / prototype-key inputs (`constructor`,
  `__proto__`, `"DATABASE "`) as `other` via `String(...).trim().toLowerCase()`
  + `Object.prototype.hasOwnProperty.call(palette, k)`. Dot positions are
  deterministic across reloads — `hash(pid|ppid)`-mod-bucket inside 78% of
  the cube's interior volume, jittered to break stripes. Hovering a dot
  surfaces a tooltip with pid, name, user, and category; agent-controlled
  string fields are HTML-escaped and clamped to 256 chars before escape to
  bound the worst-case CPU cost on pathological 1MB names. Process dots
  raycast *before* cube meshes so the operator can drill into a dot through
  the translucent cube face. Per-machine `processGroup` is attached as a
  child of each cube (architectural pick over a single sibling group to
  keep PR 8 per-cube edges + PR 11 per-cube LOD trivial) and `clearFleet`'s
  existing recursive `traverse(disposeNode)` walk releases all per-instance
  geometry+material on every refresh. `mousemove` raycasts are
  rAF-throttled (~60 Hz cap) and processes-per-cube are soft-capped at
  1000 for graceful degradation on heavily-threaded hosts (the cube
  tooltip's process-count still reports the true total reported by the
  agent). PR 11 polish migrates the per-process Mesh pattern to
  `InstancedMesh` for the 100k-machine ceiling.
- **`/viz/fleet` cube renderer + Sprite labels + hover tooltip (PR 6 of
  the 11-PR `/viz/fleet` 3D fleet network-topology ladder).** The fleet
  page now renders one translucent cube per fleet machine on a deterministic
  grid (FNV-1a 32-bit hash of `agent_id` for stable cross-reload layout).
  Per-OS palette: Linux `#f0c674`, macOS `#a0a0a0`, Windows `#5294e2`,
  default `#666666`. Live agents render at opacity `0.18`; stale agents
  (no `tar.fleet_snapshot` response within the 5 s deadline) drop to
  `0.08` so they remain visible without competing for visual attention.
  Hostname `Sprite` labels appear above each cube and always face the
  camera (truncated at 24 chars; full hostname visible in tooltip).
  Hovering a cube surfaces a fixed-position tooltip via `THREE.Raycaster`
  with hostname / OS / process count / connection count. Renderer also
  guards against agent-controlled XSS via Array-spoofed `processes.length`
  by coercing through `Number(...) | 0` and validates `Array.isArray` on
  the topology payload before iteration.
- **`yuzu_viz_topology_fetch_duration_seconds` Prometheus histogram (PR 6 / OBS-2).**
  Times the inner agent-dispatch path (`tar.fleet_snapshot` fan-out +
  aggregation) on cache-miss refills only, distinguishing "agent dispatch
  is slow" from "the rest of the request is slow" (the existing
  `yuzu_viz_topology_request_seconds` covers the full HTTP path). Wired
  via a new opt-in `FleetTopologyStore::set_fetch_duration_observer()`
  setter and a recommended `VizFleetSlowAgentDispatch` alert at p99 > 5 s
  (the `tar.fleet_snapshot` deadline).

### Changed

- **`/viz/fleet` renderer module migrated from hand-written TU to
  `embed_js.py` codegen** (PR 6). The renderer source of truth is now
  `server/core/static/yuzu-viz.js`; the previous hand-written
  `server/core/src/yuzu_viz_js_bundle.cpp` was deleted. The migration
  was forced by the renderer bundle exceeding MSVC's 16,380-byte raw-
  string-literal limit (C2026) at PR 6's additions; codegen via the
  same `embed_js.py` pipeline used for ECharts and Three.js sidesteps
  the limit by chunking. The `kYuzuVizJs` symbol name and consumer
  contract are unchanged.

### Security

- **Fleet renderer hardens tooltip against agent-controlled Array-spoof
  XSS** (gov R6 UP-1 / sec-MEDIUM). The hover tooltip previously
  interpolated `machine.processes.length` and `machine.connections.length`
  raw into `innerHTML`. A hostile or compromised agent could ship
  `processes: {length: "<svg/onload=...>"}` (a non-array object with a
  string `length`) and the truthy `|| 0` short-circuit would return the
  malicious string. Both fields now coerce through
  `Array.isArray(...) ? Number(...) | 0 : 0`, so a 32-bit integer is the
  only thing the template ever writes. The fetch path additionally
  validates `Array.isArray(data.machines)` before iteration so a malformed
  payload surfaces a payload-error overlay instead of a TypeError
  misclassified as a network error.
- **Distinct fetch-failure overlays for 401/403/503/413/network/schema
  errors on `/viz/fleet`** (gov R6 UP-9 / UP-10 / UP-15 / UP-17). The
  renderer surfaces a granular error message for each fetch outcome
  rather than leaving the scene blank: session expiry, RBAC denial,
  kill-switch flip, oversize fleet, network failure, truncated JSON,
  schema mismatch, and missing/non-array `machines` field each get a
  distinct operator-visible message. On 401/403/503/413 the renderer
  also calls `clearFleet()` so previously-rendered cubes do not persist
  alongside the denial overlay (mixed-signal regression noted in R6).
- **Tooltip caps visual footprint against hostile-hostname DoS** (gov R6
  UP-3). Hostnames up to 100 KB no longer break tooltip layout — the
  tooltip pins `max-width:320px`, `max-height:240px`, `overflow:hidden`,
  `word-break:break-all`. The full hostname is still escaped via
  `escapeHtml` before innerHTML write.

- **`/viz/fleet` page response now sets `Cache-Control: no-cache, no-store,
  must-revalidate`** (gov R4 UP-10 / DEP-1 / CHAOS-C3). The page references
  vendored static assets that cache for 24 hours via `max-age=86400`. Without
  page revalidation, a heuristically-cached stale page after a server upgrade
  could pair with new asset bytes (or vice versa), producing a silent blank
  canvas with a module-resolution console error and no operator-visible
  diagnostic. The revalidation forces a server round-trip per navigation but
  the body is ~7 KB; the overhead is negligible vs the failure mode.
- **WASD pan listener now skips text-editable focus targets** (gov R4
  sec-M1 / UP-6). The window-level keydown listener calls
  `e.preventDefault()` on W/A/S/D; previously this would silently eat
  keystrokes destined for any future overlay-panel `<input>` /
  `<textarea>` / `contenteditable` element. The listener now bails early
  when `e.target` is `INPUT`, `TEXTAREA`, `SELECT`, or `isContentEditable`.
- **Fleet visualization page surfaces a visible error on importmap-
  incapable browsers** (gov R4 UP-16 / ER-SHOULD-1). Previously, browsers
  shipped before early 2023 (Chromium <89, Firefox <108, Safari <16.4)
  would silently fail at module-evaluation time before the renderer
  could mount, leaving a blank canvas with no diagnostic. The page now
  detects via `HTMLScriptElement.supports('importmap')` in a classic
  inline script that runs before the importmap declaration, and surfaces
  a "Fleet visualization requires Chrome 89+, Firefox 108+, or Safari
  16.4+" message via the `#viz-error` overlay if support is missing.
- **WebGL context loss now produces an operator-visible error** (gov R4
  UP-3 / CHAOS-2). The renderer registers `webglcontextlost` and
  `webglcontextrestored` handlers on the canvas. On loss (GPU driver
  crash, OS GPU reset, sleep/wake, dGPU↔iGPU switch), the rAF loop stops
  rendering and `#viz-error` shows "WebGL context lost (GPU reset or
  driver issue). Reload the page to recover." Three.js does not auto-
  recover scene state, so manual reload is the cleanest path; a future
  PR may add automatic re-mount on `webglcontextrestored`.

### Added

- **`/viz/fleet` page scaffold + WASD/orbit/zoom camera controls (PR 5
  of the 11-PR `/viz/fleet` 3D fleet network-topology ladder).** New
  page route `GET /viz/fleet` (auth-gated, same posture as `/tar`) that
  serves an HTMX-style page shell with a persistent `<div id="viz-root"
  data-yuzu-viz-url="/api/v1/viz/fleet/topology">` containing
  `<canvas id="viz-canvas">` and a swappable `<div id="viz-overlay-panel">`
  for future per-machine drill-in detail. The page declares an importmap
  resolving `"three"` and `"three/addons/controls/OrbitControls.js"` to
  the vendored bundles from PR 4. New static asset route
  `GET /static/yuzu-viz.js` serves the renderer module (`kYuzuVizJs`,
  hand-written ~6 KB ES module): mounts once on `DOMContentLoaded` and
  on every `htmx:afterSettle` (idempotent — guarded by
  `root.dataset.yuzuVizMounted` so HTMX swaps of the overlay panel
  cannot blow away the WebGLRenderer's GPU context); builds scene +
  perspective camera + ambient + directional light + ground grid (40
  divisions) + axes helper; OrbitControls drives drag-rotate +
  wheel-zoom with `enablePan = false` so a custom keyup/keydown WASD
  listener owns translation in camera-screen-space (W=+screenY,
  S=−screenY, A=−screenX, D=+screenX, requestAnimationFrame-throttled).
  ResizeObserver on the canvas keeps the renderer + camera aspect in
  sync without a window-resize listener. Empty `tick()` placeholder for
  PR 6+ to fill in topology rendering. The Fleet Viz nav link is added
  to all sibling page shells (dashboard / instructions / compliance /
  TAR / settings / help) so navigation is consistent. (#viz-engine
  ladder PR 5.)

- **Vendored Three.js r168 + OrbitControls (PR 4 of the 11-PR
  `/viz/fleet` 3D fleet network-topology ladder).** Two new build-time
  embeds: `kThreeJs` (685 KB, three.js r168 minified ES module) and
  `kThreeOrbitJs` (32 KB, OrbitControls ES module from
  `examples/jsm/controls/OrbitControls.js`), wired through the existing
  `embed_js.py` chunked-raw-string pipeline that ECharts already uses.
  Static asset routes `GET /static/three.module.min.js` and
  `GET /static/three-orbit-controls.js` serve them with
  `Cache-Control: public, max-age=86400`. Both files MIT licensed; full
  attribution in `server/core/vendor/three-NOTICE.txt` and
  `three-orbit-NOTICE.txt`, summary line added to top-level NOTICE.
  PR 5's page scaffold (`/viz/fleet`) loads them via
  `<script type="importmap">` so the OrbitControls module's
  `import ... from 'three'` resolves to the vendored bundle. Modern
  Three.js (r150+) ships only as ES modules — the planned
  `three.min.js` UMD path no longer exists upstream, so the file naming
  reflects the ES-module reality. (#viz-engine ladder PR 4.)

### Security

- **Fleet visualization fragment route now escapes `</script>` in the JSON
  body before wrapping** (gov R3 sec-M2 / UP-16). nlohmann::json's `dump()`
  does not escape `<` by default; an agent-controlled `hostname` or
  `cmdline` containing the literal substring `</script>` would otherwise
  terminate the `<script type="application/json" id="viz-data">` wrapper
  early, allowing HTML to be injected into a dashboard or HTMX consumer
  that swapped the fragment. The fix replaces `</` with `<\/` (a JSON-spec
  alternate escape for `/`) before wrapping, with a regression test that
  injects `</script><script>alert(1)</script>` as a hostname and verifies
  exactly one closing `</script>` tag in the response.
- **Fleet visualization audit result vocabulary realigned with siblings**
  (gov R3 C-1 / ER-BLOCK-1). Previous `"ok"` / `"error"` / `"oversize"`
  values landed in the `events_other_` Prometheus bucket and were silently
  invisible to SOC 2 SIEM filters keyed on the canonical `"success"` /
  `"failure"` / `"denied"` vocabulary. All `viz.fleet_topology` and
  `viz.fleet_topology.invalidate` audit emissions now use the canonical
  vocabulary; `target_type` switched from `"viz_topology"` to
  `"FleetTopology"` (PascalCase per sibling convention) and `target_id`
  from `"*"` to `""` (empty per `policy.invalidate_all` precedent at
  `compliance_routes.cpp:696`). The 413 oversize branch maps to `denied`
  with `oversize` in the detail field rather than a non-canonical result
  value.

### Added

- **`/viz/fleet` REST surface (PR 3 of the 11-PR `/viz/fleet` 3D fleet
  network-topology ladder).** New `VizRoutes` exposes
  `GET /api/v1/viz/fleet/topology` (JSON) and
  `GET /fragments/viz/fleet/topology` (HTMX-friendly `<script
  type="application/json">` wrapping the same JSON for parser-on-swap),
  both gated on `Response.Read`, audited per request, and metered via
  `yuzu_viz_topology_request_seconds` / `yuzu_viz_cache_{hit,miss}_total` /
  `yuzu_viz_oversize_response_total` / `yuzu_viz_agent_dispatch_timeout_total`,
  plus three store-internal counters now exported to Prometheus
  (`yuzu_viz_refill_oversize_drops_total`, `yuzu_viz_refill_wait_timeouts_total`,
  `yuzu_viz_refill_waiters_total`) so the 256 MiB store-level oversize cap
  and single-flight refill timeouts are observable (gov R3 OBS-1).
  Query params: `include_vuln=1` flips to the vuln-overlay cache slot;
  `fresh=1` invalidates the cache (separately audited) before the get;
  `machines_max=N` (default 5000, ceiling 100000) caps response shape and
  returns 413 + `denied`/`oversize` audit when the materialised fleet
  exceeds it (M-1 cap-check DoS gate). Kill switch via `--viz-disable` /
  `YUZU_VIZ_DISABLE` returns 503 and audits `denied`/`kill_switch`;
  tier-before-permission ordering means the kill switch takes effect even
  for callers who would otherwise fail RBAC (gov R3 sec-M1/arch-B1), and
  startup logs `[VIZ] viz endpoint disabled by configuration` when the
  flag is set so operators have explicit evidence the kill switch took
  effect (gov R3 F-1). `FleetTopologyStore` is now in the `/readyz`
  store conjunction so a construction-failed store surfaces as
  503-not-ready rather than a silent viz outage (gov R3 HC-1). The store's
  PR-2 fetcher seam is wired: on cache miss, dispatches `tar.fleet_snapshot`
  to every connected agent via `AgentRegistry::send_to`, drains
  `forward_gateway_pending()` for gateway-proxied agents, polls the
  response store for matches keyed on a synthesised `tar-<hex>` command_id
  until the 5 s deadline, and returns whatever arrived; missing agents
  come back as `stale=true` rows so the renderer dims rather than
  disappears them. The fetcher dispatch intentionally opts out of the
  executions tracker (`record_send_time` only, no `record_execution_id`)
  -- a 60 s automated refresh would otherwise spam the operator-facing
  executions pane. release.yml gains an explicit
  `--build-arg TRIPLET=x64-linux` ahead of arm64 publishing (QE-R2-02).
  (#viz-engine ladder PR 3.)

- **`tar.fleet_snapshot` action + server-side `FleetTopologyStore` (PRs 1+2
  of the 11-PR `/viz/fleet` 3D fleet network-topology ladder).** New TAR
  plugin action enumerates running processes, open network connections,
  and host-bound IPs and emits a single `fleet_snapshot.v1` JSON document
  on demand. Cmdlines are redacted using the union of operator config and
  compiled-in default patterns. Source-pause states (`process_enabled`,
  `tcp_enabled`) are honoured: when a source is paused, the corresponding
  list is empty and `process_source_paused` / `tcp_source_paused` markers
  appear in the document. Each list is hard-capped at 4096 entries with
  truncation flags. New server-side `FleetTopologyStore` (memory-only,
  LRU-of-2 by `include_vuln`, 60 s TTL, single-flight refill, fetcher
  injected at construction, soft 256 MB memory cap, `wait_for`-bounded
  caller wait) aggregates per-agent snapshots into a `fleet_topology.v1`
  document for the upcoming `/viz/fleet` renderer. Cross-machine connection
  scope (Local / InternalFleet / External) and `dst_agent_id` resolution
  are computed via an `ip_to_agent` map built from each agent's `local_ips`,
  with bracketed/zone-id IPv6 normalization and link-local defence-in-depth
  filtering. Process categorisation (`process_category.hpp`) maps ~70 known
  executable basenames to System / Browser / Database / Web / Runtime /
  Other for renderer colouring. REST route + dashboard renderer arrive in
  PR 3+; the action is dispatchable today via direct gRPC. (#viz-engine
  ladder PRs 1, 2 and governance hardening round 1.)

### Fixed

- **`ConcurrencyManager::try_acquire`: data race + cross-thread count
  corruption on `sqlite3_changes()`.** The post-`sqlite3_step()` call to
  `sqlite3_changes(db_)` read `db->nChange` without the per-connection
  mutex. `SQLITE_OPEN_FULLMUTEX` serialises individual SQLite API calls
  but not the `step → changes` pair, so a concurrent `step()` on the same
  connection both data-raced the read (TSan-flagged) and could corrupt
  the observed change count — a caller could see another thread's row
  count and either let an execution past the cap or reject one that
  should have been admitted. Fixed by adding a `RETURNING 1` clause to
  the conditional INSERT so "was a row inserted?" is the result of
  stepping that single atomic statement; `sqlite3_changes()` is no
  longer called. Honours the `dbbe01f` (#330) design intent ("one atomic
  statement, no app mutex"). The same `step + changes` anti-pattern
  exists across 24 other store sites; tracked separately as #1033.
  Also fixes `tests/unit/test_kv_store.cpp`: `REQUIRE`/`CHECK` calls
  from worker threads wrote Catch2's process-global
  `g_lastKnownLineInfo` non-atomically (TSan-flagged as #918). Workers
  now record into `std::atomic<bool>`; assertions run on the main
  thread after join. Closes #949's ConcurrencyManager half and #918's
  kv_store instance.
- **Executions drawer: dashboard "Fan-out" cell stuck at "0/0 of N".**
  `ExecutionTracker::update_agent_status` wrote to `agent_exec_status`
  and published `agent-transition` SSE events but never invoked
  `refresh_counts` to recompute the parent `executions` row's
  `agents_responded` / `agents_success` / `agents_failure`. The aggregates
  stayed at 0 forever and the row never crossed to terminal status.
  `update_agent_status` now chains `refresh_counts` at the end of every
  call (UAT 2026-05-06).
- **Executions drawer: per-agent + responses tables now live-populate
  via SSE — no page reload.** AgentServiceImpl now calls
  `ExecutionTracker::update_agent_status` from every response-receipt
  site (`Subscribe` and `process_gateway_response`, both RUNNING and
  terminal branches), so `agent_exec_status` populates as responses
  arrive and the existing `agent-transition` SSE bus fires for every
  state change. The drawer JS schedules a 500 ms-debounced
  `htmx.ajax(GET /fragments/executions/<id>/detail)` re-fetch on each
  event so the responses table picks up new rows without a manual
  refresh (UAT 2026-05-06).
- **Executions drawer: spurious "exit=1 then exit=0" pair removed.**
  Every dispatched instruction previously produced two response rows
  per agent — a RUNNING data row and an empty terminal sentinel.
  Operators read the non-zero `status` enum value (1=SUCCESS,
  2=FAILURE, …) on the sentinel as a failure exit code that "happened
  before" the real result. New `ResponseStore::finalize_terminal_status`
  updates existing RUNNING rows in place when the terminal frame
  carries no output, scoped to `(instruction_id, agent_id,
  execution_id, status=0)`. Tri-state `FinalizeResult`
  (`Updated`/`NoRow`/`Error`) prevents SQLITE_BUSY from silently
  re-creating the sentinel (UAT 2026-05-06 #11; governance UP-3 / CH-1).

### Added

- **Wall-clock `HH:MM:SS.mmm <TZ>` timestamps in the executions list
  and drawer.** Right-hand instruction-line timestamp and per-agent
  response arrival time now render in the operator's browser-local
  timezone (e.g. `12:22:33.251 BST`) instead of a relative
  "Ns ago" string. Server emits `data-epoch-ms` on the cells; new JS
  helpers (`formatLocalTime` + `renderLocalTimes`) format on
  `DOMContentLoaded` and `htmx:afterSwap`. Title attribute and cell
  fallback retain the ISO-8601 UTC timestamp for hover correlation
  and no-JS environments (UAT 2026-05-06 #9).
- **Server-side response arrival timestamp at millisecond precision.**
  New `responses.received_at_ms` column (response_store v3 migration,
  with idempotent pre-stamp probe mirroring v2) records when the
  server received each response frame. Coexists with the legacy
  seconds-precision `timestamp` column. The drawer's per-agent
  responses table gained a "Time" column that renders this value as
  wall-clock (UAT 2026-05-06 #10).
- **Live-drawer regression test.** New
  `tests/puppeteer/executions-uat-2026-05-06.mjs` operator-runnable
  test pins the four UAT contracts: dispatch toast, drawer
  populates without reload, wall-clock timestamps, single response
  row per agent.
- **`/readyz` covers `execution_tracker`.** Added to the readiness
  conjunction so a failed instructions-DB pool surfaces as HTTP 503
  rather than a silent no-op on every response receipt
  (governance UAT 2026-05-06 SRE-1).

### Changed

- **Build-time content embed locked down — single source of truth.**
  Shipped `InstructionDefinition` YAMLs are embedded into
  `yuzu-server` at build time via `embed_content.py`; the runtime
  never reads them from disk. **PyYAML is now a hard build dependency**
  — `meson setup` runs `python -c "import yaml"` and `error()`s if
  the import fails. The script itself hard-errors on missing
  PyYAML, missing `content/` directory, or zero parsed definitions
  (the historical "warn and emit empty bundle" fallback is removed,
  which silently produced binaries with empty Instructions tabs).
  Provision PyYAML with `pip install pyyaml` (Linux/macOS) or
  `pacman -S python-yaml` (MSYS2). CI workflows updated to install
  PyYAML on every leg (release Linux + macOS, ci.yml macOS +
  Windows, `Dockerfile.runner-linux` apt manifest).
- **Executions drawer SSE event volume.** Each per-agent state
  change now publishes 2 events (`agent-transition` then
  `execution-progress`) and 3 on the all-agents-responded threshold
  (additional `execution-completed`). Custom SSE consumers should
  expect the higher cadence; the drawer's debounced refresh is the
  default consumer experience.
- **Shutdown ordering.** gRPC servers now shut down BEFORE
  `execution_tracker_` is reset so in-flight `Subscribe` /
  `process_gateway_response` handlers cannot dereference a freed
  tracker pointer mid-call (governance UAT 2026-05-06 architect B-1).

### Removed

- **Install packages no longer ship `content/definitions/`.** The
  Debian `.deb`, Docker images (`Dockerfile.server`,
  `Dockerfile.server-local`), Docker compose UAT mounts, Windows
  Inno Setup `[Files]` block, and three release-archive staging
  blocks (Linux/Windows/macOS) used to copy YAMLs to filesystem
  paths the binary ignored — operator-misleading dead code. The
  paths varied between packages
  (`/usr/share/yuzu/content/definitions/` on .deb,
  `/usr/share/yuzu/definitions/` on Docker, `{app}\content\definitions\`
  on Windows). Operator runbooks pointing at any of those paths for
  edits are obsolete; use the dashboard / REST `PATCH
  /api/v1/definitions/<id>` to override shipped definitions
  (operator edits persist in `instructions.db`). Old YAMLs left
  on disk from prior installs are harmless and untouched on
  upgrade.
- **`docs/operations/disaster-recovery.md`** content-definitions
  backup row removed — it pointed at filesystem YAMLs that no longer
  ship; operator-customised definitions are already covered by the
  `instructions.db` row.

### Added

- **Cross-platform `/test` pipeline (Linux + macOS).** The `/test`
  orchestration was Linux-only — preflight required `ss`, `df -BG`,
  iproute2, `/var/lib/docker`; perf-gate read `/proc`; the UAT bring-up
  was named `linux-start-UAT.sh`. macOS operators couldn't run `/test`
  locally and had to push-and-watch CI for cross-platform validation.
  - New `scripts/test/_portable.sh` exposes `host_os`, `build_dir`,
    `port_listening`, `disk_free_gb`, `loadavg_1m`, `cpu_brand`,
    `mem_total_gb`, `ensure_docker_path` (probes OrbStack + Docker
    Desktop bundle paths on macOS), `docker_available`. Branches on
    `uname -s`; Linux behavior unchanged byte-for-byte.
  - New canonical `scripts/start-UAT.sh` replaces `linux-start-UAT.sh`
    as the cross-platform UAT bring-up. Same topology, ports, and 6
    connectivity tests; uses lsof + grep -oE/awk in place of -oP. The
    historical `scripts/linux-start-UAT.sh` is now a 9-line back-compat
    shim that execs `start-UAT.sh`.
  - `preflight.sh`, `perf-{gate,sample,cron-runner}.sh`, `teardown.sh`,
    `test-upgrade-stack.sh` patched to use the helpers and gracefully
    handle `docker_available` returning false. Phase 1 docker-image-build
    and Phase 2 upgrade-test record SKIP gate rows on macOS without
    OrbStack/Docker Desktop running rather than failing the run.
  - `disk_free_gb` rounds to nearest (rather than floor) so a box with
    exactly 20G free does not trip the default 20G preflight threshold.
  - `cpu_brand` Linux fallback explicitly handles empty stdout from
    `grep | sed` (which previously silently returned "" on ARM kernels
    that don't emit `model name`).
  - Bash 4+ guards added to `perf-gate.sh`, `teardown.sh`,
    `test-fixtures-verify.sh` for parity with `preflight.sh`.
  - macOS prerequisites: `brew install bash` (stock /bin/bash 3.2 lacks
    `mapfile` / `declare -A`), kerl-installed Erlang, OrbStack or
    Docker Desktop. `.claude/skills/test/SKILL.md` adds a
    "Cross-platform support" section; `CLAUDE.md` UAT block points at
    `scripts/start-UAT.sh`.

- **Phase 8.3 Response Offloading governance hardening — round 3.**
  Fixes for Gate 6 BLOCKING (SRE) + cheap SHOULD findings.
  - **HC-1 (SRE BLOCKING)** — `OffloadTargetStore` now appears in both
    `/readyz` and `/healthz` conjunctions in `server.cpp`. A migration
    failure on `offload_targets.db` would otherwise have left the
    probes reporting "ready"/"healthy" while every
    `/api/v1/offload-targets` endpoint and the `AgentService` fan-out
    silently no-opped. Mirrors the same pattern Guardian's
    `guaranteed_state_store` follows. The `/healthz` `stores` map gains
    an `offload_target` row.
  - **RESTART-1 (SRE SHOULD)** — `Server::stop()` now calls
    `offload_target_store_->flush_all()` after the web server stops
    accepting requests but before any further teardown. Drains pending
    batched events on graceful shutdown so a SIGTERM does not silently
    drop a partial buffer. Detached delivery threads spawned by
    `flush_all` are not joined (matches the WebhookStore precedent),
    but the buffer state is consistent and the SQLite handle is still
    open at the moment of dispatch.
  - **Round-3 re-review residual finding (MEDIUM)** — `create_target`
    now rejects control bytes (`< 0x20`) in `name` and `url` as well
    as `auth_credential`. The DELETE-audit detail change in F-3 below
    embeds `name` and `url` verbatim into the audit row's `detail`
    field as `name=<n> url=<u>`; a control byte (CR/LF/NUL) in either
    would line-split the audit row and forge a downstream event in
    any SIEM that parses log lines individually. New test cases
    `[offload_store][security]` pin the guard for both fields including
    the embedded-NUL edge case.
  - **F-3 (compliance SHOULD, 1-line fix)** — `DELETE
    /api/v1/offload-targets/{id}` now snapshots the target's `name` and
    `url` BEFORE calling `delete_target` and embeds them in the audit
    row's `detail` field as `name=<n> url=<u>`. Closes the brief
    compromise-and-cleanup forensic gap where a delete audit row carried
    only the numeric id, leaving the URL recoverable only via a chain
    join to the create row.
  - **Enterprise BLOCKING (doc)** — `docs/user-manual/rest-api.md`
    Offload Targets section now carries:
    - A "Known authentication limitations" callout explaining that
      Splunk HEC's `Authorization: Splunk <token>` header is NOT the
      same as `bearer`, AWS S3/EventBridge/Kinesis require Sigv4 (not
      shipped), and Azure Monitor/Sentinel require AAD token flow.
      Removes the misleading "S3-bucket-receiver" example and replaces
      with realistic targets (Datadog Logs, Elastic ingest, in-house
      aggregator).
    - A "Validating a new target" note explaining that there is no
      synthetic-test endpoint and the validation procedure is to set
      `batch_size=1`, fire an instruction, and poll `/deliveries`.
    - A bold "Cleartext HTTP warning" stating that `http://` URLs
      transmit data in cleartext and are not suitable for production
      deployments containing customer endpoint data (compliance F-5).
    - An "Operator trust model" callout documenting that
      `Infrastructure:Write` operators can register any URL with no
      allowlist / egress controls — known limitation tracked as a
      roadmap follow-up.
  - **Known follow-ups (deferred — sibling-pattern issues, not new in
    this PR):**
    - **Retention sweep on `offload_deliveries` and `webhook_deliveries`
      (CAP-1 SRE BLOCKING for production deployments).** Both tables
      grow unboundedly; ~21 GB/day at 100 events/sec * 5 targets *
      `batch_size=1`. Offload mirrors the existing webhook gap; fix
      should land for both stores together. Until then, deployments
      handling sustained traffic should monitor `db_dir` disk usage and
      prune deliveries manually.
    - **SSRF allowlist for outbound URLs (compliance F-2 / chaos
      CH-2).** Both webhook and offload stores accept arbitrary
      operator-supplied URLs including RFC1918 / loopback / link-local
      / cloud-metadata endpoints. The trust model accepts this as
      operator-tier-privileged today; multi-tenant deployments will
      need a network-egress allowlist before production use.
    - **Prometheus metrics on the fan-out path (perf-S10 / OBS-1).**
      `yuzu_offload_*` counters/histograms for delivery success/failure,
      buffer depth, semaphore wait. WebhookStore has the same gap;
      file as a joint follow-up.
    - **`spec.offload.targets` per-instruction filter at the
      dispatcher (UP-14).** The DSL field is documented + parsed
      verbatim; the dispatcher does not yet extract or honour it.
      Doc-warned; runtime wiring is the follow-up.
    - **Outbound TLS cert verification + proxy support (SEC-1, SEC-2).**
      `httplib::Client` defaults; cert verification is on but custom
      CA bundles are not surfaced; `HTTPS_PROXY` env vars are not
      respected. Same shape as webhooks.

  **Tests:** new `[rest][offload]` 404-on-missing-target case for
  `/deliveries`. Total `[offload]` count: 17 cases (was 11) /
  100+ assertions including hardening-pin tests for sec-H1, sec-M2,
  sec-M5, sec-L6, qe-S3 (batch accumulator), qe-S6 (migration v1),
  HP-2 (deliveries 404).

- **Phase 8.3 Response Offloading governance hardening — round 2.**
  Fixes for Gate 3 + Gate 4 findings.
  - **HP-1 / UP-6** — `agent_service_impl.cpp` outer-guard regression at
    all three fire-event sites: round-1 hoisted `wh_payload.dump()` into
    a single `body` to avoid double-serialise (perf-S1), but accidentally
    nested the offload `fire_event` inside the `webhook_store_` null
    check. Result: a deployment without a webhook store would silently
    skip offload dispatch even when the offload store was healthy. Fix
    splits the guards: outer `if (webhook OR offload)` builds the body
    once; each sink fires under its own independent guard. Both
    happy-path and unhappy-path Gate 4 reviewers caught this
    independently — exactly the Pattern C "fix commit ships a worse bug
    than the one it closes" hazard the governance ladder exists for.
  - **HP-2** — `GET /api/v1/offload-targets/{id}/deliveries` now returns
    404 when the underlying target does not exist, matching the sibling
    `GET /api/v1/offload-targets/{id}` semantics. Previously returned
    `{"deliveries":[]}` + 200, which an operator polling for a deleted
    target could mistake for "delivery channel quiet" rather than "this
    target is gone." OpenAPI 404 description updated accordingly.
  - **arch-S1 / agentic A2** — `openapi_spec()` in `rest_api_v1.cpp`
    now enumerates the five `/offload-targets*` paths so an
    OpenAPI-driven client (operator scripting, agentic workers, REST
    SDK generators) can discover the surface. Per
    `agentic-first-principle.md` §A2, mounting under `/api/v1/`
    requires enumeration through the openapi.json discovery channel.
  - **perf-S1** — `wh_payload.dump()` hoisted to a local `const auto
    body` once per fire-event site (3 sites in `agent_service_impl.cpp`)
    rather than dumping per `fire_event` call. Halves the per-response
    JSON serialise cost on the response-receipt hot path. Subject to
    the outer-guard fix above so the optimisation does not silence
    either sink.
  - **perf-S2** — `offload_targets` table now carries a partial index
    `idx_offload_targets_enabled WHERE enabled = 1` baked into the v1
    migration. `fire_event`'s SELECT scans only the index for enabled
    rows; at N>~50 targets the partial form is materially faster than
    a full table scan and stays index-resident.
  - **cpp-S-1** — `~OffloadTargetStore` destructor trade-off documented
    in the public header (the in-flight detached delivery / SQLite
    handle close race), so callers know not to assume flush-on-destroy.
    Mirrors the WebhookStore precedent.
  - **qe-B1** — `OffloadHarness` in `test_rest_offload_targets.cpp`
    refactored to use `yuzu::test::TempDbFile` RAII (member declaration
    order: `db_file` before `store`) so a partially-constructed
    fixture cleans up the on-disk SQLite + WAL/SHM siblings on any
    exit path including failed `REQUIRE(store->is_open())`. Closes the
    qe-B1 leak pattern flagged by quality-engineer in Gate 3.
  - **qe-S2** — Three `[offload_store][filter]` tests dropped their
    `sleep_for(150ms)` synchronisation barriers. The filter decision
    (target_filter / event_types / enabled) runs synchronously inside
    `fire_event` before any thread is spawned, so the absence-of-delivery
    assertion is deterministic without sleep. Tightens runtime by ~450ms
    and removes a CI-runner-pause flake hazard.
  - **qe-S3** — New test pins `batch_size > 1` accumulator behaviour:
    fire 2 events into a `batch_size=3` target, verify no dispatch yet,
    call `flush_all()`, poll `get_deliveries` for up to 5s, assert the
    single resulting delivery has `event_count == 2` and a body of
    shape `{"events":[…]}`.
  - **qe-S6** — New test pins migration v1 outcome: open a fresh
    on-disk store, query `schema_meta WHERE store='offload_target_store'`,
    assert `version == 1`. Establishes the migration self-test pattern
    for future v2+ schema work.
  - **arch-INFO / capability-map** — `docs/capability-map.md` flips
    20.7 Response Offloading to ✓ T3, bumps Future progress 32→33,
    Overall 168→169, and corrects the Domain 20 row from `7|6|0|1`
    to `7|7|0|0` (the round-2 re-review caught a three-way disagreement
    between header bar, TOTAL row, and per-domain row that was
    previously inconsistent).
  - **doc-S2 (round 2)** — `docs/yaml-dsl-spec.md` `spec.offload`
    caveat rewritten to remove the inaccurate "parsed and persisted
    (`offload_spec` column reserved for v5 migration)" claim. The
    field is preserved verbatim in `yaml_source` only and is not
    extracted, denormalised, or honoured by the dispatcher in this
    revision.
  - **doc-S3 (round 2)** — `spec.offload` now carries the same
    dashboard-YAML-editor strip caveat that `spec.visualization` and
    `spec.responseTemplates` carry, plus a stronger "no current
    runtime effect" warning so an operator authoring the field is not
    misled into expecting filtering behaviour.

  **Tests (separate from prod for changelog tracking, per
  `feedback_test_commits.md`):** new `[offload_store][batch]` batch
  accumulator pinning; new `[offload_store][migration]` v1 schema_meta
  verification; new `[rest][offload]` 404-on-missing-target deliveries
  test; harness refactor to `TempDbFile` RAII; sleep removal from
  three filter tests.

- **Phase 8.3 Response Offloading governance hardening — round 1.**
  Single-pass fixes for governance Gate 2 BLOCKING and SHOULD items on
  the Phase 8.3 work below.
  - **sec-H1** — `auth_credential` now rejected at create-time when it
    contains any byte `< 0x20`. Closed an outbound-request-smuggling
    vector where an `Infrastructure:Write` operator could plant a CRLF
    in a Bearer token to inject a second header (`X-Evil: 1`,
    `Transfer-Encoding: chunked`) on every outbound POST. Basic and
    HMAC are CRLF-safe by construction (base64 / hex output) but the
    guard fires for all auth types as defence-in-depth. Pinned by
    `[offload_store][security]` test cases against `\r\n`, `\n`-only,
    `\r`-only, embedded `NUL`, and CRLF in Basic/HMAC paths.
  - **sec-M2** — Defence-in-depth scheme guard now re-checks `tgt.url`
    at dispatch time. Create-time guard rejects non-`http(s)` URLs,
    but a tampered row (manual SQLite write, future update path)
    would otherwise be dispatched verbatim. Mismatch records an
    `invalid_scheme` delivery row and refuses to construct the HTTP
    client.
  - **sec-M4** — Destructor no longer calls `flush_all()`. Pending
    buffered events are dropped on shutdown rather than spawning
    detached worker threads that capture `this` and reach back into
    `mtx_` / `db_` after the destructor closes the database. Matches
    the WebhookStore precedent (no flush in dtor); operators that need
    at-least-once semantics should set `batch_size=1` (immediate
    dispatch) or build a queue at the receiver.
  - **sec-M5** — `std::stoll` on the `(\d+)` regex captures in the
    REST routes now wrapped in a `parse_id_segment()` helper that
    treats `out_of_range` (21+ digit ids) as 404 rather than letting
    httplib turn the throw into a 500. New test pins `GET
    /api/v1/offload-targets/999999999999999999999 → 404`.
  - **sec-L6** — `?limit=` query param on `/deliveries` clamped to
    `[1, 1000]` to prevent operator-self-DoS via a billion-row vector
    allocation. New test pins the clamp.
  - **sec-L7** — Semaphore acquire/release wrapped in an RAII
    `SemaGuard` so a `std::bad_alloc` or other exception between
    acquire and release no longer leaks a delivery slot for the
    lifetime of the process.
  - **sec-L8** — `DELETE /api/v1/offload-targets/{id}` 404 path now
    emits an audit row with `result=denied`, `detail=not_found`. The
    successful-delete-only emission was a SIEM signal gap — operators
    fishing for valid offload-target ids leave no trace today.
  - **sec-INFO9** — Secret-leak paranoia test extended to cover
    `GET /api/v1/offload-targets/{id}` and
    `GET /api/v1/offload-targets/{id}/deliveries` in addition to the
    list endpoint, so a future field-rename leaking the credential
    via either single-target read fails the test.

  **Docs:**
  - **doc-B1** — `docs/user-manual/audit-log.md` now lists
    `offload_target.create` and `offload_target.delete` in the logged
    actions table with full `target_type` / `target_id` / `detail` /
    `result` contracts. Result-vocabulary paragraph extended to cite
    Phase 8.3 explicitly.
  - **doc-S2** — `docs/yaml-dsl-spec.md` `spec.offload` caveat
    rewritten. The previous draft claimed the field was "parsed and
    persisted (`offload_spec` column on `instruction_definitions`
    reserved for v5 migration)"; no such column exists and no parser
    extracts the field. Updated to state accurately that the field is
    preserved verbatim in `yaml_source` only and currently has no
    runtime effect.
  - **doc-S3** — `spec.offload` now carries the same dashboard YAML
    editor strip caveat that `spec.visualization` and
    `spec.responseTemplates` carry, so an operator authoring the
    field is not misled into expecting runtime fan-out filtering.
  - **doc-S4** — `audit-log.md` Event Structure table's `result` field
    description updated from "success or failure" to
    "success, denied, or failure" with a pointer to the Result
    vocabulary section, fixing a stale row that the round-1
    response-templates work also missed.

- **Phase 8.3 Response Offloading (#255).** Configurable external HTTP
  endpoints — *offload targets* — that receive a copy of `agent.registered`
  and `execution.completed` events as they fire. Built around a sibling
  `OffloadTargetStore` (`offload_targets.db`, migration v1) wired into
  `AgentServiceImpl` next to the existing webhook fan-out, so every event
  that fires a webhook also fans out to every enabled target whose
  `event_types` filter matches.
  - **Typed auth** — `none`, `bearer`, `basic`, `hmac`. Bearer adds
    `Authorization: Bearer <token>`; Basic adds
    `Authorization: Basic <base64(user:pass)>`; HMAC adds
    `X-Yuzu-Signature: sha256=<hex>` so receivers can share verification
    code with webhooks. `auth_credential` is persisted but **never**
    returned by any REST surface (`list()` / `get()` / `get_by_name()`
    redact; the test harness includes a paranoia assertion that the secret
    string never appears in any serialised list body).
  - **Server-side batching** — `batch_size > 1` accumulates events into a
    per-target buffer and flushes on threshold; flush body is JSON of
    shape `{"events":[…]}` plus an `X-Yuzu-Event-Count` header. SIEM /
    data-warehouse receivers that prefer fewer larger requests can set
    `batch_size = 50–500`; real-time alerting stays on `1`. `flush_all()`
    drains pending buffers on store destruction.
  - **Per-instruction filter (DSL)** — `spec.offload.targets: [<name>, …]`
    in `InstructionDefinition` YAML restricts fan-out to a named subset
    of targets. The store honours an explicit `target_filter` argument
    on `fire_event`; the dispatcher does NOT yet extract the filter from
    the originating definition (tracked as a follow-up so the global
    fan-out path lands clean first). Documented in
    `docs/yaml-dsl-spec.md` § `spec.offload`.
  - **REST** — `GET/POST/DELETE /api/v1/offload-targets`,
    `GET /api/v1/offload-targets/{id}`,
    `GET /api/v1/offload-targets/{id}/deliveries`. RBAC:
    `Infrastructure:Read` for GETs, `Infrastructure:Write` for POST/DELETE.
    Audit events: `offload_target.create` (success | denied),
    `offload_target.delete`. Routes are exposed via both
    `httplib::Server` (production) and `HttpRouteSink` (tests) overloads
    so the suite dispatches in-process without an acceptor thread (#438).
  - **URL scheme guard** — only `http://` and `https://` are accepted at
    create time; `ftp://`, `javascript:`, empty URL all rejected with -1
    return + warning log + 400 + denied audit. Matches the WebhookStore
    L12 hardening.
  - **UNIQUE name + batch_size validation** — duplicate target names and
    `batch_size < 1` rejected at create time so the dashboard can rely
    on names as stable references.
  - **Files:** new `server/core/src/offload_target_store.{hpp,cpp}` and
    `server/core/src/offload_routes.{hpp,cpp}`; `server/core/src/server.cpp`
    opens `offload_targets.db`, wires the store into AgentServiceImpl,
    and registers routes; `server/core/src/agent_service_impl.{hpp,cpp}`
    fires `agent.registered` and `execution.completed` to the offload
    store at the same three call sites as webhooks; `docs/roadmap.md`
    8.3 marked done; `docs/yaml-dsl-spec.md` adds `spec.offload`;
    `docs/user-manual/rest-api.md` adds the Offload Targets section
    with auth-header reference and per-event header table.

  **Tests (separate from prod for changelog tracking):** new
  `tests/unit/server/test_offload_target_store.cpp` (16 cases / 68
  assertions — store CRUD, URL scheme, UNIQUE name, batch_size
  validation, secret redaction, base64 RFC 4648 vectors,
  RFC 4231 HMAC-SHA256 case 2, target_filter exclusion,
  event_types filter exclusion, disabled-target skip, auth-type
  string roundtrip with unknown→`None` fallback) and
  `tests/unit/server/test_rest_offload_targets.cpp` (11 cases — list
  empty, create 201, secret-redaction-paranoia,
  GET/:id 200+404, DELETE remove+audit, POST 400 missing fields,
  POST 400 invalid JSON, POST 400 bad URL scheme + denied audit,
  403 perm denied, 503 null store, deliveries empty list).

- **Response Templates governance hardening — round 2.** Round-2
  re-review of the round-1 hardening commit caught a BLOCKING and three
  SHOULD regressions that round-1 introduced or left unaddressed:
  - **B-2** — OpenAPI PUT `requestBody.schema` referenced `#/components/
    schemas/ResponseTemplate` but the schema was never defined; spec
    validators / SDK generators would fail. Added the `ResponseTemplate`
    schema to `components.schemas` (with required field, sort/filter
    sub-schemas, `default` flag) and switched the POST inline schema to
    the same `$ref` for sibling parity with `ManagementGroup`/`Tag`/
    `GuaranteedStateRule`.
  - **S-7** — round-1 emitted `result="failure"` on every 4xx audit
    branch, but `audit-log.md` is explicit that 4xx is `denied` and only
    internal 5xx is `failure`. Switched the 16 4xx audit emissions to
    `denied`; the 3 persist-failure 500 emissions remain `failure` per
    the documented vocabulary. `audit-log.md` table extended with the
    explicit branch→result mapping for each new action.
  - **S-8** — `rest-api.md` POST/PUT/DELETE error tables did not list
    the new 413 (body cap) or 500 (persist failure) status codes.
    Added explicit Errors tables on every verb and a bold callout that
    the 64 KiB cap fires before parsing.
  - **S-9** — `kRtMaxBodyBytes` is now annotated as scoped specifically
    to the response-templates routes, with a comment pointing to the
    follow-up hardening pass that would lift the convention to other
    POST/PUT mutations (Guardian rules, management-group create, tag
    PUT, token POST).
  - **I-2** — `capability-map.md` headline figure updated from
    `166/225 (74%)` to `168/225 (75%)`, matching the per-phase table
    that round-1 already updated.

- **Response Templates governance hardening round.** Single-pass fixes for
  governance Gates 2–6 BLOCKING and critical-SHOULD items on the Phase 8.2
  Response Templates work below.

  **Code BLOCKING:**
  - **UP-4 / sec-M3** — InstructionStore probe-and-stamp guard now checks
    every `sqlite3_prepare_v2` and `sqlite3_step` return; failure
    fails-closed (closes the DB) instead of silently falling through to
    the migration ledger and tripping the `ALTER TABLE … ADD COLUMN`
    duplicate-column error that would wedge boot with no diagnostic.
  - **UP-8 / sec-M2 + sec-M4** — POST/PUT bodies on
    `/api/v1/definitions/{id}/response-templates[/{tid}]` are now capped
    at 64 KiB (returns 413). The YAML-import path's string-form re-parse
    of `responseTemplates` is capped at 256 KiB and a malformed string
    is dropped with a logged warning rather than passed through verbatim.
    Closes the operator-tier JSON-bomb DoS that crashed the
    single-process server via nlohmann's recursive-descent stack
    overflow.
  - **B-1 / arch-B1** — OpenAPI spec now lists the 5 new response-template
    routes (List/Get/Create/Update/Delete). Closes the `agentic-first`
    A2 (discovery) violation.
  - **S-4 / sec-L3 / dsl-S2** — `import_definition_json` now silently
    drops any `responseTemplates` element with `id == "__default__"`,
    closing the stuck-state bug where an imported pack could inject a
    reserved-id row that REST PUT/DELETE refused to remove.

  **Code critical-SHOULD bundled in:**
  - **sec-M1 / S-1** — failure-path audit emissions added to all three
    response-template mutations (`response_template.{create,update,
    delete}`) with `reason=<r>` codes
    (`malformed_definition_id`, `body_too_large`, `invalid_json`,
    `definition_not_found`, `template_not_found`, `validation_failed`,
    `reserved_id`, `persist_failure`, `malformed_id`). Sibling parity
    with `execution.visualization.fetch`.
  - **F-3** — dashboard `/fragments/results` now treats the standalone
    `?dir=` query param as evidence of operator sort intent
    (`sort_explicit = req.has_param("sort") || req.has_param("dir")`),
    so a URL with `dir=desc` and `template_id=X` no longer silently
    overrides the operator's chosen direction.
  - **OBS-3** — 500 (persist failure) branches now log at ERROR with
    `def_id`, `tid`, and the underlying error string before returning
    a generic `"persist failure"` envelope (no SQLite error text leaked
    to clients).

  **Docs BLOCKING:**
  - **doc-B1** — `docs/user-manual/audit-log.md` table extended with
    the three `response_template.*` actions and their failure-reason
    vocabulary.
  - **doc-B2** — `docs/capability-map.md` § 20.6 and § 28.2 flipped from
    `:x:` to `:white_check_mark:`; phase totals updated (20: +1 done,
    -1 open; 28: +1 done, -1 open; grand total 167→168 done, 55→54
    open).
  - **doc-B3** — `docs/user-manual/rest-api.md` Table of Contents now
    lists "Response Templates" under Definitions.
  - **doc-B4** — `docs/user-manual/server-admin.md` Upgrade Notes
    section gains a vNEXT entry for migration v3 covering the
    pre-upgrade snapshot command, the post-upgrade `schema_meta`
    validation query, and the manual recovery path for the
    probe-and-stamp boot-wedge case.

- **Response Templates (Phase 8.2, issue #254).** Named response-view
  configurations attached to an `InstructionDefinition` — column subset,
  sort order, and filter presets the dashboard's filter-bar **View**
  dropdown surfaces. Storage is a new `response_templates_spec` JSON
  column on `instruction_definitions` (migration v3 with the same
  probe-and-stamp guard used for v2). Every definition gets a synthesised
  `__default__` template derived from `spec.result.columns` (preferred)
  or the plugin's column schema, so the dropdown is never empty even
  before an operator authors anything.

  REST CRUD at
  `/api/v1/definitions/{id}/response-templates[/{template_id}]` (List/Get
  on `InstructionDefinition:Read`; POST/PUT/DELETE on
  `InstructionDefinition:Write`). Reserved id `__default__` cannot be
  authored, replaced, or deleted. Filter ops accepted: `equals`,
  `not_equals`, `contains`, `starts_with`, `ends_with`. The dashboard
  auto-applies `equals`-op filters to the URL filter map; other ops
  are honoured by REST consumers but not auto-applied client-side in
  this revision (planned to follow when `FacetFilter` grows an op field).

  YAML authoring is `spec.responseTemplates: [{...}]`. Same caveat as
  `spec.visualization`: the dashboard YAML editor's lightweight
  line-scanner does not extract the templates spec into the indexed
  column — author through `POST /api/v1/definitions/import` or the
  REST template endpoints. Audit events: `response_template.create`,
  `response_template.update`, `response_template.delete`. Files:
  `server/core/src/response_templates_engine.{hpp,cpp}` (new),
  `server/core/src/instruction_store.{hpp,cpp}` (column + migration v3),
  `server/core/src/rest_api_v1.cpp` (5 routes),
  `server/core/src/dashboard_routes.{hpp,cpp}` (selector + visibility +
  template-driven sort/filter defaults), `docs/yaml-dsl-spec.md` §
  `spec.responseTemplates`, `docs/user-manual/instructions.md` §
  Response Templates, `docs/user-manual/rest-api.md` § Response
  Templates.

- **CodeQL SARIF post-processing filter** at `scripts/ci/filter-codeql-sarif.sh`
  wedged between `analyze` and `upload-sarif` in `codeql.yml`. CodeQL's
  `paths` / `paths-ignore` config keys do not reliably suppress C/C++
  alerts whose location is a transitively-included header (the C++
  extractor follows every `#include`; vendored `vcpkg_installed/` and
  generated `build-*/` headers end up in the database; structural rules
  fire on their AST). The filter drops non-security findings in those
  paths but **preserves security-severity findings everywhere**,
  including in vendored code — a vendor vulnerability that ships in our
  binary is real customer exposure regardless of who wrote the bug.
  Companion gist documents the upstream limitation:
  https://gist.github.com/Tr3kkR/73fbe826634f97e97ebb138f4c6b98d8 .
  Without this, every CodeQL run re-creates ~2154 noise alerts on
  vendored/generated paths.
- **CodeQL coverage fix — force compile in tracer step** (`CCACHE_RECACHE=true`
  on `meson compile -C build-linux-codeql`). The tracer cannot observe
  compile invocations that ccache short-circuits; with persistent ccache
  on the self-hosted runner this had been silently dropping 98% of TUs
  from the database since the runner was adopted, masking both standard
  and custom-rule findings. Cost: cold-compile budget (~15-25 min Linux
  vs ~3 min cached) — justified, since CodeQL coverage was the entire
  point.
- **Custom CodeQL query pack at `.github/codeql/queries/`** — Yuzu-specific
  queries that the standard `security-and-quality` suite cannot encode
  because the rules depend on per-project directory scope and the plugin
  threat model (#371). First pass ships two queries:
  `cpp/yuzu/plugin-command-exec-non-literal` (POSIX `system`/`popen`/`exec*`
  in `agents/plugins/<name>/src/*` with a non-literal command argument)
  and `cpp/yuzu/plugin-windows-process-spawn-non-literal` (the Windows
  `CreateProcess*`/`ShellExecute*`/`WinExec` equivalent). The pattern
  matches the four CRITICAL command-injection findings in waves 1-4 — a
  custom query against the Yuzu CodeQL database would have caught all
  four before they shipped. Wired into `codeql.yml` via
  `queries: +security-and-quality,+./.github/codeql/queries`. The
  remaining catalog from #371 (RBAC, audit-field, plugin-export, header-
  bundle queries) is deferred to better-fit tooling — see #371's close-
  out comment for the rationale.
- **`/api/health` alias** of the existing `/health` endpoint (#620).
  Both URLs now serve the same JSON body and both bypass authentication so
  monitoring integrations that prefix every REST call with `/api/` keep
  working. Both are also exempt from API rate limiting (so a NAT'd or
  shared-bucket monitoring host can't 429-starve the probe), matching the
  treatment `/livez` and `/readyz` already get. Restores the path that
  operators had been pointing monitors at before the #401 fix moved the
  canonical health endpoint to `/health`.

  **Body shape now varies by auth.** Unauthenticated callers get the cheap
  probe response: `status`, `uptime_seconds`, `agents.online`, `stores.*`,
  `version`. Authenticated callers additionally get `agents.pending`,
  `executions.{in_flight, completed_last_hour, failed_last_hour}`, and
  `system.*` — these were always populated for everyone before, but
  involve SQLite scans on every request and would be a DoS amplification
  primitive now that the rate limiter no longer caps probe rate. Monitoring
  dashboards that displayed `executions.*` from `/health` should switch
  to the authenticated alternative or query an authenticated REST endpoint.
- **Docs:** `docs/user-manual/server-admin.md` gains a "File Logging"
  section covering `--log-file` semantics and the implicit-default
  fallback, and a "Health Endpoints" section enumerating `/livez`,
  `/readyz`, `/health`, and `/api/health` with guidance on which to use
  for which monitoring scenario.
- **Docs:** `docs/user-manual/rest-api.md` `GET /health` entry now notes
  the `/api/health` alias and the explicit non-draining-aware contract.
- **Docs:** `docs/user-manual/upgrading.md` v0.12.0 section gains an
  "A3 UX ladder (#620, #622, #624)" sub-entry with the operator action
  required for local compose overrides.

### Removed

- **Qodana code-quality workflow and `qodana.yaml`.** The JetBrains Qodana
  scanner was wired up but unused; carrying the workflow added third-party-
  action attack surface and a Token-Permissions Scorecard finding for no
  benefit. Deleted `.github/workflows/qodana_code_quality.yml` and root
  `qodana.yaml`; `scripts/check-compose-versions.sh`-style baseline-bump
  references in `.github/workflows/vcpkg-baseline-update.yml` updated
  accordingly. CodeQL + Scorecard + zizmor remain the active static-analysis
  surface.

### Changed

- **Defensive hardening of `pre-release.yml` against template-injection.**
  Eight `run:` blocks that interpolated `${{ needs.resolve.outputs.version }}`,
  `${{ needs.resolve.outputs.prev_tag }}`, or related workflow_run-tainted
  values directly into bash were refactored to bind them via the step's
  `env:` block and reference the values as `"$VERSION"` / `"$PREV_TAG"` /
  `"$NEW_VER"` in the script body. CodeQL flagged 4 critical
  `actions/code-injection/critical` alerts on this file (lines 68, 84,
  125, 923 in older revisions) — three of those four were already fixed
  in earlier work; this pass extends the same env-binding pattern to
  every other run-block interpolation in the file so future CodeQL
  scans don't re-discover the same shape. Matrix-driven values
  (`${{ matrix.distro }}` in the .deb / .rpm install steps) are kept
  as-is because matrix entries are workflow-author-defined and not
  externally controllable.

- **Static-analysis alert cleanup pass.** Reduced the open code-scanning
  alert backlog by ~70% in one pass:
  - 15 vendored security-severity false-positives in `vcpkg_installed/`
    and `vcpkg/buildtrees/` (abseil/protobuf/httplib/cli11) bulk-dismissed
    as "won't fix" — outside Yuzu's patch surface; will re-dismiss on each
    scan until upstream feedback is sent.
  - 30 stale `zizmor/artipacked` alerts will auto-clear on next zizmor run
    (every active `actions/checkout@v6.0.2` already carries
    `persist-credentials: false`; alerts predate that fix).
  - 8 Scorecard `TokenPermissionsID` alerts dismissed: 5 reflect
    job-level write scopes the action documentation requires (release,
    CLA bot, peter-evans/create-pull-request, Qodana before deletion),
    matching the "top-level read, opt-in per job" policy noted in
    `release.yml`'s comment block; 3 are stale against pre-permissions-
    block commits.
  - 9 cpp/unused-* deletions of truly dead code: unused `run_command*`
    helpers in `network_actions_plugin.cpp` and `event_logs_plugin.cpp`,
    `deployment_status_to_string` in `patch_manager.cpp`, the duplicate
    `json_quoted` and unused `add_cors_headers` in `rest_api_v1.cpp`,
    plus a few stale local-variable bindings.
  - 4 platform-conditional helpers wrapped in matching `#if` so CodeQL
    stops seeing them on the wrong platform: `run_command` in
    `network_diag_plugin.cpp` (`__APPLE__` only), `run_command_exit` in
    `services_plugin.cpp` (`__linux__ || __APPLE__`), `run_command` in
    `ioc_plugin.cpp` (tightened from linux+apple to apple-only),
    `run_command` in `sccm_plugin.cpp` (`_WIN32` only).
  - 24 `[[maybe_unused]]` annotations on idiomatic `std::from_chars`
    structured-binding `[ptr, ec]` / `[_, ec]` sites where only the
    error code is needed.
  - 8 cpp/unused-static-function alerts dismissed where CodeQL ignores
    `[[maybe_unused]]`: settings_routes refactor-staging family pre-
    extracted from the server.cpp god-object decomposition, plus the
    `.CRT$XCB` Windows static-init function-pointer pair in `agent.cpp`
    / `main.cpp` that's reached via linker-section magic CodeQL can't
    follow.

- **Better error message when `POST /api/policy-fragments` (or `/api/policies`)
  receives YAML without a `kind:` field** (#621). The previous body
  `kind must be 'PolicyFragment', got ''` left operators stuck because they
  often sent JSON like `{"kind":"PolicyFragment", "yaml_source":"..."}`
  expecting `kind` to be a request parameter. The error now includes a
  full worked YAML example and a link to `docs/user-manual/policy-engine.md`,
  while keeping the original `kind must be 'PolicyFragment'` (and `'Policy'`)
  prefix so existing operator scripts that grep on it continue to work.
  `docs/user-manual/policy-engine.md` gains a worked `curl` example covering
  both the JSON-envelope and raw-YAML body forms.

### Fixed

- **`device.agent_actions.info` returns the real `plugins_count` and
  the agent.plugins.N.* roster.** Per-plugin `PluginContextImpl` config
  maps were snapshot-copied from `plugin_ctx_.config` during the load
  loop in `agent.cpp`, freezing each one before the agent had populated
  `agent.plugins.count`, `agent.modules.count`, the `agent.plugins.N.*`
  roster, or any `agent.modules.N.*` entries written after that
  plugin's own snapshot point. The `agent_actions:info` action then
  read `(not set)` for `plugins_count` from its frozen context even
  though the master config had the right value. A new
  `sync_master_config_to_plugins` helper (extracted to
  `agents/core/src/plugin_config_sync.hpp` for unit testing) re-walks
  every per-plugin context after load completes and copies in every
  master key. Validated end-to-end: `agent_actions info` from the
  dashboard now returns `agent.plugins.count|45` matching the
  "Loaded 45 plugin(s)" agent log line. Runtime keys written
  post-registration (`agent.session_id`, `agent.reconnect_count`,
  `agent.latency_ms`, `agent.grpc_channel_state`,
  `agent.connected_since`) still observe stale snapshot values — that
  pre-existing gap is tracked separately as `status_plugin runtime
  staleness` follow-up.

- **MCP token authorization restored to documented tier-first design
  (#520, #630, branch `fix/520-630-auth-hardening`).** An earlier
  hardening pass (`5fcb346`..`7c8d4ac`) conflated MCP tokens with
  service-scoped tokens — required RBAC to be enabled and capped MCP
  tokens at `ITServiceOwner` permissions regardless of the creator's
  role. That broke the documented design (`docs/user-manual/mcp.md`
  §"Authorization Tiers"): the tier (`readonly`/`operator`/`supervised`)
  is the primary access boundary, applied independently of RBAC, with
  the creator's actual role as the secondary RBAC layer. The regression
  made MCP unusable for its intended purpose — agentic fleet management —
  on every RBAC-disabled deployment.

  Restored behavior:
  - `auth_routes::require_permission()` and `require_scoped_permission()`
    now call `mcp::tier_allows()` first, then fall through to the
    standard RBAC/role check using the creator's actual role.
  - Tier enforcement now applies on **all** transports (MCP JSON-RPC and
    REST API) — closes a path-bypass where an MCP token used directly
    on `/api/v1/...` could skip the tier check that `/mcp/v1/` enforces.
  - Approval-gated operations (supervised tier on destructive ops) are
    blocked on every transport with a new `auth.approval_required`
    audit action until the Phase 2 re-dispatch path is built. This
    closes a separation-of-duties gap where a supervised MCP token
    issued by an admin could execute destructive operations via REST
    without approval.
  - `require_admin()` MCP block kept — admin/settings routes (user
    management, TLS, OIDC) are not the MCP use case.
  - RBAC-enabled and legacy-fallback denial paths now emit
    `audit_log()` and use the structured JSON envelope, closing prior
    audit-evidence gaps (CC7.2).
  - `settings_routes.cpp` tier-string validation replaced with
    `mcp::is_valid_tier()` to keep the canonical tier set in
    `mcp_policy.hpp` as the single source of truth.

  Audit detail string format changed for MCP-token denials. Operators
  with SIEM rules pattern-matching the old strings (`"MCP token
  blocked: RBAC not enabled"`, `"MCP token blocked: lacks
  ITServiceOwner permission"`) must update them; see
  `docs/user-manual/authentication.md` § "Audit Actions". The broken
  intermediate (`5fcb346`..`7c8d4ac`) never shipped in a release —
  no customer-facing upgrade notes are required.

- **Docker healthchecks for `docker-compose.uat.yml`** (#622).
  The server check used `curl` (not installed in the runtime image); the
  gateway check used `CMD-SHELL` which on Alpine resolves to busybox `sh`
  with no `/dev/tcp`. Replaced with `bash` + `/dev/tcp` (server, matches
  `deploy/docker/docker-compose.reference.yml`) and busybox `wget --spider`
  (gateway, no shell required). The compose stack now reports `healthy`
  in `docker inspect`. Operators with a local copy of the same broken
  pattern (e.g. an untracked `docker-compose.local.yml`) should mirror
  the same change — see `docs/user-manual/upgrading.md`.
  The bash healthcheck explicitly closes FD 3 after the grep to avoid
  leaking CLOSE_WAIT sockets under sustained probe cadence.
- **Server log directory in container deployments** (#624).
  `Dockerfile.server` now creates `/var/log/yuzu` with mode 0750 and the
  right ownership during the runtime stage, aligning with the deb postinst
  and preventing log disclosure to other UIDs in the container. The
  unconditional file-logger setup in `server.cpp` no longer logs
  WARN/ERROR on failure — when the default log path is not writable it
  now drops to a single INFO line and proceeds, since file logging is
  best-effort observability. INFO (not DEBUG) is the right level so
  operators auditing the SOC 2 evidence chain or troubleshooting "where
  did my logs go?" still get a visible breadcrumb at default loglevel.
  Operators who want explicit on-disk logs can pass `--log-file <path>`;
  explicit-path failures still log at ERROR.

### Tests

- **Response Templates governance hardening test additions.** 11 new cases
  in `tests/unit/server/test_rest_response_templates.cpp` covering the
  Gate 7 hardening round: PUT-with-non-existent-template_id 404
  (qe-B1), DELETE-of-operator-default re-instates synth (qe-B2),
  malformed template_id rejected by route regex (qe-B4), PUT/DELETE/POST
  403 paths (qe-S2), 503 path on POST/PUT/DELETE with null store
  (qe-S6), oversized POST body returns 413 + failure audit (UP-8 +
  sec-M1), success audits asserted on POST/PUT/DELETE (qe-S1 / sec-M1),
  POST validation failure emits failure audit (sec-M1),
  `import_definition_json` strips reserved `__default__` id (S-4),
  oversized string-form import dropped to `[]` (sec-M4), and a
  full-cycle migration v3 probe-and-stamp regression test (qe-B3) that
  pre-seeds a DB with the column already present + `schema_meta` at v1
  and verifies the InstructionStore opens cleanly. Total response-
  templates suite now 43 cases / 237 assertions (was 32 / 154).

- **Response Templates engine + REST coverage** (issue #254). New
  `tests/unit/server/test_response_templates_engine.cpp` (18 cases /
  pure-engine: parse round-trip incl. singular form, malformed JSON,
  default synthesis from `result_schema` and from plugin column schema,
  `resolve()` precedence rules, `validate_payload()` rejecting
  `__default__` as authored id / missing name / unknown filter op /
  multiple `default:true` / id collisions, serialise→parse round-trip)
  and `tests/unit/server/test_rest_response_templates.cpp` (14 cases,
  HTTP-level via `TestRouteSink`: synth-default visibility rules,
  POST→list→PUT→DELETE round-trip, 400 on `__default__` mutation,
  `result_schema` populating synthesised columns, 403/503/404 paths).
  All 32 cases / 154 assertions green on first run; `[instruction_store]`
  + `[visualization]` + `[rest][visualization]` regression-set still
  green (62 cases, 285 assertions).

- `tests/unit/test_trigger_engine.cpp`,
  `tests/unit/server/test_patch_manager.cpp` — `[[maybe_unused]]` on three
  `auto& [plugin, action, params]` structured bindings (only one binding
  is asserted on per test) and removal of an unused `bool found_reboot`
  in the patch_manager Windows-reboot test, in step with the
  static-analysis alert-cleanup pass.

- `tests/unit/server/test_agent_service_impl.cpp` — new file, 9 cases /
  47 assertions covering `AgentServiceImpl::record_execution_id` and
  `AgentServiceImpl::process_gateway_response`. Closes the gap explicitly
  deferred at `tests/unit/server/test_workflow_routes.cpp:820` ("no
  AgentServiceImpl in ExecHarness") by constructing a real
  AgentServiceImpl and driving response receipt end-to-end into a real
  `ResponseStore`. Pins four contracts from #117's response-streaming
  call-out: (1) `record_execution_id` registers and clears the
  command_id → execution_id mapping; (2) `process_gateway_response`
  stamps execution_id on RUNNING streaming rows, terminal SUCCESS rows,
  terminal FAILURE rows (with `error_detail`), and degrades to empty
  execution_id for unmapped command_ids; (3) the HF-1 multi-agent
  fan-out invariant — the terminal branch does NOT erase the mapping,
  so 4 agents responding to the same `command_id` (with mixed terminal
  statuses SUCCESS/FAILURE/TIMEOUT) all stamp the same `execution_id`;
  (4) the `__timing__|...` sentinel takes the early-return branch in
  the RUNNING handler and does NOT persist a row. The pre-existing
  `test_workflow_routes.cpp:814` pin exercised the response-store level
  only; this new file exercises the `process_gateway_response` upstream
  path that the comment said had to be deferred to UAT. (#117)
- `scripts/start-UAT.sh` (formerly `linux-start-UAT.sh`) — added
  regression assertion that `/health`
  and `/api/health` return 200 AND identical JSON bodies, guarding
  against both the #620 regression and a future split of the dual-mount
  handler lambda.
- `tests/unit/server/test_policy_store.cpp` — extended the existing
  wrong-kind / missing-kind cases to assert the new helpful content
  (`apiVersion: yuzu.io/v1alpha1` substring + docs link), so the
  improvement is pinned by the test surface rather than relying on a
  fragile substring match. Adds a missing-`kind:` test for `create_policy`
  (governance Gate 7 hardening — was asymmetric with `create_fragment`)
  and pins the docs link on the `create_fragment` missing-kind branch
  for the same symmetry reason.

## [0.12.0-rc0] - 2026-05-03

### Breaking

- **`POST /api/settings/users` `role` field is now ignored.** New users are
  always created with `role=user` regardless of what the form body sends.
  Operators that scripted user-create calls with `role=admin` should expect
  the user to land as `user` and explicitly promote them via the new
  dedicated endpoint:

  ```
  POST /api/settings/users/{username}/role
  Content-Type: application/json
  { "role": "admin" }
  ```

  Rationale (security C1, governance Gate 4): collapsing privilege change
  into the create endpoint allowed a 4xx-on-create + audit-as-success
  pattern that was hard to reason about. The dedicated role endpoint emits
  a single `user.role_change` audit event with `old_role` / `new_role` in
  the detail field, invalidates active sessions for the target user, and
  has its own RBAC + denied-branch audit chain (see `### Security` below).

### Added

- **Plugin code signing — CMS detached-signature verification + Settings UI** (#80).
  Two-layer supply-chain check on every plugin: the existing
  `--plugin-allowlist` (filename → SHA-256) is now joined by an
  operator-managed CA trust bundle that the agent uses to verify a
  sibling `<plugin>.so.sig` (PEM CMS detached) before `dlopen`.
  Verification runs **before** `dlopen`/`LoadLibrary` so a tampered or
  untrusted binary never executes code. The trust anchor is
  deployment-format-agnostic — operators can use a public CA, an
  internal CA, or (forthcoming) the Yuzu self-managed CA. The Yuzu
  release pipeline does not yet sign the in-tree `agents/plugins/`;
  see the *Fleet-suicide caveat* in `docs/user-manual/server-admin.md`
  for rollout guidance.

  **Agent surface.** Two new CLI flags + env-var equivalents:
  - `--plugin-trust-bundle <path>` (`YUZU_PLUGIN_TRUST_BUNDLE`) — PEM
    file with one or more X.509 CA certificates. Enables verification.
  - `--plugin-require-signature` (`YUZU_PLUGIN_REQUIRE_SIGNATURE`) —
    when set, plugins without a `.sig` sibling are rejected. When
    unset (default), unsigned plugins still load (transitional mode
    for ops rolling out signing). Passing this flag with an empty
    trust-bundle path causes the agent to refuse to start, preventing
    the silent fail-open that would otherwise occur.

  Default behaviour for deployments that do not set the new flags is
  unchanged. The verifier enforces `X509_PURPOSE_CODE_SIGN` — a leaf
  without `EKU=codeSigning` is rejected even if it chains to a CA in
  the trust bundle, so a single internal PKI does not implicitly
  authorise its mTLS / S/MIME / TLS-server siblings to sign plugins.

  **Server surface.** New **Settings → Plugin Code Signing** card with
  status badge, multipart PEM upload (256 KB cap, OpenSSL-validated on
  the way in), Require-signed-plugins toggle, and Remove-bundle
  button. Bundle metadata (cert count, SHA-256, up to 16 subjects) is
  recomputed from the file at render time so disk + DB cannot drift.
  PEM persists atomically (temp + rename) at
  `<cert-dir>/plugin-trust-bundle.pem`; the require flag persists in
  `runtime_config` as `plugin_signing_required`.

  **REST routes.** `GET /fragments/settings/plugin-signing` (admin
  HTML), `POST /api/settings/plugin-signing/{upload,clear,require}`
  (admin, HTMX), `GET /api/v1/agent/plugin-policy` (admin only,
  returns JSON `{enabled, required, trust_bundle_pem, cert_count,
  sha256}` for out-of-band operator distribution to agents — automatic
  agent-side fetch is a forthcoming change).

  **Audit + metrics.** Three new actions
  (`plugin_signing.bundle.uploaded` /
  `plugin_signing.bundle.cleared` / `plugin_signing.require.changed`)
  using the standard `success/failure/denied` result vocabulary, with
  `target_type` of `PluginTrustBundle` (bundle ops) or `RuntimeConfig`
  (require-flag toggle). Three new label values on
  `yuzu_agent_plugin_rejected_total{reason}`: `signature_missing`,
  `signature_invalid`, `signature_untrusted_chain` — distinct from
  the existing `reserved_name` and `load_failed` buckets so operators
  can alert per category. Operator workflow + `openssl cms -sign`
  recipe in `docs/user-manual/agent-plugins.md` § Plugin Code
  Signing; full REST contract in `docs/user-manual/rest-api.md`
  § Settings — Plugin Code Signing; upgrade notes in
  `docs/user-manual/upgrading.md`.

- **Persistent SQLite-backed authentication.** `auth.db` (in `--data-dir`)
  now holds user accounts, sessions, and enrollment tokens with PBKDF2-SHA256
  hashed passwords. Replaces the prior in-memory + on-config-flush model
  that lost users on every restart (#618). File is created with mode 0600
  on Linux; migrations are versioned via the same `MigrationRunner`
  pattern as the other stores (instruction, response, audit, etc.).
  Backup procedure: `sqlite3 /var/lib/yuzu/auth.db ".backup ..."` — never
  `cp` against a live WAL. First-boot seeds from `yuzu-server.cfg`; on
  restart the DB is authoritative and the config seed is no-op. Recovery
  procedure for a corrupt `auth.db`: see `docs/ops-runbooks/auth-db-recovery.md`.

- **Dedicated role-change endpoint with full audit chain.**
  `POST /api/settings/users/{username}/role` (admin-only) accepts
  `{"role": "admin"|"user"}` and emits `user.role_change` audit on every
  branch — success, self-target denied, invalid_username, missing_role,
  invalid_json, invalid_role, user_not_found, db_failure, plus a `no_op`
  result when the requested role matches the current role. Closes
  governance PR4 audit-coverage gap. Sessions for the demoted/promoted
  user are invalidated atomically with the role write so existing tabs
  re-authenticate against the new role.

- **`/sse/executions/{id}` audit policy clarification.** Every successful
  subscribe emits `execution.live_subscribe` (target_type=Execution,
  target_id={id}, result=success). Per-session-per-execution dedup is
  deferred (#700) — until then, operators on the SOC 2 evidence chain
  receive a row per reconnect; the forensic-grade audit on first-load
  remains on `/fragments/executions/{id}/detail`'s
  `execution.detail.view`.

- **Login-latency observability.** New histogram
  `yuzu_auth_login_duration_seconds{method="password",result=...}`
  observes PBKDF2 verify time on every login attempt. Result label is
  `success`, `bad_password`, or `unknown_user` so SREs can alert on
  success-path regressions independently of brute-force noise on the
  failure paths.

- **Audit-pipeline observability.** New counter
  `yuzu_server_audit_emit_failed_total` increments when
  `AuditStore::log()`'s `sqlite3_step` returns anything other than
  `SQLITE_DONE`. SOC 2 CC7.2 gate — alerting on a non-zero rate
  surfaces audit-chain degradation that was previously silent.

- **`auth.admin_required` audit on every privileged-endpoint 403.**
  `AuthRoutes::require_admin` emits an audit row with
  `target_type=endpoint, target_id=req.path, result=denied` on every
  role-mismatch rejection. Closes the gap where dozens of admin-only
  routes rejected non-admin callers without surfacing the attempt in
  `audit_store`. SOC 2 CC7.2.

- **Restart-loop guard on systemd units.**
  `deploy/systemd/yuzu-server.service` and
  `deploy/systemd/yuzu-gateway.service` now declare
  `StartLimitIntervalSec=60` + `StartLimitBurst=3` in `[Unit]` so a
  recurring crash (e.g. corrupt `auth.db` failing the integrity check)
  puts the unit cleanly into `failed` instead of spinning indefinitely.
  See `docs/ops-runbooks/auth-db-recovery.md` for the recovery
  procedure once a unit lands in `failed`.

- **`LimitNOFILE=65536` on systemd units + `ulimits.nofile` 65536 on
  Docker compose.** Default 1024 caps the server at ~16k SSE
  connections and the gateway at ~700 agents under fanout. Aligned
  systemd + compose so containerised and bare-metal deployments
  behave identically.

- **`docs/ops-runbooks/auth-db-recovery.md`** — Linux + Windows
  recovery procedure when `auth.db` integrity check fails at startup,
  WAL-aware backup procedure, Windows Defender exclusion list for
  `auth.db*`, filesystem-permission audit (0600 on Linux).

- **Live drawer updates via SSE (PR 3 of executions-history ladder).**
  `GET /sse/executions/{id}` opens a per-execution Server-Sent Events
  channel that pushes `agent-transition` (one per agent state change),
  `execution-progress` (counts snapshot when the recompute crosses the
  all-agents-responded threshold), and `execution-completed` (terminal
  status) events. RBAC `Read` on `Execution`; 410 Gone for
  already-terminal executions so the browser stops reconnecting; 503
  when the bus is not configured. New `ExecutionEventBus`
  (`server/core/src/execution_event_bus.{hpp,cpp}`) backs the channel —
  per-execution ring buffer (1000 events, ~30s window) supports
  `Last-Event-ID` replay on reconnect; channels GC'd 60s after terminal
  status and zero subscribers via opportunistic sweep on `publish` so
  no separate timer thread is required. Server constructs the bus
  alongside `ExecutionTracker` and calls `set_event_bus` so
  `update_agent_status` / `refresh_counts` / `mark_cancelled` publish
  transitions automatically. Drawer JS in `instruction_ui.cpp` opens an
  `EventSource` only when the row was rendered with status=running or
  pending (data-execution-status / data-execution-id stamps); the
  listener applies in-place DOM updates against `#exec-kpi-{id}`,
  `.agent-cell[data-agent-id]`, `tr[data-agent-id]` (per-agent table
  row), `.per-agent-status`, and `.per-agent-exit-code`. Closes the
  reload-to-watch-fan-out UX gap.

- **WorkflowRoutes deps-struct refactor (PR 2.5, #670, hard
  predecessor for PR 3).** `WorkflowRoutes::register_routes` now takes
  a single `Deps` aggregate instead of 16 positional arguments. Both
  the `httplib::Server&` and `HttpRouteSink&` overloads share the same
  signature; new dependencies (the SSE event-bus pointer was the
  trigger) are added as fields, not parameters. Mechanical update at
  the two call sites (`server.cpp`, `test_workflow_routes.cpp`); no
  behaviour change.

- **Exact correlation between executions and responses (PR 2 of
  executions-history ladder).**
  `responses.execution_id` is a new column (migration v2 on
  `response_store`) populated at write time by an in-memory
  `command_id → execution_id` mapping that the dispatch path registers
  with `AgentServiceImpl::record_execution_id` after
  `ExecutionTracker::create_execution` returns the new id. The mapping
  is auto-erased on terminal status (DONE / ERROR) so the map size is
  bounded by the number of in-flight commands. Backed by partial index
  `idx_resp_execution_ts ON responses(execution_id, timestamp) WHERE
  execution_id != ''` — the index is slim because legacy / out-of-band
  rows with the empty-string sentinel are excluded. New helper
  `ResponseStore::query_by_execution(execution_id, ResponseQuery{...})`
  returns rows whose `execution_id` matches; rejects empty input
  (returns no rows) so callers can detect "no PR-2 data" and fall back
  to the timestamp-window join.

  Closes UP-8 (response cross-contamination) from PR 1's governance
  Gate 4 risk register: two concurrent executions of the same
  definition to overlapping agent sets no longer show each other's
  responses in the inline drawer. The timestamp+agent join was a
  best-effort heuristic; PR 2 makes correlation exact going forward.

  Pre-PR-2 rows (execution_id='') stay legible via a fallback in the
  detail handler that runs the legacy `query()` and filters to agents
  in this execution's set. The fallback is gated on "no PR-2 rows
  exist for this id" so it cannot dilute correctly-tagged drawers.
  An admin backfill CLI (`yuzu-server admin backfill-responses`) is
  **planned in PR 2.1 — not yet shipped in this release**; the command
  does not exist on disk. Once it lands and confirms 100% coverage, the
  fallback branch in the detail handler can be removed.

  **Dispatch-path coverage scope.** Only `POST /api/instructions/:id/execute`
  is wired to register the mapping in PR 2. Workflow-step dispatch
  (`POST /api/workflows/:id/execute`), MCP `execute_instruction`,
  scheduled / approval-triggered dispatch, and rerun-via-`create_rerun`
  produce responses with `execution_id=''` and use the legacy fallback.
  Closing those surfaces is the scope of PR 2.x follow-ups.

  **Server-restart caveat.** The `command_id → execution_id` mapping
  is held in memory inside `AgentServiceImpl::cmd_execution_ids_`. If
  the server restarts mid-execution, the mapping is lost — agent
  responses arriving post-restart for in-flight commands stamp empty
  `execution_id` and use the legacy fallback.

  **Performance contract — partial-index predicate** (governance
  perf-B1). SQLite's planner does NOT use `idx_resp_execution_ts` for
  a `WHERE execution_id = ?` bind alone; the WHERE clause must
  syntactically subsume the partial-index predicate `execution_id != ''`.
  `query_by_execution`'s SQL includes the redundant `AND execution_id != ''`
  exclusively for planner eligibility — the early-return guard at the
  top of the method ensures the clause is always trivially true.

  **FAST-agent race close** (governance UP2-4). The dispatch path now
  creates the execution row BEFORE calling `cmd_dispatch` and threads
  `execution_id` THROUGH the dispatch closure (new parameter on
  `CommandDispatchFn`). The closure registers the
  `command_id → execution_id` mapping with `AgentServiceImpl` BEFORE
  any RPC is sent — closing the race where a sub-millisecond loopback
  agent could reply before a post-dispatch register-mapping call
  landed. Backwards-compatible: callers passing empty `execution_id`
  (workflow steps + non-tracker dispatch surfaces) skip registration
  with no behaviour change vs. pre-PR-2.

  **Multi-agent fan-out invariant** (governance HF-1). A single
  `command_id` is dispatched to N agents and produces N responses;
  the terminal-status branches in `agent_service_impl.cpp` no longer
  erase `cmd_execution_ids_` (erasing on the first agent's terminal
  would leave agents 2..N stamping empty `execution_id`). Map entries
  persist for the process lifetime; a periodic sweeper is filed as
  PR 2.x — accepted bounded leak (sec-M1 / perf-S1) for the same
  reason `cmd_send_times_` and `cmd_first_seen_` carry the same
  shape today.

  **Phantom-execution-row close** (governance Pattern-C re-review).
  The reorder of `create_execution` BEFORE `cmd_dispatch` (needed for
  the UP2-4 race fix above) initially left an orphan row at
  `status='running'` whenever dispatch failed (sent=0 or thrown).
  Both failure paths in `/api/instructions/:id/execute` now call
  `ExecutionTracker::mark_cancelled` to record the failed-dispatch
  attempt for forensic audit instead of orphaning a phantom in-flight
  row. Pinned by a regression test.

  Migration uses the same probe-and-stamp idempotency dance as
  `instruction_store`'s v2 migration (governance arch-B2 / CP-5) so
  re-opening a DB that already has the column does not wedge on
  duplicate-column ALTER. Forward-compat: writers always bind the
  column; readers that don't care leave the field empty in
  StoredResponse.

  No proto changes, no plugin ABI changes, no agent-side changes —
  the agent's CommandResponse already carries `command_id` and the
  server-side mapping handles the rest.

- **Instructions → Executions tab — clickable history + per-execution drawer
  (PR 1 of executions-history ladder).**
  The Executions tab is no longer a flat text list. Each row carries a
  4-segment SVG status sparkbar (succeeded / failed / running / pending —
  length encodes count, hue encodes status, widths sum to exactly 120 px
  with rounding residue absorbed by the last non-zero segment), the
  resolved definition name (with id-prefix fallback), relative time in
  the cell with ISO-8601 UTC in `title=` for forensic copy/paste, a
  3 px error-color left stripe on failed rows, and — for failed rows —
  a UTF-8-safe 80-char truncation of the most recent agent error
  populated via a gated correlated subquery on `executions` (zero query
  cost when `agents_failure == 0`). Clicking a row lazy-loads
  `/fragments/executions/{id}/detail` once via HTMX `hx-trigger="click once"`
  and expands an inline drawer beneath. The drawer is laid out as four
  scan-tiers in priority order: a KPI strip (Total / Succeeded / Failed /
  p50 / p95 duration; "—" when any agent is still running), a
  CSS-grid agent fan-out as small multiples (12×12 px cells colored by
  status; bucketed into deciles when `agents_targeted > 1024` so a
  10 000-agent execution doesn't ship 10 000 DOM nodes), a per-agent
  table sorted failed-first then by duration descending with an inline
  server-rendered duration bar scaled to the slowest agent in this run,
  and a `<details>`-collapsed responses section so opening a drawer
  doesn't dump 500 rows. Single-drawer-open invariant: clicking row B
  collapses row A's drawer first; keyboard reach via `tabindex="0"` and
  Enter/Space. RBAC: detail handler requires `Read` on `Execution`.
  Information-design discipline: every status conveyed by two channels
  (color + icon/text/shape) for WCAG + colorblind safety; SVG widgets
  carry `role="img"` + descriptive `aria-label` with child `<rect>`
  elements `aria-hidden`; no JS chart library on this surface
  (server-rendered SVG/CSS only, ECharts reserved for the genuinely
  interactive Response Visualization Engine in #253). New web
  helpers in `web_utils.hpp`: `render_status_sparkbar`,
  `render_duration_bar_html`, `format_iso_utc`, `format_relative_time`,
  `now_epoch_seconds`, `truncate_utf8` — all pure, header-only,
  unit-tested. `WorkflowRoutes::register_routes` gains an `HttpRouteSink&`
  overload (matching `SettingsRoutes` / `RestApiV1`) so future executions
  PRs (live SSE updates, comparison view, pagination) can be unit-tested
  in-process without httplib's TSan-hostile acceptor thread (#438).

- **Yuzu design tokens + dark navy palette (dashboard re-skin).**
  91 `--mds-*` CSS custom properties (color / spacing / type / state /
  elevation / indicator) layered into `kYuzuCss`; legacy aliases
  (`--bg`, `--fg`, `--accent`, `--surface`, `--sp-*`, `--text-*`,
  `--radius-*`, `--font-sans/mono`) re-pointed onto the design tokens
  so every component re-skins through the same layer. Default values
  use a deep navy canvas `#0e1a2d`, cyan accent `#00bceb`, and
  mint / gold / coral indicators. Re-skinning Yuzu is now a token
  override, not a CSS rewrite. (#XXX)

- **Inter v4.0 variable webfont shipped (SIL OFL 1.1).**
  Vendored at `server/core/vendor/inter/InterVariable.woff2` (345 KB),
  served at `/static/fonts/InterVariable.woff2` with
  `Cache-Control: public, max-age=2592000, immutable`. One file covers
  weights 100-900 via `font-variation-settings`. `--mds-font-family-default`
  starts with `'Inter'`. Self-hosted — no CDN dependency, air-gap-safe.

- **Apache ECharts 5 chart renderer (Apache-2.0).** Vendored at
  `server/core/vendor/echarts.min.js` (1.0 MB), served at
  `/static/echarts.min.js`. Replaces the previous bespoke SVG
  renderer in `charts_js_bundle.cpp`. Same `[data-yuzu-chart-url]`
  auto-render contract and same JSON payload schema — operators do
  not migrate. Adapter resolves design-system tokens via `getComputedStyle`
  at render time, so palette switches go live without a JS rebuild.
  Empty-data payloads now render an explicit `'No data to plot.'`
  message (matching the prior renderer) rather than a blank canvas.

- **Build-time content auto-import.** All YAML files in
  `content/definitions/*.yaml` and `content/packs/*.yaml` (217
  InstructionDefinitions + 10 InstructionSets at this commit) are
  converted to JSON envelopes at build time by
  `server/core/scripts/embed_content.py` (PyYAML, build-time
  dependency pinned in `requirements-ci.txt`) and embedded in the
  server binary as `kBundledDefinitions` / `kBundledSets`. On every
  startup the server upserts each entry via `import_definition_json`
  and `create_set`. **Conflicts on existing IDs are silently skipped
  — operator-customized definitions are never overwritten.** This
  is BREAKING for one specific case: definitions an operator
  previously DELETED will reappear on next restart. To permanently
  suppress a shipped definition, set `enabled: false` via the
  dashboard or `PATCH /api/v1/definitions/{id}` rather than DELETE.
  Each successful import / errored import emits an
  `audit_events.action="content.bundled_import"` row with
  `principal=system` for SOC 2 traceability. Sidesteps yaml-cpp on
  Windows MSVC (#625).

- **Inter, ECharts, HTMX, htmx-ext-sse attribution in `NOTICE`.**
  Closes a long-standing gap for HTMX (0BSD) which was already
  vendored. ECharts upstream NOTICE vendored at
  `server/core/vendor/echarts-NOTICE.txt` per Apache 2.0 §4(c).

- **Build-time embed scripts** in `server/core/scripts/`:
  `embed_js.py` (chunked raw-string-literal generator for arbitrary
  vendored JS, sized to MSVC's 16,380-byte C2026 limit),
  `embed_binary.py` (constexpr byte-array generator for binary
  assets), `embed_content.py` (YAML→JSON envelope converter for
  shipped instruction content). These replace hand-written chunked
  literals; future vendor additions should use the scripts.

- **`tests/puppeteer/echarts-smoke.mjs`** — regression test for the
  ECharts adapter; renders all five chart types against synthetic
  payloads and verifies design-system tokens resolve correctly.

- **Test pinning for embedded asset symbols** in
  `tests/unit/server/test_static_js_bundle.cpp`: pinned size +
  content sentinels for `kEChartsJs`, `kInterVariableWoff2`,
  `kYuzuCss`, `kYuzuChartsJs`. Plus `kConflictPrefix` contract tests
  for `import_definition_json` and `create_set` in
  `tests/unit/server/test_instruction_store.cpp` so a future error-
  string drift cannot silently miscount the boot-time auto-import.

- **Visualization engine: optional row pre-filter (`whereField` /
  `whereEquals`).** Lets a chart isolate one logical category of rows
  from a plugin that emits a mixed `key|value` row layout (firewall,
  bitlocker, antivirus, os_info, …). Spec authors set `whereField` to a
  column index and `whereEquals` to the required value; rows whose
  field at that index doesn't match are skipped before bucketing. The
  filter is conjunctive with the existing `labelField` / `valueField`
  extraction. Half-config (one of the pair set, the other absent) is
  silently disabled rather than half-applied — half-applied filters
  produce non-deterministic charts depending on row order. Documented
  in `docs/yaml-dsl-spec.md` § `spec.visualization`. Live use: every
  one of the six chart-bearing demo definitions added in this release
  except `vuln_scan.scan` and `os_info.os_name`. Tracking issue #626
  covers the matching value-substring extractor for plugins whose
  values themselves carry pipe-delimited sub-fields (firewall's
  `Domain|enabled`, bitlocker's full volume descriptor) — this PR's
  filter handles the row-selection half; #626 will close the
  field-extraction half.

- **Six demo charts ship as default examples for the Phase 8.1 Response
  Visualization Engine (#253 — closes the issue).** `spec.visualization`
  blocks added in-place to six existing instruction definitions, covering
  every processor (`single_series`, `multi_series`) and the most-used
  chart types (`pie`, `column`):
  - `security.vuln_scan.summary` — pie of vulnerabilities by severity
    (`labelField: 0` severity + `valueField: 1` count summed across
    devices). The headline demo chart.
  - `security.antivirus.defender_status` — pie of Windows Defender
    real-time protection state across the fleet.
  - `security.encryption.state` (BitLocker / LUKS / FileVault) — pie of
    volume `protection_status`.
  - `security.firewall.state` — column chart, multi-series, one column
    per profile (Domain/Private/Public on Windows; firewalld / ufw /
    iptables / pf elsewhere) and one series per state (ON/OFF).
  - `security.certificates.list` — pie of certificates by issuer with
    `maxCategories: 8` (top-N + "Other"). Most informative when run
    with `expiring_within_days: 90` so the chart focuses on certs
    needing renewal.
  - `device.os_info.os_name` — pie of OS distribution across the fleet
    with `maxCategories: 8`.

  Bundled as `InstructionSet demo.visualization.fleet-posture` in
  `content/definitions/visualization_demo_set.yaml` and as
  `ProductPack pack.demo.visualization` in
  `content/packs/visualization-demo-pack.yaml` (the new `content/packs/`
  directory is conventional shipping ground for example product packs).
  Both ship unsigned because they carry only read-only `question`
  definitions sourced from the in-tree library — production / customer
  packs should still be signed per `docs/yaml-dsl-spec.md` §8.

  Use the dashboard YAML import view or
  `POST /api/v1/product-packs` to install the pack against a UAT or
  demo fleet; running any of the six instructions then auto-renders the
  declared chart above the standard results table.

### Security

- **C1 closed — privilege-escalation via the user-create role parameter.**
  `POST /api/settings/users` ignores the `role` field; the only path to
  promote/demote is `POST /api/settings/users/{username}/role`. Audit
  events on the new endpoint emit `old_role` and `new_role` so SIEMs
  can detect anomalous role transitions without inferring intent from
  the request body.

- **C2 closed — atomic enrollment-token consumption.** Token validation
  + use_count increment now happens inside a single `BEGIN IMMEDIATE`
  transaction, eliminating the TOCTOU window where two concurrent
  enrollments against the same single-use token could both succeed.

- **C3 closed — OIDC admin role assignment.** Admin role is granted
  ONLY when the OIDC `groups` claim contains the configured admin
  group id (`--oidc-admin-group`). Email/name match no longer escalates
  to admin. Operators relying on the legacy email-match shortcut must
  add their admins to the configured Entra group.

- **`auth.db` is created with mode 0600 on Linux** (owner read/write
  only). On Windows the equivalent restricted ACL is applied via
  `CreateFile`. World-readable hashes are not produced.

- **Audit chain coverage on every privileged-mutation denied branch.**
  `POST /api/settings/users/{username}/role` (8 denied codes), `DELETE
  /api/settings/users/{name}` (`invalid_username`, `user_not_found`,
  `self_delete_blocked`), and the centralised `auth.admin_required`
  rejection in `AuthRoutes::require_admin` now all emit `audit_fn_(...,
  "denied", ..., reason)`. SOC 2 CC7.2 evidence chain.

### Tests

- **Gateway perf baseline calibration captured at N=300 (#738, ref
  #530).** Five-hour overnight run on Shulgi (5950X, quiet box,
  2026-05-02 23:00 UTC → 2026-05-03 04:16 UTC, exit=0, 300/300
  samples). Raw data at `tests/perf-baseline-provenance-N300.jsonl`,
  derived stats at `tests/perf-baseline-provenance-N300.json`. The
  capture confirms what the N=20 trial suggested: 3 of the 4
  gateway perf metrics (`registration_ops_sec`,
  `burst_registration_ops_sec`, `session_cleanup_ms_per_agent`) are
  not Gaussian and σ-bounding them is statistically inappropriate —
  `registration_ops_sec` is hard-ceiling-bounded with 70% of samples
  within 5% of the 19,200 ops/sec ceiling; `session_cleanup_ms_per_agent`
  is dominated by a single race-condition outlier; only
  `heartbeat_queue_ops_sec` (CV 6.45%, |skew| 0.11, |kurt-3| 0.33,
  280/300 distinct values) fits the Gaussian assumption. The full
  finding plus inline ASCII histograms is recorded in
  `docs/perf-baseline-calibration-2026-05-03.md`. Perf-gate redesign
  to percentile floors for ceiling-bounded metrics is deferred to a
  later cycle; in the interim the gate runs as-is and human
  judgement is the loop.
- **PR 3 coverage net — `tests/unit/server/test_execution_event_bus.cpp`
  (new file)** — 10 Catch2 cases / 1039 assertions tagged
  `[execution_event_bus][pr3]`: subscribe/publish/unsubscribe round-trip
  on a single channel; per-execution channel partitioning (subscribers
  on exec A receive zero events for exec B and vice versa, with each
  channel keeping its own monotonic id space); ring buffer caps at
  `kBufferCap=1000` with FIFO eviction; `replay_since` is strictly
  greater-than (Last-Event-ID semantics); terminal flag and GC retention
  (channels with subscribers are not evicted; channels with retention
  expired AND no subscribers are); listener invocation is synchronous
  within `publish` (no event lost across the publish→listener boundary);
  concurrent publishers never lose events (4 threads × 250 publishes =
  1000 monotonic ids, no gaps); `subscriber_count` / `channel_count`
  smoke; `unsubscribe` is idempotent; `snapshot` is a copy not a view.
- **PR 3 coverage net — `tests/unit/server/test_workflow_routes.cpp`**
  — 12 new Catch2 cases tagged `[workflow][executions][pr3]`:
  `/sse/executions/{id}` 404 on unknown id; 410 Gone on already-terminal
  execution; 403 when `perm_fn` denies `Execution.Read`; 200 + correct
  Cache-Control / X-Accel-Buffering headers on a happy-path running
  execution; integration that `update_agent_status` publishes
  `agent-transition` onto the bus (subscribe directly, watch the
  events flow); integration that `refresh_counts` crossing the
  threshold emits both `execution-progress` AND `execution-completed`
  with progress-before-terminal ordering; `mark_cancelled` emits the
  terminal `execution-completed`; ring buffer holds events for late
  connectors; per-execution channel partitioning under the routes
  layer (no cross-leak between two concurrent executions of the same
  definition); list view stamps `data-execution-id` and
  `data-execution-status` for the JS SSE bootstrap; detail KPI strip
  carries `id="exec-kpi-{id}"` for partial swaps; per-agent status
  badge has `.per-agent-status` + `.per-agent-exit-code` classes for
  partial swaps. `ExecHarness` gained an `event_bus` member that is
  attached to the tracker before any test runs and torn down before
  the tracker on harness destruction (preserves the
  bus-outlives-tracker invariant the production code relies on).
- **PR 3 puppeteer smoke extension —
  `tests/puppeteer/executions-drawer-smoke.mjs`** — added two new
  assertions: every `.exec-row` carries both `data-execution-id` and
  `data-execution-status` attributes (the drawer's SSE bootstrap
  binding), and the open drawer's KPI strip carries an
  `id="exec-kpi-{id}"` stamp (the partial-swap binding). Failure of
  either is a markup contract regression that breaks live updates
  silently.

- **PR 2 coverage net — `tests/unit/server/test_response_store.cpp`**
  — 6 new Catch2 cases tagged `[response_store][execution_id]`:
  default-empty for legacy writers; round-trip when the dispatch path
  stamps it; `query_by_execution` returns only matching rows
  (provably no cross-contamination across two same-definition
  executions); empty-execution_id sentinel rejected by
  `query_by_execution`; agent_id / since-until / status filters honour
  on the new query path; migration v2 idempotency (re-open a v2 DB and
  confirm the ALTER doesn't fire twice + existing tagged rows survive).
- **PR 2 coverage net — `tests/unit/server/test_workflow_routes.cpp`**
  — 3 new Catch2 cases tagged `[workflow][executions][detail][pr2]`:
  the cross-contamination scenario (two concurrent executions of the
  same definition to the same agent — each detail drawer sees only
  its own response, proving exact correlation); legacy
  timestamp-window fallback is reachable when only pre-PR-2
  (execution_id='') rows exist for the run; the fallback is suppressed
  when ANY PR-2 row exists for this execution_id, so legacy rows
  cannot dilute correctly-tagged drawers. New `store_response` helper
  on `ExecHarness` accepts an optional `execution_id` so future PR 2.x
  follow-ups can extend the regression net without rewriting fixtures.

- **PR 2 Gate-7 hardening regression net** — 4 new Catch2 cases
  pinning the contracts closed by the governance hardening rounds.
  - `cmd_dispatch receives non-empty execution_id when create_execution
    succeeds` (`[workflow][executions][pr2][hardening]`) — captures
    the value passed to the cmd_dispatch stub via the new
    `last_dispatch_execution_id` field on `ExecHarness`. Proves UP2-4
    close: the FAST-agent race is closed because `record_execution_id`
    runs INSIDE the dispatch closure before any RPC; by the time
    cmd_dispatch returns, the mapping is registered.
  - `query_by_execution includes the partial-index predicate
    'execution_id != ''' in its SQL (perf-B1)` — exercises mixed
    PR-2 and legacy rows; would surface a regression where the
    redundant-but-required predicate is dropped from the SELECT.
  - `multi-agent fan-out — terminal-branch does NOT erase the mapping
    (HF-1)` — stores two responses with the same `execution_id` and
    asserts both appear in `query_by_execution`. Pre-fix erasing on
    first agent's terminal would drop one row from the drawer.
  - `failed dispatch does NOT orphan a phantom 'running' execution
    row (Pattern-C regression close)` — dispatches against a stub
    returning sent=0; asserts the resulting execution row is in
    `cancelled` status, not `running`. Pins the `mark_cancelled` call
    that the create_execution-before-dispatch reorder introduced.
  Plus the new `last_dispatch_execution_id` field on `ExecHarness`
  so future PR 2.x tests can exercise dispatch-time mapping behaviour.

- **Gate-7 hardening regression net for executions PR 1** — 5 new
  Catch2 cases pinning the contracts that closed the governance
  hardening-round findings.
  - `executions list: 403 when perm_fn denies (sec-M1)` —
    `[workflow][executions][list][rbac]`. Dispatches LIST with
    `perm_grant=false` and asserts 403, proving the new
    `perm_fn(Execution, Read)` gate fires before any rendering work.
  - `executions detail: agent_id with single-quote is bound via data-*
    attrs, not interpolated into JS (UP-1)` —
    `[workflow][executions][detail][xss]`. Feeds `agent'with'quote`
    through the renderer; asserts (a) `scrollToAgentRow(` does not
    appear in the rendered HTML, (b) `data-agent-id="agent&#39;with&#39;quote"`
    does. Pins the JS-context-XSS fix against any future revert that
    re-introduces the inline-onclick interpolation pattern.
  - `ExecutionTracker.query_executions: include_error_detail default
    false leaves the field empty (arch-B2 hot-path)` —
    `[workflow][executions][tracker]`. Default-constructed
    ExecutionQuery does NOT trigger the correlated subquery; protects
    server.cpp:1727's `query_executions({.limit=1000})` health-tick
    from regressing back to 1000 partition sorts per call.
  - `ExecutionTracker.get_execution: always populates last_error_detail`
    — `[workflow][executions][tracker]`. Single-row reads (rare) opt
    in unconditionally; pins the contract that detail handler / MCP
    `get_execution_status` / unit tests get the field populated.
  - `ExecutionTracker.query_executions: agents_failure>0 with empty
    error_detail yields empty last_error_detail (qa-S4)` —
    `[workflow][executions][tracker]`. Pins the silent SQLite
    `col_text(NULL) == ""` contract — an exit-code-only failure with
    no agent error message produces an empty preview, not a crash.
  Two prior cases at `[workflow][executions][tracker]` updated to set
  `q.include_error_detail = true` explicitly so they exercise the
  intended path post-arch-B2.
- **Sparkbar fallback-chain regression test** —
  `render_status_sparkbar: every fill has a two-arg var() fallback (UP-13)`
  in `tests/unit/server/test_web_utils.cpp` `[web_utils][sparkbar][fallback]`.
  Pins all four token-named fills (`--mds-color-bg-success-emphasis`,
  `--mds-color-theme-indicator-error`, `--mds-color-theme-indicator-stable`,
  `--mds-color-theme-text-tertiary`) carry the `,var(--green|red|accent|muted)`
  fallback so a yuzu.css load failure or token rename does not render
  the bar invisible. Two prior sparkbar tests adjusted to match the
  new fill-string format (token-name substring check rather than
  full-`var(...)`-string equality).
- **Test fixture hardening on `ExecHarness`** in
  `tests/unit/server/test_workflow_routes.cpp`:
  - `SqliteHandleGuard` first-member RAII guarantees `sqlite3_close`
    runs even if a constructor `REQUIRE` throws between the
    `sqlite3_open` and the `tracker.reset()` in the destructor (qa-B2
    fixture-leak P0 per `feedback_test_quality.md`).
  - Execution IDs generated via `static std::atomic<int>` counter
    instead of `std::hash<std::string>` (qa-B1) — matches CLAUDE.md
    test-isolation rule against hash-based uniqueness salts.
- **`tests/unit/server/test_web_utils.cpp`** — extended with 18 new
  Catch2 cases for the executions-tab rendering primitives.
  - `format_iso_utc`: dash sentinel for `<= 0`; canonical RFC 3339 form
    for known UTC moments; fixed-width 20-byte output (`YYYY-MM-DDTHH:MM:SSZ`).
  - `format_relative_time`: dash sentinel for `<= 0`; bucketing across
    seconds / minutes / hours / days; future-`then` (clock-skew) clamps
    to "0s ago".
  - `now_epoch_seconds`: monotonicity smoke.
  - `truncate_utf8`: ASCII pass-through under limit, ASCII truncation
    appends U+2026 ellipsis, walks back across both 2-byte (`café`) and
    4-byte (FIRE U+1F525) codepoint boundaries — proves the cell can
    truncate any agent error string without producing invalid UTF-8 that
    breaks browser `title=` rendering or screen-reader announcement.
  - `render_status_sparkbar`: hatched empty state when `total == 0`
    (with `aria-label="no agents matched scope"`); zero-count buckets
    emit no `<rect>`; aria-label summarises the four counts; widths sum
    to exactly 120 px including the rounding edge case (1/1/1/0 of 3,
    2/2/2/1 of 7) — rounding residue is absorbed by the last non-zero
    segment.
  - `render_duration_bar_html`: width clamps to 100 % when over
    max-duration; zero max yields zero width; status class flows through
    to the `duration-bar--{class}` selector; negative duration clamps to
    zero in the `aria-label`.
- **`tests/unit/server/test_workflow_routes.cpp`** — new Catch2 file
  covering the executions list and detail handlers (19 cases / 159
  assertions). Uses the `TestRouteSink` pattern (no httplib::Server
  acceptor, no #438 TSan trap) registered against the new
  `WorkflowRoutes::register_routes(HttpRouteSink&, ...)` overload.
  Pins: empty state; definition-name resolution vs id-prefix fallback;
  `definition_id` query filter; failed-row stripe class
  (`exec-row--failed`); ISO-8601 UTC time title; sparkbar `aria-label`
  shape; zero-agent run renders the empty-state sparkbar variant; detail
  404 on unknown id; detail 403 when `perm_fn` denies; KPI strip carries
  Total / Succeeded / Failed / p50 / p95; "—" sentinel for p50/p95
  when any agent is still `running`; per-agent table sorts failed-first;
  agent grid switches to decile bucketing above 1024 agents; UTF-8
  truncation does not tear emoji; sidebar shows dispatched_by + ISO
  timestamps; `last_error_detail` correlated subquery is empty for
  fully-successful runs and surfaces the most-recent agent error
  (highest `completed_at`) for failed runs.
- **`tests/puppeteer/executions-drawer-smoke.mjs`** — new browser-level
  visual regression net for the executions tab. Logs in, switches to
  Executions, asserts: at least one `.exec-row` + `.status-sparkbar`
  rendered; ISO-8601 title on `.exec-time`; sparkbar `aria-label`
  matches the four-counts pattern; clicking a row lazy-loads the drawer
  with `.exec-kpi-strip` + `.agent-grid` + `.per-agent-table` all
  present; KPI strip carries the five labelled tiles
  (Total / Succeeded / Failed / p50 / p95) and the "—" sentinel does
  not appear in KPI value position for completed runs; opening row B
  collapses row A's drawer (single-drawer-open invariant); six Cisco
  Momentum tokens (`--mds-color-bg-success-emphasis`,
  `--mds-color-theme-indicator-error`, `--mds-color-theme-indicator-stable`,
  `--mds-color-theme-text-tertiary`, `--mds-color-state-hover`,
  `--mds-color-state-selected`) resolve non-empty so silent palette
  drift is detected. Same shape as `tests/puppeteer/echarts-smoke.mjs`.

### Changed

- **`scripts/test/perf-gate.sh` is no longer a regression-detecting
  gate.** It runs `yuzu_gw_perf_SUITE`, parses throughput/latency from
  `ct:pal` output, records each metric into the test-runs DB, and exits
  PASS. It does not read a baseline file, has no tolerance, and never
  FAILs on a metric value. The N=300 calibration captured in this same
  release showed 3 of the 4 gateway perf metrics are ceiling-bounded
  with long left tails — neither σ nor %-tolerance bands fit them — so
  perf is moved to measure-and-report until the gate can be rebuilt
  around percentile primitives. Removed: `tests/perf-baselines.json`
  file, `--baseline`, `--tolerance-pct`, `--capture-baselines`, and
  `--report-only` flags (the script now rejects them with a one-line
  pointer to the calibration doc). Kept: the quiesce check (refuses to
  run with UAT ports listening), `--allow-busy` debug bypass, hardware
  fingerprint and loadavg metric capture, parser-drift WARN. SKILL.md,
  CLAUDE.md, `tests/shell/test_pr2_gates.sh`, and
  `scripts/test/perf-sample.sh` all updated to match. Coverage gate is
  unchanged — it still enforces `tests/coverage-baseline.json`. Full
  rationale and the deferred percentile-redesign live in
  `docs/perf-baseline-calibration-2026-05-03.md`.
- **Release supply-chain assets renamed and expanded for OpenSSF Scorecard
  visibility.** The cosign signature on `SHA256SUMS` is now published as
  `SHA256SUMS.sigstore` rather than `SHA256SUMS.bundle`, matching the
  canonical Sigstore Bundle filename and the
  `\.(minisig|asc|sig|sign|sigstore)$` extension regex Scorecard's
  Signed-Releases check requires. Each binary archive, installer, and
  Docker image now also publishes its SLSA build provenance attestation
  as a sibling `<artifact>.intoto.jsonl` release asset, so Scorecard can
  see the provenance without reaching the GitHub Attestations API. v0.11.0
  and v0.11.0-rc2 were backfilled with `SHA256SUMS.sigstore` and per-asset
  `*.intoto.jsonl` files alongside their original `SHA256SUMS.bundle`;
  v0.12.0 onwards will ship only the canonical `.sigstore` filename.
  Customers should update verification scripts to use the `.sigstore`
  filename — both files are byte-identical Sigstore bundles and `cosign
  verify-blob --bundle` accepts either path. See
  `docs/user-manual/release-verification.md` for the migration table.

- **`GET /fragments/executions` now honours the `definition_id` query
  parameter.** Previously the parameter was accepted but silently ignored.
  After this release, passing `?definition_id=<id>` filters the list to
  executions of that definition only. Any operator or automation that
  embedded the executions fragment URL with `definition_id` expecting
  the full list must drop the parameter. Behaviour change, not a wire
  break — the URL shape and response Content-Type are unchanged.

- **Executions surface — Gate-7 hardening round on PR 1.** Information-design
  PR 1 (the clickable executions history + per-execution drawer) shipped
  with the visible feature; this round addresses governance findings
  produced by the `/governance` pipeline:
  - **`/fragments/executions` LIST handler now gates on `Execution:Read`**
    (sec-M1). The LIST exposes resolved definition_name and a per-row
    `last_error_detail` preview — same data class as the DETAIL handler,
    earns the same RBAC gate. Mirrors MCP `list_executions` and REST
    `/api/v1/execution-statistics`.
  - **Detail handler emits an audit event on success** (sec-M2):
    `audit_fn(req, "execution.detail.view", "success", "Execution",
    exec_id, "")` — closes the SOC 2 evidence chain for forensic-grade
    reads. The LIST and other read-only fragment routes continue to skip
    audit per the documented fragment-route policy (forensic-grade
    content audits; aggregate / presentation surfaces do not).
  - **Detail path regex tightened to `[A-Za-z0-9_-]{1,128}`** (sec-L3) —
    matches the visualization route's bound from #253; prevents
    unbounded path lengths from reaching `get_execution()`.
  - **Agent grid uses `data-*` attributes + delegated event listener**
    (UP-1 / sec-L1): `agent_id` and `exec_id` are no longer interpolated
    into a JS string literal inside an inline `onclick` attribute. The
    pre-fix path was: `html_escape` converts `'` to `&#39;` which the
    HTML parser un-escapes BEFORE the JS lexer sees the attribute value
    — a malicious or compromised agent registering with `agent_id` like
    `'); evil(); //` could land arbitrary JS in the operator's session.
    Mitigated by binding via `addEventListener` against `data-agent-id`
    / `data-exec-id` so wire-provided bytes never enter a JS-string
    context. Per-agent table rows also gain matching `data-*` attrs;
    grid → row scroll lookup uses `getAttribute` not string-concat ID.
  - **`ExecutionQuery::include_error_detail` opt-in flag** (arch-B2 /
    perf-B1): the `last_error_detail` correlated subquery on
    `kSelectAll` is now off by default. The LIST fragment opts in (it
    renders the field); `get_execution` for single-row reads opts in
    (rare callers). Hot-path callers (server.cpp:886/963/1721/1727/1871
    metrics + health ticks at limit=1000) leave the default false and
    pay zero subquery cost. Eliminates the regression where every 15s
    metrics tick scanned `agent_exec_status` partitions and sorted by
    `completed_at` for every row with `agents_failure > 0`.
  - **KPI percentile sort hoisted out of `fmt_pct` lambda** (perf-B2 /
    cpp-S3): the durations vector is now sorted once per drawer request
    rather than twice (once per p50, again per p95).
  - **Sparkbar SVG fills carry CSS-variable fallbacks** (UP-13): every
    `var(--mds-color-*)` now declares a second-arg fallback to the
    pre-token alias (`--green` / `--red` / `--accent` / `--muted`) so a
    yuzu.css load failure or token rename leaves the bar legible
    instead of rendering invisible.
  - **`Execution.last_error_detail` carries a PII-adjacent struct
    comment** (arch-B1): the field is gated by `Execution:Read` at every
    serializer; a future contributor adding it to a JSON-blanket-emit
    REST handler will see the warning at IDE-hover time.

### Removed

- **`/static/debug/<name>.png` route deleted.** A skin-iteration
  debug helper that served PNG screenshots from
  `/usr/share/yuzu/screenshots/` (only present in
  `Dockerfile.server-local`). Unauthenticated by design as a dev
  helper, but the route existed in every build; closing the data-
  disclosure surface area before any pilot ship. The `.screenshots/`
  directory is now gitignored.

### Fixed

- **#743 — workflow canary wall time cut from ~70 min to ~10–15 min.**
  The `Workflow canary (GHA-hosted ubuntu-24.04)` job had ccache
  installed and used as the compiler wrapper but never persisted
  across runs, so every TU compiled cold every run on the 4-vCPU
  GHA-hosted runner. Added an `actions/cache` step for `~/.cache/ccache`
  keyed on source hash with cascading restore-keys (mirrors the macOS
  leg's pattern). Also dropped the `meson test` step from the canary —
  the canary's purpose is workflow-regression detection, not test
  regression, and `meson test` runs on every other Linux leg
  (linux_matrix on push, nightly asan/tsan/coverage). Net: ~17 min
  saved on compile via warm ccache, ~5–10 min saved by dropping tests.

- **#741 follow-up — sentinel now self-heals on no-drift orphan state.**
  The original #741 fix wiped both halves of `vcpkg_installed/` on
  cache-key drift, which closes the path where a NEW commit lands on a
  corrupt workspace. PR #742's CI then failed with the same abseil
  `read_lines` symptom because the workspace was already corrupt and the
  inputs hadn't drifted: the sentinel correctly reported "unchanged",
  the orphaned `vcpkg/info/abseil_*.list` survived, and `vcpkg install`
  short-circuited again. Sentinel now runs a defensive invariant on every
  invocation — if `vcpkg_installed/vcpkg/` exists but
  `vcpkg_installed/<triplet>/` does not, the registry is orphaned by
  definition and gets wiped regardless of cache-key state. Test 4 in
  `scripts/ci/test-vcpkg-sentinel.sh` pins the new behaviour
  (orphan detection fires on no-drift run; no-op on healthy workspace).

- **#741 — vcpkg sentinel registry-desync wedged Windows CI.** Two
  related defects converged on today's CodeQL Windows job:
  (a) `scripts/ci/vcpkg-triplet-sentinel.sh` wiped
  `vcpkg_installed/<triplet>/` on cache-key drift but left the sibling
  per-workspace registry (`vcpkg_installed/vcpkg/{info,status,updates}/`)
  intact, so orphaned `info/<port>_<triplet>.list` entries persuaded the
  next `vcpkg install` to short-circuit to "already installed" and then
  fail post-install pkgconfig validation with
  `read_lines("…/lib/pkgconfig/<pkg>.pc"): no such file or directory`
  (today's failure hit on `absl_absl_check.pc`); (b) `codeql.yml` had
  its **own** inline sentinel (`.x64-windows-triplet.sha256`) that
  hashed only `triplets/x64-windows.cmake` — missing manifest + baseline
  drift — and shared the same registry-orphan bug. The shared sentinel
  now wipes both halves of `vcpkg_installed/` together; `codeql.yml` now
  calls the shared script instead of its own inline logic;
  `scripts/ci/test-vcpkg-sentinel.sh` pins the four behaviours the
  sentinel must preserve and runs from the `canary` job in `ci.yml`.
  `docs/ci-troubleshooting.md` §7 separates this from the pre-existing
  `vcpkg/packages/` buildtree corruption path.

- **`CertReloader` shutdown latency drops from up to 5s per teardown to
  near-zero.** The watcher thread used to sleep in 5-second increments and
  only check the stop flag between increments, so each `stop()` (and each
  destructor, since `~CertReloader()` calls `stop()`) blocked for up to
  one full sleep window. With multiple `[cert-reload][lifecycle]` test
  cases each paying that cost, the `server unit tests` suite was creeping
  up to its 120-second meson budget — close enough that PR #734's run on
  a contended `yuzu-wsl2-linux` runner overran by 4.6s and got SIGTERM'd
  mid-`CertReloader: destructor stops cleanly`. Replaced the polling
  sleep with a `std::condition_variable::wait_for` whose predicate the
  `stop()` path notifies, so shutdown is bounded by `notify_all` + thread
  join (sub-millisecond) rather than the next 5-second poll. Also
  silences the `[[deprecated]]` warning on `httplib::SSLServer::ssl_context()`
  by routing through `tls_context()` with a typed cast — same underlying
  `SSL_CTX*`, no behaviour change.

- **#618 — users lost across server restarts.** Pre-`auth.db` the user
  list was held in memory, written back to `yuzu-server.cfg` on save,
  but state created via the dashboard between saves was lost on a
  crash or hard restart. AuthDB persists every write atomically.

- **#388 — config write failure was silent.** `save_config()` now
  returns explicit `bool` and is checked on every callsite; auth
  state and on-disk config diverge no longer.

- **#527 — auth state lifecycle unclear.** Server now has a single
  authoritative `AuthDB` instance whose lifetime is tied to
  `ServerImpl`; `AuthManager::set_auth_db()` injection makes the
  contract explicit at construction.

- **Windows MSVC compile fixes that landed alongside the AuthDB
  rollout** — explicit `<algorithm>` / `<ctime>` / `<cctype>` /
  `<cstring>` includes for the strict MSVC STL transitive-include
  policy, destructor SQLite-handle ordering on the workflow_routes
  test (so `fs::remove` runs after `sqlite3_close`), and
  `path.string().c_str()` conversion for `sqlite3_open_v2` (C2664).

- **`InstructionStore::create_set` now uses the `kConflictPrefix`
  contract on duplicate-id.** Previously returned
  `"insert failed: UNIQUE constraint failed: ..."` on duplicate, which
  the boot-time auto-import substring-matched against `"already exists"`
  and miscounted as `errored`. Every server restart logged
  `0 sets imported / 0 skipped / 10 errored` plus 10 WARN lines —
  looking like a persistent fault to any SIEM integration. The store
  now does a pre-INSERT existence check and returns `kConflictPrefix`-
  prefixed errors, mirroring `create_definition_impl`. Auto-import
  classifies via the shared `is_conflict_error()` helper.

- **`/static/yuzu.css` Cache-Control loosened to
  `no-cache, no-store, must-revalidate`** (was `max-age=3600`) to
  prevent stale skin during design-token iteration. Operators running
  a reverse-proxy cache will see slight uplift in origin load on
  dashboard pageloads. Tracked for dev-mode-flag gating in follow-up
  — not gated yet.

- **`/static/fonts/InterVariable.woff2` zero-copy.** Route now passes
  the underlying byte-array `data + size` directly to
  `httplib::Response::set_content`, skipping a 345 KB `std::string`
  allocation per fetch.

- **CI: Windows MSVC debug failed at link with LNK2038 abseil
  RuntimeLibrary mismatch and LNK1181 truncated obj-path errors when
  it ran after Windows MSVC release on the same self-hosted
  yuzu-local-windows runner.** Both legs of the matrix shared a single
  `build-windows/` dir under `clean: false`. When release ran first,
  `meson setup --reconfigure` for the debug leg did not regenerate
  ninja's link response files cleanly, so debug-build link.exe
  invocations pulled release-CRT abseil libs (mismatched
  `_ITERATOR_DEBUG_LEVEL=0` vs `=2` in `src_main.cpp.obj`) and
  truncated obj-path entries in the response file (e.g.
  `'isualization.cpp.obj'` for `unit_server_test_rest_visualization.cpp.obj`).
  This is the same `--reconfigure` variant-leak edge case the Linux
  matrix already worked around with per-variant `build-linux-{compiler}-{buildtype}/`
  dirs (ci.yml:265-274). Fix: split Windows into `build-windows-debug/`
  and `build-windows-release/` so the two legs can never poison each
  other's ninja state. Pre-checkout sentinel also wipes the legacy
  `build-windows/` so a stale pre-split dir cannot linger on the runner.

- **CI: Linux + Windows self-hosted runners rebuilt every vcpkg port from
  source on every run.** Two compounding causes: (a) `lukka/run-vcpkg`
  defaults `VCPKG_DEFAULT_BINARY_CACHE` to a per-run UUID temp dir under
  its own state path, so every job started with a 0% hit rate; (b)
  `actions/checkout@v6` defaults to `clean: true` (`git clean -ffdx`),
  which wiped both `vcpkg/` and `vcpkg_installed/` from the workspace.
  Combined effect: ~25 min from-source on Linux and ~90 min on Windows
  for grpc + abseil + protobuf, every push, on a runner that had every
  byte already on disk in a different directory. Symptom signature in
  the build log: `Restored 0 package(s) from .../<uuid>/vcpkg_cache`.

  Fix: redirect `VCPKG_DEFAULT_BINARY_CACHE` to `${{ runner.tool_cache }}`
  on every self-hosted job (matrix linux × 4, sanitize-asan, sanitize-tsan,
  coverage, windows × 2). The tool_cache path lives outside
  `$GITHUB_WORKSPACE` so checkout's clean leaves it alone. After warm-up,
  vcpkg restores from zip in ~10 s on Linux / ~30 s on Windows. Caches
  are scoped by triplet only (`-linux`, `-asan`, `-windows`) — variants
  using the same triplet share one cache because the package zips are
  bit-identical regardless of consumer compiler/buildtype. Previous CI
  rounds had used per-matrix scoping for defensive isolation, which
  caused 4× from-source on the Linux matrix's first warm-up; we've
  never had an isolation incident, so the speed wins. Net cumulative
  first-warm cost dropped from ~5 h to ~2 h 20 min.

- **CI: ASan job lacked sentinel-based triplet drift detection.** The
  `triplets/x64-linux-asan.cmake` overlay is fingerprinted into vcpkg's
  ABI hash, but vcpkg's _incremental install_ keys on the manifest only
  — an edit that touches sanitiser flags or `VCPKG_BUILD_TYPE` would
  silently leave the existing tree in place, yielding phantom link
  errors that look like ABI mismatches. Mirrored the Windows
  `Force fresh vcpkg install when triplet changed` step on the ASan
  job, sentinel at `vcpkg_installed/.x64-linux-asan-triplet.sha256`.
  Stock `x64-linux` jobs (matrix linux, TSan, coverage) don't carry an
  overlay so don't need the sentinel; vcpkg-pinned commit ID covers
  upstream triplet changes.

- **CI: dead `Export GitHub Actions cache variables` step on the Windows
  self-hosted job.** `ACTIONS_CACHE_URL` / `ACTIONS_RUNTIME_TOKEN` were
  exported for an in-process GHA cache backend that nothing on this
  runner consumes (binary cache is in `runner.tool_cache`, ccache writes
  to the runner's HOME). Replaced with a comment explaining the history;
  the macOS leg still uses `actions/cache@v5` directly so its export is
  also dead but left in place pending a separate scope.

- **Windows MSVC: `dashboard_ui.cpp` C2026 raw-string-literal limit hit
  by round-2 visualization additions.** The `kDashboardIndexHtml` raw
  string at the top of `dashboard_ui.cpp` was already at ~16 019 bytes
  (a notorious sub-section of the 16 380-byte MSVC C2026 limit). Adding
  the `<div id="chart-deck-host">` placeholder, the
  `<script src="/static/yuzu-charts.js">` tag, and the
  `.yuzu-chart-deck` / `.yuzu-chart-card` CSS for the chart deck pushed
  it over, breaking Windows MSVC release with
  `error C2026: string too big, trailing characters truncated`. Linux,
  macOS, and clang accepted the bigger string fine.

  Fix: split the raw string at the `</head>` boundary so chunk 1
  (head + style) is now ~12 810 bytes and chunk 2 (body onward) is its
  own 3 209-byte literal. Adjacent string literals concatenate at
  compile time, so the runtime HTML is byte-identical. Same chunking
  pattern `static_js_bundle.cpp` already uses for `kHtmxJs` and the
  governance build-ci agent flagged for `charts_js_bundle.cpp` (#607).

- **Windows MSVC: `yuzu_agent_tests.exe` LNK2019 regression from #572.**
  PR #572 changed `yuzu_agent_tests` to depend on `yuzu_proto_headers_dep`
  (no link_with) instead of `yuzu_proto_dep`. On Linux/macOS this works
  because `proto/meson.build` compiles with `-fvisibility=default`, so
  proto symbols appear in `libyuzu_agent_core.so`'s dynamic symbol table
  and the test binary resolves them at runtime. On Windows MSVC there
  is no equivalent — `shared_library` produces a `.dll` + import lib
  but does not export every symbol the way ELF visibility does (no
  `__declspec(dllexport)` on proto symbols means they are not in the
  import lib). Result: every `.pb.o` symbol referenced in
  `test_guardian_engine.cpp` (`yuzu::agent::v1::CommandRequest`,
  `yuzu::guardian::v1::GuaranteedStateRule`, etc.) became unresolved at
  link time, breaking both Windows MSVC debug and release CI jobs that
  had previously been green.

  Fix: make the proto-dep choice platform-conditional in
  `tests/meson.build`. Linux and macOS keep
  `yuzu_proto_headers_dep` (the ASan-clean #572 path); Windows uses
  `yuzu_proto_dep` (with link_with) since the duplicate-registration
  CHECK is non-fatal there and ASan is not part of the Windows MSVC
  build matrix. Linux verified: `yuzu_agent_tests` 366 cases / 35 775
  assertions and `yuzu_server_tests` 1252 cases / 14 923 assertions
  both green after reconfigure + rebuild.

### Changed

- **Visualization: governance round-2 hardening on the multi-chart and
  dashboard auto-render deltas.** Resolved in-PR: arch-B2 (migration v2
  duplicate-column was non-idempotent on iterated DBs — added a
  pre-migration probe that stamps `schema_meta` to v2 when the column
  already exists, so the migration runner skips the failing ALTER);
  C-14/sec-F5/UP-36 (raw `&` replaced with `&amp;` in three HTML
  attribute emit sites for strict HTML5 conformance and consistency
  with `render_results`); CP-1/sec-F1/ER-NEW-2 (reverse-lookup at
  `/api/dashboard/execute` now gates on `InstructionDefinition:Read`
  in addition to `Execution:Execute` — a principal denied
  `InstructionDefinition:Read` no longer enumerates definition IDs
  through this side channel; the dispatch itself still succeeds, only
  the chart auto-render is suppressed); CP-2/C-16 (the `command.dispatch`
  audit `detail` now appends `definition_id=<id>` when the reverse-lookup
  resolved one — closes the SIEM correlation gap between dispatch and
  the subsequent `execution.visualization.fetch` event); sec-F3/C-15
  (REST endpoint regex-validates `definition_id` against
  `^[A-Za-z0-9._-]{1,128}$` matching the dashboard fragment, so
  unbounded values no longer reach SQL bind / audit / log paths);
  sec-F2 (added failure audit emission for every 4xx path on the REST
  visualization endpoint with a structured `reason=<r>` token in
  `detail` so SIEM rules can detect probe / fuzz traffic);
  doc-SF1 (visualization-demo.sh header comment updated — the
  browser-console paste workaround is removed in favour of the
  dashboard auto-render UX); doc-SF2 (`audit-log.md` table now
  documents `execution.visualization.fetch` with the success / failure
  detail vocabulary and the SIEM-correlation note);
  doc-SF3/ER-NEW-4 (`instructions.md` § 13 grew a "Response
  Visualization (chart deck)" subsection covering the auto-render
  flow, RBAC, and known limitations).

  Tests: `[visualization]` filter now 28 cases / 186 assertions, all
  green. Added "REST visualization: malformed definition_id → 400" and
  asserted failure-path audit emission on the existing missing-
  definition_id 400 case.

- **Visualization: chart deck auto-renders inline in the dashboard
  results panel (no manual paste needed).** New `<div id="chart-deck-host">`
  placeholder above the filter bar in `dashboard_ui.cpp`; `yuzu-charts.js`
  now ships in the dashboard's `<script>` block alongside `htmx.js` and
  `sse.js`. `/fragments/results` accepts an optional `definition_id`
  query parameter and emits an OOB `<div id="chart-deck-host">` swap
  alongside the tbody, populating the deck with one chart card per
  configured chart. The dashboard `/api/dashboard/execute` path does a
  best-effort reverse lookup against `InstructionStore` for a
  definition matching the dispatched (plugin, action) that has a
  `spec.visualization` configured; when found, `definition_id` is
  threaded through (a) the OOB filter-bar `load delay:2s` URL,
  (b) the OOB chart-deck-host load URL, (c) the filter-bar form's
  hidden inputs, and (d) the pagination/sort/filter base URLs. Operators
  who type an instruction whose plugin/action matches a chart-bearing
  definition now see charts render automatically as soon as responses
  arrive, with no need for the browser-console paste from
  `scripts/visualization-demo.sh`. Minimal CSS for the
  `.yuzu-chart-deck` flex container keeps multiple charts side-by-side
  with sensible min-width/max-width.

- **Visualization: multi-chart definitions (issue #587, governance arch-S2).**
  A definition can now declare more than one chart via the canonical
  plural form `spec.visualizations: [<vis>, ...]`. The singular
  `spec.visualization: <vis>` is accepted as syntactic sugar for a
  single-element list and is normalised at ingest by
  `import_definition_json`. The REST endpoint accepts an optional
  `?index=N` query parameter (default `0`); the response payload
  includes `chart_index` and `chart_count` so clients can iterate.
  Out-of-range `index` returns 404; non-integer `index` returns 400.
  The dashboard fragment emits one `<div data-yuzu-chart-url="...&index=K">`
  per configured chart wrapped in a `<div class="yuzu-chart-deck">`
  container, so each chart is rendered independently and a slow/failed
  fetch on one doesn't block its siblings. Engine API grew
  `count(spec_json)` and `transform_at(spec_json, index, ...)`;
  `has_visualization` and `transform` continue to work for the legacy
  single-chart case. Storage column `visualization_spec` keeps its
  TEXT/JSON shape but values are normalised to JSON arrays at ingest.

- **Visualization fragment route relocated to `dashboard_routes.cpp`
  (issue #589, governance arch-S6).** `GET /fragments/executions/{id}/visualization`
  was registered in `server.cpp` alongside the static-asset handlers
  because that's where the stores were already in scope. Every other
  `/fragments/*` route lives in `dashboard_routes.cpp`; this one now
  joins them. `DashboardRoutes::register_routes(...)` grew an optional
  `InstructionStore*` parameter (defaulted to `nullptr` for
  backward-compatible call sites). Behavior, URL, permission gate
  (`Response:Read`), and XSS-safe `definition_id` regex validation
  all unchanged. Demo script and unit tests (`[visualization]`)
  continue to pass; live UAT confirms the moved route returns
  HTTP 200 with the expected `data-yuzu-chart-url` placeholder.

### Added

- **Response Visualization Engine — server-side chart rendering for
  instruction responses (issue #253, Phase 8.1).** New
  `spec.visualization` block on `InstructionDefinition` declares a
  chart configuration (5 chart types: pie / bar / column / line /
  area; 3 processors: single_series / multi_series / datetime_series).
  The server walks the response set, runs the chosen processor, and
  returns chart-ready JSON via
  `GET /api/v1/executions/{id}/visualization` (gated on `Response:Read`
  for sibling parity with the rest of the response-store read surface;
  requires `definition_id` query parameter). Dashboard fragment
  `GET /fragments/executions/{id}/visualization` returns an
  HTMX-friendly placeholder div the embedded vanilla-SVG renderer
  (`/static/yuzu-charts.js`, no third-party dependency) populates on
  settle. `visualization_spec` is stored on the definitions table as
  a JSON string and tracked by `MigrationRunner` v2 so the schema
  ledger reflects when the column became canonical. Field names use
  camelCase (`labelField`, `valueField`, `seriesField`, `xField`,
  `yField`, `maxCategories`, `valueLabel`); the engine still accepts
  the snake_case forms as deprecated aliases for backward compat.
  Row reads cap at 10000 (sibling parity); when the cap is hit the
  payload includes `rows_capped:true` and a server-side warn log
  fires so on-call has a signal. Engine label cardinality is also
  hard-capped at 10000 distinct labels per chart as defense-in-depth.
  Every render emits an `execution.visualization.fetch` audit event.
  REST API documented in `docs/user-manual/rest-api.md` and the
  embedded OpenAPI spec; YAML DSL documented in
  `docs/yaml-dsl-spec.md` § `spec.visualization` with two worked
  examples and an entry in the §3.2 complete example.

  Hardening followed an 8-gate `/governance` run on the initial
  commit; this entry reflects the post-hardening surface. Resolved
  in-PR: sec-H1 reflected XSS via `definition_id`, sec-H2/C-1 wrong
  securable, sec-L6/C-4 missing audit, sec-M4/F-9 unbounded label
  cardinality, bld-B1 macOS `std::from_chars(double)` compile,
  arch-B1/F-6 migration discipline, dsl-B1 broken services-plugin
  example, dsl-B2 snake_case→camelCase rename, dsl-B3 missing §3.2
  example, doc-B1/B2 missing rest-api.md and OpenAPI entries, qe-1/2/3
  test gaps for 403/audit/503 paths, C-2 row-cap drift 5000→10000,
  UP-3/ER-P1 silent truncation. Deferred to follow-up issues:
  sec-M3/F-3 mgmt-group visibility filter (non-trivial — needs
  `ManagementGroupStore` wired into `RestApiV1::register_routes`),
  UP-5/SRE-7 concurrent render DoS semaphore, UP-19 duplicate
  command_id collision, arch-S2 multi-chart-per-definition, arch-S6
  fragment route relocation to `dashboard_routes.cpp`.

  Test deltas: `tests/unit/server/test_visualization_engine.cpp`
  (12 engine cases, all camelCase), `tests/unit/server/test_rest_visualization.cpp`
  (10 wire cases including 403 perm-denied, 503 null-stores, audit
  emission, snake_case alias, rows_capped meta).

- **CI: ASan job now uses `x64-linux-asan` triplet so vendored deps
  (protobuf/abseil/grpc) are built with `-fsanitize=address,undefined`
  — fixes a 4-of-4 ASan FAIL streak.** Every prior ASan run aborted
  in 0.44s with `AddressSanitizer: use-after-poison` triggered before
  any Yuzu test code executed: protobuf's `DescriptorPool::Tables`
  static constructor inserts into an `absl::flat_hash_map` whose
  unused slots are poisoned by abseil's container-overflow logic, but
  abseil's `ABSL_HAVE_ADDRESS_SANITIZER` macro only fires when the
  abseil build itself sees `-fsanitize=address` — vcpkg's stock
  abseil port doesn't, so the application's ASan instrumentation
  diverged from the library's, gcc 13's libstdc++ basic_string SSO
  inline-buffer read on an adjacent slot was flagged as
  use-after-poison, and the binary aborted.
  Building the deps with the same sanitiser flags as the application
  (via the new `triplets/x64-linux-asan.cmake` overlay triplet)
  makes abseil cooperate with ASan and resolves the static-init
  abort. Per-sanitiser binary-cache directory keeps the instrumented
  .zips separate from the regular `x64-linux` cache. First run pays
  ~25 min from-source for the ASan-instrumented deps; subsequent
  runs are extract-from-zip (~10s) since the runner's local disk has
  ample room (issue #569's local-cache architecture made this
  tractable). TSan deferred — different shadow-memory model, no
  similar abseil interference today.

- **CI: dropped `actions/cache@v5` on every self-hosted runner —
  Linux + Windows now use runner-local persistent state only
  (issue #569).** 14 cache blocks removed across `ci.yml` (8),
  `release.yml` (5), and `codeql.yml` (1). On a self-hosted
  runner, ccache's OS-default location (`~/.cache/ccache` on
  Linux, `~\AppData\Local\ccache` on Windows) lives in the
  github-runner user's home directory, which persists between
  jobs by definition; `vcpkg_installed/` similarly persists in
  `${{ github.workspace }}` since self-hosted workspaces are not
  recycled. Routing those directories through GHA's 10 GB cache
  backend was pure overhead — the post-`a5436ed` ccache contents
  alone (~4 GB per (compiler, mode) entry) couldn't all fit, and
  LRU eviction was forcing from-scratch rebuilds on every job.
  Expected impact: per-job CI wall time drops from 50-80 min to
  8-12 min on self-hosted Linux, and the cumulative push-to-CI
  cycle from 5-7 hours to 30-60 min. macOS jobs (cloud-hosted,
  ephemeral) keep their `actions/cache` blocks — those are the
  only legitimate use of GHA cache in this workflow set.

  The vestigial `compact_compiler` matrix include from the
  earlier round-3 cache-key unification is also removed — it only
  fed the cache keys that no longer exist.

- **CI: unified vcpkg + ccache cache-key form to compact `gcc13` /
  `clang19` (no hyphen) across every Linux job (issues #569, #547
  /test investigation).** The matrix-driven Linux build jobs were
  using `vcpkg-x64-linux-${{ matrix.compiler }}-...` which
  interpolated as `gcc-13` / `clang-19` (with hyphen). The
  standalone Sanitizer / Coverage / Real-upstream jobs hard-coded
  `vcpkg-x64-linux-gcc13-...` (no hyphen). Two parallel cache
  entries for identical content forced the GHA 10 GB cap into LRU
  eviction during the v0.12.0-rc /test run on dev — net effect
  was 5-7h CI cycles where 50-80 min was vcpkg-from-source rebuilds
  and 20-40 min ccache uploads, instead of the expected 8-12 min.
  Added a `compact_compiler` matrix include that maps
  `gcc-13 → gcc13` / `clang-19 → clang19`; every Linux cache key
  now uses that field. The deeper architectural fix (drop
  `actions/cache@v5` on self-hosted Linux entirely in favour of
  runner-local persistent dirs) is tracked separately as issue
  #569; this entry closes only the cache-key-mismatch half.
- **`.claude/agents/consistency-auditor.md` extended to cover
  `.github/workflows/*.yml`.** Cache-key parity across sibling
  jobs, restore-key subsumption, runner-label coherence
  (self-hosted vs cloud), matrix-include shape parity, action SHA
  pinning uniformity, and workflow-dispatch input contract are now
  explicit Key Questions for the agent. Without this, /governance
  runs miss CI-yaml drift like the gcc-13 / gcc13 cache split that
  thrashed the GHA cache for weeks before /test surfaced it.

- **TAR dashboard hardening round 4 — Gate 5/6 BLOCKING (issue #547).**
  Folds the BLOCKING items Gates 5 + 6 (compliance / sre / enterprise-
  readiness / chaos) caught after the first three hardening rounds:
  - **compliance F1 (RBAC denied audit gap)** — both new POST handlers
    (`/fragments/tar/retention-paused/scan` and `.../reenable`) now emit
    `result=denied` audit rows when `perm_fn_` rejects the request. The
    audit catalog (`docs/user-manual/audit-log.md`) documented the
    `denied` rows but the code did not deliver them, contradicting the
    SOC 2 CC6.1 / CC7.2 control claim. Two `audit_fn_` calls plus the
    sibling `denied` counter increments close the gap.
  - **sre OBS-1 (Prometheus metrics)** — the design doc spec'd 5
    metrics; PR-A in scope is 4: `yuzu_tar_dashboard_view_total`
    (counter, labels: `frame`, `result`),
    `yuzu_tar_retention_paused_devices` (gauge, labels: `source`),
    `yuzu_tar_scan_dispatched_total` (counter, labels: `result` —
    `success` / `rate_limited` / `no_visible_agents` /
    `no_connected_agents` / `denied`), and
    `yuzu_tar_source_reenable_total` (counter, labels: `result` —
    `success` / `scope_violation` / `agent_not_connected` / `denied` /
    `invalid_input`). Plumbed `MetricsRegistry*` through
    `DashboardRoutes::register_routes` (new optional parameter,
    defaults `nullptr` so tests don't have to construct one).
    Descriptions registered at startup so the Prometheus serializer
    emits HELP and TYPE lines correctly. The retention-paused gauge is
    re-set per source on every render — operators tracking
    "process retention is paused on N devices over time" now have a
    queryable signal.
  - **sre CAP-1 (per-operator scan cooldown)** — `POST .../scan` now
    enforces a 30-second cooldown using the already-stored
    `dispatched_at` field. Subsequent dispatches within the window
    return HTTP 429 with `Retry-After`, an HTML fragment showing the
    remaining wait, and a `denied` audit row carrying
    `rate_limited cooldown=Ns`. Without this, a compromised session
    could spam Scan in a loop and storm the fleet with `tar.status`
    RPCs at the operator's `Execution:Execute` permission tier.
  - **enterprise SHOULD-1 (mixed-version upgrade caveat)** —
    `docs/user-manual/server-admin.md` gains a "v0.12.0 — TAR dashboard
    page + mixed-version agent caveats" subsection covering the
    em-dash rendering for pre-PR-A agents, the per-operator scan-state
    persistence model, and the new audit-action surface. Without this,
    operators upgrading the server before the agent fleet would see
    `—` columns and have no documented explanation.
  - **enterprise SHOULD-2 (TAR nav-link conditional rendering)**
    deferred to follow-up — requires a JS-time permission lookup that
    is more architectural than a one-line CSS hide. The current
    behaviour (click → 401/redirect) is not a security issue.

- **TAR dashboard hardening round 3 — Gate 4 + Gate 3 follow-up
  (issue #547).** Folds the BLOCKING items Gate 4 caught after the
  first two hardening rounds, plus the QE BLOCKING test gap on
  `json_escape`:
  - **QE F1** — `json_escape` promoted from `static` in
    `dashboard_routes.cpp` to inline in `web_utils.hpp` so future
    hx-vals call sites inherit the helper instead of rolling their
    own. New `test_web_utils.cpp` block (8 cases) pins JSON-escape
    semantics for empty / plain ASCII / `"` / `\` / named escapes
    (`\b\f\n\r\t`) / C0 control bytes / 0x20+ pass-through / the
    full `html_escape(json_escape(value))` pipeline contract that
    sec-M3 depends on. Without this test, a future refactor that
    drops a case from json_escape would silently re-open sec-M3.
  - **consistency-auditor BLOCKING-8** — `docs/capability-map.md`
    §28.4 still said `/dashboard/tar`. Fixed to `/tar` matching
    the implementation and the rest of the docs.
  - **consistency-auditor BLOCKING-9** — `docs/tar-dashboard.md`
    §3.5 and §6 (permissions matrix) still said
    `Infrastructure:Update` for Re-enable. Updated to
    `Execution:Execute` matching the round-1 perm-tier fix and
    the user-manual / rest-api docs that already said Execute.
    The Scan-fleet row was also added to the permissions matrix.
  - **happy-path SHOULD-1** — empty-state message on the
    retention-paused fragment now distinguishes "scan still in
    progress" (responses < dispatched) from "scan complete and
    clean" (every dispatched agent responded with no paused
    sources). Without this, the operator would see a "click
    Refresh in a moment" prompt even after every agent had
    answered, leading to unnecessary re-fetches.
  - **happy-path NICE-1** — Scan-fleet button no longer fires a
    success-level toast saying "dispatched to 0 agent(s)" when
    no agents in scope are connected. The zero-reach case now
    fires a warning-level toast that matches the empty-state body.
  - **unhappy-path UP-11** — three TAR fragment endpoints now
    emit `Cache-Control: no-store, private` and `Vary: Cookie`.
    Without these, a corporate proxy honouring default `text/html`
    caching could re-replay one operator's filtered, visibility-
    scoped scan results to a different operator on the shared URL,
    defeating the round-1 sec-H2 fix.

- **TAR dashboard hardening round 2 — docs from Gate 2 governance
  (issue #547).** Folds the four BLOCKING + four SHOULD-FIX docs
  findings the docs-writer caught:
  - **doc-B1** — `docs/user-manual/tar.md` gains a new "TAR
    dashboard page" section after "Checking TAR status," covering
    the page URL, the retention-paused list workflow, columns,
    permissions (`Infrastructure:Read` to view, `Execution:Execute`
    to scan or re-enable — reflects the round-1 perm tier fix), the
    in-memory per-username scan-state caveat, and the audit-action
    surface. Also extends the `tar.status` example output block
    with the four new per-source `enabled` / `paused_at` /
    `live_rows` / `oldest_ts` lines so operators reading the manual
    know what to expect.
  - **doc-B2** — URL drift fixed across `docs/tar-dashboard.md`,
    `CLAUDE.md`, and `docs/roadmap.md`. The page is at `/tar` (the
    implementation), not `/dashboard/tar` (the prior design-doc
    text). The CLAUDE.md routed-concerns trigger pattern updates to
    `/tar` and `/fragments/tar/...`.
  - **doc-B3** — `docs/tar-dashboard.md` §3.1 no longer claims
    background refresh every 60s. Replaced with the actual
    behaviour (manual Refresh button) and a forward-pointer to
    Phase 15.G operational hardening.
  - **doc-B4** — `docs/user-manual/audit-log.md` "Logged actions"
    table gains entries for `tar.status.scan` and
    `tar.source.reenable`, including the `result=failure` /
    `detail=scope_violation|agent_not_connected` distinction the
    handler emits server-side even when the HTTP response body is
    identical (404 with body `Agent not reachable.`) for both
    cases — so SIEM rules can distinguish forged-form attempts
    from transient connectivity issues.
  - **doc-S1** — `docs/user-manual/rest-api.md` "Dashboard TAR"
    section gains entries for `GET /tar`, `GET
    /fragments/tar/retention-paused`, `POST .../scan`, and `POST
    .../reenable` with method, path, permission, request schema,
    response codes, and the audit-action emitted.
  - **doc-S2** — `docs/tar-dashboard.md` §7 audit-action list
    corrected: `tar.retention_paused.list` (never implemented) →
    `tar.status.scan` (the actual emission). Forward-pointer added
    to `tar.source.purge` etc. as the Phase 15.A.next deliverables.
  - **doc-S3** — `docs/roadmap.md` Phase 15 issue index row for
    #547 now reflects PR-A.A delivery — "In progress —
    PR-A.A shipped (paused_at + status extension + dashboard page +
    Scan + Re-enable; purge action + persistence pending)" rather
    than the bare "In progress" of the prior doc commit.
  - **doc-S4** — `docs/tar-dashboard.md` PR ladder row for PR-A
    flips from "In flight — current session" to "Shipped PR-A.A"
    so future readers do not treat the deferred purge action as an
    accidental omission.
- **TAR dashboard hardening round 1 — Gate 2 governance findings
  (issue #547).** The PR-A.A initial commit shipped on
  `Infrastructure:Read` for the Scan dispatch and a single shared
  `latest_tar_scan_id_` server slot. Governance Gate 2 caught two
  HIGH and three MEDIUM findings before merge and this round folds
  the fixes:
  - **sec-H1 (perm tier mismatch).** `POST .../scan` and
    `POST .../reenable` now require `Execution:Execute` (matched to
    sibling dispatch handlers `run-instruction` / `tar-execute`).
    Reading the rendered list still requires `Infrastructure:Read`.
  - **sec-H2 (cross-operator data leak).** Scan state is now
    per-username (`tar_scans_by_user_` map keyed by session
    username, bounded LRU at 256 entries). Operator B opening
    `/tar` no longer sees operator A's scan results, and the
    rendered table is **filtered by the operator's visible-agent
    set** (`ManagementGroupStore::get_visible_agents`) so even
    cached responses from agents outside the operator's RBAC scope
    are dropped. Defense-in-depth: the dispatch itself is now
    scoped to visible agents at fan-out time, not to all connected
    agents.
  - **sec-M1 (per-device RBAC scope).** The reenable endpoint now
    verifies `device_id` is in the operator's visible-agent set
    before dispatching. Out-of-scope IDs are rejected.
  - **sec-M2 (404 enumeration oracle).** Out-of-scope and
    not-connected reenable attempts now return identical 404
    bodies ("Agent not reachable") so the response cannot be used
    to enumerate device existence. Audit detail records the real
    reason (`scope_violation` vs `agent_not_connected`)
    server-side.
  - **sec-M3 (`hx-vals` JSON injection).** A new local
    `json_escape()` helper in `dashboard_routes.cpp` escapes JSON
    metacharacters in `device_id` / `source` before the
    surrounding `html_escape` runs. Without this, a malicious
    agent registering with a `device_id` containing `"` could
    close the JSON string in an HTMX `hx-vals` attribute and
    inject keys that the operator's browser would submit on Re-
    enable. Bounded today (only same-fleet agents can mint device
    IDs) but defense-in-depth.
  - The scan-provenance header now reports out-of-scope responses
    that were filtered out, so the operator understands the
    visibility-bounded view they are seeing.

- **TAR dashboard page + retention-paused source list (PR-A,
  issue #547).** New `/tar` page off the main dashboard
  nav, served as `kTarPageHtml` from a dedicated translation unit
  (`server/core/src/tar_page_ui.cpp`). The page is the operator's
  destination for *doing TAR* — first frame is the retention-paused
  source list, with placeholder slots for the scope-walking-aware
  SQL frame (Phase 15.D / issue #550) and the process tree viewer
  (Phase 15.H / issue #554) that drop in as those PRs land.
  Three new HTMX fragment endpoints:
  - `GET /fragments/tar/retention-paused` queries the response store
    for the most recent operator-triggered `tar.status` scan, parses
    each agent's `<source>_enabled=false` rows along with the
    matching `paused_at` / `live_rows` / `oldest_ts` companions, and
    renders a sortable table with one row per (agent × paused
    source) pair. Sorted paused-longest-first so the boxes
    accumulating non-aging data the longest float to the top. Honest
    scan-provenance header showing dispatched-to count,
    responded-so-far count, and the "all-collecting-normally" count.
  - `POST /fragments/tar/retention-paused/scan` dispatches a fresh
    `tar.status` to all connected agents, records the resulting
    command_id in an in-memory `latest_tar_scan_id_` (per-server-
    instance for now; persistence + multi-server coordination land
    in Phase 15.G operational hardening). Audit row written:
    `action=tar.status.scan` with the dispatched-agent count.
  - `POST /fragments/tar/retention-paused/reenable` takes
    `device_id` + `source` form params, validates `source` against
    the canonical four (`process` / `tcp` / `service` / `user`)
    rejecting forged form submissions with `400 Unknown source`,
    requires `Infrastructure:Update` per device (re-enable is more
    consequential than view), then dispatches a single-device
    `tar.configure` with `<source>_enabled=true`. The row drops
    optimistically via HTMX `hx-swap=delete`; the next operator-
    triggered Refresh reconciles against a fresh scan. Audit row:
    `action=tar.source.reenable` with `device_id` and `source` in
    the detail. Per-source independence preserved (the #539
    invariant) — re-enabling one source does not touch the others.

  The page also gains a "TAR" entry in the main dashboard nav,
  added consistently across `dashboard_ui.cpp`, `help_ui.cpp`,
  `instruction_ui.cpp`, `settings_ui.cpp`, and `compliance_ui.cpp`
  so the link is reachable from every existing page.

- **TAR `tar.status` now emits per-source `paused_at`, `live_rows`,
  `oldest_ts` (PR-A foundation, issue #547).** The `configure` action's
  per-source enable/disable surface gained a transition timestamp:
  flipping `<source>_enabled` from `true` → `false` records the
  wall-clock seconds in `<source>_paused_at`, and the reverse
  transition clears it to `"0"` (deliberately not unset — a missing
  key would be ambiguous with "never paused"). Idempotent re-sets do
  not advance the timestamp, so the dashboard's "paused since" column
  reflects the actual operator action rather than the most recent
  configure round-trip. `tar.status` now also emits one `live_rows`
  and one `oldest_ts` line per source — the rendering data the
  retention-paused dashboard list (PR-A) needs without a second
  round-trip. The transition logic is extracted to a free function
  `yuzu::tar::apply_source_enabled_transition()` in
  `tar_aggregator.{hpp,cpp}` so the plugin and the regression tests
  share one source of truth. Backwards-compatible: agents pre-PR-A
  simply do not emit the new lines, and the dashboard renders `—` for
  the missing fields.

- **TAR query examples, test coverage, and implementer documentation
  (issue #60).** Two new pre-built `InstructionDefinition`s shipped
  in `content/definitions/tar_warehouse.yaml` directly answering the
  examples called out in the issue body:
  `crossplatform.tar.daily_process_summary` (live-to-aggregate rollup
  reading from `$Process_Daily` with `datetime(day_ts, 'unixepoch')`
  for human-readable dates), and `crossplatform.tar.recent_processes_iso`
  (the canonical pattern for the SQLite-equivalent of competing
  platforms' `EPOCHTOJSON(TS)` helper). Both carry per-parameter
  `description` fields so the dashboard and REST API surface them
  without docs-side cross-references. (The originally-shipped
  `crossplatform.tar.process_by_exact_name` was removed during
  governance — it relied on `${process_name}` interpolation in the
  hidden default SQL, but the server has no parameter-interpolation
  pass for `parameters.<key>.default`. Re-add once that surface lands.)
- **`tar.compatibility` InstructionDefinition + DSL spec registration
  (governance docs Finding 4 + plugin Finding 5).** The action shipped
  in the plugin (issue #59) but had no corresponding YAML
  `InstructionDefinition` in `content/definitions/tar.yaml` and no row
  in `docs/yaml-dsl-spec.md` §14.15 — meaning operators could not
  invoke it from the dashboard or via the standard
  `/api/v1/instructions/execute` flow without hand-crafting a
  `CommandRequest`. Both gaps are closed; `minAgentVersion: "0.12.0"`
  is set since the action does not exist on prior agents.
- **`tar.configure` InstructionDefinition now declares the six new
  parameters introduced by issue #59** (governance plugin Finding 2):
  `process_enabled` / `tcp_enabled` / `service_enabled` /
  `user_enabled` (boolean-as-string with `^(true|false)$` regex
  validation), `network_capture_method`, and
  `process_stabilization_exclusions` — all four with descriptions and
  agent-version notes so the dashboard form widget and the OpenAPI
  spec render the new surface correctly.
- **TAR OS compatibility metadata + capture configuration surface
  (issue #59).** The schema registry's `CaptureSourceDef` now carries a
  per-OS `os_support` vector (`OsSupportStatus` × `capture_method` ×
  `notes`) describing how each of the four capture sources (process,
  tcp, service, user) gathers data on Windows / Linux / macOS, including
  documented constraints (`KERN_PROCARGS2` invisibility for hardened
  runtimes, `systemctl`'s `unknown` startup_type, container `/var/run/utmp`
  absence, `lsof` cost, etc.) and `kPlanned` rows for the ETW and
  Endpoint Security collectors that have not landed yet
  (`agents/plugins/tar/src/tar_schema_registry.{hpp,cpp}`). Operators
  can read the live matrix at runtime via the new `compatibility`
  action, which emits one `header|...` + N `row|source|os|status|method|notes`
  lines that the dashboard can render directly.
- **TAR per-source enable/disable + stabilization exclusions + network
  capture-method surface (issue #59).** The `configure` action gained
  four new validated parameters: `process_enabled` /
  `tcp_enabled` / `service_enabled` / `user_enabled` (default `true`,
  short-circuit the per-collector block in `collect_fast` /
  `collect_slow` when `false`); `network_capture_method` (validated
  against `accepted_capture_methods("tcp")` so unsupported values are
  rejected at write time, with a `warn|...` line if the value is
  accepted but not yet wired — currently anything other than
  `polling`); and `process_stabilization_exclusions` (JSON array of
  glob patterns; matching processes are dropped before the diff so
  noisy short-lived helpers don't dwarf real activity, with the
  forensic-completeness trade-off documented in
  `docs/user-manual/tar.md`). `do_status` now also surfaces the
  `<source>_enabled` and `network_capture_method` config rows so
  operators can see effective state without reading the DB
  (`agents/plugins/tar/src/tar_plugin.cpp`).

### Breaking

- **`--allow-one-way-tls` requires `YUZU_ALLOW_INSECURE_TLS=1` on
  upgrade or the server refuses to start (issue #79).** Existing
  deployments that pass `--allow-one-way-tls` (or the new flag name
  `--insecure-skip-client-verify`) will fail to start after upgrade
  unless `YUZU_ALLOW_INSECURE_TLS=1` is also present in the server
  environment. The deprecated flag name is still accepted for one
  release with a startup deprecation warning. To restore mTLS, add
  `--ca-cert <path>` and remove the insecure flag. See the
  `### Security` entry below and `docs/user-manual/server-admin.md`
  "Upgrade note (v0.12.0)" for the full migration including a
  systemd drop-in recipe.
- **Management gRPC listener now subject to the same
  `YUZU_ALLOW_INSECURE_TLS=1` gate as the agent listener (governance
  C-79-1).** Deployments that supply `--management-cert` /
  `--management-key` without `--management-ca-cert` previously got an
  unauthenticated management plane silently. They will now fail to
  start unless `--insecure-skip-client-verify` AND
  `YUZU_ALLOW_INSECURE_TLS=1` are both set, OR
  `--management-ca-cert` is supplied. Most deployments do not set
  the `--management-*` overrides at all (the management listener
  reuses the agent listener credentials by default) and are
  unaffected.
- **`crossplatform.tar.process_by_exact_name` removed from
  `content/definitions/tar_warehouse.yaml` (governance plugin H-1 /
  enterprise-readiness Finding 9).** The instruction shipped briefly
  with `${process_name}` interpolation in its hidden default SQL,
  but the server has no `${param}` interpolation pass for
  `parameters.<key>.default` — the literal `${process_name}` would
  hit SQLite verbatim and match zero rows. Operators who imported
  the InstructionDefinition during the brief window it was on
  `dev` should expect the ID `crossplatform.tar.process_by_exact_name`
  to be missing on upgrade. Re-add once server-side parameter
  interpolation lands.
- **`tar_warehouse.yaml` `minAgentVersion` bumped to `"0.10.0"` for
  every `tar.sql`-based InstructionDefinition (governance H-2).**
  Previously claimed `"0.7.0"` against agents on which `tar.sql` did
  not exist. Server-side compatibility checks will now skip these
  instructions on agents older than v0.10.0 instead of dispatching
  and getting `unknown action: sql` per device.

### Fixed

- **`yuzu_agent_tests` no longer double-links `yuzu_proto.a`, removing
  the duplicate protobuf descriptor registration that aborted ASan
  runs (issue #572).** Both `libyuzu_agent_core.so` and
  `yuzu_agent_tests` listed `yuzu_proto_dep` (which carries
  `link_with: yuzu_proto_lib` — a static archive). The linker pulled
  every `.pb.o` into both the .so and the test exe, so each `.pb.cc`
  static initializer ran twice at process startup. Non-ASan builds
  silently tolerated the double registration (the second
  `DescriptorPool::InternalAddGeneratedFile` saw the same encoded
  descriptor and returned without retrying); ASan flipped static-init
  ordering enough to make protobuf's `GOOGLE_CHECK` fire with `File
  already exists in database: yuzu/common/v1/common.proto`, which
  this option-2 chain (`afd3904`, `4321a40`, `bc498b3`) finally
  exposed. The fix has two halves: (a) compile `yuzu_proto` with
  `-fvisibility=default` (added via per-target `cpp_args` since
  `add_project_arguments`'s `-fvisibility=hidden` would otherwise
  win the last-flag-wins fight with `gnu_symbol_visibility`) so the
  proto symbols actually get exported from any `.so` they're linked
  into; (b) introduce a `yuzu_proto_headers_dep` (includes + sources
  + protobuf/grpcpp deps, no `link_with`) and use it in the
  `yuzu_agent_tests` executable so the test binary resolves proto
  symbols dynamically against `libyuzu_agent_core.so` instead of
  relinking the static archive. The ASan path can now exercise the
  agent test surface end-to-end. (`proto/meson.build`,
  `tests/meson.build`)
- **TAR `network_capture_method=polling` (the documented default) is
  no longer rejected by the configure surface (governance C-1 / QA
  Finding 2).** Both `do_status` reported `polling` as the default and
  `do_configure` validated against `accepted_capture_methods("tcp")`
  — but `polling` was never in that accept-list (the per-OS
  `os_support` rows describe the underlying platform API:
  `iphlpapi` / `procfs` / `proc_pidfdinfo`, not the logical
  `polling` sentinel). The status → configure → status round-trip was
  broken. `do_configure` now special-cases `polling` and accepts it
  unconditionally; the rejection error message also lists `polling`
  alongside the registry-derived methods so the operator sees the
  full accept-set. (`agents/plugins/tar/src/tar_plugin.cpp`)
- **TAR macOS TCP `capture_method` metadata corrected
  (governance C-1 consistency).** `tar_schema_registry.cpp` declared
  the macOS TCP collector as `capture_method = "lsof"` with notes
  describing `lsof -nP -iTCP -iUDP`. The actual implementation in
  `tar_network_collector.cpp` uses `proc_listallpids` +
  `proc_pidfdinfo(PROC_PIDFDSOCKETINFO)` via `libproc` — `lsof`
  appears nowhere in the collector. The new `tar.compatibility`
  diagnostic action (issue #59) was therefore shipping factually
  wrong information to operators on the most operator-facing
  surface in this batch. Updated the registry, `docs/user-manual/tar.md`
  OS compatibility matrix, and `docs/tar-implementer.md` to all
  reflect `proc_pidfdinfo` / libproc with the inherent TOCTOU caveat.
- **TAR Windows User collector capture-method note corrected
  (governance H-1 consistency).** `os_support` notes claimed
  `WTSEnumerateSessionsEx`, but `tar_user_collector.cpp` uses the
  legacy `WTSEnumerateSessionsW`. Note now reflects the actual symbol
  and adds a forward-pointer to the recommended successor.
- **`tar_warehouse.yaml` `minAgentVersion` bumped from `"0.7.0"` to
  `"0.10.0"` across all 13 entries (governance H-2 consistency).**
  All entries use `tar.sql`, which first shipped in v0.10.0. The
  previous claim caused server-side compatibility checks to schedule
  these instructions against v0.7.x–v0.9.x agents that would then
  reject them with `unknown action: sql`.
- **TAR retention no longer deletes data after a source is disabled
  (issue #539, P1, forensic-completeness regression).** The
  `configure` action and `docs/user-manual/tar.md` both promise that
  setting `<source>_enabled=false` "leaves existing rows queryable,"
  but `run_retention()` in `tar_aggregator.cpp` was iterating
  `capture_sources()` unconditionally — so the rollup trigger
  continued draining hourly within 24h, daily within 31d, and monthly
  within ~365d after disable, breaking the forensic-preservation use
  case that TAR's headline pitch is built around. The retention loop
  now consults `<source>_enabled` and skips disabled sources entirely;
  re-enabling the source resumes time-based retention on the next
  rollup tick. Per-source independence is preserved: disabling
  `process_enabled` does not pause retention on `tcp` / `service` /
  `user`. Surfaced by the /governance run on commit range
  `b2554ad..HEAD` as unhappy-path H-59-3, chaos-injector CHAOS-2,
  consistency-auditor M-1, and sre Q2 — all four converged on the
  same docstring-vs-code drift.

### Documentation

- **`docs/enterprise-parity-plan.md`, `docs/capability-map.md`,
  `docs/roadmap.md`: System Guardian recognised as the GS delivery
  vehicle.** Today's parity doc claimed `PolicyStore + CEL + 6
  trigger types` is equivalent to commercial peers' Guaranteed State —
  that is a server-side compliance evaluation match, not a real-time
  enforcement match. Commercial peers' GS uses kernel-event-driven agent-side
  enforcement (firewall, registry, services revert in milliseconds,
  not on the next 5-minute poll), and that is the headline parity
  feature operators evaluate against. The System Guardian work
  (`docs/yuzu-guardian-design-v1.1.md`, agent-side `GuardianEngine`,
  Windows-first 17-PR ladder in `docs/yuzu-guardian-windows-implementation-plan.md`)
  is what closes that gap. PRs 1-2 already shipped (proto, server
  store, agent scaffolding, `__guard__` dispatch hook); PR 3+ is the
  rest of the ladder.
  - **Parity doc**: Part 1 architecture row split into "server-side"
    and "real-time agent-side enforcement" — only the first is
    equivalent today; the second is in flight via Guardian. New gap
    entry G14 calls Guardian out as the CRITICAL parity feature.
    Priority matrix gains Phase 15 + Phase 16 rows; execution order
    diagram and total-effort estimate updated. Part 5 capability-map
    growth target raised from ~215 to ~225 to include the 10 new
    System Guardian capabilities.
  - **Capability map**: §16 title clarified to "Policy and Compliance
    Engine (Server-Side Guaranteed State)" with a header note
    explaining that real-time agent-side enforcement lives in §31. New
    §31 "System Guardian — Real-Time Agent-Side Guaranteed State"
    with 10 capabilities: Guardian Engine + wire protocol (Partial,
    PRs 1-2 shipped), Windows event guards, condition guards, Linux
    event guards, macOS event guards, state evaluator + remediation,
    audit journal + server store (Partial, PR 1 shipped), pre-login
    activation + offline capability (Done — service install side
    operational), dashboard + approval workflow, rule signing +
    quarantine integration. Totals adjusted: 166/225 done, 3 partial.
  - **Roadmap**: new Phase 16 with three issues (16.A Windows, 16.B
    Linux, 16.C macOS — gated on Windows soak; 16.C additionally
    gated on Endpoint Security entitlement) filed as #555-#557.
    Recommended execution order extends through Phase 16; total issue
    count updated to 126.
- **`docs/capability-map.md`: Phase 15 capabilities added (the WHAT).**
  Section 28 (Response Visualization) gained 28.4 TAR Dashboard Page,
  28.5 TAR Process Tree Viewer, 28.6 Retention Awareness Surface. New
  Section 30 (Scope Walking & Result Sets) covers 30.1 Result Set
  Persistence and Lineage, 30.2 Composable Scope from Previous Query,
  30.3 YAML DSL `fromResultSet:` Surface, 30.4 Result Set Operational
  Hardening. Progress totals adjusted: 165 done / 215 total / 1 partial
  (15.A is in flight, marked `:large_orange_diamond:`); the rest are
  honestly `:x:` Not Started. The capability map now describes what we
  will do; the roadmap's Phase 15 PR ladder describes how we will get
  there. Phase 15 issues filed on GitHub as #547 (15.A) through #554
  (15.H); the roadmap's "TBD" entries replaced with the issue links.
- **New `docs/tar-dashboard.md` + `docs/scope-walking-design.md`
  (Phase 15 design — see `docs/roadmap.md` Phase 15 PR ladder).** Two
  rigorous design documents covering (a) a dedicated TAR dashboard
  page with three frames — retention-paused source list, scope-walking-
  aware ad-hoc SQL, and process tree viewer reconstructed from
  `process_live` seed + events — and (b) the cross-cutting
  composable-scope-from-previous-query primitive that is Yuzu's
  product differentiator. Result-set storage schema (immutable
  lineage edges, TTL with pin override, source payload JSON for live
  re-eval), Scope Engine `from_result_set:<id>` short-circuit kind,
  REST API, YAML DSL `fromResultSet:` surface, dashboard sidebar +
  breadcrumb, audit chain. Reference walkthrough is the Chrome
  incident-response scenario — operator iteratively narrows from
  `__all__` → all-windows → windows-chrome → windows-chrome-bad-hash
  → windows-chrome-compromised → quarantine + remediate +
  un-quarantine + heightened-IOC watch, with every step's audit row
  carrying `parent_result_set_id` and `result_result_set_id` so
  forensic reconstruction shows the full reasoning chain.
  `CLAUDE.md` routed-concerns table gains pointers to both docs;
  `docs/roadmap.md` gains Phase 15 (8 issues, 15.A–15.H) with the
  PR ladder explicit. PR-A (TAR page shell + retention-paused list)
  is the first slice and is in progress.
- **New `docs/tar-implementer.md` (issue #60).** The implementer-facing
  companion to `docs/user-manual/tar.md`, covering: TAR as a
  forensics + inventory capability (and what TAR is *not*); the
  collect_fast / collect_slow / rollup data flow; the on-disk format
  (plain SQLite WAL today, with explicit honest notes that
  encryption-at-rest via SQLCipher and page-level compression are
  deferred); persistence semantics across in-place upgrade, uninstall,
  reinstall, and `data_dir` change; the post-restart double-capture
  caveat for TCP and the design rationale for keeping it (forensic
  completeness over heuristic suppression); device-impact expectations
  measured on a 5950X (worst-case per-collect timings, default-retention
  disk usage); and a routine-debugging entry-point table. The doc
  closes the issue's "supportable without the original upstream page"
  acceptance criterion. `docs/user-manual/tar.md` gained a top-of-page
  pointer to it for engineers.
- **`docs/user-manual/tar.md`** gained an "OS compatibility matrix"
  section (per-OS capture method + constraints for each source, status
  legend) and a configuration table extended with the seven new
  `configure` parameters introduced by issue #59. Includes a worked
  example combining retention, fast_interval, user_enabled=false, and
  process_stabilization_exclusions.
- **`docs/user-manual/server-admin.md` now documents the gRPC TLS
  flag surface (governance docs Finding 3 / enterprise-readiness
  blocker).** The "Server CLI Flags" table gained entries for `--no-tls`,
  `--cert`, `--key`, `--ca-cert`, `--insecure-skip-client-verify`,
  the deprecated `--allow-one-way-tls`, and the three `--management-*`
  override flags. The "TLS Configuration" section now distinguishes
  the two independent TLS surfaces (HTTPS dashboard vs. gRPC agent +
  management listeners), shows the full mTLS / one-way-TLS / `--no-tls`
  invocation patterns, and adds an "Upgrade note (v0.12.0)" subsection
  walking operators through the `YUZU_ALLOW_INSECURE_TLS=1` requirement
  with a copy-pasteable systemd drop-in. An Ansible role can now be
  authored from this doc alone.

### Security

- **`--allow-one-way-tls` renamed to `--insecure-skip-client-verify`,
  now requires `YUZU_ALLOW_INSECURE_TLS=1` (issue #79).** Disabling
  client certificate verification on the server's agent listener
  previously required only a single `--allow-one-way-tls` CLI flag and
  emitted a single `spdlog::warn()` line at startup. A copy-paste
  mistake or an operator unfamiliar with the flag could silently
  downgrade an mTLS deployment to one-way TLS — any reachable peer
  could then register without a client certificate. The flag has been
  renamed for clarity, the server now refuses to start unless the
  matching `YUZU_ALLOW_INSECURE_TLS=1` environment variable is also set
  as a second confirmation, and a multi-line ERROR-level banner is
  logged at startup. While the listener is running in this degraded
  mode a background thread re-emits the warning every 5 minutes so the
  posture remains visible after the startup logs scroll off
  (`server/core/src/main.cpp`, `server/core/src/server.cpp`). The
  operator dashboard's TLS row turns red and renames the field to
  "Insecure Skip Client Verify"
  (`server/core/src/settings_routes.cpp`). The deprecated
  `--allow-one-way-tls` flag is still accepted for one release with a
  startup deprecation warning and will be removed thereafter; existing
  deployments must add `YUZU_ALLOW_INSECURE_TLS=1` to their environment
  on upgrade or supply `--ca-cert` to re-enable full mTLS.
  `SECURITY_REVIEW.md` MEDIUM finding marked resolved against this
  release.
- **Management listener now gated by the same `YUZU_ALLOW_INSECURE_TLS=1`
  check as the agent listener (governance C-79-1 follow-up).** Previously
  the management gRPC listener (port 50052) called
  `build_tls_credentials(..., /*allow_one_way_tls=*/true, ...)` with the
  flag hardcoded — an operator who set `--management-cert` /
  `--management-key` without `--management-ca-cert` got an
  unauthenticated management plane with no env-var gate, no banner, and
  no recurring reminder. The `true` literal has been replaced with
  `cfg_.allow_one_way_tls`, so the management listener is now subject to
  the same two-factor confirmation as the agent listener
  (`server/core/src/server.cpp`). On upgrade, deployments that supply
  management cert + key without management CA cert must also pass
  `--insecure-skip-client-verify` and `YUZU_ALLOW_INSECURE_TLS=1`.
- **`--no-tls` startup banner (governance C-79-2 follow-up).** `--no-tls`
  remains intentionally ungated — it is the supported posture for local
  UAT, customer demos, and development until the CA/CSR pipeline is
  automated. The flag now emits a multi-line ERROR-level startup banner
  spelling out that both the agent gRPC listener AND the management
  gRPC listener accept plaintext from any peer with no encryption and
  no peer authentication, and that the administrative surface is
  ungated. The 5-minute recurring reminder thread also fires under
  `--no-tls`, not just `--insecure-skip-client-verify`
  (`server/core/src/main.cpp`, `server/core/src/server.cpp`).
- **TLS-degraded posture now writes audit events for SOC 2 CC7.2
  evidence (governance H-3 / compliance Finding 2).** The 5-minute
  reminder thread now writes an `AuditEvent` (`action: "server.tls_degraded"`,
  `principal: "system"`, `result: "warning"`) to `audit_store_` for every
  recurring tick, in addition to the existing ERROR-level spdlog line.
  Without this hookup, `journald` / SIEM forwarding was the only durable
  evidence of degraded-mode duration; `audit.db` queries for "show me
  every period the server ran without mTLS" returned nothing. The
  startup gate-failure case (server refuses to start) remains spdlog +
  systemd-journal only by structural necessity (audit_store is not yet
  initialized at that point).

### Tests

- **`tests/unit/test_tar_warehouse.cpp`** — new Catch2 suite for issue
  #60 (15 cases / 284 assertions). Pins: every source/granularity has
  a `CREATE TABLE` and a timestamp index in `generate_warehouse_ddl()`;
  `columns_for_table` returns `id` + every declared column for every
  table; every `$Dollar_Name` is a unique round-trip;
  process / tcp / service / user rollups cite the correct lower-tier
  source and upper-tier target; service rolls up only to hourly (no
  daily/monthly); user rollup has the day-bucket midnight-rollover
  arithmetic and tracks login_count / logout_count as a count-of-events
  rather than session-duration; row-count retention uses the H6 OFFSET
  pattern (not the older O(n*k) NOT IN); time-based retention uses a
  cutoff predicate; each granularity's retention SQL touches *only*
  that granularity (independence invariant); and post-restart TCP
  diff-with-empty-previous yields all-`connected` events (the
  documented forensic-completeness double-capture caveat).
- **`tests/unit/test_tar_schema_registry.cpp`** — new Catch2 suite for
  issue #59 (6 cases / 44 assertions). Pins: every source declares
  windows + linux + macos rows; every non-`kUnsupported` row has a
  non-empty `capture_method` + `notes`; `accepted_capture_methods` is
  deduped + sorted + non-empty; unknown source returns empty; all
  `kPlanned` methods stay in the accept-list (so operators can
  pre-stage); `kUnsupported`-only methods are excluded.
- **`tests/unit/server/test_insecure_tls_gate.cpp`** — new Catch2 suite
  pinning the #79 env-var gate. Constants `kInsecureTlsEnvVar` /
  `kInsecureTlsEnvAuthorizedValue` are pinned to their documented
  values, and `insecure_tls_env_authorized()` is exercised against
  nullptr, the empty string, `"0"`, `"true"` (any case), `"yes"`,
  `"on"`, `"enabled"`, whitespace-padded `"1"`, `"10"`, `"1abc"`, and
  the only authorizing value `"1"`. The exact-match policy is the
  point — any future "be permissive" change to the gate would have to
  delete a test case and survive review.
- **`tests/unit/test_tar_aggregator.cpp`** — extended with 4 PR-A
  cases (issue #547) pinning the
  `apply_source_enabled_transition()` helper and the
  `<source>_paused_at` semantics: enabled→disabled writes the
  passed timestamp; disabled→enabled clears to `"0"`; idempotent
  re-set leaves the timestamp untouched (so repeated configure
  round-trips don't pretend the pause is fresher than it is); per-
  source isolation (disabling `process` does not touch `tcp` /
  `service` / `user` paused_at). The four cases sit alongside the
  existing #539 retention-guard suite — same fixture pattern, same
  `yuzu::test::TempDbFile` shared helper.
- **`tests/unit/test_tar_aggregator.cpp`** — original 4-case Catch2
  suite pinning the issue #539 retention guard. Reproduces the chaos-injector
  CHAOS-2 scenario (48 hourly rows seeded across a 48h window centred
  on the test's `now`, disable the source, run retention) and asserts
  every row survives. Counter-tests pin that enabled sources still age
  out, that re-enabling a disabled source resumes retention, and that
  disabling one source does not pause retention on the others — so a
  future refactor cannot turn the per-source guard into a global
  switch without deleting a named test case. Adds
  `agents/plugins/tar/src/tar_aggregator.cpp` to the TAR test
  executable's source list (the existing tests are schema-registry-only
  and did not exercise the rollup engine). Tests use
  `yuzu::test::TempDbFile` per the shared-helper convention in
  `tests/unit/test_helpers.hpp`.
- **`tests/unit/test_tar_schema_registry.cpp`** — orphaned `lsof`
  assertion fixed. The test on line 73 still expected the macOS TCP
  capture-method accept-list to contain `"lsof"`, but commit
  `5a41db5` corrected the registry to `"proc_pidfdinfo"` (matching
  the actual collector `proc_listallpids` + `proc_pidfdinfo` via
  libproc). The test was missed in that commit's update wave; this
  closes the loop and includes a forward-pointer to the SHA in the
  comment so a future code archaeologist can find the rationale.

## [0.11.0] - 2026-04-25

### Fixed

- **Settings → Users: short-password submission now shows the real rejection
  instead of failing silently.** `POST /api/settings/users` in
  `server/core/src/settings_routes.cpp` was fire-and-forgetting the bool
  return from `AuthManager::upsert_user`, which silently rejects passwords
  shorter than 12 characters (G2-SEC-A1-003). When an operator typed a
  short password, the handler still logged `"User added/updated"`, wrote
  a **success** entry to `audit_store`, and emitted the `"User created"`
  green toast via HX-Trigger — while nothing was persisted. UAT reported
  this as "setting a password less than 12 characters silently fails."
  The handler now checks the return, audits
  `user.upsert / denied / weak_password`, returns HTTP 400, and emits
  `{"showToast":{"message":"Password must be at least 12 characters",
  "level":"error"}}` so the dashboard shows a red toast and the user is
  not created. The rendered add-user fragment also carries HTML5
  `minlength="12"` plus an inline `(min 12 chars)` helper label so the
  browser surfaces the rule natively before the submit round-trip —
  defence-in-UX, not a security control; the server-side check remains
  canonical. Three new test cases in
  `tests/unit/server/test_settings_routes_users.cpp` pin the denial
  (short password, 11-char boundary, fragment-carries-minlength).

### Changed

- **Governance Gate 7 hardening round — `/governance 4b35786..HEAD`.**
  Closes the findings from the full governance re-run on `dev` after
  Guardian PR 2 merged. No new functionality; tightens four correctness
  and accuracy gaps against the existing entries on this branch.
  - **`ci.yml` `Upload meson-logs` trigger broadened from `failure()` to
    `failure() || cancelled()`** (ci-C1 / Gate 5 CH-3 / Gate 6 OB-1).
    The motivating scenario for #501 — rapid-dev-push concurrency cancel
    on the Windows leg — makes `failure()` evaluate false, silently
    dropping the forensic artifact on the exact runs that need it most.
    `if-no-files-found: warn` already covers cancels that fire before
    meson writes `testlog.txt`, so there is no false-positive risk.
  - **`guardian_engine.hpp` `get_status()` doc comment corrected**
    (hp-F1). The header had claimed rules report `status="compliant"`
    in PR 2; the implementation at `guardian_engine.cpp:223-225,249`
    pessimistically reports `status="errored"` for every rule because
    no evaluator is running yet. Pre-existing drift from the Guardian
    PR 2 baseline caught by the Gate 4 happy-path review. Matching
    comment in `guardian_engine.cpp` also tightened. Speculative
    "Dashboards surface … as 'Guardian installed but inert'" phrasing
    removed — no such dashboard presentation exists yet; it is a PR 3
    concern.
  - **CHANGELOG scope correction for the #482 follow-up list**
    (doc-GS1 / Gate 4 CA-1). The original TempDbFile migration entry
    named `test_rest_guaranteed_state.cpp`, `test_rest_api_tokens.cpp`,
    `test_rest_api_t2.cpp`, and `test_kv_store.cpp` as the remaining
    sibling test files still managing their own RAII. Those four were
    already remediated in prior commits; the Gate 4 consistency audit
    caught the misattribution. The accurate 6-file list is now carried
    in the TempDbFile entry below (`test_tar_store.cpp`,
    `test_api_token_store.cpp`, `test_management_group_store.cpp`,
    `test_settings_routes_users.cpp`, `test_guaranteed_state_store.cpp`,
    `test_plugin_loader.cpp`).
  - **#501 entry rewritten for factual accuracy** (doc-GS2 / Gate 7
    re-review BLOCK-1). The original entry described the fix as
    "switching from `Map::operator[]` to `Map::insert`"; that framing
    contradicts `.claude/agents/build-ci.md`, which documents both APIs
    as equally ineffective (both go through `raw_hash_set`'s bucket-
    index path). The merged fix is the `YUZU_EXPORT
    guardian_dispatch_push_bytes_for_test` DLL-side helper; the entry
    now reflects that, and cross-platform's verification that the
    sibling `server.cpp` pattern is safe (server_core is a
    `static_library`) is carried into the entry rather than left as an
    open follow-up.
  - **Test substring assertions space-anchored** (test-T1 / Gate 3
    qe-S3). `tests/unit/test_guardian_engine.cpp:208-214` now matches
    `"applied=1 "` (trailing space) and `" generation=42 "` (both
    sides) so that a future test growing to 10-rule batches cannot
    silently pass a stale `"applied=1"` check against `"applied=10"`
    output.

- **CI observability: upload `meson-logs/` as artifact on Windows test
  failure (#501).** meson + ninja truncate test stdout to the last 100
  lines in the GitHub Actions UI, which hides all but one assertion
  expansion when a test fails with multiple asserts.
  `meson-logs/testlog.txt` contains the full Catch2 output for every
  failed test. Issue #501 tracks a Windows-only `yuzu_agent_tests`
  failure that can't be diagnosed from the truncated log —
  two failing test cases and seven assertions are known, but only one
  expansion currently escapes the truncation. Artifact retention 14
  days, keyed on `build-type + run-attempt` so re-runs don't overwrite
  each other. Added to the Windows MSVC leg only; Linux and macOS
  will get the same treatment in a follow-up once this one has proven
  useful.

- **Windows runner hardening: broaden Defender exclusions + migrate
  project scripting to PowerShell 7+ (`pwsh.exe`) (#501, #516, #517).**
  Two coupled changes shipped together.

  First, **`scripts/windows-runner-defender-exclusions.ps1`** gains
  `C:\WINDOWS\SystemTemp\yuzu_*` as a wildcard path — the prior
  exact-path entries (`yuzu_test_guardian`, `yuzu_test_kv`) did NOT
  match the actual runtime directory names the test suite creates
  (`yuzu_test_guardian_SHULGI$`, `yuzu_test_kv_SHULGI$`,
  `yuzu_test_reserved_plugin_<random>`, `yuzu_trigger_test`). Three
  test binaries (`yuzu_agent_tests.exe`, `yuzu_server_tests.exe`,
  `yuzu_tar_tests.exe`) and two release binaries (`yuzu-agent.exe`,
  `yuzu-server.exe`) are added to `ExclusionProcess` — Defender has
  been observed retaining handles on freshly-written `.obj` / `.pdb`
  siblings after these processes exit, contributing to the EBUSY
  loop we hit on #501's rerun of 2026-04-24.

  Second, **stock Windows PowerShell 5.1 (`powershell.exe`) is no
  longer supported for Yuzu-authored scripting**; the project standard
  is PowerShell 7+ (`pwsh.exe`). Reason: the repo saves `.ps1` files
  as UTF-8 without BOM (POSIX / git convention), and PS 5.1 reads
  such files as the system ANSI codepage (Windows-1252 on English
  installs), which mangles non-ASCII characters — a right-double-quote
  byte at 0x94 closes a string literal early and downstream tokens
  become "command not found" errors. PS 7+ defaults to UTF-8. The
  `yuzu-local-windows` runner already has `pwsh.exe` 7.6.1
  pre-installed; 7 workflow steps across `release.yml` and
  `pre-release.yml` were already on `shell: pwsh`. Concrete changes:
  - Preflight guard at the top of
    `scripts/windows-runner-defender-exclusions.ps1`:
    `PSVersionTable.PSVersion.Major -lt 7` → `Write-Error` + `exit 1`
    with an actionable message (after the `[CmdletBinding()]`/`param`
    block, per PS's required ordering).
  - `docs/yuzu-guardian-design-v1.1.md:781` example guard command
    changed from `powershell.exe -NonInteractive …` to
    `pwsh.exe -NonInteractive …`.
  - `docs/windows-build.md` gains a new **PowerShell: pwsh.exe only**
    section documenting the standard and the preflight pattern.

  Three latent bugs in the exclusion-applicator script fixed along
  the way: (a) `<path>` in a double-quoted `Write-Host` string
  tripped PS's redirection parser; now single-quoted. (b) Hostname
  allowlist default `^yuzu-local-windows` never matched
  `$env:COMPUTERNAME` (which is `SHULGI` — the physical machine name,
  not the GitHub Actions runner role label); default now `^SHULGI$`.
  (c) Unicode box-drawing characters in `Write-Host` banners now
  work correctly (they would have required UTF-8 BOM under PS 5.1;
  the PS 7+ preflight makes that irrelevant).

- **Tests: route Guardian dispatch test `CommandRequest` population through
  a DLL-side helper — unblocks Windows MSVC debug CI (#501).** Two test
  cases in `tests/unit/test_guardian_engine.cpp` were tripping a static-
  linkage limitation that falls out of the Windows option D
  `cxx.find_library()` wiring documented in CLAUDE.md / #375. Root cause:
  `absl::hash_internal::MixingHashState::Seed()` returns the ADDRESS of
  `kSeed`. `absl_hash.lib` is linked statically into both the test EXE
  and `yuzu_agent_core.dll`, so each image holds its own `kSeed` at a
  different virtual address. Protobuf `Map<K,V>` mixes that address into
  every bucket-index calculation, so an `insert()` performed in the test
  EXE and a `find()` performed inside the DLL compute different buckets
  for the same key. The test dispatch silently fell into the
  "missing 'push' parameter" branch, yielding exit_code=1 instead of 0/2.
  Deterministic and reproducible on `build-windows-ci`; issue #501 has
  the testlog.

  The fix adds a `YUZU_EXPORT guardian_dispatch_push_bytes_for_test`
  helper in `agents/core/src/guardian_engine.cpp` that constructs the
  `CommandRequest` and populates its `parameters` map INSIDE the DLL,
  then dispatches. Both the insert and the find now execute against the
  DLL's copy of `kSeed`. An earlier attempt in the PR swapped
  `Map::operator[]` for `Map::insert({k,v})` on the test side —
  **that workaround is ineffective** and was reverted: both APIs go
  through the same `raw_hash_set` bucket-index path and both are tripped
  by the cross-image seed split. `.claude/agents/build-ci.md` gains a
  new "#501 Windows DLL-boundary absl hash seed mismatch" section that
  documents the failure mode, the DLL-helper fix, the audit pattern for
  future tests that populate a proto `map<K,V>` in EXE code and pass it
  to DLL-side code, and the six other approaches that do not work.

  Production agents are unaffected because the gRPC Subscribe stream
  parses `CommandRequest` bytes inside `yuzu_agent_core.dll`, so
  population and lookup share a seed. `server/core/src/server.cpp:{2395,
  4316,4434,4577}` uses the same `(*cmd.mutable_parameters())[k] = v;`
  pattern — **verified safe** by the Gate 3 cross-platform review:
  `yuzu_server_core` is a `static_library`, not a DLL, so there is no
  cross-image boundary for the bucket index to diverge across.

- **`.claude/agents/` cleanup — token efficiency + routing effectiveness.**
  Audit-driven sweep of the subagent frontmatter and a few body-text
  fixes that bring the descriptions in line with how the parent agent
  actually picks subagents.
  - **Bug fix:** `workflow-orchestrator.md` declared `TodoWrite` in its
    `tools:` list. The harness has long since migrated to the
    `Task*` family (`TaskCreate`, `TaskUpdate`, `TaskList`, `TaskGet`,
    `TaskOutput`, `TaskStop`); `TodoWrite` resolves to nothing and the
    orchestrator's progress-tracking calls silently no-op'd. Replaced
    with `TaskCreate, TaskUpdate, TaskList`.
  - **Merged `erlang-dev` into `gateway-erlang`.** The two agents had
    overlapping scope ("generic Erlang" vs "Yuzu Erlang gateway") with
    no clean disjoint routing rule, and the gateway is the only Erlang
    component in the codebase, making `erlang-dev` functionally
    redundant. `gateway-erlang` now carries the full body of both:
    OTP supervision trees, rebar3 + EUnit + CT + dialyzer toolchain,
    `prometheus_httpd` pitfalls, gpb↔protoc compat, plus the language-
    expert content (process lifecycle rules, EXIT-signal semantics,
    EUnit isolation recipe, mock-process-leak diagnosis from #336,
    Erlang idioms, anti-patterns table). References updated in
    `CONTRIBUTING.md`, `.claude/agents/workflow-orchestrator.md`
    (gate-3 agent list + domain-trigger map), and
    `.claude/skills/governance/SKILL.md`.
  - **Tightened body wording in `docs-writer` and `quality-engineer`**
    so it matches their read-only `tools:` lists. Both are governance
    *reviewers*: their output is a structured findings report
    (required doc updates / missing test coverage / fixture leaks)
    that the producing agent then applies. Previous wording
    ("produce documentation diff", "Maintain `docs/test-coverage.md`",
    "Expand EUnit coverage") implied authoring authority they don't
    have.
  - **Rewrote `description:` for the five highest-traffic agents** in
    "use when…" routing-instruction style instead of role-label style:
    `cpp-expert`, `security-guardian`, `docs-writer`, `cross-platform`,
    `build-ci`. The descriptions now name the file patterns / change
    classes that should trigger each agent, so the parent's routing
    decision is mechanical rather than interpretive.

- **Tests: migrate `GuardianFixture` in `test_guardian_engine.cpp` to
  `yuzu::test::TempDbFile` RAII (#482).** Replaces the fixture's
  hand-rolled destructor (`kv_path` member + three manual `fs::remove`
  calls on `.db` / `-wal` / `-shm`) with the shared
  `TempDbFile`-as-first-member pattern documented in CLAUDE.md. Also
  migrates the sibling `[guardian][engine][persistence]` test case
  (line 277) which was managing cleanup the same way. Added a new
  path-accepting `TempDbFile(std::filesystem::path)` constructor to
  `tests/unit/test_helpers.hpp` so fixtures that need a per-UID
  subdirectory (agents/tests/unit/test_guardian_engine.cpp keeps files
  under `yuzu_test_guardian_<uid>/` so shared dev boxes don't collide
  between users) can adopt a precomputed path while still getting the
  destructor-fires-on-partial-construction guarantee. The
  `unique_kv_path()` helper is retained — it composes `unique_temp_path`
  with the per-UID dir prefix and remains the single uniqueness source
  for this test file. Progresses #482; six sibling test files still
  carry the flake-#473 salt pattern (`std::hash<std::thread::id>` +
  `steady_clock::now()`, or a fresh `random_device` per construction)
  instead of the shared `yuzu::test::TempDbFile` helper:
  `tests/unit/test_tar_store.cpp`,
  `tests/unit/server/test_api_token_store.cpp`,
  `tests/unit/server/test_management_group_store.cpp`,
  `tests/unit/server/test_settings_routes_users.cpp`,
  `tests/unit/server/test_guaranteed_state_store.cpp` (has its own
  local duplicate `struct TempDbFile` — switch to the shared helper),
  and `tests/unit/test_plugin_loader.cpp`. Left for follow-up so this
  PR stays bisectable.

- **BREAKING (licensing): Yuzu is now distributed under AGPL-3.0-or-later
  (community edition) with a separate commercial license for the new
  `enterprise/` subtree.** Previously the repository was Apache-2.0. The
  motivation is §13 of the AGPL: any operator running a modified Yuzu as a
  network service must offer the modified source to users of that service.
  This protects the commons and the viability of a commercial enterprise
  edition, which a permissive licence would not.

  Releases tagged v0.11.0-rc2 and earlier **remain licensed under
  Apache-2.0** for everyone who received them — Apache grants are perpetual
  and we are not retroactively re-licensing past code. The first release
  cut after this entry lands is the first AGPL-era release.

  Mechanical changes in this commit:
  - `LICENSE` replaced with the verbatim AGPL-3.0 text from
    `https://www.gnu.org/licenses/agpl-3.0.txt`.
  - New top-level `NOTICE` file records the copyright holder, relicensing
    history, dual-licensing boundary, SDK linking exception, and starter
    third-party attribution roll-up.
  - `meson.build` `license:` field → `AGPL-3.0-or-later`.
  - `vcpkg.json` `license` field → `AGPL-3.0-or-later`.
  - `gateway/apps/yuzu_gw/src/yuzu_gw.app.src` `licenses` → `["AGPL-3.0-or-later"]`
    (fixes a legacy `"Proprietary"` drift).
  - `deploy/docker/Dockerfile.ci-gateway`,
    `deploy/docker/Dockerfile.ci-linux`, and
    `.github/workflows/release.yml` OCI image-label `org.opencontainers.image.licenses`
    set to `AGPL-3.0-or-later` (the release-workflow entry previously
    incorrectly said `MIT`).
  - `README.md` License section rewritten to document the AGPL core, the
    enterprise SKU, and the SDK linking exception.

- **New `enterprise/` subtree — opt-in commercial module surface.** Added
  as empty scaffolding behind the new Meson option
  `-Denable_enterprise=true` (default `false`). Does not compile into OSS
  builds. Includes `enterprise/README.md`, a placeholder
  `enterprise/LICENSE-ENTERPRISE.md` (TODO: legal review before shipping
  paid builds), and `enterprise/meson.build`. First real premium feature
  (SAML/SSO) will land in a follow-up PR. See
  `docs/enterprise-edition.md`.

- **Contributor License Agreement (CLA) introduced.** New `CLA.md` (based
  on the Harmony 1.0 template, pending counsel review) assigns copyright
  to the project steward with a broad re-license grant covering both AGPL
  and commercial use. `CONTRIBUTING.md` updated to reference it; a
  disabled-by-default CLA-bot stub at `.github/workflows/cla.yml` is
  included — ops must provision `CLA_REPO_ACCESS_TOKEN` to activate.
  Accepting external contributions before activation would lock those
  contributions to AGPL-only.

- **Plugin SDK linking exception documented.** New `sdk/LICENSE-SDK.md`
  carves out dynamically-loaded plugins that consume only the stable
  `plugin.h` C ABI, analogous to the GCC Runtime Library / Classpath
  Exception. Proprietary plugins remain permitted. Wording must be
  legal-reviewed before the first AGPL-era release ships.


  + exclude vendored and generated paths from CodeQL scanning.** Two
  security-tooling follow-ups surfaced by the first real CodeQL scan
  after the Scorecard lift landed.
  - **Code injection fix.** CodeQL critical rule
    `actions/code-injection/critical` flagged line 49 of
    `.github/workflows/pre-release.yml`, where
    `${{ github.event.workflow_run.head_branch }}` was interpolated
    directly into the bash `run:` block of the "Determine version" step.
    `workflow_run` is an externally-influenced event trigger, and branch
    or tag names can carry shell metacharacters. Rebound both
    `head_branch` and the `workflow_dispatch` `inputs.tag` value to step-
    level `env:` entries (`EVENT_BRANCH`, `INPUT_TAG`) and reference them
    as shell variables — the canonical Actions security pattern.
  - **CodeQL scope.** Added `.github/codeql/codeql-config.yml` with a
    `paths-ignore` list (`vcpkg_installed/**`, `build-*/**`,
    `builddir*/**`, `_build/**`) and wired it into the `codeql-action/init`
    step via `config-file:`. Previously the scan indexed every header
    under `vcpkg_installed/x64-linux/include/` — protobuf, abseil,
    httplib — producing one "critical" (protobuf `map.h`) + six "high"
    (abseil `raw_hash_set.h`, protobuf tctable, httplib `non-https-url`)
    findings that are upstream-vendor bugs we cannot fix in-tree and
    would be erased by the next vcpkg cache rebuild. Excluding them
    collapses the noise and leaves first-party findings visible.

- **Isolate `yuzu_gw_real_upstream_SUITE` from CI's gateway CT discovery.**
  The suite needs a live `yuzu-server` reachable on `127.0.0.1:50055`
  AND `YUZU_GW_TEST_TOKEN` set (or `scripts/linux-start-UAT.sh` to have
  just run); CI provisions neither. Previously the suite was registered
  alongside the regular CT tree and ran as part of `meson test --suite
  gateway`, where it failed deterministically on the Windows MSVC runner
  (TCP probe to `:50055` succeeded against an unrelated listener bound by
  WSL2 port-forwarding from the same physical box, so the suite proceeded
  to the gRPC `ProxyRegister` call and exploded). Linux hid the failure
  because the self-hosted runner has no `rebar3` on PATH and the entire
  gateway CT step is skipped at meson configure time.
  - **Move:** `gateway/apps/yuzu_gw/test/yuzu_gw_real_upstream_SUITE.erl`
    → `gateway/apps/yuzu_gw/integration_test/yuzu_gw_real_upstream_SUITE.erl`.
    `git mv` so file history follows.
  - **rebar3 wiring:** add `{extra_src_dirs, [{"integration_test",
    [{recursive, false}]}]}` under the `test` profile in
    `gateway/rebar.config` so the moved suite still compiles in the test
    profile but is reachable only via explicit `--dir
    apps/yuzu_gw/integration_test`.
  - **CI invocation:** `scripts/test_gateway.py ct` (called by the meson
    `gateway ct` test target) keeps using `--dir apps/yuzu_gw/test` and
    no longer discovers the suite — verified locally: 6 suites / 52
    tests, all pass, no `yuzu_gw_real_upstream_SUITE` entry.
  - **`/test` invocation:** `.claude/skills/test/SKILL.md` Phase 5 now
    runs a second `gate_run "CT real-upstream"` step that targets `--dir
    apps/yuzu_gw/integration_test --suite=yuzu_gw_real_upstream_SUITE`,
    relying on Phase 4's `linux-start-UAT.sh` to have stood up the
    server and provisioned the enrollment token. Doc-comment in the
    SKILL warns about the prerequisites and the per-case
    `{test_case_failed, "No enrollment token: …"}` failure mode if
    either is missing.

- **CI dedup: drop `feature/**` and `fix/**` from the `push:` triggers in
  `ci.yml` and `docs-lint.yml`.** Pushes to feature/fix branches with an
  open PR previously fired both the `push` and `pull_request` events on
  the same SHA, doubling runner consumption for every commit pushed to a
  PR branch. Mainline branches (`main`, `dev`) remain on the `push:`
  list so merge runs still fire exactly once. Pre-PR work (no PR open
  yet) no longer runs CI automatically — open the PR earlier or use the
  existing `workflow_dispatch` trigger to fire it manually.

- **Digest-pin Dockerfile `FROM` lines, replace `curl | sh` installers,
  and hash-pin `requirements-ci.txt` (PR #3 of Scorecard lift).**
  Completes Scorecard's `Pinned-Dependencies` check — the remaining
  two-thirds after PR #2 addressed the GitHub Actions third. Changes:
  - **Dockerfile `FROM` digest pins.** Eight `deploy/docker/Dockerfile.*`
    base images were previously referenced by tag only
    (`ubuntu:24.04`, `erlang:28`, `alpine:3.23`). Pinned each to its
    current multi-arch index digest. `Dockerfile.runner-linux` — which
    seeds the self-hosted runner image on Shulgi — is now pinned to an
    exact digest of `ghcr.io/actions/actions-runner:latest`; Dependabot's
    `/deploy/docker` docker scope will continue to propose bumps as new
    runner releases ship.
  - **`curl | bash` NodeSource installs replaced with verified tarball
    download.** `Dockerfile.ci-linux` and `Dockerfile.ci-gateway` both
    installed Node.js 20 via `curl -fsSL https://deb.nodesource.com/setup_20.x | bash -`,
    which Scorecard flags as unverified code execution. Replaced with a
    direct `.tar.xz` download from `nodejs.org` + `sha256sum -c`
    verification. `NODE_VERSION` and `NODE_SHA256_LINUX_X64` are `ARG`
    pairs so bumps are atomic.
  - **Trivy installer replaced with `aquasecurity/trivy-action`.**
    `pre-release.yml` was installing Trivy via `curl -sfL … install.sh | sh`;
    swapped for the SHA-pinned `aquasecurity/trivy-action@57a97c7e…`
    (v0.35.0). **Scope clarification:** while making this swap, removed
    the Trivy SBOM generation step entirely — `release.yml` already emits
    authoritative Syft-based SBOMs via `anchore/sbom-action` for every
    platform archive and container image, so Trivy's SBOMs were a
    redundant second source that disagreed on component enumeration.
    Trivy now does vulnerability scanning only (its strength); Syft owns
    SBOM generation across the entire release pipeline.
  - **Hash-pinned `requirements-ci.txt` via `pip-compile --generate-hashes`.**
    Added `requirements-ci.in` as the human-edited source; `pip-compile`
    regenerates `requirements-ci.txt` with `--hash=sha256:…` continuation
    lines. Every `pip install -r requirements-ci.txt` call in `ci.yml`
    and `release.yml` now uses `--require-hashes`; a tampered package
    would fail the install rather than silently execute. macOS pipx grep
    path updated (`awk '/^meson==/ {print $1}'`) to handle the trailing
    `\` that `pip-compile` adds to hashed requirement lines. Bump cadence
    documented at `docs/dependency-updates.md`.
  - **Docker Compose image digests.** `docker-compose.local.yml` and the
    root `docker-compose.uat.yml` referenced `prom/prometheus:latest`,
    `grafana/grafana:latest`, and `clickhouse/clickhouse-server:latest`.
    Aligned all three with the digest-pinned variants already used under
    `deploy/docker/docker-compose*.yml` (Prometheus v3.2.1, Grafana
    11.5.2, ClickHouse 24.12). Two `clickhouse-server:24.12` tag-only
    refs under `deploy/docker/` also gained digests.

- **SHA-pin every GitHub Actions reference for OpenSSF Scorecard
  Pinned-Dependencies check (PR #2 of Scorecard lift).** Scorecard's
  `Pinned-Dependencies` check scored 0 because every `uses:` line in
  `.github/workflows/*.yml` resolved by tag (`@v6`, `@v3`, `@v0`) rather
  than by immutable commit SHA — a compromised upstream could silently
  repoint the tag at a malicious commit. Rewrote all 144 `uses:` refs
  across 12 workflow files to the form
  `owner/repo@<40-char-sha> # vX.Y.Z`; the trailing version comment is
  mandatory so Dependabot can still detect newer releases and propose
  coordinated SHA+comment bumps. Floating-major refs (`anchore/sbom-action@v0`,
  `ilammy/msvc-dev-cmd@v1`, `erlef/setup-beam@v1`, `bufbuild/buf-setup-action@v1`,
  plus two cases where the `v3` major tag lagged the latest point release —
  `actions/attest-build-provenance` and `sigstore/cosign-installer`) are
  pinned to the latest exact X.Y.Z SHA rather than the floating major's
  current SHA, so the pin doesn't drift back when the major tag is
  eventually updated. `github/codeql-action/init` and `/analyze` are pinned
  to the same parent-repo SHA per CodeQL's documented invariant.
  Self-hosted runners (`yuzu-wsl2-linux`, `yuzu-local-windows`) are
  unaffected — action pins control which code runs on the runner, not the
  runner image itself. PR #3 will pin the remaining two thirds of
  `Pinned-Dependencies` (Dockerfile FROMs + `curl | sh` installers +
  pip hash-pinning).
- **Group Dependabot GitHub Actions PRs.** After SHA-pinning, Dependabot
  opens one PR per action per bump — roughly 3× the pre-pin weekly
  volume. Added a `groups:` block under the `github-actions` ecosystem
  in `.github/dependabot.yml` to bundle related cohorts:
  `actions-core` (`actions/*`), `docker-actions` (`docker/*`), and
  `github-codeql` (`github/codeql-action/*`). Ungrouped actions still
  ship as individual PRs.

- **Tighten GitHub Actions token permissions for OpenSSF Scorecard
  Token-Permissions check.** Scorecard's Token-Permissions check scored 0
  because `qodana_code_quality.yml` had no top-level `permissions:` block
  (one missing block zeroes the entire check) and several workflows
  declared writes at workflow scope that only specific jobs actually
  needed. Changes:
  - `qodana_code_quality.yml`: new top-level `permissions: contents: read`;
    dropped unused job-level `contents: write` + `pull-requests: write`
    (pr-mode is false, so the action never opens PRs); kept `checks: write`
    at job scope.
  - `release.yml`: demoted top-level `contents: write` + `packages: write`
    to job scope. `id-token: write` and `attestations: write` stay at
    workflow scope because every build job calls
    `actions/attest-build-provenance`. The `release` job gets explicit
    `contents: write` + `id-token: write`; `docker-publish` already had
    its own explicit block.
  - `vcpkg-baseline-update.yml`: top-level `permissions: contents: read`;
    moved `contents: write` + `pull-requests: write` into the
    `propose-bump` job.
  - `ci.yml`: removed unused top-level `packages: write` (the workflow
    doesn't push to any registry); top-level is now `contents: read` only.

- **Wire `SCORECARD_READ_TOKEN` PAT into `scorecard.yml`.** Scorecard's
  `Branch-Protection` check caps at ~3/10 without a PAT because the
  public GitHub API can't read Repository Rulesets. The action now
  receives `repo_token: ${{ secrets.SCORECARD_READ_TOKEN || github.token }}`
  so the ruleset-aware code path runs once the secret is populated. The
  `|| github.token` fallback keeps fork runs and first-time-setup scans
  succeeding. PAT creation + rotation procedure documented at
  `docs/security/scorecard-token.md` — classic PAT with `public_repo` +
  `read:org` scopes ONLY; 90-day expiration with a 365-day rotation
  cadence.

### Added

- **Guardian PR 2 — REST control plane + agent-side `GuardianEngine`
  skeleton.** Stands up the operator-facing surface and the agent
  scaffolding the rest of the Windows-first rollout grafts onto. No real
  guards are running yet; PR 3 lands the Registry Guard + state evaluator
  + remediation that turns the wire path into actual enforcement.
  - **Server REST endpoints under `/api/v1/guaranteed-state/*`.** Full CRUD
    on rules (`GET / POST / GET :id / PUT :id / DELETE :id`) plus `POST
    /push` (returns `202 Accepted` — fan-out is PR 3), `GET /events`
    (paginated query mirroring `audit_store` semantics; `limit` capped at
    1000 at the REST boundary), `GET /status`, `GET /status/:agent_id`,
    and `GET /alerts`. Conflict detection routes through `kConflictPrefix`
    → HTTP 409 (matching #396/#399/#402). Created/updated rules carry the
    session principal in `created_by` / `updated_by`. Every mutating route
    fires an audit event under target type `GuaranteedState`.
  - **New RBAC operation `Push` + securable type `GuaranteedState`.**
    Distributes a rule set to scoped agents — separated from `Write` so
    operators can be granted "deploy existing rules" without "author new
    rules." Default seeds: `Operator` gets `Read + Push`,
    `PlatformEngineer` gets full CRUD + `Push`, `Administrator` and
    `ITServiceOwner` get the cross-type defaults, `Viewer` gets `Read`.
    The cross-type `Push` grants on non-Guardian securables are harmless
    because only the Guardian REST handlers consult `Push`.
  - **Agent-side `GuardianEngine` class** (`agents/core/src/guardian_engine.{hpp,cpp}`).
    Two-phase startup per design §4: `start_local()` runs pre-network so
    the engine is enforcing before the Register RPC opens; `sync_with_server()`
    runs post-Register and is the future drain point for buffered events.
    Persists rules into `KvStore` under reserved namespace `__guardian__`
    as JSON (binary-safe across the SQLite text APIs `KvStore` wraps).
    `dispatch()` answers `__guard__` plugin commands `push_rules` and
    `get_status`; reserved-name dispatch is intercepted in `agent.cpp`
    *before* the plugin match loop so a third-party plugin cannot shadow
    Guardian (defence-in-depth alongside the load-time reservation that
    landed in #453). PR 2 reports every rule as `errored` because no
    guards are running yet — honest about "Guardian installed but inert"
    until PR 3.
  - **`TestRouteSink` parses query strings.** The test sink now splits
    request paths on `?` and feeds the tail to `httplib::detail::`
    `parse_query_text`, populating `req.params`. This unblocks unit-level
    coverage of every existing handler that branches on `req.has_param`
    / `req.get_param_value` (the `events` query parameters were the
    forcing function). Out-of-scope for the PR but a free win for any
    follow-up REST test.

- **Guardian: agent rejects plugins declaring a reserved internal-dispatch
  name (#453).** The agent plugin loader now refuses to load any plugin whose
  `YuzuPluginDescriptor::name` matches the reserved set `__guard__`,
  `__system__`, `__update__`. Rejected plugins are logged at `error` and
  counted in `yuzu_agent_plugin_rejected_total{reason="reserved_name"}` so
  operators can alert on reserved-name attempts distinct from generic load
  failures. Prevents a compromised plugin author (or a misconfigured
  third-party plugin) from shadowing the `__guard__` dispatch intercept that
  Guardian PR 3 will add at `agents/core/src/agent.cpp`. Reserved-name
  namespace documented in `docs/cpp-conventions.md`.

- **Guardian PR 2 prerequisites (#452).** Pre-REST-endpoint hardening of the
  `GuaranteedStateStore` so PR 2's ingest path can land on a production-ready
  foundation:
  - **`std::expected<T, std::string>` mutators with `kConflictPrefix`.**
    `create_rule`, `update_rule`, `delete_rule`, and `insert_event` now
    return `std::expected<void, std::string>` and surface duplicate-UNIQUE
    / PRIMARY KEY collisions as `kConflictPrefix`-prefixed errors so REST
    handlers can map them to HTTP 409 (matching #396/#399/#402). Not-found
    paths return a distinct non-conflict error so routes can split 404 from
    409 cleanly.
  - **`created_by` / `updated_by` audit columns on `guaranteed_state_rules`.**
    Added to the v1 migration (before schema freeze). REST handlers in PR 2
    populate both from the session principal; SOC 2 audit-chain
    reconstruction can now answer "who authorised this rule version" from
    the store alone, with the full `audit_events` join procedure documented
    in `docs/yuzu-guardian-design-v1.1.md` §9.3.
  - **Retention reaper on `guaranteed_state_events`.** 30-day default
    (new `guardian_event_retention_days` config, overridable via runtime
    config). Events carry `ttl_expires_at` populated at insert; a
    background thread mirroring `AuditStore::run_cleanup` runs a periodic
    `DELETE`. Partial index `idx_gse_ttl WHERE ttl_expires_at > 0` keeps
    the reap query fast at fleet-scale ingest. `retention_days = 0`
    disables expiry for forensic freezes.
  - **Batch `insert_events(std::vector<…>)` API.** Wraps a `BEGIN…COMMIT`
    envelope; one fsync per batch instead of one per row (10–50× faster at
    agent batch sizes). Transactional — any failing row rolls back the
    whole batch so REST handlers never have to reason about partial state.
  - **Prometheus observability.** Four new server gauges — `yuzu_server_`
    `guardian_rules_total`, `guardian_events_total`,
    `guardian_events_written_total`, `guardian_events_reaped_total`. Wired
    into the existing health-recompute thread alongside `audit_store`'s
    gauges; sized at zero before ingest starts so alert rules
    (e.g. `yuzu_server_guardian_events_total > 5e6`) can be authored up
    front.
  - **Data inventory entry.** `guaranteed_state_events` recorded in the
    workstream-E data inventory (`docs/enterprise-readiness-soc2-first-customer.md` §3.5)
    with the 30-day retention policy, reaper mechanism, and sizing
    guidance for customers with longer forensic SLAs.

- **Guardian "Guaranteed State" engine — wire contract + server store
  skeleton (PR 1 of the Windows-first rollout).** Landed dormant: a new
  SQLite file `guaranteed-state.db` is created in the server data directory
  at startup and a `guaranteed_state_store` entry appears in the `/readyz`
  probe response. No REST endpoints, no dispatch, no agent wiring, and no
  dashboard surface in this release — PR 1 ships only the proto (new package
  `yuzu.guardian.v1` at `proto/yuzu/guardian/v1/guaranteed_state.proto`),
  the server SQLite store, and 17 unit test cases. Operators upgrading will
  see the new `.db` file alongside the existing stores (same permissions,
  same backup story: copy the full `--data-dir`) and the new `/readyz` JSON
  key. Full architecture: `docs/yuzu-guardian-design-v1.1.md`. Windows-first
  delivery plan: `docs/yuzu-guardian-windows-implementation-plan.md`.

- **Supply-chain attestation bundle: CycloneDX + SPDX SBOMs, SLSA
  provenance, and cosign image signatures on every release (#362,
  #408).** The release workflow now emits, per tag, a full verifiable
  supply-chain artefact set:
  - **CycloneDX + SPDX SBOMs per platform archive** via
    [Syft](https://github.com/anchore/syft) (`anchore/sbom-action@v0`):
    `yuzu-{linux-x64,gateway-linux-x64,windows-x64,macos-arm64}.{cdx,spdx}.json`.
    Syft picks up vcpkg C++ dependencies (reading vcpkg's generated
    `vcpkg.spdx.json` under `vcpkg_installed/<triplet>/share/`), Erlang
    deps from `gateway/rebar.lock`, and metadata on the built
    ELF/PE/Mach-O binaries.
  - **CycloneDX + SPDX SBOMs per Docker image**
    (`yuzu-{server,gateway}-image.{cdx,spdx}.json`) generated by Syft
    scanning the pushed image by digest, so the SBOM is bound to the
    exact image layers customers will pull.
  - **SLSA v1.0 build provenance attestations** for every binary archive,
    installer, and Docker image via `actions/attest-build-provenance@v3`.
    Stored in GitHub's native attestation registry and verified
    customer-side with `gh attestation verify <file> --repo Tr3kkR/Yuzu`
    (images: `oci://ghcr.io/.../<image>@sha256:<digest>`).
  - **cosign keyless Docker image signing** for both
    `ghcr.io/tr3kkr/yuzu-server` and `ghcr.io/tr3kkr/yuzu-gateway`,
    bound to the release workflow's OIDC identity (no static keys to
    rotate). Existing cosign blob signature on `SHA256SUMS` is retained.
  - **New release-gate script** at
    `scripts/check-release-artifacts.sh` runs before `gh release create`
    and fails the release if any expected archive, installer, or SBOM
    is missing — preventing partially-attested releases from ever
    reaching customers.
  - **New operator doc** at
    [`docs/user-manual/release-verification.md`](docs/user-manual/release-verification.md)
    covers `sha256sum -c`, `cosign verify-blob`, `cosign verify` (images),
    `gh attestation verify` (binaries + images), and CycloneDX / SPDX
    inspection with `jq` and the CycloneDX CLI. Includes an end-to-end
    verification script and a compliance-mapping table (SOC 2 CC6.8 /
    CC7.1, NIST SSDF PW.5 / PS.3, EO 14028, EU CRA Annex V).
  - Top-level workflow permissions extended with `attestations: write`
    (required by `actions/attest-build-provenance`); `docker-publish`
    job gains `id-token: write` + `attestations: write`. `SHA256SUMS`
    now covers the SBOM files so customers can verify them alongside
    the archives. Release notes heredoc advertises the new verification
    workflow and links to the operator doc.
  - Effective at the next tag after merge. No CHANGELOG gate on
    historical releases — retro-generating provenance for shipped tags
    is out of scope.
- **OpenSSF Scorecard + Zizmor workflows (#407).** Added
  `.github/workflows/scorecard.yml` (weekly + push to main +
  `branch_protection_rule`; publishes to scorecard.dev + SARIF to the
  GitHub Security tab) and `.github/workflows/zizmor.yml` (static
  analyzer for `.github/workflows/*.yml`, runs on workflow-touching PRs
  + weekly). README now advertises the Scorecard and Zizmor badges; the
  OpenSSF Best Practices Badge slot is wired up pending manual
  application at bestpractices.dev. Triaging Scorecard findings into
  follow-up issues is the remaining work on #407.
- **README `Install`, `Contributing`, `Reporting Issues` sections
  (#407).** Addresses the OpenSSF Best Practices `[interact]` criterion
  — README now points prebuilt-binary users at GitHub Releases +
  `ghcr.io/tr3kkr/yuzu-{server,gateway,agent}` + `deploy/docker/docker-compose.yml`
  instead of only documenting the from-source build. Adds explicit
  links to `CONTRIBUTING.md`, `CLAUDE.md`, the bug-report and
  feature-request issue templates, `SECURITY.md` (private vulnerability
  reporting), and GitHub Discussions.

### Fixed

- **Guardian PR 2 hardening round 5 — doc-RR1..doc-RR4 (documentation only).**
  Closes the BLOCKING and SHOULD doc findings from the second governance
  re-run on `21c0ba4..HEAD` (rounds 3 + 4). Pure documentation — no code
  changes, no behaviour changes. The re-run confirmed that rounds 3 + 4
  introduced no new code regressions; all remaining findings were either
  doc precision gaps or pre-existing patterns newly visible after the
  `/push` sanitisation fix (filed as follow-up issues).
  - **`docs/user-manual/audit-log.md` `guaranteed_state.push` entry now
    documents the scope-sanitisation semantic** (doc-RR1). The SIEM-
    parser-facing description previously read `scope="<expr>"` as if the
    value were verbatim operator input; after round 3's UP-R3 fix the
    value is backslash-escaped for `"` and `\` and stripped of C0 control
    bytes before embedding. The entry now names the normalisation
    explicitly with a concrete example (`env="prod"` → `scope="env=\"prod\""`)
    so SIEM rule authors don't build parsers against the wrong shape.
    The `fan_out_deferred_pr3=true` marker and the non-object-body 400
    rejection are also called out in the same row.
  - **`guaranteed_state.rule.update` entry now lists 400 invalid-body as
    an explicit denied-audit case** (doc-RR2). Round 4's UP-R1 fix emits
    `result=denied` when the PUT body is unparseable JSON; the audit-log
    page did not reflect this in its per-action row or in the result
    vocabulary prose. Both now name the specific 400 branch alongside the
    existing 404/409 cases. The result-vocabulary paragraph gains a SIEM
    filter hint: "filter on `result == "denied"` scoped to the actions
    you care about — every mutating branch produces a row."
  - **`docs/user-manual/upgrading.md` v0.12.0 section gains a negative-
    retention behaviour change note** (doc-RR3). Pre-round-4 the `PUT
    /api/v1/config/<retention-key>` handler silently accepted negative
    values and the store treated `<= 0` as "never reap"; post-round-4 the
    handler rejects with 400 and operators must use `0` explicitly to
    preserve the disable-retention semantic. Also documents that non-
    numeric values (which were previously silent no-ops) now return 400 —
    surfacing configuration errors that had been hidden.
  - **Upgrading.md's RBAC remediation SQL is now a 4-step guarded
    procedure instead of a single destructive one-liner** (doc-RR4). The
    single `DELETE` block was replaced with: (1) back up `rbac.db`
    first, (2) run a `SELECT` preview and review the rows, (3) `DELETE`
    scoped to `principal_id IN ('Administrator', 'ITServiceOwner')` so a
    custom role with a legitimate non-Guardian Push grant is left alone,
    (4) re-run the preview to confirm cleanup. Same remediation, defence-
    in-depth wrapping. `principal_id` scoping matches what the bug
    actually produced — seeded roles only.

- **Guardian PR 2 hardening round 4 — UP-R1, UP-R5, and SHOULD-tier docs.**
  Small, code-local MEDIUM/SHOULD items from the governance re-run that did
  not require architectural decisions. Systemic items (retention runtime-PUT
  propagation across 3 stores, PUT TOCTOU optimistic concurrency, RBAC
  upgrade migration, audit action namespace flatten, `.get<T>()` sweep
  across 12 non-Guardian handlers, `TempDbFile` RAII adoption) are filed as
  tracking issues #483, #484, #485, #486, #487, #488 and excluded from this
  round to keep the commit focused.
  - **PUT `/api/v1/guaranteed-state/rules/:id` 400 invalid-body branch now
    emits a `denied` audit** (UP-R1). Previously the handler rejected
    malformed JSON with `400 {"error":"invalid JSON"}` but produced no
    audit record, while the sibling `/push` 400 branch did — asymmetric
    audit coverage across two branches shipped in the same hardening round.
    Added a regression test (`[rest][guaranteed_state][crud]`) that POSTs a
    non-object body and asserts the denied audit fires with the correct
    action, target, and detail fields.
  - **`PUT /api/v1/config/<key>` now validates integer-typed values before
    persisting** (UP-R5). The prior implementation called
    `runtime_config_store_->set(key, value, ...)` first, then wrapped
    `std::stoi(value)` in `try { ... } catch (...) {}`. Any non-numeric or
    negative value persisted to the store while silently failing to update
    `cfg_` — an operator PUTting `{"value":"abc"}` received `200 {"applied":
    true}` with no behaviour change, and on the next restart the invalid
    string loaded back into `RuntimeConfigStore`. Replaced with
    `std::from_chars`-based validation that runs **before** the `set` call
    and rejects with `400 {"error":{"code":400,"message":"value must be a
    non-negative integer"}}` on any parse failure. Applies to
    `heartbeat_timeout`, `response_retention_days`, `audit_retention_days`,
    and `guardian_event_retention_days`. The `try { stoi } catch (...) {}`
    blocks in the startup-config parser remain for now because that path
    has no 400 to return — this fix targets the runtime API only.
  - **`docs/user-manual/server-admin.md` Retention Settings table documents
    `--guardian-event-retention-days`** (doc-S2). Third row added alongside
    the existing `--response-retention-days` and `--audit-retention-days`
    entries. Supporting prose updated to describe the env-var alternatives
    (`YUZU_*_RETENTION_DAYS`) and the runtime `PUT /api/v1/config` path,
    with an explicit "takes effect on restart" caveat cross-referencing
    issue #483.
  - **`CHANGELOG.md` round-1 BL-4 entry annotated with the H-4 correction**
    (doc-S3). The 19×6=114 formula describing Administrator's seed count
    was accurate at BL-4 commit time but implicitly superseded by round 2's
    H-4 fix (which removed `Push` from the cross-type seed, reducing
    Administrator to 96 and ITServiceOwner to 81). Inline note added so a
    reader walking the CHANGELOG forward sees the correction before the
    implausible math statement.
  - **`CLAUDE.md` Guardian section expanded with the invariants that keep
    surfacing in governance** (N1 + N3). Three resident notes: (a) `Push`
    seed is Guardian-only — `ops[]` is the catalogue, `crud_ops[]` is the
    cross-type seed, do not cross-seed `Push`; (b) reserved plugin name
    `__guard__` has load-time rejection AND dispatch-time intercept, both
    halves must stay; (c) Guardian wire payloads carrying raw proto bytes
    must not be placed in `map<string, string>` fields the Erlang gateway
    re-encodes via `gpb:e_type_string` — UTF-8 validation crashes. New
    "Test conventions — shared helpers" section points at
    `tests/unit/test_helpers.hpp` and names the `std::hash<thread::id>` +
    `steady_clock` anti-pattern as the flake #473 vector.
  - **`docs/user-manual/upgrading.md` gains a v0.12.0 Guardian PR 2 section**
    (N2). Documents two operator-visible upgrade notes: the stale `*:Push`
    RBAC grants on deployments that ran pre-hardening code (with manual
    remediation SQL pending the #485 auto-migration), and the
    "retention PUT takes effect on restart" limitation shared across the
    three retention stores (cross-ref #483).

- **Guardian PR 2 hardening round 3 — UP-R3, doc-B1, doc-B2, UP-R9.** Closes
  the BLOCKING findings from the governance re-run on `a90a21e..HEAD`
  (rounds 1 + 2). Pattern C confirmed: the first two hardening rounds
  themselves introduced one new security regression and two doc regressions
  that this round addresses.
  - **`/push` audit detail now sanitises the scope value before embedding**
    (UP-R3 — new regression introduced by BL-6's audit format change). The
    BL-6 vocabulary fix formatted detail as `rules=N full_sync=B scope="<scope>"
    fan_out_deferred_pr3=true`, embedding operator-controlled scope between
    raw quotes. An operator with `GuaranteedState:Push` could therefore POST
    `{"scope":"x\" result=\"denied\" fake=\""}` and forge audit-record
    fragments that parse downstream as successful-looking denials — audit log
    integrity is a SOC 2 Workstream F control, so this is a real injection
    vector. Added an inline `sanitize_audit_string` lambda that
    backslash-escapes `"` and `\` and drops all C0 control bytes (CR/LF/NUL/
    TAB and the rest of 0x00–0x1F + DEL). audit_store writes the string as
    an opaque column so the sanitisation is defensive at the SIEM layer —
    but that's the layer compliance evidence is reconstructed from. Test
    `test_rest_guaranteed_state.cpp` gains a `[security]`-tagged regression
    guard that POSTs an adversarial scope and asserts no control bytes, no
    unescaped top-level injection tokens, and the structural frame of the
    detail remains intact.
  - **RBAC matrix tables in `docs/user-manual/guaranteed-state.md` and
    `docs/user-manual/rest-api.md` now show all 6 operation columns**
    (doc-B1 — new regression introduced by my BL-4 doc authoring). The
    tables as first written showed 4 columns (Read/Write/Delete/Push) and
    silently omitted Execute + Approve. Administrator and ITServiceOwner
    actually receive Execute and Approve on `GuaranteedState` via the
    `crud_ops[]` cross-type seed loop in `rbac_store.cpp`; the tables now
    reflect that. PlatformEngineer's row is narrower (Read/Write/Delete/Push
    — no Execute, no Approve) because its grants are explicit and targeted,
    not cross-type. Added a clarifying paragraph beneath each table noting
    the cross-seed origin of the Execute/Approve grants — this sets
    expectations for future readers that those ops exist in the DB but have
    no active Guardian handler today.
  - **`docs/user-manual/guaranteed-state.md` PR-2 status banner now matches
    the actual audit vocabulary** (doc-B2 — new regression introduced by
    BL-6 + my BL-8 doc authoring). The banner still said "audited as
    `accepted`" while the rest of the same file (and the code) use
    `result=success` with `fan_out_deferred_pr3=true` in the detail field.
    Updated the banner to match. Internal doc contradiction closed.
  - **`openapi_spec()` 503 description strings aligned with the runtime body
    strings** (UP-R9 / sec-L3 — H-7's scope miss). H-7 changed nine runtime
    `error_json("service unavailable", 503)` calls but left three OpenAPI
    path-entry `"503": {"description": "..."}` strings at the old "guaranteed-
    state store unavailable" wording. Client libraries generated from the
    spec saw a description that never matched the actual response body.
    Consolidated.

- **Guardian PR 2 hardening round 2 — H-3, H-4, H-7, H-8.** Second hardening
  round after the BL-1..BL-9 commit on the same governance run. Closes the
  HIGH findings that were small enough to fold into a single commit; the
  remaining HIGHs (H-1 read-side audit gap, H-2 plugin-loader RCE, H-5 gateway
  UTF-8 crash, H-6 apply_rules atomicity) are tracked as issues #477 / #478 /
  #479 and will land separately.
  - **PUT `/api/v1/guaranteed-state/rules/:id` stops type-mismatched bodies
    from surfacing as HTTP 500** (H-3). The handler was using
    `body["k"].get<T>()` which raises `nlohmann::json::type_error` on a
    type-mismatched field (e.g. `{"enabled": "yes"}`); without a server-wide
    `set_exception_handler`, httplib's default path returns 500 with an empty
    body. Swapped to `body.value("k", existing)` matching the sibling POST
    handler — type-mismatched fields silently fall back to the current value
    rather than converting a client-side request-shape mistake into a server-
    error alertable event.
  - **`Push` operation seeding restricted to `GuaranteedState`** (H-4). The
    previous cross-type seed granted `Administrator` and `ITServiceOwner`
    the `Push` op on every securable type — harmless today because only the
    Guardian REST handlers consult `Push`, but a latent privilege grant that
    any future handler reading `perm_fn(..., "Push")` on a non-Guardian
    securable would silently accept. `ops[]` is now split into `ops[]` (all
    six, seeded into the operations catalogue) and `crud_ops[]` (the five
    used for cross-type role seeding). Push is granted explicitly on
    `GuaranteedState` for `Administrator` and `ITServiceOwner`, matching
    the already-targeted grants for `Operator` and `PlatformEngineer`.
    Test assertions updated: Administrator 114 → 96 permissions,
    ITServiceOwner 96 → 81 permissions, plus new invariant checks that
    verify `Push` exists exactly once per role and only on `GuaranteedState`.
    `rbac.md` counts updated to match.
  - **503 error body vocabulary consolidated** (H-7). Nine Guardian 503
    sites previously returned `"guaranteed-state store unavailable"`; every
    other 503 site in `rest_api_v1.cpp` uses `"service unavailable"`.
    Log-based alerting that greps the sibling string will now match Guardian
    store outages too.
  - **New `tests/unit/test_helpers.hpp` replaces the stale `thread::id`-hash
    + `steady_clock` uniqueness pattern across 5 test files** (H-8, closes
    #482). The pattern that commit a90a21e replaced in
    `test_guardian_engine.cpp` for Windows MSVC flake #473 is now extinct
    in `test_rest_guaranteed_state.cpp`, `test_rest_api_tokens.cpp`,
    `test_rest_api_t2.cpp`, and `test_kv_store.cpp`. Shared header provides
    `unique_temp_path(prefix)` with a process-local `mt19937_64`-seeded
    salt + atomic monotonic counter, and `TempDbFile` RAII wrapper cleaning
    up `.db` / `-wal` / `-shm` companions. Header-only inline impl so each
    test binary owns its own salt and counter; no shared-state hazard.

- **Guardian PR 2 hardening round — governance Gate 7 BL-1..BL-9.** Consolidates
  the blocking findings from the `/governance b13ff17~1..HEAD` run on
  `feat/guardian-pr2`. No new functionality; closes the gaps between Guardian
  PR 2's implementation and the operator, SIEM, and SOC 2 contracts it shipped
  against.
  - **`/healthz` + dashboard health fragment now include
    `guaranteed_state_store` in the `all_stores_ok` conjunction** (BL-1). Prior
    to this fix, `/healthz` reported `"healthy"` while `/api/v1/guaranteed-state/*`
    returned `503` — the readiness-probe regression pattern (HC-1) that prior
    governance runs have caught on every new load-bearing store addition.
    Matches the `/readyz` per-store check which was already correct.
  - **`guardian_event_retention_days` is now actually overridable** (BL-2). The
    field was declared in `ServerConfig` with a default of 30 but had no CLI
    flag and no runtime-config parser branch, so the CHANGELOG's
    "overridable via runtime config" and the SOC 2 data-inventory doc's
    "configurable" claims were false. Adds the `--guardian-event-retention-days`
    CLI flag (+ `YUZU_GUARDIAN_EVENT_RETENTION_DAYS` env var), the `GET /api/config`
    response key, the runtime `PUT /api/config/guardian_event_retention_days`
    branch, the `RuntimeConfigStore::allowed_keys` entry, and the startup-config
    parser branch — all matching the `audit_retention_days` pattern.
  - **All 10 `/api/v1/guaranteed-state/*` routes now appear in the OpenAPI
    spec served at `/api/v1/openapi.json` and in
    `docs/user-manual/rest-api.md`** (BL-3). Adds `GuaranteedStateRule`,
    `GuaranteedStateStatus`, and `GuaranteedStateEvent` schema components plus
    per-path entries with security, request/response bodies, and status codes.
    Rest-api.md gains a full "Guaranteed State" section with the RBAC matrix,
    every endpoint's permission, request/response shape, and error paths.
  - **`docs/user-manual/rbac.md` updated for `GuaranteedState` and `Push`**
    (BL-4). Adds the securable type and operation, recomputes role permission
    counts (Administrator 19×6=114, ITServiceOwner 16×6=96, Viewer 18×1=18) to
    match code, and documents `Push` as the deploy-authority-without-author
    operation consumed only by the Guardian REST handlers. **Note:** the 19×6
    arithmetic is correct for the state at BL-4 commit time; the subsequent
    H-4 fix in hardening round 2 (entry directly above) restricted `Push`
    from the cross-type seed loop, reducing Administrator to 96 and
    ITServiceOwner to 81. The final values that ship are Administrator 96,
    ITServiceOwner 81, Viewer 18.
  - **`docs/user-manual/audit-log.md` adds the four Guardian audit actions**
    (BL-5). `guaranteed_state.rule.create / update / delete / push`. The push
    entry explicitly warns SIEM rule authors that `fan_out_deferred_pr3=true`
    in the detail field means "server accepted the push but agent delivery is
    deferred" — misreading this as delivered would be premature until the PR 3
    fan-out lands.
  - **`/push` audit vocabulary aligned with sibling handlers** (BL-6 /
    consistency-auditor F3). Previously emitted `result="accepted"` with
    `target_id=<scope>` — a novel result string and a target_id that broke
    SIEM joins (every other audit site uses a concrete entity id in target_id).
    Now emits `result="success"` with `target_id=""` (pushes are fleet-level,
    not per-entity) and `detail=rules=N full_sync=B scope="E" fan_out_deferred_pr3=true`.
    Also rejects non-object JSON bodies with `400` + denied audit (previously
    silently coerced to empty object), and replaces the engineer-facing
    `note: "fan-out lands in Guardian PR 3"` in the response body with the
    stable operational phrase `"push accepted; agent delivery is asynchronous"`.
  - **`/status` and `/status/:agent_id` field names match the agent-side proto**
    (BL-7 / consistency-auditor F1). REST previously returned `compliant`,
    `drifted`, `errored`; the proto `GuaranteedStateStatus` uses
    `compliant_rules`, `drifted_rules`, `errored_rules`. Renamed REST keys
    to the `_rules` suffix before any downstream dashboard locks in the drift.
    Per-agent status response gains `total_rules` for symmetry.
  - **New operator-facing page `docs/user-manual/guaranteed-state.md`** (BL-8).
    Covers the PR-2 limitation ("control plane + agent skeleton; no enforcement
    until PR 3"), the YAML rule schema, the create/push/query workflow with
    `curl` examples, the RBAC matrix, retention configuration, and the
    `/healthz` / `/readyz` observability surface. Linked from the user-manual
    README table of contents.
  - **Windows Defender exclusion script now refuses to run on non-runner
    hosts** (BL-9). `scripts/windows-runner-defender-exclusions.ps1` previously
    would silently weaken Defender coverage on a dev workstation if run by
    mistake (it excludes `%USERPROFILE%\AppData\Local\ccache` and
    `C:\WINDOWS\SystemTemp\yuzu_test_*` — paths that exist on dev boxes). Adds
    a hostname allowlist (default `^yuzu-local-windows`, overridable via
    `-AllowedHostPattern` when provisioning a new runner) that errors out
    before any `Add-MpPreference` call runs.

- **`/api/health` reports the actual server version instead of the
  hardcoded "0.1.0" (#401).** The endpoint now derives the version
  string from the meson-generated `yuzu/version.hpp` constant
  `kVersionString`, so health probes track the running build (currently
  `0.11.0`) rather than a stale literal that survived the v0.10.x cycle.
- **`docker-compose.uat.yml` now passes `--data-dir /var/lib/yuzu` to
  the server (#389).** Without the flag, all SQLite stores fell back to
  the working directory (`/etc/yuzu`) instead of the persistent volume
  mount — agent registrations, audit log, and tokens were lost on
  container restart. The other compose files (`docker-compose.local.yml`,
  `deploy/docker/docker-compose.full-uat.yml`) already passed the flag;
  the UAT file was the outlier.
- **`POST /api/settings/users` returns 409 on duplicate username (#399).**
  Previously the endpoint silently overwrote an existing account via
  `AuthManager::upsert_user` — a privilege-escalation primitive in the
  hands of any authenticated admin attacker. The endpoint now rejects
  duplicates with HTTP 409, an `HX-Trigger` toast (`"Username already
  exists"`), and a denied audit event
  (`user.upsert / denied / duplicate_username`). Self-password-change
  (same username, same role) is still allowed.
- **`POST /api/instructions` returns 409 on duplicate explicit `id`
  (#402).** Previously returned a generic 400 (`"insert failed"`); the
  store now pre-checks under the existing write lock and surfaces a
  structured 409 (`{"error":"instruction definition '<id>' already
  exists"}`) plus a denied audit event
  (`instruction.create / denied / duplicate_id`). Empty `id` paths still
  generate a UUID with no duplicate-check overhead.
- **`POST /api/policy-fragments` returns 409 on duplicate fragment name
  (#396).** Previously silently inserted a duplicate row; the store now
  rejects with HTTP 409 (`{"error":"policy fragment named '<name>'
  already exists"}`) plus a denied audit event
  (`policy_fragment.create / denied / duplicate_name`).

### Tests

- Added `tests/unit/server/test_store_errors.cpp` exercising the shared
  `kConflictPrefix` constant and `is_conflict_error` /
  `strip_conflict_prefix` helpers introduced for the route↔store conflict
  contract (governance Gate 3 arch-B1).
- Added duplicate-detection cases to `test_settings_routes_users.cpp`,
  `test_instruction_store.cpp`, and `test_policy_store.cpp`. The
  pre-existing "duplicate ID" policy-store test was tightened to assert
  the new `kConflictPrefix` semantics.
- Added `tests/unit/fixtures/reserved_name_plugin.cpp` — a test plugin
  declaring the reserved `__guard__` name — plus three new test cases in
  `tests/unit/test_plugin_loader.cpp` (`is_reserved_plugin_name`
  predicate, `kReservedPluginNames` namespace pin, and a behavioural
  scan-rejection test that copies the fixture into a temp directory and
  asserts `PluginLoader::scan` refuses to load it). The fixture is built
  as a `shared_library` in `tests/meson.build` and wired as a `depends:`
  of the agent test runner so it's on disk before the test runs.
- Expanded `tests/unit/server/test_guaranteed_state_store.cpp` for
  the #452 surface: new cases for `kConflictPrefix`-formatted duplicate
  errors on both `name` and `rule_id`, conflict on rename-into-existing
  name, batch `insert_events` happy path + transactional rollback on
  mid-batch collision, `created_by` / `updated_by` round-trip, and TTL
  reaper delete mechanics (including `retention_days=0` sentinel).
- Added `tests/unit/test_guardian_engine.cpp` (13 cases, 79 assertions)
  for the agent-side `GuardianEngine` ingest contract: `apply_rules`
  persists rules + bumps generation, `full_sync` wipes the prior set,
  delta merge keeps prior rules and updates overlap, empty `rule_id` is
  skipped, `dispatch` round-trips `push_rules` through proto
  `SerializeAsString`, `dispatch get_status` returns a serialised
  `GuaranteedStateStatus`, missing `push` parameter / garbage proto map
  to distinct exit codes, rule cache + `policy_generation` survive an
  in-process engine reconstruct against the same `KvStore`, null-`KvStore`
  construction degrades gracefully, and post-`stop()` `apply_rules`
  fails. Bumps the agent test suite's `agent_test_exe` deps with
  `yuzu_proto_dep` (the test constructs proto messages directly).
- Added `tests/unit/server/test_rest_guaranteed_state.cpp` (11 cases,
  88 assertions) for the `/api/v1/guaranteed-state/*` REST surface:
  `201` on create with `rule_id` echoed, `400` on missing required
  fields, `409` mapping from `kConflictPrefix` for duplicate name, full
  list/get/update/delete round-trip with version bump, `404` on unknown
  ids with denied-audit, `202` on `/push` with rule count + scope in the
  audit detail, `events` filter + `limit` pagination, `400` on invalid
  `limit`, `status` rollup, and `alerts` placeholder. Built against the
  in-process `TestRouteSink` (no live `httplib::Server`, no #438 TSan
  trap).
- Updated `tests/unit/server/test_rbac_store.cpp`: bumped securable-type
  count to 19, operations count to 6, `Administrator` perms to 114 (19
  × 6), `Viewer` to 18, and `ITServiceOwner` to 96 (16 × 6) — all
  knock-ons from adding the `GuaranteedState` securable type and the
  `Push` operation seeded for PR 2.

- **Coverage and perf baselines locked off seed; enforcement live in
  `/test --full`.** `tests/coverage-baseline.json` and
  `tests/perf-baselines.json` shipped with PR2 of the `/test` skill as
  permissive `__seed: true` placeholders that emitted WARN regardless
  of measured numbers. Both are now captured against commit
  `40acd33` on the 5950X dev box: branch coverage **26.8%** / line
  coverage **51.8%** with **0.5 pp slack** on the coverage gate; **4
  perf metrics** (`registration_ops_sec=19084`,
  `burst_registration_ops_sec=18248`, `heartbeat_queue_ops_sec=2.86M`,
  `session_cleanup_ms_per_agent=0.05`) with **10% tolerance** and
  hardware fingerprint locked. Cross-hardware perf runs auto-downgrade
  to WARN (so a 5950X baseline doesn't false-fail on the MBP and vice
  versa); coverage stays compiler-deterministic so no fingerprint is
  recorded there. The `__seed: true` sentinel is still honored as a
  defensive WARN if anyone re-introduces it. Regenerate with
  `bash scripts/test/{coverage,perf}-gate.sh --run-id manual --capture-baselines`
  on a clean test run; both gates refuse capture when the underlying
  meson test or rebar3 ct exited non-zero (UP-18 guard).
- **`yuzu_gw_upstream_tests:flush_sends_batch` rewritten to use
  `flush_sync/0` instead of `! flush; timer:sleep(N)`.** The original
  drain pattern was racy under coverage-instrumented BEAM — the cast
  pipeline could outrun the 20ms settle window and the assertion saw
  fewer than the expected 2 heartbeats. `flush_sync/0` is a
  `gen_server:call`, so it serialises after pending casts and waits
  for `do_flush` to complete before returning, making the test
  deterministic regardless of host load. Sibling tests
  (`buffer_retained_on_failure`, `buffer_cap_on_failure`) keep
  `! flush` deliberately — they exercise the timer-flush path's
  failure-cap semantics that differ from `flush_sync`. Verified:
  148/148 pass on `rm -rf _build/test`; 3/3 sequential meson coverage
  runs pass on the originally-flaky path.
- **Test-runs DB auto-vivifies missing `test_runs` rows on operator-invoked
  writes (#528).** `scripts/test/test_db.py` `cmd_gate` / `cmd_timing` /
  `cmd_metric` previously failed `sqlite3.IntegrityError: FOREIGN KEY
  constraint failed` when the `--run-id` had no parent `test_runs`
  row — the path triggered by
  `coverage-gate.sh --run-id manual --capture-baselines` and any direct
  operator invocation outside the `/test` pipeline. New
  `_ensure_run_exists(conn, run_id)` helper auto-creates a stub row
  with `mode='manual'` / `overall_status='MANUAL'` (commit_sha + branch
  resolved via `git rev-parse`, schema-init runs first if the DB is
  brand-new). Race-safe via `INSERT OR IGNORE`; emits a stderr signal
  on actual creation so a `/test` pipeline whose `run-start` silently
  failed produces a visible signal rather than a green-looking run with
  `mode='manual'` rows. On repeat manual capture, the existing stub's
  `started_at` / `commit_sha` / `branch` are refreshed so trend queries
  attribute new metrics to the current commit.
- **`--latest` / `--last` / `--flaky` / `--prune` query helpers default-
  exclude `mode='manual'` rows.** Operator captures via
  `--capture-baselines` no longer displace real `/test --full` runs in
  the kept window or pollute trend / flaky stats. Pass `--include-manual`
  to opt back in.
- **`scripts/linux-start-UAT.sh` server bind timeout 10s → 30s.**
  `yuzu-server` cold-start walks ~20 `MigrationRunner` migrations and
  routinely takes 12+ seconds before binding `:8080`; the prior 10s
  budget produced a flaky Phase 4 in `/test --full` on WSL2 dev boxes.
  Same bump applied to `scripts/integration-test.sh:441-443` (15s →
  30s) and `scripts/win-start-UAT.sh:325` (10s → 30s) for cross-platform
  parity. `wait_for_port` in all three scripts now emits
  `bound to :PORT in Ns` on success, so future cold-start growth (e.g.
  Guardian PRs adding `MigrationRunner` stores) shows up as a leading
  indicator before the next timeout breach.
- **`tests/puppeteer/dashboard-help-test.mjs` runs headless.** The test
  was launching Chrome with `headless: false` and required an X server,
  which the WSL2 dev box and CI runners don't provide. `headless: true`
  removes the dependency; verified end-to-end against a fresh UAT stack
  with `help=162 rows / command=1 row`, exit 0.

### Tests — release tooling

- **`/release` skill: Phase 0.5 reconciliation gate catches dev/main
  divergence at preflight.** Every prior release hit the same trap —
  `dev` accumulates merged work, the prior release's prep commits land
  on `main` without coming back to `dev`, and by the next release both
  branches are diverged in both directions. `scripts/release-preflight.sh`
  now hard-FAILs check #8 (`origin/dev and origin/main reconciled`)
  with the exact ahead/behind counts; the skill's new Phase 0.5
  documents the cherry-pick + fast-forward reconcile recipe. Verified
  by `/release v0.12.0-rc0 → /release v0.11.0 final` cycle that found
  88 dev-ahead / 2 main-ahead and reconciled to 0/0 before tagging.
- **`scripts/release-preflight.sh` check #7 regex matches SHA-pinned
  `actions/cache@<40-hex>` references in addition to tag-pinned
  `@v[0-9]+`.** Dependabot + Scorecard migrated all 7 cache steps in
  `release.yml` to SHA pinning, so the prior regex matched zero and
  the count comparison printed `0/7` on a clean release. The regex is
  now `(@<40-hex-sha>|@v[0-9]+)` so both forms count.

### Changed — deployment

- **`docker-compose.yml` and `docker-compose.reference.yml` no longer
  include a `yuzu-agent` service; agents run natively on each managed
  endpoint.** Per-platform installers ship as release assets:
  `yuzu-agent_X.Y.Z_amd64.deb` / `yuzu-agent-X.Y.Z-1.x86_64.rpm` for
  Linux, `YuzuAgentSetup-X.Y.Z.exe` (Authenticode-signed) for Windows,
  `YuzuAgent-X.Y.Z-macos-arm64.pkg` (notarised + stapled) for macOS.
  The reference compose now documents these install paths and points
  at `bash scripts/linux-start-UAT.sh` for dev smoke-testing of the
  server↔agent roundtrip. Power users wanting a containerised agent
  can still build from `deploy/docker/Dockerfile.agent`; we don't
  publish a `yuzu-agent` GHCR image. `pre-release.yml` Trivy matrix
  was scanning a `yuzu-agent` image that never existed — that step is
  removed; only `yuzu-server` and `yuzu-gateway` are scanned.
- **`docker-compose.sanitizer-uat.yml` agent service preserved.**
  This is internal sanitiser test infrastructure that deliberately
  runs the agent under ASan/TSan via `Dockerfile.agent-asan` /
  `Dockerfile.agent-tsan`; not user-facing.


## [0.11.0-rc2] - 2026-04-20

### Added

- **Guardian "Guaranteed State" engine — wire contract + server store
  skeleton (PR 1 of the Windows-first rollout).** Landed dormant: a new
  SQLite file `guaranteed-state.db` is created in the server data directory
  at startup and a `guaranteed_state_store` entry appears in the `/readyz`
  probe response. No REST endpoints, no dispatch, no agent wiring, and no
  dashboard surface in this release — PR 1 ships only the proto (new package
  `yuzu.guardian.v1` at `proto/yuzu/guardian/v1/guaranteed_state.proto`),
  the server SQLite store, and 17 unit test cases. Operators upgrading will
  see the new `.db` file alongside the existing stores (same permissions,
  same backup story: copy the full `--data-dir`) and the new `/readyz` JSON
  key. Full architecture: `docs/yuzu-guardian-design-v1.1.md`. Windows-first
  delivery plan: `docs/yuzu-guardian-windows-implementation-plan.md`.

- **Supply-chain attestation bundle: CycloneDX + SPDX SBOMs, SLSA
  provenance, and cosign image signatures on every release (#362,
  #408).** The release workflow now emits, per tag, a full verifiable
  supply-chain artefact set:
  - **CycloneDX + SPDX SBOMs per platform archive** via
    [Syft](https://github.com/anchore/syft) (`anchore/sbom-action@v0`):
    `yuzu-{linux-x64,gateway-linux-x64,windows-x64,macos-arm64}.{cdx,spdx}.json`.
    Syft picks up vcpkg C++ dependencies (reading vcpkg's generated
    `vcpkg.spdx.json` under `vcpkg_installed/<triplet>/share/`), Erlang
    deps from `gateway/rebar.lock`, and metadata on the built
    ELF/PE/Mach-O binaries.
  - **CycloneDX + SPDX SBOMs per Docker image**
    (`yuzu-{server,gateway}-image.{cdx,spdx}.json`) generated by Syft
    scanning the pushed image by digest, so the SBOM is bound to the
    exact image layers customers will pull.
  - **SLSA v1.0 build provenance attestations** for every binary archive,
    installer, and Docker image via `actions/attest-build-provenance@v3`.
    Stored in GitHub's native attestation registry and verified
    customer-side with `gh attestation verify <file> --repo Tr3kkR/Yuzu`
    (images: `oci://ghcr.io/.../<image>@sha256:<digest>`).
  - **cosign keyless Docker image signing** for both
    `ghcr.io/tr3kkr/yuzu-server` and `ghcr.io/tr3kkr/yuzu-gateway`,
    bound to the release workflow's OIDC identity (no static keys to
    rotate). Existing cosign blob signature on `SHA256SUMS` is retained.
  - **New release-gate script** at
    `scripts/check-release-artifacts.sh` runs before `gh release create`
    and fails the release if any expected archive, installer, or SBOM
    is missing — preventing partially-attested releases from ever
    reaching customers.
  - **New operator doc** at
    [`docs/user-manual/release-verification.md`](docs/user-manual/release-verification.md)
    covers `sha256sum -c`, `cosign verify-blob`, `cosign verify` (images),
    `gh attestation verify` (binaries + images), and CycloneDX / SPDX
    inspection with `jq` and the CycloneDX CLI. Includes an end-to-end
    verification script and a compliance-mapping table (SOC 2 CC6.8 /
    CC7.1, NIST SSDF PW.5 / PS.3, EO 14028, EU CRA Annex V).
  - Top-level workflow permissions extended with `attestations: write`
    (required by `actions/attest-build-provenance`); `docker-publish`
    job gains `id-token: write` + `attestations: write`. `SHA256SUMS`
    now covers the SBOM files so customers can verify them alongside
    the archives. Release notes heredoc advertises the new verification
    workflow and links to the operator doc.
  - Effective at the next tag after merge. No CHANGELOG gate on
    historical releases — retro-generating provenance for shipped tags
    is out of scope.
- **OpenSSF Scorecard + Zizmor workflows (#407).** Added
  `.github/workflows/scorecard.yml` (weekly + push to main +
  `branch_protection_rule`; publishes to scorecard.dev + SARIF to the
  GitHub Security tab) and `.github/workflows/zizmor.yml` (static
  analyzer for `.github/workflows/*.yml`, runs on workflow-touching PRs
  + weekly). README now advertises the Scorecard and Zizmor badges; the
  OpenSSF Best Practices Badge slot is wired up pending manual
  application at bestpractices.dev. Triaging Scorecard findings into
  follow-up issues is the remaining work on #407.
- **README `Install`, `Contributing`, `Reporting Issues` sections
  (#407).** Addresses the OpenSSF Best Practices `[interact]` criterion
  — README now points prebuilt-binary users at GitHub Releases +
  `ghcr.io/tr3kkr/yuzu-{server,gateway,agent}` + `deploy/docker/docker-compose.yml`
  instead of only documenting the from-source build. Adds explicit
  links to `CONTRIBUTING.md`, `CLAUDE.md`, the bug-report and
  feature-request issue templates, `SECURITY.md` (private vulnerability
  reporting), and GitHub Discussions.

### Fixed

- **`/api/health` reports the actual server version instead of the
  hardcoded "0.1.0" (#401).** The endpoint now derives the version
  string from the meson-generated `yuzu/version.hpp` constant
  `kVersionString`, so health probes track the running build (currently
  `0.11.0`) rather than a stale literal that survived the v0.10.x cycle.
- **`docker-compose.uat.yml` now passes `--data-dir /var/lib/yuzu` to
  the server (#389).** Without the flag, all SQLite stores fell back to
  the working directory (`/etc/yuzu`) instead of the persistent volume
  mount — agent registrations, audit log, and tokens were lost on
  container restart. The other compose files (`docker-compose.local.yml`,
  `deploy/docker/docker-compose.full-uat.yml`) already passed the flag;
  the UAT file was the outlier.
- **`POST /api/settings/users` returns 409 on duplicate username (#399).**
  Previously the endpoint silently overwrote an existing account via
  `AuthManager::upsert_user` — a privilege-escalation primitive in the
  hands of any authenticated admin attacker. The endpoint now rejects
  duplicates with HTTP 409, an `HX-Trigger` toast (`"Username already
  exists"`), and a denied audit event
  (`user.upsert / denied / duplicate_username`). Self-password-change
  (same username, same role) is still allowed.
- **`POST /api/instructions` returns 409 on duplicate explicit `id`
  (#402).** Previously returned a generic 400 (`"insert failed"`); the
  store now pre-checks under the existing write lock and surfaces a
  structured 409 (`{"error":"instruction definition '<id>' already
  exists"}`) plus a denied audit event
  (`instruction.create / denied / duplicate_id`). Empty `id` paths still
  generate a UUID with no duplicate-check overhead.
- **`POST /api/policy-fragments` returns 409 on duplicate fragment name
  (#396).** Previously silently inserted a duplicate row; the store now
  rejects with HTTP 409 (`{"error":"policy fragment named '<name>'
  already exists"}`) plus a denied audit event
  (`policy_fragment.create / denied / duplicate_name`).

### Tests

- Added `tests/unit/server/test_store_errors.cpp` exercising the shared
  `kConflictPrefix` constant and `is_conflict_error` /
  `strip_conflict_prefix` helpers introduced for the route↔store conflict
  contract (governance Gate 3 arch-B1).
- Added duplicate-detection cases to `test_settings_routes_users.cpp`,
  `test_instruction_store.cpp`, and `test_policy_store.cpp`. The
  pre-existing "duplicate ID" policy-store test was tightened to assert
  the new `kConflictPrefix` semantics.

## [0.11.0-rc1] - 2026-04-18

_Minor bump from v0.10.0. The original `0.10.1` dev bump in `0c976c7`
predated the `feat(test)` commits that landed the `/test` skill PR1 +
PR2 (cb4cd7f, b6f1256 — ~5,000 lines of new operator-facing
functionality), the matrix CodeQL workflow expansion (8c5b934), and
the `563138f` MigrationRunner wiring with its `/readyz` response-shape
addition (`failed_stores` field on 503). Strict SemVer says any new
backward-compatible feature ⇒ MINOR bump, so this was first cut as
**v0.11.0-rc1** (2026-04-18); rc2 followed on 2026-04-20 to smoke-test
the new SBOM + SLSA + cosign supply-chain pipeline; the **v0.11.0**
final tag landed on 2026-04-25 — see the `[0.11.0]` section above for
the full set of changes between rc2 and final._

### Added

- **`/release` skill at `.claude/skills/release/SKILL.md`** — bash-first
  release orchestrator that runs preflight (`scripts/release-preflight.sh`
  + `scripts/check-compose-versions.sh`), pushes the tag, monitors the
  release workflow until terminal state, troubleshoots known failure
  modes (the v0.10.0 download-artifact bug, compose version mismatch,
  Windows signtool absence, macOS notarytool timeout, Windows MSVC
  LNK2038 vcpkg cache poisoning, EUnit meck false-positive), verifies
  the GitHub Releases page has every expected asset including the
  Compose Wizard zip and GHCR images, and produces a release report.
  Supports `--watch`, `--verify`, and `--resume` modes for
  re-entrant operation when a release stalls partway. Mirrors the
  `/test` skill's bash-first orchestration pattern (no agent fan-out;
  the LLM interprets failures and decides next-step). Use:
  `/release vX.Y.Z` — full pipeline; `/release --watch vX.Y.Z` —
  monitor an in-flight release; `/release --verify vX.Y.Z` —
  post-hoc verification.
- **Compose Wizard bundled as a release asset
  (`.github/workflows/release.yml` `Package Compose Wizard` step).**
  The browser-based docker-compose.yml + .env generator at
  `tools/compose-wizard/` (PR #405 by @fjarvis) is now packaged into
  `yuzu-compose-wizard-X.Y.Z.zip` during the release workflow's
  `release` job and uploaded alongside the other assets. Auto-included
  in `SHA256SUMS` and the cosign-signed `SHA256SUMS.bundle`. Release
  notes get a "Compose Wizard" section pointing customers at the
  download with `unzip + open index.html` instructions. Conditional
  on `tools/compose-wizard/` existing in the tag's commit tree —
  emits a workflow warning and skips the bundle if absent (release
  proceeds without it). Tag must be cut from a commit that has both
  this workflow change AND the wizard files merged in.
- **Runner inventory sentinel workflow
  (`.github/workflows/runner-inventory-sentinel.yml`,
  `.github/runner-inventory.json`).** Declarative expected-state file
  enumerates the self-hosted runners we expect to be online + idle
  (currently `yuzu-wsl2-linux` and `yuzu-local-windows`), and a
  scheduled workflow reconciles `gh api repos/Tr3kkR/Yuzu/actions/runners`
  against it. Reports drift (missing runners, offline runners, wrong
  labels) as a workflow failure with a human-readable summary in the run
  annotation. Built across three commits:
  - `12ef73b` — initial workflow + inventory file scaffold.
  - `a0425c8` — parse error fix (removed invalid `administration: read`
    workflow permission, added graceful HTTP 403 handling with
    PAT-setup runbook in stderr, added `.github/runner-inventory.json`
    and the workflow file itself to `ci.yml`'s `paths-ignore` so CI
    doesn't re-trigger on inventory edits).
  - `675d636` — cron schedule commented out with `[skip ci]`. The
    sentinel is **inactive until the `RUNNER_INVENTORY_TOKEN` PAT is
    created** — `gh api /actions/runners` requires admin scope which
    `GITHUB_TOKEN` cannot grant via workflow permissions (admin scope
    only exists at org/installation level, not workflow level). PAT
    creation is the first item on the Saturday at Jordanstone checklist;
    once it lands, uncomment the schedule block and the sentinel
    activates. The inactive-until-PAT pattern avoids the chronic-red
    anti-pattern where a permanently-failing scheduled workflow trains
    operators to ignore CI failure notifications.

- **Dependency automation — `pip` ecosystem + scheduled vcpkg baseline
  bumps (closes #363).** `requirements-ci.txt` at the repo root becomes
  the single source of truth for Python tooling pins (currently just
  `meson==1.9.2`), consumed directly by every `pip`/`pip3`/`pipx install`
  call site in `.github/workflows/ci.yml` (6 sites) and
  `.github/workflows/release.yml` (2 sites). The hardcoded
  `MESON_VERSION: "1.9.2"` env var is removed from all three tracked
  workflows (`ci.yml`, `release.yml`, and the dead reference in
  `sanitizer-tests.yml`) — the pin now lives in exactly one place.
  `.github/dependabot.yml` gains a `pip` ecosystem entry so Dependabot
  opens a weekly PR against `requirements-ci.txt` if a newer meson
  release lands, and CI re-runs on the PR so breaking changes stall
  instead of silently merging.

  **vcpkg baseline** — Dependabot does not understand vcpkg, so
  `.github/workflows/vcpkg-baseline-update.yml` is a new scheduled
  workflow (10:00 UTC on the 1st of each month, plus
  `workflow_dispatch`) that: resolves `git ls-remote vcpkg HEAD`,
  compares to the current `vcpkg.json` `builtin-baseline`, and if
  different, `sed`s the new SHA into every tracked reference
  (`vcpkg.json`, `vcpkg-configuration.json`, `qodana.yaml`, `CLAUDE.md`,
  all four workflow `VCPKG_COMMIT` env vars, and all three Dockerfile
  ARG/ENV references), failing loudly if any listed file still carries
  the old SHA after the replace, then opens a PR via
  `peter-evans/create-pull-request@v7` with `dependencies,ci` labels.

  **rebar3** — gateway dependencies stay on a manual quarterly review
  cadence, documented in the new `docs/dependency-updates.md`. The doc
  is also the reference for the full dependency-update strategy —
  ecosystem table, staleness query per ecosystem, and the known
  Dockerfile-meson duplication follow-up.

  **Why the Dockerfiles aren't centralized yet** — five Dockerfiles
  under `deploy/docker/` (`agent`, `server`, `ci`, `ci-linux`,
  `runner-linux`) still carry a hardcoded `meson==1.9.2` string in
  their build-stage `RUN` commands. Centralizing them on
  `COPY requirements-ci.txt` is tracked as a follow-up in
  `docs/dependency-updates.md`. Until then, the manual merge checklist
  for a Dependabot meson bump includes bumping the literal string in
  those five files (`grep -rn 'meson==' deploy/docker/` finds them all).

- **`/test` skill coverage + perf + sanitizer gates (PR2 of 3).** Phase 6
  and Phase 7 of the `/test` pipeline are now wired. `--full` mode
  dispatches `.github/workflows/sanitizer-tests.yml` on the
  `yuzu-wsl2-linux` self-hosted runner (ASan+UBSan and TSan rebuilds +
  test runs), downloads the artifacts, parses them for sanitizer
  findings + meson test failures, and records two Phase 6 rows to
  `test_gates`. Runner offline → WARN (not FAIL) with operator retry
  instructions in the notes, so the rest of the run continues. Phase 7
  runs `coverage-gate.sh` (gcovr with the same filter set and
  `--native-file meson/native/linux-gcc13.ini` as
  `.github/workflows/ci.yml`, branch coverage compared against
  `tests/coverage-baseline.json` with 0.5 pp slack) and `perf-gate.sh`
  (rebar3 ct `yuzu_gw_perf_SUITE` groups `registration,heartbeat,fanout,churn`
  — endurance excluded — with 10 % throughput / latency tolerance
  against `tests/perf-baselines.json`). Hardware fingerprint mismatch
  on the perf baseline auto-downgrades to WARN so a 5950X-captured
  baseline doesn't produce false failures on the Apple Silicon MBP.
  Both gates record `perf_*` / `branch_coverage_overall` /
  `line_coverage_overall` metrics to `test_metrics` for trend analysis
  via `test-db-query.sh --trend metric=...`.

  **PR2 governance hardening round (folded into the same commit).** A
  full 6-gate governance pass on the initial PR2 working tree produced
  10 BLOCKING findings (ca-B1/UP-1 grep arithmetic, UP-2 gcovr schema,
  UP-6/UP-7 sanitizer false-PASS cluster, UP-9 run-id path traversal,
  UP-10 `__seed` sentinel silently disabled enforcement, UP-14 /
  hp-B2 dispatch concurrent race, UP-18 broken-env baseline anchoring,
  qa-B1 perf CT exit code not propagated, hp-B1 perf seed → WARN
  propagating through SKILL.md, sec-M1 `rm -rf "$BUILD_DIR"` on
  operator-controlled path) plus associated high-value SHOULDs (bci-S5
  native-file parity, qa-S1 min-metrics threshold, qa-S4 partial-data
  flagging, sre-5 runner disk pre-check, ca-S3 unit column width,
  doc-S1/S2/sre-6/sre-7/er-5). All resolved in this same PR2 commit:

  - `dispatch-runner-job.sh` now uses a createdAt timestamp + headSha
    filter for run discovery instead of the single newest-ID compare,
    so concurrent operators dispatching the same workflow no longer
    attribute each other's runs. Rejects multiline values in the
    `--inputs` JSON to block split-injection into `--raw-field`.
  - `sanitizer-gate.sh` distinguishes dispatch exit codes 0/1/2/3
    (success/config-error/workflow-failed/runner-offline) so a
    workflow that concluded `failure` now writes FAIL rows rather
    than parsing possibly-degraded artifacts into a silent PASS.
    Empty sanitizer logs (runner disk full, upload truncation) are
    caught by a size+marker guard that WARNs instead of reading them
    as "0 findings". The `grep -cE ... || echo 0` idiom that produced
    `"0\n0"` and broke `(( n > 0 ))` was replaced with a single-value
    capture that whitespace-strips defensively. The meson test FAIL
    detector now uses POSIX `[[:space:]]FAIL` instead of the GNU-only
    `\<FAIL\>` word boundary.
  - `coverage-gate.sh` honors the `__seed: true` sentinel and emits
    WARN ("seed baseline active — run --capture-baselines to enable
    enforcement") rather than silent PASS against the permissive seed.
    Refuses `--capture-baselines` when `meson test` exited non-zero
    so a broken env can no longer anchor a false-low baseline. Prints
    an old-vs-new diff before overwriting any existing baseline.
    Adds `--native-file meson/native/linux-gcc13.ini` to the
    `meson setup` call so local coverage numbers match Codecov's
    gcc-13 baseline. Validates `--build-dir` is under `$YUZU_ROOT/build-*`
    or `/tmp/build-*` before the reconfigure-failure `rm -rf` path
    can fire. Partial-data runs (`TEST_RC != 0`) tag the metric notes
    with `(partial: meson test exit=N)` so trend queries can filter
    out contaminated points. The gcovr JSON parser now handles both
    the top-level and `{"root": {...}}` wrapping shapes and supports
    the gcovr 6.x+ `branches_covered`/`branches_valid` key names (the
    pre-hardening code used `branch_covered`/`branch_total` which
    don't exist in modern gcovr, producing a silent 0 %).
  - `perf-gate.sh` propagates `rebar3 ct` exit code to gate outcome:
    `CT_RC=1` (test assertion failed) → FAIL; `CT_RC > 1` (compile
    or tooling failure) → WARN. Adds a minimum-metrics-parsed
    threshold (≥ 3 of the 6 expected labels) so parser drift produces
    a FAIL with a specific message instead of a silent "no metrics
    parsed" WARN. Honors `__seed: true` with exit-0 PASS (not WARN)
    so SKILL.md full-mode doesn't abort Phase 7 on the first run
    against a seed baseline. Refuses `--capture-baselines` when
    fewer than 3 metrics were parsed. Guards the compare math
    against non-finite / zero / negative baseline values (sec-L4).
    Emits WARN when the current run is missing baseline metrics
    (UP-13 — prevents silent "only 1/6 checked" PASSes). Strips
    ANSI escape sequences from `ct:pal` lines before regex matching
    so colorized rebar3 output does not silently break metric
    extraction.
  - All three gate scripts validate `--run-id` against
    `^[A-Za-z0-9._-]+$` before constructing any filesystem path,
    closing the `--run-id "../../../tmp/evil"` traversal and
    whitespace-only-ID path.
  - `.github/workflows/sanitizer-tests.yml` gains a
    "≥30 GB free" disk-check step right after toolchain assertion,
    so a full runner fails fast with `::error::runner disk` instead
    of hitting `ninja: No space left on device` 15 minutes into
    the sanitizer build (sre-5 / UP-6 upstream of the false-PASS path).
  - `scripts/test/test_db.py` `--trend` output column widened from 6
    to 10 characters so `ops/sec` and `ms/agent` units no longer
    push the run_id column out of alignment.
  - `tests/shell/test_pr2_gates.sh` (NEW) — chaos-injector regression
    harness covering P0 scenarios CH-2 (grep arithmetic), CH-3
    (capture refuses broken env), CH-4 (gcovr root-wrap schema),
    CH-6 (perf parser drift), CH-8 (`__seed` honored on both gates),
    CH-15 (invalid run-ids), and CH-16 (sec-h-1 regression test for
    Python code injection via `--baseline` path with embedded quote).
    7 scenarios, 9 assertions, all green on the hardened tree. CH-1
    (clean-log + workflow-failure → FAIL) is deferred to PR2.1 because
    it needs a gh CLI mock harness.

  **Pattern C catch — second security pass on the hardening round**
  surfaced three new issues introduced by the hardening itself:

  - **sec-h-1 (HIGH, BLOCKING)** — `coverage-gate.sh` `--capture-baselines`
    diff and `__seed` detection paths interpolated the operator-controlled
    `--baseline` file path into single-quoted Python literals inside
    `python3 -c "..."` shell strings. A baseline path containing a single
    quote would break out of the Python literal and execute arbitrary code.
    Fix: all three call sites (lines 366, 367, 424) rewritten as quoted
    heredocs (`python3 - "$BASELINE" <<'PY'`) that receive the path via
    `sys.argv[1]`. CH-16 in the chaos harness regression-tests this by
    placing a real baseline under a directory name containing `'`.

  - **sec-h-2 (MEDIUM)** — `dispatch-runner-job.sh` fell back to
    `echo "$REF"` when `git rev-parse` failed, which allowed an
    unresolvable ref to be spliced verbatim into a jq filter
    (`--jq "... select(.headSha == \"$TARGET_SHA\")"`). Fix: strictly
    resolve ref via `git rev-parse --verify "$REF^{commit}"` and refuse
    the dispatch on failure; also require `TARGET_SHA` to match a
    hex[40-64] regex before it reaches jq. The jq filter now uses
    `env.DISPATCH_TS` and `env.TARGET_SHA` through environment
    variables instead of shell-interpolated jq syntax.

  - **sec-h-3 (MEDIUM)** — `tests/shell/test_pr2_gates.sh` helper
    functions `db_gate_status` / `db_gate_notes` / CH-4 metric read
    used the same shell-interpolation-into-Python anti-pattern as
    sec-h-1. Not exploitable today (harness controls all values) but
    a trap for future contributors. Fixed to pass values via
    `sys.argv` in quoted heredocs so the harness teaches the right
    pattern.

  The re-review clears the commit for landing. Low/INFO items from
  both security passes (sec-L2, sec-L4, sec-L5, sec-h-4, sec-h-5)
  are deferred to follow-up issues and captured in memory for the
  next hardening wave.
  - SKILL.md, CLAUDE.md updated to describe the `__seed` semantics,
    the `--capture-baselines` pre-flight requirement (clean
    `meson test` / `rebar3 ct` before capture), the sanitizer queue
    behavior under concurrent full-mode runs, and the baseline
    refresh cadence (recapture at every `vX.Y.0` tag on the
    canonical dev box).

  **New files:**
  - `scripts/test/dispatch-runner-job.sh` — shared `gh workflow run` + poll +
    download + parse helper with distinct exit codes for success / fail /
    runner-unavailable so callers can map to PASS / FAIL / WARN.
    Reused by PR3 for the Windows agent build dispatch.
  - `scripts/test/sanitizer-gate.sh` — Phase 6 orchestrator. Parses
    `ERROR: AddressSanitizer`, `ERROR: LeakSanitizer`, `WARNING: ThreadSanitizer`,
    `ThreadSanitizer: data race`, `runtime error:` out of the downloaded
    sanitizer logs and counts meson test FAIL lines separately.
  - `scripts/test/coverage-gate.sh` — Phase 7 coverage orchestrator.
    Configures `build-linux-coverage/` with `-Db_coverage=true` (separate
    from the main `build-linux/` so ccache hit rates stay intact), runs
    `meson test`, runs gcovr with `--json-summary`, and enforces the
    baseline with `--capture-baselines` / `--report-only` / default
    enforce modes.
  - `scripts/test/perf-gate.sh` — Phase 7 perf orchestrator. Parses
    `ct:pal` throughput lines (`Registration: N ops in M ms (O ops/sec)`),
    fanout latency lines (`Fanout to N agents: M ms`), and session
    cleanup latency (`Cleanup N agents: M ms (K ms/agent)`).
  - `.github/workflows/sanitizer-tests.yml` — `workflow_dispatch`-only
    workflow pinned to `[self-hosted, yuzu-wsl2-linux]`. Uses the same
    `ASAN_OPTIONS=detect_leaks=1:halt_on_error=1`,
    `UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1`, and
    `TSAN_OPTIONS=halt_on_error=1:second_deadlock_stack=1` as the
    existing CI sanitize jobs for parity. Uploads
    `sanitizer-{asan,tsan}.log`, their build logs, and
    `build-linux-{asan,tsan}/meson-logs/testlog.junit.xml` as artifacts.
  - `tests/coverage-baseline.json`, `tests/perf-baselines.json` —
    shipped as **permissive seeds** (`branch_percent=0 + slack_pp=100`,
    empty `metrics` map) with a `__seed: true` flag. PR2 must not break
    /test --full on merge day, so the seeds pass trivially; first
    operator run with `--capture-baselines` locks real numbers that
    replace the seeds. The `git blame` on these files is the audit
    trail for who raised/lowered the baseline and why.

- **`/test` skill scaffold + upgrade test path (PR1 of 3).** New
  `.claude/skills/test/SKILL.md` operator-facing runbook plus
  `scripts/test/` helper directory that orchestrates a pre-commit /
  pre-push test pipeline. Three modes: `--quick` (~10 min sanity check),
  default (~30-45 min build + upgrade test + standard gates), `--full`
  (~60-120 min adds OTA + sanitizers + perf + coverage enforce). The
  default-mode headline is **Phase 2 upgrade test**: pulls
  `ghcr.io/tr3kkr/yuzu-server:0.10.0`, populates fixture data, swaps to
  the local HEAD image (built in Phase 1 as `yuzu-server:0.10.1-test-${RUN_ID}`),
  verifies migrations ran via `/readyz` (uses the #339 compound-fix
  `failed_stores` body field), and re-checks fixture preservation. PR1
  ships Phases 0, 1, 2, 4, 5, 8 fully wired; Phases 3 (OTA), 6
  (sanitizers), 7 (coverage + perf) are stubbed with SKIP rows pending
  PR2/PR3.

- **Persistent test-runs SQLite database** at
  `~/.local/share/yuzu/test-runs.db` (override via `YUZU_TEST_DB`).
  Schema v1 has 4 tables: `test_runs` (per-invocation aggregate),
  `test_gates` (per-gate pass/fail + duration), `test_timings`
  (millisecond sub-step durations like `phase2.image-swap`,
  `phase3-linux.ota-download`, `synthetic-uat.os_info-roundtrip`),
  and `test_metrics` (quantitative measurements with units). Uses
  the `schema_meta` pattern from #339 so future schema changes can
  land via versioned migrations. New scripts:
  `scripts/test/test_db.py` (Python source of truth) plus thin
  bash wrappers `test-db-init.sh`, `test-db-write.sh`,
  `test-db-query.sh`. The query wrapper supports
  `--latest`, `--last N`, `--diff RUN_A RUN_B`,
  `--trend metric=NAME` / `--trend timing=GATE.STEP`,
  `--flaky --days N`, `--branch B`, `--export RUN_ID`,
  `--prune KEEP_N` (with `--dry-run` preview).
  Power users can `python3 scripts/test/test_db.py query ...`
  directly or run any sqlite query against the DB.

- **`scripts/test/preflight.sh`** — Phase 0 sanity checks (toolchains,
  ports, disk, docker context, dangling test containers, git state,
  test-runs DB initialization). `--force-cleanup` flag tears down
  dangling `yuzu-test-*` compose projects.

- **`scripts/test/synthetic-uat-tests.sh`** — extracts the 6
  connectivity tests from `linux-start-UAT.sh` (dashboard reachable,
  gateway readyz, server registered agents metric, gateway connected
  agents metric, help command round-trip, os_info command round-trip)
  into a standalone script that takes URLs as arguments and records
  per-command latencies into `test_timings`.

- **`scripts/test/test-fixtures-{write,verify}.sh`** — minimum-viable
  fixture set written before the upgrade and re-verified after, so the
  upgrade test can detect data loss. Records what's preserved /
  lost / skipped to a `fixtures-verify.json` report file.

- **`scripts/test/test-upgrade-stack.sh`** — Phase 2 orchestrator. Uses
  a purpose-built `scripts/test/docker-compose.upgrade-test.yml` that
  drops the `container_name:` declarations from
  `deploy/docker/docker-compose.reference.yml` so multiple parallel
  test runs can coexist via `--project-name` isolation. Records
  sub-step timings: `pull-old-images`, `stack-up-old`, `fixtures-write`,
  `image-swap`, `ready-after-upgrade`, `fixtures-verify`,
  `synthetic-uat-against-upgraded`. Counts `MigrationRunner` log events
  as a `phase2_migration_events` metric.

- **`scripts/test/teardown.sh`** — Phase 8. Stops every
  `yuzu-test-${RUN_ID}-*` compose project, removes the
  `/tmp/yuzu-test-${RUN_ID}/` scratch dir, finalizes the `test_runs`
  row with computed `overall_status` from gate aggregates.

- **Schema migrations wired into every server-side SQLite store (#339).**
  The `MigrationRunner` framework at
  `server/core/src/migration_runner.{hpp,cpp}` existed since earlier
  releases but had not been called by any store — every store relied on
  `CREATE TABLE IF NOT EXISTS` plus silent `ALTER TABLE` fallbacks, and
  the upgrade docs incorrectly claimed "automatic schema migrations"
  since v0.1.0. This change threads `MigrationRunner::run()` through the
  `create_tables()` method of all 30 stores and managers:
  `analytics_event_store`, `api_token_store`, `approval_manager`,
  `audit_store`, `concurrency_manager`, `custom_properties_store`,
  `deployment_store`, `device_token_store`, `directory_sync`,
  `discovery_store`, `execution_tracker`, `instruction_store`,
  `inventory_store`, `license_store`, `management_group_store`,
  `notification_store`, `nvd_db`, `patch_manager`, `policy_store`,
  `product_pack_store`, `quarantine_store`, `rbac_store`,
  `response_store`, `runtime_config_store`, `schedule_engine`,
  `software_deployment_store`, `tag_store`, `update_registry`,
  `webhook_store`, `workflow_engine`. Every database now stamps its
  schema version in the shared `schema_meta` table and future schema
  changes go through versioned migrations with transactional rollback.
- **`deploy/docker/docker-compose.reference.yml`** — copyable
  deployment template that pulls pinned
  `ghcr.io/tr3kkr/yuzu-{server,agent}:${YUZU_VERSION:-0.10.0}` images,
  uses a named `server-data` volume for all mutable state, and carries
  inline TLS hardening + backup + rollback + restore commentary.
  Covered by `scripts/check-compose-versions.sh` so release tags cannot
  drift from the compose default. Named "reference" rather than
  "production" because the image's default CMD is dev-friendly
  (`--no-tls --no-https --web-address 0.0.0.0`) and the template
  requires operator hardening before production use (#339).
- **Legacy compatibility shims in six stores** — `api_token_store`,
  `instruction_store`, `patch_manager`, `policy_store`,
  `product_pack_store`, `response_store`. These run the historical
  silent `ALTER TABLE ADD COLUMN` statements once before
  `MigrationRunner::run()` so databases created by pre-v0.10 releases
  that never received those columns still converge to schema v1.
  Kept for one release cycle; removable after v0.11.

### Changed

- **CLAUDE.md second compression pass — Auth/MCP/Windows-build
  sections trimmed to pure pointers, with reference rules pushed
  into the relevant agent definitions.** v0.10.0's slimming
  (`571 → 484 lines`) had crept back to 529 lines as new sections
  landed. This pass takes it to 502 by removing the inline lists
  that were already mirrored in `docs/auth-architecture.md`,
  `docs/mcp-server.md`, and `docs/windows-build.md`. The hard
  invariants did not move — they're still load-bearing — they're
  just no longer duplicated between CLAUDE.md and the docs that
  own them. Drift was the symptom: the Auth invariant list in
  CLAUDE.md was already 1 item behind `docs/auth-architecture.md`
  and would silently keep diverging on every doc update.

  To prevent the next compression pass having to relocate the
  same rules a third time, the relevant agent definitions now
  carry "Reference Documents" pointers that name the doc and the
  exact section that holds the invariants:

  - **`.claude/agents/security-guardian.md`** — Reference
    Documents table mapping (auth/RBAC/crypto/header/token →
    `docs/auth-architecture.md` "HTTPS and bind defaults",
    "HTTP security response headers", "API tokens and
    automation"; MCP → `docs/mcp-server.md` "Architecture",
    "Security Model"). Adds `security_headers.{hpp,cpp}`,
    `mcp_server.{hpp,cpp}`, `mcp_policy.hpp`, `mcp_jsonrpc.hpp`
    to the deep-dive read list. Triggers list per-doc loading
    rules so the agent loads the right doc on the first relevant
    file edit instead of recovering invariants from CLAUDE.md.
  - **`.claude/agents/build-ci.md`** — Reference Documents note
    pointing at `docs/windows-build.md` for any Windows-touching
    CI/build change (`setup_msvc_env.sh`, vcpkg Windows triplet,
    MSVC flags). Linux/macOS build details remain in CLAUDE.md
    `## Build` / `## CI matrix` / `## vcpkg` sections.
  - **`.claude/agents/cross-platform.md`** — Reference Documents
    note for Windows changes plus an explicit "Do NOT use Clang
    from `C:\Program Files\LLVM\bin`" row in the Standing
    pitfalls table (was previously buried in CLAUDE.md prose).

- **`Dockerfile.ci-gateway` aligned to Erlang/OTP 28 (closes #334).**
  The CI gateway image was still pinned to `erlang:27` while every
  other Erlang surface — `release.yml`'s `erlef/setup-beam` step,
  `scripts/ensure-erlang.sh`'s default, and the runtime
  `Dockerfile.gateway` (`erlang:28-alpine`) — had moved to OTP 28.
  CLAUDE.md is explicit that these must move together; leaving the
  CI image behind meant the GitHub Actions gateway build was
  exercising rebar3/dialyzer against an OTP version older than the
  one the release ships, and any 28-only behavioural change would
  have been invisible to CI until a release tag was cut.
  `Dockerfile.gateway`'s `erlang:28-alpine` digest pin was also
  rolled forward to the current build (`f36705c5…`) as part of the
  same dependabot bundle. Originally proposed by dependabot in
  PR #334 against `main`; landed directly on `dev` because PR #334's
  Windows MSVC failure was the unrelated vcpkg LNK2038 cache issue
  fixed in PR #355 after dependabot opened its branch. Dependabot
  will close #334 automatically on its next scan.

- **CodeQL workflow hardened to actually finish + parallel Windows
  coverage (closes #370).** Every CodeQL run from 2026-03-23 to
  2026-04-13 was cancelled by the 90-min timeout — 7 consecutive
  cancellations across both manually-dispatched and PR-event-triggered
  runs. The actual runtime on the `yuzu-wsl2-linux` self-hosted runner
  is closer to 15 min for a Linux-only single-leg analysis (32-thread
  WSL2 host, 60 GB RAM), but the prior workflow had been cancelling
  before completing. Rebuilt as a `strategy.matrix` workflow that fans
  out to BOTH self-hosted runners in parallel: `yuzu-wsl2-linux`
  (gcc-13 + `build-linux-codeql/`) and `yuzu-local-windows`
  (MSVC + `build-windows-codeql/`), with `fail-fast: false` so one
  leg failing doesn't kill the other. Each leg uploads SARIF with a
  distinct category (`/language:c-cpp-linux` vs `/language:c-cpp-windows`)
  so findings in platform-specific `#ifdef _WIN32` branches stay
  attributed to the analysis that actually observed them. Closes #370.

  Coverage knobs flipped to maximum:
  - `queries: +security-and-quality` (strict superset of
    `security-extended`; for C/C++ specifically, the "quality"
    queries are security-adjacent — memory leaks, UAF, null deref,
    dead code hiding logic bugs, inconsistent error handling — not
    style noise like they would be for JS/Python)
  - `languages: c-cpp,actions` on the Linux leg (Windows leg keeps
    `c-cpp` only — no need to double-scan the same
    `.github/workflows/*.yml` files; the `actions` extractor catches
    the well-known `${{ github.event.* }}` template-injection class
    in workflow `run:` bodies)
  - `-Dbuild_tests=true` (recovers the ~50-100 `tests/unit/*.cpp`
    files that were skipped in the earlier `build_tests=false`
    baseline run, which scanned only 231/364 C++ files)
  - Dedicated per-OS build dirs (`build-linux-codeql/` /
    `build-windows-codeql/`) isolated from operator's interactive
    `build-{linux,windows}/` and from PR2's
    `build-linux-{asan,tsan,coverage}/`
  - Pre-build runner disk-free assertion (≥40 GB Linux, ≥45 GB
    Windows; MSVC debug builds are chunkier)
  - Weekly scheduled run (Sunday 04:00 UTC) + manual `workflow_dispatch`
  - `timeout-minutes` tightened from 240 (speculation based on
    GitHub-hosted runner assumptions) to 90 (verified comfortably
    above the real cold runtime)

  Fixes accumulated during the matrix landing — each is a category
  of GHA / Windows / bash interaction that took a verification run to
  surface, all preserved in commit history for the next person who
  hits one:
  - **`${{ github.workspace }}` doesn't expand inside matrix
    `include:` values** — collapsed to literal `/vcpkg_installed/x64-linux`
    on Linux, breaking CMake's protobuf probe with "Preliminary CMake
    check failed". Fix: inline `${{ github.workspace }}` directly in
    each step's `env:` block (where it DOES evaluate) or use
    `$GITHUB_WORKSPACE` in `run:` blocks.
  - **`defaults.run.shell: bash` on the Windows self-hosted runner
    resolves to `C:\Windows\system32\bash.EXE`** (WSL bash), which
    refuses to run as `LOCAL SYSTEM` with
    `WSL_E_LOCAL_SYSTEM_NOT_SUPPORTED`. Fix: per-leg `shell:` matrix
    variable; Windows uses explicit
    `'C:\msys64\usr\bin\bash.exe --noprofile --norc -eo pipefail {0}'`
    (CLAUDE.md's documented Windows development shell).
  - **`hashFiles('**/*.cpp', '**/*.hpp', '**/*.h')` exceeds GHA's
    hard 120-second timeout** on the persistent NTFS Windows runner
    workspace because `vcpkg_installed/` accumulates thousands of
    vendored headers from gRPC/protobuf/abseil/openssl/etc. across
    runs. Linux-hosted CI in `ci.yml` doesn't hit the limit because
    GitHub-hosted runners get a fresh workspace per run. Fix: hash
    only build-system config files (`meson.build`, `meson_options.txt`,
    `vcpkg.json`, `vcpkg-configuration.json`, `meson/native/*.ini`,
    `meson/cross/*.ini`) — small, fast, and the only inputs that
    should rotate the GHA ccache slot. ccache itself handles
    source-level invalidation via content addressing.
  - **`${{ github.workspace }}` interpolated into bash `run:` source
    has its backslashes stripped by bash's escape processing on
    Windows** — the path `C:\actions-runner\_work\Yuzu\Yuzu` becomes
    `C:actions-runner_workYuzuYuzu` because `\a`, `\Y`, `\_` etc. are
    parsed as escape sequences. Fix: use `$GITHUB_WORKSPACE` (env var
    read at runtime — no escape processing) instead of
    `${{ github.workspace }}` (GHA source interpolation at parse time)
    in bash `run:` blocks.
  - **`sanitizer-tests.yml` runner label was wrong** —
    `runs-on: [self-hosted, yuzu-wsl2-linux]` was the original PR2
    pattern, but the runner's actual labels are
    `["self-hosted", "X64", "Linux"]` (no custom `yuzu-wsl2-linux`
    label exists; that string is the runner NAME, not a label). Gate 3
    build-ci review called the pattern "correct" without verifying
    against `gh api /runners`. Fixed both `codeql.yml` and
    `sanitizer-tests.yml` to use `[self-hosted, Linux, X64]` which
    matches the runner's real label set. The `sanitizer-gate.sh
    --expect-runner` check compares `runner_name` (not labels) via
    `gh api /jobs`, which correctly matches `yuzu-wsl2-linux` as the
    runner's name, so that check is unaffected.

- **Migration failure now closes the affected store (#339).** When
  `MigrationRunner::run()` returns false for a store that owns its
  SQLite handle (26 of 30 stores), the store's `create_tables()` closes
  the handle and sets `db_ = nullptr`, so `is_open()` correctly returns
  false. Previously a migration failure was logged but the store kept
  reporting itself as open, and `ResponseStore::store()` would silently
  no-op on inserts because `insert_stmt_` was null — agent results
  reached the server, were "accepted" over gRPC, and disappeared. This
  change ensures a migration failure surfaces loudly via `/readyz` and
  causes reads/writes to fail fast instead of dropping data. (Closes
  UP-1 / UP-2 / UP-9 / UP-20 compound finding from the #339 governance
  run.)
- **`/readyz` reports per-store status with failed store names (#339).**
  The readiness probe now walks 12 load-bearing stores (response, audit,
  instruction, api_token, policy, rbac, tag, management_group,
  runtime_config, inventory, workflow_engine, custom_properties) and
  returns a JSON body of the form
  `{"status":"not ready","failed_stores":["..."]}` on 503 so operators
  can diagnose upgrade failures without digging through logs.
- **`MigrationRunner` hardening**: explicit `ROLLBACK;` on COMMIT
  failure so shared-connection callers (`InstructionDbPool`) don't
  inherit a half-open transaction; removed redundant `ensure_meta_table`
  call in `current_version()`; `Migration::sql` is now `std::string`
  (owning) instead of `std::string_view` to guard against future callers
  constructing migrations from non-null-terminated views.
- **`docs/user-manual/upgrading.md`** rewritten (#339): Docker section
  references the new `docker-compose.reference.yml`, real `ghcr.io`
  image path, backup recipe with a dedicated backup directory, explicit
  Docker rollback recipe, `schema_meta` query for operator-side
  verification, and truthful failure-mode guidance that points at
  `/readyz` (not `/livez`) as the upgrade-success signal. The "Schema
  Migrations" section describes the real mechanism, which stores carry
  legacy shims, and what the log burst on first upgrade looks like.
  Drops the inaccurate "since v0.1.0" claim. Version compat table now
  spans 0.5.x → 0.9.x as a single row so the 0.10.x jump reads cleanly.
- **`docs/user-manual/server-admin.md`** Docker compose table now
  includes `docker-compose.reference.yml` with the "requires operator
  hardening" caveat.

### Breaking

- **`DELETE /api/settings/users/:name` now returns 403 + HTMX toast
  when the URL target matches the caller's own session username
  (was: 200 + deletion).** Operator scripts that previously called
  this endpoint to delete the credential they were authenticated
  with — for example, a decommission flow that removes its own
  service account as a final step — will receive `403 Forbidden`
  starting in v0.11.0. The full self-deletion lockout vector
  including UI suppression is documented in the Fixed entry below
  (#397). To remove the account a script is signed in as, create a
  second admin account first, switch authentication to that account,
  then issue the DELETE.
- **`POST /api/settings/users` now returns 403 + HTMX toast when an
  admin attempts to change their own role (typically a self-demote
  from `admin` to `user`).** The same lockout class as the DELETE
  case above; closed in the Gate 4 governance hardening round
  (ca-B1). Self-password-change (same username, same role, different
  password) is **explicitly allowed** and continues to return 200 —
  the guard is role-scoped, not a blanket self-upsert ban. Operator
  scripts that change their own role need to be split: have a
  second admin perform the role change, or perform the role change
  before swapping accounts.
- **Two new audit actions written to `audit_store`:**
  `user.delete` and `user.upsert`, each with `result` ∈
  {`success`, `denied`}. Downstream consumers (Splunk HEC,
  ClickHouse projections) that match on the existing
  `<noun>.<verb>` action convention pick this up automatically. SOC
  2 CC7.2 evidence chain (governance Gate 6 CO-1).

### Fixed

- **Settings → Users hardening round on top of the #397/#403 fix —
  ca-B1 sibling lockout, CO-1 audit chain, UP-1 empty-username
  fail-closed, UP-9 GET/POST defensive auth (governance Gate 4-6).**
  The original two-sided fix below closed the DELETE self-target
  case but left several adjacent hardening items open that the full
  governance pipeline surfaced:
  - **ca-B1 — POST self-demotion guard.** `POST /api/settings/users`
    is the second equivalent route to the same lockout class: an
    admin POSTing their own username with a lower role demotes
    themselves out of admin and is locked out of every admin-gated
    page on the next request. Now rejected with HTTP 403 + "Cannot
    change your own role" toast when
    `(username == session->username && role != session->role)`.
    Self-password-change (same role) is explicitly allowed.
  - **CO-1 — SOC 2 CC7.2 audit chain.** The 403 self-reject branches
    and the success delete/upsert paths now emit `audit_fn_` events
    (`user.delete` / `user.upsert` with `result` ∈ {`denied`,
    `success`}). `spdlog::warn` alone is not the audit chain — SIEM
    ingestion paths and SOC 2 evidence collection both read
    `audit_store`, not log files. Pre-existing gap on the success
    path also closed.
  - **UP-1 — empty session username fail-closed.** All three
    handlers now return HTTP 500 + `spdlog::error` when
    `session->username.empty()`. Defense-in-depth against an
    upstream OIDC mis-config returning empty `preferred_username`;
    previously the empty-string sentinel could match an empty-
    username row via `"" == ""` or render every row as non-self.
  - **UP-9 — GET/POST defensive 401.** GET `/fragments/settings/users`
    and POST `/api/settings/users` now mirror the DELETE handler's
    defensive 401 branch when `admin_fn_` passes but `auth_fn_`
    returns nullopt. Previously they fell through with empty
    `self_name`, re-rendering Remove buttons on every row including
    the operator's own — the #403 bug pattern resurrected inside
    the response body.
  - **arch-S1 — `render_users_fragment` no longer has a default
    argument.** Every call site must pass `current_username`
    explicitly so a future caller forgetting it is a compile error
    rather than a silent UI regression.
  - **CLAUDE.md** under Authentication & Authorization captures the
    self-target principal-destruction guard as a hard invariant for
    future handlers (doc-S2).
- **Self-deletion lockout in Settings → Users closed on both UI and
  handler sides (#397 critical, #403 UI — both filed from the Apr 2026
  UAT pass).** The Settings → Users page rendered a "Remove" button
  next to every account including the currently authenticated
  operator's own row, and `DELETE /api/settings/users/:name` did not
  check the target against the caller's session. Confirming the
  generic hx-confirm dialog dropped the sole admin credential on a
  running server, leaving every API call returning 401 until the
  process was restarted against its on-disk config — a permanent
  lockout on single-seat deployments where the only recovery was a
  container restart. Fix lands both halves because a hand-crafted
  HTTP DELETE bypasses the dashboard entirely:
  - `server/core/src/settings_routes.cpp` —
    `render_users_fragment(const std::string& current_username)` now
    takes the caller's session username and renders an italicised
    "Current user" badge (not a button, no hx-delete) for the matching
    row. Every call site (`GET /fragments/settings/users`,
    `POST /api/settings/users` success and error paths,
    `DELETE /api/settings/users/:name`) resolves the session via
    `auth_fn_` and threads the name through so the UI stays consistent
    after user CRUD.
  - The `DELETE` handler resolves `session = auth_fn_(req, res)` after
    the `admin_fn_` gate passes, compares `session->username` to the
    URL-captured target, and rejects with HTTP 403 +
    `HX-Trigger: {"showToast":{"message":"Cannot delete your own
    account","level":"error"}}` if they match. The rejected attempt is
    logged at warn level (`User '<x>' attempted to delete their own
    account via /api/settings/users — rejected`) so operators chasing
    a lockout incident can see it in the server log.
- **Windows MSVC LNK2038 closed end-to-end via "option D" — static
  triplet override + hand-rolled `cxx.find_library()` wiring for
  grpc/protobuf/abseil/zlib/openssl (#375, PR #373 merged as
  `bf95d3b`).** The earlier `0fe5eac` fix (removing
  `VCPKG_BUILD_TYPE release` from `triplets/x64-windows.cmake`) stopped
  vcpkg from emitting release-only binaries but did not stop meson's
  cmake dependency translator from baking the release library paths
  into the debug link line — every Windows MSVC debug build still
  produced dozens of `RuntimeLibrary` / `_ITERATOR_DEBUG_LEVEL`
  mismatches against `absl_cord.lib`, `protobuf.lib`, and friends.
  Four iterations (per-build-type triplets → explicit
  `CMAKE_BUILD_TYPE` → drop static override → option H hybrid) failed
  in distinct ways (`12e40ae` through `220e7bd` on the dev branch).
  Option D is the combination that works:
  - `triplets/x64-windows.cmake` forces `VCPKG_LIBRARY_LINKAGE static`
    + `VCPKG_CRT_LINKAGE dynamic` so vcpkg emits per-build-type static
    archives (`.lib` for release, `d.lib` for debug) that can be
    selected at link time by the consumer.
  - `meson.build` replaces the meson `dependency('grpc++',
    method: 'cmake')` wiring on Windows MSVC with a hand-rolled
    `cxx.find_library()` chain that picks the correct variant
    (`protobuf`/`protobufd`, `zlib`/`zlibd`, `libssl`/`libcrypto` —
    unconditional because gRPC's TLS/JWT/PEM paths always resolve
    against OpenSSL regardless of schannel aspirations) per the
    active `buildtype`. Debug and release link lines are now symmetric
    and CRT-consistent.
  - `vcpkg.json` openssl dependency loses its `"platform": "!windows"`
    filter (it was aspirational, never worked, and confirmed wrong by
    the option D canary's LNK2019 errors).
  Full history — every failed option, the symmetry breakage at each
  step, and the strategic escape path to a QUIC-based transport
  (P1 #376) in case the option D wiring ever rots — is preserved in
  `.claude/agents/build-ci.md` under "Windows MSVC static-link history
  and #375". **Do not simplify either half of the Windows wiring** —
  the triplet override OR the hand-rolled `cxx.find_library()` list —
  without reading that agent doc first. Linux and macOS are unaffected
  throughout (meson's cmake dep translator works correctly on
  platforms with single-variant runtime libraries). The rest of the
  dependency rollout (#363, 7 stale Dependabot PRs rebased onto
  `dev`) was gated on this fix and unblocked immediately after the
  PR #373 merge.

- **Erlang gateway test suites (`eunit` + `ct`) now survive Windows
  parallel test scheduling (#375, folded into PR #373).** Two distinct
  Windows-only failures in the gateway test wrapper
  `scripts/test_gateway.py` had to be untangled in sequence:
  - **Cover-races-compile on `gateway_pb.beam`** (commit `b33f1df`
    regression, fixed in `6d8aa5a`). `b33f1df` added a pre-fetch step
    `rebar3 as test compile --deps_only` to warm the hex cache before
    the actual test run. On Linux/macOS this is harmless because
    `_build/test/lib/yuzu_gw/src/` is a symlink to `apps/yuzu_gw/src/`
    and cover instrumentation always reads a consistent view of the
    ebin tree. On Windows — where symlinks are unavailable so rebar3
    copies source files instead — the pre-fetch left
    `_build/test/lib/yuzu_gw/` in a state where the subsequent
    `rebar3 as test eunit` incremental compile raced cover's
    `pmap_spawn` module-scan. Result was a consistent ~10 s failure
    with `{cover,get_abstract_code,2,...,{file_error,
    ".../gateway_pb.beam",enoent}}` on the gpb-generated protobuf
    module before any test executed. `6d8aa5a` drops the pre-fetch
    entirely (redundant on the persistent `yuzu-local-windows` runner
    whose hex cache is already warm) and retains the
    `run_with_retry()` helper with `max_attempts=4` on the actual
    test invocation for continued hex.pm flake protection.
  - **Parallel-compile race between the two gateway suites** (fixed
    in `f0b84c7`). Meson's default test scheduler runs `gateway eunit`
    and `gateway ct` in parallel, both invoking `test_gateway.py`,
    both running `rebar3 as test <suite>` against the same
    `_build/test/lib/<dep>/` tree. rebar3's compile worker writes
    `<name>.bea#` then atomically renames to `<name>.beam`; when two
    processes collide on the same dep (`proper` is first, being the
    largest Erlang dependency), whichever renames first wins and the
    loser's `MoveFileEx` call fails with `ENOENT` on the temp file.
    Linux/macOS tolerate the race via POSIX atomic rename and
    symlinked source trees; Windows does not. The failing suite
    flipped between eunit and ct across runs depending on which
    rebar3 process lost the race. Fix: `meson.build` sets a distinct
    `REBAR_BASE_DIR` per suite (`_build_eunit` vs `_build_ct`) via
    the test `env:` parameter; `scripts/test_gateway.py` honors the
    env var when computing its ebin-wipe path; `.gitignore` gains the
    two new build roots. Two disjoint `_build/` trees cannot race.
    Cost is a one-time extra compile of Erlang dependencies
    (`meck`, `proper`, `covertool` ≈ 10–15 s) in whichever suite
    starts second from a cold cache, paid once per fresh runner and
    then cached by rebar3's user-level hex cache for subsequent runs.
  The pre-`b33f1df` eunit path was passing on an earlier commit only
  because that run happened to avoid the parallel-race by winning the
  scheduling flip; both failure modes had to be fixed before the CI
  cycle could go consistently green. Validated on PR #373 push CI
  run `24426124422` (Windows MSVC debug: `gateway eunit OK 58.58s`,
  `gateway ct OK 78.39s`) — the first fully-green Windows MSVC
  gateway run in the #375 fix chain.

- **`.github/workflows/ci.yml`: Linux jobs (gcc-13/clang-19,
  debug/release) migrated from `ubuntu-24.04` GHA-hosted to
  `yuzu-wsl2-linux` self-hosted runner (commits `f4d634e`, `d12ba74`).**
  Mirrors the Windows MSVC migration to bring all four mainstream
  platforms under self-hosted control, trading hosted-runner cold-cache
  cost for persistent-runner warm-cache and freedom from GHA outages.
  Two follow-up infrastructure gaps surfaced and were closed during the
  migration:
  - **NOPASSWD sudo for `github-runner`** — first push run failed on the
    `Install system packages` step because the `github-runner` user had
    no NOPASSWD sudo grant. Fixed out-of-band by adding
    `/etc/sudoers.d/github-runner` granting NOPASSWD for `apt-get`,
    `apt`, and `dpkg`. The grant is host-side and not version-controlled;
    canonical recovery procedure is documented in
    `docs/ci-troubleshooting.md`.
  - **PEP 668 `externally-managed-environment` (`d12ba74`)** —
    Ubuntu 24.04 (which the WSL2 distro is) ships PEP 668's marker so a
    system-wide `pip3 install` refuses with `EXTERNALLY-MANAGED`. All
    four Linux jobs now use
    `pip3 install --user --break-system-packages -r requirements-ci.txt`
    (the documented bypass for ephemeral CI install-and-go environments)
    plus `echo "$HOME/.local/bin" >> $GITHUB_PATH` so the subsequent
    `meson setup` step finds the `~/.local/bin/meson` shim.

- **WSL2 utility VM keep-alive: `vmIdleTimeout=-1` in `.wslconfig`,
  `loginctl enable-linger dornbrn` for defense-in-depth.** The
  `yuzu-wsl2-linux` self-hosted runner lives inside the WSL2 host distro
  on Shulgi. WSL2's default `vmIdleTimeout=60000` (60 s) shut the utility
  VM down ~60 s after the last interactive shell session ended, which
  killed both the `actions.runner.Tr3kkR-Yuzu.yuzu-wsl2-linux.service`
  systemd unit AND any tmux sessions inside the distro. Confirmed by 4
  VM cycles on 2026-04-15 (07:52, 08:24, 10:06, 13:07 UTC, captured by
  `last reboot`) correlating with SSH disconnect events, and by the
  parent-run-wedge cascade where CI run `24450261405` lost its
  `Linux gcc-13 debug` job mid-execution and the orphaned job could not
  be cancelled until the runner reincarnated and force-cancel propagated.
  Fix in two coordinated changes (both host-side, neither in the repo):
  - `vmIdleTimeout=-1` in `/mnt/c/Users/natha/.wslconfig` (Windows-side
    WSL2 host config, applied via `wsl --shutdown`). `-1` disables the
    idle timeout entirely — appropriate for a runner host where the
    cost of the VM running idle is dwarfed by the cost of cancelling
    an in-flight CI run.
  - `loginctl enable-linger dornbrn` so user-scope systemd survives
    "no sessions" windows even with the VM up. Defense-in-depth, since
    the runner unit is system-scope and didn't strictly need it.
  Canonical recovery procedure documented in `docs/ci-troubleshooting.md`
  as the first runbook entry for the "Linux runner shows offline" /
  "tmux is dying" failure mode.

- **`.github/workflows/ci.yml`: Windows MSVC debug and release jobs
  migrated from the GHA-hosted `windows-2022` runner to the
  `yuzu-local-windows` self-hosted runner (#374, commit `3960f46`).**
  Hosted Windows runners have long vcpkg install times (grpc alone
  takes 10+ minutes from a cold cache) and occasional `applocal.ps1`
  / grpc-build flakes that were blocking the #375 debug iteration
  loop. Moving Windows MSVC onto the persistent self-hosted runner
  cuts warm-cycle time significantly and gives vcpkg's binary cache a
  stable disk to live on across runs. The single-runner serialization
  pattern (only one Windows MSVC job runs at a time) is deliberate —
  the `yuzu-local-windows` runner is a single physical machine with
  one worker — and has the side-effect of flushing out any Yuzu test
  code that was inadvertently relying on hosted-runner-fresh state.
  The migration exposed #375 (LNK2038 was masked on hosted runners by
  a different vcpkg cache layout) which was the gate that had to
  close before the dependabot rollout could proceed.

- **`scripts/test/` harness bugs discovered running `/test --full`
  against uncommitted #339.** Three PR1 harness fixes that landed the
  headline upgrade test at green:
  (a) `test-upgrade-stack.sh` wrote the upgrade-test admin credentials
  with `chmod 600` owned by the test runner's UID. `Dockerfile.server`
  drops to `USER yuzu` (unprivileged) before reading the config, so
  the file was invisible inside the container and v0.10.0 fell through
  to first-run-setup and exited. Now `chmod 644` on the cred file and
  `chmod 700` on the parent `/tmp/yuzu-test-${RUN_ID}/` dir — the
  parent-dir restriction prevents host-side leakage and the 644 on
  the file lets the container yuzu user read it. Also fixes the
  fallback `docker compose logs` diagnostic in the /readyz-timeout
  branch which was missing the required `YUZU_VERSION` and
  `YUZU_TEST_CONFIG` env vars, producing a confusing
  "empty section between colons" error instead of the actual logs.
  (b) `test-fixtures-verify.sh` hit `/api/settings/enrollment-tokens`
  and `/api/settings/api-tokens` as JSON list endpoints — neither
  exists; enrollment tokens are only exposed via the HTMX fragment at
  `/fragments/settings/tokens`. The verifier now reads the fragment
  HTML and counts `<code>...</code>` token-id cells; API tokens are
  verified through the proper `/api/v1/tokens` REST endpoint and
  parsed as JSON.
  (c) `test-fixtures-write.sh` POSTed to `/api/settings/api-tokens`
  with `label=` and `ttl=` form fields, but the handler expects
  `name=` and `ttl_hours=` and silently returns an HTML error
  fragment on mismatch. The writer now uses the correct field names
  and inspects the response body for `feedback-error` before accepting
  the write. (#339 /test verification)
- **`scripts/linux-start-UAT.sh` now exits non-zero on connectivity test
  failure.** Previously the script always exited 0 after the stack stood
  up, regardless of whether the 6 inline connectivity tests passed. The
  /test Phase 4 gate relied on the exit code to detect a broken stack
  and was therefore a false-positive trap. `start_all()` now captures
  the result into `UAT_TEST_RESULT` and returns it, which the script
  propagates as its exit code. **This is a breaking change for any
  caller that assumed the script always exits 0** — in practice there
  are no such callers in-tree, but operators with external scripts that
  pipe to `|| true` should verify they actually want to swallow the
  failure.
- **`ci(release)`: filter `actions/download-artifact@v4` to `yuzu-*`
  pattern.** The auto-generated `*.dockerbuild` provenance metadata files
  (uploaded by docker buildx attestation) consistently failed download
  with `Artifact download failed after 5 retries`, killing the Create
  Release job for v0.10.0 on both the initial run and a `--failed`
  retry. The v0.10.0 release was published manually from local instead,
  at the cost of the `SHA256SUMS.bundle` cosign keyless attestation
  (which requires the GitHub-Actions OIDC issuer
  `token.actions.githubusercontent.com` and cannot be replicated from a
  developer machine). The filter restores the cosign signature for
  v0.10.1+ by skipping the broken artifacts entirely; the 10 `yuzu-*`
  release binaries are unaffected.
- **`ci(cache)`: include `matrix.build_type` in Windows vcpkg cache
  key.** The Windows MSVC matrix runs both debug and release builds
  against the same `vcpkg-x64-windows-${hashFiles(...)}` cache key.
  Whichever job populated the cache first won, and the other job linked
  user code (compiled with `/MDd` and `_ITERATOR_DEBUG_LEVEL=2`) against
  `absl_*.lib` variants built with `/MD` and `_ITERATOR_DEBUG_LEVEL=0`,
  producing dozens of `LNK2038` "RuntimeLibrary mismatch" errors. The
  flake hit PR #355's CI matrix and required an admin override to merge.
  Adding `${{ matrix.build_type }}` to the cache key gives debug and
  release independent slots; the legacy build-type-less restore key was
  intentionally **not** preserved so a poisoned cache can't be silently
  restored. Both matrix jobs will populate fresh caches on their next
  run; this is self-healing. See #356 for the watch list — the
  underlying meson+vcpkg+`CMAKE_BUILD_TYPE` interaction may need a
  follow-up fix if the symptom recurs.

### Tests

- **`tests/unit/server/test_settings_routes_users.cpp` (new, 9
  cases).** First test file for the Settings routes layer. Stands up a
  real `httplib::Server` on a random port with `SettingsRoutes`
  registered against a two-account `AuthManager` (`admin` +
  `bob`), mocks the `auth_fn`/`admin_fn`/`perm_fn`/`audit_fn`
  callbacks (audit_fn captures every call into a vector for evidence-
  chain assertions), and exercises the full HTTP surface. Coverage:
  - **#397 handler guard:** admin-self-DELETE returns 403 with the
    full HX-Trigger payload (not just substring) and leaves the
    account intact; the rejected attempt emits a `user.delete` /
    `denied` audit event (CO-1 evidence chain).
  - **Non-self DELETE:** admin-DELETE of another user returns 200,
    the account is removed, and emits a `user.delete` / `success`
    audit event.
  - **Non-admin DELETE:** rejected by the `admin_fn_` gate before
    the self-delete guard is reached, no audit event recorded.
  - **Unauthenticated DELETE:** rejected by `admin_fn_` with 403,
    target account intact, no audit event recorded.
  - **ca-B1 self-demotion guard (POST):** admin POSTing
    `username=admin&role=user` is rejected with 403 +
    "Cannot change your own role" toast; role remains admin;
    `user.upsert` / `denied` audit event captured.
  - **POST self-password-change:** same username, same role only
    password change — explicitly allowed, returns 200,
    `user.upsert` / `success` audit emitted.
  - **POST success path renders self-row guard:** new user appears
    in the response fragment with hx-delete; operator's own row
    still has Current user badge — regression cover for the
    self_name threading through the success branch.
  - **#403 UI guard:** `GET /fragments/settings/users` emits no
    `hx-delete="/api/settings/users/admin"` attribute for the self
    row, still emits it for every other row, and renders the
    "Current user" badge in its place.
  - **UI guard with multiple users:** every non-self row keeps its
    Remove button when the user list grows.
  Harness uses an RAII `TmpDirGuard` member that cleans up the temp
  directory even if a `REQUIRE` inside the constructor body throws
  (qe-B1 — partially-constructed objects don't run their own
  destructor but fully-constructed members do). Pattern available for
  future Settings-routes regression coverage.
- **`tests/unit/server/test_migration_runner.cpp`** — four new cases
  tagged `[migration][adoption]` exercise the adoption and hardening
  paths: (a) running v1 on a database that already has tables populated
  with data preserves rows and stamps `schema_meta`, (b) a fresh DB gets
  the full latest schema, (c) the legacy compat shim + v1 combination
  stays idempotent across simulated server restarts, (d) a bad migration
  statement rolls back cleanly and leaves the shared connection usable
  for subsequent migrations on other stores (#339). `TestDb` now uses
  `sqlite3_open_v2` with `SQLITE_OPEN_FULLMUTEX` to match the flags
  every production store opens with; `count_rows` and `column_exists`
  helpers now `REQUIRE` that `sqlite3_prepare_v2` succeeds so a test
  typo cannot mask itself as a false-green.

### Deferred follow-ups from #339 governance

- **#358** — Chaos regression tests for the migration runner
  hardening: concurrent-server race (CH-B), mid-startup SIGKILL
  (CH-E), forward-version DB downgrade protection (CH-F / UP-6).
- **#359** — Per-shim-store adoption test coverage: targeted tests
  for the six legacy-compat-shim stores (`api_token_store`,
  `instruction_store`, `patch_manager`, `policy_store`,
  `product_pack_store`, `response_store`) plus `schema_meta` stamp
  assertions in existing store tests and test coverage for the
  eleven stores that currently have none.
- **#360** — Migration observability + SRE hardening: Prometheus
  counters for migration events (OBS-3), log-burst summary line
  (OBS-4), independent `migration.log` audit trail (compliance-F4),
  hot backup via SQLite online backup API (REC-1), CI lint for
  migration runner wiring invariants (UP-17), and compile-time
  `static_assert` for legacy shim removal (arch-SH2).

### Known issues

- **#354** — Linux build job bundles a stale `yuzu-gateway 0.9.0`
  package alongside the fresh `0.10.0` agent and server packages in the
  `yuzu-linux-deb` and `yuzu-linux-rpm` artifacts. Discovered during the
  manual v0.10.0 release on 2026-04-13. **The artifact-download flake
  above masked this** — without the flake, v0.10.0 would have shipped a
  corrupted release with mixed-version `.deb` / `.rpm` files
  (`yuzu-gateway_0.9.0_amd64.deb` next to `yuzu-server_0.10.0_amd64.deb`).
  The manual v0.10.0 release explicitly excluded the stale packages
  when assembling assets locally. Root cause not yet investigated;
  suspected ccache reuse from the v0.9.0 release run, hardcoded version
  in a packaging script, or duplicate gateway packaging in the linux
  build job that should defer to the dedicated `Build Gateway (Erlang)`
  job. P1.
- **#356** — Watch issue for the Windows MSVC debug `LNK2038` flake
  fixed by the cache-key change above. The cache-key fix prevents one
  class of cross-variant cache contamination, but the bug class can
  recur if (a) anyone reverts the discriminator, (b) Linux/macOS jobs
  hit the same pattern (latent — only Windows manifests because of
  MSVC's `_ITERATOR_DEBUG_LEVEL` ABI), or (c) the actual root cause is
  meson's CMake dependency resolver not propagating `CMAKE_BUILD_TYPE`
  into vcpkg's exported port-config files (in which case the cache-key
  fix is incomplete and the next CI run will still fail). Watch list in
  the issue body and follow-up comment. P2.

## [0.10.0] - 2026-04-12

### Added

- **`/governance` skill** at `.claude/skills/governance/SKILL.md` — a
  reusable prompt-writing runbook for the Gate 1–7 governance pipeline
  defined in CLAUDE.md. Provides parameterized agent preambles, the
  Gate 3 domain-triggered decision matrix, conditional Gate 5 chaos
  analysis, and a "Known patterns" section seeded with the five
  failure modes caught in the #222/#224 governance run (sibling IDOR,
  cycle-safe parity, error-branch info disclosure, enumeration oracle,
  readiness probe coverage). Default range is `dev..HEAD` because
  Yuzu's main working branch is `dev`, not `main`. Invoke with
  `/governance <commit-range>` — the skill doesn't fully automate
  (judgment calls on Gate 3 fan-out and Gate 5 skip still required)
  but cuts per-run prompt-writing overhead roughly in half.

- New Prometheus metrics for the auth and audit subsystems:
  `yuzu_server_token_cache_hits_total`, `yuzu_server_token_cache_misses_total`,
  and `yuzu_server_token_cache_size` expose API-token cache effectiveness so
  cold-cache stampedes after restart are visible to operators.
  `yuzu_server_audit_events_total{result}` counts audit-event writes bucketed
  by `success`/`failure`/`denied`/`other`.
- `tests/test_changelog_order.py` enforces reverse-chronological ordering of
  CHANGELOG sections (Keep a Changelog convention). Wired in as a meson test
  (`changelog order`, suite `docs`) and as a new lightweight GitHub Actions
  workflow (`Docs Lint`) that triggers on `CHANGELOG.md` / `docs/**` edits —
  CHANGELOG drift is now caught in CI rather than discovered months later.

### Changed

- **CodeQL workflow is manual-only and runs on the self-hosted Linux
  runner.** `.github/workflows/codeql.yml` previously ran on
  `ubuntu-24.04` via `push` to `main` + weekly schedule, consuming
  GitHub-hosted Actions minutes on every merge. It now targets
  `[self-hosted, Linux]` (same runner as `release.yml`) and triggers
  only on `workflow_dispatch` — fire via the Actions UI or
  `gh workflow run codeql.yml`. No `push`/`pull_request`/`schedule`
  triggers, so it cannot gate PR merges and is not listed in any
  branch protection required check. Output lands in the GitHub
  Security tab under "Code scanning alerts" for informational review.
  Preflight now uses the same `gcc-13 / cmake / ninja / meson / ccache`
  dependency-check pattern as `release.yml`, uses the runner's
  pre-installed vcpkg (drops `lukka/run-vcpkg@v11`), and wraps the
  compiler with ccache for fast repeat runs. Private-repo caveat:
  if the repo ever flips private, CodeQL will require GitHub
  Advanced Security — the action enforces the entitlement check
  server-side regardless of where the job runs.

- **`integration-test.sh` — sleep-assert sweep, gateway-crash regex,
  env-overridable ports.** Three drift fixes to
  `scripts/integration-test.sh` that together reduce per-run
  wall-clock and eliminate two assertion false positives:
  1. **Heartbeat metric wait is now loop-poll, not sleep-assert.**
     The previous `sleep 10` started before the agent finished
     enrolling (which can take ~12s on a cold run with enrollment-
     token retry backoff), so by the time the sleep ended the
     agent's 5s-interval heartbeat thread hadn't fired yet and the
     `yuzu_heartbeats_received_total` assertion failed with no
     signal that the wait budget was wrong. Now a 30s loop-poll on
     `/metrics` that exits the instant the counter appears — sub-
     second on warm runs, still succeeds within 30s on cold runs.
  2. **Gateway-stability regex tightened.** The old
     `grep -qi "crash\|supervisor.*error\|SIGTERM"` tripped on
     benign `[info]`-level diagnostic log lines of the form
     `[info] crash: class=exit exception={noproc,...}` that the
     gateway emits when an agent's first registration attempt
     races the upstream `gen_server` startup (the agent's built-in
     exponential backoff resolves it in ~6s). The regex now
     matches only actual Erlang crash markers:
     `CRASH REPORT|=ERROR REPORT|Supervisor: .* terminating|\[error\].*SIGTERM`.
  3. **Env-overridable port defaults.** Every `SERVER_*_PORT` and
     `GW_*_PORT` now uses `${VAR:-default}` so the script can
     coexist with other live stacks — notably the docker UAT from
     `scripts/docker-start-UAT.sh`, which binds `50055` and `50063`
     on the host. Override pattern:
     `SERVER_GW_PORT=50155 GW_MGMT_PORT=50163 bash scripts/integration-test.sh`.
  Bonus sweep: replaced `sleep 3` gateway grpcbox startup with
  `wait_for_port $GW_AGENT_PORT`, and `sleep 2` agent-disconnect
  propagation with a 2s poll on `kill -0` of the killed PID.
  Verified: 22/22 PASS on first run with zero flakes.

- **Friction pass on build / test workflow** — four developer-experience
  fixes from the governance-run retrospective:
  - **Third-party warnings silenced.** Every `dependency()` in the
    top-level `meson.build` and each subdirectory file now carries
    `include_type: 'system'`, so vcpkg / gRPC / abseil / protobuf /
    Catch2 deprecation warnings become `-isystem` includes and no
    longer appear in compile output. Our own code remains under
    `warning_level=3`. Compile logs dropped by dozens of lines per
    incremental build without a wrapper script in the way.
  - **Short test suite names.** `tests/meson.build` now attaches
    `suite: 'agent' | 'server' | 'tar'` to each `test()` call, so
    `meson test -C build-linux --suite server` works directly — no
    more guessing `"yuzu:server unit tests"` or `"unit tests"`.
  - **Stable top-level test binary paths.** New
    `scripts/link-tests.sh` creates
    `/tests-build-<component>-<triplet>/` directories (e.g.
    `tests-build-server-linux_x64/yuzu_server_tests`) as symlinks
    to the real build output. `scripts/setup.sh` runs it
    automatically after configure. Gitignored. Binaries stay live
    across rebuilds because the symlinks point at paths, not
    contents. Catch2 tag filtering (e.g. `[token][owner]`) is now
    one line from the repo root without remembering the build-dir
    layout.
  - **`.gitignore` cleanup.** Added `.codex`, `test_output.txt`,
    `test_xml.txt`, `update.finished`, `node_modules/`,
    `__pycache__/`, `gateway/.deps_cache/`, `gateway/ebin/`, and
    `/tests-build-*/` so `git status` no longer carries session
    noise from dev-machine artifacts.

- **`CLAUDE.md` slimmed from 571 → 484 lines** by splitting three
  implementation-detail sections into dedicated `docs/` files and
  compressing four already-linked sections to pointers. The Auth &
  Authorization feature history (inventory of mTLS, OIDC, AD/Entra,
  Windows cert store, CSP construction, etc.) moved to
  `docs/auth-architecture.md`; only the hard invariants that every
  session must respect (mTLS, HTTPS default, localhost bind,
  `/metrics` auth, owner-scoped token revoke) remain in CLAUDE.md.
  The MCP server architecture and 22-tool inventory moved to
  `docs/mcp-server.md`; only the tier-before-RBAC rule, kill-switch
  flags, audit pattern, and `JObj`/`JArr` serialization rule remain.
  The Windows build toolchain path table moved to
  `docs/windows-build.md`; CLAUDE.md keeps the "MSYS2 bash +
  `setup_msvc_env.sh`, NOT `vcvars64.bat`" rule. Instruction Engine,
  Enterprise Readiness / SOC 2, Development Roadmap, and CI matrix
  sections were compressed to pointers since the target docs already
  exist. Build, Deploy, Release, Erlang Gateway, UAT Environment,
  Darwin Compatibility, and Agent Team / Governance sections stay
  resident intact — churning subsystems and areas that repeatedly
  need re-loading belong in CLAUDE.md, not in `docs/`.

- `AuthRoutes` exposes a public `resolve_session(req)` helper that performs the
  three-tier auth resolution (cookie → `Authorization: Bearer` → `X-Yuzu-Token`)
  used by `require_auth`, `make_audit_event`, and `emit_event`, plus the eight
  call sites in `server.cpp` that previously inlined fragments of the same logic.
  Removes a shadow copy of `extract_session_cookie` from `server.cpp`.

- **Per-OS canonical build directory** — `scripts/setup.sh` now defaults the
  build directory to `build-linux`, `build-windows`, or `build-macos` based on
  the host OS so the same source tree can be configured concurrently from
  WSL2 and a native Windows shell — and a separate macOS dev box — without
  the build dirs trampling each other. The script refuses to reuse a build
  dir whose `meson-info.json` source path was recorded on a different host
  unless `--wipe` is passed (catches the opaque "ninja dyndep is not an
  input" / Windows-path failures from cross-host reuse). It also stops
  auto-wiping existing dirs — `--wipe` is now opt-in; default behaviour is
  `meson setup --reconfigure` to preserve prior compilation state. The
  legacy `builddir/` is gone from the tree; CLAUDE.md documents the
  convention. `YUZU_BUILDDIR` env var still overrides everywhere.

### Breaking

- **API token revocation is owner-scoped** — non-admin users can no longer
  revoke API tokens they do not own. A caller holding `ApiToken:Delete` may
  revoke only tokens whose `principal_id` matches their session username;
  the global `admin` role is the sole bypass. Deployments that used a
  shared non-admin service account to rotate tokens for other principals
  will begin receiving `HTTP 404 token not found` after upgrade. Either
  grant the rotation account the global `admin` role, or refactor the
  rotation so each principal owns its own token (recommended). The same
  constraint applies to both `DELETE /api/v1/tokens/{id}` and
  `DELETE /api/settings/api-tokens/{id}`. See
  `docs/user-manual/server-admin.md` "Upgrade Notes" for details.

### Fixed

- **UAT script `python` vs `python3` drift.**
  `scripts/docker-start-UAT.sh` (8 inline sites) and
  `scripts/uat-command-test.sh` (2 inline sites) both invoked
  `python -c` for JSON / regex parsing. WSL2 Ubuntu has no `python`
  symlink — only `python3` — so every inline parser silently
  returned empty string, and every downstream numeric check
  degraded without error:
  - `docker-start-UAT.sh`: the 10 embedded connectivity tests
    (server registered count, gateway connected count, Prometheus
    target count, ClickHouse event count, os_info round-trip
    parsing) all read "0" or empty strings and reported test
    failures against a stack that was actually working.
  - `uat-command-test.sh`: every command dispatch reported
    `dispatch error` because the `cmd_id` extraction returned
    empty. All 138 test cases failed. After the fix: 136 PASS /
    0 FAIL / 2 legitimate long-running-plugin timeouts
    (`firewall.rules`, `chargen.chargen_start`).

  Both scripts now use `python3 -c` via a mechanical sed fix.
  Worth a broader audit:
  `grep -rn '\bpython -c' scripts/` would surface any remaining
  sites that were missed.

- **`scripts/docker-start-UAT.sh` build dir detection.** The
  script hardcoded `BUILDDIR=$YUZU_ROOT/builddir`, which predates
  the per-OS build dir convention that landed in `830ba7c`. On a
  fresh clone configured via `scripts/setup.sh`, the agent binary
  now lives at `build-linux/agents/core/yuzu-agent` (or
  `build-macos` / `build-windows`), and the preflight check
  reported "yuzu-agent not found — run: meson compile -C builddir"
  even though the binary existed under the new name. Fixed by
  detecting the host OS and selecting `build-<os>`, falling back
  to the legacy `builddir/` path for older trees. Also added
  `Bash(bash scripts/docker-start-UAT.sh:*)` and the `./` variant
  to the project allowlist at `.claude/settings.json`.

- **Governance Gate 4 follow-up hardening** — Gate 4 unhappy-path and
  consistency-auditor surfaced three new BLOCKING items on the prior
  hardening round; all are addressed here:
  - **Denied-branch token-table leak regression (UP-11)** — the prior
    hardening round's new 404 denied branch on
    `DELETE /api/settings/api-tokens/:id` called
    `render_api_tokens_fragment()` which lists ALL users' tokens with no
    principal filter. A non-owner probe therefore received a 404
    response with a complete fleet-wide token table in the HTML body —
    worse than the IDOR the round was closing. The denied branch now
    returns a minimal static error fragment with no token data.
  - **`render_api_tokens_fragment` cross-user enumeration (C1)** — the
    same underlying `list_tokens()` leak affected the success-path
    re-render (`POST`, `DELETE` success) and the `GET
    /fragments/settings/api-tokens` panel load. The fragment now takes
    a `filter_principal` argument. All four call sites pass
    `session->username` for non-admin sessions and empty (full view)
    for admins, matching the `GET /api/v1/tokens` scoping that
    `rest_api_v1.cpp` already enforced. A new
    `ApiTokenStore: list_tokens(principal) scopes results to owner`
    unit test pins the store contract the fix relies on.
  - **Audit-trail integrity, `principal_role` hardcoded `"admin"`
    (C2, Gate 4 unhappy-path UP-9, Gate 4 happy-path SHOULD, Gate 2
    re-review NICE)** — three audit emission sites in
    `settings_routes.cpp` (token create, token revoke success, token
    revoke denied) hardcoded `.principal_role = "admin"`. This was
    benign when the panel was admin-only but became a forensic lie
    once the hardening round opened the handlers to non-admin callers
    with `ApiToken:Delete`. All three sites now read
    `auth::role_to_string(session->role)`, matching the convention in
    `auth_routes.cpp`.
  - **Test fixture brittleness** — `create_token_for` in
    `test_rest_api_tokens.cpp` used `listing.back()`, but
    `list_tokens` orders by `created_at DESC`, so `.back()` is the
    oldest token. Swapped to `.front()` with a comment so future
    multi-token tests in the same harness do not silently regress.

- **Governance hardening round for #222 and #224** — Gate 2 security review
  on the original fixes surfaced two HIGH sibling findings that are
  addressed here:
  - **Dashboard IDOR** — `DELETE /api/settings/api-tokens/:token_id` (the
    HTMX Settings path) had the same ownership gap as the REST handler
    closed by #222. It now looks up the token, rejects cross-user revokes
    with a generic 404 fragment, and emits a `denied` audit event with
    `detail=owner=<principal>` so forensics can tell an enumeration probe
    from a real not-found.
  - **`get_ancestor_ids` cycle safety** — the companion BFS-upward walk
    in `ManagementGroupStore` still had no visited-node tracking, only a
    depth-10 cap. `RbacStore::check_scoped_permission` unions ancestors
    into the set of groups used for role resolution, so on a cyclic DB a
    user could inherit spurious permissions from phantom ancestors
    reported by the cycle's alternating output. `get_ancestor_ids` now
    carries the same `unordered_set<std::string> visited` + warning-log
    pattern as `get_descendant_ids`.
  - **Enumeration oracle closed on REST `DELETE /api/v1/tokens/:id`** —
    the original fix returned `403 "cannot revoke another user's API
    token"` for cross-user revokes, which let a non-owner with
    `ApiToken:Delete` distinguish "token does not exist" (404) from
    "exists but not yours" (403) and enumerate valid token ids. Both
    paths now return `404 "token not found"` with an identical response
    body; the audit log still carries the distinction server-side via
    `result=denied` + `detail=owner=<principal>`.
  - **`create_group` self-parent** — the create path accepted a
    caller-supplied `group.id == group.parent_id` and produced an
    immediate 1-row self-cycle. It now returns
    `"group cannot be its own parent"` from the same layer as
    `update_group`.
  - **REST-handler test coverage (#222 follow-up)** — the original fix
    landed with store-level coverage only. A new
    `tests/unit/server/test_rest_api_tokens.cpp` spins up a real
    `httplib::Server` on a random port, registers `RestApiV1` routes
    with mock `auth_fn`/`perm_fn`/`audit_fn`, and exercises all four
    paths end-to-end: owner self-revoke, admin cross-user bypass,
    non-owner → 404 (no oracle), unknown id → 404 (no audit). 5 HTTP
    cases, 55 assertions, plus the existing store-level cases.
  - **Store-test fixture parallelism** — both
    `test_management_group_store.cpp` and `test_api_token_store.cpp`
    used hardcoded SQLite paths (`/tmp/test_mgmt_groups.db`,
    `/tmp/test_api_tokens.db`) that would collide under
    `meson test --num-processes N`. Each `TempDb` now builds a unique
    path per instance from `std::thread::id` + `steady_clock`, matching
    the `unique_temp_path` pattern already used in
    `test_rest_api_t2.cpp`.
  - **Deep / self-loop cycle regression tests** — the original fix
    only tested a 2-node cycle. New cases exercise a 3-node A→B→C→A
    cycle and the degenerate self-loop `parent_id == id` on a single
    row. A reparent-to-root regression test guards the null-bind
    branch in `update_group` that the cycle/depth block now gates on.

- **API token revocation is now owner-scoped (#222)** — `DELETE
  /api/v1/tokens/:token_id` previously required only `ApiToken:Delete`
  permission without verifying ownership, so any user with that
  permission could enumerate token IDs (the handler always returned 404
  for unknown IDs but 200 for any real token) and revoke other users'
  tokens. The handler now looks up the token via a new
  `ApiTokenStore::get_token(token_id)` method, rejects cross-user
  revokes with `403` and a `denied` audit event, and only allows the
  bypass for callers holding the global `admin` role. Owner-scoped
  audit detail (`owner=<principal>`) is logged on both success and
  denial paths so forensics can distinguish intent.

- **`get_descendant_ids` is cycle-safe; `update_group` validates
  `parent_id` (#224)** — the management-group BFS traversal had no
  visited-node tracking and no depth cap, so any existing cycle in
  `management_groups.parent_id` (injectable via legacy tooling or
  bugs) would hang the server thread indefinitely. It now carries an
  `unordered_set<std::string> visited` and a `10_000` node safety cap,
  logging a warning if the cap is hit. Independently,
  `ManagementGroupStore::update_group` now rejects self-parent,
  parent-not-found, cycle-forming, and depth-exceeding updates at the
  store layer so non-REST callers (admin tooling, tests, future
  endpoints) cannot bypass the checks that previously only lived in
  the REST handler. Store unit tests cover injected-cycle termination
  via a direct SQLite write that mimics on-disk corruption.

- **Docker-compose UAT image tags parameterized** — `docker-compose.uat.yml`
  was shipping with hardcoded `ghcr.io/tr3kkr/yuzu-{server,gateway}:0.8.1-rc0`
  references that were not updated when the version bumped to 0.9.0, so a
  tester running the file fresh would pull the wrong images. The tags are
  now parameterized as `${YUZU_VERSION:-0.9.0}` so operators can override at
  `docker compose up` time, and a new `scripts/check-compose-versions.sh`
  runs as the first step of the release workflow's `release:` job — it
  rejects any hardcoded `yuzu-{server,gateway,agent}:X.Y.Z` references in
  tracked compose files and verifies the parameterized default matches the
  tag being released, so a stale default blocks the release before any
  assets are published. A corrected `docker-compose.uat.yml` was uploaded as
  a v0.9.0 GitHub release asset to unblock current UAT testers.

- Login page no longer renders `[object Object]` on bad credentials. The inline
  JS in `login_ui.cpp` was reading `resp.error` directly from the structured
  error envelope (`{"error":{"code":N,"message":"..."}}`) and assigning the
  object to `textContent`. It now reads `resp.error.message`, with a string
  fallback for legacy responses and a status-keyed default if parsing fails.
  Fixes #333.

- **`ConcurrencyManager::try_acquire` TOCTOU race** — the count-then-insert
  sequence used a separate `SELECT COUNT(*)` and `INSERT OR IGNORE`, so two
  concurrent callers could each read `count < limit`, each insert, and exceed
  the configured `global:N` or `per-definition` cap. `SQLITE_OPEN_FULLMUTEX`
  serializes individual API calls but does not bind two-statement sequences
  together, so it could not catch this. Fix collapses the check and write
  into a single atomic statement: `INSERT OR IGNORE … SELECT … WHERE
  (SELECT COUNT(*) …) < ?`. The COUNT subquery and the INSERT execute as
  one statement under SQLite's per-statement write lock, so the cap is now
  honored under contention. Idempotent re-acquire of the same
  `(definition_id, execution_id)` is preserved via a follow-up existence
  check on the no-op path. Removes the dead `std::shared_mutex mtx_` member
  in `ConcurrencyManager` and `ScheduleEngine` (declared but never acquired
  by any method) — both classes prepare-and-finalize their statements per
  call, so the application-level mutex is unnecessary on top of FULLMUTEX.
  Fixes #330.

- **Audit Trail Integrity Fix (YZA-2026-001)** — Audit log and analytics event
  rows for requests authenticated via `Authorization: Bearer` or `X-Yuzu-Token`
  now populate the `principal` and `principal_role` fields. Previously these
  helpers resolved the principal from the session cookie only, so every
  API-token-authenticated request — including every MCP tool call — wrote audit
  rows with empty `principal`, breaking attribution for SOC 2 evidence purposes.
  The same gap affected `def.created_by` on instruction creation,
  `sched.created_by` on schedule creation, the `user` recorded by execution
  rerun/cancel, and the `reviewer` recorded by approval approve/reject.

  This is a forward-only fix: pre-fix audit rows are not backfilled. Operators
  auditing a window that spans v0.9.0 (released 2026-04-11) and v0.10.0 should
  expect a bimodal `principal` distribution split at the merge date — pre-fix
  token-authenticated rows will have empty `principal`. Cookie auth and login
  flows are unchanged.

### Tests

Test-suite changes are listed separately so other teams can follow test
development independently from the primary software changelog.

- **TOCTOU regression test for `ConcurrencyManager`** — new `[threading]`
  cases in `tests/unit/server/test_concurrency_manager.cpp` race 64 threads
  against `try_acquire("global:3")` and `per-definition` on a
  `SQLITE_OPEN_FULLMUTEX` `:memory:` connection, asserting that exactly the
  configured limit wins. Adds a `TestDbMt` RAII helper for thread-safe
  in-memory connections, and a non-threaded idempotent re-acquire case.
  Server unit-test count: 1112 → 1128 cases.

- **`scripts/run-tests.sh` (and integration / UAT scripts) honour the per-OS
  canonical build directory** — `build-linux` / `build-windows` / `build-macos`
  selected from `uname` (and overridable via `YUZU_BUILDDIR`). Removes the
  hard-coded `builddir/` path that broke under WSL2 once the Windows-side
  build dir disappeared.

- **`run-tests.sh erlang-unit` invokes `rebar3 eunit --dir=apps/yuzu_gw/test`**
  — works around rebar3 3.27 auto-discovery rejecting test modules whose name
  has no 1:1 src/ counterpart (`circuit_breaker_tests`, `env_override_tests`,
  `scale_tests`, every `*_SUITE` file, etc.). The bare `rebar3 eunit`
  invocation would error out with "Module … not found in project" before
  running any test. Tracking issue: #337.

- **Gateway eunit fixture leak: `agent_tests:starts_streaming` cancellation**
  — `yuzu_gw_health_nf_tests:cleanup/1` only killed the mock pids it captured
  in `setup/0`, but the `readyz_503_dead_process` test kills the original
  `yuzu_gw_registry` mock and re-registers a fresh `mock_loop/0` pid that the
  cleanup tracking never sees. The leaked mock survived into every subsequent
  test module; downstream tests checked `whereis(yuzu_gw_registry)` and
  reused it as if it were the real gen_server. When `agent_tests:setup`
  fired, `yuzu_gw_agent:init/1` issued `gen_server:call(yuzu_gw_registry,
  {register, …})` against the mock, which received the message and silently
  recursed without replying — eunit cancelled the call at its 5-second limit
  and the rest of `agent_tests` (14 tests) never ran. The full eunit suite
  reported "Passed: 132. One or more tests were cancelled" instead of the
  expected 148. Fixes:
  - `health_nf_tests:cleanup/1` now looks up the *current* registered pid
    via `whereis/1` for each name it owned at setup time, so re-registered
    mocks are killed too.
  - `agent_tests:setup/0` defensively detects a stale mock under
    `yuzu_gw_registry` (anything whose `proc_lib:initial_call/1` is not
    `{gen_server, init_it, _}`), unregisters it, and starts a real
    registry — guarding against the same class of leak from any future
    test module.
  - `agent_tests:setup/0` also asserts `whereis(yuzu_gw_upstream) =:=
    undefined` so meck-coexisting-with-a-live-gen_server failures fail
    loudly at the boundary instead of producing opaque downstream timeouts.
  - `circuit_breaker_nf_tests`, `circuit_breaker_tests`, and
    `upstream_tests` cleanup paths now use synchronous
    `gen_server:stop(Pid, shutdown, 5000)` instead of `exit(Pid, shutdown)
    + timer:sleep(50)`. The sleep was racy on busy boxes (WSL2 in
    particular) and could leave the upstream gen_server alive into the
    next test module. Eunit count: 133 passing (with all 15 `agent_tests`
    cases cancelled) → 148 passing. Fixes #336.

- **`scripts/integration-test.sh` fixes** — admin password bumped from 8 to
  12 characters to satisfy the post-v0.9 length requirement; `--no-https`
  added so the server starts without TLS in test mode; port matrix split so
  single-host gateway + server no longer collide on 50051 (server `5005x`,
  gateway `5006x`); `YUZU_KEEP_WORK_DIR=1` env var preserves
  `/tmp/yuzu-integration.*` after teardown for post-mortem of failed runs.

- **`scripts/linux-start-UAT.sh` `kill_stale` matches the gateway** —
  `pgrep -f "beam.smp"` is replaced with `pgrep -f "yuzu_gw[/_]"` because
  the rebar3 release wrapper rewrites `cmdline` so the binary name doesn't
  appear in `/proc/$pid/cmdline`. Previous behaviour leaked the gateway
  beam between UAT runs and tied up port 9568 / 50063 indefinitely.

- **`scripts/e2e-security-test.sh` no longer skips on missing creds** —
  honours `YUZU_ADMIN_PASS` env var, then auto-detects against the canonical
  UAT password (`YuzuUatAdmin1!`) and the post-tightening `adminpassword1`
  before falling back to legacy short passwords. Hard-fails if no candidate
  works rather than silently skipping the auth-bearing test categories.
  Brings the security suite from 33 → 60 tests against a live UAT stack.

## [0.9.0] - 2026-04-11

### Added

#### Server
- **`--data-dir` CLI flag** (env: `YUZU_DATA_DIR`) — separates SQLite database storage from the config file location. Required for containerized deployments where the config is mounted read-only but databases need a writable volume. Path is resolved to canonical form at startup (symlinks followed). A writable probe runs at startup to fail fast if the directory is not writable, rather than deferring to the first DB open.
- **`execute_instruction` MCP tool** — dispatches plugin commands to agents via MCP JSON-RPC. Accepts `plugin`, `action`, `params`, `scope`, and `agent_ids`. Returns a `command_id` for asynchronous result polling via `query_responses`. Plugin and action names are normalized to lowercase before dispatch. MCP tool count: 22 → 23.
  - `operator` tier: executes immediately (auto-approved).
  - `supervised` tier: returns `-32006 APPROVAL_REQUIRED` with an explicit message that approval-gated MCP execution is not yet implemented.
  - `readonly` tier: blocked.
  - If neither `scope` nor `agent_ids` is provided, defaults to all agents (documented in tool description as a warning).

#### Testing
- **Puppeteer E2E test expanded** (`Synthetic-UAT-Puppeteer.js`) — 70 → 115 non-destructive commands. Cross-platform path support via `YUZU_AGENT_OS` env var. Added: `network_config dns_cache`, `network_actions ping/flush_dns`, `users group_members`, `filesystem search/search_dir/create_temp/create_temp_dir`, `vuln_scan cve_scan/config_scan/inventory`, `storage set/get/list`, `tags set/get/get_all/check/count`, `agent_actions set_log_level`, TAR extended, `chargen start/stop`, `wol check`, registry read-only (Windows), `windows_updates` extended.
- **REST API command test expanded** (`scripts/uat-command-test.sh`) — 145 → 151 dispatches. Added: `agent_actions set_log_level`, `network_actions flush_dns`, `filesystem create_temp/create_temp_dir`, `interaction notify`. Removed destructive `status switch`.
- **MCP Haiku subagent test framework** — stdio-to-HTTP MCP adapter (`scripts/mcp-http-adapter.js`), Claude Code agent definition (`.claude/agents/mcp-uat-tester.md`), and test harness (`scripts/e2e-mcp-haiku-test.sh`) that invokes Haiku to exercise all MCP tools end-to-end.
- **15 `execute_instruction` unit tests** (`tests/unit/server/test_mcp_server.cpp`) — happy dispatch, null dispatch_fn, missing params, zero agents, default scope, explicit agent_ids, params forwarding, non-string params, read_only_mode, readonly/operator/supervised tier enforcement, audit trail on success and failure.
- **`--setup` flag on all E2E test scripts** — optional Docker Compose lifecycle management. Default: health-check and fail fast. `--setup`: bring up `docker-compose.local.yml`, wait for health, then run.
- Tool count assertions changed from exact equality to `>= 23` minimum with named presence checks — no more magic numbers that break when tools are added.

#### Deployment
- **`docker-compose.local.yml` port topology** — gateway owns host port 50051 (agent-facing), server agent port is container-internal only. Agents connect to `localhost:50051` with default settings.
- **`docker-compose.local.yml` uses `--data-dir /var/lib/yuzu`** — config at `/etc/yuzu/yuzu-server.cfg` (read-only Docker config mount), databases at `/var/lib/yuzu` (writable volume).

### Changed
- `AuthManager::state_dir()` — enrollment tokens and pending agents now written to `--data-dir` when set, instead of always using the config file's parent directory. `reload_state()` re-loads from the new location after `set_data_dir()`.
- `Config::db_dir()` helper method — all ~25 DB path derivations in `server.cpp` use `cfg_.db_dir()` instead of `cfg_.auth_config_path.parent_path()`.
- MCP `read_only_mode` and `mcp_disabled` flags captured by reference (not value) so runtime toggle via Settings UI takes effect without server restart.
- MCP operator tier no longer requires approval for `Execution/Execute` — matches documented "auto-approved" behavior.
- MCP approval-gated operations return `-32006 APPROVAL_REQUIRED` (was `-32603 Internal Error`). Audit status logged as `"approval_required"` instead of `"failure"`.
- `linux-start-UAT.sh` gateway startup changed from `erl` direct to rebar3 prod release binary.
- Default password in test scripts updated to `adminpassword1` (Docker UAT default) with `YUZU_PASS` env var override.

### Documentation
- `docs/user-manual/server-admin.md` — `--data-dir` flag added to CLI flags table and Data Storage section.
- `docs/user-manual/mcp.md` — `execute_instruction` tool added (#23), tool count updated, tier authorization table corrected (operator execution is auto-approved), approval workflow table updated, troubleshooting section clarified.
- `CLAUDE.md` — MCP Phase 1 updated (23 tools, `execute_instruction` documented), Phase 2 reduced to 5 remaining tools.
- `.claude/agents/release-deploy.md` — UAT environment knowledge documented (port topology, data directory separation, Docker file/directory race condition, Grafana dashboard packaging gap, enrollment token API).

## [0.8.1] - 2026-04-11

### Added

#### Testing
- **Comprehensive MCP protocol test suite** (`scripts/e2e-mcp-test.sh`, 140 tests) — exercises all 22 read-only tools, 3 resources, 4 prompts, JSON-RPC protocol methods (initialize, ping, notifications), parameter validation, authentication enforcement, audit trail verification, Phase 2 write tool guards, response format validation, and sequential call state isolation.
- **Expanded REST API E2E test suite** (`scripts/e2e-api-test.sh`, 153 tests) — 26 new sections covering execution statistics, help system, webhook/policy/workflow/instruction-set CRUD, YAML validation, approvals, execution lifecycle with response polling, notifications, agent properties, runtime config, analytics, NVD, inventory queries, directory/discovery, scope engine, 17 settings fragments, 5 dashboard fragments, SSE stream connectivity, static asset delivery, security header verification, MCP endpoint reachability, topology, statistics, license, software deployment, and patch management.
- **Expanded plugin command test** (`scripts/uat-command-test.sh`, ~115 commands across 36 groups) — 12 new plugin groups: example plugin (ping/echo), asset tags, network actions, storage KV CRUD, tags CRUD, TAR extended (sql/configure), vulnerability scanning extended (scan/cve_scan/config_scan), Wake-on-LAN check, chargen traffic generation, HTTP client extended, certificates, and Windows update patch connectivity. Filesystem and IOC tests auto-detect Linux vs Windows and use appropriate paths.

#### Infrastructure
- **Docker Compose local UAT stack** (`docker-compose.local.yml`, gitignored) — uses locally-built images (`yuzu-server:local`, `yuzu-gateway:local`) with full observability (Prometheus, Grafana, ClickHouse). Dashboards provisioned via Docker configs. Separate from `docker-compose.uat.yml` which references ghcr.io images for remote testers.

### Fixed

#### Server
- **Web server connection drops under modest load** — increased cpp-httplib TCP listen backlog from 5 to 128 via `-DCPPHTTPLIB_LISTEN_BACKLOG=128` compile flag. The default backlog of 5 caused the kernel to reject incoming TCP connections when more than 5 were queued for acceptance, resulting in HTTP 000 (connection refused) errors during serial API testing at ~50 requests. Also increased socket read/write timeouts from 5s to 30s to prevent in-progress connections from being dropped under load.
- **Parameterized instruction definitions returning "Unknown Action"** — agent plugins register actions in lowercase but instruction definitions preserved the original case from YAML. Added `std::tolower` normalization at all three creation paths (JSON POST, YAML POST, and the `CommandDispatchFn` adapter).
- **Approval gate not enforced on instruction execution** — `ApprovalManager` was fully implemented but never wired into `workflow_routes::register_routes`. Added approval_mode validation on create/update, fail-closed gate on execute (auto/always/role-gated/unknown), and 202 response for pending approvals.
- **PUT /api/instructions/:id resetting approval_mode** — full-object replacement was overwriting existing fields including `approval_mode`. Changed to partial update preserving unspecified fields.
- **Agent heartbeat deadlock and session races** — fixed heartbeat processing deadlock, session race conditions during re-enrollment, and gateway connection lifecycle issues.

#### Gateway
- **EUnit test cascade failure** (7 modules, 47 tests) — root cause was `yuzu_gw_scale_tests` starting `yuzu_gw_router` and `yuzu_gw_heartbeat_buffer` in test functions without stopping them in cleanup. Fixed cleanup to stop all started processes, added defensive `catch meck:unload` before `meck:new` in all test setups, and defensive `case whereis` for `start_link` calls.
- **`compute_scheduler_util` undef in gauge tests** — function was behind `-ifdef(TEST)` guard but rebar3 test profile didn't propagate `{d, 'TEST'}` to umbrella app compilation. Fixed by unconditionally exporting the function.
- **`agent_count/0` returning `undefined`** — `ets:info(Table, size)` returns `undefined` for nonexistent tables. Added guard clause in `yuzu_gw_registry.erl`.

### Documentation
- `docs/user-manual/rest-api.md` — added 202 response documentation for instruction execute endpoint.
- `docs/user-manual/instructions.md` — documented approval executor-side behavior and action case-insensitivity.
- `docs/yaml-dsl-spec.md` — added case-insensitivity note to action field specification.

## [0.8.0] - 2026-04-09

### Added

#### Security
- **HTTP security response headers (SOC2-C1, #310)** — every HTTP response (dashboard, REST API, MCP, metrics, health probes) now carries six headers: `Content-Security-Policy`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy` (deny-all baseline for camera/mic/geo/usb/etc.), and `Strict-Transport-Security: max-age=31536000; includeSubDomains` on HTTPS deployments. The CSP also appends `upgrade-insecure-requests` on HTTPS.
- New `--csp-extra-sources` CLI flag (env: `YUZU_CSP_EXTRA_SOURCES`) for whitelisting customer CDNs, monitoring beacons, or analytics endpoints. Validated at startup with strict allow-list — rejects control bytes, semicolons, commas, `'unsafe-eval'`, `'strict-dynamic'`, and other unsafe CSP keywords.
- New `server/core/src/security_headers.{hpp,cpp}` module (`yuzu::server::security` namespace) with `HeaderBundle::make()`/`apply()` shared between the production server and the unit/integration tests, ensuring header logic cannot drift between code and tests.
- New `tests/unit/server/test_security_headers.cpp` (38 cases / 146 assertions) and `tests/unit/server/test_static_js_bundle.cpp` (11 cases / 30 assertions) covering CSP construction, validation grammar, end-to-end emission via real `httplib::Server`, and embedded HTMX bundle integrity.
- Resolved security header bundle is logged at INFO at startup so operators can confirm activation: `Security headers active: CSP=N bytes, HSTS=on/off, ...`.

#### Server
- **HTMX 2.0.4 runtime and htmx-ext-sse 2.2.2 extension embedded in the server binary** (`server/core/src/static_js_bundle.cpp`) and served from same-origin `GET /static/htmx.js` and `GET /static/sse.js`. The dashboard works in **air-gapped deployments out of the box** with no internet connectivity required. The HTMX bundle is split into 4 chunks of ≤14000 bytes (MSVC raw string literal limit C2026) and concatenated at static-init into a single `extern const std::string`. Reassembled output is byte-identical to the upstream minified file (50918 bytes). Both upstream packages are 0BSD which imposes no redistribution conditions.

### Changed

#### Security
- **CSP `script-src` is now fully `'self'`-only** with no external CDN allowance — `https://unpkg.com` whitelist removed because HTMX is now served same-origin. Improves SOC 2 supply-chain posture and removes a third-party origin from the dashboard's attack surface.
- All six dashboard-bearing UI templates (`dashboard_ui.cpp`, `settings_ui.cpp`, `compliance_ui.cpp`, `instruction_ui.cpp`, `statistics_ui.cpp`, `topology_ui.cpp`) migrated from `<script src="https://unpkg.com/htmx.org@2.0.4">` to `<script src="/static/htmx.js">`. Same for the SSE extension.

#### UAT Scripts
- `scripts/win-start-UAT.sh` and `scripts/linux-start-UAT.sh`: added `--listen 0.0.0.0:50054` to the server invocation when running with the gateway on the same host. In single-host UAT both server and gateway default to `:50051` for agent gRPC; without the override the server wins the bind and the agent connects directly, bypassing the gateway. Confirmed via `gw-session-` prefix on the agent session ID. Multi-host production deployments are unaffected.

### Fixed

- **Agent registration never reported OS or architecture** — `agents/core/src/agent.cpp` declared compile-time `kAgentOs`/`kAgentArch` constants for every supported platform but never plumbed them into `RegisterRequest.info.platform`. The `Platform` sub-message was always empty, so the server stored `os=""` and `arch=""` for every agent, the dashboard scope panel meta line read `<agent_id> · / · vX.Y.Z` (orphaned `/` between empty fields), and the OTA updater couldn't match agent platform to update binaries. Fix: populate `info->mutable_platform()->set_os/set_arch/set_version` during the registration build. New `get_os_version()` helper uses `RtlGetVersion` via NTDLL on Windows (avoids manifest-based version spoofing) and `uname()` on Unix. Verified end-to-end: `/api/agents` now returns `{os: "windows", arch: "x86_64"}` and the scope panel meta line reads `<agent_id> · windows/x86_64 · vX.Y.Z`.
- **Dashboard scope panel showed "0 agents" under strict CSP** — the SOC2-C1 CSP introduced in commit 7474006 forbade `'unsafe-eval'`, but the dashboard relied on HTMX's `hx-on:` attributes and `hx-vals="js:..."` syntax which both internally call `new Function(...)`. The browser silently blocked the eval, so the scope-list HTMX poll fired without its `selected` parameter and the SSE-driven refresh hooks never ran. Effect: registered agents appeared in the server's API and could execute commands, but never appeared in the dashboard scope panel — even when they responded successfully. Fix: replaced all 8 eval-requiring HTMX attributes in `dashboard_ui.cpp` (3× `hx-on:htmx:sse-message`, 2× `hx-on::after-*`, 1× `hx-on::before-request`, 2× `hx-vals="js:..."`) with equivalent `addEventListener` and `htmx:configRequest` event-listener bindings in the existing inline `<script>` block, which is covered by the `'unsafe-inline'` allowance and does not require `'unsafe-eval'`. Verified end-to-end via headless Chrome: scope panel populates (`agent_count_text: "1 agent"`, `scope_list_child_count: 6`) and `browser_errors` count drops from 1 to 0 in the Synthetic UAT report.
- **Dashboard `agents` map was indexed wrong** — the `/fragments/scope-list` endpoint returns the agent list as a JSON array of `{agent_id, hostname, ...}` objects, but the dashboard's JS expected an object keyed by `agent_id`. `agentDisplayName(agentId)` and `cmdPalette.agentsCache` both silently failed to look up agents by ID. Fix: convert the array to a `{agent_id: agentObj}` map in the new `htmx:afterSwap` handler before assigning to the global `agents` variable.
- Closed M11 in `Release-Candidate.local.MD` risk register: HTMX no longer loaded from external `unpkg.com` CDN.

### Documentation

- `docs/user-manual/security-hardening.md` rewritten with: a six-row CSP/HSTS/X-Frame-Options/X-Content-Type-Options/Referrer-Policy/Permissions-Policy table, the `'unsafe-inline'` rationale, embedded HTMX runtime explanation (replacing the old "unpkg.com allowance" section), `--csp-extra-sources` validation behavior with rejection examples, "Behind a reverse proxy" CSP-intersection note, bandwidth note (~700-900 bytes/response overhead), and a corrected `curl | grep -E` verification example.
- `CLAUDE.md` Authentication & Authorization section updated to document the SOC2-C1 implementation, the local HTMX embedding, and the validated `--csp-extra-sources` flag.
- `docs/test-coverage.md` registers the new `test_security_headers.cpp` and `test_static_js_bundle.cpp` suites.
- `docs/user-manual/rest-api.md` cross-links to the new HTTP Security Response Headers section.
- `docs/user-manual/server-admin.md` documents the new `--csp-extra-sources` flag with rejection grammar.


## [0.7.1] - 2026-04-08

### Added

#### Server
- ClickHouse analytics event drain with CLI configuration parameters
- TAR data warehouse: typed SQLite tables, SQL query engine, rollup aggregation
- Instruction execute API endpoint for programmatic command dispatch
- Rich Grafana dashboard templates for fleet analytics and observability
- Ctrl+K command palette enabled on all dashboard pages
- Default evaluation credentials (`admin/administrator`, `user/useroperator`) documented with change-immediately warning

#### Infrastructure
- Enterprise readiness plan for SOC 2 compliance and first customer preparation
- Enterprise installers: DEB and RPM packages with systemd integration
- Pre-release QA pipeline with release workflow artifact validation
- Docker UAT environment with dep-cached builds and automated tests
- Windows UAT environment with Prometheus + Grafana observability stack
- Puppeteer synthetic UAT tests for end-to-end browser validation
- Pre-populated CI Docker images for faster build times
- Self-hosted runner infrastructure (Linux, Windows)
- NuGet binary cache as fallback for vcpkg package caching
- 3 new governance agents: compliance-officer, SRE, enterprise-readiness
- `scripts/docker-release.sh` — local Docker build + push script with `--dry-run` and `--build-only` flags

### Changed

#### Networking — Port Standardization
- **Port 50051 is now the universal agent door** — server listens on 50051 in standalone mode, gateway listens on 50051 in scaled deployments. Agents always connect to `<host>:50051` regardless of topology.
- Gateway agent-facing port changed from 50061 → 50051 (all configs, compose files, scripts, docs)
- Stale port 50054 references corrected to 50051 across 25 files
- Standalone Docker Compose (`docker-compose.yml`) simplified — server + agent only, no gateway required
- Gateway Docker Compose (`docker-compose.full-uat.yml`) updated for gateway-mode server deployment

#### Docker
- Server Dockerfile defaults to zero-arg startup: `--listen 0.0.0.0:50051 --no-tls --no-https --web-address 0.0.0.0 --web-port 8080 --config /var/lib/yuzu/yuzu-server.cfg`
- Gateway Dockerfile upgraded from Erlang/OTP 27 to 28 (pinned digest)
- Gateway Dockerfile exposes health port 8081
- Agent Docker image removed from release pipeline (use native installers instead)
- Multi-arch Docker builds removed (linux/amd64 only; macOS agent uses native installer)

#### Build & CI
- Release workflow gateway build upgraded from OTP 27 to OTP 28

### Fixed

#### Security — CRITICAL
- **SIGBUS crash in SQLite stores under concurrent HTTP load (#329)** — all 30 stores migrated from `sqlite3_open()` to `sqlite3_open_v2()` with `SQLITE_OPEN_FULLMUTEX`, enabling SQLite's serialized threading mode per-connection. Runtime `sqlite3_threadsafe()` guard added at server and agent startup. WAL mode and `busy_timeout` pragma consistency enforced across all stores.

#### Security — MEDIUM
- XSS, error information leakage, and missing SQLite pragmas (governance findings)
- MCP thread-safety race conditions identified and fixed via ThreadSanitizer
- CEL list index undefined behavior on out-of-bounds access

#### Server
- Gateway command forwarding: IPv6 port conflict resolution and retry logic
- ClickHouse analytics drain connection and ingest reliability
- Enter key form submission fixed on all dashboard pages
- Patch manager test crash on Windows

#### Build & CI
- macOS CI upgraded to macos-15 (Xcode 16) with `clock_cast` and CTAD compatibility fixes
- Clang upgraded 18 → 19 with CoreFoundation linkage and `from_chars` portability fixes
- ARM64 cross-compile: pkg-config path resolution for vcpkg
- Windows: migrated to `x64-windows-static-md` vcpkg triplet, static gRPC/abseil linkage fixes (LNK2005/LNK2019)
- Windows system libraries migrated to `#pragma comment(lib)` for build reliability
- LTO disabled for problematic configurations (Linux x64 self-hosted, Clang 19 release)
- Apple Clang: deduction guide for `ScopeExit`, `execvpe` platform guard, `environ` linkage
- CI concurrency: per-SHA group to prevent self-cancellation
- InnoSetup plugin paths corrected for Windows installer builds
- Linux ARM64 cross-compile removed from CI (no ARM64 runner available)

## [0.7.0] - 2026-03-30

### Added

#### Gateway
- Gateway defaults moved to own port range (5006x) — server, gateway, and agent can now run on the same box without port overrides
  - Agent-facing gRPC: 50051 → 50061
  - Management gRPC: 50052/50053 → 50063
  - Health HTTP: 8080 → 8081 (consistent across dev and prod configs)
- UAT enrollment token automatically saved to `/tmp/yuzu-uat/enrollment-token` for CT suite consumption

#### Server
- Semantic YAML syntax highlighting in the Instructions editor preview pane
  - `type: question` renders green, `type: action` orange, `approval: required` red, `concurrency: single/serial` yellow
  - Color legend now matches actual preview output
- YAML editor value color changed from near-blue (#a5d6ff) to gray-white (#c9d1d9) for clearer key/value contrast

#### Infrastructure
- Linux UAT script (`scripts/linux-start-UAT.sh`) with full server-gateway-agent stack, 6 automated connectivity and command round-trip tests
- `real_upstream_SUITE` CT suite auto-reads enrollment token from UAT environment (no manual token setup needed)

### Fixed
- YAML editor preview now triggers on paste events (changed HTMX trigger from `keyup` to `input` for cross-browser compatibility with Safari/context-menu paste)
- Stale database directories no longer break session authentication on server restart (UAT script wipes state on each run)
- Help command display and result table clearing on HTMX dashboard
- Enrollment token `max_uses` increased from 10 to 1000 to support CT suite test runs

## [0.6.0] - 2026-03-28

### Changed (Architecture — God Object Decomposition)

- **server.cpp decomposed from 11,437 to 4,411 LOC** — ServerImpl is now a slim composition root
- 24 new files extracted (9,008 LOC total), each independently compilable and testable
- Route modules use callback-injection pattern: `register_routes(httplib::Server&, AuthFn, PermFn, AuditFn, ...stores...)`
- Extracted route modules: `auth_routes`, `settings_routes`, `compliance_routes`, `workflow_routes`, `notification_routes`, `webhook_routes`, `discovery_routes`
- Extracted inner classes: `agent_registry`, `agent_service_impl`, `gateway_service_impl`, `event_bus`
- `InstructionDbPool` RAII wrapper replaces raw `sqlite3*` pointer for shared instruction DB (fixes G3-ARCH-T2-002)
- `route_types.hpp` provides shared `AuthFn`/`PermFn`/`AuditFn` callback type aliases
- `AgentServiceImpl` mutable members moved from public to private
- Governance findings G3-ARCH-001, G3-ARCH-T2-001, G3-ARCH-T2-002 marked FIXED in code review register

### Fixed
- Scoped API tokens with null `TagStore` now return 503 instead of silently granting access
- `InstructionDbPool` member declaration order corrected — destroyed after all consumers

### Added
- Wave 8: Release hardening (schema migrations, env var config, rate limiting, log rotation, health endpoints)
- MCP (Model Context Protocol) server embedded at `/mcp/v1/` with JSON-RPC 2.0 transport
- 22 read-only MCP tools: list_agents, get_agent_details, query_audit_log, list_definitions, get_definition, query_responses, aggregate_responses, query_inventory, list_inventory_tables, get_agent_inventory, get_tags, search_agents_by_tag, list_policies, get_compliance_summary, get_fleet_compliance, list_management_groups, get_execution_status, list_executions, list_schedules, validate_scope, preview_scope_targets, list_pending_approvals
- 3 MCP resources: yuzu://server/health, yuzu://compliance/fleet, yuzu://audit/recent
- 4 MCP prompts: fleet_overview, investigate_agent, compliance_report, audit_investigation
- Three-tier MCP authorization model (readonly, operator, supervised) enforced before RBAC
- MCP token support via existing API token system with mandatory expiration (max 90 days)
- `--mcp-disable` kill switch and `--mcp-read-only` mode CLI flags (+ YUZU_MCP_DISABLE / YUZU_MCP_READ_ONLY env vars)
- Audit trail integration for all MCP tool calls with `mcp_tool` field on AuditEvent
- MCP unit tests covering JSON-RPC parsing, tier policy, token integration, and store interactions

### Changed (Capability Audit — 2026-03-26)

- Capability map audited against codebase: 32 capabilities marked "not started" or "partial" were already implemented
- Corrected total from 96/142 (68%) to **150/184 (82%)**
- Updated per-domain summary counts and progress bars
- Plugin coverage matrix expanded from 29 to 44 entries with all plugin categories

#### Capabilities confirmed implemented (previously marked not started)
- **Network:** WiFi scanning (4.6), Wake-on-LAN (4.7), ARP subnet discovery (4.10)
- **User/Session:** Primary user determination (6.2), local group membership (6.3), connection history (6.4), active sessions (6.5)
- **Patch Management:** Deployment orchestration (8.3), per-device status tracking (8.4), metadata retrieval (8.5), fleet compliance summary (8.7)
- **Security:** Device quarantine with whitelist (9.6), IOC checking (9.7), certificate inventory (9.8), quarantine status tracking (9.9)
- **File System:** ACL/permissions inspection (10.7), Authenticode verification (10.8), find-by-hash (10.14)
- **Inventory:** Table enumeration (15.3)
- **Auth:** Management-group-scoped roles (18.4), AD/Entra integration via Graph API (18.6)
- **Device Mgmt:** Hierarchical management groups (19.4), device discovery (19.5), custom properties (19.6), deployment jobs (19.7)
- **Notifications:** System notifications (21.3), webhook event subscriptions (21.4)
- **Infrastructure:** Product packs with Ed25519 signing (22.8)

#### Capabilities upgraded from partial to done
- **Platform Configuration (22.4):** RuntimeConfigStore with safe-key whitelist, no-restart updates
- **Gateway / Scale-Out (22.5):** Full Erlang/OTP gateway with circuit breaker, heartbeat batching, health endpoints
- **REST API (24.3):** Versioned `/api/v1/` prefix, 70+ endpoints, OpenAPI spec, CORS allowlist
- **Data Export (24.5):** CSV and JSON export endpoints with Content-Disposition headers

#### Capabilities upgraded from not started to partial
- **Reboot Management (8.6):** `reboot_if_needed` flag on patch deployments (no scheduled reboot workflow yet)
- **System Health Monitoring (22.1):** /livez, /readyz probes + Prometheus metrics (no CPU/memory/queue monitoring yet)

### Added (Governance — 2026-03-28)
- 4 governance review agents: happy-path, unhappy-path, consistency-auditor, chaos-injector
- 7-gate governance process (expanded from 5 gates) with mandatory correctness & resilience analysis
- REST API v1 documentation for 25 previously undocumented endpoints (inventory, execution statistics, device tokens, software deployment, license management, topology, fleet statistics, file retrieval, OpenAPI spec)
- Agent reconnect loop with exponential backoff (1s to 5min) on registration or stream failure
- Semver downgrade protection in OTA updater — rejects older/equal versions
- Per-plugin KV namespace isolation — `PluginContextImpl` with correct `plugin_name` per plugin

### Fixed (Full Governance Review — ~380 findings across 492 files)

#### Security — CRITICAL (5 fixed)
- OIDC JWT signature verification via JWKS — forged ID tokens were previously accepted
- 4 SQLite stores had mutexes declared but never locked (tag, discovery, instruction, deployment)

#### Security — HIGH (18 fixed)
- Replaced `std::regex` with RE2 in CEL `.matches()` and scope `MATCHES` operator (ReDoS)
- CEL evaluation wall-clock timeout (prevents infinite loops in policy evaluation)
- 11 SQLite stores gained shared_mutex protection for thread-safe concurrent access
- RBAC permission cache to reduce per-request SQL query amplification
- API token IDs extended from 12-char to 24-char hex (96-bit collision resistance)
- MCP kill switch now evaluated at runtime, not just startup
- ApprovalManager TOCTOU fixed with mutex + atomic WHERE on concurrent approve/reject
- MCP read_only_mode captured by reference for runtime toggle support
- Prometheus histogram `observe()` fixed — was double-counting across all bucket boundaries
- Agent double plugin shutdown prevented on normal exit
- Stagger/delay capped at 5min each to prevent thread pool worker exhaustion

#### Security — MEDIUM (25 fixed)
- Minimum password length enforced (12 characters)
- Expired sessions opportunistically reaped
- Token generation switched from mt19937_64 to CSPRNG (RAND_bytes)
- Security response headers added (X-Frame-Options, HSTS, X-Content-Type-Options)
- CSRF protection via Origin header validation
- RBAC `set_permission` validates effect as "allow" or "deny"
- OIDC pending challenges capped at 1000 entries with expiry cleanup
- MCP `/health` resource now requires RBAC check
- Dead CORS helper removed (was reflecting arbitrary Origin)
- Execution statistics limit clamped to 1000
- CEL recursion depth reduced from 64 to 16; string concatenation capped at 64 KiB
- Unknown characters in CEL lexer return Error token instead of silent skip
- Scope engine NOT recursion protected with DepthGuard
- Response/audit store cleanup threads wrapped in proper mutex locks
- Fleet compliance cache writes corrected from shared_lock to unique_lock
- Non-thread-safe static RNGs made thread_local
- Deleted user sessions now invalidated; session role updated on role change
- Offline agents get 24hr staleness TTL on compliance status
- MCP automation gets separate rate limit bucket from dashboard
- Approval workflow: 7-day TTL and 1000 pending cap
- CEL unresolved variables produce tri-state (true/false/error) instead of silent false

#### Agent & Plugins (10 fixed)
- `SecureZeroMemory` on CNG + CAPI intermediate key blobs after cert store export
- Symlink rejection before plugin dlopen
- OTA updater download size capped at 512 MiB
- Content distribution staging directory set to owner-only permissions
- Hash re-verification before executing staged content
- HTTP client SSRF protection extended to CGNAT (100.64/10) and benchmarking (198.18/15) ranges
- HTTP client response body capped at 100 MiB
- `script_exec` output capped at 16 MiB; `setsid()` + `kill(-pid, SIGKILL)` for process group cleanup
- `script_exec` child environment sanitized (PATH, HOME, USER, LANG, LC_ALL, TERM, TZ only)
- Certificate plugin command injection fixed: hex-only thumbprint validation, safe path checks, temp file for PEM parsing

#### Gateway
- 5 dialyzer warnings resolved (ctx dependency, contract violations, dead code)
- gpb bumped 4.21.2 → 4.21.7 for OTP 28 compatibility
- Gateway proto synced from canonical (added stagger_seconds, delay_seconds)

#### Documentation
- REST API v1 now 100% documented (was 48% undocumented)
- Full governance review document with cross-tier finding register
- Erlang gateway build pitfalls documented in CLAUDE.md

### Fixed (RC Sprint — 52 findings resolved)

#### Security (CRITICAL + HIGH)
- Gateway now uses TLS for upstream gRPC connections (was plaintext)
- Gateway health/readiness endpoints (`/healthz`, gRPC Health Check)
- Gateway circuit breaker with exponential backoff for upstream failures
- AnalyticsEventStore thread safety — mutex protection on query methods
- Proto codegen reproducibility — protoc version validation
- Web UI binds to `127.0.0.1` by default (was `0.0.0.0`)
- HTTPS enabled by default — operators must provide cert/key or use `--no-https`
- `/metrics` requires authentication for remote access (localhost exempt, `--metrics-no-auth` override)
- Private key file permission validation on Unix (refuses group/others-readable)
- Certificate hot-reload with PEM validation, cert/key match, and permission checks
- CORS headers on all `/api/` endpoints via `set_post_routing_handler`

#### Server
- REST API unit test suite (previously 0 tests for 1,355 LOC, 31+ endpoints)
- JSON error envelope on all error responses: `{"error":{"code":N,"message":"..."},"meta":{"api_version":"v1"}}`
- Health probe contract: `/livez` and `/readyz` return `{"status":"..."}`

#### Gateway
- Command duration metrics (was hard-coded to 0)
- Backpressure alerting for agent send buffer
- grpcbox dependency pinned
- Graceful shutdown with in-flight command draining
- .appup files for hot code upgrades

#### Build & Packaging
- Binary signing for Windows (Authenticode) and macOS (codesign + notarization)
- Sanitizer CI jobs (ASan+UBSan, TSan)
- Release workflow artifact validation with SHA256 checksums
- deb/rpm package integration
- Docker health checks in all 3 Dockerfiles
- Docker base images pinned to sha256 digests
- buf lint + breaking change CI job for proto compatibility

#### Agent & Plugins
- Agent UUID generation uses CSPRNG (RAND_bytes/BCryptGenRandom, was Mersenne Twister)
- Plugin ABI runtime version check — sdk_version field, ABI v3
- OIDC client secret moved to Authorization: Basic header (RFC 6749 §2.3.1)

#### Build Hardening
- Compiler hardening flags: `_FORTIFY_SOURCE=2`, `-fstack-protector-strong`, full RELRO, PIE
- MSVC `/DYNAMICBASE /HIGHENTROPYVA /NXCOMPAT` for ASLR + DEP

#### Documentation
- macOS x64 limitation documented in README and user manual
- cliff.toml added for git-cliff changelog automation

## [0.1.0] - 2026-03-21

### Added

#### Server
- HTMX-based web dashboard with dark theme, role-based context bar, command palette
- REST API v1 with CORS support and OpenAPI documentation (133+ endpoints)
- Server-side response persistence with filtering, pagination, and aggregation (SQLite)
- Audit trail system with structured JSON events and configurable retention
- Device tagging system with hierarchical scope expression engine (AND/OR/NOT/LIKE/IN)
- Instruction engine: YAML-defined definitions, sets, scheduling, approval workflows
- Workflow primitives (if, foreach, retry) for multi-step instruction chains
- Policy engine with CEL-like compliance expressions and fleet compliance dashboard
- Granular RBAC with 6 roles, 14 securable types, per-operation permissions
- Management groups for hierarchical device grouping and access scoping
- OIDC SSO integration (tested with Microsoft Entra ID)
- Token-based API authentication (Bearer and X-Yuzu-Token)
- System notifications (in-app) and event subscriptions (webhooks with HMAC-SHA256)
- Product packs with Ed25519 signature verification for bundled YAML distribution
- Active Directory / Entra ID integration via Microsoft Graph API
- Agent deployment jobs and patch deployment workflow orchestration
- Device discovery (subnet scanning with ARP + ping sweep)
- Custom properties on devices with schema validation
- Runtime configuration API with safe key whitelist
- Inventory table enumeration and item lookup
- NVD CVE feed sync with vulnerability matching
- ClickHouse and JSONL analytics event drains
- Prometheus /metrics endpoint with fleet health gauges and request histograms
- CSV and JSON data export
- HTTPS for web dashboard with HTTP→HTTPS redirect
- Error code taxonomy (1xxx-4xxx)
- Concurrency enforcement (5 modes)

#### Agent
- Plugin architecture with stable C ABI (version 2, min 1) and C++ CRTP wrapper
- 44 plugins: hardware, network, security, filesystem, registry, WMI, WiFi, WoL, and more
- Trigger engine: interval, file_change, service_status, event_log, registry_change, startup
- Agent-side key-value storage (SQLite-backed, per-plugin namespaces)
- HTTP client plugin (cpp-httplib, no shell) with SSRF protection
- Content staging and execution (CreateProcessW/fork+execvp, no system())
- Desktop user interaction: notifications, questions, surveys, DND mode (Windows)
- Timeline Activity Record (TAR): persistent process tree, network, service, user session tracking
- OTA auto-update with hash verification and rollback
- Bounded thread pool (4-32 workers, 1000 max queue) with output buffering
- Windows certificate store integration (CryptoAPI/CNG)
- Tiered agent enrollment (manual approval, pre-shared tokens, platform trust stubs)

#### Gateway
- Erlang/OTP gateway node with process-per-agent supervision
- Heartbeat buffer (dedicated gen_server, batched upstream flush)
- Consistent hash ring for multi-gateway deployments
- Prometheus metrics endpoint

#### Infrastructure
- Meson + vcpkg build system with cross-platform support (Windows/Linux/macOS/ARM64)
- CI matrix: GCC 13, Clang 18, MSVC, Apple Clang, ARM64 cross-compile
- AddressSanitizer, ThreadSanitizer, and code coverage CI jobs
- Docker deployment (3 multi-stage Dockerfiles, docker-compose.yml)
- Systemd service units with security hardening
- GitHub Actions release workflow (3 platforms, SHA256 checksums)
- 628+ unit test cases across 44 test files

### Security
- 51 security findings identified and fixed (5 CRITICAL, 15 HIGH, 15 MEDIUM, 16 LOW)
- Eliminated 4 CRITICAL command injection vulnerabilities (replaced system()/popen() with safe alternatives)
- mTLS for agent-server gRPC with certificate chain validation
- PBKDF2 password hashing for local authentication
- Command-line redaction in TAR (configurable patterns)
- SSRF protection with private IP range blocking
- Input validation on all REST API endpoints
- Registry sensitive path audit logging
- PRAGMA secure_delete on TAR database
