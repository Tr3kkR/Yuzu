# Upgrading Yuzu

This guide covers upgrading Yuzu components (server, agent, gateway) between versions.

## Version Compatibility

| Server Version | Min Agent Version | Min Gateway Version | Notes |
|---|---|---|---|
| 0.1.x | 0.1.0 | 0.1.0 | Initial release family |
| 0.5.x | 0.5.0 | 0.5.0 | Compiler hardening flags (`-fstack-protector-strong`, `_FORTIFY_SOURCE=2`, full RELRO), config file permission enforcement (`0600` on Unix), SRI integrity attributes on CDN scripts, configurable trigger limit (default 2000), git-derived version strings, chargen instruction definitions. |
| 0.6.x – 0.9.x | same as 0.5.x | same as 0.5.x | No on-disk format changes from 0.5.x; upgrade directly to 0.10.x. |
| 0.10.x | 0.10.0 | 0.10.0 | Server-side schema migration runner wired into every SQLite store. Upgrading from 0.9.x or earlier is data-preserving: the first 0.10.x startup stamps each database at schema v1 and runs a one-time legacy compatibility shim for stores that historically added columns via silent `ALTER TABLE` (`api_token_store`, `instruction_store`, `patch_manager`, `policy_store`, `product_pack_store`, `response_store`). Failed migrations close the affected store's DB handle and are reported via `/readyz` with the failed store name — **check `/readyz`, not `/livez`, to confirm upgrade success**. |
| 0.15.x (next) | 0.12.0 | 0.12.0 | **Fleet visualization three-tier layout + talking sockets + curved tube wires (PR 12).** `/viz/fleet` no longer renders machines on a single flat grid. Cubes now stack into three architectural tiers: frontend on the top Y plane, applications in the middle, databases on the bottom. Classification is heuristic — `classifyTier` reads listener-port hints (DB/web port sets) and process category, priority `db > web > app`. **Behavioural break for automation consumers:** if you scripted SIEM rules or dashboards that filter by "where a cube falls in the canvas", expect tier reassignments after upgrade. The wire change is *additive* — `schema_minor` bumps `3 → 4` with a new optional `local_addr` field on `ListenerSocket` carrying the kernel-reported bind address (server-side bounded at 64 bytes per field). Strict-validating consumers pinned to `schema_minor == 3` should relax their validator to `minimum: 3`. **Loopback-only listeners (`127.x`, `::1`, `[::1]`, `::ffff:127.x`) no longer appear on cube surfaces** — they're not reachable from other instances. **New talking-socket primitive:** each cube grows a ring of cool-blue dots on its BOTTOM face, one per unique outbound `(proto, dst_ip, dst_port)`; hover surfaces `talking: tcp → ip:port`. **Wire geometry changed:** cross-machine connections render as `THREE.TubeGeometry` along a `CubicBezierCurve3` with vertical end-tangents instead of 1px `THREE.Line` — wires drop straight down out of the source cube floor, run mostly-straight through space, and dock straight up into the destination's listener sphere. Screen-scrapers that parsed wire colour or geometry need updating. **Origin RGB `AxesHelper` removed** from the empty-scene scaffold — the three tier planes replace it as the orientation cue. **Default camera reframed** to `(45, 60, 45)` looking at the middle tier (was `(35, 30, 35)` looking at origin); bookmarked URLs will land on the new framing. Bundle size ~70 → ~84 KB. **Known limitation:** databases on non-standard ports (Postgres on 5431, etc.) misclassify as `app` tier unless their process is identified as `database` by the agent's process classifier. **Rolling-upgrade behaviour:** during a staged agent rollout, agents on a build older than the `tar.fleet_snapshot` action have no topology to push and appear in `/viz/fleet` as dimmed `stale` cubes until their agent is upgraded — this is expected, not a regression (previously such agents vanished from the visualization entirely once any agent pushed). **Kill-switch change:** `--viz-disable` now also `503`s the `/viz/fleet` and `/viz/host/<id>` page shells, not just the REST endpoints — an operator who sets the flag no longer sees a half-working page; it also writes a `server.viz_disabled` audit event at boot. **Governance Gate 7 hardening (no operator action required):** parser field caps on all agent-controlled strings, an IP-claim reclaim window so a crashed agent no longer strands its IPs forever, CAP-1 eviction keyed on the server clock, per-entry isolation in gateway `BatchHeartbeat` ingest, and a fix for a registration-replay storm under upstream flapping. **Scope-walking YAML `fromResultSet:` DSL (PR-E).** Policies whose `spec.scope:` used a `selector:` mapping block previously stored an empty scope (matched all devices — the selector was silently ignored). Existing rows are not migrated, but **re-creating or re-importing** such a policy after upgrade applies the selector as a real predicate and may narrow targeting — review the intended scope before re-import. Inline flow-mapping scope (`scope: {fromResultSet: x}`) is now rejected; use the block form. Result-set aliases referenced from `fromResultSet:` must be drawn from the `[A-Za-z0-9_.:*-]` charset (no spaces/quotes). **Inventory freshness gauge now server-clock-stamped (#1685).** `yuzu_inventory_stale_agents` keys on the server's receipt time, not the agent-supplied `collected_at`. A one-time migration (v3) at first 0.15.x startup clamps any `inventory_state` row whose `last_seen`/`first_seen` was stamped from a future-skewed agent clock back down to now. **Operator-visible:** if any agents had future-skewed clocks, the gauge may show a one-time *increase* post-upgrade as previously-hidden endpoints re-enter the staleness window with a fresh ~48h grace — genuinely active agents fall back out within two daily sync cycles; this is the intended security correction, not an incident. No operator action required (the `YuzuInventoryStaleAgents` alert ships disabled). **Rollback note:** downgrading the server below 0.15.x after v3 has run is data-safe (schema unchanged) but new inventory syncs revert to stamping `last_seen` from agent time, silently re-opening the clock-skew gap for those rows. **DEX application performance over time (opt-in).** New per-app, per-version CPU/working-set trend views (DEX → Performance → "Application performance over time"; REST `/api/v1/dex/perf/{apps,app,group}` + the `list_dex_perf_apps`/`get_dex_app_perf`/`get_dex_group_app_perf` MCP tools; per-device drill `GET /api/v1/dex/devices/{id}/app-perf`). **No action is required to upgrade, but the views are EMPTY until you opt in:** per-application sampling ships **off by default** (`procperf_enabled=false`) because it is usage-class telemetry (works-council-relevant). Enable `procperf_enabled=true` on the target devices via `tar.configure` (and leave the daily-sync master switch `--inventory-disable` unset). Data appears **after the first completed UTC midnight** on each opted-in device (the agent ships a daily summary, not immediately), and the trends lengthen as days accumulate (fleet ≤180 days, group ≤31 days). A freshly-enrolled or non-opted-in device shows an honest empty state ("no application performance history yet"), not a bug. The per-device drill is also reachable from a dashboard panel on the `/device` DEX lens ("Application performance over time" — same retained data, no live query, no `Execute` permission; no upgrade action needed). The per-device drill is behavioural PII — scoped + audited (`dex.device.app_perf.view`, fail-closed); the fleet and group aggregates suppress any app/version on fewer than 10 devices to a count only (no singling-out). **Response/execution reads fail closed on a corrupt RBAC store (#1634, partial).** The response readers (`query_responses` + `aggregate_responses` MCP tools, `GET /api/v1/executions/{id}/visualization`, `GET /api/responses/{id}` / `/aggregate` / `/export`) route through a per-agent management-group filter. **The only operator-visible change in this release** is fail-closed behavior under a **corrupt/load-failed `rbac.db`**: these surfaces now return zero rows (the legacy `/api/responses/{id}/aggregate` returns `503`) instead of exposing the whole fleet via the legacy read fallback. **Not yet changed:** under normal RBAC operation these reads are **not** management-group-scoped — a holder of global `Response:Read` still sees all agents' responses (the filter is inert under the current global gate; the gate change that makes scoping effective is tracked under #1634). RBAC explicitly disabled is unchanged. No operator action required. **MCP agentic write surface + A2 discovery + A4 error-shape (R2, #289 / #1794).** Five MCP write tools (`set_tag`/`delete_tag`/`approve_request`/`reject_request`/`quarantine_device`) ship with a ticket-then-recall approval flow, plus the `/api/v1/discover/*` discovery family. The approvals store gains additive `consumed_at` + `consumed_by` columns (auto-migrated at first startup; no operator action). **Breaking wire-shape change:** many `/api/v1` error bodies that were previously `{"error":"<string>"}` are now the nested A4 object `{"error":{"code","message","correlation_id",…}}` — a REST client that read `error` as a *string* must migrate to `error.code` / `error.message` (see `rest-api.md` §Error envelope). The MCP write surface is gated behind the existing tier model + a maker-checker approval workflow; audit `mcp.<tool>` covers every write. **NVD CVE-store schema migration (v1→v2) + full CPE version-range matching.** The server-side NVD store is reshaped on first startup (flat `cve` → normalized `cve` + `cve_match`); `/api/nvd/match` now evaluates real CPE version ranges. **Operator-visible on upgrade:** (a) the migration **drops and rebuilds the local CVE mirror** — vulnerability-matching coverage is reduced until the next NVD sync completes (rate-limited; up to a few hours without an API key), self-healing and logged with a warning at migration time; (b) `GET /api/nvd/status` `total_cves` now counts **distinct CVEs** (was one row per affected product) so it reads **lower** after upgrade even once fully synced, and near-zero during the rebuild window — **expected, not data loss**. Any SIEM/dashboard alerting on the `total_cves` magnitude should be re-baselined. No config change or action required. **NVD CVE sync now actually runs (was dormant).** A `rate_limit()` integer overflow meant the server-side NVD sync slept ~292 years before its first request, so it never populated on any prior deployment (`/api/nvd/status` `total_cves` stayed at the built-in seed). It now runs on startup. **Operator-visible:** (a) the server makes **new outbound HTTPS requests to `services.nvd.nist.gov`** — restricted-egress / air-gapped deployments that silently never reached it before may now log connection failures (set `--no-nvd-sync` to disable, or `--nvd-proxy`); (b) `total_cves` grows from the seed as the (keyword-scoped) sync populates. No config change required to benefit. **OIDC JWT signature verification now enforced on the Windows server (#1856/#1782, CRITICAL).** A Windows *server* build previously **skipped OIDC `id_token` signature verification entirely** — accepting forged RS256/384/512 tokens (session minting / account takeover). It now verifies on every platform via the same OpenSSL path. **Operator-visible only if you run a Windows server with OIDC SSO:** verification now genuinely depends on the IdP's JWKS being reachable, so a misconfigured or unreachable `jwks_uri` that the old Windows build *silently tolerated* (by accepting everything) will now cause **all OIDC logins to fail closed**. **Before upgrading a Windows + OIDC deployment**, confirm the server can reach the IdP `jwks_uri` and that system clock skew is within tolerance; if OIDC logins start failing fleet-wide post-upgrade, check JWKS reachability first. Local-password and API-token auth are unaffected; Linux/macOS servers already verified and are unchanged. |
| 0.15.x (next) | 0.12.0 | 0.12.0 | **Fleet visualization three-tier layout + talking sockets + curved tube wires (PR 12).** `/viz/fleet` no longer renders machines on a single flat grid. Cubes now stack into three architectural tiers: frontend on the top Y plane, applications in the middle, databases on the bottom. Classification is heuristic — `classifyTier` reads listener-port hints (DB/web port sets) and process category, priority `db > web > app`. **Behavioural break for automation consumers:** if you scripted SIEM rules or dashboards that filter by "where a cube falls in the canvas", expect tier reassignments after upgrade. The wire change is *additive* — `schema_minor` bumps `3 → 4` with a new optional `local_addr` field on `ListenerSocket` carrying the kernel-reported bind address (server-side bounded at 64 bytes per field). Strict-validating consumers pinned to `schema_minor == 3` should relax their validator to `minimum: 3`. **Loopback-only listeners (`127.x`, `::1`, `[::1]`, `::ffff:127.x`) no longer appear on cube surfaces** — they're not reachable from other instances. **New talking-socket primitive:** each cube grows a ring of cool-blue dots on its BOTTOM face, one per unique outbound `(proto, dst_ip, dst_port)`; hover surfaces `talking: tcp → ip:port`. **Wire geometry changed:** cross-machine connections render as `THREE.TubeGeometry` along a `CubicBezierCurve3` with vertical end-tangents instead of 1px `THREE.Line` — wires drop straight down out of the source cube floor, run mostly-straight through space, and dock straight up into the destination's listener sphere. Screen-scrapers that parsed wire colour or geometry need updating. **Origin RGB `AxesHelper` removed** from the empty-scene scaffold — the three tier planes replace it as the orientation cue. **Default camera reframed** to `(45, 60, 45)` looking at the middle tier (was `(35, 30, 35)` looking at origin); bookmarked URLs will land on the new framing. Bundle size ~70 → ~84 KB. **Known limitation:** databases on non-standard ports (Postgres on 5431, etc.) misclassify as `app` tier unless their process is identified as `database` by the agent's process classifier. **Rolling-upgrade behaviour:** during a staged agent rollout, agents on a build older than the `tar.fleet_snapshot` action have no topology to push and appear in `/viz/fleet` as dimmed `stale` cubes until their agent is upgraded — this is expected, not a regression (previously such agents vanished from the visualization entirely once any agent pushed). **Kill-switch change:** `--viz-disable` now also `503`s the `/viz/fleet` and `/viz/host/<id>` page shells, not just the REST endpoints — an operator who sets the flag no longer sees a half-working page; it also writes a `server.viz_disabled` audit event at boot. **Governance Gate 7 hardening (no operator action required):** parser field caps on all agent-controlled strings, an IP-claim reclaim window so a crashed agent no longer strands its IPs forever, CAP-1 eviction keyed on the server clock, per-entry isolation in gateway `BatchHeartbeat` ingest, and a fix for a registration-replay storm under upstream flapping. **Scope-walking YAML `fromResultSet:` DSL (PR-E).** Policies whose `spec.scope:` used a `selector:` mapping block previously stored an empty scope (matched all devices — the selector was silently ignored). Existing rows are not migrated, but **re-creating or re-importing** such a policy after upgrade applies the selector as a real predicate and may narrow targeting — review the intended scope before re-import. Inline flow-mapping scope (`scope: {fromResultSet: x}`) is now rejected; use the block form. Result-set aliases referenced from `fromResultSet:` must be drawn from the `[A-Za-z0-9_.:*-]` charset (no spaces/quotes). **Inventory freshness gauge now server-clock-stamped (#1685).** `yuzu_inventory_stale_agents` keys on the server's receipt time, not the agent-supplied `collected_at`. A one-time migration (v3) at first 0.15.x startup clamps any `inventory_state` row whose `last_seen`/`first_seen` was stamped from a future-skewed agent clock back down to now. **Operator-visible:** if any agents had future-skewed clocks, the gauge may show a one-time *increase* post-upgrade as previously-hidden endpoints re-enter the staleness window with a fresh ~48h grace — genuinely active agents fall back out within two daily sync cycles; this is the intended security correction, not an incident. No operator action required (the `YuzuInventoryStaleAgents` alert ships disabled). **Rollback note:** downgrading the server below 0.15.x after v3 has run is data-safe (schema unchanged) but new inventory syncs revert to stamping `last_seen` from agent time, silently re-opening the clock-skew gap for those rows. **DEX application performance over time (opt-in).** New per-app, per-version CPU/working-set trend views (DEX → Performance → "Application performance over time"; REST `/api/v1/dex/perf/{apps,app,group}` + the `list_dex_perf_apps`/`get_dex_app_perf`/`get_dex_group_app_perf` MCP tools; per-device drill `GET /api/v1/dex/devices/{id}/app-perf`). **No action is required to upgrade, but the views are EMPTY until you opt in:** per-application sampling ships **off by default** (`procperf_enabled=false`) because it is usage-class telemetry (works-council-relevant). Enable `procperf_enabled=true` on the target devices via `tar.configure` (and leave the daily-sync master switch `--inventory-disable` unset). Data appears **after the first completed UTC midnight** on each opted-in device (the agent ships a daily summary, not immediately), and the trends lengthen as days accumulate (fleet ≤180 days, group ≤31 days). A freshly-enrolled or non-opted-in device shows an honest empty state ("no application performance history yet"), not a bug. The per-device drill is also reachable from a dashboard panel on the `/device` DEX lens ("Application performance over time" — same retained data, no live query, no `Execute` permission; no upgrade action needed). The per-device drill is behavioural PII — scoped + audited (`dex.device.app_perf.view`, fail-closed); the fleet and group aggregates suppress any app/version on fewer than 10 devices to a count only (no singling-out). **Response/execution reads fail closed on a corrupt RBAC store (#1634, partial).** The response readers (`query_responses` + `aggregate_responses` MCP tools, `GET /api/v1/executions/{id}/visualization`, `GET /api/responses/{id}` / `/aggregate` / `/export`) route through a per-agent management-group filter. **The only operator-visible change in this release** is fail-closed behavior under a **corrupt/load-failed `rbac.db`**: these surfaces now return zero rows (the legacy `/api/responses/{id}/aggregate` returns `503`) instead of exposing the whole fleet via the legacy read fallback. **Not yet changed:** under normal RBAC operation these reads are **not** management-group-scoped — a holder of global `Response:Read` still sees all agents' responses (the filter is inert under the current global gate; the gate change that makes scoping effective is tracked under #1634). RBAC explicitly disabled is unchanged. No operator action required. **MCP agentic write surface + A2 discovery + A4 error-shape (R2, #289 / #1794).** Five MCP write tools (`set_tag`/`delete_tag`/`approve_request`/`reject_request`/`quarantine_device`) ship with a ticket-then-recall approval flow, plus the `/api/v1/discover/*` discovery family. The approvals store gains additive `consumed_at` + `consumed_by` columns (auto-migrated at first startup; no operator action). **Breaking wire-shape change:** many `/api/v1` error bodies that were previously `{"error":"<string>"}` are now the nested A4 object `{"error":{"code","message","correlation_id",…}}` — a REST client that read `error` as a *string* must migrate to `error.code` / `error.message` (see `rest-api.md` §Error envelope). The MCP write surface is gated behind the existing tier model + a maker-checker approval workflow; audit `mcp.<tool>` covers every write. **NVD CVE-store schema migration (v1→v2) + full CPE version-range matching.** The server-side NVD store is reshaped on first startup (flat `cve` → normalized `cve` + `cve_match`); `/api/nvd/match` now evaluates real CPE version ranges. **Operator-visible on upgrade:** (a) the migration **drops and rebuilds the local CVE mirror** — vulnerability-matching coverage is reduced until the next NVD sync completes (rate-limited; up to a few hours without an API key), self-healing and logged with a warning at migration time; (b) `GET /api/nvd/status` `total_cves` now counts **distinct CVEs** (was one row per affected product) so it reads **lower** after upgrade even once fully synced, and near-zero during the rebuild window — **expected, not data loss**. Any SIEM/dashboard alerting on the `total_cves` magnitude should be re-baselined. No config change or action required. **NVD CVE sync now actually runs (was dormant).** A `rate_limit()` integer overflow meant the server-side NVD sync slept ~292 years before its first request, so it never populated on any prior deployment (`/api/nvd/status` `total_cves` stayed at the built-in seed). It now runs on startup. **Operator-visible:** (a) the server makes **new outbound HTTPS requests to `services.nvd.nist.gov`** — restricted-egress / air-gapped deployments that silently never reached it before may now log connection failures (set `--no-nvd-sync` to disable, or `--nvd-proxy`); (b) `total_cves` grows from the seed as the sync populates. No config change required to benefit. **NVD sync now builds the FULL CVE catalog (newest-first), not ~20 keywords.** The sync backfills every CVE published within a configurable window — `--nvd-backfill-years` / `YUZU_NVD_BACKFILL_YEARS` (default **8 years**; `0` = full history) — newest-first and **resumable across restarts**, then settles into a periodic last-modified freshness re-check. **Operator-visible:** the server makes sustained HTTPS requests to `services.nvd.nist.gov`, the local NVD DB grows into the hundreds of MB, and `/api/nvd/status` `total_cves` climbs continuously while `backfill_complete` stays `false` until the backfill floor is first reached — `last_sync_time` advances after every successful fetch window and is **not** a completion signal (use the new `backfill_complete` + `backfill_oldest_published` fields, and the `yuzu_nvd_total_cves` / `yuzu_nvd_backfill_complete` metrics, for progress). **`/api/nvd/status` `enabled` semantics corrected:** it now reflects whether sync is configured on, so under `--no-nvd-sync` it reports `enabled:false` (was `true`); a monitor keying on `enabled` to mean "mirror usable" should check `total_cves` instead. The initial backfill is NVD-rate-limited (hours without an `--nvd-api-key`, minutes with one) and resumes where it left off if interrupted. Set `--no-nvd-sync` to disable, `--nvd-proxy` for restricted egress. Product matching stays name-based (vendor-precise CPE identity pending ADR-0018). |
| 0.14.x | 0.12.0 | 0.12.0 | **Fleet visualization intra-cube edges (PR 8).** `/viz/fleet` now draws faint white lines (opacity `0.3`) inside each machine cube connecting process dots that are reciprocal ends of a loopback TCP socket (127.0.0.1 / ::1). Two operator-visible changes: (a) **wire shape** — `/api/v1/viz/fleet/topology` `schema_minor` bumps `1 → 2` and a new optional `dst_pid` field appears on `scope: local` connection edges. Renderers that ignore unknown keys per the contract see no break; strict-validating consumers pinned to `schema_minor == 1` should relax their validator to `minimum: 1`. (b) **dropped unmatched halves** — unpaired Local-scope edges (kernel snapshot race during teardown, agent's 4096-connection cap cutting a partner) are now dropped server-side before serialisation. Integrations counting `connections` array length per machine as a proxy for active IPC pairs should re-baseline after upgrade; the count trends marginally lower. Lines appear only when the host has active loopback flows (e.g. Prometheus scraping node_exporter, a client talking to local Redis / Postgres); a fresh agent with no inter-process loopback shows process dots but no lines — expected, not a regression. |
| 0.13.x | 0.12.0 | 0.12.0 | **Fleet visualization process layer.** `/viz/fleet` now renders interior process dots inside each machine cube, coloured by category (system/browser/database/web/runtime/other) — no operator action required, but operators upgrading from a 0.12.x build will see the dashboard suddenly populated with thousands of small spheres on next page load. Process data was already collected via `tar.fleet_snapshot` since 0.12.x; PR 7 only renders it. To suppress process visibility for specific agents (privacy-sensitive hosts, regulated workloads), set `process_enabled=false` on those agents via `tar.configure` — this also suppresses their dots on the visualization. Hover a dot to see pid/name/user/category; agent-controlled string fields are HTML-escaped and length-clamped before render. Per-cube dot count is soft-capped at 1000 for graceful degradation on heavily-threaded hosts; the cube tooltip still shows the true reported count. |
| 0.12.x | 0.12.0 | 0.12.0 | **Build-time content auto-import.** All YAML files in `content/definitions/` (217 InstructionDefinitions) and `content/packs/` (10 InstructionSets at this version) are now embedded in the server binary and auto-imported on every startup. Existing operator-customised definitions with matching IDs are NEVER overwritten — conflicts are silently skipped. **Behaviour change for upgrades:** definitions that an operator previously DELETED via the REST API or dashboard will reappear after upgrade because the auto-import treats a missing row as "needs creation". To permanently suppress a shipped definition, set `enabled: false` via the dashboard or `PATCH /api/v1/definitions/{id}` rather than DELETE-ing the row. Each auto-import write emits an `audit_events.action="content.bundled_import"` row with `principal=system` so operators can audit which definitions were inserted at boot. **Yuzu dark navy palette + Inter webfont** (visual change every operator sees) and **Apache ECharts chart renderer** (replaces bespoke SVG; same payload contract — no operator migration required) ship in the same release. |

**Rule of thumb:** agents and gateway should be the same minor version as the server, or one minor version behind. The server is always upgraded first.

## ⚠️ Security: rotate `oidc_client_secret` if it was ever set on this install

**Every release up to and including v0.13.0** emitted the OIDC client secret in the clear to three
places, and this upgrade closes all three:

- the **server log**, written verbatim by the startup override pass on **every boot**;
- `GET /api/config`, a route gated only on `Infrastructure:Read`;
- the `config.update` **audit detail** written by `PUT /api/config/:key`, which is durably retained and
  readable by every role seeded `AuditLog:Read` - the seeded `Operator` role among them.

**Breaking for automation:** closing the second path changed a response shape.
`GET /api/config` now reports `"is_set": true|false` for a secret-valued key instead of `value`, so a
client reading `value` for `oidc_client_secret` gets nothing where it previously got the credential.
Full shape and the reason it is not a placeholder:
[`rest-api.md`](rest-api.md#get-apiconfig).

Because the log path fired on every boot, **historical logs** — and anything that ingested them, such
as journald, a Docker log driver, or a SIEM — may still hold the secret in plaintext. Purge or restrict
those as your retention policy allows.

Audit rows written before the upgrade are now redacted when read, so the value stops being disclosed
through that path too. The rows themselves are deliberately left intact: an audit row is compliance
evidence, and rewriting history to conceal a mistake is a worse posture than declining to disclose it.
**So the plaintext remains at rest** in those rows, and a direct database read or a restored backup
still shows it. Do not assume a fixed expiry: `audit_retention_days` defaults to 365, but each prune
pass is capped, and the retention guard deliberately declines a pass after a clock anomaly or a long
outage, so rows can outlive the nominal figure. The secret also remains stored in plaintext
in runtime-config; this fix closes disclosure paths and does not encrypt it at rest (see
`security-hardening.md`, "Current encryption posture").

**Who this affects:** any install where `oidc_client_secret` was ever set through **Settings -> OIDC**
or `PUT /api/config/oidc_client_secret` on an affected release. All three paths above read from
runtime-config, so a secret supplied **only** via `--oidc-client-secret` or `YUZU_OIDC_CLIENT_SECRET`,
and never written through Settings or the API, was not disclosed by *those three paths*.

**That is not the same as "not disclosed".** A secret passed as `--oidc-client-secret` sits in the
process command line, world-readable through `ps` or `/proc/<pid>/cmdline`, and it is typically also in
a systemd unit, a Compose file, or shell history. If you cannot rule those out, rotate anyway.
`YUZU_OIDC_CLIENT_SECRET` is better against other local users — `/proc/<pid>/environ` is owner-only,
unlike `cmdline` — but it is *not* better if the value is written into a Compose file or unit, since
`docker inspect` exposes it to anyone in the `docker` group. Prefer a secrets manager that injects the
environment variable at runtime.

**Before you begin, check you have a local account you can sign in with** — and on
`--auth-mode=sso-only`, that it is the configured break-glass account, MFA-enrolled and armable.
Rotating breaks SSO until Yuzu is re-pointed, and the way back in needs an account that already exists:
break-glass *names* one rather than creating it. On an install with none, the only fallback
[`auth-db-recovery.md`](../ops-runbooks/auth-db-recovery.md) documents is destructive.

**What to do: rotate the client secret at your IdP, and delete the old one.** The upgrade closes the
disclosure paths but **does not change the stored value** — anything that already read it still holds a
working credential, and only the IdP can invalidate it. Most IdPs let you *add* a second client secret
without removing the first; adding one is not a rotation, because the disclosed secret keeps working
until it is deleted.

Deletion does not reach what the secret already bought: access tokens minted with it are signed JWTs
that stay valid until they expire, and IdP sessions can outlast them. Treat revoking those as part of
the same job. Yuzu's own sessions are separate — the IdP cannot reach them — and are held in memory for
at most 8 hours; they end on a restart, or per operator via
`DELETE /api/v1/sessions?username=<name>` (admin, `UserManagement:Write`). **Neither reaches API
tokens**: one minted under a session that used the disclosed secret survives every step above. List
them with `GET /api/v1/tokens` and revoke with `DELETE /api/v1/tokens/{id}`.

Re-pointing Yuzu at the new secret is a configuration task rather than a remediation one: once
everything above is dealt with, SSO failing until you update it is an outage, not a continuing
disclosure. It is also configuration-specific and easy to get subtly wrong, so it is being written up as
a reviewed runbook rather than summarised here. Until that lands, see
[`authentication.md`](authentication.md) ("OIDC Single Sign-On") for the durable and non-durable ways to
configure OIDC.

## Behaviour change: MCP approval-store permanent failures now say don't retry (#2786)

An MCP approval-ticket recall that hits a store fault has always returned `-32603` with a `retry_after_ms` hint. Previously that hint was `5000` (retry after 5 seconds) for every store fault except a never-opened store, including one that was open but failing in a way no amount of retrying clears — SQLite corruption, not-a-database, a read-only filesystem, or a full disk. Those four cases now correctly get `retry_after_ms: null` (the same "escalate to an operator" response a never-opened store gets) instead of the transient retry hint.

**What to do:** if you have automation that blindly retries on `-32603` without checking `retry_after_ms`, it now stops retrying sooner in this specific case — which is the correct behavior (the old retries were futile). If your automation already honors `retry_after_ms` per [invariant A5](../agentic-first-principle.md), no change is needed. See [`mcp.md`](mcp.md) "`-32603`: Approval store unavailable" for the full response-body reference.

## Behaviour change: `mcp.bridge.*` audit rows can now carry `result=failure` (#2487 / #2506)

Audit rows for the MCP progress bridge (`mcp.bridge.done_reap`, `session_dead`, `arming_reaped`, `pin_acked`, `forced_expire`) were previously stamped `result=success` unconditionally, regardless of what actually happened. They now report the real outcome: `result=failure` when a background teardown could not release one of the resources it owns, or when the terminal-frame publish ladder poisoned the session, threw, or was never reached. The `detail` field names which, and no longer asserts a delivery or a poisoning that did not occur.

**What to do:** if you have a SIEM rule, dashboard or evidence query that treats `result` on this verb family as a constant `success` - for example "alert if any `mcp.bridge.*` row is not `success`" - update it before upgrading, or it will fire on legitimate rows. Note also that `failure` here is *self-audited*: a rule that surfaces failure branches by filtering on `denied` will not see these. Filter on `result != "success"` where you need both. `mcp.bridge.cancel` is unaffected and remains `success`.

These rows are background-actor events (`principal=system`), not operator actions, and a `failure` row does **not** mean a client lost a result - executions stay durably fetchable by `execution_id`. See [`audit-log.md`](audit-log.md) for the verb family and [`../ops-runbooks/mcp-bridge-teardown-recovery.md`](../ops-runbooks/mcp-bridge-teardown-recovery.md) for what to do when the paired alert fires.

## Behaviour change: an MCP maintenance failure degrades instead of aborting the server (#2487)

A transient failure in the MCP progress-bridge sweep or the MCP session collector, which runs on the server's maintenance thread, previously escaped that thread and terminated the whole process. It is now contained: the tick is skipped and retried on the next cycle.

**What to do:** be aware this is a genuine trade, not a pure win. The old failure was self-announcing - the process died, your supervisor restarted it, and uptime monitoring saw it. The new one is silent unless you are scraping metrics: a sustained failure means bridge teardown or session collection stops running, live MCP progress can degrade for the remaining life of the process, and `/readyz` will continue to report healthy throughout (MCP session state deliberately does not gate readiness). If you run Prometheus, scrape `yuzu_mcp_bridge_teardown_incomplete_total`, `yuzu_mcp_maintenance_tick_failures_total` and `yuzu_mcp_bridge_records_active`, and load the bundled rules in `docs/prometheus/yuzu-alerts.yml` - they are not applied automatically. If you do not, you will not see this condition at all.

Note this narrows the crash surface rather than closing it: other work on the same maintenance thread remains unguarded, so a sufficiently severe resource exhaustion can still terminate the process from a different call site.

## Behaviour change: `yuzu-agent` no longer restart-loops forever (ADR-0021 rung 7.7a)

The `yuzu-agent` systemd unit now sets `StartLimitIntervalSec=300` + `StartLimitBurst=5` in its `[Unit]` section. Previously the unit was `Restart=always` with no start limit, so an agent that could not stay up restarted every 10 seconds indefinitely. With this change, if the agent exits 5 times within 300 seconds systemd stops retrying and the unit enters `failed`.

This matters because the agent's Guardian engine can now `hard_exit()` when an I/O worker is wedged past a grace period (a permanently wedged watched target, e.g. a dead NFS mount or a hung service query); without the start limit that would be a silent 10-second crash loop.

**What to do:** if you alert on systemd unit state, add `yuzu-agent` entering `failed` to your alerts - it means the agent gave up after a crash loop and the device is now dark, which the old restart-forever behaviour hid. Recover with `systemctl reset-failed yuzu-agent` once the underlying cause (e.g. the wedged mount) is resolved, then `systemctl start yuzu-agent`. The Guardian spark detection path this rung wires is dormant (`--spark-disable` unchanged, legacy detection unaffected), so there is no detection-behaviour change to account for. See also [`server-admin.md`](server-admin.md) "Stopping a wedged agent".

## Behaviour change: a Guardian rule that fails to arm no longer crashes the agent (ADR-0021 rung 7.7b PR-1a)

Independent of the dormant spark path above, the Guardian engine's `apply_rules` (which runs on the **live legacy detection path** regardless of `--spark-disable`) now firewalls a per-rule reconcile failure. Previously, if arming a rule threw - e.g. a `std::thread` creation failure under resource exhaustion, or a `bad_alloc` - the exception escaped onto the agent's dispatch thread and aborted the whole daemon. It now degrades: the failure is caught and counted, the rule stays persisted, and the agent keeps running. The `full_sync` teardown and the dispatch boundary carry the same firewall.

One behaviour to be aware of: when a rule fails to arm, the agent **holds its policy generation** (does not report "caught up") so the server's heartbeat reconcile keeps re-pushing and retrying - a transient resource failure self-heals within a reconcile cycle. A rule that fails **persistently** (rare - it requires a durable resource condition, not bad rule content) keeps the agent behind-generation and drives a re-push each reconcile interval; this is visible in the server's `guaranteed_state.reconcile` audit rows for that agent. No operator action is required.

## Behaviour change: Guardian event-drop metric narrows to genuine collisions (ADR-0021 rung 7.7b PR-Sv)

Guardian event ingest now distinguishes an idempotent **redelivery** (a matching-fields `event_id` PK conflict — the durable agent lifecycle journal's expected crash-durable, duplicate-tolerant, bounded-retry redelivery, not a guarantee of eventual delivery - an un-acked record that ages out of the 7-day retention window is a rare, counted loss, not silent) from a genuine **collision** (a mismatched-payload conflict — a forged-id pre-claim or an `event_seq_` reset carrying a different event). The eviction-loss counter (`yuzu.guardian_journal_evicted_no_send_evidence`) is in-memory only and resets on agent restart, and today has no dashboard, REST, or MCP surface at all, per-agent or fleet-wide - see [Reconnect replay traffic](guaranteed-state.md#reconnect-replay-traffic-durable-lifecycle-journal) for the full picture (tracked under #2298). **A high redelivery count after an agent outage or reconnect storm is expected and is NOT a loss signal** - genuine loss shows up only as a mismatched collision (`..._events_dropped_total`) or the rare journal-eviction case above. Three operator-visible consequences:

- **`yuzu_server_guardian_events_dropped_total` narrows.** It now counts only mismatched collisions; benign redeliveries move to the new `yuzu_server_guardian_events_redelivered_total`. **If you deployed the bundled `YuzuGuardianEventsDropped` rule from `docs/prometheus/yuzu-alerts.yml`** (a copy, not something the server auto-upgrades) **with your own or a wider threshold tuned to reconnect churn, re-apply the updated rule (now `> 5/1h`)** — otherwise your old threshold's baseline drops post-upgrade and the alert goes **silently dead**, not loud, on a CC7.3 signal.
- **A metric series steps down, and a new one appears.** Any Grafana panel/PromQL against `..._events_dropped_total` shows a step-change *drop* at upgrade with no incident — **expected, not data loss**; watch total PK-conflict volume via the new `..._events_redelivered_total` series. A third new series, `..._events_ingest_errors_total` (with a bundled `YuzuGuardianIngestErrors` alert), counts operational ingest faults so a persistent fault can't silently hide collisions.
- **DEX de-duplication on reconnect.** Before this change, a redelivered event re-ran the DEX blast-radius + alert observers on every agent reconnect. If you saw duplicate/false blast-radius sightings or duplicate routed alerts during reconnect storms, those stop now — an intentional fix, not a regression.

**Verify:** post-upgrade, confirm the new series are present and re-tune any custom copy of the drop alert:

```promql
yuzu_server_guardian_events_redelivered_total   # should appear and climb on reconnects
yuzu_server_guardian_events_ingest_errors_total # should stay at 0 in a healthy fleet
```

No config or data migration is required.

## Behaviour change: dashboard YAML Save is schema-aware and stricter (#1993)

`POST /api/instructions/yaml` (the New Definition panel's Save endpoint) and
`POST /api/instructions/validate-yaml` now share one schema-aware parser that
accepts the canonical nested InstructionDefinition schema (`metadata.id`,
`spec.execution.plugin/action` — the documented format every shipped
definition uses), which the old substring scanner rejected. In exchange, the
endpoint is stricter about malformed input:

**Who this affects:** automation POSTing YAML to `/api/instructions/yaml`
that (a) omits `apiVersion:`/`kind:` lines, (b) relied on a stray `name:`
substring anywhere in the document being picked up as the definition name,
(c) re-creates a definition whose `metadata.id` already exists (now **409**
with a denied audit row instead of a silent second copy under a generated
id), (d) supplies an explicit id outside `[A-Za-z0-9._-]{1,128}`, or
(e) pastes multi-document (`---`-separated) files (now rejected; save one
definition at a time). Interactive panel users are unaffected — the
structured form's output stays accepted.

**Verify:** re-run your automation against a test server; failures surface as
specific per-field messages (e.g. `Missing metadata.id (or metadata.name)
field`), and successful saves now emit `instruction.create` /
`instruction.update` audit rows.

## ⚠️ Reserved on-behalf-of headers rejected + `principal_class` metric label (ADR-1005 Phase 1)

Two operator-visible changes ship together:

**1. Reserved headers now 403.** Five header names are reserved and rejected
on every HTTP endpoint before authentication (`On-Behalf-Of`,
`X-On-Behalf-Of`, `X-Yuzu-On-Behalf-Of`, `X-Yuzu-Delegated-Operator`,
`X-Yuzu-Delegation-Artifact`, case-insensitive; the equivalent gRPC metadata
keys cause the call to be cancelled). Nothing previously consumed these
headers, so a correctly-built integration is unaffected — but **pre-flight
check any proxy, service mesh, or SSO gateway in front of Yuzu**: some
API-gateway products stamp an on-behalf-of/OBO convention header on every
upstream request (the name is Microsoft's Entra OBO term), which would 403
**all** REST/MCP/dashboard traffic after upgrade. Health probes (`/livez`,
`/readyz`, `/health`, `/api/health`) are exempt, so the pod stays in rotation
— a green probe with a 100% 403 rate is the signature (see
`docs/operations/troubleshooting.md`). Rejections are visible in
`yuzu_onbehalf_rejected_total` and throttled `[ADR-1005]` warn lines.

**2. `yuzu_http_requests_total` gains a `principal_class` label**
(`human`/`agent`/`none`; `engine` reserved). This is a Prometheus
series-identity change on a long-shipped metric: old `{method,status}` series
freeze at upgrade and new `{method,status,principal_class}` series start at
zero. Plain selector queries and `sum by (method, status)` keep working;
re-baseline any dashboard or alert that matches the exact label set or joins
on series identity.

## ⚠️ Breaking: account lockout is ON by default

This release adds account lockout for failed **local-password** logins (SOC 2
CC6.3) and it is **active by default** (`--auth-lockout-threshold=5`,
`--auth-lockout-window-secs=900`) **on any deployment that runs with a
persistent auth database** — i.e. one started with `--data-dir`.

> **⚠️ `--data-dir` is required.** Lockout state lives in the persistent
> `auth.db`, which only exists when the server is started with `--data-dir`.
> The shipped **container images and compose files** pass `--data-dir
> /var/lib/yuzu`, so lockout genuinely is on by default there. The
> **systemd/.deb** unit now also passes `--data-dir /var/lib/yuzu` (added in
> this release) — but if you run a **custom invocation** without `--data-dir`,
> the server falls back to in-memory auth and lockout (and session persistence)
> is silently **off**. The server logs a loud startup `WARN` in that state.
> Set `--data-dir` to make the control active.
>
> **Superseded by the AuthDB→Postgres migration (see below).** Lockout state
> now lives in **Postgres** (`users.failed_login_count` / `locked_until`), not
> `auth.db`. It is active whenever `--postgres-dsn` (or `YUZU_POSTGRES_DSN`) is
> set — which the server now **requires to boot at all** (no SQLite fallback) —
> and `--data-dir` no longer gates it. Read the `--data-dir` requirement above
> as historical, for pre-migration builds only.

No further config change is required to opt in — a deployment that already runs
with `--postgres-dsn` gains the behavior the instant you start the new build.

What changes on upgrade:

- After **5 consecutive failed `POST /login` attempts** a local-password account
  is locked for **15 minutes**. While locked, every login attempt — *including
  one with the correct password* — returns the **same generic 401 as a bad
  password** (no `Retry-After`, no "you are locked" message; this is deliberate,
  to avoid a username-enumeration / lock-state oracle).
- The lock **auto-expires** after the window — it is never permanent — and a
  user who waits it out regains a full attempt budget.
- Scope is **local-password only**. SSO/OIDC logins (throttled by your IdP) and
  API/automation tokens are **unaffected** — no automation breakage.

**Highest-risk targets** on upgrade: shared or service accounts that log in with
a password, and any password-rotation / monitoring automation that may submit a
stale password in a loop — these can now lock themselves out where previously
nothing happened.

**Before upgrading, do ONE of:**

1. Accept the default (recommended for most) — it closes a real
   credential-stuffing surface. Make sure operators know the recovery path
   below.
2. Raise the threshold if you also rate-limit at the network layer
   (NIST 800-63B §5.2.2 suggests ≥10): `--auth-lockout-threshold=10`.
3. Disable it (not recommended; constitutes a deviation from the CC6.3 hardened
   baseline): `--auth-lockout-threshold=0` (the server logs a startup `WARN`).

**Recovery if an account is locked out:**

- Another admin can clear it immediately:
  `POST /api/v1/users/{username}/unlock` (`UserManagement:Write`, MFA step-up).
- Or wait out the window (default 15 min).
- **Single-admin deployments:** there is no self-service unlock for the *only*
  admin (the unlock endpoint requires a second privileged principal), so either
  wait out the window or use the offline recovery procedure in
  `docs/ops-runbooks/auth-db-recovery.md` § Account lockout recovery. That
  runbook is now Postgres-native throughout: its fallback clears
  `failed_login_count` / `locked_until` with `psql "$YUZU_POSTGRES_DSN"`
  against `auth.users`, which is exactly the sole-admin case. It writes no
  audit row, so record it in your change-management system.

## Behaviour change: operator/API tags now beat agent self-report (#1411)

An agent's self-reported tags (`scopable_tags`, synced on every Register) can no
longer overwrite an operator- or API-set tag for the same `(agent_id, key)` — the
operator/API value is now authoritative. This closes a path where a rogue or
misconfigured agent could self-assign into an operator-declared benchmark cohort.

**Who this affects:** only an operator who *deliberately* relied on agent-reported
values winning over an operator/API-set tag for the same key. After upgrade those
agent values stop overriding — silently (no error, no log line); an affected device
simply drops out of the cohort the operator-set value defines.

**Verify:** audit the `source` column — `GET /api/v1/tags?agent_id=<id>` shows whether
each key is `server`- (operator/API) or `agent`-sourced.

**Remediate:** if an agent-reported value was the *intended* one, re-set it explicitly
via the REST API or MCP `set_tag` (which writes `source=server`, authoritative). Keys
the agent reports that the operator never set are unaffected.

## Behaviour change: MCP approval-gated calls use ticket-then-recall (-32006) (#289)

Supervised-tier MCP tokens that attempt an approval-gated operation (e.g. `delete_tag`,
`quarantine_device`) now run through a **ticket-then-recall** approval flow. The first
call returns JSON-RPC error `-32006` (`ApprovalRequired`) whose `error.data` carries an
`approval_id` and a `status_url` (`GET /api/v1/approvals/{id}`). After a second principal
approves the ticket, the caller re-invokes the same tool with the `approval_id` and the
operation executes (the ticket is consumed exactly once, args-bound, replay-rejected).

> An earlier development iteration returned `-32004` (`TierDenied`) for these operations
> because the approval re-dispatch path was unbuilt. That intermediate behaviour **never
> shipped in a release** and is fully superseded by the flow above — there is no `-32004`
> approval-denial in the released product.

**Who this affects:** any MCP client that matched on the approval-gated denial. Match
`-32006` and read `error.data.approval_id` / `status_url` to drive the approval workflow;
`operator`-tier executions are auto-approved and are unaffected. On the REST transport an
approval-gated operation by an MCP-tier token is denied (there is no JSON-RPC ticket
channel on REST) — use the MCP `/mcp/v1/` flow or the dashboard.

Three review-round hardenings in the same release (PR #1796):

- **Supervised REST quarantine is now mirror-denied.** `POST /api/v1/quarantine` and
  `DELETE /api/v1/quarantine/{agent_id}` return `403` for a supervised-tier token. An
  operation-mapping mismatch previously let a supervised token quarantine via REST with
  **no approval** — if any automation relied on that, it was riding the bug; route it
  through the MCP `quarantine_device` ticket flow or use a non-tiered token.
- **Approved-but-unconsumed approval tickets expire after 7 days** (measured from the
  review). An approved ticket is a live one-time capability; it now ages out on the same
  window as unreviewed pending requests. Recalling an expired ticket returns the standard
  "approval was expired" denial — submit a fresh request.
- **`consumed_by` traceability column** (additive, auto-migrated): the approvals store
  records WHO recalled each consumed ticket alongside the existing `consumed_at`
  (SOC 2 CC7.2 evidence chain: `submitted_by` → `reviewed_by` → `consumed_by`).

## Behaviour change: `POST /api/v1/tokens` now honors `mcp_tier`

The token-mint endpoint now applies the `mcp_tier` field from the request body
(`readonly` / `operator` / `supervised`). Previous releases **silently dropped**
it: a token requested with an `mcp_tier` was stored **tier-empty** (RBAC-deferred),
which means it was *over-privileged* relative to the tier the operator intended —
a `readonly` request behaved as a full RBAC-scoped token, not a read-only MCP
token. The endpoint also now validates at mint time: an unrecognised tier, or a
tiered/service-scoped token whose `expires_at` is missing or more than 90 days
out, returns `400` (previous releases returned a misleading `503`).

**Who this affects:** any operator who minted an MCP token via `POST /api/v1/tokens`
**before** this upgrade and relied on the `mcp_tier` to constrain it. Those tokens
are still tier-empty and therefore broader than the requested tier.

**Remediate:** **rotate any pre-upgrade `mcp_tier` tokens** — revoke the old token
(`DELETE /api/v1/tokens/{id}`) and re-mint it; the new token stores the tier and is
constrained as intended. Tokens minted with no `mcp_tier` are unaffected.

**Additive (no operator action required):** the `discover_plugins` discovery response
(REST `GET /api/v1/discover/plugins` and the MCP tool) is now `version: 2` — it adds an
inline `parameter_schema` per action (where a published `InstructionDefinition` exists and
the caller holds `InstructionDefinition:Read`) plus a top-level `actions_enriched_with_schema`
count. The change is purely additive; any client that pinned `version == 1` should relax the
check to a minimum (`>= 1`).

## ⚠️ Breaking: API and MCP bearer tokens are invalidated on upgrade (ApiTokenStore → Postgres, ADR-0030)

`ApiTokenStore` — the store backing every `Authorization: Bearer` API token and
every MCP token — moves from SQLite (`api-tokens.db`) to the server's PostgreSQL
substrate in this release (engine-principals PR 4.1; ADR-0006/ADR-0030). This is
a **fresh-start cutover with no data migration**: the new server creates an empty
Postgres `api_token_store.api_tokens` table and **never reads the old
`api-tokens.db`**, so every API/MCP token minted before the upgrade stops working
the instant the new server starts. Interactive cookie-session login (dashboard,
OIDC/SAML SSO) is **not** affected — only bearer tokens.

The rationale for no backfill (convention with every prior server-store migration,
plus the token store holds only verify-only hashes) is in ADR-0030.

**Who this affects:** every external automation consumer that authenticates with an
API or MCP bearer token — CI/CD scripts, SIEM/webhook pollers, cron jobs, MCP
clients. Because it is a fresh-start cutover, **all of them break at once** at the
moment of upgrade; there is no rolling/staged token continuity.

**Remediate:** after upgrading, **re-mint every API/MCP bearer token** (`POST
/api/v1/tokens`) and update the credential wherever it is stored (CI secrets, cron
configs, MCP client configs). Plan the upgrade in a **maintenance window** and
**notify automation/integration owners in advance** so a batch of `401`s across
every integration is expected, not a surprise incident.

**Diagnostic:** if the legacy `api-tokens.db` is still on disk, the server logs
`[auth] Legacy SQLite api-tokens.db found at … — API/MCP tokens now live in
PostgreSQL and any prior tokens were INVALIDATED by the migration (ADR-0030)` at
boot. The old file is inert (never read again) and can be removed once you have
re-minted; it contains only token hashes + metadata, no plaintext secret.

**Multi-instance note:** the Postgres substrate now permits running multiple server
replicas against one database. Token *validation* uses a per-process 60-second
cache, so a token revoked on one replica may remain accepted on another replica for
up to that window — see ADR-0030 for the tracked hardening.

## ⚠️ Breaking: `engine:` namespace reservation — server refuses to start on a pre-existing collision (engine principals PR 4.2)

This release introduces the **engine principal** class — a distinct identity
class for autonomous/agentic callers, stored in the new `EnginePrincipalStore`
and resolved through RBAC/`ApiTokenStore` (design doc §3.1/§3.3). To make that
resolution unambiguous, the `engine:` prefix is now a **reserved namespace**
for both local usernames (`users.username`) and local RBAC group names
(`groups.name`).

**Pre-upgrade collision check** (mirrors the plugin-trust-bundle filename
collision check above). At boot, the server now scans for any pre-existing
`engine:`-prefixed local user or local RBAC group and **refuses to start** if
it finds one — silently coexisting with (or being shadowed by) a real engine
principal is not an acceptable outcome, so this fails closed rather than
booting into an ambiguous state (decision log #3). Before upgrading, run
against both stores.

> **Superseded by the RbacStore → PostgreSQL migration (ADR-0041):** the
> per-node `sqlite3 rbac.db` query below is a HISTORICAL artifact from the era
> when local RBAC groups were SQLite. RBAC config is now a **single shared
> PostgreSQL** `rbac_store` schema, so run **one** `psql` query, **not**
> per-node `sqlite3`. Both queries below target Postgres:

```bash
# Local users — Postgres.
psql "$YUZU_POSTGRES_DSN" -c \
  "SELECT username FROM auth.users WHERE username LIKE 'engine:%';"

# Local RBAC groups — PostgreSQL (shared; one query, not per-node — ADR-0041).
psql "$YUZU_POSTGRES_DSN" -c \
  "SELECT name FROM rbac_store.groups WHERE source = 'local' AND name LIKE 'engine:%';"
```

If either query returns rows, rename or remove those users/groups **before**
upgrading — the new server will not boot until the collision is cleared (or,
if the boot-time collision scan itself fails, e.g. a mid-scan database error,
the server also fails closed rather than guessing). See
[`docs/ops-runbooks/engine-principal-store-recovery.md`](../ops-runbooks/engine-principal-store-recovery.md)
for the full recovery procedure if you hit this at boot.

**Scope of this release:** PR 4.2 ships the engine-principal store, RBAC
resolution, and attribution plumbing only — there is **no operator-facing
surface yet** (no dashboard/REST CRUD for minting or managing engine
principals). That ships in PR 4.3.

## ⚠️ Breaking: `--mfa-enforcement` now enforces

Releases before this one accepted `--mfa-enforcement=admin-only` and
`--mfa-enforcement=required` but treated them as **no-ops** (the parser
accepted the value for forward-compat and the server emitted a startup
`WARN`). **This release makes them enforce.** If you staged the flag based
on that prior documentation, enforcement goes live the instant you start
the new build.

What changes on upgrade if the flag is set to `admin-only` or `required`:

- An **un-enrolled** user covered by the mode can no longer log in directly.
  `POST /login` returns a 202 `mfa_enrollment_required` challenge and the
  user must complete TOTP enrollment (scan QR → enter first code at
  `POST /login/mfa/enroll`) before a session is minted. This is a no-lockout
  bootstrap, **but** it requires the user to enroll at their next login.
- The startup log line for non-default modes changes from `WARN` (no-op) to
  `INFO` (enforcement active).
- An operator can no longer disable their own MFA while the mode protects
  their role.

**Before upgrading with the flag set, do ONE of:**

1. **Recommended:** leave the flag at `optional`, upgrade, have all affected
   users enroll (Settings → Multi-Factor Authentication), *then* set
   `admin-only`/`required` and restart. or
2. Upgrade with the flag set and accept that affected un-enrolled users will
   be walked through enrollment on their next login.

**SSO / OIDC pre-flight (required reading if you use SSO):** under
`required` (and `admin-only` for admin SSO users), OIDC sessions are
MFA-gated by the IdP's `amr` claim — an SSO login the IdP did **not** MFA
is blocked from high-risk endpoints (it must re-authenticate via SSO),
symmetric with a local user being forced to enrol. Yuzu cannot mint a
second factor for an external identity, so **before enabling
`required`/`admin-only` with SSO you MUST verify your IdP asserts an `amr`
claim containing a recognized MFA method** (Entra: `mfa`; others:
`otp`/`hwk`/etc., RFC 8176). If it does not, affected SSO users will be
unable to reach high-risk endpoints — recoverable by restarting in
`optional` (see `docs/ops-runbooks/auth-db-recovery.md` § "Locked out by MFA
enforcement misconfiguration"; that runbook is now Postgres-native throughout).
Under `optional`, no IdP `amr` configuration is required (SSO sessions pass
the gate).

**Single-admin deployments:** do not first-boot a fresh single-admin
deployment straight into `required`. Enroll the admin under `optional` first,
then switch. If you do start with `required`, the admin must complete
login-time enrollment within `--mfa-login-pending-secs` (default 120s); if
the token expires, restart with `optional`, log in, enroll, then re-enable.

**Recovery if you get locked out** (IdP doesn't assert `amr`, or the sole
admin can't enroll): restart the server with `--mfa-enforcement=optional`
(this re-seeds the in-memory config), log in, resolve enrollment, then
re-enable. See `docs/ops-runbooks/auth-db-recovery.md` — that runbook is now
Postgres-native throughout, so both the restart procedure above and its SQL
steps apply as written to a Postgres-backed AuthDB.

## Hardened auth mode (`--auth-mode=sso-only`) — opt-in (SOC 2 CC6.3/CC6.6)

**No operator action on upgrade.** Existing deployments default to
`--auth-mode=standard` and behave exactly as before. This release adds the
*option* to disable local-password login fleet-wide so only OIDC SSO can mint a
session.

If you intend to enable `sso-only`, do this **first** — the server **fails
closed (non-zero exit, refuses to serve)** otherwise:

1. Configure OIDC (`--oidc-issuer` + the related flags) and confirm SSO works in
   `standard` mode. `sso-only` without `--oidc-issuer` refuses to start (it would
   lock every operator out).
2. (Recommended) Create a single break-glass local account and **enroll MFA on
   it** (Settings → Multi-Factor Authentication). Point `--break-glass-user` at
   it. `sso-only` refuses to start if the named break-glass user doesn't exist or
   has no MFA enrolled — a break-glass account must carry a second factor.
3. Restart with `--auth-mode=sso-only`. Local-password login is now rejected for
   everyone except the break-glass account, and only **while armed**.

**Breaking the glass (IdP outage).** The break-glass account is dormant until
armed out-of-band on the server host: `yuzu-server --break-glass-arm
--break-glass-user <name> --config … --data-dir … --postgres-dsn …` arms it for
`--break-glass-window-secs` (default 24 h, auto-expiring). It still requires the
account's MFA at login. Since the AuthDB→Postgres migration this one-shot opens
the **Postgres** auth store, so `--postgres-dsn` (or `YUZU_POSTGRES_DSN`) is
**required** — point it at the same database the server uses; without it the
command fails closed with "requires the Postgres auth store" and does nothing.
`--data-dir` is still needed for the audit record. Full runbook:
`docs/ops-runbooks/auth-db-recovery.md` § Break-glass arm (that runbook is now
Postgres-native throughout).

**Migration.** `break_glass_armed_until` is a nullable column on `auth.users`.
It arrived as SQLite `auth.db` migration v4, but the AuthDB→Postgres cutover
folded every historical migration into the born-on-PG schema, which starts at
**v1** — there is no v4 to apply and no rollback-past-v4 question. See the
AuthDB→Postgres section above for the (fresh-start, no-backfill) upgrade
contract that replaces it.

## ⚠️ Breaking: server generates default TLS certificates on first boot (v0.13.0)

Before v0.13.0 the server **refused to start** without operator-provided certs
(or `--no-tls`/`--no-https`). From v0.13.0, when a TLS surface has no certs the
server **auto-generates a per-install ECDSA CA + leaf certs** on first boot and
serves encrypted with no operator action.

Impact by prior configuration:

| Prior startup flags | After upgrade |
|---|---|
| `--cert`/`--key` (+ `--https-cert`/`--https-key`) supplied | No change — operator certs always win; defaults are never generated for a supplied surface. |
| `--no-tls --no-https` (plaintext dev) | No change — both surfaces disabled; no certs generated. |
| `--no-tls` only (HTTPS previously errored without certs) | **HTTPS now serves an auto-generated default cert** instead of failing. The agent surface stays plaintext. |
| No cert flags (previously refused to start) | **Now starts, encrypted, on default certs**, with a loud banner. |

What to expect / do:

- **Browsers show an untrusted-issuer warning** for the dashboard until you trust
  the per-install CA (`<ca-dir>/default-ca.pem`, default `/etc/yuzu/certs`) or
  replace the cert with `--https-cert`/`--https-key`. The connection is encrypted;
  only issuer verification is missing.
- **Agents:** while on default certs the agent listener is encrypted but does
  **not require** client certs (per-agent mTLS arrives in a later release).
  Agents that previously connected over plaintext must switch to TLS — point them
  at the CA with `--ca-cert <ca-dir>/default-ca.pem`.
- **To keep the legacy refuse-to-start behaviour**, pass `--no-default-certs`.
- **Back up `<ca-dir>/default-ca.key` (0600) and the new `ca.db`** in `--data-dir`
  — losing the CA key forces a full fleet re-enrollment.
- Relocate the cert directory with `--ca-dir` (e.g. a dedicated container volume).

## ⚠️ Behaviour change: response history resets on Postgres cutover (ADR-0039)

`ResponseStore` (agentic command/instruction results — the executions drawer
and TAR read source) moves from the SQLite `responses.db` file to the server's
PostgreSQL substrate in this release (ADR-0006 Wave 1, schema `response_store`).
Like the `ApiTokenStore` and AuthDB cutovers, this is a **fresh-start cutover
with no data migration** — response results are expendable, TTL'd telemetry
(ADR-0009 skippable backfill), so the legacy `responses.db` is **never read** on
upgrade.

**What happens on first PG boot:**
- The server logs a one-time `response history reset on Postgres cutover`
  warning.
- Executions-drawer and TAR views for commands issued **before** the cutover
  are empty; results for commands issued after are unaffected and refill
  immediately as agents report.
- No operator action required. To preserve pre-cutover response history,
  export it from the old `responses.db` before upgrading (see
  `docs/user-manual/response-store.md` → periodic exports).

**Also in this release:** non-UTF-8 bytes in a plugin's output/error (which
the old SQLite `TEXT` column tolerated but PostgreSQL `TEXT` rejects) are now
replaced with the Unicode replacement character (U+FFFD) at ingest — the
response row is still stored and still renders, defanged, rather than being
dropped (governance #1593). Retention moved from an hourly background thread
to a clock-guarded, capped reap on the maintenance tick (no operator-visible
behaviour change beyond the same 90-day default).

## RBAC store moves to PostgreSQL — config preserved by mandatory backfill (RbacStore → Postgres, ADR-0041)

`RbacStore` — the authorization substrate holding **role definitions,
role→permission grants, principal→role assignments, RBAC groups + membership,
and the global `rbac_enabled` flag** — moves from the SQLite `rbac.db` file to
the server's PostgreSQL substrate in this release (ADR-0041, Wave 2.1), schema
`rbac_store`. **Unlike the AuthDB/ScimStore cutover below, this is NOT a
fresh-start reset — your RBAC configuration is preserved by a mandatory
backfill.** No new flag or environment variable is added (it reuses the shared
server `PgPool`).

**What happens on first PG boot:**

- A one-time, idempotent, **fail-closed** backfill copies every role, grant,
  group, and membership out of the legacy `rbac.db` into `rbac_store`. Operator
  edits to seeded permissions are preserved — including a revoked built-in
  default (`remove_permission`), which is **deleted** (matching legacy
  exactly) rather than silently restored. The revocation itself is recorded
  separately as reseed-suppression bookkeeping, so the deleted row cannot be
  silently re-seeded on the very next restart, without ever becoming a real
  authorization fact (never a `deny` row an unrelated role could be vetoed
  by). This is the same mechanism `remove_permission()` itself uses for a
  revocation made after upgrading. The
  backfill reconciles counts (roles + grants + groups + members) and **refuses
  the completion marker on any shortfall** — if it cannot complete, the server
  **fails the boot closed** and retries on the next start (it never boots on a
  partial authorization config).
- **CRITICAL — the `rbac_enabled` flag is preserved and read-back-verified.** It
  is migrated first, so an operator who had RBAC **enabled** stays enabled after
  upgrade. (Losing this flag would silently boot the fleet RBAC-**off**, making
  every confined operator fleet-wide-authorized — the migration is engineered
  specifically to prevent that.) An unreadable **or non-canonical** durable
  flag also refuses boot — a value other than exactly `true`/`false` is
  rejected both by a schema-level constraint on write and by a strict parse on
  every read, rather than being silently treated as `false`. That schema-level
  constraint is itself a migration, so on the (unexpected) case of a
  non-canonical value already sitting in the row from before this upgrade — a
  hand-edit or a bug on an old release — the migration's own `ALTER TABLE ...
  ADD CONSTRAINT` fails validation and the server refuses to boot with a raw
  Postgres `23514 check_violation` rather than the app's own message. Recovery:
  connect directly and correct the row (`UPDATE rbac_store.rbac_meta SET value
  = 'false' WHERE key = 'rbac_enabled'`, or `'true'` if RBAC was genuinely
  enabled) before restarting.
- The legacy `rbac.db` file is **moved aside** only after the backfill is
  verified — but a once-failed move-aside can leave it in place, and in that
  case it **is** read again: every subsequent boot that still finds it
  fingerprints its content (a SHA-256 content hash, stamped alongside the
  completion marker) and re-verifies it against what was actually migrated,
  refusing to boot rather than silently trust a marker this replica's own
  file was never proven part of. This closes a multi-replica anti-pattern
  (a fileless replica could otherwise foreclose migration for a sibling
  genuinely holding the real file) but means an operator on a mixed-fleet
  first boot or a retained legacy file may see one of a few distinct
  refusals — `docs/ops-runbooks/rbac-store-backfill-recovery.md` covers each
  and how to tell them apart. **On a multi-replica upgrade, boot the replica
  holding the real, authoritative `rbac.db` first** — this lets the actual
  migration land before any fileless/stale sibling replica boots and stamps a
  sourceless marker, avoiding the refusals above entirely rather than having
  to recover from one. A verified-match boot also retries the
  move-aside automatically, so a once-failed rename does not need manual
  cleanup once the underlying problem (e.g. a permissions issue) is fixed.
  Keep the moved-aside copy until you have confirmed RBAC behaves as
  expected, then remove it.

**What to expect / do:**

- **Widened startup budget on large RBAC datasets.** A fleet with many custom
  roles / grants / groups will see a longer first-boot while the backfill
  runs; this is one-time. Budget for it in the maintenance window and avoid
  killing the server mid-backfill if you can help it — it is **not** resumable
  (unlike AuditStore's larger, cursor-resumed migration): a killed boot is
  data-safe (nothing is left half-migrated), but the next boot restarts the
  whole backfill from scratch rather than continuing where it left off, so an
  interruption costs you the full window again.
- **Routine (not just one-time) boot-time cost, every deployment.** Every
  server boot's `seed_defaults()` reseed now coordinates its built-in-default
  grants against any concurrent revoke via a cluster-wide advisory lock
  (closes a rare Postgres race where a revoked permission could otherwise be
  silently resurrected mid-boot). This adds a small, ordinarily negligible
  amount of boot time on every restart, not just first boot — but if you
  bulk-restart or scale out MANY replicas of the same RBAC-on-Postgres
  deployment **simultaneously**, their reseed passes serialize against each
  other and against any in-flight legacy backfill, which can add up at large
  replica counts. Prefer a rolling (not all-at-once) restart/redeploy
  strategy for this reason, as you likely already do for other reasons.
- **Reads now FAIL CLOSED (deny-on-degrade).** A degraded or unreachable
  `rbac_store` (pool-acquire timeout, query error) now **denies** authorization
  rather than falling through to an allow — this **closes** the prior
  "corrupt `rbac.db` fails open" behavior. Watch the new
  `yuzu_server_rbac_read_degrade_total` metric and the `YuzuRbacReadDegraded`
  alert after upgrade; a degrade denies authz fleet-wide.
- **Multi-replica staleness caveat.** If you run multiple server replicas, a
  role/permission/enabled-flag change on one replica is typically visible on
  the others within a **~1 s** window under normal conditions (a durable
  generation token, refreshed at most once per second) — this is a target the
  refresh loop aims for, not a hard guarantee: a replica whose refresh is
  genuinely slow (pool saturation, a Postgres blip) can observe staleness
  beyond the window, now counted via a `stale_beyond_accepted_bound` degrade
  rather than silently assumed. A revoke is therefore not strictly
  instantaneous cross-replica — well inside the fleet's existing
  revocation-latency envelope (heartbeat + session/token TTLs measured in
  minutes), and an accepted residual risk (`LISTEN/NOTIFY` is the named
  follow-up).
- **Bounded stale-serve, then fail-fast deny, under backend degradation —
  two independent mechanisms.** An already-cached authorization decision
  keeps answering from cache for up to a **~5 s** bound past the last
  confirmed-good refresh, regardless of anything else failing (bounded
  staleness for continuity) — a brief blip does not deny cached decisions
  immediately. Separately, a fail-fast breaker governs *pool access, not
  cache validity*: once it sees **2 consecutive** pool-acquire/query
  failures, any check that is not already a cache hit denies immediately
  rather than blocking on the acquire budget first, and it stops touching
  the pool for a ~1 s cooldown between recovery probes. **"How fast" depends
  on the degradation mode:** pool exhaustion (no connection available) trips
  the breaker in well under a second (2 × the 250 ms acquire budget); a
  query blocked on a PostgreSQL-side lock (e.g. a migration touching
  `rbac_meta`) instead inherits `PgPool`'s `lock_timeout` (10 s default) per
  attempt — measured ~18.5 s for 2 such attempts against a live held lock
  (#3016). Both converge on the same fail-closed deny, just not at the same
  speed. Net effect on a sustained outage: previously-seen decisions keep
  answering for up to ~5 s regardless of breaker state; new/uncached
  decisions deny once the breaker trips, at whichever of the two speeds
  above applies; once the 5 s bound elapses, every check denies until the
  backend recovers. **Not just a sustained outage — flapping (repeated
  short degrade/recover cycles, the shape a managed-Postgres failover or a
  brief network partition actually produces) is arguably the worse case for
  this mechanism, not a milder one:** the breaker's closed-state failure
  streak resets to 0 on a single success, so each recovery — even one that
  lasts only as long as the next probe — reopens the breaker back to FULL
  concurrency rather than easing back in; a Postgres backend that is
  flapping rather than cleanly down can therefore see repeated full-
  concurrency retry bursts instead of a single clean trip-and-stay-open
  (tracked for a half-open concurrency cap, see #3016). **Blast radius while
  open is bounded by the shared connection pool, not the breaker itself:**
  every authz check on this replica denies while the breaker is open —
  including checks against securable types that have nothing to do with
  whatever degraded — because the breaker gates pool ACCESS, shared across
  every `RbacStore` caller on the process, not per-query health. **No
  operator action is needed for recovery** — the breaker self-heals: once a
  probe succeeds (the next attempt after its ~1 s cooldown), it closes
  again automatically and normal service resumes. Watch
  `yuzu_server_rbac_breaker_open` (gauge) and
  `yuzu_server_rbac_authz_check_seconds` (histogram) after upgrade.
- **If you alert on the raw `generation_refresh_failed` reason label,
  re-baseline after upgrade.** This release splits what was previously a
  single reason into two: `generation_refresh_failed` (still denying —
  unchanged meaning) and the new `generation_refresh_failed_within_bound`
  (a refresh failure that landed inside the bounded ~5 s stale-serve window
  above and denied nobody). A custom alert or dashboard built against the
  pre-upgrade single-reason series may see its rate drop after upgrade —
  that is the intended effect of the split, not a sign the underlying
  condition stopped occurring. The shipped `YuzuRbacReadDegraded` alert
  already accounts for this (see `docs/prometheus/yuzu-alerts.yml`); a
  custom query built directly against `yuzu_server_rbac_read_degrade_total`
  should be reviewed against the reason list in `metrics.md` before relying
  on it post-upgrade.
- **Shutdown grace bounds now stack; raise your orchestrator's termination
  grace period, but understand what that does and does not buy you.** A
  graceful `SIGTERM` walks several independently-bounded waits in sequence —
  up to 30 s draining in-flight executions, up to 5 s waiting on the
  NVD-sync background thread, up to 15 s waiting on the HTTP listener thread
  (#2703 Gate 7 item 2), and up to 5 s on the gRPC shutdown deadline — which
  can stack to **~55 s** in the worst case if more than one is genuinely
  wedged. Kubernetes' default `terminationGracePeriodSeconds` is **30**, so
  a pod with slow-draining work in more than one of those stages can be
  `SIGKILL`ed mid-sequence before the server finishes its own bounded
  teardown. If you run under Kubernetes (or any orchestrator with a similar
  default), raise the grace period to comfortably exceed ~55 s rather than
  relying on the platform default. **Two things a longer grace period does
  NOT fix:** (1) the 30 s drain window re-queries `execution_tracker_` for
  `running` executions on each of its one-second iterations — so it also
  picks up work that starts mid-drain, not just what was already running
  when `SIGTERM` arrived — but it never stops the HTTP listener from
  ACCEPTING new requests during that window, so a request that lands late in
  the drain is not bounded by the ~55 s figure at all; raising the grace
  period does not close this gap, because the gap is about admission, not
  about how long the drain itself waits. (2) if the 15 s HTTP-listener bound IS exceeded, the server
  force-exits (`std::_Exit(1)`) on its OWN internal schedule, independent of
  whatever grace period the orchestrator was configured with — a longer
  external grace period only prevents the orchestrator from `SIGKILL`ing
  the process BEFORE that internal bound fires; it cannot prevent or delay
  the force-exit itself, and the force-exit skips
  `offload_target_store_->flush_all()` and any other still-pending teardown
  the same way a `SIGKILL` would. If the 15 s HTTP-listener bound is
  exceeded, the diagnostic line is written directly to **stderr** (not
  through the configured logger) before the process force-exits — an
  async-signal-safety requirement, since `stop()` runs synchronously inside
  the SIGTERM handler (see #3007). If you rely on the log file or a
  structured log sink rather than captured stderr, this one line will not
  appear there; check container/service stderr capture for it instead.
- Confirm on first boot: the backfill completion log line, no `RbacStore`
  open/migrate errors, and that RBAC is still enabled if you had enabled it
  (Settings → RBAC, or check that confined operators still see only their
  scoped fleet).

See `docs/auth-architecture.md` § "RbacStore — the authorization substrate" and
[ADR-0041](../adr/0041-rbac-store-postgres-migration.md) for the full design.

## ⚠️ Breaking: local accounts + MFA enrolments reset (AuthDB/ScimStore → Postgres, ADR-0006)

`AuthDB` (local user accounts, MFA enrolments, enrollment tokens) and
`ScimStore` (SCIM-provisioned users/groups) move from the SQLite `auth.db`
file to the server's PostgreSQL substrate in this release (ADR-0006 Wave 3),
schemas `auth` and `scim_store`. Like the earlier `ApiTokenStore` cutover,
this is a **fresh-start cutover with no data migration**: on first boot
against a Postgres database whose `auth.users` table is empty, the server
seeds exactly the config-file admin and **never reads the old `auth.db`**.
Sessions are (and always were) in-memory-only, so they are unaffected beyond
the usual "log in again after a restart."

**Who this affects:** every local-password operator, everyone with TOTP MFA
enrolled, and every SCIM-provisioned user/group. This is **not** limited to
password auth — SSO/OIDC/SAML session establishment itself is unaffected
(the IdP still asserts identity), but any RBAC role/group mapping recorded
only in the old `auth.db` local-account tables is gone until re-established.

**What happens on first PG boot:**

- Prior local accounts, roles, and MFA enrolments that existed only in the
  pre-cutover `auth.db` are gone. The server re-seeds a single admin account
  from `yuzu-server.cfg` (the same config-as-seed-only behavior as the
  original v0.12.0 AuthDB bring-up).
- SCIM-provisioned users/groups are **not** lost long-term: `ScimStore`
  self-heals on the IdP's next scheduled sync cycle, which re-provisions
  everything from the IdP as the source of truth. There is a gap between
  first PG boot and that next sync during which SCIM-provisioned users
  cannot log in.
- Anyone with TOTP MFA enrolled must **re-enrol** — the encrypted
  `mfa_totp_secret` blob and enrolment state do not carry over.
- The server logs a loud boot warning: **`AUTH DATA RESET ON POSTGRES
  CUTOVER`**. If you do not see this line on first boot against the new
  Postgres database, the cutover did not happen as expected — investigate
  before assuming accounts are intact.

**Remediate:**

1. Plan the upgrade in a maintenance window and notify every local-password
   operator, MFA-enrolled user, and SCIM administrator in advance — expect a
   batch of failed logins immediately after cutover, not a surprise incident.
2. After upgrade, log in as the re-seeded admin using the credentials in
   `yuzu-server.cfg`.
3. Re-create any other local operator accounts that are not SCIM-provisioned
   (Settings → Users), and have every user re-enrol MFA
   (Settings → Multi-Factor Authentication).
4. For SCIM-provisioned users, either wait for the next scheduled IdP sync or
   trigger one manually if your SCIM setup supports it; do not manually
   re-create SCIM-managed users (they will be re-provisioned).
5. Confirm the `AUTH DATA RESET ON POSTGRES CUTOVER` line appeared in the
   server log at the boot where the cutover ran.

**Not affected:** the `PgTestTemplate` config, engine principals (a separate
store), and API/MCP bearer tokens (already migrated to Postgres in an
earlier release, see "⚠️ Breaking: API and MCP bearer tokens are invalidated
on upgrade" above — this AuthDB/ScimStore cutover is independent of that one
and does not re-invalidate already-reissued tokens).

See `docs/auth-architecture.md` § "AuthDB — persistent authentication store"
for the full design rationale, and
[`docs/ops-runbooks/auth-db-recovery.md`](../ops-runbooks/auth-db-recovery.md)
for lockout/break-glass recovery — that runbook has been rewritten for this
cutover and is Postgres-native throughout (`psql "$YUZU_POSTGRES_DSN"` against
the `auth` schema).

## Notification feed moves to PostgreSQL — history preserved (NotificationStore, ADR-0046)

`NotificationStore` — the dashboard toast/badge feed — moves from the SQLite
`notifications.db` file to the server's PostgreSQL substrate in this release
(ADR-0006 Wave 2, ADR-0046), schema `notification_store`. **Unread/dismissed
state is preserved by a mandatory backfill, not a fresh start.** No new flag
or environment variable is added (it reuses the shared server `PgPool`).

**What happens on first PG boot:**

- A one-time, idempotent, **fail-closed** backfill copies every notification
  out of the legacy `notifications.db` into `notification_store`, preserving
  ids (so any bookmarked/linked notification id stays valid) and read/dismissed
  state. The legacy file is moved aside once the backfill is verified.
- **Startup failure mode changed.** Previously, a broken or unreadable
  `notifications.db` degraded only the notification feature — the store ran
  closed and `/api/notifications*` returned 503. **It now fails the whole
  server boot** (matching every other Postgres-migrated store's fail-closed
  contract): if the schema can't open, or the backfill can't complete, the
  server logs `[PG] Refusing to start` and refuses to serve at all. If you
  hit this, the log line names the legacy file and states the remediation:
  repair it, or move it aside to skip the backfill (unread/dismissed history
  in it will **not** carry over if you do).
- **Multi-instance consolidation — boot the authoritative replica first.**
  If you are consolidating multiple previously-independent server instances
  (each with genuinely different local `notifications.db` content) onto one
  shared Postgres for the first time, whichever instance boots first and
  completes the backfill becomes the fleet's sole notification history — every
  other instance's own legacy file will permanently fail closed (a
  holder-side fingerprint mismatch) on every subsequent boot, requiring manual
  reconciliation (move the losing instances' legacy files aside once you've
  confirmed their content is disposable). This is the intended fail-loud
  behavior, not a bug — there is no automated merge across independent legacy
  files. Boot the instance holding the notification history you want to keep
  first, same guidance as the RBAC store migration above.

**Not affected:** `/api/notifications*` request/response behavior is
unchanged — this is a storage-engine swap only, no API change.

## Audit trail migrates to PostgreSQL — history preserved (AuditStore, ADR-0040)

The audit log (`AuditStore`, the SOC 2 evidence chain) moves from the SQLite
`audit.db` file to the server's PostgreSQL substrate in this release (ADR-0006
Wave 1.3), schema `audit_store`. **Unlike the AuthDB/ScimStore and ApiTokenStore
cutovers above, this is NOT a fresh start — audit history is preserved.** Because
the audit trail is SOC 2 evidence retained 365 days, pre-cutover rows are
migrated, not reset.

No new flag or environment variable is introduced: the store reuses the shared
`--postgres-dsn` / `YUZU_POSTGRES_DSN` connection the rest of the server already
requires, and (like every server store) it **fails closed** at boot if Postgres
is unreachable — there is no SQLite fallback.

**What happens on first PG boot:**

- If a legacy `audit.db` is present, the server runs a **one-time, mandatory,
  streamed backfill** of every audit row (in bounded batches, so a multi-GB table
  does not exhaust memory) into `audit_store` before serving. The retention
  horizon (`ttl_expires_at`) and clock-guard state come across too, so retention
  behaviour is preserved exactly. Row counts are reconciled and logged.
- The backfill is **idempotent and resumable** (a `backfill_complete` marker
  gates re-runs; a crash mid-backfill resumes from where it stopped, with no
  duplication and no loss).
- **A failed or partial backfill fails the boot** — the server refuses to serve
  with a knowingly-incomplete evidence chain, logs a loud diagnostic, and
  **retries on the next start**. It does not silently start with a partial trail.
  **The boot log is your primary signal here, not a metric.** The backfill runs
  during server construction, and a failure stops the boot before the HTTP
  listener starts, so `/metrics` is never served on that path and the
  `yuzu_server_audit_backfill_total{result="failed"}` sample is never scraped.
  The metric's `fresh` / `completed` values are observable on a server that came
  up; the shipped `YuzuAuditBackfillFailing` sample rule therefore alerts on the
  *absence* of a success outcome (see `docs/prometheus/yuzu-alerts.yml`), and a
  wedged replica among healthy ones shows up as a down instance rather than on
  that alert. **Silence that rule for the upgrade window if your legacy
  `audit.db` is large enough to make the first boot long** — the server does not
  serve `/metrics` until the backfill finishes, so a healthy multi-hour backfill
  looks exactly like a wedged one from outside. The boot log is what tells them
  apart.
- **The backfill only ever runs against an empty `audit_store` schema or its own
  interrupted copy.** Before resuming, it checks that the audit rows already in
  PostgreSQL really are the partial copy of *this* `audit.db`. If they are not —
  the usual causes are a DSN pointing at a different deployment's database, or a
  restore that brought back `audit_events` without `audit_retention_meta` (which
  carries the `backfill_complete` marker) — the server **refuses to start** with
  `the existing rows are NOT an interrupted copy of …` rather than resuming past
  rows it cannot account for and reporting a complete migration. Point the server
  at the right database, or clear `audit_store.audit_events` if those rows are
  not wanted, then restart.
- **A server with no `audit.db` of its own will not "complete" someone else's
  partial backfill.** The completion marker asserts the trail is whole, so a
  server that finds audit rows already in PostgreSQL, no marker, and no usable
  legacy file **refuses to start** rather than stamping the marker over rows it
  cannot account for. The two ways to reach that state are a replica started
  while another is still streaming (bring up one replica first, below), and a
  partial backfill whose `audit.db` was moved aside before it finished. Restore
  the legacy file and let the backfill finish, or use the abandon procedure in
  [audit-store-backfill-recovery.md](../ops-runbooks/audit-store-backfill-recovery.md)
  if it is genuinely unrecoverable.
- After a verified backfill the legacy `audit.db` is **moved aside, not deleted**
  — it becomes an operator-managed backup of the pre-cutover trail. Relocating or
  archiving that file afterward is expected and safe. Its `-wal`/`-shm` sidecars,
  if the previous server stopped uncleanly and left any, are moved with it: the
  main file **alone is not a usable copy** when a WAL tail exists, so keep the set
  together if you relocate it.

**What to expect / do:**

- **Budget for a longer first boot on a large `audit.db`.** A trail with tens of
  millions of rows (~16 GB) can take meaningfully longer to stream than a normal
  startup. **Widen your startup budget accordingly:** raise the Kubernetes
  `startupProbe` (and any liveness) failure/period budget, or the Docker Compose
  healthcheck `start_period`, so the orchestrator does not kill the server
  mid-backfill and restart it into the same long boot repeatedly. The backfill is
  resumable, so a killed boot is not corrupting — but it wastes the window.
- **Scale-out: bring up the replica that HOLDS `audit.db` first — recommended,
  not load-bearing for safety.** In a multi-replica deployment, starting that
  one server first and letting it finish the backfill (the `backfill_complete`
  marker is stamped in `audit_store`) before the rest avoids a refusal, but a
  wrong boot order no longer loses evidence: if a replica with no legacy
  `audit.db` of its own boots first against an empty table, it stamps the
  completion marker over that emptiness (logging a WARNING naming what it
  forecloses — routine on a genuine fresh install, the signal you started the
  wrong host on an upgrade) — but the replica that DOES hold the trail does
  **not** silently trust that marker. It re-reads its own `audit.db`, proves
  (by fingerprint) whether that file's content was ever actually migrated, and
  **refuses to boot** on a mismatch rather than reporting success over an
  unmigrated trail. The file is left untouched at its original path — nothing
  is lost, but that host needs an operator to resolve it (see
  [audit-store-backfill-recovery.md](../ops-runbooks/audit-store-backfill-recovery.md))
  before it will serve. Getting the boot order right the
  first time avoids that operator step; it is no longer the thing standing
  between you and silent evidence loss. Once the marker is present (and, for
  every OTHER holder, verified) the remaining replicas start normally;
  retention afterward is single-swept fleet-wide via an advisory lease (see
  [Audit Log](audit-log.md#the-retention-clock-guard)).
- **Reads deny-on-degrade.** After cutover, an audit-store or connection-pool
  failure makes `GET /api/v1/audit*` return `503` rather than an empty `200`, so
  an infrastructure blip can never be mistaken for "no audit activity."
- **The break-glass one-shots run the backfill too.** `--mfa-reset` and
  `--break-glass-arm` write an audit record without going through boot, so on an
  upgraded host the first one of them to run performs the same migration a first
  boot would (streaming the trail, stamping the marker, moving `audit.db` aside)
  before it writes its record. Budget for that if you use one during the upgrade
  window; if the backfill cannot complete, the one-shot refuses and changes
  nothing rather than writing a record that would block every later boot.

**Backfill refused at boot or from a one-shot?** Both refusal shapes — a
holder-side verification failure (marker already set, this host's file
unproven) and an unrecoverable legacy trail (marker absent, rows present) —
including the SQL for the second one, now live in their own runbook:
[audit-store-backfill-recovery.md](../ops-runbooks/audit-store-backfill-recovery.md).
Not duplicated here.

**Not affected:** the audit event vocabulary and REST/MCP query surface are
unchanged; SIEM export recipes keep working. One deliberate behaviour change: on
a multi-replica deployment an identical-magnitude repeat clock step no longer
re-emits `yuzu_server_audit_clock_anomaly_skips_total` on every pass (only a
distinct anomaly does) — if you alerted on that counter's *cadence*, alert on a
sustained increase instead. See
[Audit Log](audit-log.md#the-retention-clock-guard).
## Management-group confinement config migrates to Postgres (mandatory backfill, ADR-0042)

The `ManagementGroupStore` — the confinement hierarchy that backs operator
scoping and the ADR-0017 `authorize_list_read` gate — moves from the SQLite
`management-groups.db` file to the server's PostgreSQL substrate in this release
(ADR-0006 Wave 2.2), schema `management_group_store`. It reuses the existing
shared connection pool, so **no new connection flag or config is required** —
the same `--postgres-dsn` / `YUZU_POSTGRES_DSN` that every other server store
uses.

**This is NOT a fresh-start cutover.** Unlike the AuthDB/ScimStore/API-token
migrations above (which deliberately reset), a management group's hierarchy,
static memberships, and group→role assignments are irreducible operator intent —
losing them would silently widen or narrow confinement. So the migration
performs a **mandatory one-time backfill** on first Postgres boot:

- **What is preserved:** every group (name, parent, membership type, scope
  expression), every static membership record, and every group→role assignment
  carry over exactly. Dynamic memberships re-resolve from their scope expression
  on the next reconcile, as before.
- **Fail-closed boot on backfill failure.** If the backfill cannot complete —
  Postgres write error, unreadable legacy DB, or the safety check below — the
  server **refuses to boot** rather than come up with an empty or partial
  confinement hierarchy (which would fail-open, exposing out-of-scope devices).
  The backfill marker is only stamped on success, so a failed attempt is
  **retried on the next start** once you have fixed the underlying cause; it
  never proceeds with partial state.
- **Legacy file moved aside after a verified backfill.** Once the backfill is
  confirmed complete, `management-groups.db` is renamed to
  `management-groups.db.migrated-<epoch>` (the server never reads it again). If
  you do not see this file appear, the backfill did not run to completion —
  investigate before assuming confinement is intact. Keep the renamed file until
  you have confirmed scoping behaves correctly, then treat it as an
  operator-managed backup and dispose of it per your data-retention policy.
- **The backfill REFUSES an over-deep or cyclic legacy tree.** If the legacy
  hierarchy contains a parent cycle or exceeds the maximum depth of 10 levels,
  the backfill fails closed (and, per above, blocks boot). This can only happen
  on a legacy DB that was hand-edited or corrupted outside the API (the create
  path caps depth at 5). **Remediate by repairing the legacy tree** (flatten it
  below 10 levels / break the cycle) **or moving `management-groups.db` aside
  yourself** to start fresh — then restart. Do not force-boot around this: a
  malformed hierarchy is exactly the state confinement must not silently accept.
- **Widened startup budget.** First boot takes longer than usual while the
  backfill runs; the server's startup readiness budget is widened to accommodate
  it. Do not treat a slower-than-normal first boot as a hang.

**Operator-visible behaviour change (fail-closed reads).** After cutover, a
confinement-feeding read that degrades (store not open, pool-acquire timeout, or
query error) now returns a distinguishable failure that the caller resolves to
**DenyAll** — a scoped operator sees a reduced or empty list rather than the
store silently returning an empty deny-set and **under-restricting** (the old
fail-open hazard). A re-parent (`PUT /api/v1/management-groups/{id}`) whose
hierarchy reads degrade now returns **503** rather than a misleading success.
Watch the new `yuzu_server_mgmt_group_read_degrade_total{reason}` counter — a
non-zero rate means scoped operators are seeing reduced/empty lists because the
confinement substrate is degraded, **not** that groups actually shrank (see
`docs/user-manual/metrics.md` § "Management group metrics" and the shipped
`YuzuMgmtGroupReadDegraded` alert). `yuzu_server_mgmt_group_backfill_total{result}`
records the one-time backfill outcome (`completed` / `fresh` / `failed`).

**Not affected:** the confinement hierarchy's semantics, the REST/MCP surface,
and dynamic-group scope expressions are unchanged — only the storage substrate
and the fail-closed read posture change.

## Custom properties migrate to Postgres (mandatory backfill, ADR-0045)

The `CustomPropertiesStore` — operator-authored per-agent metadata (properties
and their optional type/validation schemas) used in scope expressions via
`props.<key>` — moves from the SQLite `custom-properties.db` file to the
server's PostgreSQL substrate in this release (ADR-0006 Wave 2), schema
`custom_properties_store`. It reuses the existing shared connection pool —
**no new connection flag or config is required**.

**This is NOT a fresh-start cutover.** Custom properties and their schemas are
irreducible operator-authored asset-tagging data — losing them would silently
break any `props.<key>`-scoped dispatch, policy, or push rule. The migration
performs a **mandatory one-time backfill** on first Postgres boot:

- **What is preserved:** every property (agent, key, value, type) and every
  property schema (key, display name, type, description, validation regex)
  carry over exactly.
- **Fail-closed boot on backfill failure.** If the backfill cannot complete —
  Postgres write error, an unreadable legacy DB, or a holder-side
  fingerprint-verification refusal (see below) — the server **refuses to
  boot** rather than come up with partial data. The backfill marker is only
  stamped on success, so a failed attempt is **retried on the next start**
  once you have fixed the underlying cause.
- **Legacy file moved aside after a verified backfill.** Once the backfill is
  confirmed complete, `custom-properties.db` is renamed to
  `custom-properties.db.migrated-<epoch>` (the server never reads it again).
  If you do not see this file appear, the backfill did not run to completion.
  Keep the renamed file until you have confirmed properties/schemas look
  correct, then treat it as an operator-managed backup and dispose of it per
  your data-retention policy.
- **Multi-replica deployments: boot the replica holding the authoritative
  `custom-properties.db` FIRST.** Unlike this store's SQLite era, a
  multi-replica Postgres deployment shares ONE `custom_properties_store`
  schema — the first replica to complete the backfill wins, and every other
  replica's boot verifies its own local legacy file against what actually
  landed rather than trusting the shared completion marker blindly. If two
  replicas hold genuinely different legacy content (an unusual topology for
  this store — `custom-properties.db` is ordinarily a single server's local
  file, not something expected to diverge across replicas of the same
  logical deployment), the second replica to boot refuses with a
  **HOLDER-SIDE VERIFICATION FAILED** error rather than silently accepting
  or silently overwriting the winner's data — see
  `docs/ops-runbooks/custom-properties-store-backfill-recovery.md` for the
  recovery procedure.
- **Budget for a longer first boot.** First boot takes longer than usual while
  the backfill runs; a large `custom-properties.db` (many agents/properties)
  extends this further. **Widen your own orchestrator's startup budget
  accordingly** (Kubernetes `startupProbe` failure/period budget, or the
  Docker Compose healthcheck `start_period`) so it does not kill the server
  mid-backfill and restart it into the same long boot repeatedly — do not
  treat a slower-than-normal first boot as a hang.

**Operator-visible behaviour change (fail-closed reads).** After cutover, a
`props.<key>`-feeding read that degrades (store not open, pool-acquire
timeout, or query error) now aborts the whole scope evaluation rather than
silently resolving the property as absent — a `props.<key>`-scoped
dispatch/policy/push rule now matches **nobody** while degraded, instead of
(under a `NOT`/`!=` scope) silently matching **everybody**. `GET
/api/agents/:id/properties` now returns **503** on a degraded read rather
than an empty list. Watch the new
`yuzu_server_custom_properties_read_degrade_total{reason}` counter — a
non-zero rate means `props.<key>`-scoped rules may be silently matching
nobody, not that operators removed the properties (see `docs/user-manual/
metrics.md` and the shipped `YuzuCustomPropertiesReadDegraded` alert).
`yuzu_server_custom_properties_backfill_total{result}` records the one-time
backfill outcome.

**Not affected:** the `props.<key>` scope-DSL syntax, the REST API request/
response shapes, and property/schema semantics are unchanged — only the
storage substrate and the fail-closed read posture change.

## Network-discovered device data migrates to Postgres (mandatory backfill, DiscoveryStore, ADR-0044)

The `DiscoveryStore` — the network-discovered devices behind `POST /api/discovery/scan`
and `GET /api/discovery/results` — moves from the SQLite `discovery.db` file to the
server's PostgreSQL substrate in this release (ADR-0006 Wave 2), schema
`discovery_store`. It reuses the existing shared connection pool — no new connection
flag or config is required.

**This is NOT a fresh-start cutover.** The `managed` flag an operator has set on a
discovered device (confirming "this is my enrolled agent") is real, non-regenerable
operator intent, so the migration performs a **mandatory one-time backfill** on first
Postgres boot:

- **What is preserved:** every discovered device — IP/MAC/hostname, the `managed`
  flag and its associated `agent_id`, and first-seen (`discovered_at`/`discovered_by`)
  provenance — carries over (any field containing invalid UTF-8 or an embedded NUL
  is scrubbed to U+FFFD on write, matching every other field in this store).
- **Fail-closed boot on backfill failure.** If the backfill cannot complete —
  Postgres write error, an unreadable legacy DB, or a fingerprint mismatch (below) —
  the server **refuses to boot** rather than come up with an empty or partial
  discovered-device inventory. The backfill marker is only stamped on success, so a
  failed attempt is **retried on the next start** once the underlying cause is fixed.
- **Fingerprint-verified, not marker-only.** Unlike a plain "did the marker get
  stamped" check, the backfill records a fingerprint of the migrated content
  alongside the completion marker. On a multi-replica deployment sharing one
  Postgres database, this lets a later-booting replica tell apart "this is the same
  content I already migrated" from "a different replica's data was migrated, not
  mine" — the latter fails closed rather than silently accepting a completion this
  replica's own discovered devices were never part of. If you see a "HOLDER-SIDE
  VERIFICATION FAILED" log line, do not force-boot around it: this indicates two
  replicas each hold `discovery.db` files with genuinely different content, and an
  operator needs to decide which is authoritative before either can proceed.
- **A 0-byte `discovery.db` is refused, not treated as a fresh install.** SQLite
  opens a 0-byte file as a valid empty database, which looks identical to "this
  legacy store was created but never used" — but a genuine fresh install never has
  a `discovery.db` file at all. If you see a log line saying this is "NOT a fresh
  install... a truncated/corrupted real database", either delete the empty file and
  retry (if the legacy store genuinely was never used) or restore `discovery.db`
  from backup before retrying (if it held real data that got truncated).
- **A conflict during backfill can also refuse the boot, not just a fingerprint
  mismatch.** On a multi-replica deployment, if a live scan (or a `mark_managed`
  call through a sibling replica) lands a row for an IP before this replica's own
  backfill reaches it, and that legacy row was `managed=true` or had an
  `agent_id` assigned, the backfill verifies the row already in Postgres carries
  the same values before trusting the migration — refusing (with a
  "reconciliation FAILED" log line naming the IP) rather than silently dropping
  or misattributing an operator's managed-device assignment. **This does NOT
  resolve itself on its own** — the legacy data is frozen and a retry
  conflict-skips against the same mismatched row every time, so this replica
  restart-loops until an operator manually reconciles: check
  `discovery_store.discovered_devices` for the named IP to see which value is
  actually correct, then either accept the value already in Postgres (delete the
  legacy file and let this replica take the sourceless-skip path) or correct the
  row via `mark_managed` before retrying.
- **Legacy file moved aside after a verified backfill.** Once the backfill is
  confirmed complete, `discovery.db` is renamed to
  `discovery.db.migrated-<epoch>` (the server never reads it again). Keep the
  renamed file until you have confirmed discovery data looks correct, then dispose
  of it per your data-retention policy.

**Operator-visible behaviour change (fail-closed reads).** `GET /api/discovery/results`
now returns **503** on a degraded read (store not open, pool-acquire timeout, or query
error) instead of silently rendering an empty device list — previously, a local SQLite
read essentially never failed short of file corruption, so this failure mode was not
practically reachable. Watch the new `yuzu_server_discovery_read_degrade_total{reason}`
counter — a non-zero rate means the discovery view is degraded, **not** that no devices
were found. `yuzu_server_discovery_backfill_total{result}` records the one-time
backfill outcome (`completed` / `fresh` / `failed`).

**Breaking — `POST /api/discovery/scan`'s response contract changed.** The endpoint no
longer always returns `200 {"status":"ok",...}`: the response gains a `devices_failed`
count, `status` is `"partial"` when some but not all devices in a batch persisted, and
the endpoint returns **503** when every attempted device failed to persist (previously
this was silently reported as `200`/`"ok"`, with the `discovery.scan` audit row always
saying `"success"` regardless of outcome — the audit outcome is now
`"success"`/`"partial"`/`"failure"`). A caller that asserts a bare `status == "ok"`, or
that treats any 5xx from this endpoint as a hard failure needing operator escalation,
should account for the new value and status code. Re-sending the exact same request body
is safe — `upsert_device` is idempotent per `ip_address`, so a byte-identical retry cannot
double-count or corrupt already-stored devices — but a fresh re-scan is not the same
thing: `mac_address`/`subnet` overwrite unconditionally on every upsert, so a re-scan that
fails to resolve a device's MAC this time will blank a previously known-good value rather
than simply retry the earlier failure. See the REST API reference's Network Discovery
section for the full response shapes.

## Guardian quarantine records migrate to Postgres (mandatory backfill, QuarantineStore, ADR-0047)

The `QuarantineStore` — the Guardian device-quarantine bookkeeping behind
`POST /api/v1/quarantine`, `DELETE /api/v1/quarantine/{agent_id}`, and the MCP
`quarantine_device` tool — moves from the SQLite `quarantine.db` file to the server's
PostgreSQL substrate in this release (ADR-0006 Wave 2), schema `quarantine_store`. It
reuses the existing shared connection pool — no new connection flag or config is
required.

**This is NOT a fresh-start cutover.** An active quarantine record is live security
containment state — losing it would silently un-quarantine a device in the server's
view — so the migration performs a **mandatory one-time backfill** on first Postgres
boot:

- **What is preserved:** every quarantine record, active and released — agent_id,
  status, who quarantined it, timestamps, the IP whitelist, and the reason — carries
  over, in full history (not just the current active row).
- **Fail-closed boot on backfill failure.** If the backfill cannot complete — a
  Postgres write error, an unreadable legacy DB, an unrecognised legacy `status` value,
  or a fingerprint mismatch (below) — the server **refuses to boot** rather than come
  up with an empty or partial quarantine inventory. The backfill marker is only
  stamped on success, so a failed attempt is **retried on the next start** once the
  underlying cause is fixed.
- **Fingerprint-verified, not marker-only**, the same shape `DiscoveryStore` uses
  (see that section above for the full rationale): on a multi-replica deployment
  sharing one Postgres database, a later-booting replica that still holds its own
  legacy file verifies its content against the recorded fingerprint before trusting
  an already-set completion marker. A "HOLDER-SIDE VERIFICATION FAILED" log line means
  two replicas each hold `quarantine.db` files with genuinely different content — do
  not force-boot around it; an operator needs to decide which is authoritative first.
  Two narrower variants of the same "don't trust the marker blindly" check also
  refuse and require manual reconciliation: a marker set with **no** recorded
  fingerprint at all (predates this mechanism) while this replica still holds real
  legacy content, and a marker set **sourceless** (no replica has ever migrated real
  content for this fleet yet) while this replica holds real content — in the second
  case, refusing matters because a live `quarantine_device`/`release_device` call
  could already have landed against the sourceless-stamped store, and blindly
  migrating stale legacy content on top would silently clobber it.
- **A 0-byte `quarantine.db` is refused, not treated as a fresh install** — same
  rationale as `discovery.db` above (SQLite opens a 0-byte file as a valid empty
  database, indistinguishable from "never used" without an explicit check, but a
  genuine fresh install never has a file here at all).
- **An unrecognised legacy `status` value refuses the boot.** The `status` column is
  only ever `active` or `released`; a legacy row carrying anything else (e.g. from
  manual DB surgery) fails the backfill closed with a log line naming the offending
  `agent_id` and value, rather than silently inserting an unrecognised state or
  silently dropping the row.
- **More than one `active` record for the same agent in the legacy file also
  refuses the boot.** The legacy SQLite schema never enforced "at most one active
  record per agent" at the database level (only an in-process mutex the server no
  longer runs did), so a legacy file could in principle hold a duplicate from
  pre-existing data corruption or a hand-edited file. The backfill checks for this
  before touching Postgres and names the offending `agent_id`, rather than aborting
  mid-transaction on a raw database constraint-violation error.
- **More than 500,000 legacy records refuses the boot** as a sanity/DoS cap on a
  single backfill transaction — quarantine records are a manually-curated security
  list, so this is not expected to bind in practice; contact platform engineering
  before raising it if it does.
- **Legacy file moved aside after a verified backfill.** Once the backfill is
  confirmed complete, `quarantine.db` is renamed to
  `quarantine.db.migrated-<epoch>` (the server never reads it again). If the rename
  itself fails (e.g. a permissions issue), this is logged as a warning and does
  **not** block boot — the file is safe to archive or remove manually, and every
  later boot re-verifies it by fingerprint before trusting the already-set marker,
  so a lingering un-renamed file is never silently re-migrated. Keep the renamed
  file (or the un-renamed original) until you have confirmed quarantine history
  looks correct, then dispose of it per your data-retention policy.
- **A same-boot race between two replicas migrating for the first time is
  serialized, not refused.** If two replicas reach the backfill within the same
  narrow window, one waits on the other under an internal database lock (bounded by
  the same timeout as the backfill transaction itself) rather than both attempting
  the insert; the loser then re-verifies by fingerprint as described above. This is
  expected, self-resolving behavior on a fresh multi-replica rollout and does not
  need operator action.

**Operator-visible behaviour change (fail-closed reads).** `GET /api/v1/quarantine`
now returns **503** on a degraded read (store not open, pool-acquire timeout, or query
error) instead of silently rendering an empty quarantine list — previously, a local
SQLite read essentially never failed short of file corruption, so this failure mode
was not practically reachable. Watch the new
`yuzu_server_quarantine_read_degrade_total{reason}` counter — a non-zero rate means
the quarantine view is degraded, **not** that no devices are quarantined.
`yuzu_server_quarantine_backfill_total{result}` records the one-time backfill outcome
(`completed` / `fresh` / `failed`).

**Not affected:** the agent-side quarantine firewall enforcement (WFP/nftables/pf
block-all + exceptions) is untouched by this migration — only the server-side
bookkeeping's storage substrate changes. `POST /api/v1/quarantine` and
`DELETE /api/v1/quarantine/{agent_id}`'s request/response shapes, and the MCP
`quarantine_device` tool's ticket-then-recall approval flow, are unchanged.

## Upgrade Order

Always upgrade in this order:

1. **Server** -- new server versions accept connections from older agents
2. **Gateway** -- updated to match server protocol changes
3. **Agents** -- can be upgraded via OTA or manually, in batches

Never upgrade agents before the server -- the server must understand the agent's protocol version.

## Pre-Upgrade Checklist

Before upgrading any component:

- [ ] Back up all data (see [Server Administration](server-administration.md))
  - `yuzu-server.cfg`, `enrollment-tokens.cfg`, `pending-agents.cfg`
  - All `.db` files (response store, audit, policies, **auth.db**, etc.) — use `sqlite3 <path> ".backup ..."` rather than `cp` against live WAL databases
  - The **PostgreSQL database**, once your deployment carries one (ADR-0006 — bundled in the composes; provisioned natively by `install-server-postgres.sh`) — use `pg_dump --format=custom`; see [Server Administration § PostgreSQL Substrate](server-admin.md#postgresql-substrate) for the full backup/restore procedure and the ADR-0010 restore-pairing invariant (DB and `KeyProvider` keys-dir backups restore **together**)
- [ ] **Verify the server's clock before upgrading** (`timedatectl status` or
  `chronyc tracking`; under Docker it is the host's clock that matters). Rows
  already stamped cannot be protected retroactively by any setting, and a server
  upgraded to schema v3 while its clock was skewed FORWARD could delete expired
  audit rows unremarked on its first guarded pass - see [Retention clock
  guards](#retention-clock-guards-2360-server-audit-store-2361-tar-agent-warehouse)
  below and #2579. Fixed forward: that pass now declines instead, so the risk is
  to servers upgrading FROM an affected version with a wrong clock.
- [ ] Check the [CHANGELOG](../../CHANGELOG.md) for breaking changes
- [ ] Verify disk space (at least 500 MB free for migration)
- [ ] Note current version: `yuzu-server --version` / `yuzu-agent --version`
- [ ] Plan a maintenance window (upgrades take < 5 minutes per component)
- [ ] **Review new opt-in telemetry:** this release adds DEX per-application
  performance sampling (`procperf`), a new usage-class data category. It is
  **off by default** (no action needed to keep it off) — but if you intend to
  enable it for an EU workforce, treat it as a works-council co-determination
  trigger. See the *DEX per-application sampling* upgrade note in
  [Server Administration](server-admin.md#upgrade-notes).
- [ ] **New device performance sampling on Linux:** this release wires the TAR
  `perf` collector on **Linux**, and because it is default-ON, Linux agents
  **begin recording on-device performance samples automatically on agent
  upgrade** (device-level, no user identity; opt out per host with
  `tar.configure perf_enabled=false`). These rows carry no per-user or per-app
  identity, but the project treats the *capability to observe* as the
  works-council co-determination trigger, so EU deployments should note the new
  Linux coverage as they did for the Windows network facts below.
  Per-application sampling (`procperf`) is now also implemented on Linux but
  remains **opt-in on every OS** — the works-council posture above applies
  unchanged. Details and caveats: the upgrade note in
  [the TAR user manual](tar.md#performance-impact).
- [ ] **New network telemetry on Windows:** this release makes **Windows** agents
  emit device-aggregate network facts (throughput + interval retransmit rate) on
  the heartbeat, automatically on agent upgrade — gated by the existing
  `--dex-disable` / `YUZU_AGENT_DEX_DISABLE` flag (no separate opt-in). These
  carry no per-user or per-application identity (lighter than `procperf`), but the
  project treats the *capability to observe* as the works-council co-determination
  trigger, so EU deployments should note the new Windows coverage as they did for
  the DEX signals. See [Network Quality](network.md) → Collection & privacy.
- [ ] **New daily installed-software sync (ADR-0016):** on agent upgrade, agents
  begin syncing their **machine-wide installed-software** inventory to the server
  once per ~24 h over the existing gRPC channel (hash-skip keeps unchanged hosts
  to a tiny hash, not the full list). Three operator-visible effects: (a) new daily
  outbound `ReportInventory` traffic per agent — adjust egress baselines/firewall
  expectations; (b) the data lands in a **new Postgres schema**
  (`software_inventory_store`, auto-migrated at boot, fail-closed); (c) it requires
  the `installed_apps` plugin to be loaded — a build with `-Dbuild_examples=false`
  (or a plugin dir missing it) collects **nothing**, silently (agent logs only at
  debug). Machine-scope only, no end-user PII (no username collection) — but the
  data is device-attributable, and on **personally-assigned devices** installed-
  software enumeration may be **works-council co-determination-relevant** (see the
  works-council note in [Installed-Software Inventory](inventory.md)). To suppress
  collection entirely, pass **`--inventory-disable`** / set
  `YUZU_AGENT_INVENTORY_DISABLE` on the agent (deploy-time opt-out). Reads are
  gated on the new `Inventory:Read` RBAC securable; today the data is queryable via
  direct SQL (see [Installed-Software Inventory](inventory.md)). On a **non-English
  fleet**, upgrading across #1662 changes stored names: app/publisher names that
  earlier builds mangled to `?` (cp1252) are rewritten to correct UTF-8 on each
  agent's next daily sync, so any query automation that matched the corrupted `?`
  strings will return nothing afterward — see the non-ASCII troubleshooting note in
  [Installed-Software Inventory](inventory.md) for the force-resync path.
- [ ] **New SparkEngine health telemetry (auto-on, engine-health only):** on agent
  upgrade, agents begin shipping SparkEngine posture tags on the existing
  heartbeat (2 keys when quiescent), and the server exposes 11 new
  `yuzu_fleet_spark_*` gauges. The engine is **observe-only at this rung** —
  nothing about Guard detection or enforcement changes — and the tags are pure
  engine-health counts (no user, process, or path identity; no works-council
  trigger). During a staged rollout, not-yet-upgraded agents are simply absent
  from the new gauges — expected, see the staged-rollout example in
  [Metrics](metrics.md#sparkengine-fleet-gauges). Deploy-time opt-out:
  `--spark-disable` / `YUZU_AGENT_SPARK_DISABLE` (the opt-out itself stays
  visible as `yuzu_fleet_spark_disabled`). See
  [Guaranteed State](guaranteed-state.md#sparkengine--the-next-generation-detection-engine-observe-only).
- [ ] **Changed agent signal handling (Linux/macOS):** graceful shutdown now runs
  on a dedicated watcher thread (fixes an abort/hang class on `SIGTERM`), and a
  **second** `SIGTERM`/`SIGINT` immediately hard-exits the agent (exit 1) —
  by design, with **no grace window**: the second signal is read as "the stop is
  wedged". Stop scripts that deliberately double-signal agents will now
  force-kill them; send one signal and wait instead. On Windows a second Ctrl-C
  also terminates promptly. See *Stopping a wedged agent* in
  [Server Administration](server-admin.md).
- **Non-English fleets — additional plugins (#1682).** The same `Reg*A` → `Reg*W`
  encoding fix was extended to four more Windows plugins: `vuln_scan` (app
  DisplayName/Publisher/Version in vulnerability findings), `os_info` (OS
  ProductName / edition), `sccm` (client version), and `windows_updates` (the WSUS
  `WUServer` URL). Unlike `installed_apps`, these produce **transient** response
  data — no stored names are rewritten; each call simply delivers correct UTF-8
  immediately after the agent upgrade. Any operator automation that matched
  previously-mangled non-ASCII strings in those plugins' responses (e.g. a vuln
  finding filtered on `title == "Caf?"`) will need updating.

## Upgrading the Server

### Linux (systemd)

```bash
# 1. Stop the server
sudo systemctl stop yuzu-server

# 2. Back up data
sudo cp /var/lib/yuzu/*.db /var/lib/yuzu/backup/
sudo cp /etc/yuzu/*.cfg /var/lib/yuzu/backup/
# ... and the Postgres database, if provisioned. The DSN lives only in the
# root-only env file (NOT in interactive shells) — load it, and keep the
# password off the argv via PGPASSWORD. Full recipe + restore procedure:
# server-admin.md § PostgreSQL Substrate.
sudo sh -c '. /etc/yuzu/yuzu-server.env
  export PGPASSWORD="$(printf "%s\n" "$YUZU_POSTGRES_DSN" | sed -E "s!^[a-z]+://[^:/@]*:([^@]*)@.*\$!\1!")"
  pg_dump --format=custom --file=/var/lib/yuzu/backup/yuzu-pg.dump \
    "$(printf "%s\n" "$YUZU_POSTGRES_DSN" | sed -E "s!^([a-z]+://[^:/@]*):[^@]*@!\1@!")"'

# 3. Replace the binary
sudo cp yuzu-server /usr/local/bin/yuzu-server
sudo chmod +x /usr/local/bin/yuzu-server

# 4. Start the server (schema migrations run automatically)
sudo systemctl start yuzu-server

# 5. Verify
sudo systemctl status yuzu-server
curl -s http://localhost:8080/livez
```

### Docker

The reference deployment template lives at `deploy/docker/docker-compose.reference.yml` — copy it into your deployment directory next to a `.env` file, set `YUZU_VERSION`, and harden per the inline TLS checklist in the file header **before** exposing the stack to any untrusted network. The compose file declares a named volume (`server-data`) that survives container replacement and holds every piece of mutable state: `yuzu-server.cfg`, all SQLite databases, `enrollment-tokens.cfg`, `pending-agents.cfg`, `auto-approve.cfg`, and OTA binaries.

An upgrade is a pull-and-restart:

```bash
# 1. Back up first (see below) — the old data is the only recovery path
#    if a migration fails on your specific DB.

# 2. Pick the new release tag (use an .env file or export)
export YUZU_VERSION=0.10.1

# 3. Pull the new image and recreate the container
docker compose -f docker-compose.reference.yml pull server
docker compose -f docker-compose.reference.yml up -d server

# 4. Verify the new version came up and schema migrations ran
docker compose -f docker-compose.reference.yml logs server | tail -40
docker compose -f docker-compose.reference.yml ps server    # should be "healthy"
```

Schema migrations execute automatically during the first `up` with the new image — look for `MigrationRunner: <store> migrated to v<N>` lines in the log (one per store on first upgrade, silent on subsequent restarts). The healthcheck used by `depends_on: service_healthy` probes `/readyz`, which returns 200 only after every store in the readiness conjunction has successfully migrated — so a healthy server container genuinely reflects migration success, not just liveness.

**Back up before upgrading** (run from a dedicated backup directory so `$PWD` is predictable):

```bash
mkdir -p ~/yuzu-backups && cd ~/yuzu-backups
docker run --rm -v server-data:/data -v "$PWD":/backup alpine \
  tar czf "/backup/yuzu-data-$(date +%F).tar.gz" -C /data .

# PostgreSQL state (the postgres-data volume) — pg_dump is consistent
# against a LIVE database, no stop required:
docker exec yuzu-postgres pg_dump -U postgres --format=custom yuzu \
  > "yuzu-pg-$(date +%F).dump"
```

> **Note:** this recipe is a cold-ish backup — SQLite is running in WAL mode and a filesystem-level `tar` of a live database may capture a torn snapshot. For strong consistency, `docker compose -f docker-compose.reference.yml stop server` before backup (seconds of downtime) and `start` after. A fully hot backup via SQLite's online-backup API is tracked in the roadmap. The `pg_dump` half has no such caveat — logical dumps are transactionally consistent by construction. **Never** back up Postgres by `tar`-ing the `postgres-data` volume while the database is running; a torn copy of `pg_wal/` is unrecoverable, which is why the procedure above dumps through the database instead.

> **Restore-pairing (ADR-0010 — forward reference):** once envelope-encrypted secrets land, the Postgres dump contains ciphertext + wrapped DEKs only and is unusable without the matching `KeyProvider` keys directory. Back up and restore the two **as a pair** — full procedure in [Server Administration § PostgreSQL Substrate](server-admin.md#postgresql-substrate), key-management runbook tracked in #1341.

**Rollback if a migration fails** (Docker):

```bash
# 1. Stop the new server (KEEPING the named volume — do NOT use -v)
docker compose -f docker-compose.reference.yml down server

# 2. Restore the previous backup over the existing volume
docker run --rm -v server-data:/data -v "$PWD":/backup alpine \
  sh -c 'rm -rf /data/* && tar xzf /backup/yuzu-data-YYYY-MM-DD.tar.gz -C /data'

# 2b. Restore the Postgres dump (postgres container still running)
docker exec -i yuzu-postgres pg_restore --clean --if-exists --no-owner \
  --role=yuzu -U postgres --dbname=yuzu < "yuzu-pg-YYYY-MM-DD.dump"

# 3. Pin the previous release
export YUZU_VERSION=0.9.0

# 4. Start the previous version
docker compose -f docker-compose.reference.yml up -d server
```

**Never** run `docker compose down -v` unless you intend to delete `server-data`, `postgres-data` (the PostgreSQL substrate — the server's primary data store), and every bit of server state. `down` alone is safe; the `-v` flag removes named volumes.

### Windows

```powershell
# 1. Stop the service (if running as service) or kill the process
Stop-Service yuzu-server  # or: taskkill /IM yuzu-server.exe /F

# 2. Back up data
Copy-Item C:\ProgramData\Yuzu\*.db C:\ProgramData\Yuzu\backup\
Copy-Item C:\ProgramData\Yuzu\*.cfg C:\ProgramData\Yuzu\backup\

# 3. Replace the binary
Copy-Item yuzu-server.exe "C:\Program Files\Yuzu\yuzu-server.exe"

# 4. Start
Start-Service yuzu-server  # or start manually
```

## Upgrading the Gateway

### Linux (systemd)

> **Breaking (#659):** the gateway refuses to start without a non-default Erlang
> distribution cookie. `.deb`/`.rpm` installs auto-generate `/etc/yuzu/gateway.env`;
> for tarball/manual installs create it once (see "Gateway distribution cookie now
> required" under *Upgrade notes by release* below) before the restart step.

```bash
sudo systemctl stop yuzu-gateway
# Replace the release directory
sudo rm -rf /opt/yuzu_gw
sudo tar xzf yuzu-gateway-linux-x64.tar.gz -C /opt/
sudo systemctl start yuzu-gateway
```

### Docker

```bash
docker pull ghcr.io/<owner>/yuzu-gateway:v0.1.1
docker compose up -d yuzu-gateway
```

## Upgrading Agents

### OTA (Recommended)

If the server has OTA updates enabled (`--update-dir`):

1. Place the new agent binary in the server's update directory
2. Agents will check for updates on their configured interval (default: 6 hours)
3. Monitor the fleet dashboard for version rollout progress

### Manual

Follow the same stop/replace/start pattern as the server, per platform.

### Batch Rollout

For large fleets, upgrade in stages:
1. Upgrade a pilot group (5-10 agents) first
2. Monitor for 24 hours
3. Roll out to remaining agents in batches of 10-20%

## Plugin Code Signing (vNEXT, #80)

A new operator-managed plugin trust bundle ships in this release. **Default behaviour is unchanged**: agents that don't pass `--plugin-trust-bundle` and operators that don't upload a bundle through Settings → Plugin Code Signing see identical behaviour to prior releases.

If you turn the feature on, three things change:

1. **New on-disk artifact at `<cert-dir>/plugin-trust-bundle.pem`.** Linux/macOS: `/etc/yuzu/certs/plugin-trust-bundle.pem`; Windows: `C:\ProgramData\Yuzu\certs\plugin-trust-bundle.pem`. **Add this path to your backup procedure** alongside the SQLite databases. A backup that captures the DBs but not the cert dir restores `plugin_signing_required=true` (in `runtime_config`) without the bundle, and require-mode agents reject every plugin until the bundle is restored. The Docker reference `docker-compose.reference.yml` mounts only `server-data`; if your cert dir is outside that volume you must add a separate bind-mount or named volume and include it in the backup script.

2. **Cert-dir filename collision check.** The server now treats `plugin-trust-bundle.pem` in the cert dir as authoritative. The filename was unused in prior releases, but if any deployment placed an unrelated PEM at that exact path for another purpose, it will be interpreted as the plugin trust bundle on first read after upgrade. Run `ls <cert-dir>/plugin-trust-bundle.pem` on every server host before upgrading and rename any pre-existing file.

3. **DO NOT enable "Require signed plugins" yet.** The Yuzu release pipeline does not currently sign the 44 in-tree plugins under `agents/plugins/`. Enabling Require with an operator-only trust bundle will reject every Yuzu-shipped plugin on next agent restart — fleet-wide outage. Use the transitional mode (bundle uploaded, Require off) until you have signed every plugin your fleet uses, including the in-tree ones. The Settings card displays this warning inline.

The new audit actions (`plugin_signing.bundle.uploaded` / `.cleared` / `.require.changed`) and metric labels on `yuzu_agent_plugin_rejected_total` (`signature_missing` / `signature_invalid` / `signature_untrusted_chain`) are documented in `audit-log.md` and `metrics.md` respectively. SIEM and alert rules already filtering on the existing `success`/`failure`/`denied` audit vocabulary pick these up unchanged — no new vocabulary tokens were introduced.

## Schema Migrations

Starting with **v0.10.0**, every server-side SQLite store is wired through a single `MigrationRunner` that tracks schema version per store and applies pending migrations in a transaction. Prior releases relied on `CREATE TABLE IF NOT EXISTS` plus silent `ALTER TABLE ADD COLUMN` statements, which made rollbacks opaque and left no audit trail of what had been applied.

How it works:

- Each store declares an ordered `std::vector<Migration>` where each entry is `{version, sql}`.
- On startup, the runner creates the `schema_meta` table if missing, reads the current version for the store, and runs any migration with a higher version number inside a `BEGIN IMMEDIATE` / `COMMIT` transaction.
- If a migration SQL statement fails, the transaction rolls back and the store stays at its previous version — the server logs `MigrationRunner: migration v<N> failed for <store>: <sqlite error>` and the corresponding store constructor logs `<Store>: schema migration failed`.
- Already-applied migrations are skipped; running the same server binary twice against the same database is a no-op.
- Multiple stores share one database connection but keep independent version counters.

**Indexes are normally migration entries. `audit_store`'s retention index is a
deliberate, single exception** (`idx_audit_ttl_id`, #2360) - every other index in
the server is created inside `MigrationRunner`, and new code should follow that
rule, not this one. Two conditions justify the exception here and both must hold
before it is copied: (a) a failed migration closes the store, and for
`audit_store` that means every audit write then fails, taking the SOC 2 trail
offline; and (b) the build is `O(N log N)` over an existing multi-million-row
table, unlike the v1 indexes which are created on an empty one. A best-effort
object may silently not exist, so nothing with a CORRECTNESS dependency may use
this path - the retention guard is correct without its index, only slower.

Cost on a large existing `audit_events`: a one-time build at first boot after
upgrade, measured at ~81 MB and ~1.8-3.3 s at 5M rows on NVMe. At 50M rows the
build reads a ~16 GB table - tens of seconds on local NVMe, and potentially
minutes on container overlayfs or network storage.

**This runs synchronously, before the server binds its listeners**, so nothing
answers `/livez` or `/readyz` until it finishes. If your orchestrator's
kill-before-ready budget is shorter than the build you get a CRASH LOOP rather
than a slow boot: `CREATE INDEX` is one atomic statement, so every killed attempt
rolls back and the next boot re-pays it in full, indefinitely. Budget at least
**5 minutes** before the first liveness kill for an `audit_events` above ~20M
rows on non-NVMe storage. The shipped
`deploy/docker/docker-compose.reference.yml` sets `start_period: 30s`, which is
fine for a fresh install and NOT enough for a large first post-upgrade boot -
raise it before upgrading such a deployment. The
elapsed time is logged when it exceeds a second, and subsequent boots are a
no-op. If the build fails, retention still runs, but each pass then scans the
table AND sorts the whole expired backlog for its `ORDER BY ... LIMIT` (measured
2.0 s versus ~285-315 ms for the same capped pass WITH the index; the range
reflects different benchmark runs, not two different operations) - still far better than the unguarded code it
replaced, but the failure is logged as an error.

**Upgrading from v0.9.x or earlier** is data-preserving: the first 0.10.x startup stamps every database at schema v1. A small set of stores (`api_token_store`, `instruction_store`, `patch_manager`, `policy_store`, `product_pack_store`, `response_store`) also runs a one-time legacy compatibility shim that re-applies the historical `ALTER TABLE` statements before stamping, so databases from very old releases that never received those columns still converge to the latest schema. These shims are kept in code for one release cycle and can be removed after v0.11.

**No manual migration steps are required.** Just replace the binary (or pull the new image and `up -d`) and start the server. Migration progress is logged at `info` level as:

```
[info] MigrationRunner: rbac_store migrated to v1
[info] MigrationRunner: response_store migrated to v1
...
```

**Expect a log burst on first startup after upgrade.** 30+ `MigrationRunner: <store> migrated to v1` info lines appear on the first run against a pre-v0.10 database — one per store. On every subsequent restart the runner is silent at info level. If your log-shipping pipeline has per-second rate limits, widen them for the upgrade window or filter this single line pattern.

**Verifying migration state after startup**, query the per-store audit trail directly:

```bash
docker exec -i yuzu-server sqlite3 /var/lib/yuzu/rbac.db \
  "SELECT store, version, datetime(upgraded_at, 'unixepoch') FROM schema_meta ORDER BY upgraded_at;"
```

Every store that has ever run through the migration runner has a row here with its current version and the wall-clock timestamp of the last stamp. This is the operator-side audit trail for schema evolution.

**The Postgres-backed stores are not in that file.** Stores migrated onto the PostgreSQL
substrate — `audit_store` among them (ADR-0040) — run through `PgMigrationRunner`, log
`PgMigrationRunner: <store> migrated to v<N>`, and stamp `public.schema_meta` **in
PostgreSQL**. Query those there instead:

```bash
psql "$YUZU_POSTGRES_DSN" -c \
  "SELECT store, version, to_timestamp(upgraded_at) FROM public.schema_meta ORDER BY upgraded_at;"
```

For `audit_store` specifically, the legacy `audit.db` also **stops existing at its old path**
after the one-time backfill: it is renamed to `audit.db.migrated-<epoch>` (with any
`-wal`/`-shm` sidecars). A `sqlite3 /var/lib/yuzu/audit.db` command therefore fails with
`unable to open database file` on a migrated server, and that is expected, not a fault.

If a migration fails:

1. Check the log for `MigrationRunner: migration v<N> failed for <store>: <sqlite error>` and note both the store name and the SQLite error.
2. The server will have **closed the failing store's database handle**, so `/readyz` returns 503 with the failed store name in the `failed_stores` body field — the probe accurately reflects degraded state. Don't rely on `/livez` for readiness; it only checks process liveness, not schema integrity.
3. Stop the server and restore the **affected** database file from backup — not the whole data directory. Restoring all databases to fix one broken store wipes in-flight approvals, pending agents, and enrollment tokens. **This step does not apply to a Postgres-backed store** such as `audit_store`: there is no per-store file to restore, so use the Postgres dump procedure under "Rollback if a migration fails" above.
4. Start the previous server version against the restored data.
5. Open an issue with the full error line, the source/target version numbers, and the output of the `schema_meta` query above.

## Upgrade notes by release

### Retention clock guards (#2360 server audit store, #2361 TAR agent warehouse, #2964 rotation sweep)

Both retention paths used to issue an unbounded `DELETE` driven by the local wall
clock, so one forward clock step could wipe a store in a single statement. They
are now guarded and capped. Two operator-visible consequences on upgrade:

- **Audit retention is now a floor, not a ceiling.** A pass that would expire
  every datable row declines once, and every accepted pass is capped at 25,000
  rows, so a large backlog ages out over hours rather than in one statement.
  Watch `yuzu_server_audit_retention_cap_reached_total` alongside
  `yuzu_server_audit_rows_deleted_total` to see whether a backlog is draining.
  The cap paces at two different cadences depending on whether a backlog is
  forming — see [Audit Log § Capacity](audit-log.md#capacity) for both
  figures; comparing your event rate against only the quiet-operation one is
  overly conservative by roughly three orders of magnitude. Note that
  changing `--audit-retention-days` never re-dates
  existing rows (`ttl_expires_at` is stamped at INSERT), so a reduction does not
  reclaim disk retroactively. Operator triage when the guard declines a pass:
  [audit-log.md § The retention clock guard](audit-log.md#the-retention-clock-guard).
- **`audit_store` gains schema v3** (a small `audit_retention_meta` key/value
  table holding the durable clock reading - one row, instant) plus the
  best-effort index build described under Schema Migrations above.
- **`YuzuAuditRetentionNotRunning` now fires for a crash-looping server
  (#2553, redesigned by #2854 rung D), and there is a new
  `YuzuAuditRetentionNeverRan` alert to route.** The old rule's young-server
  grace keyed on uptime, so a process restarting more often than the 3-hour
  alert window never accumulated enough uptime to leave the grace and was
  excused on every evaluation - silently, and for one of the leading causes of
  the exact condition the rule detects. The grace is now the restart-surviving
  last-pass stamp (`yuzu_server_audit_retention_last_pass_unixtime`, seeded
  from the durable anchor at startup): the rule excuses only a database no
  retention pass has EVER run against, fires at every restart cadence on an
  anchored one, and stays firing while the reaper stays dead. The excused
  never-ran state gets its own alert, `YuzuAuditRetentionNeverRan` (stamp
  still `0` after 3 hours) - **a new alertname: give it an Alertmanager route**.
  **If you re-apply this rules file and have a crash-looping server, expect a
  new-to-you firing** that reflects a pre-existing condition rather than a new
  fault - including on crash loops faster than the 60-minute first-pass sleep,
  a true positive the old grace hid. The rules file is a copy you apply
  yourself; the server does not upgrade it for you, and a stack that does not
  re-apply it keeps the old blind rule and never gains the new alert. In a
  staged rollout apply SERVERS first, rules second: an old, not-yet-upgraded
  server restarting under the new rules reads a `0` stamp even on an anchored
  database and pages `YuzuAuditRetentionNeverRan` with a fresh-install story
  that is false for it (see the runbook's rollout note). The same
  re-apply also removes an `on(instance)` join from the liveness rule, so a
  server that was being silenced by an unrelated series sharing its `instance`
  value (a canary, an HA pair, a federated series) can now correctly fire too -
  the same new-to-you-firing shape as the crash-loop fix, for the same reason.
- **You must ADD a new rule by hand: `YuzuAuditRetentionMetricMissing` (#2553).**
  `YuzuAuditRetentionNotRunning` cannot detect its own input going missing -
  `increase()` over a metric with no series is an empty vector, so the rule selects
  nothing and never fires. A Prometheus holding these rules against a server that
  does not export `yuzu_server_audit_retention_passes_total` therefore reports
  healthy forever while the audit reaper is entirely unmonitored, which is exactly
  the state you are in if you apply this rules file ahead of upgrading your
  servers. The new rule keys on `absent(...)` and fires after 15m. It is
  **fleet-wide by construction**: it cannot see one server among many going quiet.
  **A `up`-based target-down alert does NOT close that gap** — a server that is
  running an older build is alive and scraped, so its `up` is 1; it simply does
  not export this counter. Measured (#2553): in a fleet where one server exports
  the counter and another does not, *neither* retention rule fires, for either
  server, indefinitely. During a staged upgrade the practical mitigation is to
  confirm coverage directly rather than to rely on an alert —
  `count(yuzu_server_audit_retention_passes_total)` against your expected server
  count — until every server is upgraded. A per-target rule for this is tracked
  separately.
- **The first guarded pass now declines when it has no stored reading and rows
  are already expired (#2579).** The stored clock reading (the anchor) is new in
  schema v3, so every database starts its first guarded pass without one. An
  ABSENT reading is not a statement about the clock - it is the ordinary
  fresh-install case - which previously left one shape unguarded: a host already
  skewed FORWARD, where rows written after the skew were still inside the window,
  so the would-expire-everything test did not fire either, and the pass deleted up
  to the 25,000-row cap unremarked. Such a pass now declines ONCE, warns, and
  anchors the reading; the next pass proceeds normally, paced by the cap. A fresh
  install with nothing expired does not decline at all. **Expect at most one such
  decline per server on this upgrade**, counted by the new
  `yuzu_server_audit_retention_bootstrap_declines_total` and NOT by
  `yuzu_server_audit_clock_anomaly_skips_total` - so it does not fire
  `YuzuAuditRetentionClockAnomaly`, and you should not stand that alert down for
  it. Servers upgrading FROM an affected version with a wrong clock may already
  have lost rows; there is no reliable retrospective test, and the loss is not
  recoverable without a backup predating it. Detail:
  [audit-log.md § The retention clock
  guard](audit-log.md#the-retention-clock-guard).
- **Expect a first-pass retention decline on the AGENT, and only conditionally on
  the server.** The two guards differ here and the difference matters:
  - **TAR declines on a missing anchor, by design.** It checks per warehouse
    table, so on an agent upgrade every enabled time-based table declines in that
    same pass and `retention_guard_declines_total` rises by the number of those
    tables (5-10 on a default agent), not by 1. That is the benign bootstrap
    case, not a fleet of separate anomalies, and it needs no action.
  - **The audit store's triggers are NOT the same**, so do not carry the agent's
    expectation across to it and do not pre-emptively stand down
    `YuzuAuditRetentionClockAnomaly` on a fleet upgrade. If one fires, work it as
    an alert rather than assuming a benign bootstrap:
    [audit-log.md § The retention clock guard](audit-log.md#the-retention-clock-guard)
    states when the server's guard declines, and
    [the ops runbook](../ops-runbooks/audit-store-clock-guard.md) is the response
    path.
- **Agents surface new `tar status` lines**: `storage_state`,
  `retention_guard_declines_total`, `retention_guard_failures_total`, and
  per-table detail. On the healthy path `storage_state|ok` is the first line,
  and existing consumers filter on the `config|` prefix and ignore unknown
  lines, so nothing breaks. **On the offline path they do break**: when the TAR
  database has been closed after a wedged rollback, `tar status` returns
  non-zero and emits only an `error|` line followed by `storage_state|offline` -
  no `record_count`, no `config|` lines at all. Note the order is REVERSED
  there: `error|` comes first, because server and dashboard consumers key off
  the output starting with `error|`. A consumer keyed on the presence of
  `record_count` must handle that. See
  [tar.md](tar.md#the-retention-clock-guard). TAR persists its own clock reading
  in `tar_config` (`retention_guard_last_pass`) - no schema change.
- **TAR row-count retention is now paced.** Its ceiling semantics are unchanged,
  but a large excess (after a long disable, or an upgrade backlog) drains over
  several 900 s rollup ticks rather than in one statement.
- **`ApiTokenStore` gains a THIRD, independent clock guard (#2964) — the
  rotation sweep that auto-revokes rotation predecessors.** Same shape as the
  audit store's, same schema-migration pattern (a new `rotation_retention_meta`
  key/value table holding the durable anchor), same bootstrap-decline
  consequence, but a much shorter cadence: this sweep ticks every 60 seconds,
  not hourly. **If you are upgrading a populated store that already has
  elapsed, not-yet-swept rotation pairs** — a predecessor whose overlap
  window has already ended, sitting there because nothing has run the guard
  against it before — **expect the sweep's first tick after the migration to
  decline once**, the same "no durable anchor yet, and there is already
  something eligible" bootstrap case #2579 describes for the audit store.
  Both credentials in every affected pair simply stay active for that one
  tick; the very next tick has an anchor and proceeds normally, so at a
  60-second cadence this resolves in roughly two minutes, not the audit
  store's next-hourly-pass timescale. Nothing is lost or at risk here (an
  auto-revoke deferred by one tick is the intended failure mode, not the
  audit store's deletion-risk case) — this is a heads-up so the log line and
  the one-off decline are not mistaken for something wrong with the upgrade.
  See `docs/user-manual/metrics.md` "Rotation-sweep clock guard metrics" and
  `docs/ops-runbooks/rotation-sweep-clock-guard.md`.

New Prometheus alert rules ship in `docs/prometheus/yuzu-alerts.yml`, which is the
current set. The declined-pass and failed-pass
counters must be alerted on separately: both leave rows undeleted, so an audit
table that never shrinks looks identical either way. One rule,
`YuzuAuditRetentionNotRunning`, fires on the reaper NOT running - the state in
which none of the other counter-driven rules can fire, because they all key on a
counter rising.

### SLE — the `SoftwareLicensing` securable auto-grants on upgrade (ADR-0024)

This release adds the **SLE** (Software Licensing & Entitlements) **discovery** surface,
gated on a new **`SoftwareLicensing`** RBAC securable. Per **ADR-1005** the server ships
the discovery mechanism only: the per-device **`GET /api/v1/sle/agents/{id}`** drill, its
machine-scope MCP twin `query_software_licenses`, and the audited erasure
**`DELETE /api/v1/sle/agents/{id}`**. The licence **compliance / entitlement / reclamation**
views and the fleet **posture** reads (a `/sle` page and `/api/v1/sle/summary` ·
`/licenses` · the per-product device fan-out) **interpret** discovered facts and ship with
the future **SAM use-case-engine module** — they are *not* in this release, so a reader
who saw the earlier ADR expecting an in-server compliance page should not look for one yet.
Because RBAC role defaults are seeded with `INSERT OR IGNORE` on **every** boot, an
upgrading deployment **silently auto-grants** the new securable to the built-in roles the
first time it starts the new build:

| Role | Grant |
|---|---|
| Viewer, PlatformEngineer | Read |
| Operator | Read + Write |
| ITServiceOwner, Administrator | full CRUD |
| ApiTokenManager | none |

**No action is required** if that matches your intent — the securable gates the SLE
discovery reads/erasure (`GET`/`DELETE /api/v1/sle/agents/{id}` and the MCP twin); the
`/inventory` software catalog is unchanged and remains under `Inventory:Read`.

**But** the per-device drill exposes each endpoint's **detected-licence facts** —
product, vendor, channel, status, expiry, and, on per-user surfaces, the per-user
**`user_ref`** identifier — **to every Read holder, including `Viewer`**. **A deployment
that must restrict this visibility should deny or remove the `SoftwareLicensing` Read
grant from `Viewer` (and any other broad role) BEFORE enabling the SLE sources.** A
**deny rule wins** over the seeded allow (deny-override), so an explicit deny is the
durable control — re-seeding on the next boot cannot re-open it. (Entitlement/purchase
**cost** metadata is *not* served in-server this release — it is the SAM UCE module's,
governed by that module's own RBAC when it ships.)

The SLE detection source also collects a new, suppressible **per-user identifier**
(`user_ref`) on per-user licence surfaces. It defaults to a per-device keyed-HMAC
pseudonym; see [Software licence detection](software-licensing.md) for the
`--license-scan-user-ref` flag, the honest limits of that default, and the
`--inventory-disable` source-level opt-out.

### Gateway distribution cookie now required (#659) — **BREAKING**

The Erlang gateway shipped a hardcoded default distribution cookie
(`yuzu_gw_secret_change_me`). The cookie is the sole authentication for
inter-node RPC, so a publicly-known value is unauthenticated remote code
execution for anyone who can reach EPMD (TCP 4369). The gateway now **refuses to
boot** with the default (or an empty/unsubstituted) cookie unless explicitly
overridden.

**Before upgrading:**

- **`.deb` / `.rpm` installs** auto-generate a unique cookie into
  `/etc/yuzu/gateway.env` (mode `0640`, `root:yuzu-gw`) on first install and
  never clobber it on upgrade — no action needed for a single node.
- **Tarball / manual systemd installs** must create the env file once:
  ```bash
  sudo install -d -m 0755 /etc/yuzu
  printf 'YUZU_GW_COOKIE=%s\n' "$(openssl rand -hex 32)" | sudo tee /etc/yuzu/gateway.env >/dev/null
  sudo chown root:yuzu-gw /etc/yuzu/gateway.env && sudo chmod 0640 /etc/yuzu/gateway.env
  ```
  The systemd unit loads it via `EnvironmentFile=-/etc/yuzu/gateway.env`.
- **Docker / Compose** deployments must set `YUZU_GW_COOKIE` in the gateway
  service environment (e.g. `export YUZU_GW_COOKIE=$(openssl rand -hex 32)` then
  reference it). Dev/CI may instead set `YUZU_GW_ALLOW_DEFAULT_COOKIE=1`.
- **Multi-node clusters:** every node must share the **same** cookie — set an
  identical `YUZU_GW_COOKIE` (or write the same `/etc/yuzu/gateway.env`) on all
  nodes; the per-host auto-generated value will NOT match across hosts.

**Recovery — gateway won't start after upgrade:**

| Symptom | Diagnose | Fix |
|---|---|---|
| `systemctl status yuzu-gateway` shows `start-limit-hit` / `failed` | `journalctl -t yuzu-gateway \| grep -i cookie` shows "insecure distribution cookie" (for manual/`foreground` or container runs, check stdout / `gateway.log` instead) | Create `/etc/yuzu/gateway.env` with `YUZU_GW_COOKIE=$(openssl rand -hex 32)` (see above), then `systemctl reset-failed yuzu-gateway && systemctl start yuzu-gateway`. **Do not** use `YUZU_GW_ALLOW_DEFAULT_COOKIE=1` in production. |

> The generated `/etc/yuzu/gateway.env` is intentionally **preserved across
> `apt purge` / `rpm -e`** (the `/etc/yuzu` directory may be shared with other
> Yuzu packages). To remove the cookie after uninstall: `sudo shred -u /etc/yuzu/gateway.env`.

> **Never set `YUZU_GW_ALLOW_DEFAULT_COOKIE=1` in production** — it disables the
> guard and restores the unauthenticated-RPC surface. It exists only for
> ephemeral dev/CI stacks.

### InstructionDefinition import signature enforcement now on-by-default (#1073 / W7.4 sibling-gap) — **BREAKING**

`InstructionStore::import_definition_json` (the storage path behind
`POST /api/instructions/import`) previously accepted unsigned JSON
envelopes without verification. After upgrade, unsigned imports are
rejected with:

```
instruction-import is unsigned and signature enforcement is enabled (set --allow-unsigned-definitions / YUZU_ALLOW_UNSIGNED_DEFINITIONS=1 to bypass)
```

This is intentional and closes the sibling-gap to #802. Without the
gate, any operator with `InstructionDefinition:Write` permission can
import a definition that dispatches an arbitrary plugin invocation on
every targeted agent — same fleet-RCE blast radius the pack-signing
default closed.

**Two migration paths, in order of preference:**

1. **Sign your imports.** Generate an Ed25519 keypair, sign the
   `yaml_source` field's bytes with the private key, and wrap the
   envelope with `signature: <hex>` + `publicKey: <hex>` top-level
   fields. The wire format mirrors ProductPack: signature is hex-
   encoded over the verbatim `yaml_source` bytes; `publicKey` is the
   hex-encoded raw Ed25519 public key (32 bytes / 64 hex chars).
   Until the dedicated helper script lands (tracked as a follow-up
   issue covering both pack-signing and definition-signing tooling),
   use the raw `openssl` recipe directly:

   ```bash
   # One-time: generate a keypair (rotate periodically per your policy).
   openssl genpkey -algorithm Ed25519 -out yuzu-signing.pem
   openssl pkey -in yuzu-signing.pem -pubout -outform DER \
       | tail -c 32 | xxd -p -c 64    # → 64-hex publicKey

   # Per definition: sign yaml_source bytes, hex-encode the output.
   echo -n "$YAML_SOURCE" \
       | openssl pkeyutl -sign -inkey yuzu-signing.pem -rawin \
       | xxd -p -c 128                # → 128-hex signature
   ```

   Inject `signature` and `publicKey` as top-level string fields in
   the JSON envelope POSTed to `/api/instructions/import`. See the
   REST API reference (`docs/user-manual/rest-api.md` →
   `POST /api/instructions/import`) for the full signing-rules table
   and per-rejection error strings.

2. **Opt out temporarily** (legacy environments only). Pass
   `--allow-unsigned-definitions` to `yuzu-server` or set
   `YUZU_ALLOW_UNSIGNED_DEFINITIONS=1` in the service environment. The
   server emits an `InstructionStore: signature enforcement DISABLED
   by configuration` warning on every start AND a
   `server.unsigned_definitions_allowed` audit row at boot, so the
   relaxed posture is recoverable from both operator logs and the
   audit store. **Remove the flag** as soon as the signing migration
   completes.

**Pre-existing imported definitions are unaffected.** The gate fires
only on the public import path. The bundled-content boot seed (the
`kBundledDefinitions` baked into `yuzu-server` at build time) routes
through an internal `import_definition_json_trusted` variant that
bypasses the gate; its authenticity comes from binary linkage, not
runtime signature.

**Authoring surfaces are NOT gated.** `POST /api/instructions`,
`POST /api/instructions/yaml`, and `PUT /api/instructions/{id}` — the
dashboard and CLI surfaces where operators author definitions in-
session — continue to trust `InstructionDefinition:Write` as the
author trust boundary (the operator IS the source; there is no
supply chain to authenticate). The `--allow-unsigned-definitions`
flag does NOT affect those surfaces; they have always accepted
unsigned author-time input and continue to. The architectural
question of whether authoring surfaces should ALSO require signed
envelopes is tracked as a follow-up issue with operator-decision-
required framing (UX trade-off: gating authoring would break in-
browser definition authoring).

**Audit-trail evidence chain.** Every rejection emits an
`instruction.import / denied` audit row with the store error string
in `detail` (stable SIEM-keyable tokens listed in the
`audit-log.md` reference). If the audit-store write itself fails
(locked DB, disk full), the response carries `Sec-Audit-Failed: true`
header AND `audit_emitted: false` in the JSON body, surfacing the
SOC 2 CC7.2 evidence gap to the operator immediately rather than
silently dropping the event.

### Product pack signature enforcement now on-by-default (#802 / W7.4) — **BREAKING**

The `ProductPackStore` previously shipped with signature enforcement
**disabled** by default and the setter to enable it was never wired to
any operator-facing flag — the protection was effectively unreachable.
After upgrade, calls to install a `ProductPack` without a `signature:`
field are rejected with:

```
pack '<name>' is unsigned and signature enforcement is enabled (set --allow-unsigned-packs / YUZU_ALLOW_UNSIGNED_PACKS=1 to bypass)
```

This is intentional. Unsigned packs are a fleet-wide arbitrary-code-
execution surface: any operator with `Pack:Install` permission, or a
MITM on pack delivery, could install a pack containing
`InstructionDefinition` or plugin payloads that would then execute on
every enrolled agent.

**Two migration paths, in order of preference:**

1. **Sign your packs.** Generate an Ed25519 keypair, sign each pack's
   non-metadata YAML content with the private key, and add
   `signature: <hex>` + `publicKey: <hex>` fields to each pack's
   `ProductPack` metadata document. The existing verify path
   (`ProductPackStore::verify_signature`) accepts the result. Pack
   install then succeeds and the `verified` column in the store is set
   to true so a future "show only verified packs" query has the data
   it needs.

2. **Opt out temporarily** (legacy environments only). Pass
   `--allow-unsigned-packs` to `yuzu-server` or set
   `YUZU_ALLOW_UNSIGNED_PACKS=1` in the service environment. The
   server emits a `[SECURITY] product pack signature enforcement
   DISABLED by configuration` warning on every start and writes a
   `server.unsigned_packs_allowed` audit row, so the relaxed posture
   is recoverable from both operator logs and the audit store.
   **Remove the flag** as soon as the pack-signing migration completes;
   it is not intended as a permanent configuration.

**Pre-existing installed packs are unaffected.** The check fires only
on the install path (`POST /api/product-packs`). List, get, and
uninstall paths do not re-verify, so already-installed unsigned packs
remain queryable and uninstallable after upgrade.

### Executions-history PR 2 — `responses.execution_id` exact correlation

PR 2 of the executions-history ladder closes a forensic-data correctness
gap (UP-8) where two concurrent executions of the same definition to
overlapping agent sets could show each other's responses in the
Instructions → Executions detail drawer. Operators upgrading to a
release that includes PR 2 should expect the following:

**Schema migration v2 on `response_store`.** The migration adds an
`execution_id TEXT NOT NULL DEFAULT ''` column to the `responses` table
plus a partial index `idx_resp_execution_ts ON responses(execution_id,
timestamp) WHERE execution_id != ''`. The migration is automatic and
data-preserving — `MigrationRunner::run` wraps the ALTER + CREATE INDEX
in a single transaction. Pre-upgrade rows are NOT deleted; they receive
the empty-string sentinel value `''`. The migration is idempotent: a
pre-stamp probe at startup detects an already-altered DB and skips the
duplicate ALTER (mirrors the precedent at `instruction_store.cpp` v2).

Observable after upgrade:

```sql
SELECT execution_id, COUNT(*) FROM responses GROUP BY execution_id;
```

will show ALL pre-upgrade rows under the empty string `''`. This is
expected — there's no way to retroactively attribute pre-upgrade
responses to executions because the dispatch path didn't record the
linkage. The Executions drawer detects empty-`execution_id` rows and
falls back to the legacy timestamp-window-plus-agent-set join so they
render correctly without operator action. **No operator action
required** for the migration itself.

**Dispatch-path coverage gap (PR 2.x follow-ups).** Only executions
dispatched via `POST /api/instructions/:id/execute` (the dashboard's
Execute Instruction form goes through this path) get exact correlation
in PR 2. Three dispatch surfaces continue to write rows with
`execution_id=''` until follow-up PRs close them:

- **MCP `execute_instruction`** — agent dispatches issued through the
  MCP protocol.
- **Workflow steps** (`POST /api/workflows/:id/execute` step dispatch
  via `cmd_dispatch` callback) — multi-step workflows.
- **Scheduled / approval-triggered dispatches** — the dispatch path
  inside `schedule_engine` / approval-fired execution.
- **Reruns** (`/api/executions/:id/rerun`) — `create_rerun` creates
  the execution row but does not dispatch; the operator-triggered
  follow-up dispatch will be wired in PR 2.x.

For runs from these surfaces, the drawer's responses section uses the
legacy timestamp-window join. Cross-execution contamination (UP-8) is
still possible if two such runs overlap on the same definition + agent
set. Track via the executions-history follow-up issues.

**Mixed-mode detail drawer behaviour.** During an upgrade transition
window (executions in flight at restart time, or in-progress executions
that started pre-upgrade and finished post-upgrade), some responses for
a single execution may carry `execution_id=''` while others are
correctly tagged. The drawer prefers exact-correlation rows when they
exist and only falls back to the legacy join when zero exact rows are
returned — this means **mixed-mode runs may show only the
post-upgrade subset of their responses** in the drawer. Pre-upgrade
responses for those runs remain in the database and are queryable via
SQL; the upcoming admin backfill CLI (PR 2.1) will stamp them with
their correct execution_id once it ships.

**Server restart caveat.** The dispatch-time `command_id → execution_id`
mapping is held in memory inside `AgentServiceImpl`. If the server is
restarted while a command is in flight, the mapping is lost and any
agent responses arriving post-restart will be tagged `execution_id=''`
and use the legacy fallback. Avoid restarting the server during active
executions where possible, or accept that the affected runs will use
legacy correlation.

**Admin backfill (planned in PR 2.1, not in this release).** A
`yuzu-server admin backfill-responses` CLI is filed as a follow-up. It
will walk the executions table cross-store and stamp pre-upgrade
responses with their best-effort execution_id (timestamp + agent set
heuristic). Until it ships, pre-upgrade rows remain queryable via the
legacy fallback in the drawer; no operator action is required.

**Verifying the migration.** After upgrade, the server log should
contain `MigrationRunner: response_store migrated to v2`. To verify the
column directly:

```bash
sqlite3 /var/lib/yuzu/responses.db ".schema responses"
# Expected: execution_id TEXT NOT NULL DEFAULT ''
sqlite3 /var/lib/yuzu/responses.db ".schema idx_resp_execution_ts"
# Expected: CREATE INDEX idx_resp_execution_ts ON responses(...) WHERE execution_id != ''
```

### v0.12.0 — AuthDB persistent authentication (#618)

v0.12.0 replaces the in-memory + on-config-flush authentication model
with a SQLite-backed `auth.db` that holds user accounts, sessions, and
enrollment tokens.

**First boot after upgrade:**

- The server probes `--data-dir` for `auth.db`. If absent, it creates
  the file with mode `0600` (Linux) or restricted ACL (Windows), runs
  the initial schema migration via `MigrationRunner`, then seeds users
  from `yuzu-server.cfg`. Subsequent boots read from `auth.db`
  directly; the config file is no longer the live source of truth.
- The seed is one-shot. Editing `yuzu-server.cfg` after first boot
  does NOT re-seed users into `auth.db` — use the dashboard or
  `POST /api/settings/users` instead.
- Existing in-flight sessions are NOT preserved across the upgrade
  (sessions live in memory before this release; `auth.db` starts fresh
  on first boot). Operators must log in again.

**`role` parameter ignored on `POST /api/settings/users`.** New users
are always created as `user` (security finding C1). To assign or
change a role, use the dedicated `POST
/api/settings/users/{username}/role` endpoint introduced in v0.12.0
(see [REST API → Settings → User Management](rest-api.md#settings--user-management)).
The dashboard exposes a **Change Role** button on each user row that
calls the new endpoint.

**Live drawer updates via SSE.** The Executions tab opens an
`EventSource` to `/sse/executions/{id}` for in-progress runs. Reverse
proxies in the request path must NOT buffer SSE — the server emits
`X-Accel-Buffering: no` and `Cache-Control: no-cache` but a poorly-
configured proxy can still chunk the stream. Verify with
`curl -N https://<server>/sse/executions/<id>` from inside your
network if the drawer freezes mid-execution.

**`LimitNOFILE=65536` on systemd units.** v0.12.0 raises the systemd
file-descriptor limit from the default 1024 to 65536. SSE
connections + agent gRPC streams + SQLite WAL handles can saturate
the default soft limit on busy fleets. The new value matches Docker
compose's `ulimits.nofile` so containerised and bare-metal deployments
behave identically.

**Restart-loop guard.** `StartLimitIntervalSec=60` +
`StartLimitBurst=3` in the systemd `[Unit]` section so a corrupt
`auth.db` failing the integrity check at startup puts the unit
cleanly into `failed` instead of spinning. Recovery procedure:
[`docs/ops-runbooks/auth-db-recovery.md`](../ops-runbooks/auth-db-recovery.md).

**Rollback to a pre-AuthDB release** (only if you have not yet
written user state via the new dashboard):

1. Stop the v0.12.0 server.
2. Move `auth.db` aside (`mv auth.db auth.db.v0.12.0`).
3. Restore `yuzu-server.cfg` from your pre-upgrade backup.
4. Reinstall the prior release binary.
5. Start the server. It reads `yuzu-server.cfg` as before.

If you HAVE written user state via v0.12.0's dashboard, that state
is in `auth.db` only — rolling back loses it. Export users via
`GET /api/v1/settings/users` first if rollback is required.

### v0.12.0 — Guardian PR 2

Guardian PR 2 ships the Guaranteed State control plane + agent skeleton. Two items require operator awareness on upgrade:

**Stale `*:Push` RBAC grants on deployments that ran pre-hardening Guardian PR 2 code.** Between commits `7c83911` and `1f39401`, the RBAC seed granted the `Push` operation to `Administrator` and `ITServiceOwner` on **every** securable type, not just `GuaranteedState`. The H-4 fix (commit `21c0ba4`, hardening round 2) restricted the seed to `GuaranteedState` only going forward — but because `seed_defaults()` uses `INSERT OR IGNORE`, the stale cross-type grants already written to `role_permissions` are not removed on upgrade. These grants are semantically inert today (only the Guardian REST handlers consult `Push`), but become a latent privilege for any future release that adds a non-Guardian handler checking `perm_fn(..., "Push")`.

Manual remediation until the auto-migration in issue #485 lands. **Run each step in order:**

1. **Back up the RBAC database first.** Destructive SQL with no rollback.

   ```bash
   docker exec yuzu-server cp /var/lib/yuzu/rbac.db /var/lib/yuzu/rbac.db.bak.$(date +%Y%m%d)
   # or for a systemd install:
   cp /var/lib/yuzu/rbac.db /var/lib/yuzu/rbac.db.bak.$(date +%Y%m%d)
   ```

2. **Preview the rows that will be deleted.** This should return only `Administrator` and `ITServiceOwner` rows on a fresh Guardian PR 2 upgrade. If it returns rows for any other principal_id, you have custom RBAC grants that the bulk `DELETE` below would silently wipe — in that case stop and prune by hand.

   ```bash
   docker exec -i yuzu-server sqlite3 /var/lib/yuzu/rbac.db \
     "SELECT principal_id, securable_type FROM role_permissions \
       WHERE operation = 'Push' AND securable_type != 'GuaranteedState' \
       ORDER BY principal_id, securable_type;"
   ```

3. **Delete the stale grants.** Scoped to the two seeded roles so custom grants are left alone:

   ```bash
   docker exec -i yuzu-server sqlite3 /var/lib/yuzu/rbac.db \
     "DELETE FROM role_permissions \
       WHERE operation = 'Push' \
         AND securable_type != 'GuaranteedState' \
         AND principal_id IN ('Administrator', 'ITServiceOwner');"
   ```

4. **Confirm cleanup:** re-run the preview query from step 2 — zero rows expected.

Safe on fresh installs (no matching rows). If you are upgrading **from** a v0.11.x release directly **to** v0.12.0 or later, skip this entire sub-section — your RBAC database never carried the stale grants.

**Retention changes take effect on restart, not on runtime PUT.** BL-2 wired `--guardian-event-retention-days` (default 30) through `RuntimeConfigStore` + `PUT /api/config/guardian_event_retention_days`, matching the existing `response_retention_days` and `audit_retention_days` pattern. However, all three retention-bearing stores (`AuditStore`, `ResponseStore`, `GuaranteedStateStore`) capture their retention value at construction time and never re-read it — the runtime PUT mutates `cfg_` and `RuntimeConfigStore` but the running reaper continues using the startup value. An operator who PUTs a new retention value sees `200 {"applied": true}` but the store behaviour does not change until the next server restart. This is a systemic limitation shared across all three stores, not a Guardian-specific bug; it is tracked as issue #483.

**Runtime config PUT now rejects non-numeric and negative integer values with HTTP 400.** Hardening round 4 (UP-R5) added `std::from_chars` validation to `PUT /api/config/<key>` for `heartbeat_timeout`, `response_retention_days`, `audit_retention_days`, and `guardian_event_retention_days`. The previous handler silently wrote invalid strings to `RuntimeConfigStore` and swallowed the `stoi` error, leaving `cfg_` unchanged. If your automation relied on setting retention to a **negative** value (e.g., `"-1"`) to disable retention — which the store then treated as "never reap" via the `<= 0` sentinel — that automation will now receive `400 {"error":{"code":400,"message":"value must be a non-negative integer"}}`. Use `"0"` instead **only for `guardian_event_retention_days`**, where it preserves the disable-retention semantic and passes validation. For `heartbeat_timeout`, `response_retention_days` and `audit_retention_days` the store applies its own `> 0` check *after* the route's, so `"0"` is also rejected - with a different, bare-shaped body, `{"error":"value must be a positive integer"}`. There is no supported way to disable retention for those three through this endpoint. Automation that previously set non-numeric strings (anything other than a base-10 integer) was silently a no-op before this release — the 400 now surfaces the configuration error that had been hidden.

### v0.12.0 — A3 UX ladder (#620, #622, #624)

Three operator-visible behaviour changes ship in the v0.12.0 A3 ladder. None require code changes on the operator side, but two of them require **action if you maintain a local compose override**:

**1. Container healthchecks now pass (#622).** The shipped `docker-compose.uat.yml` healthcheck blocks were updated to use tools available in each runtime image (`bash` + `/dev/tcp` for the server; busybox `wget --spider` for the gateway). After upgrade, `docker compose ps` reports `(healthy)` instead of `(unhealthy)`.

> **If you maintain a local copy of the compose file** (e.g. `docker-compose.local.yml` or a pinned vendored copy), your override still uses the broken pre-fix healthcheck pattern and will continue showing `(unhealthy)` until you sync the change. Replace your server-service healthcheck stanza with:
>
> ```yaml
>     healthcheck:
>       test:
>         - "CMD"
>         - "bash"
>         - "-c"
>         - "exec 3<>/dev/tcp/localhost/8080 && printf 'GET /livez HTTP/1.0\\r\\nHost: localhost\\r\\n\\r\\n' >&3 && grep -q '200 OK' <&3 ; rc=$? ; exec 3>&- ; exit $rc"
> ```
>
> And the gateway-service healthcheck stanza with:
>
> ```yaml
>     healthcheck:
>       test: ["CMD", "wget", "--spider", "-q", "http://localhost:8081/healthz"]
> ```

**2. `/api/health` is restored as an alias of `/health` (#620).** The pre-#401 endpoint path is back. Monitoring integrations that point at `/api/health` work without reconfiguration; both URLs serve identical JSON. Both are exempt from rate limiting (a follow-up hardening over the bare `/health` behaviour). For load-balancer probes that should drain in-flight traffic before stopping, continue using `/readyz` — `/health` and `/api/health` are intentionally not draining-aware (Kubernetes pattern: liveness/health probes are not draining-aware).

**3. File-logger boot messages are now quieter (#624).** The previous `WARN: Could not create log directory /var/log/yuzu` + `ERROR: file logger setup failed` pair on every container boot is replaced by a single INFO-level line when the default path cannot be created. The Docker server image now pre-creates `/var/log/yuzu` (mode 0750, owned by `yuzu`) so the path is writable out of the box. **If your monitoring previously alerted on the WARN/ERROR lines as a misconfig signal, those signals will no longer fire** — the failure mode is now a single INFO line. Operators who require explicit on-disk logs should pass `--log-file <path>`; explicit-path failures still log at ERROR and are not silently degraded.

## Rollback

If an upgrade causes issues:

1. Stop the new version
2. Restore the backed-up `.db` and `.cfg` files
3. Start the previous version binary

**Important:** Rolling back after a schema migration requires restoring the database files from backup. The old binary cannot read the new schema.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Server won't start after upgrade | Schema migration failure | Check logs, restore backup, report issue |
| Agents can't connect | Protocol version mismatch | Ensure server was upgraded first |
| Dashboard shows errors | Browser cache | Clear browser cache, hard refresh |
| Gateway disconnects | Version mismatch with server | Upgrade gateway to match server version |
| Slow startup | Large database migration | Normal for first start; wait for migration to complete |
