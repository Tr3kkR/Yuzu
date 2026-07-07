# Postgres migration ladder — existing server stores

The committed end state (ADR-0006, 2026-06-22 Update) is that **every** server-side store reaches
PostgreSQL — none stays on SQLite. The agent stays SQLite. This is the ordered queue. It is
**mutable state that drains over time**, not a contract; the timeless how-to is
`docs/postgres-store-playbook.md` and the contract is ADR-0012.

Each row migrates behind **its own per-store ADR + PR** (ADR-0006). Ordering follows the ADR-0006
priorities: cross-store-join + durable + high-write stores first; security/authz authoritative
stores next; trivial config and secret-gated stores last. **Posture and secret columns below are
provisional** — each is finalized in that store's per-store ADR after reading the code.

Schema name = `snake_case(FullClassName)` incl. the `Store` suffix (ADR-0008 Update).

## Done

| Store | Schema | Notes |
|---|---|---|
| `OfflineEndpointStore` | `offline_endpoint_store` | First born-on-Pg store (#1320 PR 3). **Schema rename pending**: ships today as `endpoint_state`; renamed to conform to the ADR-0008 naming rule (safe pre-alpha — data reconstructs from heartbeats). Construction fail-closed (ADR-0012 §1); runtime durability-on-top. |
| `SoftwareInventoryStore` | `software_inventory_store` | Born-on-Pg (ADR-0016). Typed projection for the daily-sync `installed_software` source (normalized rows, no JSONB). authoritative reads; ingest fail-soft (next sync + weekly floor self-heal). **Coexists with the generic `InventoryStore` (Wave 1 below) — it is NOT that store's migration.** |
| `AppPerfFleetStore` | `app_perf_fleet_store` | Born-on-Pg (DEX app-perf-over-time B2). Fleet aggregate `(app, version, day)` + fixed-bucket CPU/WS histogram + device_count, 180-day retention (the trend window). **Single-schema owner** — it does NOT write itself; the B1→B2 roll-up is the dedicated cross-store query owner `AppPerfRollup` (ADR-0012 §3 seam: one lease, schema-qualified `INSERT … SELECT` spanning `app_perf_daily_store` → `app_perf_fleet_store`). authoritative reads; derived aggregate (rebuilt by the next roll-up). No `agent_id` (no per-device attribution). No backfill (greenfield). |
| `AppPerfDailyStore` | `app_perf_daily_store` | Born-on-Pg (DEX app-perf-over-time B1). Typed per-device daily app-version perf projection for the daily-sync `app_perf` source (plain table, PK `(agent_id, app_name, version, day)`, 31-day per-agent prune, no JSONB). authoritative reads; ingest fail-soft. **Hash-less** (perf changes daily → no hash-skip), so unlike `SoftwareInventoryStore` it stores no content hash and a hash-only report is answered `need_full`. No backfill (greenfield). |
| `VulnFindingStore` | `vuln_finding_store` | Born-on-Pg (ADR-0023 M1a, vuln-scan CAVM). Typed CVE-findings projection + per-agent assessment-coverage tallies (`finding` PK `(agent_id, cve_id, package_name)` with `resolved_at_ms IS NULL` = open; `agent_coverage` PK `(agent_id)`). Construction fail-closed (ADR-0012 §1); runtime durability-on-top. `reconcile_agent` runs one agent's matching pass in ONE txn: per-agent advisory lock (namespaced `hashtextextended('vuln_finding_store:'||agent,0)` — disjoint from `SoftwareInventoryStore`'s bare key on the same agent) → in-txn **monotonic run_ts** (NTP-step-back safe) → upsert-always → **authoritative-gated** disappear-sweep + `disposed_clean` delete + coverage clobber (keep-last-good on a suspect/partial pass). **UP-2 backstop**: an authoritative pass observing NOTHING against a prior-open agent is demoted to non-authoritative so a producer bug can't mass-false-resolve the fleet. Timestamps are epoch **ms** (SoftwareInventoryStore is **seconds** — never cross the boundary). AUTHORITATIVE reads (coverage tri-state Ok/NotFound/Degraded; `fleet_summary` nullopt-on-degrade, GLOBAL Vuln:Read gated in PR 6). **DORMANT until PR 4** (constructed + wired into /readyz + /healthz; no engine calls `reconcile_agent` yet). No backfill (greenfield). |
| `PreflightRunStore` | `preflight_run_store` | Born-on-Pg (ADR-0006). Persists `/auto` pre-flight run metadata, the frozen target cohort, and the computed per-device check grid (`runs` + `run_device`, FK cascade). Construction fail-closed (ADR-0012 §1: `!is_open()`→`startup_failed_`); runtime durability-on-top (a transient lease error degrades /auto to a note). 14-day retention via best-effort prune in the background runner; owner-scoped reads. Concurrency/lifecycle contract: the background `PreflightRunner` (60 s tick, tick wrapped try/catch → `yuzu_preflight_tick_errors_total`) is joined BEFORE the stores in `server.cpp` `stop()`; it re-dispatches the READ-ONLY checks to not-yet-answered FROZEN targets until the window closes — **safe ONLY because every check is read-only/idempotent; any future MUTATING check must re-resolve `devices_fn(creator)∩group` per dispatch, never reuse the frozen cohort**. Pure `compute_device_results` is the single verdict path; BOTH the result route and the runner persist the grid + complete via the shared `preflight::persist_and_maybe_complete` — the store's `complete_run` CAS is the single completion authority, a run completes **only on persist success** (UP-1), and `persist_grid` is status-guarded so a stale route-persist can't overwrite a completed run's final grid. |
| `DeploymentRunStore` | `deployment_run_store` | Born-on-Pg (ADR-0006). Persists the `/auto` DEPLOY stage — a deployment's artifact spec + source pre-flight run + the per-device stage→execute **state machine** (`deployments` + `deployment_device`, FK cascade). Construction fail-closed (ADR-0012 §1); runtime durability-on-top. Unlike PreflightRunStore it does NOT recompute a grid — it exposes **guarded one-way transitions**, and `claim_for_exec` (staged→executing `RETURNING`) is the **execute-once CAS** (the installer runs at most once per device across concurrent advances / restart). Owner-scoped reads; 14-day prune. The `deployment::advance` engine ticks: poll stage+exec responses → guarded transitions → mark out-of-scope skipped → CAS-claim+dispatch stage(pending) then execute(staged) → refresh counts → complete-if-settled (settled-check IN SQL). **ANY future store mutation must stay a guarded transition (never an unconditional grid overwrite) or the execute-once guarantee breaks.** |

## Wave 1 — cross-store-join / durable / high-write

These feed the vuln-graph scoring join (the headline ADR-0006/0004 benefit) or carry
high write volume or durable state. Migrate first; they also exercise the cross-store
query-owner seam (ADR-0012 §3) when scoring lands.

| Store | Schema | Provisional posture | Notes |
|---|---|---|---|
| `InventoryStore` | `inventory_store` | authoritative | Generic per-source blob store (backs the `kInventoryQuery` scope source + eval engine). Still SQLite. **Note:** the typed `installed_software` projection already went born-on-Pg as `SoftwareInventoryStore` (ADR-0016, Done above); this row is the *generic* store's own migration, still pending. vuln-graph join input; high-write. |
| `GuaranteedStateStore` | `guaranteed_state_store` | authoritative | Guardian state; high-write; join input. Uses `SqliteTxn`/`SqliteStmt` today. |
| `FleetTopologyStore` | `fleet_topology_store` | authoritative | durable topology; viz; join-adjacent. |
| `ResponseStore` | `response_store` | durability-on-top? | high-write, TTL'd 90d; backfill **skippable** (ADR-0009). |
| `ResultSetStore` | `result_set_store` | authoritative | scope-walking; inherently cross-store. |
| `AuditStore` | `audit_store` | authoritative | SOC 2 retained 365d; backfill **mandatory**. |

## Wave 2 — authoritative config / reference (operator state that cannot be lost)

Security/authz and operator-authored state. Authoritative; a silent empty read is a fail-open
hole — `security-guardian` gates each.

| Store | Schema | Provisional posture | Notes |
|---|---|---|---|
| `RbacStore` | `rbac_store` | authoritative | authz; security-critical. |
| `ManagementGroupStore` | `management_group_store` | authoritative | authz/targeting. |
| `PolicyStore` | `policy_store` | authoritative | compliance evaluation. |
| `BaselineStore` | `baseline_store` | authoritative | Guardian deployable unit; uses `SqliteTxn`/`SqliteStmt`. |
| `TagStore` | `tag_store` | authoritative | scope/targeting. |
| `CustomPropertiesStore` | `custom_properties_store` | authoritative | device facts. |
| `InstructionStore` | `instruction_store` | authoritative | build-time-seeded + operator additions. |
| `ProductPackStore` | `product_pack_store` | authoritative | seeded content. |
| `QuarantineStore` | `quarantine_store` | authoritative | Guardian quarantine. |
| `DeploymentStore` | `deployment_store` | authoritative | |
| `SoftwareDeploymentStore` | `software_deployment_store` | authoritative | |
| `DiscoveryStore` | `discovery_store` | authoritative | |
| `AnalyticsEventStore` | `analytics_event_store` | authoritative? | high-volume; may suit a TTL/ephemeral posture. |
| `NotificationStore` | `notification_store` | authoritative | |
| `LicenseStore` | `license_store` | authoritative | |

## Wave 3 — secret-gated (need the ADR-0010 secrets seam wired)

Migrate last because they require `SecretCodec` (or a verify-only-hash schema) in place. Backfill
**transforms** (encrypt/hash), never copies (ADR-0010).

| Store | Schema | Secret handling | Notes |
|---|---|---|---|
| `ApiTokenStore` | `api_token_store` | hash-only (**unblocked**) | no plaintext column; can move earlier. |
| `CaStore` | `ca_store` | key_ref-only (**unblocked**) | private key behind `KeyProvider`, never in a column. |
| `DeviceTokenStore` | `device_token_store` | verify/hash (confirm in ADR) | classify in its per-store ADR. |
| auth DB (`auth_db.{hpp,cpp}`) | `auth` | `SecretCodec` (TOTP); sessions → SHA-256 verify-only | not a `*Store` class; see `.claude/agents/authdb.md`. |
| `WebhookStore` | `webhook_store` | `SecretCodec` | shared secrets. |
| `OffloadTargetStore` | `offload_target_store` | `SecretCodec` | target credentials. |
| `RuntimeConfigStore` | `runtime_config_store` | `SecretCodec` | secret-valued config keys. |

## Notes

- **`NvdDatabase` (`nvd_db`) — deferred, still SQLite (2026-07-04).** The store was reshaped
  (v1→v2: flat `cve` → normalized `cve` + `cve_match` with full CPE version ranges) but
  **deliberately kept on SQLite** as an eyes-open owner override of the born-on-PG mandate,
  to ship matching precision now; the born-on-PG reshape is vuln-scan roadmap **M1a** and stays
  queued. Recorded here (not a fresh exception ADR — the store is not new) so a control-mapping
  review doesn't read the ladder as silently non-compliant. The normalized header/match split
  maps directly onto the eventual two PG tables, so this reduces migration debt rather than
  adding it.
- The count is ~27 `*Store` classes + the auth DB; the exact set is whatever currently opens a
  `sqlite3*` under `server/core/src/`. Re-derive before declaring the ladder complete:
  `grep -rl "sqlite3_open" server/core/src`.
- A store may be **split** or **merged** during migration if its schema warrants it — record that
  in its per-store ADR.
- When the last row clears, remove the `migration_runner.*` SQLite path from the server target and
  delete this file (its job is done).
