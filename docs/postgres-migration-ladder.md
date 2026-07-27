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
| `VulnFindingStore` | `vuln_finding_store` | Born-on-Pg (ADR-0023 M1a, vuln-scan CAVM). Typed CVE-findings projection + per-agent assessment-coverage tallies (`finding` PK `(agent_id, cve_id, package_name)` with `resolved_at_ms IS NULL` = open; `agent_coverage` PK `(agent_id)`). Construction fail-closed (ADR-0012 §1); runtime durability-on-top. `reconcile_agent` runs one agent's matching pass in ONE txn: per-agent advisory lock (namespaced `hashtextextended('vuln_finding_store:'||agent,0)` — disjoint from `SoftwareInventoryStore`'s bare key on the same agent) → in-txn **monotonic run_ts** (NTP-step-back safe) → upsert-always → **authoritative-gated** disappear-sweep + `disposed_clean` delete + coverage clobber (keep-last-good on a suspect/partial pass). **UP-2 backstop**: an authoritative pass observing NOTHING against a prior-open agent is demoted to non-authoritative so a producer bug can't mass-false-resolve the fleet. Timestamps are epoch **ms** (SoftwareInventoryStore is **seconds** — never cross the boundary). AUTHORITATIVE reads (coverage tri-state Ok/NotFound/Degraded; `fleet_summary` nullopt-on-degrade, GLOBAL Vuln:Read gated in PR 6). **DORMANT until PR 4** (constructed + wired into /readyz + /healthz; no engine calls `reconcile_agent` yet). No backfill (greenfield). **Re-homing note (ADR-1005, 2026-07-07):** grandfathered-interim — scheduled for re-homing into the vuln UCE module and deletion from the server (incl. /readyz unwiring) by the execution plan's Phase-7 strangler; see `docs/adr-1005-execution-plan.md` § "Relationship to ADR-0023 and ADR-4001" before investing further here. |
| `PreflightRunStore` | `preflight_run_store` | Born-on-Pg (ADR-0006). Persists `/auto` pre-flight run metadata, the frozen target cohort, and the computed per-device check grid (`runs` + `run_device`, FK cascade). Construction fail-closed (ADR-0012 §1: `!is_open()`→`startup_failed_`); runtime durability-on-top (a transient lease error degrades /auto to a note). 14-day retention via best-effort prune in the background runner; owner-scoped reads. Concurrency/lifecycle contract: the background `PreflightRunner` (60 s tick, tick wrapped try/catch → `yuzu_preflight_tick_errors_total`) is joined BEFORE the stores in `server.cpp` `stop()`; it re-dispatches the READ-ONLY checks to not-yet-answered FROZEN targets until the window closes — **safe ONLY because every check is read-only/idempotent; any future MUTATING check must re-resolve `devices_fn(creator)∩group` per dispatch, never reuse the frozen cohort**. Pure `compute_device_results` is the single verdict path; BOTH the result route and the runner persist the grid + complete via the shared `preflight::persist_and_maybe_complete` — the store's `complete_run` CAS is the single completion authority, a run completes **only on persist success** (UP-1), and `persist_grid` is status-guarded so a stale route-persist can't overwrite a completed run's final grid. |
| `DeploymentRunStore` | `deployment_run_store` | Born-on-Pg (ADR-0006). Persists the `/auto` DEPLOY stage — a deployment's artifact spec + source pre-flight run + the per-device stage→execute **state machine** (`deployments` + `deployment_device`, FK cascade). Construction fail-closed (ADR-0012 §1); runtime durability-on-top. Unlike PreflightRunStore it does NOT recompute a grid — it exposes **guarded one-way transitions**, and `claim_for_exec` (staged→executing `RETURNING`) is the **execute-once CAS** (the installer runs at most once per device across concurrent advances / restart). Owner-scoped reads; 14-day prune. The `deployment::advance` engine ticks: poll stage+exec responses → guarded transitions → mark out-of-scope skipped → CAS-claim+dispatch stage(pending) then execute(staged) → refresh counts → complete-if-settled (settled-check IN SQL). **ANY future store mutation must stay a guarded transition (never an unconditional grid overwrite) or the execute-once guarantee breaks.** |
| `ApiTokenStore` | `api_token_store` | Migrated Postgres, fresh-start/no-backfill (ADR-0030, PR 4.1, engine-principals program). Adds `principal_kind TEXT NOT NULL DEFAULT 'human' CHECK IN ('human','engine')` — inert until a later PR arms `'engine'`. AUTHORITATIVE/fail-hard (ADR-0012 §1): construction fail-closed, a runtime read error denies, a revoke/delete error surfaces (never a silent success — backs "Sign out everywhere"/stolen-laptop). Hash-only (SHA-256 verify-only `token_hash`, never plaintext) — ADR-0009's secret-material carve-out reasoning does not bind this store; ADR-0030 records the reconciliation. **No backfill**: legacy `api-tokens.db` is no longer opened; existing API/MCP tokens are invalidated on upgrade and operators must re-mint them. |
| `EnginePrincipalStore` | `engine_principal_store` | Born-on-Pg (ADR-0031, engine-principals PR 4.2). Identity store for the new engine-principal class, keyed on the reserved `engine:<slug>` namespace (`principal_id TEXT PRIMARY KEY`, DB `CHECK` mirrors the C++-side prefix/slug guard). Construction fail-closed (ADR-0012 §1: `!is_open()`→`startup_failed_`). `get_for_auth` is the authoritative auth-lookup chokepoint with a **three-state** result (`Active` / `MissingOrRevoked` terminal-401-class / `StoreUnreachable` retryable-503-class) — both non-Active outcomes deny, the split changes retry behavior only, never the authorization outcome (no downgrade path from "unreachable" to "admitted"). Its sibling `get_for_auth_revalidate` (#2367) serves ONLY the per-tick stream-liveness re-check, from a bounded 15 s Active-only cache (jittered TTL, short failure backoff, invalidated on `revoke`/`transfer_owner`); it returns liveness WITHOUT a row and flags `from_cache`, which the pump needs so a cached answer does not reset its grace budget. Every fresh authorization decision still calls `get_for_auth` and reads through. `ApiTokenStore::create_token`'s engine block calls this at mint time via a resolver seam wired post-construction in `server.cpp`; a boot-time collision scan across `auth`/`rbac.db` refuses to start if a pre-existing `engine:`-named local user or group predates the reservation. **No operator CRUD yet** (no dashboard/REST surface — lands in PR 4.3); this release ships FLEET-WIDE engine role grants only, scoped (management-group) engine assignment is rejected outright pending Phase-5 resolution. |
| `AccessReviewStore` | `access_review_store` | Born-on-Pg (ADR-0006, Periodic Access Reviews / SOC 2 CC6.2). Persists review-CAMPAIGN metadata + per-grant attestation decisions (`access_review_campaign` + `access_review_attestation`, PK the full `(campaign_id, principal_type, principal_id, role_name)` 4-tuple). AUTHORITATIVE/fail-hard (ADR-0012 §1), same posture as `EnginePrincipalStore` — construction fail-closed (`!is_open()`→`startup_failed_`), every mutator/completeness-reader returns `std::expected`. `open_campaign` freezes the complete current grant population as `pending` rows in ONE transaction (R3 — the provable "every grant that existed at open time has a reviewable row" invariant). `list_campaigns` (hardening round) returns every campaign's metadata newest-first, capped at 500 — backs `GET /api/v1/access-reviews`. **Deliberately NO prune method** — unlike the `/auto` pre-flight/deployment runs (operational scratch state, 14-day-pruned), a closed campaign IS the compliance evidence and persists indefinitely; any future retention policy is a separate, explicit decision. Does not itself compute the grant population — that's the pure read-model `access_review_model.hpp` (`build_access_review`), which reads `AuthDB`/`RbacStore`/`EnginePrincipalStore` (+ optional `ApiTokenStore`/`DirectorySync` enrichment) and fails the WHOLE export on the first read error, never a silent partial result. **Grant-table-driven (UP-1, hardening round):** the population is read directly off the grant table (`RbacStore::list_all_principal_roles_checked()`), not the three principal rosters, so a grant on a principal outside every roster is surfaced (`source="orphan"`) rather than silently omitted. No backfill (greenfield). |
| auth DB (`auth_db.{hpp,cpp}`) | `auth` | **SHIPPED — Wave 3, ahead of queue order (auth was pulled forward as the last major server SQLite store).** Fresh-start/no-backfill (matches `ApiTokenStore`'s 4.1 precedent): a legacy SQLite `auth.db` is never read; `AuthDB::seed_admin_if_empty` re-seeds the config-file admin on an empty `auth.users`, with a loud one-time "auth data reset on Postgres cutover" boot warning. **`SecretCodec`'s first production consumer** (ADR-0010) — `users.mfa_totp_secret` is now envelope-encrypted (AES-256-GCM, AAD-bound to `{schema,table,column,row id}`); password hashes/recovery codes/enrollment tokens stay verify-only hashes. Construction fail-closed (ADR-0012 §1). **Dropped, not migrated:** the `sessions` table (sessions are `AuthManager`'s in-memory-only `sessions_` map; the DB mirror was a permanent dead-write) and `auth_kv` (unused SQLite-era scaffolding, superseded by `SecretCodec`). Bundled hardening: MFA state reads now fail CLOSED (`AuthDBError::SecretUnavailable`) on a store/decrypt failure — see `docs/auth-architecture.md` "MFA / TOTP". See `.claude/agents/authdb.md` for the full invariant set. |
| `ScimStore` | `scim_store` | **SHIPPED in lockstep with auth DB above** (both landed in the same PR). Retires the prior SQLite `auth.db`-cohabitation exception (see removed "Notes" entry below) — SCIM tokens stay a verify-only SHA-256 hash (nothing to decrypt, `SecretCodec` not needed here). |

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
| `AuditStore` | `audit_store` | authoritative | SOC 2 retained 365d; backfill **mandatory**. Carries SQLite schema v3 (`audit_retention_meta`, one k/v row) plus the partial index `idx_audit_ttl_id`; both must come across. The retention clock guard (#2360) is migration-REQUIRED behaviour, not an optimisation - dropping it on the way over reinstates an unbounded clock-driven `DELETE` on the evidence chain. **Single-writer assumption, and this is the part that does not port:** `clock_anomaly_latched_` is a per-PROCESS member while the clock reading it pairs with is durable, so N servers each spend the guard independently; on PG the latch must become a per-store advisory lease (the ADR-0012 §3 `AppPerfRollup` pattern). Likewise `kMaxAuditDeletesPerPass` is calibrated as a drain rate for ONE hourly loop - N processes x 25k is a different number. |

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
| `CaStore` | `ca_store` | key_ref-only (**unblocked**) | private key behind `KeyProvider`, never in a column. |
| `DeviceTokenStore` | `device_token_store` | verify/hash (confirm in ADR) | classify in its per-store ADR. |
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
- **`scim_resources`/`scim_tokens` exception RETIRED (2026-07-16).** The prior deliberate SQLite
  exception — SCIM's tables rode the existing `auth.db` SQLite file pending `AuthDB`'s own
  cutover — is closed: `ScimStore` now migrates independently to its own `scim_store` Postgres
  schema, shipped in lockstep with `auth DB`'s own cutover (see "Done" above). Kept here as a
  dated record of the retired exception, not as a live carve-out. Detail:
  `docs/auth-architecture.md` "SCIM v2 provisioning" § Storage.
- The count is ~27 `*Store` classes + the auth DB (now itself Postgres); the exact set of
  still-SQLite server stores is whatever currently opens a `sqlite3*` under `server/core/src/`.
  Re-derive before declaring the ladder complete: `grep -rl "sqlite3_open" server/core/src`.
- A store may be **split** or **merged** during migration if its schema warrants it — record that
  in its per-store ADR.
- When the last row clears, remove the `migration_runner.*` SQLite path from the server target and
  delete this file (its job is done).
