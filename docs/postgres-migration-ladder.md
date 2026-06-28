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
| `OfflineEndpointStore` | `offline_endpoint_store` | First born-on-Pg store (#1320 PR 3). **Schema rename pending**: ships today as `endpoint_state`; renamed to conform to the ADR-0008 naming rule (safe pre-alpha — data reconstructs from heartbeats). durability-on-top. |
| `SoftwareInventoryStore` | `software_inventory_store` | Born-on-Pg (ADR-0016). Typed projection for the daily-sync `installed_software` source (normalized rows, no JSONB). authoritative reads; ingest fail-soft (next sync + weekly floor self-heal). **Coexists with the generic `InventoryStore` (Wave 1 below) — it is NOT that store's migration.** |
| `AppPerfFleetStore` | `app_perf_fleet_store` | Born-on-Pg (DEX app-perf-over-time B2). Fleet aggregate `(app, version, day)` + fixed-bucket CPU/WS histogram + device_count, 180-day retention (the trend window). **Single-schema owner** — it does NOT write itself; the B1→B2 roll-up is the dedicated cross-store query owner `AppPerfRollup` (ADR-0012 §3 seam: one lease, schema-qualified `INSERT … SELECT` spanning `app_perf_daily_store` → `app_perf_fleet_store`). authoritative reads; derived aggregate (rebuilt by the next roll-up). No `agent_id` (no per-device attribution). No backfill (greenfield). |
| `AppPerfDailyStore` | `app_perf_daily_store` | Born-on-Pg (DEX app-perf-over-time B1). Typed per-device daily app-version perf projection for the daily-sync `app_perf` source (plain table, PK `(agent_id, app_name, version, day)`, 31-day per-agent prune, no JSONB). authoritative reads; ingest fail-soft. **Hash-less** (perf changes daily → no hash-skip), so unlike `SoftwareInventoryStore` it stores no content hash and a hash-only report is answered `need_full`. No backfill (greenfield). |

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

- The count is ~27 `*Store` classes + the auth DB; the exact set is whatever currently opens a
  `sqlite3*` under `server/core/src/`. Re-derive before declaring the ladder complete:
  `grep -rl "sqlite3_open" server/core/src`.
- A store may be **split** or **merged** during migration if its schema warrants it — record that
  in its per-store ADR.
- When the last row clears, remove the `migration_runner.*` SQLite path from the server target and
  delete this file (its job is done).
