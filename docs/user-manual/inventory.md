# Installed-software inventory

Yuzu collects each endpoint's **installed-software inventory** and syncs it to the
central server's PostgreSQL database on a **daily** cadence, so you can answer
fleet-wide questions like "which devices have package X at version < Y" for asset
management and vulnerability relevance. This is the first source of the agent's
**daily-sync framework** (ADR-0016); more data types will follow on their own
cadences.

## What is collected

- **Machine-wide installed software**: name, version, publisher, install date.
  Collected by the existing `installed_apps` plugin via its `list` action
  (Windows: `HKLM` + the agent service account's own `HKCU`; Linux:
  `dpkg`/`rpm`/`pacman`; macOS: `system_profiler`).
- **No end-user profiles / personal data.** We do **not** use the plugin's
  per-user enumeration (`list_per_user`), so no logged-in-user profiles and no
  usernames are collected — no end-user PII. (The only `HKCU` read is the agent's
  own service-account hive, which is benign.) It carries **lower behavioral
  sensitivity** than the process/performance tiers (no run-time, no resource
  attribution). **Note for works-council jurisdictions:** the data is still
  device-attributable, and on personally-assigned devices installed-software
  enumeration may be co-determination-relevant under national law (e.g. BetrVG
  §87(1)(6)) — co-determination is triggered by the *capability to monitor*, not
  by username presence. Use the opt-out below where an agreement requires it.
- **Disabling it.** Pass **`--inventory-disable`** (or set
  `YUZU_AGENT_INVENTORY_DISABLE`) on the agent to collect and push **no**
  installed-software inventory. Deploy-time opt-out; not a server-side runtime
  toggle.

## How the sync behaves (and why it's quiet on the network)

- **Daily, per source.** Installed software syncs every ~24 h.
- **Spread, not lockstep.** Each endpoint picks a stable, per-agent time offset,
  so a fleet does not all report at once. A freshly enrolled (or long-offline)
  agent does its first sync shortly after connecting, jittered to avoid a
  mass-enrollment thundering herd.
- **Hash-skip.** If a device's installed software hasn't changed since its last
  successful sync, the agent sends only a small **content hash** instead of the
  full list. The server replies asking for the full list only when it can't match
  the hash (e.g. a fresh/restored server). A full list is also sent at least once
  a week regardless, as a safety net.
- **Resilient.** Sync state is kept on the agent and survives reconnects and
  reboots; a failed sync simply retries on the next cycle.

## Reading the inventory

The data lands in the Postgres schema **`software_inventory_store`**:

- `installed_software(agent_id, name, version, publisher, install_date)` — one
  row per installed package per device. `version`, `publisher`, and
  `install_date` may be empty (`''`) — the `installed_apps` plugin does not
  guarantee them on every platform/package.
- `inventory_state(agent_id, source, content_hash, first_seen, last_seen)` — per
  device sync bookkeeping.

Today it is queried with **direct SQL**, e.g.:

```sql
-- Which devices have Google Chrome, and what version?
SELECT agent_id, version
FROM software_inventory_store.installed_software
WHERE name = 'Google Chrome'
ORDER BY version;

-- Everything installed on one device
SELECT name, version, publisher, install_date
FROM software_inventory_store.installed_software
WHERE agent_id = '<agent-id>'
ORDER BY name;
```

**Counting the *active* fleet (excluding decommissioned devices).** A device's
rows persist after it stops reporting — Yuzu keeps last-known state rather than
silently dropping a host (the same posture as the offline-endpoint view). So for
software-asset-management counts ("how many devices run X *right now*"), scope to
recently-seen devices via `inventory_state.last_seen` rather than counting raw
rows, which would include long-gone hosts:

```sql
-- Devices that ran Google Chrome AND reported within the last 30 days
SELECT s.agent_id, s.version
FROM software_inventory_store.installed_software s
JOIN software_inventory_store.inventory_state st
  ON st.agent_id = s.agent_id AND st.source = 'installed_software'
WHERE s.name = 'Google Chrome'
  AND st.last_seen > EXTRACT(EPOCH FROM now()) - 30 * 86400
ORDER BY s.version;
```

(A platform-wide decommission/retention purge across all per-device stores is a
tracked follow-on; until then, `last_seen` is the canonical "is this device still
active" filter.)

### MCP (for agentic workers)

The **`query_installed_software`** MCP tool exposes the same data to agentic
workers (gated on `Inventory:Read`):

- Filter by software `name` and/or `agent_id`; omit both for a fleet-wide scan.
- Returns up to `limit` rows (max 1000). When `result_truncated_by_cap` is
  `true`, more rows exist past the cap (keyset pagination is a follow-up).
- **Results are scoped to your management groups** — devices outside your
  groups are omitted (and the omission audited), and the count is returned as
  `devices_omitted` (absent when zero). A positive value means matching software
  exists outside your scope — an empty or short result does **not** mean the
  software is absent fleet-wide. This is distinct from the generic
  `query_inventory` / `get_agent_inventory` tools, which read a *separate*
  generic blob store on `Infrastructure:Read` and do **not** surface this typed
  software data.
- **On store degradation (authoritative reads, ADR-0016 §7):** if the Postgres
  store cannot be read (pool-acquire timeout or query error), the tool returns a
  JSON-RPC error (`kInternalError`) rather than an empty result. Treat any error
  response as "unknown — do **not** proceed as if nothing is installed". A
  genuinely empty result (no error, zero rows) means the query succeeded and
  matched nothing in your scope.

A dedicated REST endpoint and a software dashboard / per-device drill-down view
are planned follow-ons.

## Access control

Inventory reads are governed by the **`Inventory`** RBAC securable
(`Inventory:Read`), granted by default to the Administrator, ITServiceOwner,
PlatformEngineer, Viewer, and Operator roles. (The gate applies to the
inventory REST/MCP surfaces; direct database access is governed by your Postgres
credentials.)

## Troubleshooting

**The `installed_software` table is empty after upgrading agents.** Most likely
the `installed_apps` plugin isn't loaded — the sync source then idles silently
(it logs `sync: installed_apps plugin not loaded` only at **debug**). Verify the
agent was built with `-Dbuild_examples=true` (the default for released binaries)
and that `installed_apps` is present in the agent's `--plugin-dir`. The sync also
only runs once per ~24 h per agent (spread across the fleet), so a freshly
enrolled agent populates within minutes (jittered first sync), not instantly.

**Observability.** The server emits `yuzu_inventory_ingest_total{source,outcome}`
(outcome ∈ `stored` / `touched` / `need_full` / `error` / `dropped` / `rejected`,
the last for a whole report rejected at the source-map cap) — watch the
`need_full` and `error` rates to spot a fleet whose hash-skip is degrading or
whose ingest is failing. Four further series sharpen the picture:

- `yuzu_inventory_ingest_duration_seconds{source,phase}` (histogram) — how long
  applying one source's report holds a pooled Postgres connection (advisory lock +
  the atomic replace, whose inserts are now batched into a single `unnest()`
  statement). `phase=full` is the full-payload replace; `phase=hash_only` is the
  cheap hash-skip compare + `last_seen` bump — split so the steady-state
  hash_only majority doesn't bury the `full` tail, the pool-pressure signal under
  a cold-cache `need_full` herd.
- `yuzu_inventory_read_degrade_total{reason}` (counter, reason ∈ `store_not_open` /
  `pool_acquire_timeout` / `query_error`) — an **authoritative read** that returned
  a degrade (no data) rather than a silent empty. `/readyz` stays green under pure
  pool saturation, so without this counter a degraded fleet software query is
  otherwise invisible. The per-degrade WARN is sampled (1st then every 100th per
  site) so a fan-out outage can't flood the log; the counter is the continuous
  signal.
- `yuzu_inventory_stale_agents{source}` (gauge) — agents that have not synced this
  source within the staleness window (two missed daily cycles), a freshness /
  liveness signal sampled on the metrics sweep. On a degrade the gauge **holds its
  prior value** (it is never set to a false `0`), so pair it with the counter below
  to know whether a low reading is current.
- `yuzu_inventory_stale_count_unavailable_total` (counter) — the freshness count
  could not be computed (pool saturation / query timeout) and the gauge above was
  held at its prior value. A non-zero rate means `yuzu_inventory_stale_agents` may
  be **frozen, not genuinely low** — the freeze-detector that travels with the
  gauge (the freshness count uses a tighter 250 ms budget than the read paths, so
  it can stall while `yuzu_inventory_read_degrade_total` stays quiet).

Shipped alert rules live in the `yuzu-inventory` group of
`docs/prometheus/yuzu-alerts.yml`: `YuzuInventorySustainedIngestErrors` (a non-zero
`error` rate held for 15m), `YuzuInventoryHighNeedFullRatio` (>20% of ingests are
`need_full` for 15m — hash-skip is not taking, so agents keep re-sending full
payloads), `YuzuInventoryDroppedBlobs` (an over-cap blob dropped + nacked),
`YuzuInventoryReportRejected` (a whole report rejected at the source-map cap),
`YuzuInventoryReadDegraded` (a read returned a degrade, by reason),
`YuzuInventoryIngestSlow` (full-payload ingests holding a connection >10s — a
leading pool-saturation indicator), and `YuzuInventoryStaleCountUnavailable` (the
freshness gauge may be frozen).

`YuzuInventoryStaleAgents` ships **disabled** (commented out) in the same group:
the `yuzu_inventory_stale_agents` gauge has no fleet-size-independent absolute
threshold (`>50` is day-one noise on a 100-device pilot and 0.1% ambient churn on a
50k fleet), and a fleet-relative ratio against `yuzu_fleet_agents_healthy` needs
explicit `on()/group_left()` matching with a denominator caveat. **Enable it** once
you have observed your fleet's normal stale-count baseline and set the threshold to
~5–10% of your expected active fleet; correlate with `yuzu_fleet_agents_healthy` to
separate "agents offline" from "sync source broken / disabled".

## See also

- `docs/adr/0016-agent-daily-sync-framework.md` — the design and rationale.
- `docs/os-capability-matrix.md` — per-OS collection coverage.
