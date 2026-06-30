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
  device sync bookkeeping. `first_seen`/`last_seen` are **server receipt times**
  (epoch seconds, stamped when the report is ingested), **not** the agent-supplied
  `collected_at` — so the recency filters and freshness gauge below are immune to
  agent clock skew (#1685).

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
- **A per-agent management-group drop filter is applied** — out-of-scope
  devices are dropped (and the omission audited), with the count returned as
  `devices_omitted` (absent when zero). **Caveat (ADR-0017): this confinement is
  not yet verified effective.** The tool gates on the *global* `Inventory:Read`
  permission, under which the filter does not narrow results (a confined operator
  is denied at the gate; a global operator sees all) — list-view management-group
  confinement becomes effective only once the ADR-0017 admit-then-filter gate lands
  and the #1713/#1676 UAT confirms it. When present, a positive `devices_omitted`
  means matching software exists outside your scope — an empty or short result does
  **not** mean the software is absent fleet-wide. This is distinct from the generic
  `query_inventory` / `get_agent_inventory` tools, which read a *separate*
  generic blob store on `Infrastructure:Read` and do **not** surface this typed
  software data.
- **On store degradation (authoritative reads, ADR-0016 §7):** if the Postgres
  store cannot be read (pool-acquire timeout or query error), the tool returns a
  JSON-RPC error (`kInternalError`) rather than an empty result. Treat any error
  response as "unknown — do **not** proceed as if nothing is installed". A
  genuinely empty result (no error, zero rows) means the query succeeded and
  matched nothing in your scope.

### REST (for automation / scripts)

The same data is exposed over REST at **`GET /api/v1/inventory/software`** (gated on
`Inventory:Read`), the agentic-first sibling of the MCP tool:

```bash
# Which devices run Google Chrome (fleet-wide, within your scope)?
curl -H "Authorization: Bearer $TOKEN" \
  "$SERVER/api/v1/inventory/software?name=Google%20Chrome"

# Everything on one device
curl -H "Authorization: Bearer $TOKEN" \
  "$SERVER/api/v1/inventory/software?agent_id=<agent-id>"
```

- Query params: `name` (exact), `agent_id` (exact), `limit` (max 1000). Omit both
  `name` and `agent_id` for a fleet-wide scan.
- Success body: `{"data": {"software": [...], "count": N, "devices_omitted": M, ...},
  "meta": {"api_version": "v1"}}`. Each row is
  `{agent_id, name, version, publisher, install_date}`.
- **Carries the same per-agent management-group drop filter as the MCP tool**
  (out-of-scope devices dropped, omission audited, `devices_omitted` reports the
  count) — and the same **ADR-0017 caveat: not yet verified effective** under the
  global `Inventory:Read` gate (see the MCP note above; #1713/#1676). When present, a
  positive `devices_omitted` means matching software exists outside your scope — an
  empty or short result does **not** mean the software is absent fleet-wide.
- `result_truncated_by_cap: true` (present only when set) means more rows exist past
  `limit` (keyset pagination is a follow-up, #1634).
- **On store degradation** the endpoint returns **`503`** (an A4 error envelope with a
  `correlation_id`), **never** an empty `200` — so a vulnerability query cannot read a
  transient Postgres outage as "installed nowhere" (ADR-0016 §7 authoritative reads).
  Distinct from a genuinely empty result (`200` with `count: 0`), which means the query
  succeeded and matched nothing in your scope.

**Narrow scope on a large fleet (applies to *both* the MCP tool and the REST
endpoint).** The 1000-row cap is applied by the store *before* the management-group
scope filter runs. So a narrow-scope operator querying a popular title across a large
fleet can see `result_truncated_by_cap: true` together with few — or **zero** — of
their own rows, because the cap was consumed by out-of-scope devices that sort ahead
of yours. **That is "incomplete", not "absent in your scope."** Until keyset
pagination lands (#1634), narrow the query: pass `agent_id` (`?agent_id=<id>` on REST,
the `agent_id` arg on MCP) to read a specific device, or a more selective `name`
filter, so your in-scope rows fit under the cap.

### Dashboard (`/inventory`)

The **Inventory** dashboard (top-nav **Inventory**) is the point-and-click view of the
same data, with three tabs:

- **Software** (default) — the fleet **software list**: each installed-software title
  rolled up to its **install count** (number of devices carrying it) and its number of
  distinct **versions**, most-installed first. Click a title to drill into its
  **installs per version** (how many devices run each version). A title filter narrows
  the list. **These counts are fleet-wide totals**, gated on the global
  `Inventory:Read` — they are **not** management-group scoped (the same ADR-0017 caveat
  as the REST/MCP surfaces: confinement is inert under the global gate, so the counts
  span all groups; the UI says so inline). A freshness KPI shows the **stale** count
  (devices that have not synced within two daily cycles). **The catalogue is a
  precomputed rollup**, not an on-demand query: a background thread recomputes the
  per-title and per-version counts on a cadence (hourly) and the page reads the small
  precomputed tables — the underlying installed-software changes only on the daily sync,
  so recomputing per page-load would be wasteful and would not scale. The KPI strip shows
  an **"updated N ago"** stamp for the rollup; immediately after a fresh server starts (or
  before the first refresh) the catalogue shows a **"building"** note until the first
  recompute lands. This keeps the default tab fast at any fleet size.
- **Devices** — a **thin device inventory**: hostname, OS, online/offline/**stale**
  status, and last-seen, sourced from the server's persisted endpoint state so a device
  appears here **even when it is offline** (joined to the live registry for the online
  flag). The **list** is gated on the global `Inventory:Read`, filtered to the
  operator's visible scope by the device provider, and the roster read is audited
  (`inventory.devices`). **Clicking a
  device** loads that device's installed software; that per-device drill is additionally
  gated by the management-group chokepoint (`Inventory:Read` for the device's group, so
  an operator only opens a device in their scope) **and is audited**
  (`inventory.device.software`). An offline device shows its *last daily sync*, clearly
  labelled. The richer CI columns (serial, model, CPU, RAM, MAC …) are greyed pending
  the device-CI sync source (a follow-on). A large device list is rendered first-N with
  the total shown; use the filter to narrow.
- **Find software** — type an exact title to see **which devices run it** and at which
  versions. Like the REST/MCP siblings, Find is gated on the **global `Inventory:Read`**
  and returns **fleet-wide** results: management-group confinement is **not yet effective**
  on this list view (the per-row scope filter is a foundation for the ADR-0017
  admit-then-filter gate, #1716, not effective list-confinement today — only the
  per-device drill is scoped). 1000-row cap; a short/zero result under a narrow scope is
  *incomplete*, not *absent* (keyset paging is the #1634 follow-up).

**On store degradation** the **Software**, **Find**, and **per-device-software** views —
the *authoritative* reads — show an explicit **"unavailable"** banner rather than an
empty table, because an empty table would read as "installed nowhere", the fail-open the
authoritative-read contract (ADR-0016 §7) forbids. The **Devices roster** is sourced from
the deliberately *fail-soft* endpoint-state store (durability-on-top, not authoritative),
so during a database incident it may render an empty/short roster rather than a banner;
its empty-state copy says so and points you to the authoritative Software tab.

The full **device CI inventory** (offline-readable hardware/identity records — a
ServiceNow-style CI record) is a planned follow-on: it adds a device-CI **daily-sync
source** (the ADR-0016 framework's source #2) feeding a born-on-Postgres
`DeviceInventoryStore`, at which point the greyed CI columns above become real.

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

**Non-ASCII app names show as `?` after upgrading from a pre-#1662 build.** The
initial `installed_apps` plugin read the Windows registry with the ANSI `Reg*A`
APIs, which return the system code page (cp1252 on Western installs), so any
non-ASCII character in an app or publisher name was stored as `?` (e.g. `Café` →
`Caf?`). This is fixed in the release containing #1662 (the plugin now reads via
`Reg*W` + UTF-8). After upgrading an agent, the corrected names land on that
agent's **next daily sync** — typically within hours, not the weekly full-floor,
because the changed bytes change the content hash and force a full re-send (it is
*not* gated behind the weekly floor). Until then, an exact-match query
(`WHERE name = 'Café'`) returns zero rows for that device. To force the refresh
immediately on a device, **restart the Yuzu agent** there — the first sync after
restart sends a full list. Note that app *counts* can rise slightly after the
fix: names that previously collapsed to the same `?`-mangled string (e.g. two
different non-ASCII apps) now separate into distinct rows.

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
  otherwise invisible. The per-degrade WARN is sampled per site — the leading edge
  of each outage *episode* (a degrade arriving after a quiet gap), then every 100th
  within it — so a fan-out outage can't flood the log while a second, later outage
  still logs its onset rather than staying silent; the counter is the continuous
  signal.
- `yuzu_inventory_stale_agents{source}` (gauge) — agents that have not synced this
  source within the staleness window (two missed daily cycles), a freshness /
  liveness signal sampled on the metrics sweep. Staleness keys on the **server
  receipt time** (`inventory_state.last_seen`), not the agent's `collected_at`, so a
  future-skewed or hostile agent cannot pin itself "fresh" and hide a dark endpoint
  (#1685). On a degrade the gauge **holds its
  prior value** (it is never set to a false `0`), so pair it with the counter below
  to know whether a low reading is current.
- `yuzu_inventory_stale_count_unavailable_total` (counter) — the freshness count
  could not be computed (pool saturation / query timeout) and the gauge above was
  held at its prior value. A non-zero rate means `yuzu_inventory_stale_agents` may
  be **frozen, not genuinely low** — the freeze-detector that travels with the
  gauge (the freshness count uses a tighter 250 ms budget than the read paths, so
  it can stall while `yuzu_inventory_read_degrade_total` stays quiet).

The **catalogue rollup** (the `/inventory` Software tab's precomputed counts, refreshed
hourly by the background `SoftwareCatalogRollup` thread) emits three further series:

- `yuzu_inventory_catalog_rollup_total{outcome}` (counter, outcome ∈ `success` / `error`)
  — one per recompute attempt. A rising `error` count with a frozen
  `…_last_success_timestamp` means recomputes are failing (PG outage / the 60s budget
  exceeded at scale) and the catalogue is going stale; keep-last-good serves the prior
  rollup meanwhile.
- `yuzu_inventory_catalog_rollup_duration_seconds` (gauge) — the last recompute's
  wall-clock. A rising value approaching the 60s budget is the leading indicator to raise
  the budget (or shard the rollup) before recomputes start timing out. (A gauge, not a
  histogram: at one sample/hour percentiles add nothing.)
- `yuzu_inventory_catalog_rollup_last_success_timestamp` (gauge, epoch seconds) — the
  primary liveness signal; it is the source of the Software tab's "updated N ago" stamp.
  **Seeded to `0` at startup** so the series always exists (a never-succeeded server is
  still alertable). Alert on `time() - this > 7200` **guarded by `and this > 0`** — the
  `> 0` guard skips the cold-boot "building" window (epoch 0); the never-succeeded /
  ongoing-failure case is caught by `…_rollup_total{outcome="error"}` instead.

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

A **recording rule**, `yuzu:inventory_ingest_duration_seconds:p99{source,phase}`,
ships in the same group: it precomputes the 99th-percentile ingest duration per
`(source, phase)` over a 10m window (matching `YuzuInventoryIngestSlow`) so
dashboards and any future tighter latency alert read a cheap single series rather
than a fan-out `histogram_quantile` at query time — meaningful only because the
extended 10-60s buckets resolve the tail. Reference it directly in Grafana panels
or custom alert expressions; it returns no data unless the shipped rules file is
loaded.

`YuzuInventoryStaleAgents` ships **disabled** (commented out) in the same group:
the `yuzu_inventory_stale_agents` gauge has no fleet-size-independent absolute
threshold (`>50` is day-one noise on a 100-device pilot and 0.1% ambient churn on a
50k fleet), and a fleet-relative ratio against `yuzu_fleet_agents_healthy` needs
explicit `on()/group_left()` matching with a denominator caveat. **Enable it** once
you have observed your fleet's normal stale-count baseline and set the threshold to
~5–10% of your expected active fleet; correlate with `yuzu_fleet_agents_healthy` to
separate "agents offline" from "sync source broken / disabled".

## Device-identity inventory (`device_ci`)

A second daily-sync source, **`device_ci`** (ADR-0016 source #3), is live on the
agent and server. It collects the machine's stable hardware/OS identity — a
ServiceNow-CMDB-style configuration item — and persists one row per device in the
Postgres schema **`device_inventory_store`** (table `device_ci`): manufacturer,
model, **serial number**, **system UUID**, BIOS vendor/version/date, CPU
model/cores/threads, RAM, a disk summary, **primary MAC** + MAC summary + NIC
count, OS name/version/build, and architecture. Serial number and system UUID are
the CMDB correlation key.

It is collected via the existing `hardware` (incl. a new `system` action for
serial + UUID), `device_identity`, `os_info`, and `network_config` plugins. It
**excludes volatile telemetry** — free disk space, uptime, IP addresses —
deliberately: those change between cycles and would flip the content hash every
sync, defeating the hash-skip protocol.

- **Scope / privacy.** Machine-scope only (no per-user data), but serial/UUID/MAC
  are device-persistent identifiers — treat as potentially personal data where a
  device is person-assigned. The same **`--inventory-disable`** flag suppresses
  `device_ci` along with the other sources (it gates the whole daily-sync thread).
- **Observability.** Ingest shares
  `yuzu_inventory_ingest_total{source="device_ci"}` +
  `yuzu_inventory_ingest_duration_seconds{source="device_ci"}`; read degrades use
  `yuzu_inventory_read_degrade_total{source="device_ci"}`. The store joins
  `/readyz` + `/healthz`.
- **VMs / serial-less hosts.** A device with no SMBIOS serial (many VMs) reports
  `serial`/`system_uuid` as the literal `"unknown"` — use `manufacturer`/`model`
  (e.g. "VMware, Inc."/"VMware7,1") to recognise it.

The operator-facing read surface — the `/inventory` **Devices** tab CI columns and
the per-device CI panel — ships in **PR2**; until then the data is in Postgres but
not yet surfaced in the dashboard.

## See also

- `docs/adr/0016-agent-daily-sync-framework.md` — the design and rationale.
- `docs/os-capability-matrix.md` — per-OS collection coverage.
