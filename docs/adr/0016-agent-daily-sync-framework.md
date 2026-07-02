# ADR-0016: Agent→Server Daily Sync Framework (hash-skip conditional push)

**Date:** 2026-06-24
**Status:** Accepted (v1 sliced — installed software is source #1)
**Component:** Agent core (sync scheduler) · Server (inventory ingest + Postgres store) · Gateway (proxy)
**Authors:** Dave Rae

## Context

We are beginning to write endpoint-reported data to the server's **PostgreSQL**
substrate (ADR-0006/0008). The first concrete need: every endpoint reports its
**installed-software inventory daily** into central Postgres, queryable
fleet-wide for software asset management (SAM), vulnerability relevance, and
(future) software-entitlement reclamation ("software not used in ≥ X days").

This is the first instance of a broader, recurring need: the agent should push
**different *flavours* of data on *different cadences*** to the server. We want
one mechanism for that, not a bespoke path per data type.

Two existing constraints shape the design:

- **Be kind to the network at fleet scale.** A full installed-software list is
  ~100–300 entries/host; shipping it from every endpoint every cycle is exactly
  the traffic we want to avoid.
- **Thin central (ADR-0004).** Most device data stays on the per-agent edge
  warehouse; central Postgres holds only what fleet-wide queries need.

### Why not "TAR first"

The initial instinct was to land this in the agent's local **TAR** edge
warehouse and pull it centrally. Rejected: TAR is **pull-only by design** and
**event-shaped** (it records *change events*, e.g. PR #1620's `$Software`
source records install/uninstall/upgrade deltas). TAR answers *"what changed,
when"* on the edge. Our goal is *"what is installed now, daily, in central
Postgres."* Routing a full daily snapshot through TAR would require building a
new push/export transport that contradicts TAR's no-push philosophy, and TAR's
delta shape does not match a full-snapshot need. The two are **complementary,
not substitutes**: this framework owns *current state, central*; TAR owns
*change history, edge*. PR #1620 is out of scope here and lives or dies on its
own merits.

## Decision

Build a **generic, agent-driven, per-source daily sync framework** that pushes
data to the server over the existing (dormant) `ReportInventory` RPC, with a
**hash-skip conditional protocol** to keep the network quiet. Installed software
is **source #1**; the seam is built right so further sources (and a future
`last_used` usage source for SAM/entitlement) are drop-ins.

### 1. Vehicle — direct push over `ReportInventory`
Reuse the dormant `AgentService.ReportInventory(InventoryReport) → InventoryAck`
RPC. `InventoryReport.plugin_data` is already a generic `map<string,bytes>`
envelope (key = data-type, value = opaque blob). No TAR involvement.

### 2. Generic per-source framework (agent)
A small, source-agnostic seam:
- `SyncSource { name, interval, collect_fn, hash_fn }`.
- `SyncScheduler` owns the per-source loop, the spread/startup policy, the
  hash-skip protocol, and the weekly full-floor.
- Sources register installed_software for v1. No speculative knobs.

### 3. Trigger — agent-internal, per-source cadence, no fleet lockstep
- The **agent owns the clock**; each source has its **own cadence** (software =
  24 h).
- Spread across the fleet by a **stable per-agent phase offset**:
  `offset = hash(agent_id + source) % interval`. Deterministic → a reboot does
  not re-cluster the fleet or trigger a spurious sync.
- Persist `last_sync_ts` + `last_hash` per source in the agent **`KvStore`**
  (`agents/core/src/kv_store.cpp`, `kv_store.db`), namespace `__sync__` — the
  same agent-core state store Guardian uses (namespace `__guardian__`).
  Explicitly **not** TAR: TAR is a *plugin-owned, append-only* capture
  warehouse; this is *mutable agent-core* KV state, and core must not depend on
  a plugin's DB being loaded/healthy.
- **Startup policy:** first-run or overdue (gone past one interval while
  offline) → one catch-up sync after a *short random startup delay* (so a
  mass-deploy or a site's Monday-morning power-on does not herd); otherwise wait
  for the next phase fire.

### 4. Hash-skip conditional protocol
- The agent **always** sends a per-source `content_hash`; it **omits the full
  blob when the hash is unchanged** since the last successful sync.
- The server is **authoritative**: on stored-hash mismatch *or no record* it
  replies `need_full` for that source, and the agent re-pushes the full list
  (conditional-request / HTTP-304 pattern). This covers all cold-cache cases:
  DB wiped, new/migrated server, reassigned agent.
- A **weekly full-floor** (send full regardless) is the defense-in-depth
  backstop.
- **Hash trust:** the server **recomputes the canonical hash server-side from
  the received rows** on a full payload and stores *that* — it never trusts the
  agent's claimed hash as the stored value. Skip decisions compare the agent's
  claimed hash against the server-recomputed stored hash. A buggy agent that
  wrongly believes "unchanged" is bounded by the weekly full-floor (accepted
  staleness bound).

Proto additions (wire-compatible, additive):
- `InventoryReport.content_hashes : map<string,string> = 4`
- `InventoryAck.need_full : repeated string = 2`

### 5. Two server entry points → one shared ingest seam
A gateway-connected agent does **not** reach `AgentServiceImpl::ReportInventory`;
it reaches `GatewayUpstreamServiceImpl::ProxyInventory` (the gateway re-encodes
and calls the server's `ProxyInventory`, exactly like Register/ProxyRegister).
Both entry points route the typed sources through **one** shared
`ingest_inventory_report(...)` seam (mirroring `HeartbeatIngestion`) so direct
and gateway paths persist `installed_software` **identically** into the typed
`SoftwareInventoryStore`. The gateway additionally keeps its pre-existing
generic `InventoryStore::upsert` for any **other** `plugin_data` key (the
sync-framework baseline), skipping `installed_software` there to avoid double
storage. Closing the direct/gateway gap is load-bearing, since the gateway
topology is the one we do **not** internet-expose direct.

The report is **untrusted external input**: size caps on `plugin_data`, row
caps, UTF-8 validation at the seam (security-guardian gate).

### 6. Gateway field survival
`ReportInventory` is already proxied, but the gateway **decodes then re-encodes**
via gpb (`gateway_pb:encode_msg`). New proto fields are silently dropped at the
gateway hop unless the gateway's `agent_pb.erl` + `gateway_pb.erl` are
regenerated (the documented "csr_pem trap"). Regen is in scope — without it,
through-gateway agents lose both the hash-skip and the `need_full` nack, so
their data never lands.

### 7. Server store — coexistence: generic baseline + typed Postgres projection
**Correction (recon error):** the existing `InventoryStore` is **not** a dead
stub — it is the generic per-source blob store (`agent_id, plugin, data_json`)
that **backs a documented, tested scope-walking source** (`kInventoryQuery` /
`from-inventory-query` in `scope-walking-design.md`) **and** the inventory eval
engine (`evaluate_inventory`, `/api/v1/inventory/evaluate`). It is unfed today
(no agent calls `ReportInventory`), but it is wired + tested + documented.
Crucially, its per-*source* shape is the **same shape** as the daily-sync
envelope, so it is the natural **baseline store for the whole sync framework**
(many data types will sync — not just software).

Therefore we **coexist, not replace**:
- Keep the generic `InventoryStore` (SQLite today) **untouched** — the
  sync-framework baseline + the scope/eval surface. (Porting it to Postgres
  under the sync framework is a follow-on, aligned with ADR-0006.)
- Add a **new born-on-Postgres `SoftwareInventoryStore`** (schema
  `software_inventory_store`) — the **typed, read-optimized projection** for
  sources that need fleet-wide queries. `installed_software` is the first;
  future high-query sources get their own typed table in this store. Built per
  the `OfflineEndpointStore` template + ADR-0012 + the postgres-store-playbook:
  - **Current-state only** (replace on change). No history in central PG —
    change-history stays an edge/TAR concern (ADR-0004 boundary).
  - **Normalized relational rows**, **no JSONB/GIN** — honors the
    "migrate off Postgres easily" constraint. Generic parent
    `inventory_state(agent_id, source, content_hash, first_seen, last_seen)` +
    one **typed child per source** (`installed_software(agent_id, name, version,
    publisher, install_date)`). Replace an agent's child rows in one transaction.
- **Failure posture:** authoritative for reads (surface errors, never
  silent-empty); ingest tolerates a transient PG outage (next sync + weekly
  floor self-heal).
- App-identity key kept **stable + normalizable** so a future `last_used` usage
  source can join (`installed ⨝ last_used → unused ≥ X days`).

### 8. Scope, identity, and access
- **No end-user profiles** for v1. We invoke `installed_apps` `list` (Windows:
  `HKLM` + the *agent service account's own* `HKCU`; Linux: the system package
  DBs dpkg/rpm/pacman; macOS: a `system_profiler SPApplicationsDataType`
  application-**bundle scan** of machine-wide locations + the calling account's
  user-domain context — NOT a package DB) — **not** `list_per_user`, which
  enumerates every user profile + carries usernames. So no end-user PII and no
  works-council co-determination trigger. The Windows `HKCU` and the macOS
  user-domain context are benign **by run identity**: the agent runs as a service
  account (`NT SERVICE\YuzuAgent` / `_yuzu`) or root, never the console user, so
  neither crawls a logged-in user's hive / `~/Applications`. (If macOS ever moves
  to a console-scoped account, re-evaluate.) Per-user enumeration is a later,
  gated, pseudonymized addition if needed.
- Reuse the existing `installed_apps` plugin (already 3-OS) **in-process via
  `LocalDispatcher`** — no new collector.
- New **`Inventory` securable type**; reads gated on `Inventory:Read` (no
  inventory securable exists today; `Response` is semantically wrong for a
  dedicated store; `Inventory` future-proofs the framework).
- Read surfaces: **shipped in v1** — direct SQL (free) + an **MCP query tool**
  (`query_installed_software`, `Inventory:Read`, management-group scoped).
  **Planned follow-ons** (NOT in v1): a **REST** endpoint, an installed-software
  section on the existing `/device` drill-down, and a dedicated fleet-wide
  software dashboard.

> **Update (2026-06-26):** the REST read surface shipped as
> `GET /api/v1/inventory/software` (`Inventory:Read`, management-group scoped,
> degrade→503-never-empty per §7, set-and-proceed audit per §8) — the REST sibling
> of `query_installed_software`, mirrored 1:1. See `docs/user-manual/inventory.md`
> §REST and `docs/user-manual/rest-api.md`. Remaining follow-ons: the `/device`
> drill-down section and the fleet-wide software dashboard.

> **Update (2026-06-28):** the "management-group scoped" qualifier on the read
> surfaces above (`query_installed_software` and `GET /api/v1/inventory/software`)
> is **superseded — not yet effective.** Both gate on the *global* `Inventory:Read`
> permission, under which the per-agent drop filter does not narrow results (a
> management-group-confined operator is denied at the global gate; a global operator's
> filter is a no-op). Read these as "global `Inventory:Read`; per-device confinement
> only" until the admit-then-filter list gate lands. See **ADR-0017** (the decision +
> gate design), **#1716** (doc-honesty), and **#1713/#1676** (the inventory
> effective-vs-inert UAT).

## Consequences

**Positive**
- One mechanism for all future agent→server periodic data; new sources are
  drop-ins.
- Network cost tracks *change*, not cadence: steady-state is a per-source hash,
  not a list.
- Portable store (plain relational rows) — re-homing off Postgres is swapping
  the substrate layer, not rewriting the data model.
- Direct + gateway parity via a single ingest seam.

**Negative / costs**
- Proto + gateway gpb regen required (multi-module: `agent_pb`, `gateway_pb`).
- A new born-on-PG store + RBAC securable + MCP/REST/dashboard surfaces.
- Server-side hash recompute on full payloads (cheap; bounded by hash-skip
  rarity).

**Risks**
- A buggy agent under-reporting "unchanged" → bounded by the weekly full-floor.
- Forgetting the gateway regen → silent field drop for through-gateway agents
  (explicitly called out; covered by a gateway wire test).

## Alternatives considered

- **TAR-first + central pull** — rejected (pull-only, event-shaped; see Context).
- **JSONB blob + GIN index** — rejected (Postgres lock-in; clunky range
  filters; conflicts with the migrate-off-PG constraint).
- **Always send the full list** — rejected (abandons network-kindness).
- **Server-dispatched daily schedule** — rejected (daily fleet fan-out; the
  agent-push model matches the RPC's purpose and self-staggers).
- **Full version history in central PG** — rejected for v1 (fattest; contradicts
  thin-central; history is TAR's edge concern).

## Relationship to other ADRs
- **ADR-0004** (edge warehouses / thin central) — this framework's
  current-state-central / history-on-edge boundary is a direct application.
- **ADR-0006/0008** (Postgres substrate) — `InventoryStore` is born-on-PG.
- **ADR-0012** (server Postgres store contract) — `InventoryStore` follows it;
  recorded as a prioritized net-new store in `docs/postgres-migration-ladder.md`.
- **PR #1620 / `$Software` TAR source** — complementary edge change-history,
  not a substitute for this framework.

## Updates

### 2026-06-27 — freshness keys off server receipt time, not agent `collected_at` (#1685)

**Decision.** `inventory_state.last_seen` (and `first_seen`) is stamped with the
**server receipt time**, not the agent-supplied `collected_at`. The
`yuzu_inventory_stale_agents` freshness gauge therefore measures *contact
freshness* (when the server last heard from the agent for this source), not
*content-collection time*.

**Why.** The gauge (`count_stale_agents`, surfaced from the metrics sweep)
flags `last_seen < server_now − 2d`. With `last_seen` written from
`collected_at`, that comparison straddled **two clocks** — a server-side
threshold versus an agent-supplied timestamp. A future-skewed or hostile agent
could pin `last_seen` ahead of `now`, so it never counted as stale and a *dark
endpoint stayed hidden* (the worst case); a >2d past-skewed agent counted as
stale while actively syncing (false positive). Server-stamping puts both sides
of the comparison on one clock, immune to agent skew in either direction. This
supersedes the implicit "trust `collected_at` for freshness" of §4/§7.

**Implementation.** No schema change and no new column were needed — `last_seen`
has no display/REST consumer, only the gauge, so the existing column is reused
with corrected write semantics. `collected_at` remains on the wire
(proto-carried) and in the ingest signature for a possible future *content-age*
signal, but drives no persisted timestamp. The write fix is forward-only (a dark
agent cannot re-stamp itself), so **migration v3** clamps any pre-fix row whose
`last_seen` was written into the future down to `now`, re-entering it into the
staleness window. Options weighed and rejected: a `min(collected_at, now)`
*clamp* (kills only future-skew, not past-skew) and a *separate server-stamped
column* (correct but an unnecessary migration given the absent display consumer).

### 2026-06-30 — source #3 `device_ci` (device hardware/OS identity, CMDB CI record)

A third sync source, **`device_ci`**, collects the machine's stable
hardware/OS identity by invoking the existing `hardware`, `device_identity`,
`os_info`, and `network_config` plugins in-process (`LocalDispatcher`) and
rendering them into a canonical CI record: manufacturer, model, **serial
number**, **system UUID**, BIOS vendor/version/date, CPU model/cores/threads,
RAM bytes, a disks summary, **primary MAC** + a MAC summary + NIC count, OS
name/version/build, and architecture. A new `hardware` plugin `system` action
collects serial + UUID (Windows WMI, Linux `/sys/class/dmi/id` via
`cap_dac_read_search`, macOS `ioreg`). **Volatile telemetry — disk free space,
uptime, IP addresses — is deliberately excluded** so the content hash is stable
and hash-skip suppresses steady-state traffic (an IP that churns on DHCP renewal
would flap the hash and force a daily full resend).

**No proto change and no gateway gpb regen.** A new source is a new KEY in the
existing `plugin_data`/`content_hashes` maps, not a new proto FIELD — §6's regen
requirement is about new fields (`content_hashes`/`need_full` themselves), which
already shipped. `app_perf` (source #2) established this precedent; `device_ci`
confirms it. The Erlang gateway decodes/re-encodes only the existing map fields
and never inspects opaque map values, so a new key survives the hop unchanged.

**Store.** Born-on-PG `DeviceInventoryStore` (schema `device_inventory_store`,
table `device_ci`) — **1:1 per agent** (one identity per machine, the
`OfflineEndpointStore` shape), not the 1:N parent+child of §7 (that is for the
N-row `installed_software`). Ingest via the shared `device_ci_ingestion.*` seam
on **both** `ReportInventory` and gateway `ProxyInventory` (§5 parity). Failure
posture per §7: ingest fail-soft, reads authoritative (`std::expected` /
`std::nullopt`, never silent-empty). `last_seen`/`first_seen` are the server
receipt time from day one (#1685).

**Data classification + co-determination (supersedes the borrowed §8 citation).**
§8's "no PII / no co-determination trigger" argument was constructed for
`installed_software` (HKLM app names) and does **not** transfer unchanged:
`serial`, `system_uuid`, and `primary_mac` are **stable device-persistent
identifiers**, which are personal data under GDPR when a device is
person-assigned, and the *capability* to track a device (and by association its
user) over time triggers EU works-council co-determination review regardless of
per-user data. The collection is still **machine-scope** (no username/SID/user
path). The existing **`--inventory-disable`** flag is the collection toggle and
covers `device_ci` at the same gate as the other sources (it gates the whole
daily-sync thread). A DPIA / Workstream-E data-inventory entry for centralizing
serial/UUID/MAC is a pre-PR2 assurance item.

**Binding PR2 requirement — do NOT correlate on `"unknown"`.** When the platform
identity subsystem is unavailable, or a host genuinely has no SMBIOS serial (many
VMs; Linux without the capability), `serial`/`system_uuid` are the literal
`"unknown"`. The PR1 collect skips a cycle only when manufacturer AND model are
both `"unknown"` (a wholesale WMI/DMI outage — `core_identity_unavailable`),
which prevents a transient blip from overwriting a good row and flapping the hash;
but a serial-less VM with real manufacturer/model is persisted with
`serial="unknown"` by design. **PR2's CMDB correlation/merge logic MUST treat
`serial=="unknown"` / `system_uuid=="unknown"` as ABSENT and never merge distinct
devices on it** (otherwise every WMI-down or serial-less host collapses into one
CI). The store keys on `agent_id`, so there is no PR1 collision — this is purely a
PR2 correlation concern. Also note **macOS `IOPlatformUUID` ≠ the SMBIOS UUID**
reported on Windows/Linux, so cross-OS correlation by UUID will miss.

**Known inherited property (forward).** The content hash covers the field *set*,
so a mixed-version rollout (an agent that adds/removes a field vs an older server)
round-trips to a different hash → continuous `need_full` until both sides match.
This is identical to `installed_software` and is a **framework-wide** trait;
hashing the raw received blob bytes instead of the re-serialized record would
neutralize it (and the multi-copy scrub/clamp drift surface) but must be done for
**all** sources together, not `device_ci` alone — tracked as a follow-up. The
agent↔server scrub/clamp byte-equality is locked by a clean **and dirty** cross-pin
test today. A 1-byte blob format-version prefix is the other future-proofing option.

The `yuzu_inventory_stale_agents` freshness gauge is **not** yet extended to
`device_ci` (it reads `SoftwareInventoryStore::count_stale_agents` only); the
#1685 server-stamped `last_seen` is in place but its gauge consumer is a deferred
follow-up (same as `app_perf`).
