# ADR-0020: Software Catalog & Licensing (agent-detected licence compliance)

**Date:** 2026-07-04
**Status:** Proposed
**Component:** Agent (new `license_scan` plugin + sync source) · Server (two new Postgres stores, ingest seam, compliance evaluator, REST/MCP/UI) · Gateway (proxy passthrough)
**Authors:** Alex Young

## Executive summary

This ADR delivers capability-map **§27 Software Catalog & Licensing** (roadmap
Phase 10, issues #264–#267) across three governed PRs. It answers four
operator questions the platform cannot answer today:

1. **What software licences are in use on an asset, and of what type?**
2. **Is anything running on a lapsed licence?**
3. **Which licences are coming up for renewal/expiry?**
4. **What are we paying for that is never or rarely used?** (reclamation)

**How:** licence data is **detected by agents, never entered manually**. A new
`license_scan` agent plugin probes every licence surface available on the
endpoint (Windows OS licensing API, Office, vendor registry/licence-file
probes, per-user licence artefacts, Linux package metadata + entitlement
certs + FlexLM, macOS receipts) and reports per-install records —
product, licence type, channel, status, expiry — via a new `software_licensing`
daily-sync source (ADR-0016 framework, hash-skip, no proto change). Two new
born-on-Postgres stores hold canonical software identities
(`SoftwareCatalogStore`, with deterministic automatic matching) and detected
licence state (`SoftwareLicensingStore`). A background evaluator derives
**effective licence state** (including lapse) server-side, rolls up per-product
fleet posture, and emits deduplicated `software_license.expiring` /
`software_license.expired` notifications + webhook events. Operators get a
LICENSING tab on `/inventory`, `/api/v1/licensing/*` REST, and MCP tools, all
gated on a new `SoftwareCatalog` securable. PR2 adds machine-scope usage
metering (last-used / launch counts from the TAR edge warehouse) to power
reclamation; PR3 adds software tags and the reclamation dashboard.

**Honesty commitments baked into the design:** with no purchase register there
is **no purchased-vs-installed seat math** — compliance is per-install detected
state, expiry warnings, and usage-based waste. Detection confidence
(`authoritative`/`probable`/`heuristic`) and `unknown` states are first-class
and surfaced, never papered over. Reclamation never fires on missing data
(absent usage source ⇒ *Unreported*, not *Unused*).

**Deliberate deviation:** at the product owner's direction, licence detection
probes **per-user surfaces** (user registry hives, profile licence files) for
coverage, which deviates from ADR-0016's machine-scope/no-PII posture. §8
isolates that data in two suppressible fields and defines the remediation
path; this carve-out applies to the `software_licensing` source **only**.

## Context

The capability map (§27, five sub-capabilities, all Not Started) and roadmap
Phase 10 sketched this feature in 2026-03 as: a SQLite `CatalogStore`, a
manual entitlement register (product, purchased_seats, license_type), a
`software_usage` agent plugin, software tags, and a compliance dashboard.
Three things have changed under that sketch:

- **The storage substrate moved.** ADR-0006/0007 forbid new SQLite server
  stores; new stores are born-on-Postgres per the store playbook and
  ADR-0012. The Phase 10 file names ("CatalogStore (SQLite)",
  `entitlement_store.cpp`) are stale.
- **The ingestion substrate now exists.** ADR-0016's daily-sync framework is
  live with three sources (`installed_software`, `app_perf`, `device_ci`),
  a shared server ingest seam used by both the direct gRPC path and the
  Erlang gateway proxy, and typed Postgres projections
  (`SoftwareInventoryStore` et al.). ADR-0016 explicitly anticipated "a
  future `last_used` usage source for SAM/entitlement" — this ADR is that
  future, plus licence detection.
- **The product decision changed.** The manual entitlement register drafted in
  issue #266 is **rejected by the product owner**: licence data must be
  automatically detected by agents. Manual seat/contract entry is out of
  scope for all three PRs. Consequently "over/under-licensed vs purchased
  seats" is not computable and is explicitly **not** claimed; the compliance
  model is per-install detected licence state.

Name collisions constrain the design: `LicenseStore` and the `License` RBAC
securable already exist for **Yuzu's own product licence** (capability §22.3)
and are untouched; everything here uses `SoftwareCatalog*`/`SoftwareLicensing*`
naming and `software_license.*` event names.

## Decision

### 1. Agent detection — new `license_scan` plugin

A new plugin at `agents/plugins/license_scan/` (C ABI v3, `yuzu::Plugin`,
pipe-delimited output, cross-platform in per-OS translation units with pure
parsers split out for unit testing). Actions: `list` (run all surfaces, emit
records) and `surfaces` (diagnostics: which surfaces are available and why
not).

Output wire contract (one record per detected licence):

```
lic|product|vendor|version|license_type|channel|status|expires_at|source|confidence|key_hint|exe_hints|user_scope|user_ref
probe_status|<surface>|ok|<rows>        (one per surface)
probe_status|<surface>|error|<message>
```

Closed vocabularies (unknown-preserving — the plugin never fabricates):

- `license_type`: `perpetual | subscription | trial | volume | oem | retail | open_source | freeware | unknown`
- `status`: `licensed | subscription_active | trial | grace | expired | unlicensed | unknown`
- `source`: `os_licensing_api | entitlement_cert | registry_probe | license_file | package_metadata | app_receipt | heuristic`
- `confidence`: `authoritative | probable | heuristic` — `authoritative` only
  from an OS/vendor licensing API or a parsed vendor licence artefact.

Detection surfaces (v1):

| Platform | Surface | Confidence | Yields |
|---|---|---|---|
| Windows | WMI `SoftwareLicensingProduct` (own bounded COM; never `WBEM_INFINITE`; 10 s `Next` timeout, 512-row cap) | authoritative | OS + Office/MS-server licence status, channel (KMS/MAK/OEM/retail), grace, `EvaluationEndDate`, partial key |
| Windows | Office ClickToRun registry (`HKLM\...\ClickToRun\Configuration`) | probable | C2R SKU → subscription/volume type |
| Windows | Extensible `ProbeSpec` table: MS server products (SQL Server, Exchange, Visual Studio machine installs), Autodesk (AdskLicensing configs), security/backup agents (Veeam, Acronis, AV suites), VMware Workstation, WinRAR, open-source classification rows | probable/heuristic | presence/type/serial-derived hints, `exe_hints` |
| Windows | **Per-user surfaces** (HKU hives incl. `RegLoadKey` of offline `NTUSER.DAT` — precedent: registry plugin §12.7; profile licence files, e.g. JetBrains `%LOCALAPPDATA%`, Adobe NGL) | probable | per-user licence records, `user_scope=user`, `user_ref=<profile>` (see §8) |
| Linux | `rpm --qf %{LICENSE}` / dpkg DEP-5 `copyright` header | probable/heuristic | declared licence classification (no lapse detection — stated) |
| Linux | RHEL entitlement certs (`/etc/pki/entitlement/*.pem` notAfter) | authoritative | subscription expiry |
| Linux | FlexLM `.lic` files (MATLAB/Ansys-class; pure `INCREMENT` parser) | authoritative (expiry) | feature expiry dates |
| macOS | `_MASReceipt` presence + `Info.plist` identity; machine-scope vendor plists (Office volume, Parallels) | probable | App Store/retail licensed |

Adding a vendor later = one `ProbeSpec` table row (+ optional interpreter
function); no engine change.

Sanitisation: every field strips `| \n \r 0x1F 0x1E NUL` and clamps to
1024 bytes; the sync source re-clamps defensively and the server seam clamps
again (untrusted input).

### 2. Transport — `software_licensing` daily-sync source

`agents/core/src/sync_source_software_licensing.{hpp,cpp}` mirrors
`sync_source_installed_software`: parse plugin output → canonical blob
(records sorted + deduped, fields `0x1F`-joined, records `0x1E`-joined) →
SHA-256, cross-pinned byte-for-byte with the server's recomputation. Wire key
`software_licensing` in `InventoryReport.plugin_data` — **no proto change, no
gateway regen** (opaque `map<string,bytes>`, verified against
`agent_pb.erl` + the gateway inventory wire tests). Interval 24 h; hash-skip
is meaningful because licence estates are stable day-to-day.

**Blob stability rule:** the canonical blob contains only facts that change
when detected state changes. No collection timestamps; countdowns (KMS grace
minutes) are converted to an absolute UTC date (`collection_time + remaining`,
date-truncated) so a ticking counter does not defeat hash-skip. Enforced by a
two-collects-same-hash unit test.

**Empty-vs-error semantics:** zero licence rows is a legitimate state (minimal
Linux box) and sends a valid empty blob (server full-replaces to empty). The
cycle is skipped (`nullopt`) only when the platform's *primary* surface
reported `probe_status|...|error` — a real failure must not wipe stored state.

Shared canonical helpers (`sanitize_utf8_strict`, `clamp_field`,
`sha256_hex`) are extracted from `sync_source_installed_software.cpp` into
`agents/core/src/sync_canonical.{hpp,cpp}` first; the existing cross-pin test
proves the refactor is byte-neutral.

The source registers beside the existing three in `agent.cpp` and shares the
existing `inventory_disable` opt-out.

### 3. Server stores — two new born-on-Postgres stores

Per the postgres-store playbook (migrate-at-construction on a pinned lease,
schema-qualified runtime SQL, `exec_params`, `RETURNING`, bounded leases,
fatal-on-open-failure inside the `pg_pool_` guard, destruct-before-pool):

**`SoftwareCatalogStore`** (schema `software_catalog_store`) — §27.1 canonical
identities + match links. Migration v1:

- `catalog_products(product_id BIGSERIAL PK, norm_key TEXT UNIQUE, vendor,
  title, edition, platform, created_at, updated_at)`
- `catalog_aliases(source, raw_name, raw_publisher, product_id FK CASCADE,
  method, confidence, first_matched_at, last_seen_at,
  PK(source, raw_name, raw_publisher))` + index on `product_id`

Migration v2 (PR3): `catalog_tags(product_id FK CASCADE, tag, created_by,
created_at, PK(product_id, tag))`.

Posture: authoritative reads (nullopt on degrade → REST 503); writes come only
from the background evaluator (fail-soft, retried next cycle).

**`SoftwareLicensingStore`** (schema `software_licensing_store`) — per-agent
detected licence rows + posture rollups + alert dedup. Migration v1:

- `agent_license_state(agent_id PK, content_hash, first_seen, last_seen)` —
  hash-skip parent; timestamps are **server receipt time** (ADR-0016
  clock-skew rule)
- `agent_licenses(id, agent_id FK CASCADE, product, vendor, version,
  license_type, state, expiry_at /*agent-observed epoch, 0=none*/, channel,
  key_hint, detector, user_scope, user_ref, collected_at, first_seen,
  last_seen)` + indexes on `agent_id`, `state`, partial on `expiry_at > 0`
- `license_posture_rollup(product_key PK /*soft key = catalog norm_key*/,
  vendor, title, device_count, install_count, per-effective-state counts,
  next_expiry_at, expiring_soon_count, refreshed_at)`
- `license_alert_state(product_key PK, fingerprint, bucket, last_fired_at)`

Ingest fail-soft; reads authoritative — a silent empty list would read as
"nothing expired", which is a fail-open compliance lie (ADR-0016 §7 posture).

PR2 adds **`SoftwareUsageStore`** (schema `software_usage_store`):
`agent_usage_state` hash parent + `agent_app_usage(agent_id, app_name /*bare
exe*/, last_used_day, starts_30d_bucket, starts_90d_bucket, days_active_90d,
first_seen, last_seen, PK(agent_id, app_name))`. Usage categories are derived
at read time, not stored (§5).

No cross-schema SQL or FKs; cross-store joins happen in C++ in the evaluator
(ADR-0012 lease discipline: never hold a lease across another store call).

### 4. Ingest seam + the typed-source registry

`server/core/src/software_licensing_ingestion.{hpp,cpp}` (and
`software_usage_ingestion.{hpp,cpp}` in PR2) sit beside
`inventory_ingestion.cpp` / `app_perf_ingestion.cpp` and are called from
**both** `AgentServiceImpl::ReportInventory` and the gateway
`ProxyInventory`. Untrusted-input discipline at the seam, before the store:
blob ≤ 1 MiB, ≤ 10 000 records, field ≤ 1024 B UTF-8-scrubbed exactly as the
agent clamps (so the server-side hash recomputation matches), enum whitelists
(unrecognised → `unknown`), `expiry_at` plausibility-clamped. The server
**recomputes** the canonical hash — it never trusts the claimed one.

**Load-bearing:** each new wire key is added to
`typed_inventory_sources.hpp::is_typed_inventory_source()` **in the same
commit** as its seam. Omission double-stores the blob into the generic
`InventoryStore` on the gateway path, readable under `Infrastructure:Read` —
a leak past the `SoftwareCatalog` securable. A parity test asserts the skip.

### 5. Compliance semantics + background evaluator

`server/core/src/license_compliance_evaluator.{hpp,cpp}` — one background
thread cloning the `SoftwareCatalogRollup` lifecycle (first pass at boot, then
completion-spaced hourly cadence, keep-last-good, stop/join before store
teardown). Passes, sequential:

1. **Catalog matching** (§27.1) via a pure library
   `catalog_normalize.{hpp,cpp}`: `normalize_title` (lowercase, strip
   arch/version/edition tokens → edition extracted), `normalize_vendor`
   (strip legal suffixes, alias table), then strictly ordered deterministic
   tiers — `exact_norm` (1.0) → `title_vendor` (0.9) → `token_set` (0.8) →
   `birth` (new product). **No probabilistic/Levenshtein matching in v1** —
   every decision is reproducible in unit tests. Aliases persist
   `method`+`confidence` so manual curation can layer on later by editing
   aliases, without redesign. Inputs: distinct names from
   `SoftwareInventoryStore::software_catalog()` (consumed via public API —
   never modified) + distinct products from `SoftwareLicensingStore`; PR2
   adds `source='usage'` with an exe→title seed-map tier fed by `exe_hints`.
2. **Posture rollup**: per-product counts by
   `effective_license_state(state, license_type, expiry_at, now)` — the
   server re-derives lapse against server-now so a device that *stopped
   syncing* before its licence lapsed still shows `expired` (driver 2's
   definition of lapsed: effective state ∈ {expired, unlicensed});
   `next_expiry_at`; `expiring_soon_count` (≤ 30 days); `install_count`
   joined from installed-software rows through `catalog_aliases` — the
   "installed but licence-unreported" delta is shown, not hidden.
3. **Alert pass** (§6).

Usage categories (PR2) are policy, computed server-side at read time from
agent-shipped facts (`last_used_day`, bucketed counts): Used ≤ 30 d, Rarely
31–90 d, Unused > 90 d, **Unreported** = no usage source for the asset (TAR
absent/disabled) or no matched usage row. Thresholds live server-side so a
policy change never forces fleet re-sync, and *Unreported never counts as
Unused* — reclamation must not fire on missing data.

### 6. Notifications / events (deduplicated)

The evaluator computes per-product condition fingerprints — `expired`
(expired+unlicensed count > 0) and `expiring` bucketed by min-days-to-expiry
(30/14/7/1) — and fires **only** on (a) fingerprint/bucket transition, or
(b) persistence past a 7-day re-arm. Emission uses the existing dual-sink
pattern (`server.cpp` alert wiring): `NotificationStore::create(...)` +
`webhook_store_`/`offload_target_store_->fire_event(...)` with event types
**`software_license.expiring`** / **`software_license.expired`** and payload
`{event, product_key, vendor, title, device_count, next_expiry_at, days_left,
bucket}`. This satisfies "not dashboard-only" without daily spam, and
escalates as expiry approaches.

### 7. Access surfaces — REST, RBAC, MCP, UI

New securable **`SoftwareCatalog`** seeded in `rbac_store.cpp seed_defaults()`
(Read granted to the standard viewer/operator role lists; `Write` used only by
PR3 tag CRUD). No MFA step-up anywhere in §27 — nothing executes on endpoints.

REST (`rest_api_v1.cpp`, modelled on the `/api/v1/inventory/software`
handler: auth → perm → 503-on-degrade → limit clamp 1..1000 → scope filter →
audit, errors via `error_json_a4` + X-Correlation-Id):

- `GET /api/v1/licensing/summary` — fleet posture headline (global gate;
  ADR-0017 confinement caveat documented, same as the software catalog read)
- `GET /api/v1/licensing/products?state=&expiring_within_days=&q=&limit=`
- `GET /api/v1/licensing/products/{key}/devices` — per-device rows behind the
  ADR-0017 admit-then-filter predicate, filtered **before** LIMIT
- `GET /api/v1/licensing/agents/{agent_id}` — driver 1, scoped per-device gate
- PR2: `GET /api/v1/licensing/reclamation?unused_days=90`
- PR3: `GET/POST/DELETE /api/v1/catalog/products/{id}/tags`

MCP (`mcp_server.cpp`, tier-before-RBAC): `query_software_licenses`,
`get_license_compliance_summary` (PR3: `query_license_reclamation`).

UI: a **LICENSING tab on the existing `/inventory` page** (extends
`inventory_routes.{hpp,cpp}` with closures; renderers in a new
`inventory_licensing_ui.cpp`) — KPI strip (expired / expiring-30d /
unlicensed / unknown, "as of" from rollup meta), product posture table with
state chips, product→device and device→licences drill-downs, one ECharts
state-mix donut via the `yuzu-chart-card` adapter. Command-palette entry only;
no new top-level nav item (avoids the hand-duplicated nav edit across every
`*_ui.cpp`). Store degrade renders an honest banner, never an empty table.

### 8. Scope, identity, and privacy — the per-user carve-out

ADR-0016 §8 set a machine-scope/no-PII posture for daily-sync sources. At the
product owner's explicit direction ("probe everything; full coverage of all
available licence surfaces; remediation can come later"), the
`software_licensing` source **deviates**: per-user licence surfaces are
probed, and records may carry `user_scope=user` + `user_ref=<local profile
name>`. Containment and remediation path:

- The deviation is confined to **two fields on one source**. `user_ref` is a
  local profile name only — never SIDs, emails, or directory identities.
- Machine-scope records (`user_scope=machine`, `user_ref` empty) remain the
  overwhelming majority; per-user probes add coverage for per-user-licensed
  products (JetBrains, Adobe-class) that are otherwise `unknown`.
- **Remediation later** (as directed): a single agent-side flag can suppress
  or hash `user_ref` without schema or wire changes; a follow-up issue tracks
  making that the works-council deployment profile default if required.
- The **usage** source (PR2) does **not** inherit this carve-out: usage rows
  stay machine-scope, the per-user TAR dimension is aggregated out on the
  agent (`GROUP BY` app name only), and a unit test fails if a username
  column or value reaches the blob.
- Licence **key material is never persisted or transmitted**: `key_hint` is
  the OS-provided partial (last-5) or an in-memory SHA-256 prefix of key
  files; full keys never touch output, logs, or KvStore. This moots ADR-0010
  SecretCodec for these stores by construction.

Maintainer sign-off on this section is requested explicitly in the PR1
review (it amends ADR-0016's posture for this source).

### 9. Identity join (installed ⨝ licence ⨝ usage)

Three name spaces reach the server: installed display names, licence product
names, and (PR2) bare exe image names (Windows ETW is name-only). Joins:
`exe_hints` on licence records (from the probe table) are the authoritative
product↔exe bridge; then a server-side exe→title seed map; then normalised
title matching; anything left is an honest **unmatched** bucket excluded from
reclamation verdicts (conservative by design — a paid product is only
"unused" when its install row exists AND matched usage says so, or usage is
entirely absent → *Unreported*).

## Delivery roadmap (three governed PRs)

Each PR is independently shippable, runs the full `/governance` 8-gate +
`/test` pipelines, branches from `origin/dev`, and ships a `changelog.d/`
fragment. Sequential (each builds on the previous PR's merged stores/UI).

### PR1 — `feat/software-licensing` — licence visibility + expiry alerting
**Drivers 1–3. Closes #266 (reframed to agent-detected licensing — override
of the manual entitlement register documented on the issue), closes #264
(catalog store; automatic matching here, `/inventory` foundation delivered by
PR #1759), advances the new §27.5 dashboard issue.**

- Agent: `license_scan` plugin (§1) + `sync_canonical` extraction +
  `sync_source_software_licensing` (§2), registered in `agent.cpp`.
- Server: `SoftwareCatalogStore` + `SoftwareLicensingStore` (§3),
  `software_licensing_ingestion` + typed-source registry entry (§4),
  `catalog_normalize` + `license_compliance_evaluator` (§5), notifications
  (§6), `SoftwareCatalog` securable + REST + MCP + LICENSING tab (§7).
- Docs: this ADR; `postgres-migration-ladder.md` ticks (two stores);
  capability-map §27.1/§27.3 status; roadmap Phase 10 staleness note;
  `docs/user-manual/software-licensing.md`.
- Tests: pure normalize/parser suites; `[pg]` store suites (hash-skip
  trichotomy, replace-in-txn, nullopt-on-degrade, cascade); ingest caps +
  **cross-pinned canonical-hash constant shared byte-for-byte between the
  agent and server test files**; evaluator with injected clock (transitions,
  buckets, re-arm, degrade ≠ false all-clear); route tests (authz, 503,
  scope filter); blob-stability test.
- Size ~3k LOC. Pre-agreed split seam if review requests it: PR1a =
  plugin + source + stores + ingest + REST; PR1b = UI + evaluator/events +
  MCP.

### PR2 — `feat/software-usage-metering` — usage facts for reclamation
**Driver 4 (data layer). Closes #265.**

- Agent: `sync_source_software_usage` querying the TAR warehouse via the TAR
  plugin's sandboxed read-only `sql` action through `LocalDispatcher` (no
  second DB handle; ADR-0016 prescribed exactly this seam). Machine-scope
  aggregation (user dimension dropped on-device, test-enforced), bucketed
  counts + `last_used_day` (monthly-tier fallback errs toward "recently
  used" — never over-claims unused). Hash-less like `app_perf`. **Opt-in**:
  `--usage-sync-enable` / `YUZU_AGENT_USAGE_SYNC_ENABLE`, default off; TAR
  absent/disabled → source no-ops → asset is *Unreported*.
- Server: `SoftwareUsageStore` + ingest seam + typed-source entry; evaluator
  reclamation pass (usage→catalog join per §9; Used/Rarely/Unused/Unreported
  per §5); `GET /api/v1/licensing/reclamation`; usage column on the software
  tab.
- Docs: ADR-0021 (usage metering privacy posture) or an Updates section
  here; ladder tick; capability-map §27.2.

### PR3 — `feat/software-tags-reclamation` — tags + reclamation dashboard
**Driver 4 (visible reclamation). Closes #267 + the new §27.5 issue.**

- `SoftwareCatalogStore` migration v2 (`catalog_tags`); tag CRUD REST
  (`SoftwareCatalog:Write`) + tag chips in the catalog/licensing UI.
- Management-group dynamic-rule integration ("devices with software tagged
  X") — time-boxed; splits to a follow-up issue rather than bloat the PR.
- RECLAMATION view on the LICENSING tab: candidates = paid `license_type` ×
  (Unused | Rarely used), per-title drill-down, charts; unmatched-usage
  coverage view (honest gap reporting).
- MCP `query_license_reclamation`; capability-map §27.4/§27.5 done.

## Consequences

- Yuzu can answer, per asset and fleet-wide: what licences exist, their
  types/channels, what has lapsed, what expires within N days — with
  notifications — and (after PR2/PR3) what paid software is going unused.
- No manual data entry anywhere; the licence picture is only as good as the
  detection surfaces, and the UI says so (`confidence`, `unknown`,
  *Unreported*, installed-but-licence-unreported deltas are all visible).
- No purchased-seat compliance claims. If a purchase register is ever
  wanted, it layers on as a new store + evaluator input without disturbing
  the detected-state model (aliases and rollups already carry the keys it
  would join on).
- Two (then three) more born-on-Postgres stores join the ladder; server
  refuses to boot if their migrations fail (consistent with the substrate
  posture).
- The per-user carve-out (§8) is a deliberate, contained ADR-0016 deviation
  requiring maintainer sign-off, with a one-flag suppression path.
- Fleet network cost is negligible: licence blobs hash-skip (stable
  estates), usage blobs are tens of KB daily from active machines only.

## Alternatives considered

- **Manual entitlement register (roadmap 10.3 as drafted)** — rejected by
  product decision; purchased-seat math is explicitly out of scope.
- **Routing licence/usage data through TAR** — rejected; ADR-0016 already
  settled this (TAR is pull-only, event-shaped, edge-resident). The usage
  source *reads* TAR locally and pushes via daily-sync.
- **A new top-level dashboard page** — rejected; the nav bar is hand-copied
  into every `*_ui.cpp`, and `/inventory` (PR #1759) is the natural home.
- **Fuzzy/probabilistic catalog matching in v1** — rejected for determinism
  and testability; the tiered exact/normalised/token-set matcher with
  persisted method+confidence leaves room for smarter matching later.
- **Extending `SoftwareInventoryStore`** with licence columns — rejected;
  one-store-per-typed-domain is the established precedent, and installed
  software vs detected licences have different lifecycles and postures.
- **MFA step-up on licensing endpoints** — rejected; nothing in §27 executes
  on endpoints; tags are non-destructive metadata.

## Relationship to other ADRs

- **ADR-0006/0007/0008/0012** — both new stores are born-on-Postgres under
  the store contract; no SQLite anywhere.
- **ADR-0016** — this feature is two new daily-sync sources riding the
  framework exactly as anticipated; §8 above records the single, contained
  deviation from its no-PII posture (licence source only) and the usage
  source's full conformance. The typed-source registry rule (§4) implements
  ADR-0016 §5 parity.
- **ADR-0017** — per-device licensing reads route through the
  admit-then-filter list gate; fleet aggregates carry the documented
  inert-confinement caveat until the gate lands fleet-wide.
- **ADR-0010** — mooted by construction: no licence key material is stored.
