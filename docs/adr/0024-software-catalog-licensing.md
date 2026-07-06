# ADR-0024: Software Catalog & Licensing (agent-detected compliance + entitlements)

**Date:** 2026-07-04
**Revised:** 2026-07-04 (rev 2 — entitlements return to scope; SCL top-level page) · 2026-07-06 (rev 3 — review remediation on PR #1870: renumbered 0020→0021 [0020 was already owned by the accepted TAR-netqual retrospective]; M365 secret via SecretCodec; SCL aggregates pinned global-only per ADR-0017; named `user_ref` config knob shipped in PR1; `ProductRegistryStore` rename; enterprise data-inventory acceptance criteria; terminology and registry-encoding rules) · 2026-07-06 (rev 4 — second review round on PR #1870: renumbered 0021→0024 [0021 is claimed by two open branches (spark-reflex, cavm-observed-reachability), 0022 by vuln-dashboard, 0023 by vuln-correlation-engine — verified across all open remote branches, first-to-merge wins]; the M365 client secret moves **out of `RuntimeConfigStore` entirely** into a SecretCodec-registered column on the born-on-PG entitlement store, and PR2 owns the codec's **first production wiring** with named encrypted-at-rest / fail-closed tests; `--license-scan-user-ref` default flipped `collect`→`hash` and `hash` upgraded from unsalted `sha256/12` to a **per-agent keyed HMAC**; `docs/os-capability-matrix.md` + `docs/agent-privilege-model.md` rows added to the PR1 file plan; same-day internal governance pass [6 gates, docs-only adaptation — all PASS, no CRITICAL/HIGH] folded in: `exe_hints` persisted from migration v1, M365 connector input pinning + admin-gated config + config-write audit event, worsening-only/hold-down alert semantics, §6 Observability metric families, §8 GDPR-personal-data/erasure/`omit`-scope/effective-mode-verifiability clarifications, `host_ref` format pin, no-reaper retention statements, user-manual REST/MCP/TOC/metrics doc rows across PR1–PR4, PR3 `delete_agent` hook) · 2026-07-06 (rev 5 — third review round on PR #1870, **blockers only**; the round's should-fix/minor items are deliberately deferred to the implementation PRs per operator direction and remain recorded on the PR review: §10.3 SecretCodec wiring **reordered** to `register_secret_column` + `set_audit_hook` **before** `codec.init()` — `init()` snapshots the registered columns for the boot-time orphan scan and emits the first-boot `kek.generated` audit event, so the rev-4 order silently dropped both; §7 per-device SCL routes **no longer claim the not-yet-implemented ADR-0017 PR-A chokepoint** — they ship global-gated in PR1 (the same inert-confinement posture as every existing list read) and are registered as flip-wave consumers of PR-A [#1634 umbrella, #1715 prerequisite — PR-A has no dedicated tracker; the `#1716` comment forward-references in server/core point at a closed doc-honesty PR, not the gate], with the filters-before-LIMIT test landing at the flip)
**Status:** Proposed
**Component:** Agent (new `license_scan` plugin + sync source) · Server (three new Postgres stores, ingest seams, compliance evaluator, M365 licensing connector, SCL page, REST/MCP) · Gateway (proxy passthrough)
**Authors:** Alex Young

## Executive summary

This ADR delivers capability-map **§27 Software Catalog & Licensing** (roadmap
Phase 10, issues #264–#267, #1869) across four governed PRs. It answers five
operator questions the platform cannot answer today:

1. **What software licences are in use on an asset, and of what type?**
2. **Is anything running on a lapsed licence?**
3. **Which licences and subscriptions are coming up for renewal/expiry?**
4. **How does what we've purchased compare with what's deployed?**
   (over-/under-licensed per product, where entitlement data exists)
5. **What are we paying for that is never or rarely used?** (reclamation)

**How — two data planes:**

- **Licence detection is agent-only.** A new `license_scan` agent plugin
  probes every licence surface available on the endpoint (Windows OS
  licensing API, Office, vendor registry/licence-file probes, per-user
  licence artefacts, Linux package metadata + entitlement certs + FlexLM,
  macOS receipts) and reports per-install records — product, licence type,
  channel, status, expiry — via a new `software_licensing` daily-sync source
  (ADR-0016 framework, hash-skip, no proto change).
- **Entitlements (what is purchased) accept manual, CSV, and automated
  input** (rev 2): a per-record form and CSV upload in the GUI, a raw
  `text/csv` REST ingest endpoint, a scheduled **Microsoft Graph M365
  connector** (`subscribedSkus` purchased-vs-consumed seats +
  `/directory/subscriptions` renewal dates), and **agent-observed
  entitlements** (FlexLM licence-file seat counts, KMS host activation
  counts) riding the same daily-sync source as a second record kind.

Three new born-on-Postgres stores hold canonical software identities
(`ProductRegistryStore`, with deterministic automatic matching), detected
licence state (`SoftwareLicensingStore`), and entitlements
(`SoftwareEntitlementStore`). A background evaluator derives **effective
licence state** (including lapse) server-side, computes per-product
**purchased-vs-deployed compliance** where entitlement data exists, rolls up
fleet posture, and emits deduplicated `software_license.expiring` /
`software_license.expired` / `software_entitlement.renewal_due`
notifications + webhook events. Operators get a **new top-level SCL page**
(Software Catalog & Licensing: Licences | Entitlements | Compliance
sub-views, with the software catalog staying on `/inventory`, cross-linked),
`/api/v1/scl/*` REST, and MCP tools, all gated on a new `SoftwareCatalog`
securable.

**Honesty commitments baked into the design:** purchased-vs-installed math is
claimed **only for products with entitlement data** — detected-only products
carry an explicit `unentitled`/detected-state-only posture, never "compliant".
Seat sums across sources keep a per-source breakdown visible (double-counting
is shown, not hidden). Detection confidence
(`authoritative`/`probable`/`heuristic`) and `unknown` states are
first-class. Reclamation never fires on missing data (absent usage source ⇒
*Unreported*, not *Unused*). Unknown seat counts are `NULL`, never a
fabricated zero.

**Deliberate deviation:** at the product owner's direction, licence detection
probes **per-user surfaces** (user registry hives, profile licence files) for
coverage, which deviates from ADR-0016's machine-scope/no-PII posture. §8
isolates that data in two fields controlled by a **named knob shipped in PR1**
(`--license-scan-user-ref=collect|hash|omit`, **default `hash`** — a per-agent
keyed-HMAC pseudonym, rev 4; raw profile names are opt-in) and makes
data-inventory transparency a PR1 acceptance criterion; this carve-out
applies to the `software_licensing` source **only**.

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
  issue #266 was initially **rejected by the product owner**: licence data
  must be automatically detected by agents.

**Revision 2 (2026-07-04).** The product owner revised the entitlement
decision: entitlements — purchased seats, licence type, renewal dates, cost —
**return to scope**, measured alongside detected licences, with
purchased-vs-deployed compliance math for entitled products. Inputs:
automated where an API exists (Microsoft Graph M365; agent-observable FlexLM
seat counts and KMS activation counts), plus a GUI form, GUI CSV upload, and
a CSV REST ingest. The earlier rejection stands **only for licence
detection**, which remains agent-only. The owner also directed a **brand-new
top-level "SCL" dashboard page**, reversing rev 1's tab-on-/inventory choice;
the software catalog itself stays on `/inventory` (SCL links across).

Name collisions constrain the design: `LicenseStore` and the `License` RBAC
securable already exist for **Yuzu's own product licence** (capability §22.3)
and are untouched; everything here uses
`ProductRegistry*`/`SoftwareLicensing*`/`SoftwareEntitlement*` naming and
`software_license.*`/`software_entitlement.*` event names. Likewise,
"software catalog" already means the shipped `/inventory` rollup of
**installed** software (`SoftwareCatalogRow`/`SoftwareCatalogRollup`) — the
new canonical-identity store is therefore named **`ProductRegistryStore`**
(a master-data registry, not a catalog), and "software catalog" keeps its
existing meaning. The **`SoftwareCatalog` securable name is retained**: it
gates the whole §27 capability surface and matches the capability-map name,
not the registry store.

**Terminology rule (rev 3, applies to all downstream docs/UI/support copy):**
the bare word "licence" is ambiguous the moment this ships. Always qualify:
**"Yuzu licence"** for the product licence (§22.3), **"software licence"** /
**"detected licence"** for endpoint software licensing. Spelling of the
capability name follows the capability map: **"Catalog"** (SCL = "Software
Catalog & Licensing").

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

**Registry string encoding (rev 3):** all Windows registry string reads in
this plugin follow the repo-wide rule — wide `Reg*W` APIs +
`WideCharToMultiByte(CP_UTF8)` via `agents/shared/win_str.hpp`, never
`Reg*A` — and `test_licensing_parsers.cpp` includes a **non-ASCII registry
fixture** (product/vendor values with non-Latin characters) proving the
round-trip.

**Forward compatibility (load-bearing, shipped in PR1):** both the agent-side
blob parser and the server ingest seam **skip unrecognised record-kind
prefixes** (test-enforced). This lets later PRs add record kinds — §10's
`ent|` entitlement records — without breaking mixed-version fleets in either
direction (a PR2 agent talking to a PR1 server, or vice versa, degrades to
ignoring the unknown kind rather than erroring or wiping state).

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

### 3. Server stores — three new born-on-Postgres stores

Per the postgres-store playbook (migrate-at-construction on a pinned lease,
schema-qualified runtime SQL, `exec_params`, `RETURNING`, bounded leases,
fatal-on-open-failure inside the `pg_pool_` guard, destruct-before-pool):

**`ProductRegistryStore`** (schema `product_registry_store`) — §27.1 canonical
identities + match links. Migration v1:

- `products(product_id BIGSERIAL PK, norm_key TEXT UNIQUE, vendor,
  title, edition, platform, created_at, updated_at)`
- `product_aliases(source, raw_name, raw_publisher, product_id FK CASCADE,
  method, confidence, first_matched_at, last_seen_at,
  PK(source, raw_name, raw_publisher))` + index on `product_id`

Migration v2 (PR4): `product_tags(product_id FK CASCADE, tag, created_by,
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
  key_hint, detector, exe_hints, user_scope, user_ref, collected_at,
  first_seen, last_seen)` + indexes on `agent_id`, `state`, partial on
  `expiry_at > 0` — `exe_hints` is persisted from migration v1 (governance
  pass): it is on the §1 wire contract and is §9's authoritative
  product↔exe bridge for PR3's usage join; adding it later would leave the
  column empty on stable estates (hash-skip suppresses re-sync exactly when
  nothing changes)
- `license_posture_rollup(product_key PK /*soft key = catalog norm_key*/,
  vendor, title, device_count, install_count, per-effective-state counts,
  next_expiry_at, expiring_soon_count, refreshed_at)`
- `license_alert_state(product_key PK, fingerprint, bucket, last_fired_at)`

Ingest fail-soft; reads authoritative — a silent empty list would read as
"nothing expired", which is a fail-open compliance lie (ADR-0016 §7 posture).

**`SoftwareEntitlementStore`** (schema `software_entitlement_store`, PR2) —
purchased-state records from five sources; full design in §10.

PR3 adds **`SoftwareUsageStore`** (schema `software_usage_store`):
`agent_usage_state` hash parent + `agent_app_usage(agent_id, app_name /*bare
exe*/, last_used_day, starts_30d_bucket, starts_90d_bucket, days_active_90d,
first_seen, last_seen, PK(agent_id, app_name))`. Usage categories are derived
at read time, not stored (§5).

No cross-schema SQL or FKs; cross-store joins happen in C++ in the evaluator
(ADR-0012 lease discipline: never hold a lease across another store call).

### 4. Ingest seam + the typed-source registry

`server/core/src/software_licensing_ingestion.{hpp,cpp}` (and
`software_usage_ingestion.{hpp,cpp}` in PR3) sit beside
`inventory_ingestion.cpp` / `app_perf_ingestion.cpp` and are called from
**both** `AgentServiceImpl::ReportInventory` and the gateway
`ProxyInventory`. Untrusted-input discipline at the seam, before the store:
blob ≤ 1 MiB, ≤ 10 000 records, field ≤ 1024 B UTF-8-scrubbed exactly as the
agent clamps (so the server-side hash recomputation matches), enum whitelists
(unrecognised → `unknown`), `expiry_at` plausibility-clamped. The server
**recomputes** the canonical hash — it never trusts the claimed one. From
PR2, `ent|` records in the same blob route to the entitlement store (§10);
unrecognised record kinds are skipped (§1 forward-compat rule).

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
   `product_normalize.{hpp,cpp}`: `normalize_title` (lowercase, strip
   arch/version/edition tokens → edition extracted), `normalize_vendor`
   (strip legal suffixes, alias table), then strictly ordered deterministic
   tiers — `exact_norm` (1.0) → `title_vendor` (0.9) → `token_set` (0.8) →
   `birth` (new product). **No probabilistic/Levenshtein matching in v1** —
   every decision is reproducible in unit tests. Aliases persist
   `method`+`confidence` so manual curation can layer on later by editing
   aliases, without redesign. Inputs: distinct names from
   `SoftwareInventoryStore::software_catalog()` (consumed via public API —
   never modified) + distinct products from `SoftwareLicensingStore` + (PR2)
   entitlement `product_raw`/`vendor_raw`; PR3 adds `source='usage'` with an
   exe→title seed-map tier fed by `exe_hints`.
2. **Posture rollup**: per-product counts by
   `effective_license_state(state, license_type, expiry_at, now)` — the
   server re-derives lapse against server-now so a device that *stopped
   syncing* before its licence lapsed still shows `expired` (driver 2's
   definition of lapsed: effective state ∈ {expired, unlicensed});
   `next_expiry_at`; `expiring_soon_count` (≤ 30 days); `install_count`
   joined from installed-software rows through `product_aliases` — the
   "installed but licence-unreported" delta is shown, not hidden.
3. **Entitlement compliance pass** (PR2, §10): purchased-vs-deployed per
   product, renewal calendar.
4. **Alert pass** (§6).

Usage categories (PR3) are policy, computed server-side at read time from
agent-shipped facts (`last_used_day`, bucketed counts): Used ≤ 30 d, Rarely
31–90 d, Unused > 90 d, **Unreported** = no usage source for the asset (TAR
absent/disabled) or no matched usage row. Thresholds live server-side so a
policy change never forces fleet re-sync, and *Unreported never counts as
Unused* — reclamation must not fire on missing data.

### 6. Notifications / events (deduplicated)

The evaluator computes per-product condition fingerprints — `expired`
(expired+unlicensed count > 0) and `expiring` bucketed by min-days-to-expiry
(30/14/7/1) — and fires **only** on (a) a **worsening** fingerprint/bucket
transition (an improving transition — e.g. renewing the nearest-expiring
licence moves the bucket 7→30 — never fires; governance pass), or
(b) persistence past a 7-day re-arm. A condition that clears and re-asserts
inside the re-arm window is suppressed (hold-down) so oscillating states
(KMS grace↔expired drift, daily re-imaged VMs) cannot spam; both the
improving-transition and clear/re-assert cases are named rows in the
`test_license_compliance_evaluator.cpp` matrix. Emission uses the existing dual-sink
pattern (`server.cpp` alert wiring): `NotificationStore::create(...)` +
`webhook_store_`/`offload_target_store_->fire_event(...)` with event types
**`software_license.expiring`** / **`software_license.expired`** and payload
`{event, product_key, vendor, title, device_count, next_expiry_at, days_left,
bucket}`. PR2 adds **`software_entitlement.renewal_due`** (§10) with the same
bucket/re-arm discipline and its own dedup table. This satisfies "not
dashboard-only" without daily spam, and escalates as expiry approaches.

**Observability (governance pass).** Each PR ships metric families per
`docs/observability-conventions.md` (bounded labels, initialised-to-0,
named like the NVD-sync precedent), with matching
`docs/user-manual/metrics.md` and `docs/prometheus/yuzu-alerts.yml` rows in
the PR file plans: PR1 — evaluator last-success-timestamp gauge +
cycle-failure counter (a stuck keep-last-good evaluator must be scrapeable,
not just a UI freshness caption), ingestion-reject counter (caps/enum
whitelist hits — a fleet-misbehaviour signal), notification-fired counter;
PR2 — `yuzu_server_m365_lic_sync_failures_total{reason}` cloning the NVD
convention + connector last-success gauge; PR3 — usage ingest counters.

### 7. Access surfaces — the SCL page, REST, RBAC, MCP

New securable **`SoftwareCatalog`** seeded in `rbac_store.cpp seed_defaults()`
in PR1: **Read** granted to the standard viewer/operator role lists (all
views — a **conscious acceptance**, noted here and in the PR2 data-inventory
row, that entitlement financial metadata (cost, contract/PO refs) is visible
to every `SoftwareCatalog:Read` holder fleet-wide, consistent with how other
securables scope), **Write** to admin/operator roles (entitlement CRUD/import
and connector triggers in PR2, tag writes in PR4). Connector *configuration*
— tenant/client IDs and the client secret — is **admin-gated** (the
`admin_fn_` OIDC-Settings precedent), not `SoftwareCatalog:Write`; only
**Sync-now** rides the securable (§10.3, governance pass). **No MFA step-up anywhere in
§27**: entitlement records are financial metadata and nothing here executes
on endpoints — the `software-packages` step-up precedent exists because that
endpoint introduces *executable content dispatched to the fleet*. RBAC Write
+ full audit (including denied rows + the `Sec-Audit-Failed` header) is the
control.

**The SCL page (rev 2).** A brand-new top-level dashboard page **`/scl`**
("SCL — Software Catalog & Licensing"), built on the shared guardian shell
(`kGuardianDetailPageHtml`: {{TITLE}}/{{FRAGMENT}} substitution + the
exact-string active-nav replace pair), implemented as
`scl_routes.{hpp,cpp}` + `scl_ui.cpp` cloning the `/inventory` model
(provider closures returning `std::optional` — nullopt renders a degrade
banner, **never** an empty table; two `register_routes` overloads;
TestRouteSink tests; MSVC 16380-byte raw-string chunking). Sub-views as
`/fragments/scl/*` hx-get tabs:

- **Licences** (PR1): KPI strip (expired / expiring-30d / unlicensed /
  unknown, rollup freshness), product posture table with state chips,
  product → device and device → licences drill-downs, one ECharts state-mix
  donut (`yuzu-chart-card`; the echarts + yuzu-charts script tags are added
  to the shared shell — verified harmless to other shell consumers, and the
  auto-render hook location is checked at implementation time).
- **Entitlements** (PR2, §10): table with per-source badges, add/edit form,
  CSV upload (capped), connector status card + Sync-now.
- **Compliance** (PR2, §10): purchased-vs-deployed table with CSS delta
  bars; `unentitled` products listed honestly, not hidden.
- **Reclamation** (PR4): candidates = paid licence type × Unused/Rarely.

The software **catalog stays on `/inventory`** (owner decision); the SCL
header carries a cross-link. Nav: an SCL link is inserted after Inventory in
**all 11 hand-duplicated nav copies** plus the command-palette `navEntries`;
the pre-existing Result Sets nav drift is reconciled in the same PR as its
own commit — the drift spans **three** files (the viz-host short nav plus
the two guardian navs missing the Result Sets link), each confirmed drift,
not design, via a `git log` check before editing.

**REST** (`rest_api_v1.cpp`; everything under a unified **`/api/v1/scl/*`**
prefix; modelled on the `/api/v1/inventory/software` handler: auth → perm →
503-on-degrade → limit clamp 1..1000 → scope filter → audit, errors via
`error_json_a4` + X-Correlation-Id; OpenAPI literals updated):

- PR1: `GET /api/v1/scl/summary` · `GET /api/v1/scl/licenses?state=&expiring_within_days=&q=&limit=`
  · `GET /api/v1/scl/licenses/{key}/devices` ·
  `GET /api/v1/scl/agents/{agent_id}` — all four gated on **global
  `SoftwareCatalog:Read`** in PR1 (see "Per-row surfaces — honest
  sequencing" below for why the per-device pair does not claim the
  ADR-0017 chokepoint yet).

**ADR-0017 aggregate pinning (rev 3, blocker fix).** The SCL fleet-wide
aggregate surfaces — `GET /api/v1/scl/summary`, `GET /api/v1/scl/licenses`,
and the Licences-view fragments they feed — are built from the precomputed
`license_posture_rollup` (and later `entitlement_posture`), whose counts are
aggregated across every management group. Exactly like their `/inventory`
`software_catalog` twin, they **cannot take a per-row admit-then-filter at
read time** (ADR-0017:221-231). They are therefore **pinned global-only, by
design and not by accident**: when list reads flip to admit-then-filter
fleet-wide, these aggregates remain gated on the *global*
`SoftwareCatalog:Read` — a group-confined principal is **denied (403)**, never
served a partial or leaky rollup. The SCL fragments render that denial as
explicit guidance ("requires global SoftwareCatalog:Read"), not a bare 403 —
an all-scoped-operators deployment (MSP/divisional) sees an honest
explanation, and recompute-per-visible-set remains the documented future
option for that shape (governance pass).

**Per-row surfaces — honest sequencing (rev 5, blocker fix).** The
admit-then-filter chokepoint (`authorize_list_read`, ADR-0017 **PR-A**) is
**not implemented yet** — the open umbrella is **#1634** (systemic
response-read scoping) with the PR-A prerequisite decision in **#1715**;
PR-A itself has **no dedicated tracker yet**, and the `#1716`
forward-references scattered through existing `server/core` comments point
at a *closed* doc-honesty companion PR, not the gate — do not follow them.
Rev 4 was wrong to write as if PR1 could call the chokepoint. PR1
therefore does **not** build the foundation and does **not** wire an
ad-hoc per-row filter (the exact pattern ADR-0017 exists to replace).
Instead the per-row surfaces (`/scl/licenses/{key}/devices`,
`/scl/agents/{agent_id}`, device drill fragments) ship gated on **global
`SoftwareCatalog:Read`** — the same inert-confinement posture every
existing list read in the codebase has today, no worse and no better —
and are hereby **registered as flip-wave consumers of ADR-0017 PR-A**
(#1634/#1715): when the chokepoint lands, these routes take
`authorize_list_read` (filter before LIMIT) in the same fleet-wide flip as
the other list reads, and the follow-up test
`"per-device drill filters before LIMIT"` lands with that flip, not with
PR1. MCP tools are classified by the same row-shape test at wiring time
(ADR-0017's "does a returned row carry an agent id?"): a §27 MCP tool
returning fleet aggregates stays pinned-global like its REST twin; any
tool returning per-device rows joins this flip-wave registration alongside
its REST sibling. Named tests in `test_scl_routes.cpp` at PR1: `[scl][adr0017]`
`"aggregate routes are global-gated: scoped principal gets 403, never a
partial rollup"` and `"per-device drills are global-gated (chokepoint
pending ADR-0017 PR-A: scoped principal gets 403, never an unfiltered
row set)"`. Recomputing aggregates per visible set is the documented
future alternative if group-scoped rollups are ever demanded; it is out of
scope here.
- PR2 (§10): entitlement CRUD + CSV import + compliance + connector routes.
- PR3: `GET /api/v1/scl/reclamation?unused_days=90`.
- PR4: `GET/POST/DELETE /api/v1/scl/catalog/products/{id}/tags`.

**MCP** (`mcp_server.cpp`, tier-before-RBAC): `query_software_licenses`,
`get_license_compliance_summary` (PR1; extended with entitlement fields in
PR2), `query_software_entitlements` (PR2), `query_license_reclamation` (PR4)
— all `{"SoftwareCatalog","Read"}`.

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
- **The configuration knob ships in PR1, named and tested (rev 3; modes and
  default revised in rev 4):**
  **`--license-scan-user-ref=collect|hash|omit`** (env
  `YUZU_AGENT_LICENSE_SCAN_USER_REF`), applied in the sync source before the
  canonical blob is built — `collect` sends the raw profile name, `hash`
  sends a **pseudonym**: `HMAC-SHA256(k_agent, profile)` truncated to 16 hex
  characters, where `k_agent` is a random 256-bit key generated on first use
  (OS CSPRNG), persisted in the agent's local KvStore, and **never
  transmitted or logged** — not the rev-3 unsalted `sha256/12(profile)`,
  which a low-entropy profile name (`jsmith`, `admin`) makes trivially
  dictionary-reversible. `omit` sends an empty field (records stay,
  `user_scope` still distinguishes per-user detections). **Default: `hash`**
  (rev 4, per the PR #1870 second review round): every other per-user or
  behavioral source in this project ships off/safe by default (`procperf`,
  `$Software`, `$NetQual`, `$NetConn` — enterprise-readiness works-council
  section), the existing `installed_software` daily-sync source is
  machine-scope by deliberate ADR-0016 §8 decision (per-user enumeration
  "deliberately not used"), and the TAR `software` source documents the same
  no-per-user-hives / no-`NTUSER.DAT` posture in
  `docs/agent-privilege-model.md` — a raw-identifier default here would
  reverse that posture. The default-`hash` pseudonym keeps the per-user
  **capability** intact on unconstrained fleets (per-user detections still
  flow; distinct users on a machine stay distinct and stable across syncs,
  so per-user seat math works within a device), while raw operator-readable
  names are one explicit flag away (`collect`). Honest
  limits, stated in the operator docs: `hash` is **pseudonymization, not
  anonymization** — the mapping is stable per agent (linkable over time on
  one device; the same person on two devices yields two unrelated
  pseudonyms, so cross-device user dedup needs `collect`) — and
  works-council-grade suppression is **`omit`**, not `hash`.
  `test_licensing_sync.cpp` covers all three modes, asserts the default is
  `hash`, asserts HMAC-key stability across runs (same profile → same
  pseudonym after agent restart; distinct profiles → distinct pseudonyms),
  and asserts the HMAC key itself never appears in the blob or logs.
- **Honest legal + verification posture (governance pass):** a hashed
  `user_ref` is pseudonymized and therefore still **personal data under
  GDPR** (Recital 26) — retention and erasure obligations attach even in
  the default mode. The erasure path, stated plainly: licence records are
  full-replaced on every sync, so flipping the knob to `omit` purges the
  identifiers fleet-wide within one 24 h cycle, and agent removal cascades
  via the `delete_agent` hook; there is **no row-level erasure API** (an
  honestly stated gap — the PR1 data-inventory row carries both facts). A
  deployment electing `collect` owns its DPIA/lawful-basis assessment.
  `omit` suppresses the *identifier*, not per-user *probing* — per-user
  hives are still read and `user_scope=user` records still ship (on a
  single-user device the person may be attributable by inference); fully
  suppressing per-user probing today means the source-level
  `inventory_disable` opt-out, and a dedicated per-user-probe disable is
  the named future knob if a deployment demands it. Fleet posture is
  **centrally verifiable**: the source's `surfaces` diagnostics report the
  effective `user-ref` mode per agent and the per-device SCL drill
  (`/scl/agents/{agent_id}`) surfaces it — an auditor can evidence "every
  agent runs `hash`" without endpoint-by-endpoint config inspection.
- **Transparency ships in PR1 too:** the enterprise data inventory
  (`docs/enterprise-readiness-soc2-first-customer.md`) and
  `docs/user-manual/software-licensing.md` document exactly which fields are
  collected per surface (including `user_scope`/`user_ref` and the knob), so
  what is collected can be shown to a works council on request. Both are PR1
  acceptance criteria — nothing is deferred to unfiled follow-ups.
- The **usage** source (PR3) does **not** inherit this carve-out: usage rows
  stay machine-scope, the per-user TAR dimension is aggregated out on the
  agent (`GROUP BY` app name only), and a unit test fails if a username
  column or value reaches the blob. The M365 connector (§10) likewise pulls
  **tenant-level** seat counts only — no per-user `licenseDetails` fan-out.
- Licence **key material is never persisted or transmitted**: `key_hint` is
  the OS-provided partial (last-5) or an in-memory SHA-256 prefix of key
  files; full keys never touch output, logs, or KvStore. This moots ADR-0010
  SecretCodec for these stores by construction. (The M365 connector's client
  secret is handled separately — SecretCodec-encrypted on the entitlement
  store, §10.3.)

Maintainer sign-off on this section is requested explicitly in the PR1
review (it amends ADR-0016's posture for this source).

### 9. Identity join (installed ⨝ licence ⨝ entitlement ⨝ usage)

Four name spaces reach the server: installed display names, licence product
names, entitlement product names/SKUs, and (PR3) bare exe image names
(Windows ETW is name-only). Joins: everything resolves to catalog
`norm_key` via the §5 matcher (entitlement rows carry `product_key` as a soft
key, re-resolved each evaluator cycle so later matcher improvements
self-heal); `exe_hints` on licence records (from the probe table) are the
authoritative product↔exe bridge; then a server-side exe→title seed map; then
normalised title matching; anything left is an honest **unmatched** bucket
excluded from reclamation verdicts (conservative by design — a paid product
is only "unused" when its install row exists AND matched usage says so, or
usage is entirely absent → *Unreported*).

### 10. Entitlements — sources, store, and compliance math (rev 2)

#### 10.1 Sources

| Source | Mechanism | What it yields |
|---|---|---|
| `manual` | GUI add/edit form + REST CRUD | any field, operator-owned |
| `csv` | GUI file upload (multipart) + REST raw `text/csv` ingest — same parser/validator/caps | bulk licence-register import |
| `graph_m365` | scheduled server connector (§10.3) | purchased vs consumed seats per Microsoft SKU, renewal dates |
| `agent_flexlm` | `license_scan` plugin: FlexLM `.lic` `INCREMENT` seat counts (already parsed for expiry) | seats_total (+ optional in-use via lmstat probe later) per feature |
| `agent_kms` | `license_scan` plugin on the KMS host: WMI `SoftwareLicensingService` activation counts | volume-activation pool counts |

Agent-sourced entitlements ride the existing `software_licensing` daily-sync
blob as a second record kind (protected by the §1 forward-compat rule):

```
ent|product|vendor|feature|seats_total|seats_in_use|license_type|term_end|source(flexlm|kms)|host_ref
```

`host_ref` is format-pinned so the §10.2 identity keys derive
deterministically from the wire (governance pass): FlexLM records carry
`<server>:<port>` from the `.lic` `SERVER` line; KMS records carry the
observing agent's ID, with `product` carrying the KMS SKU identifier —
yielding `flexlm:<server>:<port>:<feature>` and `kms:<agent_id>:<sku>`
without server-side guessing.

#### 10.2 `SoftwareEntitlementStore` (born-on-PG, schema `software_entitlement_store`)

Migration v1 tables:

- `entitlements(entitlement_id BIGSERIAL PK, source CHECK(manual|csv|graph_m365|agent_flexlm|agent_kms),
  external_id, product_raw, vendor_raw, sku_part_number, product_key /*soft
  catalog key, '' until matched*/, seats_purchased BIGINT NULL,
  seats_assigned BIGINT NULL, license_type, term_start_at, term_end_at,
  renewal_at, cost_amount_minor BIGINT NULL, cost_currency, contract_ref,
  po_ref, notes, created_by, import_id, retired_at, created_at, updated_at,
  last_synced_at, UNIQUE(source, external_id))` + indexes on `product_key`,
  partial on `renewal_at > 0`. `NULL` seat/cost values mean *unknown* —
  never fabricated zeros.
- `entitlement_observations(source, external_id, agent_id, first_seen,
  last_seen, PK(source, external_id, agent_id))` — which agents currently
  observe an agent-sourced entitlement (server receipt time), for dedupe +
  a 30-day GC that soft-retires unobserved rows.
- `entitlement_imports(import_id PK, filename, uploaded_by, surface
  api|dashboard, rows_total, rows_upserted, rows_unchanged, created_at)` —
  CSV provenance.
- `entitlement_posture(product_key PK, entitled_seats NULL-able,
  seats_assigned, installed_count, winning_source, basis, delta, compliance,
  next_renewal_at, refreshed_at)` — evaluator output, replace-in-txn.
- `entitlement_alert_state(product_key, kind renewal_due|overdeployed,
  fingerprint, bucket, last_fired_at, PK(product_key, kind))` —
  `overdeployed` is a **reserved** kind (governance pass): no
  over-deployment alert ships in PR2 (the Compliance view is the surface);
  reserving the CHECK value now avoids a migration if that alert is added
  later.
- `connector_secret(connector TEXT PK, secret_enc BYTEA NOT NULL,
  updated_by, updated_at)` — one row per connector (`graph_m365` in v1);
  `secret_enc` is a **`SecretCodec` envelope blob, never plaintext** (§10.3).
  `TEXT` PK is deliberate: it is one of the two PK types the codec's AAD
  canonical encoding supports (`SecretCodec::SecretColumn` — BIGINT / text;
  `SERIAL`/`int4` would brick rotation).

**Identity/upsert per source:** manual = server UUID, full CRUD; csv =
`external_id` column if present else `sha256/16(product|vendor|contract_ref|term_end)`,
**upsert-by-key** (re-uploading a corrected file updates in place; imports
never delete — deletion is explicit); graph_m365 = `skuId`, full-set upsert
per sync with **soft-retire** (`retired_at`) for SKUs that disappear;
agent_flexlm = `flexlm:<server>:<port>:<feature>` so a fleet of agents seeing
the same licence server converges on one row; agent_kms = per-host
(`kms:<agent_id>:<sku>` — two KMS hosts are two activation pools).

**Field ownership:** connector/agent writes touch only observed fields and
**never clobber operator annotations** (`cost_*`, `contract_ref`, `po_ref`,
`notes`). Connector-owned rows are immutable in GUI/REST (409) *except* those
annotation fields. Postures: reads authoritative (nullopt → 503/banner);
connector/agent ingest fail-soft; manual/CSV/REST writes user-facing and
audited (`software_entitlement.create/update/delete/import`, denied rows
included) — connector **config and secret writes are additionally audited**
(`software_entitlement.connector_config_update`, denied rows included),
since repointing the tenant is a security-relevant change (governance
pass). One secret column in the whole store —
`connector_secret.secret_enc`, SecretCodec-registered per §10.3 — and no
plaintext secret column anywhere. Retention, stated honestly for the PR2
data-inventory row (governance pass): soft-retired entitlements,
`entitlement_imports` provenance, and operator identities have **no
reaper** — explicit DELETE is the disposal mechanism, matching the
enterprise doc's honest-gap convention for stores without one.

#### 10.3 Microsoft Graph M365 connector

`server/core/src/m365_licensing_sync.{hpp,cpp}` — lifecycle cloned from
`NvdSyncManager` (start/stop jthread + condition_variable, `sync_now()`,
`SyncStatus` for UI), 24 h interval. Token + HTTP extracted from
`directory_sync.cpp` into a shared `graph_http.{hpp,cpp}` helper (OAuth2
client-credentials + WinHTTP/httplib dual) **with `@odata.nextLink` paging
added** (a known gap in `sync_entra`). Graph calls, tenant-level only:
`GET /v1.0/subscribedSkus` (skuId, skuPartNumber, prepaidUnits.enabled,
consumedUnits) + `GET /v1.0/directory/subscriptions` (nextLifecycleDateTime →
renewal, totalLicenses, isTrial). **No per-user `licenseDetails` fan-out**
(N×HTTP cost + PII, both avoided). skuPartNumber → product title via a seed
map + the §5 matcher. Required Graph application permission:
`Organization.Read.All`.

**Connector input pinning (governance pass — named PR2 tests):**
`tenant_id` must match GUID-or-verified-domain syntax and `client_id` GUID
syntax, rejected at the Settings/REST layer before storage; the token and
Graph base hosts are **fixed constants** (`login.microsoftonline.com`,
`graph.microsoft.com`) — operator input is never string-built into a URL
beyond the path-segment-encoded tenant; `@odata.nextLink` is followed
**only when same-origin with the Graph base**, with a bounded page count —
a poisoned `nextLink` must never steer the bearer token off-host (the SSRF
class). Recovery pairing, documented in PR2's operator docs: the
`FileKeyProvider` KEK lives outside Postgres, so a PG-only restore leaves
`secret_enc` undecryptable — correctly fail-closed, the connector stays
loudly down until the secret is re-entered in Settings; the KEK directory
joins the documented backup scope, and the three PR2 fatal-boot causes (PG
unreachable / migration failure / codec `init()` failure) get **distinct
triage tokens** as a named acceptance criterion.

Config lives in **Settings** (clone of the OIDC section: form + **Test
Connection** button that acquires a token and fetches one `subscribedSkus`
page). **Non-secret** keys — `m365_lic_tenant_id` / `m365_lic_client_id` /
`m365_lic_enabled` — persist via `RuntimeConfigStore` allow-listed keys.
**The client secret never touches `RuntimeConfigStore`** (rev 4): that store
is SQLite today (`runtime-config.db`, `runtime_config_store.hpp` — where the
`oidc_client_secret` plaintext gap lives), and `SecretCodec` is
Postgres-substrate machinery (its AAD binds to a PG schema/table/column/row
and its rotation scan walks registered PG columns over libpq) — an
"encrypted key in runtime config" would be unrotatable and off-registry.
Instead the secret is a **registered `SecretCodec` column on the born-on-PG
entitlement store**: `connector_secret.secret_enc` (§10.2), per-row AAD
tuple `("software_entitlement_store", "connector_secret", "secret_enc",
row_pk = "graph_m365")`.

**PR2 is `SecretCodec`'s first production wiring** (the codec shipped in
#1320 PR 4 with unit tests but no server-side consumer yet), so PR2
explicitly owns, in `server.cpp`:

- **strict construction order (rev 5, blocker fix):** construct
  `FileKeyProvider` (it implements the `KekProvider` seam,
  `key_provider.hpp`) + `SecretCodec` → **`register_secret_column(...)`** →
  **`set_audit_hook(...)`** → **`codec.init(conn)`** on a pinned pool lease
  → only then open the PG stores (ADR-0010 §2 boot order). Registration and
  the audit hook MUST precede `init()`: `init()` snapshots the registered
  columns and feeds that snapshot to the boot-time orphan scan
  (`secret_codec.cpp` — a restored DB with a `connector_secret.secret_enc`
  blob but a deleted `secrets.kek_meta` row must fail closed at *boot* with
  `kek_orphaned`, not surface later at decrypt time), and `init()` emits the
  first-boot `kek.generated` audit event, which is lost if the hook is not
  yet installed. This is the order the codec's own boot-scan tests pin
  (the orphaned-kek_version and unsupported-pk-type cases in
  `test_secret_codec.cpp` register before `init()`; the codec tolerates
  late registration for other flows, but a column only gets boot-time
  orphan protection when registered pre-`init()`), and it is safe on
  first boot: the orphan scan explicitly skips registered columns whose
  tables are not yet migrated (`42P01 undefined_table → continue`), so
  registering a column for a store that has not been constructed yet is
  correct, not a race;
- `init()` failure = `startup_failed` — the server refuses to boot rather
  than run with unreadable secrets (the codec header's stated wiring
  obligation; no deferred-init path, so the `/readyz` conjunction clause is
  not needed);
- registration tuple: `register_secret_column({"software_entitlement_store",
  "connector_secret", "secret_enc", pk_column = "connector"})` (the column
  registration names the PK *column*; the AAD tuple above binds each blob to
  its PK *value*); audit hook → AuditStore (`kek.generated`, `kek.rotated`,
  `kek.retired`, `secret.decrypt_failure` verbs).

Store API: `set_connector_secret()` encrypts (an encrypt failure **aborts
the write transaction** — never a plaintext or empty write);
`connector_secret()` decrypts **fail-closed** — on failure the connector
does not run, its status card shows the generic
`SecretCodec::to_external_error()` string (never the failure class — no
tamper/existence oracle), and the failure is audited + counted. The
Settings form's secret field is **write-only** (the UI shows
configured-yes/no, never echoes the value). This keeps the ADR-0010 §Decision
4 claim honest: the new secret lands envelope-encrypted from its first
commit, and the legacy `oidc_client_secret` gap is neither extended nor
touched (it remains separately tracked). Rev-3 intent, made concrete in
rev 4 per the PR #1870 second review round.
The SCL Entitlements view shows a status card (configured, last/next sync,
rows, last error) + a Write-gated, audited **Sync now**
(`POST /api/v1/scl/connectors/m365/sync`, 202 + status URL;
`GET /api/v1/scl/connectors` for status).

#### 10.4 CSV contract (shared by GUI upload and REST ingest)

Header row required, case-insensitive mapping; columns: `product` (req),
`seats` (req), `vendor, sku, license_type, renewal_date (YYYY-MM-DD),
term_start, term_end, cost, currency, contract_ref, po_ref, external_id,
notes` (optional). RFC-4180 (quoted fields, embedded commas/quotes/CRLF),
UTF-8 BOM tolerated. Parser is a new pure lib `csv_import.{hpp,cpp}` beside
`data_export.{hpp,cpp}` (which is export-only today). Caps: **1 MiB**
(`kSclCsvMaxBytes`, shared constant, explicit 413 — the uncapped OTA upload
precedent is deliberately not copied), 10 000 rows, ≤100 reported errors
with line numbers. **Dry-run mode** performs full validation with zero
writes (`?dry_run=true` on the API; checkbox default-ON in the GUI).
Response/report: `{rows_total, rows_ok, rows_rejected, applied,
errors:[{line, column, message}]}`.

- REST: `POST /api/v1/scl/entitlements/import?dry_run=&mode=upsert` — raw
  **`text/csv` body** (curl-scriptable; no `/api/v1` multipart precedent
  exists and none is invented).
- GUI: multipart upload form on the SCL Entitlements view via the settings
  shim macros, same cap, renders the validation report then the refreshed
  table.
- CRUD: `GET /api/v1/scl/entitlements?product=&source=&q=&renewing_within_days=&limit=`
  · `POST /api/v1/scl/entitlements` (64 KiB JSON cap) ·
  `PUT/DELETE /api/v1/scl/entitlements/{id}` (409 on connector-owned rows) —
  all `SoftwareCatalog:Write` for mutations, shared `validate_entitlement()`
  between REST and the dashboard form (the ca_routes dual-surface precedent).

#### 10.5 Compliance math v2 (evaluator pass 3)

Per catalog product: `entitled_seats = SUM(seats_purchased)` across active
(non-retired) entitlement rows **with the per-source breakdown persisted** —
when the same product has both a CSV row and an M365 SKU the double-count is
*visible*, not resolved by hidden precedence (v1 decision; explicit
precedence can layer on later). Comparison basis, chosen per product by data
availability and recorded in the posture row:
`installed_vs_purchased | assigned_vs_purchased | inuse_vs_total | none`.
Compliance vocabulary: `compliant | over_deployed | under_used | unentitled |
unknown` — products with detected licences but no entitlement rows stay
`unentitled` (rev 1's detected-state-only semantics; **never** claimed
compliant). Renewal calendar: `next_renewal_at` per product feeding
**`software_entitlement.renewal_due`** events (30/14/7/1 buckets + 7-day
re-arm, dual-sink, `entitlement_alert_state` dedup).

## Delivery roadmap and implementation plan (four governed PRs)

Each PR is independently shippable, runs the full `/governance` 8-gate +
`/test` pipelines, branches from `origin/dev`, and ships a `changelog.d/`
fragment. Sequential (each builds on the previous PR's merged stores/UI).
Conventional commits (`feat(agent):` / `feat(server):`); every source file
added or renamed updates the affected `meson.build`.

### PR1 — `feat/software-licensing` — detection + stores + SCL page (Licences) + expiry alerting
**Drivers 1–3. Closes #264 (catalog store; automatic matching here,
`/inventory` catalog foundation delivered by PR #1759 and cross-linked);
advances #266 and #1869.**

**New files (dependency order):**

| # | Path | Contents |
|---|------|----------|
| 1 | `agents/core/src/sync_canonical.{hpp,cpp}` | `sanitize_utf8_strict` / `clamp_field` / `sha256_hex` extracted byte-identically from `sync_source_installed_software.cpp` (which switches to them) |
| 2 | `server/core/src/product_normalize.{hpp,cpp}` | pure normalisation lib: `normalize_title/vendor`, `norm_key`, tiered `match`, `effective_license_state`, constants (`kExpiryWarnDays=30`, buckets 30/14/7/1, `kRearmSecs=7d`) |
| 3 | `server/core/src/product_registry_store.{hpp,cpp}` | born-on-PG store, migration v1 (`products`, `product_aliases`) |
| 4 | `server/core/src/software_licensing_store.{hpp,cpp}` | born-on-PG store, migration v1 (`agent_license_state`, `agent_licenses`, `license_posture_rollup`, `license_alert_state`) + server-side `canonical_hash` |
| 5 | `agents/plugins/license_scan/` | `meson.build`, `src/license_scan_plugin.cpp` (dispatch), `src/licensing_record.hpp` (record struct + sanitiser), `src/licensing_parsers.hpp` (pure SLP/channel/SPDX/FlexLM/DEP-5 parsers), `src/licensing_probes.{hpp,cpp}` (ProbeSpec table + engine), `src/licensing_win.cpp` / `licensing_linux.cpp` / `licensing_macos.cpp` |
| 6 | `agents/core/src/sync_source_software_licensing.{hpp,cpp}` | parse → canonical blob → sha256; `LocalDispatcher` dispatch of `license_scan list`; 24 h interval; caps 10k records / 1 MiB; **skips unknown record kinds** (§1) |
| 7 | `server/core/src/software_licensing_ingestion.{hpp,cpp}` | ingest seam (caps, enum whitelists, expiry clamp, server-side hash recompute, replace-in-txn, skip-unknown-kind) |
| 8 | `server/core/src/license_compliance_evaluator.{hpp,cpp}` | background thread: matcher pass → posture rollup → alert dedup/fire |
| 9 | `server/core/src/scl_routes.{hpp,cpp}` + `scl_ui.cpp` | the `/scl` page: guardian-shell route, `scl_subnav`, Licences view renderers, state-mix donut provider, catalog cross-link |
| 10 | `docs/user-manual/software-licensing.md` | operator doc |
| 11 | Tests — server: `tests/unit/server/test_product_normalize.cpp`, `test_product_registry_store.cpp`, `test_software_licensing_store.cpp`, `test_software_licensing_ingestion.cpp`, `test_license_compliance_evaluator.cpp`, `test_scl_routes.cpp`; agent: `tests/unit/test_licensing_sync.cpp`, `tests/unit/test_licensing_parsers.cpp` | see test matrix |

**Modified files:** top-level `meson.build` (`subdir('agents/plugins/license_scan')`);
`agents/core/meson.build`; `server/core/meson.build`; `tests/meson.build`;
`agents/core/src/sync_source_installed_software.cpp` (helper extraction only —
byte-neutral, proven by the existing cross-pin test);
`agents/core/src/agent.cpp` (descriptor scan + `add_source`);
`server/core/src/typed_inventory_sources.hpp` (**add `software_licensing` in
the same commit as the seam** — the gateway securable-leak trap);
`server/core/src/agent_service_impl.cpp` + `gateway_service_impl.cpp` (seam
calls on both topologies); `server/core/src/rbac_store.cpp` (`SoftwareCatalog`
securable + Read/Write role grants); **the 11 nav-bearing `*_ui.cpp` files**
(SCL link after Inventory; Result Sets drift reconciled as its own commit
after a `git log` sanity check) + `dashboard_ui.cpp` command-palette
`navEntries`; `guardian_page_ui.cpp` (shell: nav copy + echarts/yuzu-charts
script tags); `server/core/src/rest_api_v1.cpp` (`/api/v1/scl/*` reads +
OpenAPI literal); `server/core/src/mcp_server.cpp` (two tools);
`server/core/src/server.cpp` (stores in the `pg_pool_` guard, fatal on
`!is_open()`, destruct-before-pool order; evaluator start/stop +
`set_on_alert` dual-sink; SCL route closures; agent-removal `delete_agent`
hook); `agents/core/include/yuzu/agent/agent.hpp` + `agents/core/src/main.cpp`
(`--license-scan-user-ref` flag parsing, §8);
`docs/postgres-migration-ladder.md` (two born-on-PG rows);
`docs/enterprise-readiness-soc2-first-customer.md` (**data-inventory rows for
`product_registry_store` + `software_licensing_store`** — data class,
retention/deletion/opt-out, the `user_scope`/`user_ref` fields and knob;
correct any daily-sync "no end-user PII" line this makes inaccurate);
`docs/capability-map.md` (§27.1/§27.3); `docs/roadmap.md` (Phase 10
staleness note); `docs/os-capability-matrix.md` (**rev 4** — per-OS rows for
the `license_scan` surfaces, source-cited per the matrix's own convention:
Windows SLP/C2R/ProbeSpec/per-user-hive, Linux package/entitlement-cert/
FlexLM, macOS receipts + vendor plists, with deliberate gaps recorded
per-surface, e.g. no lapse detection on the Linux rpm/dpkg
package-metadata surface — entitlement certs and FlexLM do carry expiry);
`docs/agent-privilege-model.md` (**rev 4** — a `license_scan`
row: the per-user offline-hive probe (`RegLoadKey`) uses
`SeBackupPrivilege`/`SeRestorePrivilege`, **already granted** by
`scripts/install-agent-user.ps1` — the row cites the existing grant, no new
privilege is introduced); `docs/user-manual/rest-api.md` (**governance
pass** — the four `/api/v1/scl/*` read endpoints documented per the
manual's method/permissions/examples convention; in-code OpenAPI literals
alone do not satisfy the docs gate); `docs/user-manual/mcp.md` (both new
tools in the Available Tools table with their securable);
`docs/user-manual/README.md` (TOC row for `software-licensing.md`);
`docs/user-manual/metrics.md` + `docs/prometheus/yuzu-alerts.yml` (PR1
metric families, §6 Observability); `changelog.d/` fragment.

**Implementation order:**

1. `sync_canonical` extraction; existing installed-software cross-pin test
   stays green (proves byte-neutrality).
2. `product_normalize` + pure unit tests.
3. Both PG stores + `[pg]` store tests (TDD against a local Postgres).
4. Ingestion seam + `typed_inventory_sources.hpp` + service-impl wiring +
   cross-pinned hash constants (agent↔server test files share the constant
   byte-for-byte) + skip-unknown-kind tests both sides.
5. `license_scan` plugin + pure parser tests.
6. Sync source + `agent.cpp`/meson wiring + agent sync tests.
7. Evaluator + notification/webhook emission.
8. RBAC securable seed (Read + Write grants).
9. Nav commit (11 files + navEntries + drift reconcile), then SCL page +
   REST + MCP.
10. Docs + `changelog.d/` fragment.

**Test matrix:**

| Test file | Asserts |
|---|---|
| `test_product_normalize.cpp` | normalisation, match tiers T1–T3 + birth, `effective_license_state` lapse derivation |
| `test_product_registry_store.cpp` `[pg]` | migration-at-construction, upsert txn semantics, alias resolution, nullopt-on-degrade |
| `test_software_licensing_store.cpp` `[pg]` | hash-skip trichotomy (stored/touched/need-full), replace-in-txn, cascade delete, posture/alert-state CRUD, **cross-pinned canonical-hash constant** |
| `test_software_licensing_ingestion.cpp` | input caps, enum whitelisting, expiry plausibility clamp, hash recompute (never trusts claimed), empty-blob = valid replace-to-empty, **unknown record kinds skipped** |
| `test_license_compliance_evaluator.cpp` | injected clock: condition/bucket transitions, 7-day re-arm, degrade ≠ false all-clear |
| `test_scl_routes.cpp` | authz (401/403), 503-on-degrade banner (never empty table), subnav active states, shell substitution + active-nav replace pair, limit clamps, **`[scl][adr0017]` pinning: scoped principal → 403 on summary/licenses (never a partial rollup) AND on the per-device drills (global-gated pending ADR-0017 PR-A — the "filters before LIMIT" test lands with the fleet-wide flip, not PR1)** |
| `test_licensing_sync.cpp` (agent) | same cross-pin constant, parser overflow/injection, blob stability (countdown → same hash), empty-vs-primary-surface-error semantics, **unknown record kinds skipped**, **`--license-scan-user-ref` collect/hash/omit modes: default is `hash`; HMAC pseudonym stable across agent restarts, distinct per profile; HMAC key never reaches blob/logs** |
| `test_licensing_parsers.cpp` (agent) | SLP LicenseStatus mapping incl. grace codes, channel/SPDX classifiers, FlexLM expiry, DEP-5 header detection, key-hint never echoes input, **non-ASCII registry fixture (wide-API/UTF-8 round-trip)** |

**Verification / acceptance (PR1):**
1. `meson test --suite server --suite agent` green, with PG store tests
   running against a local PostgreSQL (`YUZU_TEST_POSTGRES_DSN` set; unset =
   clean skip, set-but-broken = fail).
2. End-to-end demo: server on Postgres → enroll one agent → first sync cycle
   pushes `software_licensing` → the `/scl` Licences view shows the
   machine's detected licences with type/status/expiry → temporarily widen
   the expiring window to observe one `software_license.expiring`
   notification + webhook event fire exactly once (dedup verified). Nav link
   present and active-marked on every page.
3. Gateway parity: on the UAT rig (server + Erlang gateway), confirm the
   `software_licensing` key ingests identically through `ProxyInventory` and
   is **skipped** by the generic-blob loop (the typed-source leak trap).
4. `/test` pipeline (includes the upgrade-from-previous-release leg — the new
   schemas must migrate cleanly on an existing database) and `/governance`
   8-gate pipeline; CRITICAL/HIGH findings block merge.
5. **Docs acceptance (rev 3):** the enterprise data-inventory rows and the
   user-manual collection disclosure (§8) are present in the PR — reviewable
   evidence that a works council could be shown exactly what is collected.

Size ~3.5k LOC. Pre-agreed split seam if review requests it: PR1a =
plugin + source + stores + ingest + REST; PR1b = SCL page + evaluator/events
+ MCP + nav.

### PR2 — `feat/software-entitlements` — entitlements end-to-end
**Driver 4 (purchased-vs-deployed). Closes #266 (re-reframed — see the
superseding scope comment on the issue).**

**New files:** `server/core/src/software_entitlement_store.{hpp,cpp}` (§10.2);
`server/core/src/csv_import.{hpp,cpp}` (pure RFC-4180 reader + column
mapper); `server/core/src/graph_http.{hpp,cpp}` (extracted from
`directory_sync.cpp`, + `@odata.nextLink` paging);
`server/core/src/m365_licensing_sync.{hpp,cpp}` (§10.3); tests
`test_software_entitlement_store.cpp` `[pg]`, `test_entitlement_csv.cpp`,
`test_m365_licensing_sync.cpp` (injected/stubbed HTTP fn).

**Modified files:** `agents/plugins/license_scan/` (emit `ent|` records:
FlexLM INCREMENT seats, KMS activation counts) + agent sync-source tests;
`software_licensing_ingestion.cpp` (route `ent|` rows to the entitlement
store); `license_compliance_evaluator.{hpp,cpp}` (compliance pass, §10.5);
`scl_routes/{cpp,hpp}` + `scl_ui.cpp` (Entitlements + Compliance views, CSV
upload form, connector status card); `settings_routes.cpp` + `settings_ui.cpp`
(M365 licensing config section + Test Connection);
`runtime_config_store.cpp` (**non-secret** `m365_lic_tenant_id` /
`m365_lic_client_id` / `m365_lic_enabled` allow-list keys only — the client
secret lives SecretCodec-encrypted in the entitlement store, §10.3);
`rest_api_v1.cpp` (entitlement CRUD/import/compliance/connector routes +
OpenAPI); `mcp_server.cpp` (`query_software_entitlements`, extend the
summary tool); `server.cpp` (store + connector lifecycle wiring; **first
production `SecretCodec` wiring** — `FileKeyProvider` + codec construction,
`register_secret_column` + audit hook, then `init()` before PG stores open,
init-failure = `startup_failed` — §10.3 strict order); meson
files; ladder/capability-map/`changelog.d/`;
`docs/enterprise-readiness-soc2-first-customer.md` (**data-inventory row for
`software_entitlement_store`** — entitlement financial-metadata class,
retention/deletion incl. the no-reaper statement; SecretCodec-encrypted
connector secret noted);
`docs/user-manual/rest-api.md` + `docs/user-manual/mcp.md` (**governance
pass** — entitlement/compliance/connector endpoints + the new MCP tool);
`docs/user-manual/software-licensing.md` (connector settings, required
egress `login.microsoftonline.com` / `graph.microsoft.com` :443 + proxy
statement, KEK backup scope + keyless-restore runbook step);
`docs/user-manual/metrics.md` + `docs/prometheus/yuzu-alerts.yml` (M365
sync-failure metrics);
`directory_sync.cpp` (switch to `graph_http` — behaviour-neutral refactor).

**Implementation order:** `SecretCodec` boot wiring in `server.cpp`
(provider + **column registration + audit hook + `init()`, in §10.3's
strict order** — registration precedes `init()`, fail-closed boot) →
entitlement store (incl. the `connector_secret` table) + `[pg]` tests →
`csv_import` + parser tests → REST CRUD/import + dry-run → GUI
(Entitlements view, form, upload) → `graph_http` extraction
(directory_sync stays green) → M365 connector + Settings section + Test
Connection → agent `ent|` records + ingest routing → evaluator compliance
pass + Compliance view → `software_entitlement.renewal_due` events → MCP →
docs.

**Test highlights:** RFC-4180 quoting/CRLF/BOM/column-mapping/line-numbered
errors/1 MiB cap/dry-run purity (stub store, zero writes); upsert-by-key on
re-upload; connector-owned 409 + annotation-field exception; Graph stub —
token failure → status error, nextLink paging, prepaid/consumed/renewal
mapping, secrets absent from logs; **secret-at-rest suite in
`test_software_entitlement_store.cpp` `[pg]`** — encrypted-at-rest (a raw
SQL read of `connector_secret.secret_enc` parses as an ADR-0010 blob-v1
envelope and contains no plaintext substring), decrypt-failure-fail-closed
(corrupted blob → store surfaces the error, connector refuses to run,
`secret.decrypt_failure` audited, external surface shows only
`to_external_error()`), encrypt-failure-aborts-txn (no partial/plaintext
write), secret never echoed by the Settings/REST read path; evaluator
compliant/over_deployed/under_used/unentitled/unknown classification + basis
selection + renewal buckets with injected clock; `ent|` parser + mixed-fleet
forward-compat both directions.

**Verification / acceptance (PR2):** CSV dry-run → report only; apply → the
Compliance view and `GET /api/v1/scl/compliance` show one over-licensed and
one under-licensed fixture product; Settings Test Connection green against a
sandbox tenant (or the stubbed harness on the UAT rig); Sync-now populates
M365 rows with source badges; FlexLM fixture `.lic` on one agent lands an
`ent|` row after a sync cycle; exactly one `software_entitlement.renewal_due`
notification on a narrowed window (dedup verified); gateway parity re-check
with `ent|` rows in the blob; `/test` + `/governance`.

Size ~4k LOC — the largest PR. **Pre-agreed split seam:** PR2a = store + CSV
lib + REST + GUI + compliance math + Compliance view + renewal events
(manual/CSV paths fully shippable); PR2b = M365 connector + Settings section
+ agent `ent|` records. Ship as one if review tolerates; split at that seam
if not (compliance math needs rows, not sources — the seam is clean).

### PR3 — `feat/software-usage-metering` — usage facts for reclamation
**Driver 5 (data layer). Closes #265.**

- Agent: `sync_source_software_usage` querying the TAR warehouse via the TAR
  plugin's sandboxed read-only `sql` action through `LocalDispatcher` (no
  second DB handle; ADR-0016 prescribed exactly this seam). Machine-scope
  aggregation (user dimension dropped on-device, test-enforced), bucketed
  counts + `last_used_day` (monthly-tier fallback errs toward "recently
  used" — never over-claims unused). Hash-less like `app_perf`. **Opt-in**:
  `--usage-sync-enable` / `YUZU_AGENT_USAGE_SYNC_ENABLE`, default off; TAR
  absent/disabled → source no-ops → asset is *Unreported*.
- Server: `SoftwareUsageStore` + `software_usage_ingestion.{hpp,cpp}` +
  `typed_inventory_sources.hpp` key (**same-commit**); the agent-removal
  `delete_agent` hook wires this store too (governance pass — usage rows
  keyed by `agent_id` must not orphan on decommission); evaluator
  reclamation pass (usage→catalog join per §9; Used/Rarely/Unused/Unreported
  per §5); `GET /api/v1/scl/reclamation?unused_days=90`; usage columns on
  SCL views.
- Tests: `test_software_usage_store.cpp` `[pg]`; `test_usage_sync.cpp` — TAR
  `sql` output parsing, three-query merge with monthly fallback (last-used
  never moves backwards), bucket boundaries, TAR-error ⇒ skip, **PII guard:
  fails if a username column is selected or a fixture username reaches the
  blob**; evaluator — Unreported never categorised Unused.
- Verification: suites `server`, `agent`, `tar`; E2E — enable TAR process
  capture + `--usage-sync-enable` on one agent, generate activity, confirm
  usage rows land and reclamation returns expected categories; a
  TAR-disabled agent reports *Unreported*; `/test` + `/governance`.
- Docs: a dedicated usage-metering ADR (number assigned at PR time — as of
  rev 4, 0021 is claimed by two open branches, 0022 and 0023 by one each,
  and this document holds 0024; re-verify against **all** open remote
  branches at PR time, first-to-merge wins) or an Updates section here;
  ladder tick; capability-map §27.2; **data-inventory row for
  `software_usage_store`** (usage telemetry class, retention, opt-in);
  `--usage-sync-enable` documented in `software-licensing.md`;
  `docs/user-manual/rest-api.md` row for the reclamation endpoint +
  metrics rows (governance pass).

### PR4 — `feat/software-tags-reclamation` — tags + reclamation view
**Driver 5 (visible reclamation). Closes #267 + #1869.**

- `ProductRegistryStore` migration v2 (`product_tags`); tag CRUD REST
  (`GET/POST/DELETE /api/v1/scl/catalog/products/{id}/tags`,
  `SoftwareCatalog:Write`) + tag chips in the SCL views.
- Management-group dynamic-rule integration ("devices with software tagged
  X") — time-boxed; splits to a follow-up issue rather than bloat the PR.
- RECLAMATION sub-view on `/scl`: candidates = paid `license_type` ×
  (Unused | Rarely used), per-title drill-down, charts; unmatched-usage
  coverage view (honest gap reporting). MCP `query_license_reclamation`.
- **New files:** `tests/unit/server/test_software_product_tags.cpp` (`[pg]`,
  migration v2 upgrade path from v1, tag CRUD, cascade on product delete).
- **Verification:** migration-upgrade test against a v1-created database
  (plus the `/test` upgrade leg); tag writes audited and rejected without
  `SoftwareCatalog:Write`; reclamation view matches
  `GET /api/v1/scl/reclamation`; `/test` + `/governance`.
- Docs: a tags ADR or a rev here (number assigned at PR time);
  capability-map §27.4/§27.5 done; data-inventory row updated for
  `product_tags`; `docs/user-manual/rest-api.md` (tag CRUD endpoints) +
  `docs/user-manual/mcp.md` (`query_license_reclamation`) rows
  (governance pass).

## Consequences

- Yuzu can answer, per asset and fleet-wide: what licences exist, their
  types/channels, what has lapsed, what expires or renews within N days —
  with notifications — how purchases compare with deployment for entitled
  products, and (after PR3/PR4) what paid software is going unused.
- **Licence detection has no manual path; entitlements do** (form, CSV,
  connectors) — the two planes are kept distinct so detected "truth on the
  endpoint" is never hand-edited.
- Purchased-vs-deployed math is claimed only where entitlement data exists;
  detected-only products stay honestly `unentitled`. Multi-source seat sums
  keep the per-source breakdown visible.
- Three (then four) more born-on-Postgres stores join the ladder; server
  refuses to boot if their migrations fail (consistent with the substrate
  posture).
- A new top-level SCL nav entry costs edits to 11 hand-duplicated nav copies
  (accepted at owner direction; the long-standing Result Sets drift gets
  reconciled in the same PR).
- The per-user carve-out (§8) is a deliberate, contained ADR-0016 deviation
  requiring maintainer sign-off. Default posture is **pseudonymous**
  (keyed-HMAC `hash`); raw profile names are opt-in (`collect`) and full
  suppression is one flag (`omit`).
- The M365 connector's client secret is envelope-encrypted via SecretCodec
  from its first commit, in a registered column on the entitlement store —
  PR2 carries the codec's first production wiring (boot-time `init()`,
  fail-closed) as a scoped, tested deliverable; the pre-existing
  `oidc_client_secret` plaintext gap remains separately tracked and is not
  extended.
- Fleet network cost is negligible: licence blobs hash-skip (stable
  estates), usage blobs are tens of KB daily from active machines only;
  Graph sync is one tenant-level call pair per day.

## Alternatives considered

- **Manual entitlement register (roadmap 10.3 as drafted)** — rejected
  2026-03 by product decision… **REVERSED 2026-07-04 for entitlements**
  (manual/CSV/connector inputs are in scope); licence *detection* remains
  agent-only.
- **Routing licence/usage data through TAR** — rejected; ADR-0016 already
  settled this (TAR is pull-only, event-shaped, edge-resident). The usage
  source *reads* TAR locally and pushes via daily-sync.
- **A new top-level dashboard page** — rejected in rev 1 (hand-copied nav
  cost)… **REVERSED 2026-07-04 at owner direction** (the SCL page); the
  11-copy nav edit is accepted and the existing drift reconciled while
  we're in those files.
- **Per-user Graph `licenseDetails` fan-out** — rejected for v1: N×HTTP per
  tenant user and per-user PII, for seat math that `subscribedSkus` already
  gives at tenant level.
- **Replace-by-import CSV semantics** — rejected in favour of upsert-by-key:
  overlapping files would duplicate rows and destroy operator annotations;
  imports never delete.
- **Fuzzy/probabilistic catalog matching in v1** — rejected for determinism
  and testability; the tiered exact/normalised/token-set matcher with
  persisted method+confidence leaves room for smarter matching later.
- **Extending `SoftwareInventoryStore`** with licence columns — rejected;
  one-store-per-typed-domain is the established precedent, and installed
  software vs detected licences have different lifecycles and postures.
- **MFA step-up on SCL endpoints** — rejected; nothing in §27 executes on
  endpoints (the software-packages step-up guards executable content);
  entitlements are financial metadata under `SoftwareCatalog:Write` + full
  audit.

## Relationship to other ADRs

- **ADR-0006/0007/0008/0012** — all new stores are born-on-Postgres under
  the store contract; no SQLite anywhere (the entitlement connector's
  **non-secret** runtime config uses the existing `RuntimeConfigStore`,
  which predates the cutover and is already on the migration ladder; its
  client secret does not — §10.3).
- **ADR-0016** — this feature is two new daily-sync sources riding the
  framework exactly as anticipated (licensing in PR1, usage in PR3; PR2's
  `ent|` records extend the licensing blob under the §1 forward-compat
  rule); §8 above records the single, contained deviation from its no-PII
  posture (licence source only) and the usage source's and M365 connector's
  full conformance. The typed-source registry rule (§4) implements ADR-0016
  §5 parity.
- **ADR-0017** — the SCL fleet-wide aggregate surfaces are **pinned
  global-only by design** (a group-confined principal gets 403, never a
  partial or leaky rollup); the per-device SCL reads ship **global-gated at
  PR1** and are **registered as flip-wave consumers of ADR-0017 PR-A**
  (#1634 umbrella; #1715 prerequisite) — they adopt the admit-then-filter chokepoint when it
  lands, in the same fleet-wide flip as every other list read (§7, rev 5).
  Both halves are enforced by §7's named `[scl][adr0017]` tests, mirroring
  the `/inventory` `software_catalog` precedent that ADR-0017:221-231
  documents.
- **ADR-0010** — no software-licence key material is stored (moot by
  construction); the M365 client secret is a registered `SecretCodec`
  column on the entitlement store from PR2, which also carries the codec's
  **first production wiring** (column registration + audit hook, then boot
  `init()` fail-closed — §10.3 strict order). The legacy `oidc_client_secret`
  plaintext gap (SQLite `RuntimeConfigStore`) is out of scope and
  separately tracked.
