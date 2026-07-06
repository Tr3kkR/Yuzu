---
status: proposed
date: 2026-07-06
owner: Alex Young
deciders: product-owner direction; planning Q&A 2026-07-04 (rev 2 same day); privacy & secrets review rounds 2026-07-06; grilling session 2026-07-06
scope: capability §27 — agent licence detection, multi-source entitlement ingestion, server-side compliance evaluation, usage metering & reclamation, the SLE page, RBAC, and the per-user privacy carve-out
context-refs: capability §27 issues #264–#267; #266 (entitlement-register reversal); ADR-0017 flip-wave (#1634, #1715); superseded standalone ADR PR #1870 (rev 1–5 review history); deferred — #1921 (KEK operator surface), #1922 (oidc_client_secret gap), #1923 (round-3 review items)
---

# 0024 — Software Licensing & Entitlements (SLE: agent-detected licences + multi-source entitlements)

Supersedes the roadmap Phase 10 sketch of capability §27 (a SQLite `CatalogStore`, a
hand-maintained entitlement register, a `software_usage` agent plugin, software tags,
and a compliance dashboard) with the design recorded here: born-on-Postgres stores,
agent-detected licences on the ADR-0016 daily-sync framework, multi-source
entitlements, server-side compliance evaluation, and a new top-level SLE page. It also
renames the capability from the map's "Software Catalog & Licensing" to **"Software
Licensing & Entitlements" (SLE)** — the capability-map §27 entry is retitled
accordingly. It supersedes the closed standalone ADR PR #1870 (five review rounds; the
rev 1–5 history remains on that PR), and is numbered 0024 because 0021–0023 are
reserved by in-flight ADR branches. It records a single, contained deviation from ADR-0016's
machine-scope/no-PII posture — per-user licence probing on the licence source only
(Decision 11) — which requires maintainer sign-off. Yuzu's own product-licence
machinery (`LicenseStore`, the `License` RBAC securable, capability §22.3) is
untouched; all naming here uses `ProductRegistry*` / `SoftwareLicensing*` /
`SoftwareEntitlement*` / `SoftwareUsage*` and `software_license.*` /
`software_entitlement.*` event names.

## Context

The platform cannot today answer five operator questions: what software licences are
in use on an asset and of what type; whether anything is running on a lapsed licence;
which licences and subscriptions are coming up for renewal or expiry; how what was
purchased compares with what is deployed; and what is being paid for but never or
rarely used. The capability map (§27, five sub-capabilities, all Not Started) and
roadmap Phase 10 sketched this in 2026-03, but three things have since changed under
that sketch. **The storage substrate moved:** ADR-0006/0007 forbid new SQLite server
stores; new stores are born-on-Postgres per the store contract (ADR-0012), so the
Phase 10 names (`CatalogStore (SQLite)`, `entitlement_store.cpp`) are stale. **The
ingestion substrate now exists:** ADR-0016's daily-sync framework is live with three
sources (`installed_software`, `app_perf`, `device_ci`), a shared server ingest seam
used by both the direct gRPC path and the Erlang gateway proxy, and typed Postgres
projections — and it explicitly anticipated "a future `last_used` usage source for
SAM/entitlement," which this design fulfils alongside licence detection. **The product
decision changed:** the manual entitlement register drafted in issue #266 was first
rejected — licence data must be agent-detected — then, at rev 2 (2026-07-04),
entitlements returned to scope as a *separate, multi-source* plane measured alongside
detected licences, and the owner directed a brand-new top-level "SLE" page rather than
a tab on `/inventory`.

Name collisions constrain the design. `LicenseStore` and the `License` securable
already mean **Yuzu's own product licence** (§22.3) and stay untouched. "Software
catalog" already means the shipped `/inventory` rollup of *installed* software
(`SoftwareCatalogRow` / `SoftwareCatalogRollup`); the new canonical-identity store is
therefore a **registry**, not a catalog, and nothing in §27 borrows the "software
catalog" name — it keeps its existing `/inventory` meaning. The capability's RBAC
securable is named **`SoftwareLicensing`**, matching the renamed capability, the
`software_licensing` source, and the store family. Yuzu is effectively greenfield here
(small test labs, no customers on this surface), so there is no legacy-compatibility
burden beyond preserving ADR-0016 wire stability across mixed-version fleets.

## Terminology

- **Software licence** / **detected licence** — endpoint software licensing state
  (product, type, channel, status, expiry) as observed by an agent. Always qualify:
  a **Yuzu licence** is the product's own licence (§22.3), a different thing.
- **SLE** — "Software Licensing & Entitlements," the §27 capability and the new page.
- **ProductRegistry** — canonical software-identity master data (deterministic
  matching of raw names → one product). Distinct from the `/inventory` "software
  catalog," which keeps its existing meaning.
- **Detection plane** vs **entitlement plane** — the two data planes: what is
  *observed on endpoints* vs what is *purchased*.
- **Effective licence state** — the state (including lapse) the server *derives* from
  agent-reported facts against server-now; not a raw agent field.
- **Entitlement** — a purchased right (seats, type, term, renewal, cost) from a
  manual, CSV, connector, or agent source.
- **Unentitled** — a product with detected licences but no entitlement data; never
  reported as "compliant." **Unreported** — an asset with no usage data; never
  reported as "unused."

## Decisions

1. **Two data planes, kept deliberately distinct.** Licence *detection* is
   **agent-only** — there is no manual path to edit detected state, so "truth on the
   endpoint" is never hand-massaged. *Entitlements* (what was purchased) accept
   **manual, CSV, and automated** input. Purchased-vs-deployed math is computed only
   where entitlement data exists; detected-only products stay honestly `unentitled`.
   The two planes never merge into one editable record. A consequence, stated as a
   gap rather than hidden: **a wrong detection has no operator override** — the
   remedy is a corrected probe in the next agent release; detection confidence is
   surfaced precisely so operators can weight `heuristic` rows accordingly, and
   Decision 8's worsening-only/hold-down semantics bound the alert noise a misfiring
   heuristic can cause.

2. **Agent detection is a new `license_scan` plugin that probes every available
   surface.** Per-OS translation units with pure parsers split out; actions `list`
   (emit records) and `surfaces` (diagnostics — which surfaces are available and why
   not). Surfaces v1: Windows WMI `SoftwareLicensingProduct` (own bounded COM, never
   `WBEM_INFINITE`), Office ClickToRun registry, an extensible `ProbeSpec` table (MS
   server products, Autodesk, security/backup agents, VMware, open-source
   classification), and **per-user hives** (incl. `RegLoadKey` of offline
   `NTUSER.DAT`); Linux `rpm`/dpkg DEP-5 declared licence, RHEL entitlement certs,
   FlexLM `.lic` expiry; macOS `_MASReceipt` + machine-scope vendor plists. Adding a
   vendor later is one `ProbeSpec` row. Vocabularies are **closed and
   unknown-preserving** (the plugin never fabricates): `license_type`, `status`,
   `source`, and a `confidence` of `authoritative | probable | heuristic`
   (`authoritative` only from an OS/vendor licensing API or a parsed vendor artefact).
   **Licence key material is never persisted or transmitted** — only a `key_hint`
   (OS-provided partial or an in-memory hash prefix). `exe_hints` on each record is
   the authoritative product↔exe bridge for the usage join (Decision 15). Every field
   is strict-sanitised (strips delimiter/control bytes, clamps to 1024 B).

3. **Transport is a new `software_licensing` daily-sync source on the ADR-0016
   framework.** Parse plugin output → canonical blob (records sorted + deduped,
   delimiter-joined) → SHA-256. **Unlike the three legacy sources, this source's
   hash-skip comparison is computed over the raw received blob bytes** (recomputed
   server-side — the claimed hash is never trusted), not over re-parsed rows — so
   skipping unknown record kinds cannot push a mixed-version agent into the permanent
   full-resend loop ADR-0016 documents for the parse-then-recompute sources, and the
   forward-compat rule below is genuinely loop-free in both directions. (One accepted
   consequence: a server-side projection fix does not re-project a stable estate by
   itself — the framework's `need_full` path remains the forced-resync lever.) The wire key
   rides `InventoryReport.plugin_data` — **no proto change, no gateway regen** (opaque
   `map<string,bytes>`). Interval 24 h; hash-skip is meaningful because licence
   estates are stable day-to-day. **Blob-stability rule:** the canonical blob contains
   only facts that change when detected state changes — no collection timestamps, and
   countdowns (e.g. KMS grace minutes) are converted to an absolute UTC date so a
   ticking counter cannot defeat hash-skip. **Empty-vs-error:** zero rows is a
   legitimate state (a valid empty blob full-replaces to empty); the cycle is skipped
   only when a platform's *primary* surface reported an error — where "success" is
   structural, not inferred: the enumeration API itself completed (a query returning
   zero rows is success; access-denied or a failed call is error), and per-user hives
   are never a *primary* surface — so a real failure never wipes stored state and a
   privilege-stripped fleet can neither wipe state nor stall its syncs.
   **Forward-compatibility:** both the agent blob parser and the server seam **skip
   unrecognised record-kind prefixes**, so later record kinds (the `ent|` entitlement
   records, Decision 12) ride the same blob without breaking mixed-version fleets in
   either direction.

4. **Canonical state lives in born-on-Postgres stores.** `ProductRegistryStore`
   (canonical identities + match links), `SoftwareLicensingStore` (per-agent detected
   rows + posture rollups + alert dedup), `SoftwareEntitlementStore` (purchased state
   from five sources), and `SoftwareUsageStore` (usage facts). No new SQLite (ADR-0006/
   0007), full store contract (ADR-0012): migrate-at-construction on a pinned lease,
   schema-qualified runtime SQL, bounded leases, fatal-on-open-failure, destruct-
   before-pool. **No cross-schema SQL or FKs** — cross-store joins happen in C++ in the
   evaluator (never holding a lease across another store call). Reads are authoritative
   (a degrade returns nullopt → 503/banner, never a silent empty list, which on a
   compliance surface would be a fail-open lie); ingest writes are fail-soft, retried
   next cycle. *Rejected: extending `SoftwareInventoryStore` with licence columns —
   installed software and detected licences have different lifecycles and postures;
   one-store-per-typed-domain is the established precedent.*

5. **One ingest seam per source, shared by the gRPC and gateway paths, with a
   same-change typed-registry rule.** The licensing (and usage) ingest seam sits beside
   the existing inventory seams and is called from **both** the direct
   `ReportInventory` and the gateway `ProxyInventory`. Untrusted-input discipline
   before the store: blob and record caps, per-field UTF-8 scrub/clamp, enum whitelists
   (unrecognised → `unknown`), expiry plausibility-clamp. The server **recomputes** the
   hash over the raw received bytes — it never trusts the claimed one — and enum
   normalisation happens at store projection, after the hash comparison.
   **Load-bearing invariant:** each new wire key is added to
   `typed_inventory_sources.hpp` **in the same change** as its seam — omission
   double-stores the blob into the generic `InventoryStore` on the gateway path,
   readable under `Infrastructure:Read`, i.e. a leak past the `SoftwareLicensing`
   securable.

6. **Catalog matching is deterministic, not probabilistic.** A pure
   `product_normalize` library (`normalize_title`, `normalize_vendor`, `norm_key`)
   feeds strictly-ordered tiers — `exact_norm` → `title_vendor` → `token_set` →
   `birth` (new product). **No fuzzy/Levenshtein matching in v1**: every decision is
   reproducible in unit tests. Aliases persist `method` + `confidence`, so manual
   curation and smarter matching can layer on later by editing aliases, without
   redesign. *Rejected: probabilistic matching in v1 — it trades away determinism and
   testability for accuracy the tiered matcher can approximate.*

7. **Compliance is derived server-side, and the honesty commitments are load-bearing.**
   A background evaluator (cloning the existing rollup lifecycle: boot pass, then
   completion-spaced cadence, keep-last-good, stop/join before teardown) re-derives
   **effective licence state including lapse against server-now** — so a device that
   *stopped syncing* before its licence lapsed still shows `expired`. Non-negotiable
   honesty rules: detected-only products stay `unentitled`, **never** "compliant";
   reclamation's absent-usage state is **Unreported, not Unused**; unknown seat counts
   are `NULL`, never a fabricated zero; multi-source seat sums keep the **per-source
   breakdown visible** (double-counting is shown, not hidden); the "installed but
   licence-unreported" delta is shown, not hidden; and detection `confidence` and
   `unknown` states are first-class throughout. Verdict *freshness* is part of the same
   posture: compliance surfaces carry the rollup's as-of time and evaluator staleness is
   observable rather than silent — a wedged keep-last-good evaluator serving stale
   verdicts is the same fail-open class as a silent empty list.

8. **Lapse, expiry, and renewal emit deduplicated notifications and webhook events.**
   The evaluator fires `software_license.expiring` / `software_license.expired` (and
   `software_entitlement.renewal_due`, Decision 12) through the existing dual-sink
   pattern (notification store + webhook/offload event). Emission fires **only** on a
   **worsening** condition/bucket transition (buckets 30/14/7/1 days) or on persistence
   past a 7-day re-arm; an improving transition never fires, and a condition that
   clears and re-asserts inside the re-arm window is held down — so oscillating states
   (KMS grace↔expired drift, daily re-imaged VMs) cannot spam. On the *first* evaluation
   of an estate (and after a loss of dedup state) existing conditions are treated as new
   and fire once per product — a bounded burst, deliberately preferred over silently
   baselining pre-existing expiries on a compliance surface. `renewal_due` uses the
   **same bucket/re-arm machinery**, keyed on the entitlement plane's renewal date.
   This satisfies "not dashboard-only" without daily noise, and escalates as expiry
   approaches.

9. **Access is a new top-level SLE page plus unified `/api/v1/sle/*` REST and MCP
   tools, all gated on one new `SoftwareLicensing` securable.** SLE is a **brand-new
   top-level page** (`/sle`: Licences | Entitlements | Compliance | Reclamation
   sub-views), built on the shared guardian shell and cloning the `/inventory` provider
   model (nullopt → degrade banner, never an empty table). SLE v1 renders **tables and
   KPI tiles** (the `/inventory` model); charts are deliberately out of v1 — adding
   them later means an opt-in shell head token, not unconditional chart-bundle loading
   on every shell page. The in-page "Compliance" sub-view keeps its short tab label,
   but every out-of-page surface is fully qualified ("Licence Compliance" in the
   command palette, a qualified page title) to avoid colliding with the existing
   Guardian `/compliance` page — the same qualify-on-collision discipline the
   Terminology section mandates for "licence". The software **catalog stays on
   `/inventory`**, cross-linked. RBAC grants follow the established per-role shape,
   stated here so nothing is left to inference: **Viewer and PlatformEngineer Read;
   Operator Read + Write; ITServiceOwner full CRUD** (as for its other operational
   securables); **ApiTokenManager none**; admin roles per their global pattern — a
   conscious acceptance that entitlement financial metadata is visible to every Read
   holder, consistent with how other securables scope; deployments needing tighter cost
   visibility use the existing remedies (deny-override, custom roles) rather than a new
   field-level mechanism. Connector *configuration*
   (tenant/client IDs and the secret) is **admin-gated** (the `admin_fn_`
   OIDC-Settings precedent), **not** `SoftwareLicensing:Write`; only Sync-now rides the
   securable. **No MFA step-up anywhere in §27** — nothing here executes on endpoints
   (the `software-packages` step-up exists precisely because that endpoint dispatches
   executable content); RBAC Write plus full audit (including denied rows) is the
   control. The top-level nav entry costs edits to the hand-duplicated nav copies
   (accepted at owner direction), and the long-standing nav drift across those copies
   and the command palette is reconciled rather than extended. *Rejected: a tab on
   `/inventory` (rev 1) — reversed at owner direction.*

10. **List-read scoping follows ADR-0017 honestly, without inventing a chokepoint.**
    (Paths here are shorthand for `/api/v1/sle/*` routes.) The SLE fleet-wide
    aggregate surfaces (`/sle/summary`, `/sle/licenses`, and the Licences fragments)
    are built from precomputed rollups aggregated across every management group and,
    exactly like their `/inventory` `software_catalog` twin, cannot take a per-row
    admit-then-filter; they are **pinned global-only by design** — a group-confined
    principal is denied (403) with explicit guidance, never served a partial or leaky
    rollup. The per-device reads split by shape: **single-agent drills
    (`/sle/agents/{id}`) take the working ancestor-aware per-device scoped gate from
    day one** (the `device_routes` precedent: tier + management group, 403 outside
    scope) — this route is also Decision 11's privacy-verification surface, so it gets
    real confinement immediately; only the **true fan-out list reads**
    (`/sle/licenses/{key}/devices`, list fragments) ship global-gated and are
    **registered as flip-wave consumers of ADR-0017 PR-A** (the admit-then-filter
    chokepoint; umbrella #1634, prerequisite #1715). SLE gates are built on the
    fail-closed enforcement primitive (`rbac_enforcement_in_effect()`), not the
    `is_rbac_enabled()` shape whose corrupt-rbac.db fail-open is tracked by #1717 —
    or they land after #1717 closes it. *Rejected: wiring an ad-hoc
    per-row filter for the fan-out reads — that is exactly the pattern ADR-0017 exists
    to replace, and PR-A is not implemented yet (the `#1716` forward-references in
    `server/core` point at a closed doc-honesty PR, not the gate).*

11. **Per-user detection is a contained ADR-0016 deviation, pseudonymous by default.**
    At the owner's explicit direction ("probe everything"), the `software_licensing`
    source probes per-user surfaces and records may carry `user_scope=user` +
    `user_ref`, deviating from ADR-0016's machine-scope/no-PII posture — confined to
    **two fields on this one source**. `user_ref` is a local profile name only (never
    SIDs, emails, or directory identities — and "never SIDs" binds the **HMAC input**
    as well: a record whose profile name cannot be resolved ships with the identifier
    omitted, never a SID or its hash). A named knob controls it:
    **`--license-scan-user-ref=collect|hash|omit`**, **default `hash`** — a per-agent
    keyed pseudonym `HMAC-SHA256(k_agent, profile)` truncated to 16 hex, where `k_agent`
    is a 256-bit CSPRNG key persisted locally and **never transmitted or logged** (not
    an unsalted `sha256/12`, which a low-entropy name like `jsmith` makes trivially
    reversible). `collect` sends the raw name (opt-in); `omit` suppresses the
    *identifier*, not the *probe* (`user_scope` still distinguishes per-user
    detections). GDPR posture stated plainly: a hashed `user_ref` is still personal data
    (Recital 26); erasure is knob-flip to `omit` (full-replaced within one 24 h cycle
    for syncing agents; offline agents purge on reconnect or via decommission) plus the
    **agent-decommission cascade — the per-store `delete_agent`
    methods exist today with no production caller, so this capability builds the
    decommission fan-out and registers its stores with it**; there is **no row-level
    erasure API**, a stated gap. The effective mode is **centrally verifiable**: the
    stable effective-mode value rides the canonical blob as a config-stable record
    (verifiable fleet-wide from stored state, including for offline agents), while
    flapping surface diagnostics never touch the blob and are fetched live via the
    command path on the `/sle/agents/{id}` drill. Reads that render `user_ref` rows
    (that drill) join the per-open behavioral-audit tier (the `dex.device.view`
    convention: audited per open, fail-closed) and register in the enterprise read
    inventory; the four new stores and the `user_ref` data class register in the
    enterprise data inventory at implementation time. The **usage source and the M365
    connector do not inherit** this carve-out. Maintainer sign-off on this deviation is
    required. *Rejected: raw-collect default (reversed at review) and unsalted
    `sha256/12` (dictionary-reversible).*

12. **Entitlements accept five sources with a visible per-source breakdown and
    non-clobbering ownership.** Sources: `manual` (GUI form + REST CRUD), `csv` (GUI
    upload + REST raw `text/csv`), `graph_m365` (scheduled connector, Decision 13),
    `agent_flexlm` (FlexLM `.lic` `INCREMENT` seat counts) and `agent_kms` (KMS host
    activation counts) — the agent sources ride the `software_licensing` blob as `ent|`
    records under the Decision 3 forward-compat rule, with format-pinned host refs so
    identity keys derive deterministically from the wire. Identity/upsert per source
    (manual = server UUID; csv = external_id or content hash, **upsert-by-key**;
    graph = `skuId` full-set upsert with soft-retire; flexlm/kms = host-derived keys).
    **Field ownership:** connector/agent writes touch only observed fields and **never
    clobber operator annotations** (`cost_*`, `contract_ref`, `po_ref`, `notes`);
    connector-owned rows are immutable in GUI/REST (409) *except* those annotation
    fields. Compliance vocabulary `compliant | over_deployed | under_used | unentitled |
    unknown` with the comparison **basis recorded per product**
    (`installed_vs_purchased | assigned_vs_purchased | inuse_vs_total | none`); NULL
    seats ⇒ compliance `unknown`. *Rejected: replace-by-import CSV semantics —
    overlapping files would duplicate rows and destroy annotations; imports never
    delete.*

13. **The M365 connector is tenant-level only, and its secret is SecretCodec-encrypted
    on the entitlement store (ADR-0010).** Graph calls are **tenant-level**
    (`subscribedSkus`, `directory/subscriptions`) — **no per-user `licenseDetails`
    fan-out** (avoids N×HTTP and per-user PII). The connector exposes a manual
    **Sync-now** trigger (GUI + REST action under `/api/v1/sle/*`), Write-gated per
    Decision 9, alongside its schedule. The client secret **never touches
    `RuntimeConfigStore`** (SQLite, off-registry, unrotatable); it lives in a
    **registered `SecretCodec` column on the born-on-PG entitlement store**
    (`connector_secret.secret_enc`), while non-secret keys (tenant/client id, enabled)
    stay in runtime config. This is **SecretCodec's first production wiring**, with a
    strict boot order: construct provider + codec → **`register_secret_column` →
    `set_audit_hook` → `codec.init()`** → only then open the PG stores. Registration
    and the audit hook must precede `init()` — `init()` snapshots the registered
    columns for the boot-time orphan scan (a restored DB with an encrypted blob but a
    deleted KEK row must fail closed at *boot* with `kek_orphaned`) and emits the
    first-boot `kek.generated` audit event, both lost if ordered after. `init()`
    failure is `startup_failed` — the server refuses to boot rather than run with
    unreadable secrets. Encrypt failure aborts the write transaction (never a plaintext
    or empty write); decrypt is **fail-closed** (connector stops, generic external
    error, no tamper/existence oracle); the Settings secret field is write-only.
    Connector secret writes follow the OIDC-settings posture (admin gate, **no
    step-up**); if Settings credential writes ever gain step-up, connector config
    follows in the same change. **The KEK operator surface (rotation, retirement, the
    break-glass flag) is deliberately deferred to #1921** — an accepted, recorded
    deviation from ADR-0010's ships-with-the-first-secret expectation: until #1921
    lands, the KEK has no operator rotation path, and a Postgres restore *without* the
    keys directory is hard-down until the keys backup is restored (the break-glass
    relief valve arrives with #1921). The M365 client secret itself remains replaceable
    at any time by re-entry in Settings; only the wrapping key lacks an operator path.
    Connector input is pinned against the SSRF class: GUID/verified-domain validation,
    **fixed token/Graph hosts**, `@odata.nextLink` followed **only when same-origin**
    with a bounded page count, **no redirect following** (or same-origin-pinned
    redirects only), and bounded response size and timeout per call. The pre-existing
    `oidc_client_secret` plaintext gap is neither extended nor touched (separately
    tracked: #1922).

14. **CSV ingest is one shared pure parser with upsert-by-key, a mandatory dry-run, and
    hard caps.** A single pure `csv_import` library (RFC-4180 quoting/CRLF/BOM,
    case-insensitive header mapping, line-numbered errors) backs **both** the GUI upload
    and the REST raw `text/csv` endpoint — same parser, validator, and caps. Semantics
    are **upsert-by-key** (re-uploading a corrected file updates in place; imports never
    delete — deletion is explicit). A **dry-run** performs full validation with zero
    writes (default-ON in the GUI). Caps are explicit: 1 MiB, 10 000 rows, ≤100 reported
    errors (the uncapped OTA-upload precedent is deliberately not copied). **Entitlement
    writes (import apply, CRUD, connector sync) nudge the evaluator** — compliance
    verdicts refresh promptly rather than waiting out the cadence interval, so the
    dry-run → import → verify loop is coherent.

15. **Usage metering and reclamation are opt-in and conservative.** Usage is a separate
    **opt-in** daily-sync source (`--usage-sync-enable`, default off) that reads the
    agent's TAR warehouse locally through the plugin's sandboxed read-only `sql` action
    and ships **machine-scope** aggregates (the user dimension is dropped on-device,
    test-enforced; a monthly-tier fallback errs toward "recently used"). Usage
    **categories** (Used ≤ 30 d, Rarely 31–90 d, Unused > 90 d, **Unreported** = no usage
    source or no matched row) are **policy computed server-side at read time**, so a
    threshold change never forces fleet re-sync and **reclamation never fires on missing
    data**. Reclamation surfaces lead with **usage coverage** (devices reporting vs
    fleet) and render zero coverage as explicit guidance to enable the opt-in source — a
    blank candidate list must be attributable to data absence, never read as "nothing to
    reclaim". Reclamation candidates are paid licence types × Unused/Rarely usage.
    Product tags live on `ProductRegistryStore` and drive tag-based views and
    (time-boxed) management-group rules. *Rejected: routing licence/usage data through
    TAR as a transport — ADR-0016 already settled TAR as pull-only/edge-resident; usage
    *reads* TAR locally and pushes via daily-sync.*

16. **Out of scope.** Yuzu's own product-licence machinery (`LicenseStore`, the
    `License` securable, §22.3) is untouched. Per-user Graph `licenseDetails` fan-out is
    excluded (tenant-level seat math suffices). Probabilistic/fuzzy catalog matching is
    excluded in v1 (Decision 6). MFA step-up on §27 endpoints is excluded (Decision 9).
    Explicit source **precedence** for double-counted seats is excluded — the per-source
    breakdown is shown, not resolved, and explicit precedence can layer on later.

## Consequences

- Yuzu can answer, per asset and fleet-wide: what software licences exist, their
  types and channels, what has lapsed, and what expires or renews within N days —
  with notifications — how purchases compare with deployment for entitled products,
  and what paid software is going unused.
- Licence detection has **no manual path**; entitlements do (form, CSV, connector,
  and agent-derived records). The two planes stay distinct so detected "truth on the
  endpoint" is never hand-edited, and purchased-vs-deployed math is claimed only
  where entitlement data exists — detected-only products stay honestly `unentitled`.
- Multi-source seat sums keep the per-source breakdown visible; unknown seats are
  `NULL`, not a fabricated zero; absent usage is *Unreported*, never *Unused*.
- Four born-on-Postgres stores join the ladder; the server refuses to boot if their
  migrations fail, consistent with the substrate posture.
- A new top-level SLE nav entry costs edits to the hand-duplicated nav copies
  (accepted at owner direction); the long-standing nav drift across those copies and
  the command palette is reconciled rather than extended.
- The per-user carve-out (Decision 11) is a deliberate, contained ADR-0016 deviation
  requiring maintainer sign-off. Default posture is **pseudonymous** (keyed-HMAC);
  raw profile names are opt-in and full suppression of the identifier is one flag.
  A hashed `user_ref` is still personal data, and there is no row-level erasure API —
  both stated, not hidden. The agent-decommission cascade that completes the erasure
  story is built by this capability (it does not exist today).
- The M365 client secret is envelope-encrypted via SecretCodec from its first write,
  in a registered column on the entitlement store; §27 carries the codec's **first
  production wiring** (boot-time `init()`, fail-closed). The KEK operator surface is
  deferred to a tracked issue — until it lands there is no operator rotation path, an
  accepted deviation from ADR-0010's expectation. The legacy `oidc_client_secret`
  plaintext gap remains separately tracked and is not extended.
- Fleet network cost is negligible: licence blobs hash-skip on stable estates, usage
  blobs are small and only from active machines that opted in, and the Graph sync is
  one tenant-level call pair per day.

## Ratification

Acceptance of this ADR carries two explicit sign-offs beyond the design itself:
(1) the **Decision 11 deviation** from ADR-0016's machine-scope/no-PII posture
(per-user licence probing, pseudonymous by default, contained to two fields on one
source); (2) the **Decision 13 deferral** of the KEK operator surface to #1921, a
recorded deviation from ADR-0010's ships-with-the-first-secret expectation.
