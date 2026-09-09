# Presentation / Core / Engine Split — Delivery Matrix

The delivery spine for the **three-binary decomposition** of the Yuzu server
(`docs/adr/0031-presentation-core-engine-decomposition.md` — cite by filename, it shares the number
0031 with the engine-principal-store ADR). Those ADRs record the *model and invariants*; this matrix
tracks *what ships, in what order, who reviews it, and how we know it's done*. **If a row here disagrees
with the ADRs, the ADR wins; on delivery status, this matrix is the source of truth.** The `/split`
skill is a pointer to both and loses to both.

**Verified against the tree 2026-09-08** (`origin/dev` @ `f9d1275c0`; WS-0 merged #4161, INV-31-4 global test found already-shipped #842/#3991/#3992 — WS-A4 re-scoped). Re-stamp
this line whenever the table is revised — a matrix from a stale checkout is worse than none, and the
current-state claims below were wrong in the first draft because they were copied from stale ADR status
columns. Grep the tree, don't trust a doc.

> **⚠️ Standing instruction — update on close.** Every PR that closes or materially changes the status
> of a workstream in this matrix MUST update that row **and** re-stamp the Verified line in the SAME PR.
> Treat status drift as a review-blocking defect, exactly like a stale doc comment.

**Companion docs:** `docs/adr/0031-presentation-core-engine-decomposition.md` (INV-31-1..6, the 5-step
migration), `docs/adr/0032-use-case-admission-protocol.md` (the interlock — binds immediately on
acceptance), `docs/adr/0033-access-control-spine.md`, `docs/adr-1005-execution-plan.md` (M3 = the NVD
matcher-parity gate, *not* the fragment↔REST programme), `docs/adr/2002-high-availability-architecture.md`
(§4/§5 — MCP session + replay ring → durable core outbox), `docs/ha-delivery-matrix.md` (the HA
deliverables this split *consumes*).

---

## ⚠️ Current-state is grepped from the tree, not the ADRs (the docs are stale)

The first draft asserted a falsified current state; a three-model adversarial panel (Fable /
`gpt-6-astra` / Kimi-K3) caught it. Verified:

- `authorize_list_read` **exists** — 66 occurrences, `server/core/src/rbac_store.hpp:340`, live callers,
  pinned by `tests/unit/server/test_list_read_confinement.cpp` (`[1715]`). `require_list_read` (ADR-0017
  PR-A) shipped. **#1714 / #1715 / #1716 CLOSED.** Engine-principal RBAC enforcement shipped.
- **The real engine-gate blocker is #2665 (OPEN)** — #1715 shipped **additive** authorization (a global
  deny does not override a management-group allow); ADR-0032 interlock **(b)** needs **deny-precedence**.
  This ADR-level contradiction must be named, not assumed satisfied.
- Absent (0 occurrences): `use_case_run_id`, the release-log store, the `evaluate_as_operator` seam — so
  the admission/grant/audit substrate (interlock c/d/h) is open while confinement (a/b-partial) shipped.
- **The INV-31-4 GLOBAL contract test EXISTS and is green** — `scripts/ci/check-api-parity.py` (whole-tree
  CI gate) + `tests/unit/server/test_openapi_spec_completeness.cpp` (in-process `TestRouteSink` half),
  shipped out-of-band under **#842 / #3991 / #3992**; `/api/vN` drift is zero (196 routes / 195 OpenAPI
  entries / 1 allowlisted CORS `OPTIONS`). **ADR-0031's "that test does not exist today" is STALE**
  (corrected 2026-09-08). **Caveat:** it's a **LEXICAL tripwire, not a proof** — a route registered via a
  non-literal/helper-mediated call emits a CI warning but does NOT fail the build (type-aware successor
  #2572). So WS-A4's contract-test half is DONE *for literal registrations*; what remains is the
  *per-family* seam enforcement (gates WS-B2), the handler→API seam refactor, and the PII-audit relocation —
  do NOT rebuild the global test.

---

## Two axes + a cross-cutting lane (read first)

- **Axis A — logical seam / authority (monolith-OK).** Public versioned API as sole authority; every
  handler/renderer calls the API, never a store pointer; the INV-31-4 contract test; the ADR-0032/0033
  confinement + admission + audit substrate. *Makes the split correct.* Almost all buildable while one
  binary.
- **Axis B — physical decomposition.** Drogon + G10, strangler cutover, extract presentation, extract
  engine, state relocation, event spine, component service identity, `uce` DB decomposition, supervision,
  per-binary `/readyz`. *Makes the split real.*
- **Lane X — cross-cutting / continuous.** Fan-out measurement, version-skew compat, split-topology
  config, split observability, validation harness, credential hardening.

"The split shipped" as a claim = the presentation binary extracted (all families cut over, httplib
presentation retired) **and** the engine binary extracted behind its interlock gate. The two extractions
are ordered: engine is **fifth** (ADR-0031 §5), after presentation.

---

## ⚠️ STANDING MERGE-GATE — the ADR-0032 interlock binds immediately

**No engine-path code — anything that admits a run, mints a grant, serves a use-case result, or composes
released facts — merges into ANY binary until the unconditional interlock set (a)–(d)+(h) lands
complete**, including (h)'s full credential fields (admitting-credential id, frozen grant snapshot,
requesting-credential id). This binds *now*, independent of packaging: reference-and-defer is safe for
*who owns* a prerequisite, never for *whether it gates a merge*. WS-A2a and WS-A6 live under this gate.
WS-0 certifies no in-flight engine-path ballot ships before it closes.

## ⚠️ The safe-to-extract gate (the load-bearing constraint) — ONE table

The strangler's **first live family cutover** is the real extraction moment — the first request to cross
into a separate process reaching core over the network. The gate governs *that*, and each subsequent
family. WS-B8 (httplib retirement) is the *completion*, never the trigger. **A component is extractable
only when every clause below is green for the family being cut.**

**safe-to-extract(PRESENTATION)** — before any family's live cutover:

| Clause | Row | Invariant / source |
|---|---|---|
| Seam enforced + INV-31-4 test green for that family | WS-A4 | INV-31-4, migration step 3 |
| That family's public REST+MCP capabilities exist | WS-A3 | migration step 3 sizing |
| Sessions + MCP replay relocated & durable | WS-B3 | ADR-2002 §4/§5 |
| Event spine live on the HA WS-2a outbox | WS-B4 | G1; ADR-2002 §5 |
| Component service identity live | WS-B6 | INV-31-5, Decision 6 |
| Presentation `/readyz` composed (never green while core down) | WS-B7 | INV-31-6 |
| Drogon build canary green | WS-B1 | G10 |
| K-fanout measured / accepted | WS-X1 | Cost K, gate on step 4 |
| Version-skew compat enforced | WS-X2 | Decision 6 (two deployable units) |
| 6a break-glass surface live | WS-X4 | Decision 6a |
| Presentation holds zero DB credentials | WS-B11 | INV-31-3 |
| Per-family seam+contract check + rollback path | WS-B2 | strangler safety |

**safe-to-extract(ENGINE)** — before WS-B9:

| Clause | Row | Source |
|---|---|---|
| Presentation already extracted (engine is fifth) | WS-B8 | ADR-0031 §5 |
| Interlock (a)–(d)+(h) complete | WS-A6 / WS-A5 | ADR-0032 (the merge-gate floor) |
| #2665 resolved (deny-precedence) + `evaluate_as_operator` seam built | WS-A5 | ADR-0032 (b) |
| Exec semantics (i) | WS-A1 | ADR-0032 (i) |
| Engine readiness (k) · cross-run isolation (l) · per-principal quota (m) | WS-B9 | ADR-0032 (k)(l)(m) |
| `uce` DB decomposition — engine cannot reach `yuzu`, core no grant on `uce` | WS-B11 | INV-31-3 |
| Engine boundary (B2-contract) security: grant + input-hash verification at the engine | WS-B9 | Decision 2/7 |
| Joined cross-boundary audit evidence | WS-A4 / WS-X5 | audit continuity |

Miss any and the failure is **structural, not cosmetic**: a renderer still holding a `Store*` after
cutover means the boundary didn't remove the coupling; a `/readyz` green while core is down hides an
outage; an engine composing facts before the interlock enlarges authority core never confined.

---

## The matrix — current state, reviewers, status

Columns: **WS · Delivers · Axis · Owner · Depends · Gates cutover? · Reviewers · Status**.
`Owner=THIS` = net-new here; else status is *pulled* from the named source (re-verified by WS-0).
`Gates cutover?` = does the safe-to-extract gate depend on this row (P = presentation, E = engine).

| WS | Delivers | Axis | Owner | Depends | Gates? | Reviewers | Status |
|----|----------|:---:|-------|---------|:---:|-----------|--------|
| **WS-0** | Reconciliation & **interlock certification** — re-verify every deferred item **against the tree**; certify interlock (a)/(b#2665)/(c)/(d)/(h); certify no in-flight engine-path ballot ships before the merge-gate closes; ratify HA §1c with the **ADR-1005 owner (Dave Rae)** — **DONE: ratified decoupled 2026-09-07** (dissent recorded-with-rebuttal); bottom out #2665 as the engine-gate's real open question. **DONE 2026-09-08** — certification `docs/security-reviews/split-ws0-interlock-certification-2026-09-08.md`; merge-gate armed as a hard CI tripwire (`tests/test_split_interlock_tripwire.py` + `tests/split_interlock_ledger.json`, wired into `docs-lint.yml`) PLUS a routed-concern row; gate CLOSED (b/c/d/h red — (b) is #2665 deny-precedence + #2675 seam); no in-flight engine-path ballot; ADR-0032 cells (a)/(m)/(f)/(h) found STALE → **#4124** (a tracked doc follow-up correcting the ADR's own table — NOT a WS-0 deliverable; the ledger+cert carry the correct state) | — | THIS | — | **predecessor of all** | architect + security-guardian | **done** |
| **WS-A1** | Baseline execution-semantics repair (step 1); also interlock (i) | A | THIS | WS-0 | — | architect + cpp-safety | planned |
| **WS-A2r** | In-process public-API contracts, **read/command paths** (step 2, read half) | A | THIS | WS-A1 | — | architect | planned |
| **WS-A2a** | In-process **admission / grant / finalisation-receipt** contracts (step 2, admission half) — **under the standing merge-gate** | A | THIS | WS-A1, WS-A6(c/d/h) | — | architect + security-guardian | blocked on interlock |
| **WS-A3** | Capability parity — the ~40–60 missing public REST+MCP capabilities, **per family** (devices, settings, `/auto`, …) | A | THIS (ADR-0031 §3) | WS-0 | feeds A4 per-family | consistency-auditor + architect | planned |
| **WS-A4** | **Logical seam enforcement + INV-31-4 contract test** — handlers/renderers call the API, never a store pointer; build fails on any registered route absent from the published OpenAPI; **relocate behavioural-PII audit from `*_ui.cpp`/`rest_audit.hpp` to the API call** (audit continuity). **⚠️ The GLOBAL drift test (interlock-(j)'s testability half only, LEXICAL — see the current-state caveat above) SHIPPED out-of-band under #842/#3991/#3992** — see the "INV-31-4 global contract test EXISTS" current-state bullet above for detail. Interlock (j)'s **generated-projection** half (#2678) stays RED — **currently unscheduled, tracked in ADR-0032 (j), owned by no workstream row** (WS-A4 delivered only (j)'s testability half). **REMAINING for WS-A4:** per-family seam+contract enforcement (gates WS-B2) · handler→API seam refactor · PII-audit relocation. | A | THIS | WS-A2r, WS-A3 (that family) | **P (per family)** | architect + security-guardian + cpp-safety | **partial** — global drift test done (#842); per-family + seam refactor + PII relocation planned |
| **WS-A5** | Input confinement — **SHIPPED** (`authorize_list_read` / `require_list_read` live; #1714/#1715/#1716 CLOSED). Residual: **#2665** (additive vs interlock-(b) deny-precedence) + `evaluate_as_operator` seam (absent) | A | /auth | WS-0 | **E** | security-guardian | shipped; #2665 open |
| **WS-A6** | Admission/grant/audit substrate — (c) D12 audit with indexed `use_case_run_id`, (d) P7 release-log store, (h) capability-declaration registry with full credential fields. (a) shipped. **Under merge-gate** | A | /auth + exec-plan | WS-0, WS-A5 | **E** | security-guardian + architect + docs-writer | (a) shipped; c/d/h absent |
| **WS-B1** | Drogon build canary (G10) — Drogon linked in the Meson/vcpkg matrix incl. MSVC static linkage | B | THIS | WS-0 | **P** | build-ci + cross-platform | planned |
| **WS-B2** | Drogon **strangler port + cutover plane** — presentation binary beside httplib; **ingress routing/steering** between the two; per-family port (async + repoint→core API + SSE rewrite + per-family seam+contract); **long-lived stream drain**; **per-family rollback**. First live cutover behind the gate | B | THIS | WS-B1, WS-A2r, WS-A4(family) | (the gate) | architect + cpp-safety + cross-platform | planned |
| **WS-B3** | State relocation — (a) sessions inherit HA durable-PG; (b) MCP replay ring → **durable core outbox** | B | (a) HA WS-1 / (b) HA WS-2b | WS-0; HA WS-1/WS-2 | **P** | authdb + security-guardian | **(a) DONE** (HA WS-1); (b) outstanding (HA WS-2b) |
| **WS-B4** | Cross-process event spine — **rides the HA WS-2a durable `event_outbox`** (not a second transport); record the ADR-0032 Decision 9 G1 channel choice (per-subscriber vs multiplexed-with-TCB-admission) | B | THIS + HA WS-2a | HA WS-2a, WS-A2r | **P** | architect + sre + security-guardian | HA WS-2a-1 done (table); 2a-2 NOTIFY/cursor-poll outstanding |
| **WS-B6** | **Component service identity + peer attestation (INV-31-5 / Decision 6)** — presentation→core mTLS identity; peer-IP/correlation attested as infra metadata only; core stops trusting in-process identity | B | THIS | WS-A2r | **P** | security-guardian + cross-platform | planned |
| **WS-B7** | **Per-binary readiness (INV-31-6)** — presentation `/readyz` = core reachable at a compatible API version, never green while core down; core store-conjunction readyz; engine readyz **(day-one — in the cutover gate)** | B | THIS | WS-A2r | **P** | sre + docs-writer | planned (helps HA WS-8) |
| **WS-B8** | **First live cutover → progressive family cutover → httplib presentation retirement** (step 4 completion) | B | THIS | gate: safe-to-extract(presentation) | completes it | architect + security-guardian | planned |
| **WS-B9** | **Extract engine binary** (step 5) — own process; facts/effects only through core; redeem release authorization before the first byte; engine boundary (B2-contract) security; (k)(l)(m) | B | THIS | gate: safe-to-extract(engine) incl. WS-B8 done | (the gate) | security-guardian + architect + cpp-safety | planned |
| **WS-B10** | Supervision / one-deployment-unit — **covers the migration period too**; one install / one health / one upgrade / one version across three processes + Postgres | B | THIS | WS-B2 (from first cutover) | — | release-deploy + sre | planned |
| **WS-B11** | **`uce` DB decomposition (INV-31-3)** — revoke core's grant on `uce`; engine credentials that structurally cannot reach `yuzu`; presentation holds zero DB credentials; `uce` provisioning / roles / retention / migrations; **negative DB-access tests** | B | THIS | WS-0 | **P + E** | architect + security-guardian + cpp-safety | planned |
| **WS-X1** | K-fanout measurement — per-view core-call fan-out on the busiest fragment; accept or mitigate | X | THIS | WS-A4 | **P** | performance + sre | planned |
| **WS-X2** | Version-skew compat contract — core-API compat (day one) + presentation↔engine B2 contract (separately versioned) | X | THIS | WS-A2r | **P** | architect | planned |
| **WS-X3** | Credential-exchange hardening (INV-31-1, phased — P2) — presentation-audience-bound session token so raw bearers don't persist in presentation memory | X | THIS | WS-B8 | — | security-guardian | planned (P2) |
| **WS-X4** | **Break-glass 6a minimal surface + offline first-admin/recovery** — runs `on_behalf_guard` + every ADR-0033 §1 filter. **Binds at first cutover** (core loses every ingress but presentation at B8) | X | THIS + /auth | WS-A5 | **P** | security-guardian | planned |
| **WS-X5** | **Split-topology config** (co-located-vs-split flags; run three processes + PG in dev/CI) + **continuous split observability** (cross-boundary correlation ids, per-boundary latency, three `/metrics` + trace context, audit continuity, reaper-liveness alert) + **validation harness** (parity, seam "no store ptr in a renderer", negative DB-access, SSE-across-boundary, version-skew, backout) | X | THIS | tracks all | — | quality-engineer + chaos-injector + sre | planned (continuous) |

### Hard invariants that must not regress when landing any WS

- **INV-31-1** — presentation is a credential pipe: never asserts identity, mints a grant, or decides a permission.
- **INV-31-2** — core confines inputs, the engine composes them (admit-then-filter via the shipped `authorize_list_read` chokepoint + the open #2665 deny-precedence reconciliation).
- **INV-31-3** — no cross-component DB access: engine never touches `yuzu`, core holds no grant on `uce`, presentation owns no DB.
- **INV-31-4** — no private core API: every registered route appears in the published OpenAPI; the build fails otherwise.
- **INV-31-5** — presentation's service identity attests infrastructure, not people.
- **INV-31-6** — every store a component depends on appears in that component's readiness probe.
- On-behalf-of rejected on every ingress (the four health-probe paths excepted); isolation enforced as-if-remote from day one; no UI-only capability; the ADR-0032 interlock standing merge-gate; **a component is extractable only when its safe-to-extract gate is fully green at the first cutover.**

---

## Phased build order

- **Phase 0 — Reconcile & arm the merge-gate:** WS-0 + stand up the standing ADR-0032 interlock merge-gate.
- **Phase A — Seam & authority (monolith; parallel where the graph allows):** WS-A1 → WS-A2r, WS-A3
  (per-family), **WS-A4** (the net-new heart), WS-B1 (Drogon canary, parallel), WS-B11 (DB decomposition —
  can start early), WS-X2, WS-X5 (continuous from here). WS-A2a + WS-A6 (the interlock substrate) proceed
  **under the merge-gate**; WS-A5's #2665 residual is tracked. Nothing is extracted yet.
- **Phase B — Extract presentation:** WS-B2 (cutover plane) + WS-B3 + WS-B4 + WS-B6 + WS-B7 + WS-X1 +
  WS-X4 + WS-B11(presentation half) → **first live cutover behind the gate** → WS-B8 progressive cutover
  + httplib retirement → WS-B10 supervision, WS-X3.
- **Phase C — Extract engine:** **WS-B9** behind the engine gate (needs WS-B8 done + interlock (a)–(d)+(h)
  closed + #2665 resolved) → WS-B11(engine half) → finalize supervision/readyz.

**Highest-leverage first slices after WS-0:** **WS-A4's remaining work** — its GLOBAL INV-31-4 drift test
already shipped (#842/#3991/#3992; do NOT rebuild it — see the current-state bullet), so what's left is the
*per-family* seam+contract enforcement, the handler→API seam refactor, and the PII-audit relocation — plus
**WS-B1** (Drogon canary — gates presentation extraction, fully parallel); **WS-B11** (DB decomposition) is
a third independent early start. None waits on an external
programme now that WS-A3 is THIS-owned per-family.

## Relationship to HA (the split *consumes* HA, does not gate it)

The presentation/core split is **not** a prerequisite for active-active — HA §1c is decoupled,
**ratified by the ADR-1005 owner (Dave Rae), 2026-09-07**. The one in-process blocker HA cared about —
the agent `Subscribe` stream — is solved by gateway-fronting (HA WS-4), not the split. But the split has **one-way dependencies** on HA deliverables and inherits them
rather than rebuilding:

- **Sessions** (WS-B3a) inherit HA WS-1 (**done** — durable `SessionStore`, DB-clock authority).
- **Event spine** (WS-B4) rides HA WS-2a's durable `event_outbox` (**2a-1 done**; 2a-2 NOTIFY + cursor-poll
  outstanding) — never a second transport.
- **MCP replay durability** (WS-B3b) is HA WS-2b (outstanding) — ADR-2002 §4/§5 supersedes exec-plan
  D15d's non-durable stance.

The split's own contribution *helps* HA operability (tier-split `/readyz`, WS-B7) but never discharges
HA's replica gates. Kimi's original dissent (that the split is a hard safety prerequisite) is kept
recorded-with-rebuttal in `docs/ha-delivery-matrix.md`, not erased.

## Per-WS workflow

Landing a WS slice mirrors the standard Yuzu flow: read the routed doc first → smallest coherent patch
in the owning module → its tests → `/test` → `/governance <range>` with the reviewers named in the row.
A WS is done only when its safe-to-extract clause (if any) has a passing WS-X5 validation-harness scenario.
