# WS-0 — Split interlock certification (2026-09-08)

**Workstream:** WS-0 (Reconciliation & interlock certification) — the predecessor of every
presentation/core/engine split workstream. See `docs/presentation-core-split-delivery-matrix.md`.

**What this document is.** The human narrative half of WS-0's certification. It records, per
ADR-0032 sequencing-interlock item (a)–(n), the tree-verified status **with the exact grep that
proves it**, so the certification is re-runnable rather than asserted. The machine-readable half is
`tests/split_interlock_ledger.json`, enforced in CI by `tests/test_split_interlock_tripwire.py`
(wired into `.github/workflows/docs-lint.yml`). On any disagreement the **ledger + tree win over
this prose** — re-run the greps.

**Verified against** `origin/dev` @ `d2e89ffaade703ed0da31ee4cee0962438d7cc0a`. Every command below
was run against that ref (`git fetch origin dev` first). Re-stamp this line when re-certified.

> ⚠️ Current-state is grepped, never copied from an ADR status column. ADR-0032's own interlock
> table carries **stale** cells — (b), (a) and (m) — corrected here and, for the markdown itself,
> under #4124. This document is the authority (the matrix's own rule,
> `docs/presentation-core-split-delivery-matrix.md`); the ADR table is a lagging copy.

---

## 1. The merge-gate, and why it is now a test and not a sentence

ADR-0032's rule: **no ballot-A5 (engine-path) code merges into any binary until the unconditional
interlock set (a)–(d)+(h) has landed.** The falsifier the ADR names is *"a merged PR that admits
runs, mints grants or serves results"* before the substrate exists. A routed-concern row alone
cannot enforce that: governance runs from the **author's working tree**, so a branch predating the
routed table silently runs the old pipeline (CLAUDE.md, "Context discipline"), and Step 0's currency
check *reports*, it does not block. So WS-0 arms **two layers**:

1. **A hard CI tripwire** — `tests/test_split_interlock_tripwire.py`, run on the merge ref on every
   PR via `docs-lint.yml` (the same job as `test_issue_docs.py`, which binds on docs-only PRs the
   heavy platform jobs skip). It reads the ledger and fails if **any engine-path marker** appears in
   the code tree while **any of (a)–(d)+(h) is not green**, and fails if a cell is marked green while
   its substrate marker is **absent** (the false-certification guard).
2. **A routed-concern row** (`.claude/routed-concerns-access-control.md`) — the *semantic* layer:
   it routes any diff touching the interlock symbols **or the NVD-strangler paths**
   (`nvd_*` / `vuln_finding_store.*` / new `engine_principal_store` callers composing released facts)
   to `security-guardian` + `architect` with a BLOCKED-on-interlock verdict. It names ADR-0032's Rule
   as the policy-floor source, and it carries the **path trigger the symbol grep cannot**: `nvd_*`
   and `vuln_finding_store` already exist (server-side NVD sync), so a PR re-homing them behind an
   engine principal is an engine-path ballot with **zero** new interlock symbols — caught by human
   review, not by the grep.

**The two marker classes (why the tripwire does not deadlock the interlock).** Three interlock
substrate symbols — `use_case_run_id` (the D12 audit column, cell c), the release-log store (cell d)
and `evaluate_as_operator` (cell b's seam) — are the very things WS-A6/#2675 must **land** to turn
the gate green. Blocking their first occurrence would deadlock the interlock against itself. So they
are **substrate markers**: their appearance *flips a ledger cell*, routed to reviewers under normal
derivation, never blocked. Only **engine-path markers** — the run-row store, the invocation/
result-scoped grants, the finalisation receipt, the reaper metric family — block, and only while the
gate is red. `plan_hash` is **excluded**: its 45 code hits are the pre-existing dispatch-tag grammar
(`compute_plan_hash`), not the ADR-0032 Execution-Plan hash.

Today the gate is **CLOSED** — cells (b), (c), (d), (h) are red — and the tripwire confirms no
engine-path marker has breached it.

---

## 2. The interlock ledger (a)–(n)

Command shape for a substrate symbol: `git grep -n '<sym>' origin/dev -- server/ agents/ common/
proto/ sdk/ tests/` (code) vs `git grep -n '<sym>' origin/dev` (whole-tree).

| # | Prerequisite | Status | Tree evidence (re-runnable) |
|---|---|---|---|
| **(a)** | Phase-4 engine principals | **GREEN** (ADR-0032 cell STALE) | RBAC-only enforcement ships: `auth_routes.cpp` `require_permission` engine branch (`principal_kind == "engine"`, ~L667–705) — no legacy/service fallback, 503 on store-unavailable, 403 on RBAC-off/no-grant; twin in `require_scoped_permission`. `git grep -n 'engine_principal_store' origin/dev -- server/` → wired ×N. |
| **(b)** | admit-then-filter gate **+ deny-precedence + evaluate-as-operator seam** | **RED — two open halves** | Chokepoint SHIPPED + pinned: `authorize_list_read` `git grep -c … -- server/` → **66** (128 server+tests, 263 whole-tree), decl `rbac_store.hpp:340`; transport twin `require_list_read` `auth_routes.hpp:198`; pinned `tests/unit/server/test_list_read_confinement.cpp` `[1715]`. **#1715 landed ADDITIVE** → deny-precedence is **#2665 (OPEN)**. `evaluate_as_operator` = **0-in-code** → seam is **#2675 (OPEN)**. |
| **(c)** | D12 audit schema, indexed `use_case_run_id` | **RED** | `use_case_run_id` = **0-in-code** (20 whole-tree, docs/skills only). `AuditEvent` has a single `principal` field. |
| **(d)** | P7 release-log schema | **RED** | `release_log`/`ReleaseLog` = **0-in-code** (one forward-reference *comment* at `authz_model.hpp:206`, §4 below). Born-on-PG store, ADR-0012. |
| **(e)** | G1 cross-process event transport | RED (gates Decision 9 only) | Buses process-local (`execution_event_bus.hpp`). Rides HA WS-2a `event_outbox`. |
| **(f)** | per-action mutability in the plugin ABI | RED (gates fact-dispatch only) | `plugin.h` carries action **names** only; ABI v3→v4 across 49 plugins. |
| **(g)** | derived-state confinement | RED | Nothing exists. |
| **(h)** | runtime capability-declaration registry **+ credential columns** | **RED** | Securables are a compile-time `std::array<std::string_view, 27>` at `rbac_store.cpp:559`; the only INSERT is `seed_defaults()` (`:588`). No `create_securable`/`add_securable`/`register_securable` route. Admitting/requesting-credential columns absent. |
| **(i)** | execution semantics: outcome correlation + coverage envelope | RED | Coverage fields 0-in-code; `workflow_engine.cpp` marks a step successful on dispatch, uncorrelated. |
| **(j)** | capability projection (generated OpenAPI + `tools/list`) | RED | `tools/list` iterates a compile-time array; OpenAPI a hand-typed literal. INV-31-4 test cannot exist until this lands. |
| **(k)** | operational readiness (new stores in readyz + reaper liveness) | RED | Six new stores, none in `/readyz`; reaper has no liveness metric. |
| **(l)** | intra-module cross-run isolation | RED | Nothing exists; the first module (vuln-mgmt) serves many operators from one deployment. |
| **(m)** | per-principal quota caps | **GREEN** (ADR-0032 cell STALE) | `PrincipalQuota` (`principal_quota.{hpp,cpp}`, `max_concurrency=16`, `rate_per_second=20`) SHIPPED (PR 4.4, **#1973 CLOSED**), wired into `agent_service_impl.cpp` / `mcp_server.cpp` / `mcp_stream.cpp`. |
| **(n)** | credential predecessor/successor relation + terminal-reason classification | RED | Unbuilt; 2b must be amended. |

**Unconditional merge-gate set (a)–(d)+(h): a=green, m=green (informational), b/c/d/h=RED → gate
CLOSED.** No engine-path code may merge.

---

## 3. §1c ratification (split ⇎ HA decoupling) — CONFIRMED landed

PR **#4125** ("docs(split): §1c ratified — split↔HA decoupled") is **MERGED** (2026-09-08 06:53 UTC,
merge `4c3cc7d10`) and live on `origin/dev` HEAD. The ADR-1005 owner **Dave Rae** is cited at
`docs/ha-delivery-matrix.md:41,93`, `.claude/skills/ha/SKILL.md:82,199,243`,
`docs/presentation-core-split-delivery-matrix.md:121,177–178`, `.claude/skills/split/SKILL.md:97–98`.
The `/auth-and-authz` skill carries **no** §1c/split content and is therefore **not** a citation site
(correcting the earlier draft DoD, which listed it).

---

## 4. #2665 bottomed out, and the residual findings for #4124 / WS-A6

**Interlock (b) has two open halves, and neither is WS-0's to resolve — only to name:**
- **#2665 (OPEN, `decision`)** — the shipped `authorize_list_read` is *additive* (a global deny does
  not override a management-group allow); interlock (b) requires **deny-precedence**. This is the
  single engine-gate open **question** and is a human decision, not an implementation WS-0 can land.
- **#2675 (OPEN, `ready-for-agent`)** — the server-internal `evaluate_as_operator` seam (filter (4)
  evaluated as the admitting operator while the engine is the authenticated caller). Absent in code.

**Stale ADR-0032 cells for #4124** (markdown correction is #4124's scope, not WS-0's — appended here
as verified input): cell **(a)** says Phase-4 "is not [shipped]" (stale — RBAC-only enforcement
ships); cell **(m)** says "none is enforced" (stale — `PrincipalQuota` ships, #1973 CLOSED). Both are
outside #4124's original (b)-only scope; recommend appending them to #4124 rather than widening WS-0.

**Forward reference to unbuilt substrate (governance rule 3 — a truth finding WS-A6 owns):**
`server/core/src/authz_model.hpp:205–206` comments that `data_class`/`audit_verb` are *"emitted with
the release-log write"* — a write that does not exist ((d) is 0-in-code). Not a defect to fix in
WS-0 (the comment describes the intended (d) behaviour); recorded so WS-A6 reconciles the comment
when it lands the release-log write.

---

## 5. In-flight engine-path ballot sweep — CLEAN

No open PR and no remote branch/worktree is an engine-path ballot. All 6 open PRs (#4154, #4150,
#4149, #4145, #4144, #3382) are agent-plugin / docs / read-twin / route-move / CI changes; per-diff
marker grep matched only **#4149**, and solely on *relocated* `nvd_`/`vuln_finding_store` health-probe
reads (a move, no engine principal, no admission/grant/release-log) — flagged for awareness, not a
breach. The `feat/auth-engine-principals-4.*` branches are the engine **principal** auth actor class
(interlock prerequisite (a), all merged), **not** the ADR-0032 admission path. Certified: no
in-flight engine-path ballot threatens the merge-gate as of this ref.

---

## 6. Definition of done (WS-0)

- [x] Interlock ledger (a)–(n) certified against the tree with per-cell grep provenance (§2); machine
  half `tests/split_interlock_ledger.json`.
- [x] Merge-gate armed: two marker classes + CI tripwire (`test_split_interlock_tripwire.py` in
  `docs-lint.yml`) + routed-concern row with symbol **and** NVD-path triggers; `plan_hash` excluded.
- [x] §1c ratification confirmed landed (#4125), three matrices cite Dave Rae (§3).
- [x] #2665 named the single engine-gate open question; #2675 named the seam; both OPEN (§4).
- [x] In-flight engine-path ballot sweep clean (§5).
- [ ] (a)/(m) staleness + `authz_model.hpp:206` forward-reference appended to #4124 (external action —
  pending operator go-ahead to comment).
- [x] Matrix WS-0 row flipped planned→done + Verified line re-stamped in this PR.
