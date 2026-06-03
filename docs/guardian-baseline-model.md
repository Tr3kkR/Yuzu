# Guardian Baseline & Guard Model — Design

> **Status: DIRECTION RESOLVED (2026-06-03). MVP — deliberately under-specified in
> places (flagged below); do not over-build.** Glossary terms are in the root
> `CONTEXT.md` (Guard, Baseline, Assignment, Prerequisites, Mode, Deploy).
>
> **Resolved this round:**
> - **Guards are NOT deployable; *Baselines* are.** The collection is the deployable
>   unit — the same shape as a GPO, an Intune baseline, and a Jamf Configuration
>   Profile. (We explored "Guards deploy, the collection is just a lens"; rejected —
>   see *Alternatives*.)
> - **Keep per-Guard *Prerequisites*** — a deliberate choice to go *finer-grained
>   than GPO/Intune/Jamf*, which all gate applicability at the collection level.
> - Otherwise **follow the Jamf/Intune model.**
> - The collection is named **Baseline** — *not* "Policy" (collides with Yuzu's
>   existing `PolicyStore`/`PolicyEvaluator`/compliance subsystem), *not* "Benchmark".

## Context

How Guards compose into a deployable unit, how that unit targets devices, and what
"deploy" means. Resolved by a design grill (2026-06-02 → 06-03) that untangled
scope vs management-groups vs criteria, and validated the shape against GPO, Intune,
and Jamf.

## Current state (shipped on `feat/guardian-mvp`)

- **New Guard** authoring is a schema-driven modal (registry + file guards, single
  **Mode = Watch/Enforce**, resilience gated to Enforce). Guards create + persist
  for real via `/api/v1/guaranteed-state/rules`.
- **New Baseline** is a modal shell (member-guards typeahead), but **create is a
  mock** — there is no Baseline backend yet. This design unblocks building it.
- "Watch" replaced "Audit" in the **dashboard UI**; the stored/API `enforcement_mode`
  value is still `"audit"` (a wire-rename is a separate, deferred task).

## The model

**Entities**
- **Guard** — one rule (Spark → Assertion → optional remediation). Global attributes:
  `enabled`, `mode` (Watch/Enforce), optional **Prerequisites**. A building block;
  **never deployed alone**. *Different posture ⇒ a different Guard.*
- **Baseline** — a named collection of Guards + an **assignment**. **The only
  deployable unit.**
- **Assignment** — *included* − *excluded* management groups; **exclude wins**;
  whole-Baseline granularity.
- **Prerequisites** — a per-Guard **Scope expression** over device facts (OS version,
  form factor, installed software…). Global to the Guard. *Kept even though it is
  finer than GPO/Intune/Jamf* — it composes (AND) with the Baseline's group scope.
- **Mode** — **Watch** (observe + alert) / **Enforce** (remediate). Replaces "audit".
- **Deploy** — **per-device reconciliation**: converge each assigned device to its
  *complete* desired guard set (the per-device union of all deployed Baselines'
  enabled members it's assigned, each prereq-gated). **Not** a per-Baseline push.

**Effective rule** — Guard **G** is active on device **D**, in **G**'s mode, **iff**
`G.enabled` **AND** ∃ a *deployed* Baseline **B** with `G ∈ B.members`
**AND** `D ∈ B.included` **AND** `D ∉ B.excluded` **AND** `D` satisfies
`G.Prerequisites`. Reached by multiple Baselines → armed **once** (its own mode).

**Industry mapping (this model is GPO/Intune/Jamf-shaped):**

| Guardian | GPO | Intune | Jamf |
|---|---|---|---|
| **Baseline** (deployable) | GPO | policy / baseline | Configuration Profile |
| **Guard** (building block) | setting | setting | payload |
| **Assignment** (incl/excl groups) | link + security filtering | assign incl/excl groups | Scope: Targets − Exclusions |
| dynamic management group | — | dynamic group | **Smart Group** (criteria) |
| **Prerequisites** (per-Guard) | WMI filter (*per-GPO*) | Requirements (*per-policy*) | Smart Group criteria (*per-group*) |

> Note the last row: GPO/Intune/Jamf gate applicability at the **collection/group**
> level. Guardian's **per-Guard** Prerequisites is **finer than all three** — a
> deliberate choice. A Yuzu **dynamic management group == a Jamf Smart Group**
> (criteria-defined, auto-refreshing); reuse it for criteria-based populations.

## Decisions that hold (from the grill)

1. **Terminology.** Platform `Scope` unchanged (the `yuzu::scope` AND/OR/NOT
   expression). Baselines target **management groups**. **Prerequisites** = a
   Guard-level Scope expression (one engine, extended to inventory facts; do not
   fork). "Policy" deliberately avoided (collides with the existing Yuzu Policy
   subsystem); collection is the **Baseline**.
2. **Global Guard attributes** — `enabled` + `mode` live on the Guard; *different
   posture ⇒ different Guard*. The per-Guard Enable/Disable + Watch↔Enforce toggles
   edit the Guard fleet-wide.
3. **Baseline = only deployable unit**; Deploy = **per-device reconciliation**
   (converge to the device's total policy, Puppet/DSC/GPO-style — removing a Guard
   from a Baseline and re-deploying actually removes it where no other deployed
   Baseline still delivers it).
4. **Assignment** = include/exclude management groups, **exclude wins**,
   whole-Baseline grain (Jamf/Intune model).
5. **Prerequisites** = per-Guard global applicability gate — **KEPT** (finer than
   industry); the leak-proof lever for "this Guard must/must-not run on a device
   class," independent of Baseline membership.
6. **Prerequisites evaluation** — **live/agent-side is the target**; server
   last-known is an acceptable stopgap **if UI-flagged** as "from last-known
   inventory."

## MVP — deliberately deferred (do not block on these)

- **Precedence / conflict model** (Q-B): two enabled Guards writing *opposite* values
  to the same target on the same device. Every platform handles this with precedence
  (GPO "winning GPO"; Intune most-restrictive / conflict-flag). **MVP:** authoring
  discipline now; detect-and-warn at deploy later.
- **Population vs content change** (Q-A): does a device that *newly matches* a
  deployed Baseline's assignment auto-converge, or wait for manual re-deploy? **Lean:**
  population changes auto-converge (using the *deployed* snapshot); content edits stay
  manual (Baseline shows "drifted from deployed" — i.e. draft ≠ deployed snapshot).
- **Prerequisites authoring + live evaluation** — engine-dependent: needs the scope
  engine as a **shared (server+agent) library** + a **local device-fact/inventory
  store** the agent evaluates against (the engine is server-only today). **MVP:** ship
  Baselines with the `prerequisites` field reserved/unused, or a server-side
  last-known stopgap.

## Build sequence

**Buildable now (no engine dependency):**
- **Baseline store** — members (M:N to Guards), assignment (included/excluded
  management-group ids), draft + last-deployed snapshot, lifecycle.
- **Management-group picker UI** — Management Groups already exist
  (`server/core/src/management_group_store.{hpp,cpp}`; dynamic groups = Smart Groups).
- **Per-device reconciliation deploy** — the server computes each affected device's
  union desired set across deployed Baselines and full-syncs it. *Extend, don't reuse
  as-is,* the current `guardian_push_*` fan-out ("all enabled rules → scope"), which
  is neither Baseline- nor device-aware.
- **Manual re-deploy + "drifted from deployed";** auto-converge on population change.
- **Flip the per-Guard list toggles to state-only** — remove the auto-push that
  `apply_guard_change` does today (Guards are not individually deployable).
- **Reserve a `prerequisites` column** on the Guard (stored; authoring/eval later).
- **Promote the Baseline create modal from mock → real** (modal + member typeahead
  already shipped; just needs the store + assignment picker behind it).

**Engine-dependent (later):** Prerequisites authoring (AND/OR/NOT builder) + live
agent-side evaluation.

## Alternatives considered (rejected)

- **B / B+ — Guards deploy individually; Baseline = pure insights (B) or insights +
  bulk-management handle (B+).** *Rejected:* GPO, Intune, and Jamf **all** make the
  **collection** the deployable unit. The overlap/precedence complexity that B/B+
  dodges is *inherent* to policy-based fleet management and is *handled* (not avoided)
  by every major platform via precedence — so it is essential, not a design smell.
  B+'s nice ergonomic (act on a whole set at once) can still be added later as **UI
  sugar over Baselines** without making the Baseline a non-deployable lens.

## Related

- `CONTEXT.md` — glossary (Guard, Baseline, Assignment, Prerequisites, Mode, Deploy).
- `docs/guardian-mvp-contract.md` — frozen MVP contract (uses "Baseline"; §6/§7
  deferred the collection/deploy backend this design fills in).
- Single-scope-engine direction: reuse one engine, don't fork.
- When Q-A / Q-B / the precedence model are decided, capture an **ADR** under
  `docs/adr/` for the targeting & precedence model (hard to reverse; surprising
  without context; a real trade-off).
