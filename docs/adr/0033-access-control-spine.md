---
status: proposed
date: 2026-07-14
owner: "@dgr (Dave Rae)"
deciders: pending — acceptance requires the access-control ballot (A1–A5, D1–D12) and at least one recorded independent review (SOC 2 Workstream F change-management evidence)
scope: platform — capability declarations, RBAC unit, token attenuation, approvals, execution authorisation, audit posture
depends-on: >-
  1005-headless-platform-use-case-engines (every capability is reachable by an external principal;
  this ADR is what "RBAC + audit enforced at the API" concretely means once capabilities can be
  declared by a Module rather than compiled into core).
  0017-management-group-confinement-list-reads (scope confinement is one of the four narrowing
  filters below; this ADR does not restate it).
related: >-
  0031-presentation-core-engine-decomposition (the process boundary that makes "enforced once, in
  core" structural rather than reviewed — topology, TCB and the credential-pipe invariant live
  there, not here).
  0032-use-case-admission-protocol (the run/grant lifecycle, the release log, manifest ratification
  and version-locking, and the declared-mutability rules that classify a dispatch as fact or
  effect — this ADR consumes those and never restates them).
  `docs/auth-engine-principals-design.md` (2b — engine principals, delegation artifacts),
  `docs/auth-architecture.md` (roles, securables, operations, MFA step-up, JIT elevation),
  `docs/mcp-server.md` (the tier-before-RBAC ordering this ADR extends to declared tools).
---

# ADR-0033 — The access-control spine

## Binding status

Nothing here binds reviews or blocks PRs until this ADR's status is **accepted**. On acceptance the
Decisions bind **prospectively** — including §4's prohibition on new approval gates outside the core
primitive, which is a rule about the *next* gate, not a demand that the four existing ones be
rewritten (they migrate opportunistically, §4).

Tag families used throughout (ballot **A**/**D** rows, **P** pins, **G** open questions, **S**
adversarial-review findings) are indexed in **ADR-0031**.

## Context

RBAC, attribution, approvals and audit are usually treated as four features. They are not. They are
one **ordered pipeline** that every request transits at core's API:

```
authenticate → attribute → authorize (RBAC ∩ scope) → approval gate → audit → execute
```

All of it exists today — but fused into one binary, so every subsystem that needed a stage grew its
own partial copy of it. There are already **four hand-built approval gates** (instruction approval
workflows, the agent enrollment queue, Guardian's dangerous-enforce gate, deploy's operator gate),
two independent re-authorisation idioms, and a hand-maintained list of MFA step-up surfaces. Each
was a reasonable local decision. Together they are a spine that was never named, and therefore never
enforced in one place.

Two things now make naming it urgent.

**Capabilities stop being compiled in.** Under ADR-1005 a use-case Module registers its tools with
core's capability registry at activation. A tool that arrives as *data* cannot be covered by a
permission model that only knows about securables someone typed into C++ last release. Unclassified
means unenforced, and "unclassified" is a hole shaped exactly like an engine.

**The actors we trust least authenticate with the credentials we attenuate least.** An API token
inherits its owner's entire role. An agentic worker doing read-only CVE triage today carries its
owner's patch-dispatch authority. That is the opposite of least privilege for precisely the class of
operator this platform exists to serve.

This ADR is **platform-wide, not UCE-specific**. Every rule below binds the dashboard, REST, MCP,
built-in capabilities and Module-declared capabilities alike. Where a rule needs the run/grant
machinery, it cites ADR-0032; where it needs the process boundary, it cites ADR-0031.

## Decision

### 1. The narrowing law: core is the only layer that may create authority

Every other layer — a credential, a Module, an approval — may only *reduce* it.

```
effective authority = operator grants ∩ attenuated credential grants ∩ Module envelope ∩ execution authorisation
```

A requested action (tool + parameters + scope) passes through four filters, and **core denies the
action if any filter does not allow it**:

| Filter | Asks |
|---|---|
| **Operator** — RBAC + management scope | Can this principal perform this operation here? |
| **Credential** — explicit attenuated grants (§3) | Was this token deliberately minted for this power? |
| **Module** — declared maximum envelope (§2) | Was this capability reviewed for this Module version? |
| **Execution authorisation** — exact plan or bounded envelope (§4–§8) | When risk requires it, did a qualified supervisor approve? |

The **Module envelope** is not the manifest. It is **core's ratified copy** of the module's
declarations, taken at manifest approval and version-locked at admission — the same object ADR-0032
Decision 13 names "core's ratified mapping". One object, and it is core's, or the filter is
self-certified by the thing it filters.

The same law, stated from the identity axis (it is one law, not two):

```
effective authority = IdP-mapped Yuzu grants ∩ current owner grants ∩ token grant subset ∩ Yuzu scope
```

An upstream OIDC group or OAuth scope may **narrow or select** a local mapping. It never directly
means "may perform operation X on these devices" until core resolves it against Yuzu's own
authorization store. The IdP answers *who*; Yuzu answers *may they*.

Filters are **intersections, and intersection is fail-closed**: an unresolvable, missing or
unparseable filter input denies. No filter may be skipped because another one passed.

### 2. The capability declaration is the RBAC unit (D1-C · G3 · G9)

Each registered tool or capability declares, at registration, a triple plus a tier:

- **`securable`** — reusing an existing securable wherever one accurately describes the protected
  resource; a Module mints a new securable only when nothing fits.
- **`operation`** — one of the existing six (Read / Write / Execute / Delete / Approve / Push).
- **`risk_tier`** — the routing input D5's future policy layer consumes, captured from day one.
- **`mcp_tier_class`** (read / write / execute) — so the shipped **tier-before-RBAC** ordering
  (`docs/mcp-server.md`) evaluates built-in and declared tools through **one chokepoint**. A new
  gate for declared tools is prohibited: extend the existing chokepoint, never parallel it.

Role administration therefore stays at securable granularity — the role UX does not become a wall of
per-tool checkboxes — while individual tools still carry an operation and a risk tier. The goal is
that **a new engine's permissions are data, not C++**.

**They are not, today, and that gap is this section's precondition.** Securable types are a
hard-coded C++ array seeded `is_system` into the RBAC store (`rbac_store.cpp:217-236`, 20 entries);
`RbacStore` offers `list_securable_types()` and **no runtime create path**. So §2's own escape hatch
— "a Module mints a new securable only when nothing fits" — is a C++ edit, a recompile and a
release. **Building the runtime capability-declaration registry is core work, it is the precondition
for every rule in this section, and it lands on a store ADR-0006 also requires be migrated to
Postgres.** Until it exists, an engine ships with a core release.

**The declaration is the security boundary, so the declaration is vetted (G3):**

- **Namespace-bound.** `engine:vuln` may declare against `Vulnerability:*` and nothing else. A
  declaration outside the principal's namespace is rejected at registration, not audited after.
- **Approved, then diffed.** First registration and *every later change* park as a pending capability
  manifest for admin approval — the enrollment-queue pattern, reused. The diff is what an approver
  reads. A **permission expansion is a visible security change; it cannot arrive as an incidental
  Module upgrade.**
- **Undeclared fails closed.** A missing or unparseable `mcp_tier_class` makes the tool **invisible to
  MCP** and uninvocable — never "defaults to read". The same for a missing securable or operation.

How core's approved copy of the mapping becomes the *binding runtime input* — version-locked at
admission, with the Module's manifest reduced to a request — is ADR-0032 (S4); how a capability's
mutability is attested is ADR-0032 (P5/P9). This ADR fixes **what is declared and who vets it**.

### 3. Tokens carry their own, narrower grants (D2 · G8 · S9)

A token may be minted with a **subset** of its owner's authority:

```
effective = (token roles ∩ owner roles)  within  (token scope ∩ owner scope)
```

- The scope cap is expressed **in the existing scope language** — the single-scope-engine rule holds;
  no new dialect. "Read-only vuln triage, canary ring only" must be expressible at mint time.
- Narrowing only: the owner's **current** grants are one side of every intersection, so a token does
  not outlive a demotion. **This is enforced by code, not by construction** — the formula's *shape*
  guarantees nothing on its own. It is real only once M5.3's contract test exists, and only if
  **every** authority-shrinking path invalidates `RbacStore`'s permission cache (`perm_cache_`,
  keyed `user:type:op`, bumped on permission and role mutation) — **including scope and
  management-group changes**, not just role changes. A cache that misses one of those paths is a
  token that *does* outlive its demotion. (Saying "impossible by construction" here would contradict
  the migration rule below, which is written on the premise that the intersection is decorative
  storage until a test proves otherwise.)
- Same intersection machinery as delegation (2b) and as the invocation grant (ADR-0032). One
  narrowing model everywhere, not three.

**Migration rule (M5 — the enforcement contract, not just the schema):**

1. Existing owner-inherited tokens are migrated with an **explicit** `attenuation = owner_inherited`
   marker written at migration time. Legacy behaviour becomes a *declared* state; it is never an
   absence. No live token changes authority on migration day.
2. After migration the column is `NOT NULL`: a token whose attenuation record is **missing,
   unreadable or unparseable is denied** — absence is never read as owner-inheritance, and never as
   a grant. The bounded mixed-row window is closed by the constraint, not by convention.
3. **Contract test, not a comment:** an attenuated token is *denied* an operation its owner is
   *allowed*. Without that test the intersection is decorative storage.

Per-task sub-principals (a managed identity per worker run) remain a plausible later layer **on top
of** attenuation, not an alternative to it.

### 4. One core-owned approval primitive (D4)

A capability declaration may carry `requires_approval`. When it does, invocation **parks** as a
durable pending-approval object in core rather than executing:

- Approving requires the **`Approve` operation on that securable**, an **MFA step-up**, and
  **requester ≠ approver** — meaning distinct **human roots** (§7), never merely distinct
  principals.
- Execution audits **both** principals — requester and approver.
- Over MCP the call returns a **pending** state and resolution rides the **existing** SSE/progress
  spine the executions ladder already uses (`docs/executions-history-ladder.md`). No parallel
  notification path is created for approvals. **Once presentation is a separate binary, that spine
  needs a cross-process transport it does not have today (G1) — a prerequisite, per ADR-0032
  Decision 9, not an assumption.**
- **Pending-approval hygiene:** approvals expire (7 days), and an approved-but-stale request
  **re-resolves its scope at execution** (§8) — approving yesterday does not authorize against
  today's larger cohort.

The four existing gates migrate **opportunistically**, not big-bang. The binding rule is
directional: **no new approval gate may be built outside this primitive.** Guardian's
`dangerous_enforce_in_spec` is the standing precedent for how this goes right — one chokepoint,
extended, never parallelled.

### 5. Approvals are manual in v1 (D5)

Policy auto-approval ("auto-approve if risk tier is low *and* blast radius < N devices *and* the
requester is a human with a standing role; park everything else") is clearly where this ends up. It
does not ship in v1 — but the **risk tiers it consumes are captured from day one** (§2), so the
policy layer arrives with real inputs rather than a speculative rule language.

**One explicit trigger is recorded now:** when approval volume produces rubber-stamping, that is the
signal to build the policy layer. *Approval fatigue is worse than no gate at all* — an approver
trained to click yes without reading is a control that reports success while providing none.

### 6. Approvers are humans in v1 (D8)

v1 approvals are **humans-only outright**. The schema stays policy-actor-ready — it can *represent* a
non-human approver — but **enabling** one requires a later ADR plus explicit administration. A safer
initial posture without a data-model dead end.

### 7. Four-eyes compares human roots, and a run's requester root is the admitting operator (D9 · P11)

Requester and approver must resolve to **distinct human roots**. Distinct *principals* alone never
satisfies four-eyes:

| Principal | Resolves to |
|---|---|
| API token | its owner |
| engine principal | its named human owner |
| delegated call | the delegating operator |
| **any run-scoped effect** | **the admitting operator (P11)** |
| **a scheduled or background run** | **the human who armed the schedule** — recorded at arming time, re-checked at execution (§8) |

Alice's worker can never approve Alice's other worker.

**A scheduled run has no interactive operator, and that is exactly where a root goes missing.**
P11 says the requester root is the admitting operator — but a 03:00 cron-style run admits itself.
Its root is therefore **bound at arming time**: the human who created or last modified the schedule
is recorded on it, becomes the run's requester root, and their authority is **re-checked at every
execution** (§8), so a departed or demoted scheduler does not keep dispatching effects from beyond
the grave. A schedule whose armer can no longer perform the action **stops**; it does not fall back
to the engine's owner, and it does not run as a system principal. **There is no unrooted effect.**

**P11 closes a real bypass**, not a hypothetical one: a plan raised by `engine:vuln` (owned by Alice)
*inside Bob's run* would otherwise resolve its human root to Alice — letting **Bob approve his own
run's plan**. For any run-scoped effect the requester root is the **admitting operator**; the engine's
named owner is recorded, and is never the root. (What a run is, and who admits it: ADR-0032.)

### 8. Approval is a gate, not a grant (D10)

An approved action executes under the **requester's** authority, **re-checked at execution time**:

- Requester revoked → the approval is **void**, not merely stale.
- Requester's scope shrank → the run gets **smaller**, never grandfathered.
- Approvers need `Approve` on the securable and **never the underlying permission** — low-privilege
  reviewers stay possible, which is what makes four-eyes deployable at all.

Deploy's re-authorize-every-tick behaviour is the shipped precedent for this rule; it becomes the
platform's, rather than one feature's.

### 9. Audit-failure posture: mutations fail closed (D6)

When the audit write fails mid-request:

| Class | Posture |
|---|---|
| Mutating capability, or **any** approval-gated action | **Fail closed.** No audit row → no mutation. |
| Reads | Keep the surface's existing posture (`server/core/src/rest_audit.hpp`): REST behavioural-PII fails closed with `Sec-Audit-Failed`; dashboard HTML and MCP set-and-proceed. |

An **unattributable mutation** is the one thing a fleet-control product may not produce. An
unattributable page-view during an audit-store outage is survivable, and it is flagged. Making
*everything* fail closed instead would turn the audit store into an availability single point of
failure for read traffic; making everything proceed would be disqualifying in any enterprise
security review.

The read half of this rule is tightened for engine tools returning device-attributable data — that
extension is ADR-0032 (S6), not restated here.

### 10. Effects cross core as immutable Execution Plans (D11)

A **fact** is acquired under the caller's authority. An **effect** crosses a plan boundary. (Which
dispatches are which — the declared-mutability classification and its mutating-by-default posture —
is ADR-0032.)

**Execution Plan.** An immutable, resolved plan with exact versions, parameters, targets, fact
references and a **plan hash**. Prepared by a Module or by core; **authorised and executed by core**.

- **Approval binds to the plan hash**, and to nothing looser. A material plan change invalidates the
  authorisation — it does not silently inherit it.
- Execution authorisation is **time-limited** and one-use where appropriate.
- The approving human may **approve, veto, narrow or escalate**. A supervising model may *recommend*
  those actions; it can never widen or authorise.
- An enterprise messaging service may notify a supervisor and carry a deep link. **Approval occurs
  only on the trusted Yuzu presentation surface** — never in the notification channel.
- **Reuse before invention:** a Use Case composes existing **Instructions and Workflows** wherever it
  can. Specialist Module code is reserved for domain interpretation, derived state and external data
  — a Module does not get to build a second execution engine.

**Coverage envelope — part of every distributed answer.** A distributed query cannot honestly return
only rows; it must state how much of the intended fleet answered:

| Field | Meaning |
|---|---|
| `intended` | endpoints in the authorised resolved scope |
| `contacted` | endpoints to which core attempted delivery |
| `responded` | endpoints returning a valid result before the deadline |
| `failed` | endpoints returning a terminal error |
| `timed_out` / `offline` | known non-responses, kept **distinct** from an empty or negative result |
| `completeness` | `complete` · `partial` · `insufficient` · `unknown` |
| `policy` | the declared threshold, and whether incomplete evidence blocks the next step |

**Missing evidence is never a negative finding.** "No vulnerable devices found" and "62 devices never
answered" are different sentences, and the platform must not be able to say the first when it means
the second.

**Compensating recovery — never fictional rollback.** Endpoint effects cannot be rolled back
atomically, and the product will not pretend otherwise. Each state-changing capability **declares its
reversibility class**: *naturally reversible*, *compensatable*, *retry-safe*, *verification-only* or
*irreversible*. A recovery plan that creates new effects is **separately authorised** — it is a plan,
subject to every rule in this section, and it is linked to the effects it compensates.

### 11. Module presentation contributions are declarative-only (D7)

Capability views are **generic and schema-derived first** — a Module is usable by humans on day one
with zero presentation change. A Module may contribute **reviewed, declarative** metadata, forms and
result-rendering hints. **Arbitrary executable routes or templates never load into presentation**;
bespoke views ship through the normal release process, and analytical dashboards ride the existing
Prometheus-native metrics surface rather than a Module-supplied renderer.

This is an access-control rule, not a UI preference: presentation terminates operator credentials
(ADR-0031), so a Module that could inject executable code into it would be inside the credential TCB
by the side door — an authority-widening path that no filter in §1 evaluates.

## Consequences

- **The four existing gates become migration targets, and the fifth is prohibited.** Instruction
  approval, the enrollment queue, Guardian's dangerous-enforce gate and deploy's operator gate keep
  working; new approval-shaped behaviour lands in §4's primitive. Without this rule the fifth gate
  gets built by a Module team, outside core, and it is the one that is subtly wrong.
- **Schema deliverables, all born-on-PG** (ADR-0012; queued in `docs/postgres-migration-ladder.md`):
  attenuation columns on `ApiToken`; the pending-approval object; the Execution Plan record + plan
  hash; capability-declaration tables (core's approved copy); the coverage envelope on distributed
  results. The audit-envelope columns (D12) ride the audit-store migration and are specified in
  ADR-0032.
- **Deciding attenuation now is cheaper than deciding it later.** It is a schema change on
  `ApiToken`; after the auth store's Postgres migration it is a schema change *plus* a data
  migration under load.
- **Works-council counters become possible and cheap — not free.** §2's declarations give every
  capability a place to hang its own audit verb (the shipped `device.live.*` /
  `emit_behavioral_audit` pattern), but the verb is still declared per capability and routed through
  the `rest_audit.hpp` chokepoint by hand, and the counting/reporting surface does not exist. What
  §2 actually buys is that **no capability can arrive unclassified — so none can arrive
  uncountable.**
- **Every capability declaration becomes a security-review artifact.** That is the cost of Modules
  being data: the manifest diff is now something a human must actually read, and it is the last human
  check before core's registry copy becomes binding.
- **This spine is a prerequisite, not a companion, for the split-plane code paths.** The sequencing
  interlock that says which of these must land before any ADR-0032 code path ships lives in
  ADR-0032; it is not duplicated here, so that there is exactly one place to look for it.
- **Latency and UX are unaffected in the common case.** Browsing, asking questions, exploring options
  and *producing* a plan use the operator's normal authority. A new execution authorisation is
  required only when a plan crosses a protected-effect boundary, or when risk tier, scope, novelty or
  confidence says supervision is warranted.

## Alternatives considered

- **Keep building per-feature gates** (D4-A). Fastest per feature; N approval UIs, N audit shapes, N
  four-eyes implementations of varying quality. Rejected: it is exactly how four gates already
  happened, and it fails silently — a wrong gate looks like a working one.
- **One securable per Module** (D1-A). A read-granted agentic worker could invoke everything the
  Module offers, including an expensive recorrelation. Rejected: ad-hoc per-tool checks get bolted on
  afterwards, and that is how parallel gates are born.
- **One securable per tool** (D1-B). Maximally precise; every new tool mints an RBAC row and role
  administration becomes a wall of checkboxes nobody audits. Rejected.
- **Owner-inherited tokens forever** (D2-A). "Create a dedicated low-privilege account per worker"
  works today, proliferates service accounts, and nobody actually does it. Rejected: it leaves every
  agentic worker over-privileged in practice, and the first prompt-injected worker holding patch
  authority is a headline, not a bug ticket.
- **Policy auto-approval in v1** (D5-B). Designing a rule language before knowing which rules anyone
  wants. Rejected — deferred behind §5's explicit trigger.
- **Non-human approvers designatable per securable** (the pre-synthesis D8). Rejected for v1: the
  schema stays ready, the capability does not ship without its own ADR.
- **Everything fails closed on audit failure** (D6-B) — maximal integrity; an audit-store outage
  becomes a full platform outage including browsing. **Everything proceeds with a flag** (D6-C) — a
  fleet mutation with no audit row. Both rejected; §9 splits by mutability instead.
- **Atomic fleet rollback.** Rejected as undeliverable: endpoint effects are not transactional.
  Promising it would make the recovery story a lie at exactly the moment an operator depends on it.
