---
status: proposed
date: 2026-07-14
owner: "@dgr (Dave Rae)"
scope: >-
  platform — the protocol by which a Use-Case run is admitted, authorised mid-flight, evidenced,
  finalised and reaped. Pins ballot A5's protocol semantics (P1–P10) and closes the adversarial
  review's S2/S3/S4/S6/S7/S8 findings.
depends-on: >-
  0031-presentation-core-engine-decomposition (the topology this protocol runs on: core admits and
  mints the grant; presentation calls the engine directly; the engine reaches facts and effects only
  through core). 1005-headless-platform-use-case-engines (engine principals; no UI-only
  capabilities; one public surface).
related: >-
  0033-access-control-spine (registry-declared RBAC and manifest vetting, token attenuation, the
  approval primitive, Execution Plans, the coverage envelope, four-eyes and P11 — this ADR
  cross-references them and never restates them). 0017-management-group-confinement-list-reads (the
  admit-then-filter chokepoint this protocol confines against, #1716). 0012-server-postgres-store-contract
  (every new core store named here is born on Postgres). docs/auth-engine-principals-design.md (2b —
  the delegation artifact the invocation grant IS). docs/adr-1005-execution-plan.md (Phase 4 engine
  principals; the M3 gate whose style the sequencing interlock below copies).
---

# ADR-0032 — The Use-Case admission protocol

## Binding status

Nothing here binds reviews or blocks PRs until this ADR's status is **accepted**. On acceptance,
the Decisions bind prospectively and the **sequencing interlock binds immediately** — it is a
precondition on shipping code, and a precondition can only be honoured before the code exists.

## Context

ADR-0031 fixes the *shape*: core is the admission-and-authority chokepoint, not the byte path.
Core admits the run and mints an audience-bound grant; presentation then calls the use-case engine
(UCE) directly with it; the UCE reaches facts and effects only through core. That shape buys the
audit chokepoint without making core parse, proxy and re-aggregate every domain payload.

It also leaves a protocol undefined — and an undefined admission protocol is precisely where the
audit gap lives. If "the run is authorised in core" is a sentence rather than a state machine, the
first module ships with an invocation nobody can prove was admitted, a cached result nobody
re-confined, and a disclosure record that lives in a database core cannot read.

The 13 July grill pinned six protocol semantics (P1–P6); the round-4 auth/provability review pinned
five more (P7–P11) and promoted the evidence envelope to a named deliverable (D12). A Kimi+Codex
adversarial review then returned BLOCK on the ballot with three findings, two of which are this
ADR's job:

- **S2** — A5's sequencing named Phase-4 engine principals and the ADR-0017 gate, but *not* the
  D12 audit schema or the P7 release log, which its own confinement and DSAR stories consume. An
  implementation could ship admitted runs whose disclosure cannot be proven from core-owned
  evidence.
- **S3** — P8 stated the cached-result subset rule but named no component that runs it before result
  bytes move. Scenario: Alice's scope shrinks from A+B to A; the UCE serves the cached A+B aggregate
  on run id alone.

Both are fixed by writing the protocol down normatively. That is this ADR.

**What this ADR does not own.** Registry-declared RBAC and manifest *vetting* (D1-C/G3/G9), token
attenuation (D2/G8), the approval primitive (D4/D5), four-eyes and the run-scoped requester root
(D9/P11), execution under the requester's authority (D10), Execution Plans, the coverage envelope
and compensating recovery (D11) — all **ADR-0033**. The binary decomposition, the credential-pipe
invariant (D3), the presentation TCB statement and the failure-posture table — **ADR-0031**. This
ADR cross-references those by number and never restates them.

## Terminology

- **Use-Case run** (the *run*) — one admitted episode of one use case, identified by a
  core-minted `use_case_run_id`.
- **Admission** — the core-side act of authenticating, authorising, scoping, risk-tiering and
  auditing a run *before* any UCE work begins.
- **Invocation grant** (the *grant*) — the short-lived, audience-bound artifact core mints at
  admission. It **is** the 2b delegation artifact (RFC 8693 token-exchange family), not a parallel
  mechanism.
- **Result-scoped grant** — the grant minted by a cached-result re-admission (Decision 10). It
  authorises the release of *one* stored result and nothing else.
- **Release log** — core's own record of which device data it released to which run. The primary
  disclosure evidence (Decision 11).
- **Finalisation receipt** — core's record that a run completed, with the canonical result hash,
  result schema, coverage and a link to the UCE's journal entry. **Integrity, not authority.**
- **Fast lane** — a cheaper admission path for low-risk read-only use cases and cached-result
  serves. A cheaper admission, **never a skipped one**.
- **Core's ratified mapping** — core's own copy of an activated module's declarations, taken at
  manifest approval. The binding runtime input (Decision 13). The manifest itself is a *request*.

## Decision

### 1. A run is one declared episode (P1)

One admission, one input hash, one scope ceiling, one finalisation. Multi-step work happens
*inside* the UCE, under the one run — not by re-entering core with a chain of related invocations.
Iterative agentic triage is therefore **many small runs**, which makes the cost of admitting a run
a first-class design constraint: the admit path is a **single round trip and one audit row**.

A **fast lane**, declared per use case in the manifest (and projected into the A5 annotations that
describe the capability), applies to low-risk read-only use cases: no approval routing, no plan, no
mutation path. It is a cheaper admission, not a skipped one — it still authenticates, still
authorises, still writes `use_case.run.admitted`, still mints a grant.

The admission request carries: `use_case_id@version · module_id@version · raw inputs ·
requested scope · correlation_id`. Core authenticates the stable principal, resolves RBAC and
management-group scope, applies token attenuation, evaluates the risk tier from **its own ratified
mapping** (Decision 13), and writes `use_case.run.admitted` or a denial. There is no admission that
produces no audit row.

### 2. Core computes the input hash; the UCE rejects inputs that do not match it (P1)

**Presentation sends raw inputs; core canonicalises and hashes them.** Canonicalisation living in
one place is what stops it drifting between the hasher and the verifier. Core returns the canonical
input document alongside the run id and the grant; presentation forwards that document to the UCE
**verbatim**.

The UCE **recomputes the hash over the inputs it actually received and rejects any request whose
inputs do not match the grant's `input_hash`** — the "mismatched grant" rejection, made explicit.
Without it, presentation could declare one input set to core and hand a different one to the UCE,
and the run's evidence would describe work that never happened.

### 3. The grant is the 2b delegation artifact, and it gates run START only

Core mints, on admission, a short-lived, audience-bound grant binding: the admitting **principal**;
`use_case_id@version` and `module_id@version`; the `input_hash`; the **scope ceiling** (the resolved
device scope, frozen); the **risk tier**; the **intended caller** (Decision 7); and an **expiry**.
It is server-issued and never self-authored by presentation.

Two properties are load-bearing:

- **It is the same artifact family as 2b delegation** (RFC 8693 token exchange, audience-bound,
  short-TTL, server-issued). A5 deliberately pulls a bounded slice of Phase-5 delegation forward;
  it does not invent a second credential type. Opaque-vs-signed grant *format* is deferred — the
  binding, the audience and the TTL are not.
- **It gates starting the run, nothing else.** The grant's TTL is not the run's authority. Every
  subsequent core call is authorised by Decision 4's server-side lookup, so a long-lived run does
  not need a long-lived credential, and a stolen grant expires without carrying the run with it.

The UCE rejects a grant that is missing, expired, wrong-audience, or mismatched against the request
it accompanies.

### 4. Mid-run authority = engine principal ∧ server-side run lookup (P2)

The UCE authenticates **every** core call as its own 2b engine principal — never as the operator,
never on a caller-asserted identity (ADR-1005's on-behalf-of ban is unamended by this protocol).
Core authorises each such call by looking the run up **server-side** and requiring, conjunctively:

1. the run is **live** (Decision 5's state machine);
2. the request falls inside the run's **frozen scope ceiling**;
3. the engine principal's **own grants** permit the capability;
4. the **admitting operator's CURRENT authority** still permits it — re-evaluated per call, not
   frozen at admission;
5. the module version and capability are still **live** (Decision 6).

Revoking the admitting operator, or shrinking their scope, therefore **kills the run mid-flight** —
D10's re-check-at-execution rule extended to the whole run lifetime. Filter (4) is the
`authorize_list_read` admit-then-filter chokepoint (ADR-0017, #1716) evaluated **as the admitting
operator while the engine is the authenticated caller** — the server-internal *evaluate-as-operator*
seam that gate must grow, and a named prerequisite in the interlock below.

This per-call conjunction is the run-scoped instance of the platform authority-narrowing rule in
**ADR-0033**; it narrows, and can never widen.

### 5. Core owns the run state machine and reaps on TTL (P3)

The run row is a **guarded one-way state machine** — `admitted → executing → finalised | denied |
expired | aborted` — using the deployment-store transition pattern (guarded CAS transitions, never
an unconditional grid overwrite). The run store is a core-owned store, **born on Postgres**
(ADR-0012: fail-closed construction, durability on top).

Each use case declares a TTL in its manifest; core reads that TTL from **its ratified copy**
(Decision 13), version-locked at admission. Core expires overdue runs, writes the terminal audit row
(`use_case.run.expired`), and **revokes the run's read authority at that instant** — an expired run's
next core call fails filter (1) of Decision 4.

The invariant this buys: **every admitted run reaches a terminal audit state by construction.** No
run merely stops being mentioned.

### 6. Revocation symmetry: a pulled module or capability aborts the run (P10)

The grant freezes the module version at admission, so operator revocation alone was not enough —
pulling a module version or a capability would have left in-flight runs executing against a
withdrawn contract. Decision 4's per-call check therefore also verifies **module-version and
capability liveness**; pulling either **aborts** the run (terminal `aborted`, reason
`capability_revoked`).

### 7. Only presentation calls the UCE (v1) (P6)

The UCE's invocation endpoint is internal and reachable **only** from presentation's mTLS service
identity. The grant records its **intended caller**, so a leaked grant is useless off-path. This is
defence in depth, not the primary control: the primary control is that the UCE can obtain nothing
without core (Decision 4).

Automation and agentic workers reach use cases through the **projected REST/MCP capability** on the
one public surface — never by calling the UCE. Scheduled and background runs enter through the same
internal path with the same admission. Direct-to-UCE access for any other caller requires a later
ADR; it is never a default that erodes.

### 8. Fact acquisition versus effects: mutating by default (P5 + P9)

Every dispatch the UCE requests through core is an **effect** unless read-only is attested at
**both** the vetted manifest (core's ratified copy) **and** the plugin-action metadata on the agent
side. This is the safe default, not a convenience:

- **Fact acquisition** (declared read-only/idempotent) executes under the run's frozen scope
  ceiling: no Execution Plan, no approval. The behavioural-PII audit chokepoint still applies
  **per verb** (`rest_audit.hpp`'s `emit_behavioral_audit`), so each kind of sensitive read stays
  separately countable for works-council purposes.
- **Effects** (everything else) cross core as an immutable, version-pinned **Execution Plan**, with
  plan-hash approval binding and authority re-checked at execution — **ADR-0033** owns that
  machinery.

The read-only attestation is enforced where the engine cannot reach: fact-acquisition dispatches
carry a **tagged read-only envelope** that the **agent-side plugin host** enforces — it refuses a
non-read-only action arriving under that envelope. Core **quarantines the module on mismatch**.
A single mis-declaration must not be able to both collapse RBAC granularity and skip the
plan/approval path with a human manifest diff as the only backstop.

### 9. Progress rides the one event spine; results are durable in the `uce` database (P4)

The UCE posts **run-scoped progress** to core; core fans it out subscriber-tagged on the **existing**
event spine — one bus, one taxonomy, no second stream protocol
(`docs/executions-history-ladder.md`'s standing invariant). Presentation routes by tag and makes no
event-level permission decision.

Results persist in the `uce` database keyed by `use_case_run_id`. Retrieval of a past result is a
re-admission (Decision 10), never a read of a durable object on run id. Retention rides the declared
per-module SLA (Decision 15).

**Prerequisite, named (S8/G1):** the event spine's buses are **process-local today**
(`execution_event_bus.hpp`, `server.cpp`). "On the existing spine" across a process boundary
presumes a cross-process event transport that does not exist. **G1 — the cross-process event
transport — must be designed and landed before P4 ships.** It is an open question, recorded here as
a prerequisite rather than assumed away.

### 10. Cached results: a fast-lane re-admission that runs the subset check in core and mints a result-scoped grant (P8, and the S3 fix)

An aggregate cannot be un-blended. A stored result may be served **only** if the requesting
operator's **current** authority still covers the run's **full released-input set** — a subset check
against Decision 11's release log. If scope shrank, the cached result is **denied outright** and a
re-run under today's scope is offered. Results are immutable evidence: **whole, or re-derived —
never partially re-served.**

Where that rule is enforced, normatively:

1. A cached-result read **is a fast-lane re-admission**. Presentation calls core, not the UCE.
2. **Core runs the subset check** — the requesting principal's current authority against the source
   run's released-input set, read from core's own release log.
3. On success, core mints a **result-scoped grant**: audience-bound to the intended caller,
   one-use, short-TTL, naming the **source `use_case_run_id`**, the digest of the released-input set
   it was checked against, and the requesting principal.
4. **The UCE serves cached bytes only against a result-scoped grant — never on a run id alone.**
   Enforcement lands at the UCE-checks-grant seam (the same seam as Decision 3), not on
   presentation's politeness.
5. The re-admission **mints its own `use_case_run_id`**, recording `served_from_run_id`, and
   **writes its own release-log entry** for the serve, inheriting the source run's released-input
   set. Without this, a second disclosure — to a different principal, at a different time — would
   leave no evidence anywhere core can read. (Adjudicated: the sources pin the check and the grant;
   the run id and the release-log entry are what make the second disclosure provable.)

### 11. Disclosure accountability is core's release log, not the engine's journal (P7)

The composed result lives in the UCE's journal — a database core's role **cannot read**, purged on
the engine's own SLA. So the primary disclosure record must be core's own.

**At each confined fact read, core records — per run, as it releases, never trusted from the
engine — the released `agent_id` set (compact form), the data classifications, and the verbs.**
This is the **release log**: a core-owned store, born on Postgres.

- *"Which device data went to which principal in which run"* is answerable **from core alone**.
  DSAR and works-council evidence never depend on the engine's journal.
- The finalisation disclosure summary (Decision 12) becomes **corroboration plus result
  schema/coverage** — not the evidence.
- **A failed release-log write fails the read closed.** Rows do not leave core unrecorded. (This is
  the same posture as the platform mutation rule in ADR-0033 D6, applied to disclosure: an
  unattributable release is exactly the thing the log exists to prevent.)

### 12. Finalisation joins the journals; the receipt is integrity, not authority (D12)

Before release, the UCE **finalises** the run with core, submitting a canonical result hash and a
disclosure summary. Core records completion, the result schema, the coverage envelope
(**ADR-0033** owns the envelope's fields and completeness policy) and a link to the UCE's journal
entry, then issues the **finalisation receipt**. Presentation renders only a result whose run and
receipt agree.

The receipt proves **integrity** — that the bytes rendered are the bytes finalised under this run.
It proves **no authority**: nothing may be released *because* a receipt exists. **Receipt
verification is exposed on the public API**, so any client — human, agentic, auditor — can verify a
result independently.

**Two journals, linked — not merged.** They answer different questions and live in different
databases under different roles:

| Journal | Owner | Answers |
|---|---|---|
| **Use-Case business journal** | UCE (`uce` DB) | Which use case and module version ran; which inputs and fact references were used; which deterministic decisions were made; which plan was proposed; which business outcome was reported. |
| **Core fleet journal** | core (`yuzu` DB) | Who was authenticated and authorised; which exact plan and capability versions were accepted; what was dispatched to which endpoints; which effects succeeded, failed or remain uncertain; which compensating actions ran. |

They are joined by **immutable identifiers, never by a shared transaction**:

```
run_id · plan_id · execution_id · causation_id
```

**The evidence envelope (D12) is a named schema deliverable, not a convention.** Today's
`AuditEvent` (`audit_store.hpp:16`) carries a single `principal` field alongside `principal_role`
and the `principal_class` actor-class column (landed on `dev`, c5bbbe23, Phase 3a — with `engine`
reserved until Phase 4). What it has **no** representation of is the thing an admitted run needs:
**which authority the action was taken under**, and no queryable run-id column. D12 adds:

- the **acting principal**, separated from the authority it acted under (`principal_class` already
  says *what kind* of actor it was; it does not say *whose* authority was spent);
- the **authority acted under** — the `use_case_run_id` or the delegation-artifact id;
- an **INDEXED `use_case_run_id`** column.

It lands **with the audit-store Postgres migration** — the cheap moment, and the reason the
migration must not be designed without it. "Every result, plan, approval and execution traceable
through one `use_case_run_id`" is a query, and a query needs an index.

### 13. Core's ratified copy of the manifest is the binding runtime input; a manifest is a request (S4)

A module's manifest declares what it wants: use cases, capabilities, `(securable, operation, risk
tier)` mappings, mutability classes, TTLs, schemas, retention classes, coverage/completeness
policies, licence. **On manifest approval, core copies that mapping into a core-owned table.**

- **Runtime enforcement reads core's copy, never the manifest**, and the copy is **version-locked at
  admission**: a run that started under module version *N* is enforced against core's ratified
  mapping for *N* for its whole life, even if *N+1* activates mid-run.
- **A manifest is a request, never the runtime input.** The distinction is the whole security
  property: "what the engine declared, human-reviewed" is a review artifact; "what core ratified" is
  an enforceable one.
- *Who* vets the declaration, and on what namespace/tier rules — **ADR-0033** (D1-C, G3, G9).

Module packaging and activation, adopted from the counter-proposal:

| Package element | Contents |
|---|---|
| Signed module package | immutable version · publisher identity · manifest hash · compatibility range · entitlement |
| Module manifest | use cases · capabilities · risk tiers · mutability classes · schemas · retention · licence — **permission expansion is reviewable data** |
| UCE contribution | domain logic · UCE migrations · derived state · optional worker (absent for a declarative-only module) |
| Presentation contribution | declarative views · forms · result renderers — the same use case on dashboard, REST and MCP; **no private UI-only capability** |
| Core Product Pack | Instructions · Workflows · Policies — a signed content bundle on the existing content plane |
| External capability declarations | registered outbound connector calls: schemas · destinations · egress policy — **no arbitrary module network access** |

| Activation check | Rule |
|---|---|
| signature · compatibility · entitlement | verified before activation |
| permission diff | a permission expansion is a **visible security change** — it cannot arrive as an incidental module upgrade |
| migrations · recovery plan | present and applied, or activation is refused |
| ambiguity | **fail closed** |

Versions install side by side. **An in-flight run retains the exact module, use-case, workflow and
capability versions it began with** (and if one is *pulled*, Decision 6 aborts it — retention is not
resurrection). Licence expiry blocks **new** starts; it must never hide existing evidence or strand
a safe completion, cancellation or compensating recovery.

### 14. Engine behavioural-PII reads fail closed on audit-persist failure — on every surface (S6)

The platform posture (ADR-0033, D6) is: mutations fail closed on audit failure; reads keep their
surface's posture. MCP's surface posture is **set-and-proceed**. For engine tools that return
**device-attributable data**, that is an evasion path shaped exactly like the reads the
works-council controls exist for.

**Engine tools returning device-attributable data fail closed on audit-persist failure on every
surface, MCP included** — the REST posture (503 + `Sec-Audit-Failed`), not the dashboard/MCP
set-and-proceed one. Any exception is a formally recorded exception with compensating controls, in
ADR-1005's exception ledger — never a silent inheritance of the weaker surface posture.

This is consistent with Decision 11: core does not release device-attributable rows it cannot
account for.

### 15. Purge is proven, not reported (S7, hardening G4)

A device deleted in core leaves `agent_id`-tagged personal data in the `uce` database, which core's
role cannot read. G4's contract — core emits a durable **tombstone**; every engine purges within a
declared SLA and reports completion — relies, as drafted, on engine honesty. Reports are not proof.

The engine must supply **one** of:

- **signed deletion receipts** — the purged tombstone ids, signed by the engine principal's key, so
  core can verify what was purged without reading the `uce` database; **or**
- a **purpose-limited, core-readable deletion-audit table** — the single object in the `uce`
  database on which core's role holds a `SELECT` grant, containing tombstone ids and purge
  timestamps and nothing else.

Core audits per-engine purge compliance against the declared SLA and **alerts on breach**. Signing
up to this is part of being an engine (a 2c-style hosting requirement).

## Sequencing interlock — no A5 code path ships before these land (S2)

A5 ratifies a **shape**. It is not available-now, and it consumes substrate that does not exist. As
prose, that has already failed once: the ballot's sequencing clause named two prerequisites and
omitted the two that carry its own evidence. So it is a **tracked interlock**, in the style of the
M3 parity gate — a named gate with a checklist, not a sentence in an ADR.

| # | Prerequisite | Why A5 cannot ship without it | Status today |
|---|---|---|---|
| **(a)** | **Phase-4 engine principals** (ADR-1005 exec plan) | Decision 4's mid-run caller is the engine principal. Without it there is no authenticated identity for the UCE to hold. | `engine` is a **reserved** `principal_class` label; the class is not live. |
| **(b)** | **The ADR-0017 admit-then-filter gate (#1716) + a server-internal evaluate-as-operator seam** | Decision 4 confines against the **admitting operator's** current authority while the **engine** is the authenticated caller. Both halves are needed. | No `authorize_list_read` symbol exists in the server tree — only comments naming it a convergence target (#1716, #1634 remainder). |
| **(c)** | **The D12 audit schema** (acting principal · authority ref · **indexed** `use_case_run_id`) | Decision 12. Without it, "no unjoined evidence" is not merely untested — it is **unqueryable**. Rides the audit-store Postgres migration. | `AuditEvent` has a single `principal` field. |
| **(d)** | **The P7 release-log schema** | Decision 11 *is* the disclosure evidence, and Decision 10's subset check **reads it**. Ship A5 without it and admitted runs exist whose disclosure cannot be proven from core-owned evidence. | Does not exist. Born-on-PG store, ADR-0012. |
| **(e)** | **G1 — the cross-process event transport** | Gates **Decision 9 only** (progress/events), not the whole of A5. The buses are process-local. | Open question; must be designed before P4 lands. |

**Rule:** no A5 code path ships until **(a)–(d)** have landed. **(e)** gates Decision 9
specifically.

**Falsifier (what a violation looks like):** a merged PR that admits runs, mints grants or serves
results while the audit row cannot carry an indexed `use_case_run_id`, or while no release-log write
happens at fact-read time. If that PR can merge, the interlock is not tracked — it is prose again.

## Acceptance tests — the seven confidence conditions

Filed **verbatim** from the 13 July synthesis memorandum. These are acceptance gates *enforced by
tests, not convention*; they are this protocol's test plan. (Conditions 4 and 6 exercise machinery
**ADR-0033** and **ADR-0031** own respectively; they are quoted here whole because the memorandum
states them as one set, and the run is what joins them.)

- **No unadmitted run** — the UCE cannot execute without a valid Core-issued grant bound to the
  exact Use Case, versions, inputs and scope.
- **No authority in Presentation** — changing a Presentation route or template cannot grant access
  Core would deny.
- **No unjoined evidence** — every result, plan, approval and execution traceable through one
  use_case_run_id.
- **No partial-fleet ambiguity** — every distributed result reports intended, contacted, responded,
  failed and timed-out targets plus its completeness policy.
- **No private Core shortcut** — Presentation and UCE use documented, versioned Core APIs; a build
  or contract test detects undeclared endpoints.
- **No restart amnesia** — Presentation restart preserves sessions and replay; Core restart has an
  explicit reconnect-and-resume path.
- **No accidental second product** — Dashboard, REST and MCP enumerate the same registered
  capabilities and observe the same Core authority.

Two of these have a specific shape under this ADR worth naming:

- **"No unadmitted run"** is testable at the UCE-checks-grant seam: a request with no grant, an
  expired grant, a wrong-audience grant, a grant whose `input_hash` does not match the inputs
  (Decision 2), or a cached-result request with no **result-scoped** grant (Decision 10) — each is
  refused by the UCE, and each refusal is a test.
- **"No unjoined evidence"** is a *query*, run against a live database: for a sampled
  `use_case_run_id`, the admission row, every release-log entry, every plan, every approval, every
  execution and the finalisation receipt must all return. That query is the D12 index's reason to
  exist.

## Consequences

### The audit gap closes without core becoming a proxy

Core sees every invocation *as an invocation* — not indirectly, later, inferred from the fact reads
it happened to serve. That was the one thing the peer-UCE topology could not offer and the one
thing the proxy topology bought at the cost of core parsing every domain payload. The admitted run
buys it for the price of one round trip.

### Disclosure evidence stops depending on the engine

Decision 11 moves the primary record into core, where the role boundary means it survives the
engine's retention policy, the engine's bugs and the engine's honesty. It costs a write on every
confined fact read — and that write is on the fail-closed path, so it is on the critical path for
reads too. That is the price of being able to answer a DSAR without asking a module.

### Cached results become cheaper to deny than to serve

Decision 10 makes a cache hit run a subset check and mint a grant. A cache that has to re-admit is
not free — but the alternative is a cache that leaks a shrunken operator's old blend, which is not a
cache, it is an exfiltration primitive with a TTL.

### A run is a unit of cost

Because iterative agentic triage is many small runs (Decision 1), the admit path's cost is the
platform's agentic-throughput ceiling. One round trip, one audit row, one grant mint, and a fast
lane that skips approval routing entirely — that budget is a design constraint on every future
change to admission, not an implementation detail.

### Three new core stores, all born on Postgres

The run store (Decision 5), the release log (Decision 11) and the grant/receipt records
(Decisions 3 and 12) are new, core-owned, and born on Postgres under ADR-0012's contract —
fail-closed construction, durability on top. They join the migration ladder; they never land as
SQLite.

### The interlock will feel like a delay, and that is the point

Four prerequisites (a)–(d) sit between "A5 is ratified" and "A5 code merges". Every one of them
exists because the alternative is an admitted run whose disclosure cannot be proven — which is
indistinguishable, in an audit, from no admission at all.

## Alternatives considered

- **Core on the byte path** (the pre-synthesis shape: core relays each invocation to the engine and
  re-aggregates the response). Rejected in **ADR-0031**: core would parse and re-aggregate every
  domain payload, which is core interpreting domain schemas — the exact coupling ADR-1005 exists to
  prevent.
- **The UCE self-authorises on the grant alone** — treat the grant as a capability token and let the
  UCE serve everything it covers. Rejected: the grant is frozen at admission, so this is
  authority-as-of-a-past-moment. Decision 4's server-side lookup is what makes mid-flight revocation
  possible at all, and mid-flight revocation is what makes a long run safe.
- **Serve a cached result on run id, with presentation checking scope.** Rejected (S3): it puts an
  authority decision in presentation, which ADR-0031's D3 invariant forbids and which "no authority
  in presentation" tests against directly.
- **The engine's journal as the disclosure record**, with core reading it for DSAR. Rejected (P7):
  it requires core to hold a grant on the `uce` database — dissolving the role boundary that makes
  the two-database split worth having — and it makes GDPR evidence depend on a retention policy the
  engine owns.
- **The manifest as the runtime input** (enforce what the engine declared; human review as the
  backstop). Rejected (S4): a review artifact is not an enforcement artifact. Core's ratified copy
  costs one table and converts a review promise into a runtime property.
- **Trust the engine's purge report.** Rejected (S7): "we deleted it" is a claim; a signed receipt
  or a core-readable deletion-audit table is evidence. The difference matters exactly once, in
  front of a regulator.
