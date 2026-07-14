---
status: proposed
date: 2026-07-13
owner: "@dgr (Dave Rae)"
supersedes: >-
  docs/uce-deployment-topology-design.md D2 (UCE deployable = backend + GUI, one artifact, on its
  own VM) and D3 (two browser origins) — both merged via PR #2079. D1 (one PostgreSQL instance,
  two databases, separate roles and pools) is REAFFIRMED, not superseded.
  docs/uce-host-requirements.md F-10 ("no machine consumer; private UI seam") is VOIDED — its
  premise disappears with the engine's UI. F-5 / INV-7 (the engine's own confinement and the
  M3(d) equivalence test) are RELOCATED, not deleted; see "INV-7 moves, it does not vanish".
depends-on: >-
  1005-headless-platform-use-case-engines (this ADR is how its central claim becomes structurally
  true rather than review-enforced).
related: >-
  0032-use-case-admission-protocol (the normative admission/grant/evidence protocol this
  decomposition's Decision 4 delegates to).
  0033-access-control-spine (the platform-wide authority, approval and Execution-Plan spine both
  of them enforce against).
  0030-held-open-connection-scaling (this decomposition is what makes ADR-0030's durable fix
  reachable: presentation becomes a separate binary, so its runtime is a free choice).
  docs/adr-1005-execution-plan.md Decision 3 (the machine surface — voided by this ADR), track 2c,
  track 2d, Phase 5 (server-issued delegation), track 2g (A5 annotations), issue #2056.
---

# ADR-0031 — Presentation, core and engines are separate binaries

## Context

**Today the server is one binary that is both the domain and its own front end.** Nine route
families register on a single `httplib::Server` inside `yuzu-server`: REST v1, MCP, the HTMX
dashboard, settings, workflow, device, viz. The dashboard renderers can reach stores in-process.

That means ADR-1005's central claim — *no UI-only capabilities; a dashboard fragment is not an API
twin* — is a **rule enforced by review**. The `consistency-auditor` asks the standing question on
every capability-adding PR, and it asks it because nothing in the build prevents the answer being
wrong. A rule that can only be enforced by remembering to enforce it will eventually not be.

**And the 2c topology, as merged, has been producing damage.** Putting the engine on its own VM
*with its own GUI* (D2) forced three things:

1. **Two browser origins** (D3) — cross-origin artifact acquisition and hand-off, by construction.
2. **The engine re-implementing ADR-0017 confinement** (F-5, INV-7) — per-render, over the
   operator's confined device set, including which CVEs are even *visible* and every count — and
   then being graded against what `/devices` would have shown, by an M3(d) equivalence test that is
   a **hard interlock gating M3 acceptance and Phase 6**. The engine is rebuilding a mechanism the
   core already has, and being marked on whether it got the same answer.
3. **F-10 — "no machine consumer; private UI seam."** Because the engine's only external interface
   is a human UI, **an agentic worker cannot read a single vulnerability finding.** The platform's
   flagship agentic capability — an LLM-driven client triaging CVEs and dispatching the patch — is
   human-only on the first use-case engine we ship. The module's own machine-callable
   `confirm-now` action is already logged as an unresolved reconciliation item against it.

Each of those is a reasonable local decision. Together they are a decomposition telling us it is
wrong: three governed problems, all downstream of *where the UI lives*.

Separately, ADR-0030 recorded that cpp-httplib is thread-per-connection, so every held-open SSE
response pins a worker thread for its life — and that the durable fix is to stop owning a thread
per stream.

**How this ADR reached its present shape.** The first draft made core the byte path for engine
invocation. A colleague reconciliation memorandum and a counter-proposal both argued that this buys
audit coverage at the cost of making core parse, relay and re-assemble every engine request and
response — and that the property actually wanted is *control-plane mediation*, not *data-plane
proxying*. Four grill rounds and a Kimi+Codex adversarial review followed. **Decision 4 below is the
reconciled shape** (ballot A5); the earlier byte-path shape is recorded in Alternatives, because it
is the alternative most likely to be re-proposed.

## Decision

**1. Three kinds of binary: presentation, core, engine.** Co-located on one host today;
independently deployable by construction, with no code change required to move any of them to its
own host. Responsibilities are stable even if the deployment shape later changes.

**2. Core owns the API and is the sole authority.** Authentication, RBAC, tier policy, scope
confinement (ADR-0017), approvals, protected effects, audit, fleet truth and the engine-capability
registry all live in core. Every other component may **narrow** authority; none may **enlarge** it.
The platform-wide spine that expresses this is ADR-0033.

**3. Presentation is a transport-and-render adapter.** It terminates HTTP, SSE and MCP, frames
protocol, renders the HTMX dashboard, and holds live connection state — and it reaches the domain
**only** through core's API, exactly as any external client does. The GUI becomes just another API
client.
**"Core's API" means the public, versioned API — nothing else** (grill decision, 2026-07-13; ballot
A4). Presentation holds no private endpoints on core; a gap discovered while porting a dashboard
fragment is, by definition, a missing public capability — the forcing function working as designed.
Where rendering wants batch or composite reads, those are added to the **public** surface (agentic
workers want them too); any exception goes in ADR-1005's exception ledger, not in a side API.

**4. Engines are headless capability providers, and invocation splits the control plane from the
data plane** (ballot A5). An engine has **no UI and no machine surface of its own**; its Use Cases
and schemas register into core's capability catalogue at module activation, and clients discover
them through the one public catalogue.

Invocation works like this, and only like this:

- **Core admits the run.** Presentation calls a public, versioned core endpoint with
  `use_case_id@version`, module version, the raw inputs and the requested scope. Core authenticates
  the stable principal, resolves RBAC, applies token attenuation and scope, evaluates risk tier,
  computes the normalised-input hash itself, and writes an admission or a denial audit row.
- **Core mints a bounded grant.** Short-lived and **audience-bound**, binding principal, engine and
  module and use-case versions, input hash, scope ceiling, risk tier and expiry. It is the *same*
  RFC 8693 delegation artifact family as the engine-principal design (2b) — not a second token
  species. It is never self-authored by presentation.
- **Presentation calls the engine directly with the grant.** The engine rejects a missing, expired,
  wrong-audience or mismatched grant.
- **The engine reaches facts and effects only through core.** Every fact read and every capability
  request carries the run identifier and is independently confined by core, against the admitting
  operator's **current** authority — the grant's TTL gates run *start*, not the run's life.
- **The engine composes, and finalises.** It assembles results from the confined inputs core
  released to it, and finalises the run with core (canonical result hash + disclosure summary)
  before release.

The normative protocol — run lifecycle, grant semantics, the release log, cached-result
re-admission, evidence and the sequencing interlock — is **ADR-0032**. This ADR fixes only the
shape: core is the **admission and authority chokepoint, not the byte path**.

**5. Presentation runs on Drogon** (ballot A3, amended). An asynchronous, event-loop C++ framework
with coroutine handlers: it removes one thread per held-open stream — ADR-0030's durable fix —
without this project building a web framework on Boost.Beast, and without re-homing ~5k lines of
`mcp_server.cpp` and the HTMX renderers into another language. Presentation uses Drogon for
transport, framing and rendering **only**: not its ORM, not its session authorization, not its
business-logic facilities. The Erlang gateway stays exactly where it is — **southbound**, holding
agent connections; it does not move northbound.
**Gate G10:** a build canary — Drogon linked into the existing Meson/vcpkg matrix, MSVC static
linkage included — must pass before this leg is committed to. The `#375` history (grpc/protobuf/
abseil static linkage on Windows MSVC) is the reason this is a gate and not an assumption.

**6. Isolation is enforced as if remote, from day one.** Components authenticate to each other over
the network protocol even when they are co-located. **No cross-component database access** — the
engine never touches the `yuzu` database, core holds no grant on `uce`, and **presentation owns no
database at all.** ADR-1005's `REVOKE CONNECT … FROM PUBLIC` + separate-role isolation (2c D1) is
reaffirmed and becomes *more* load-bearing, because co-location removes the network as an
accidental barrier.

**7. One PostgreSQL instance, two databases, in its own sibling container** (2c D1, reaffirmed;
ballot A2). Same host as the three binaries today; separate roles, separate pools, no cross-database
grant.

**8. Every seam is a versioned contract.** Running on the same host does not remove the need for
one. The seam inventory is normative:

| Seam | Boundary | Contract |
|---|---|---|
| **B1** | Operator → presentation | One origin, one discoverable product surface for people, REST clients and MCP clients. Transport authentication on every request. Presentation never accepts a caller-authored "act as" identity. Carries: `credential · channel · correlation_id · request_deadline · client_protocol_version`. |
| **B2** | Presentation → engine (Use Case request) | Channel-neutral, versioned, separately published. Presentation passes a **core-verifiable grant**, never a self-authored identity. Result carries facts, coverage, provenance, decisions and any proposed plan reference. Carries: `use_case_id@version · module_id@version · normalised_inputs · grant · request_id · result_schema_version`. |
| **B3** | Presentation → core (platform request) | The public, versioned core API — used for admission, platform administration, direct expert operations and **all** core reads. Core validates the real credential and remains the source of every security decision. Carries: `principal_credential · securable · operation · scope · correlation_id`. |
| **B4** | Engine → core (facts, capabilities, effects) | The engine reads fleet facts through typed core capabilities, confined per read. For protected effects it submits an immutable **Execution Plan** (ADR-0033); core verifies plan hash, capability versions, scope, the **admitting operator's** authority, the module envelope and any execution authorisation. Carries: `plan_id · plan_hash · use_case_run_id · module_manifest_hash · capabilities[] · parameters[] · scope · fact_refs[] · expiry · provenance`. |
| **B5** | Engine → `uce` database | The engine role connects only to `uce`. A `uce_system` schema holds host state; each module gets its own schema and migration ledger. Core has no grant here. Carries: `module_schema · migration_version · journal_id · derived_state_version · retention_class`. |
| **B6** | Core → `yuzu` database | Identity, authorisation, fleet truth, execution state, audit. The engine has no grant here. Cross-application data is exposed through a **core capability**, never a SQL view shared across roles. Carries: `principal · grants · fleet_fact · execution · pending_command · retry · audit_event`. |
| **B7** | Core → gateway → agent | Core sends already-authorised commands with stable identities, deadlines and idempotency keys. The gateway routes and applies backpressure without becoming durable. The agent suppresses duplicates and returns correlated results. Carries: `execution_id · command_id · idempotency_key · target_agent · deadline · payload_schema · result_schema`. |

## Invariants

Named, so that a future change can be tested against them rather than argued with.

**INV-31-1 — Presentation is a credential pipe, never an identity authority** (ballot D3). It
forwards the caller's real credential, the channel, a correlation id and infrastructure metadata. It
never asserts a user identity, never mints a grant, and never makes a permission decision. This is
the same sentence structure as the on-behalf-of ban (ADR-1005): an ingress surface that could assert
who you are is an ingress surface that will.

*The honest TCB statement.* This does **not** mean a compromised presentation is harmless.
Presentation terminates the client protocol, so it **is inside the bearer-credential trust boundary
for the traffic it handles**: it can replay any credential it sees, and core's audit will attribute
the resulting action to the legitimate user. The **fused server has exactly this exposure today** —
the split neither creates nor removes it. What the split buys is narrower and still worth having:
presentation cannot *enlarge* authority, cannot reach a store, and cannot answer a question core
would have denied. The hardening path is recorded, not hand-waved: presentation exchanges the raw
credential at core for a short-lived, **presentation-audience-bound** session token (the same RFC
8693 artifact family as the invocation grant), so raw bearers stop persisting in presentation
memory. That is a **phased deliverable, not a v1 gate** — but the claim must be stated at its true
strength from now on.

**INV-31-2 — Core confines the inputs; the engine composes them** (the relocation of INV-7). Core
is the only component that decides which devices, which rows and which data classes an engine may
see, and it records that release at the moment of the read (ADR-0032's release log). The engine
therefore **cannot disclose what it was never given** — safety by construction, not by the engine
re-deriving ADR-0017 correctly. Aggregation and interpretation are the engine's job; confinement
never is.

**INV-31-3 — No cross-component database access.** Decision 6, restated as an invariant because it
is the one a "just this once, for performance" patch will attack first.

**INV-31-4 — There is no private core API.** Decision 3, restated for the same reason. A build or
contract test detects undeclared endpoints.

**INV-31-5 — Presentation's service identity attests infrastructure, not people** (ballot G2).
Presentation authenticates to core with its own mTLS service identity and may attest peer IP and
correlation id (without which session peer-binding and lockout break). Core trusts that metadata as
**infrastructure metadata only**; it never trusts it as an identity claim.

## Failure and degraded-mode posture

| Failure | Required behaviour | Reason |
|---|---|---|
| Engine unavailable | Use Cases report unavailable. Core platform administration and already-authorised fleet execution continue independently. | A specialist application must not become a fleet-control dependency. |
| Core unavailable | No new protected operation proceeds. Engine results needing fresh authority or fleet facts **fail closed** rather than serving an unconfined answer. | Core is the only authority and the only source of fleet truth. |
| `uce` database unavailable | The affected module cannot start or advance a run. Core does **not** reconstruct engine domain state. | Avoids a hidden second owner of that state. |
| `yuzu` database unavailable | Authentication, authorisation and new state-changing work fail closed; health endpoints report the condition. | Every fleet effect must remain attributed and authorised. |
| Presentation unavailable | The product surface is down; the fleet keeps running. Sessions and replay survive, because they live in core/Postgres, not in presentation memory. | Presentation is replaceable by design. |
| Gateway unavailable | Core retains pending commands and retry deadlines, every command identity unchanged. | Gateway state is disposable. |
| Endpoint reconnects after an uncertain result | Core may redeliver the same command identity; the agent suppresses the duplicate effect and returns the remembered outcome where it has one. | At-least-once delivery without repeated effect. |
| Partial distributed query | Return a coverage envelope, then apply the Use Case's completeness policy (ADR-0033 D11). | Missing evidence must never be read as a negative finding. |
| Audit or release log cannot persist | State-changing work fails closed. Reads follow the declared posture for their data classification and report the evidence failure — for engine reads of device-attributable data, that posture is **fail closed on every surface, MCP included** (ADR-0032). | Prevents an unattributable mutation and an unrecorded disclosure. |
| External connector unavailable | Return a typed dependency failure and mark the result incomplete. Never substitute invented data. | Assurance depends on honest provenance and completeness. |

## Consequences

### The headless claim stops being a promise and becomes a property

The GUI cannot bypass the API because it is a different process. Parity is no longer a question the
`consistency-auditor` has to remember to ask — the build answers it. This is the point of the ADR;
the deployment flexibility is a bonus.

### F-10 is void, and the agentic gap closes as a side-effect

F-10 exists solely because the engine's only external interface was a human UI. Remove that UI and
the carve-out has no premise. Engine capabilities are reachable through the platform surface — by a
human and by an agentic worker, through the same tools, the same RBAC, the same audit chain. The
open `confirm-now` reconciliation item resolves itself.

**The boundary this creates must be named:** the set of questions anyone can ask is the set of
capabilities the engine exposes. Agentic-first does not mean handing out SQL; it means those
capabilities must be composable and richly described (track 2g's annotations) enough that a worker
can build questions nobody enumerated. **An engine that ships three coarse tools will strangle the
agentic story just as effectively as F-10 did.**

### INV-7 moves, it does not vanish

The engine no longer re-derives ADR-0017 confinement, so **F-5 / INV-7 relocate into core** as
INV-31-2, and the M3(d) equivalence test loses the thing it was testing (an independent
re-derivation). It does not lose its *purpose*: **M3 remains the parity gate**, and its confinement
leg **retargets** to core's release gate — that what core released to the engine for a given
operator equals what that operator could have read directly (the evaluate-as-operator seam,
ADR-0017 / #1716). The test moves; the interlock survives. `docs/uce-host-requirements.md` F-5 and
`docs/adr-1005-execution-plan.md` Decision 14 / M3(d) need amendment notices to say so.

### D3's cross-origin problem disappears

One origin, one session, one auth. The 2c §6 artifact-acquisition and F-8 hand-off flows stop being
cross-origin by construction.

### ADR-0030's durable fix becomes reachable

Presentation is a separate binary, so **its runtime is a free choice**. What makes held-open
connections expensive is cpp-httplib's thread-per-connection model — a property of *that process*,
not of the domain. ADR-0030's answer is therefore not "put a gateway in front of the server" but
**"the presentation layer is the connection holder"**, and Decision 5 names Drogon as what it is
built on. The `StreamBudget` cap shipped in track 2f stays exactly what it was sold as: a stopgap
that keeps the fused server from exhausting its thread pool until this lands.

### Costs, honestly

- **Session state.** Operator sessions live in `AuthManager`'s memory today. If presentation held
  them, restarting presentation would log everyone out and presentation could never scale
  horizontally. **Sessions and the MCP replay ring move to core/Postgres** — decided *with* the
  split, not after it. This reworks the in-memory contracts around JIT elevation and inactivity
  timeout, and it is why the auth-store PG migration must be re-scoped before it starts.
- **Supervision.** Three processes plus a Postgres sibling need a supervisor, or a pod of containers
  sharing a network namespace (the better hygiene if Kubernetes is a target).
- **Version skew.** The moment the binaries *can* be split, they *will* be, at different versions.
  The core API needs a compatibility contract from day one (ballot G5) — the same
  versioning/deprecation policy ADR-1005 Phase 0.3 already defines for the public API. The
  presentation↔engine contract (B2) is separately versioned and published.
- **A cross-process event spine.** The event buses are process-local today
  (`execution_event_bus.hpp`). Streaming progress from core to presentation across a process
  boundary is **new work and a prerequisite**, not an assumption — ballot G1, and a gate on
  ADR-0032's P4.
- **Latency.** A localhost hop per request (~100 µs) against a 250 ms p95 view budget. Irrelevant.
- **Observability.** Three `/metrics` endpoints to scrape and one trace context to thread through.

### Migration — not a big bang

1. **Verify the baseline first.** Instruction-Set semantics, workflow dispatch-vs-outcome
   correlation, and approval checkpoint/resume are all documented as stronger than the code
   currently enforces. Correct the docs, then repair the execution semantics — an admission protocol
   layered on an execution engine that treats dispatch as success would inherit the lie.
2. **Define the contracts in-process.** Admission, grants, finalisation receipts, coverage, linked
   evidence — while everything still runs in one test process. Prove the *denial* and *audit*
   behaviour before adding network failure modes.
3. **Enforce the seam logically.** Dashboard, MCP and REST handlers call the API (or a local API
   client), never stores directly. This is checkable, and it is most of the value.
4. **Extract presentation** into its own Drogon binary against that seam (after G10), with durable
   sessions and replay behind the boundary.
5. **Extract the engine** — nearly free, because it is new code that already talks to the server as
   an external principal.

### The acceptance tests live in ADR-0032

The seven confidence conditions that decide whether this decomposition actually holds (no unadmitted
run; no authority in presentation; no unjoined evidence; no partial-fleet ambiguity; no private core
shortcut; no restart amnesia; no accidental second product) are recorded as the acceptance-test plan
in **ADR-0032**, next to the protocol they test. They are not repeated here.

## Alternatives considered

- **Keep the fused binary.** Parity stays a rule policed by review; the engine keeps a UI, so F-10
  keeps the agentic gap and F-5/INV-7 keep the equivalence-test interlock. Rejected: it is the status
  quo whose costs this ADR is written to explain.
- **Engine on its own VM with its own GUI** (2c D2/D3, merged). Rejected. Every one of the three
  governed problems above descends from it, and none is worth the isolation it buys — which the
  role/database separation already provides.
- **Core as the byte path** (this ADR's own first draft): core relays each engine invocation,
  injects the confined scope, receives `agent_id`-tagged rows back and re-assembles them itself.
  Rejected on the reconciliation memorandum's argument: it makes core parse, relay and re-assemble
  every request and response of every Use Case — importing engine-shaped, long-running composition
  into the authority component — to buy an audit property that **admission plus a bounded grant plus
  a release log already buys** (ADR-0032). The property wanted is control-plane mediation, not
  data-plane proxying. Kept in this list because it is the alternative most likely to be
  re-proposed, and because its audit claim is the thing ADR-0032 must actually deliver.
- **Presentation owns the API; core is a domain service behind it.** Rejected: it puts policy at the
  edge and produces two APIs, of which the private one quietly becomes the real one.
- **Give the engine its own MCP surface.** Rejected: every future engine then re-pays the whole
  ADR-1005 tax — twin surfaces, discovery, the A4 envelope, RBAC, audit, the on-behalf-of guard —
  and agentic workers must federate across N endpoints, which is exactly what the single-surface
  thesis exists to prevent.
- **Re-home presentation onto the BEAM.** Considered seriously (the project already builds, ships
  and supervises Erlang, and the BEAM holds long-lived connections as its natural unit). Rejected in
  favour of Drogon: re-homing `mcp_server.cpp` and the HTMX renderers means a language port of the
  entire northbound surface, and the connection-holding property is available in C++ without one.
  The gateway keeps its BEAM specialisation southbound, where the connection count actually is.
