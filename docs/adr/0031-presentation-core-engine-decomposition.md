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
  M3(d) equivalence test) are largely obviated; see Consequences.
depends-on: >-
  1005-headless-platform-use-case-engines (this ADR is how its central claim becomes structurally
  true rather than review-enforced).
related: >-
  0030-held-open-connection-scaling (this decomposition is what makes ADR-0030's durable fix
  reachable: presentation becomes a separate binary, so its runtime is a free choice).
  docs/adr-1005-execution-plan.md Decision 3 (the machine surface), track 2c, Phase 5
  (server-issued delegation), track 2g (A5 annotations), issue #2056.
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

## Decision

**1. Three kinds of binary: presentation, core, engine.** Co-located in one container today;
independently deployable by construction, with no code change required to move any of them to its
own host.

**2. Core owns the API.** Authentication, RBAC, tier policy, audit, ADR-0017 confinement, and the
engine-capability registry all live in core. Core is the authority.

**3. Presentation is a transport-and-render adapter.** It terminates HTTP and SSE, frames MCP,
renders the HTMX dashboard — and it reaches the domain **only** through core's API, exactly as any
external client does. The GUI becomes just another API client.

**4. Engines are headless capability providers.** An engine has **no UI and no machine surface of
its own**. It registers its tool schemas with core; core proxies invocations to it, injecting a
**server-issued** confined scope (never engine-asserted — NF-5 stands); the engine returns
`agent_id`-tagged **rows**, never aggregates; **core confines and aggregates.**

**5. Isolation is enforced as if remote, from day one.** Components authenticate to each other over
the network protocol even when they share a container. **No cross-component database access** — the
engine never touches `yuzu`, and **presentation owns no database at all.** ADR-1005's
`REVOKE CONNECT … FROM PUBLIC` + separate-role isolation (2c D1) is reaffirmed and becomes *more*
load-bearing, because co-location removes the network as an accidental barrier.

**6. One PostgreSQL instance, two databases** (2c D1) — unchanged. Co-located with the binaries.

## Consequences

### The headless claim stops being a promise and becomes a property

The GUI cannot bypass the API because it is a different process. A1 parity is no longer a question
the `consistency-auditor` has to ask — the build answers it. This is the point of the ADR; the
deployment flexibility is a bonus.

### F-10 is void, and the agentic gap closes as a side-effect

F-10 exists solely because the engine's only external interface was a human UI. Remove that UI and
the carve-out has no premise. Engine capabilities are reachable through the platform surface — by a
human and by an agentic worker, through the same tools, the same RBAC, the same audit chain. The
open `confirm-now` reconciliation item resolves itself.

**The boundary this creates must be named:** the set of questions anyone can ask is the set of
capabilities the engine exposes. Agentic-first does not mean handing out SQL; it means those
capabilities must be composable and richly described (track 2g's A5 annotations) enough that a
worker can build questions nobody enumerated. **An engine that ships three coarse tools will
strangle the agentic story just as effectively as F-10 did.**

### F-5 / INV-7 largely obviate themselves

Confinement is enforced once, in core, for every consumer. The engine never sees an unconfined
device set, so it cannot leak one. What remains to test is narrower and different: that core
correctly confines and aggregates engine-returned rows. The M3(d) equivalence test in its present
form — proving the engine independently re-derived ADR-0017 — loses its reason to exist.

### D3's cross-origin problem disappears

One origin, one session, one auth. The 2c §6 artifact-acquisition and F-8 hand-off flows stop being
cross-origin by construction.

### ADR-0030's durable fix becomes reachable

Presentation is now a separate binary, so **its runtime is a free choice.** The thing that makes
held-open connections expensive is cpp-httplib's thread-per-connection model — a property of *that*
process, not of the domain. A presentation layer on the BEAM (which this project already builds,
ships and supervises) holds long-lived connections as its natural unit. ADR-0030's answer is
therefore not "put a gateway in front of the server" but **"the presentation layer should be the
gateway."** Not near-term: re-homing ~5k lines of `mcp_server.cpp` plus the HTMX renderers is a real
migration. The decomposition is what makes it *possible*, and the decomposition is cheap now.

### Costs, honestly

- **Session state.** Operator sessions live in `AuthManager`'s memory today. If presentation holds
  them, restarting presentation logs everyone out, and presentation can never scale horizontally.
  Sessions must move to core (Postgres-backed) — decide this with the split, not after it.
- **Supervision.** Three processes plus Postgres in one container needs a supervisor, or a pod of
  containers sharing a network namespace (the better hygiene if Kubernetes is a target).
- **Version skew.** The moment the binaries *can* be split, they *will* be, at different versions.
  The core API needs a compatibility contract from day one — the same versioning/deprecation policy
  ADR-1005 Phase 0.3 already defines for the public API.
- **Latency.** A localhost hop per request (~100 µs) against a 250 ms p95 view budget. Irrelevant.
- **Observability.** Three `/metrics` endpoints to scrape and one trace context to thread through.

### Migration — not a big bang

1. **Enforce the seam logically first.** The dashboard, MCP and REST handlers call the API (or a
   local API client), never stores directly. This is checkable, and it is most of the value.
2. **Extract presentation** into its own binary against that seam.
3. **Extract the engine** — which is nearly free, because the engine is new code and already talks
   to the server as an external principal.

## Alternatives considered

- **Keep the fused binary.** A1 parity stays a rule policed by review; the engine keeps a UI, so
  F-10 keeps the agentic gap and F-5/INV-7 keep the equivalence-test interlock. Rejected: it is the
  status quo whose costs this ADR is written to explain.
- **Engine on its own VM with its own GUI** (2c D2/D3, merged). Rejected. Every one of the three
  governed problems above descends from it, and none of them is worth the isolation it buys — which
  the role/database separation already provides.
- **Presentation owns the API; core is a domain service behind it.** Rejected: it puts policy at the
  edge and produces two APIs, of which the private one quietly becomes the real one.
- **Give the engine its own MCP surface.** Rejected: every future engine then re-pays the whole
  ADR-1005 tax — twin surfaces, discovery, the A4 envelope, RBAC, audit, the on-behalf-of guard —
  and agentic workers must federate across N endpoints, which is exactly what the single-surface
  thesis exists to prevent.
