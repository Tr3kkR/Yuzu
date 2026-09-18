# High Availability Architecture

---
status: accepted
owner: Fraser Jarvis (@fjarvis)
---

**Authors:** Fraser Jarvis (@fjarvis)
**Review:** hardened after adversarial review by the `enterprise-architect` validator and
`gpt-5.6-sol` (both read the codebase), then revised again per the PR #3320 `CHANGES_REQUESTED`
review; see *Guarantees and non-guarantees*, *Deployment topology and replication axes*, and the two
*Review findings incorporated* rounds below.

## Context

Yuzu today is a **single-server design**. The server tier assumes one live process:
the agent gRPC stream registry, operator/MCP sessions, the execution event bus, and the
command→execution correlation map are all **per-process in-memory** state; several control-plane
stores are still **local SQLite**; the CA root key and enrollment state sit on **local disk**; and
the background workers that dispatch commands run **unconditionally on every process** with no
cross-instance guard. The existing `docs/operations/disaster-recovery.md` and
`capacity-planning.md` describe HA as *active-passive over shared NFS with SQLite/Litestream* —
pre-Postgres and now wrong.

We need High Availability as a **general product capability**, serving both **self-managed on-prem**
(first-deployment target, possibly a single Postgres, minimal extra infrastructure) **and a future
SaaS** offering (managed Postgres, cloud primitives available) from **one architecture**. HA must not
be scoped to any single customer, and we must **not assume the customer runs HA Postgres**.

Three groundwork facts make this tractable rather than a rewrite:

1. **The Erlang gateway already clusters** (OTP `pg` process groups, ETS registry) and already
   tolerates *server* failover — on upstream reconnect it re-proxies a `ProxyRegister` for every
   held agent because the new server "may be a fresh instance with an empty registry"
   (`yuzu_gw_upstream.erl`). **But** per-agent *targeted* routing is today a **node-local ETS lookup**
   (`yuzu_gw_registry:lookup`, `yuzu_gw_registry.erl:90`) — `pg` is used only for broadcast groups —
   so distributed intra-cluster agent→node routing is **net-new work**, not a free property (see §7).
2. **ADR-0031 (presentation/core/engine decomposition)** already commits the direction: sessions and
   the MCP replay ring "move behind the core boundary" so presentation can "scale horizontally."
   Note this **reverses** the *as-built* auth decision (post-Postgres migration) that put sessions
   **in-memory on a monotonic clock on purpose** (AuthDB routed concern) — §4 argues that reversal
   explicitly rather than treating ADR-0031 as unopposed.
3. **Postgres availability already bounds the whole system.** The server fails closed with *no*
   SQLite fallback (ADR-0007) — if Postgres is unreachable, no instance can serve. So Postgres is
   already the availability floor in every deployment, which means a Postgres-backed coordination
   default adds **no new single point of failure**.

## Decision

Adopt a **hybrid, on-prem-first (SaaS-capable) HA architecture**:

- The **operator/API plane** (REST, dashboard, MCP incl. streaming) runs **active–active** behind a
  load balancer.
- The **agent-connectivity plane** is concentrated on the **gateway cluster**, which is **mandatory
  in HA deployments** (direct server↔agent streams remain fully supported for single-node
  deployments). This fuses "server HA" and "multiple/regional gateways" into one mechanism — at the
  honest cost of net-new distributed intra-cluster routing and shared presence state (§7, §7a).
- **Singleton background work** runs on a **single fenced leader**; every side-effecting dispatch is
  emitted through a **transactional outbox with claim-before-side-effect and receiver-side
  idempotency**, so the guarantee is **at-least-once + idempotent receiver = effectively-once**, not
  a magic exactly-once (§6).
- All cross-instance coordination sits behind a **narrow seam with a Postgres-backed default**
  (fenced advisory-lock leader election + `LISTEN`/`NOTIFY`-as-hint over durable outbox tables with a
  reconnect cursor-poll), pluggable for SaaS without touching call sites. **Design for flexibility,
  implement one.**

### Guiding principles

- **Minimize infrastructure the customer must operate.** Prefer primitives that ride the Postgres
  they already run over standing up etcd/ZooKeeper/Consul/NATS/Redis. Where we ship a clustered
  dependency (HA Postgres), **we package and operate it inside the delivery bundle**.
- **Server-tier HA and storage HA are orthogonal axes.** Multi-instance servers can run against a
  single Postgres (Postgres an accepted SPOF) *or* against HA Postgres. Nothing in the server design
  *requires* Postgres to be HA.
- **Make it durable, resume anywhere.** Survivable state becomes durable and keyed so any instance
  can pick it up; **LB stickiness is a later locality optimization, never a correctness requirement.**
- **Promise only what the protocol guarantees.** No claim of exactly-once, location-transparency, or
  monotonicity that the mechanism does not actually deliver (see *Guarantees and non-guarantees*).

## Deployment topology and replication axes

This ADR must serve **both** the current monolithic server **and** the accepted (design-only,
binds-prospectively) presentation/core/engine decomposition of ADR-0031/0032/0033. Today all these
roles are **one binary**, so "behind the LB" trivially means the whole server; prospectively they
split and HA is defined over **independent replication axes**. Crucially, **the operator-plane load
balancer fronts _presentation_, not core** (ADR-0031: presentation "terminates HTTP, SSE and MCP" and
is "inside the bearer-credential trust boundary"; sessions/replay "move behind the core boundary"
precisely so **presentation** can scale horizontally). "Server tier" in this ADR is the collective
replicated server-role set — **presentation + core as two distinct axes** — *not* a fused
server+everything box, and *not* core alone:

- **Presentation replicas** — **terminate HTTP/SSE/MCP and front the operator-plane LB**, inside the
  bearer-credential trust boundary (ADR-0031); dashboard/HTMX render + protocol framing; **no `yuzu`
  database access of their own**; scale horizontally once sessions are durable (§4). SSE/MCP client
  streams are terminated here and **relayed from core's event spine** — presentation never reads the
  `yuzu` outbox directly (§5).
- **Core replicas** — the **API authority and sole `yuzu`-database writer**, and the owner of
  coordination (leader lock, transactional outbox, background workers; §§3/5/6). Sits **behind
  presentation**, not directly on the LB; `/readyz` gates presentation→core routing (ADR-0031: an LB
  must never be routed to a surface that can't serve while core is down). §§3–12's "operator plane"
  spans both roles — presentation terminates, core adjudicates.
- **Gateway replicas** — the per-zone gateway clusters (§7, §7a).
- **Engine replicas / jobs** — use-case engine host (UCE) instances, headless, consuming core through
  the versioned API as engine principals (ADR-1005), with their **own derived-state database** distinct
  from `yuzu`. So **`yuzu`-database availability and engine-database availability are separate axes**,
  and an engine outage must not take down core.

**Boundary rule (ADR-0031 INV-31-3, no cross-component DB access) — governs every section below.**
Only **core** touches `yuzu`: all reads/writes, `LISTEN`/`NOTIFY`, advisory locks, the event outbox,
and **session validation** are core's. **Presentation holds no `yuzu` handle** — it terminates the
client protocol, forwards credentials, and reaches durable state *exclusively through core's versioned
API*; it receives events over a **core→presentation event spine** (a resumable SSE/gRPC stream core
exposes, cursor-owned by core). The southbound **gateway gRPC** likewise terminates on **core**, on a
core service endpoint distinct from the operator-plane LB. Therefore, wherever a section below says
"every server," "any instance," or "server tier" *does* DB or coordination work, read **"every core
replica"**; presentation's role is protocol termination + relay, never direct durable-state access.

**Consequence for NVD (finding 1):** NVD/CVE sync and matching are being **strangled OUT of the server
into the UCE engine** (ADR-0023; ADR-1005 execution-plan Phase 7). Their HA is an **engine-tier**
concern (engine replicas/jobs + the engine DB + leader-among-engines for the sync job) — **not** a
server store leader-synced into `yuzu`. The earlier draft's "NVD leader-syncs to shared Postgres" is
**withdrawn** (§9). The `Server tier` glossary term spans **presentation + core** accordingly (the LB
fronts presentation; core is the API authority behind it), so it does not codify a fused
server+everything model.

## Guarantees and non-guarantees

- **Command dispatch: effectively-once.** At-least-once delivery via a transactional outbox +
  claim-before-side-effect, made effectively-once by **receiver-side idempotency** — the **agent**
  dedups on a stable `command_id` at the true endpoint. (The gateway forwards **transparently
  (unconditionally)** and does **not** itself dedup today — verified in `yuzu_gw_agent.erl`, which
  overwrites its `command_id`-keyed correlation entry; agent-side dedup alone is sufficient at the
  endpoint, so a gateway-side check is an optional future optimization, not a correctness dependency.)
  **This depends on a receiver mechanism that does not durably exist yet:** the agent's dedup is today
  two in-memory `std::unordered_set`s
  (`dedup_current_`/`dedup_previous_`, `agent.cpp:3464`) **`.clear()`d on every fresh connection**
  (`agent.cpp:2484`), so an agent reconnect or daemon restart — the most common failure mode — wipes
  it. **Durable agent-side command idempotency is therefore a named prerequisite workstream** (WS-0),
  not an existing property; until it lands the end-to-end guarantee degrades to at-least-once across an
  agent bounce. **WS-0 must also durably retain and _replay the terminal outcome_, not merely suppress
  the duplicate:** today a duplicate returns a bare `REJECTED` (`agent.cpp:2497`), which correctly
  stops re-execution but **loses the original success result** when the *first* acknowledgement was the
  thing that got lost (execute → succeed → ack dropped → re-drive → `REJECTED`, original outcome gone).
  So the durable store must return the *stored original outcome* on a duplicate — otherwise the honest
  guarantee is only **"effect-once, result-maybe-lost,"** which the ADR would then have to state. We do
  **not** promise exactly-once (a crash between claim commit and RPC send is unavoidable; durable
  receiver dedup **plus outcome-replay** is what closes it).
- **Events/SSE: at-least-once with gap detection.** Durable monotonic event IDs; consumers replay
  from a cursor / `Last-Event-ID`; NOTIFY is a latency hint only. A consumer may see a duplicate
  event and must tolerate it.
- **Leadership: fenced, not exclusive-by-wall-clock.** A fencing token is checked in the same
  transaction as every side-effecting claim; two momentary leaders cannot both commit the same
  occurrence.
- **Durability: selectable.** RPO=0 holds **while a synchronous-commit quorum is available**; the
  shipped default is 3-node quorum (see §11/§13). It is *not* "writes always available" — loss of
  quorum blocks writes by design (fail-closed, consistent with ADR-0007).
- **Session expiry: absolute wall-clock, DB-clock-integrity-dependent.** Moving sessions to Postgres
  trades per-host monotonicity for a single shared wall clock; this is weaker on the monotonic axis
  and depends on DB-primary clock integrity (§4).

## Decisions by area

### 1. Availability model — hybrid (Q1)
Active–active operator plane; gateway-concentrated agent plane; fenced-leader background work.
Chosen over active-passive and over full active-active agent-stream distribution.

### 2. Agent plane — gateway-fronting mandatory in HA (Q2)
No server holds a direct agent `Subscribe` stream in an HA deployment; all agents terminate on the
gateway cluster and servers hand commands to it. Direct-connect stays supported for single-server
installs. **Honest pricing (per review):** gateway-fronting does *not* make the routing problem
disappear — it **trades cross-server stream routing for (a) a fenced agent→cluster directory in
Postgres, (b) net-new distributed intra-cluster agent→node routing inside each gateway cluster, and
(c) the pending-dispatch retry loop** (§7). That is still a favourable trade — one place agents
terminate, the existing replay/circuit-breaker path, trust-zone isolation — but the team is asked to
judge it against the active-active-streams alternative with the intra-cluster cost **priced in**, not
assumed free.

### 3. Coordination substrate — seam + Postgres default (Q3)
Narrow interfaces — a **fenced** `LeaderElector` and a cross-instance signal/event channel
(`NOTIFY`-as-hint over a durable outbox table with a **mandatory reconnect cursor-poll + periodic
safety poll**). Ship only the Postgres implementation; a SaaS backend (Redis/NATS) drops in without
touching call sites. Constraints this imposes (backend affinity, no transaction-mode pooler on
coordination connections) are in §10.

**Fencing token, made explicit (finding 3):** the advisory lock provides mutual exclusion only while
its owning connection lives — it says nothing about a *paused* former leader resuming work after the
lock silently moved. So leadership carries an explicit **monotonically-increasing epoch** (a Postgres
sequence bumped on each acquisition; the acquirer records `current_leader_epoch`). Every
side-effecting claim (§6) checks `claim.epoch == current_leader_epoch` **in the same transaction as
the claim**, independent of whether the actor still *believes* it holds the lock. A stale ex-leader
therefore cannot commit a claim even in the window before it notices its lock dropped.

### 4. Operator sessions — durable in Postgres, absolute wall-clock (Q4)
Sessions move from the in-memory map (`AuthManager::sessions_`, `steady_clock`) to durable Postgres
rows **core validates**, executing the ADR-0031 direction. Presentation terminates the request and
**forwards the credential**; **core owns** validation, the short-TTL cache, the generation token, and
live revalidation (ADR-0031: presentation is inside the bearer-credential trust boundary but is not a
`yuzu` reader) — any core replica can validate any session. **This ADR explicitly reverses the
as-built in-memory-monotonic decision** (chosen for NTP-step resistance of `expires_at` /
`elevated_until` / MFA step-up, `auth.hpp`). The trade, stated honestly (correcting an earlier draft's
false "better by construction" claim):
- Postgres `now()` is **transaction-start wall-clock, not monotonic**. A backward clock step on the
  DB primary would *un-expire* sessions and *extend* live JIT-elevation and MFA step-up windows.
- `now()` **does** fix cross-*host* skew (the reason the in-memory map can't simply be shared), but
  **regresses** the monotonic property on the DB host.
- Mitigations required by this decision: (a) treat DB-primary clock integrity as a security
  dependency (monitor for backward movement; alert); (b) the **security-sensitive short windows**
  (JIT elevation, MFA step-up) are stored as absolute timestamps **and** additionally bounded by an
  issue-time + max-delta check evaluated server-side, so a backward DB step cannot silently lengthen
  an elevation beyond its authored maximum. Threat model is weaker than the endpoint case (the DB
  host is trusted operator infrastructure), which is why this is acceptable — but it is a reversal
  with a real regression, not a free win. A short-TTL cache + generation token (the `rbac_store`
  pattern) keeps sessions off the hot path. LB stickiness is a later locality optimization.

  **Invariant docs superseded by this decision (finding 4)** — accepting §4 contradicts two
  routed-concern rows as written, which must be updated in the same change: the **AuthDB row**
  ("Sessions are in-memory-only — no durable session surface on this store") and the **clock-guarded
  retention** row's carve-out ("NOT the `auth_db` session sweep — sessions moved out of AuthDB with
  the Postgres migration and live in-memory on a MONOTONIC clock, immune to this hazard by
  construction"). Once sessions are durable Postgres rows on a wall clock, the session sweep is **no
  longer exempt** from the clock-guard rule and must adopt the guarded shape. Listed under
  *Consequences*.

### 5. Event / SSE fan-out — durable outbox + NOTIFY-as-hint (Q5)
`ExecutionEventBus` becomes a **local** fan-out fed by a **dedicated append-only Postgres event
outbox** with **durable monotonic event IDs** (replacing the per-process channel counters,
`execution_event_bus.cpp:62`). Invariants (per review):
- **Atomic outbox write:** the source-state mutation and the event-row insert commit in **one
  transaction**; `NOTIFY` fires after commit. A crash therefore never leaves state without its event
  or vice versa.
- **Delivery:** every **core** replica `LISTEN`s and, **on every (re)connect to the promoted primary,
  polls the outbox forward from its last-seen cursor**, plus a periodic safety poll — NOTIFYs issued
  around a failover are lost and must not be relied on. Core re-publishes onto the **core→presentation
  event spine**; presentation-terminated SSE/MCP consumers replay via `Last-Event-ID` / `?since=`
  against **core's spine API** (never the `yuzu` outbox directly) and **tolerate duplicates**
  (at-least-once). Cursor ownership: the client cursor is core's; presentation is a stateless relay.
- The outbox inherits the **clock-guarded retention** rules (routed concern).

**Load-bearing prerequisite:** cross-instance correlation requires execution state in Postgres.
`execution_tracker` (SQLite) and `cmd_execution_ids_` (in-process map, `agent_service_impl.hpp:330`)
migrate to Postgres, and their counter updates (`agents_responded` / `agents_success`) MUST be
**atomic SQL** (`SET x = x+1` / `RETURNING`), never app-side read-modify-write — the hazard class
CLAUDE.md already flags for `sqlite3_changes()` (concurrent responses now land on multiple
instances).

**Status (WS-1(1b)): SATISFIED.** `execution_tracker` migrated to Postgres via ADR-0065
(fresh-start, no SQLite backfill); its `agents_responded`/`agents_success`/`agents_failure` counters
are recomputed in-transaction from `agent_exec_status` via correlated `COUNT(*)` inside
`UPDATE ... RETURNING`, never app-side read-modify-write. `cmd_execution_ids_` moved to
`ExecutionTracker`'s PG-backed `command_execution` table (`record_command_execution`/
`lookup_execution_id`), closing the cross-replica hazard this prerequisite names — see
`docs/executions-history-ladder.md`.

### 6. Background workers — fenced leader + transactional outbox (Q6)
A single **core** instance holds the **fenced** leader lock and runs the singleton loops. The correctness
model, corrected per review — a claim alone does **not** give exactly-once, because a crash between
claim-commit and the external send is unavoidable:
- **Claim-before-side-effect is the invariant** (as `DeploymentEngine` already does,
  `deployment_engine.cpp:125` — claim `staged→executing`, *then* dispatch). Any refactor that
  dispatches before the occurrence-CAS re-opens double-fire and is prohibited.
- **Transactional outbox:** a side-effecting dispatch commits a `pending` outbound-command row (with a
  **stable occurrence/command ID**) in the same transaction as the state transition; a claimed
  delivery loop drives `pending → sent`. A crash re-drives from `pending`.
  - **Documented exception — the stable-occurrence-key producer (WS-3 3.3, `CommandOutboxStore`).**
    A producer whose state transition lives in a *different* store than the outbox cannot literally
    share one transaction with the enqueue. `CommandOutboxStore` therefore ships **two** enqueue APIs:
    `claim_and_enqueue_on(conn, …)` for a future producer whose state IS in Postgres and CAN share the
    txn (the literal contract above), and the autocommitting `claim_and_enqueue(…)` for a producer
    whose transition is a separate write. The **first and only wired producer, `ScheduleRunner`**, uses
    the latter: its transition (`ScheduleEngine::advance_schedule`) is a separate write, committed
    *after* the enqueue. This is a **deliberate, reviewed substitute for same-txn atomicity, not a
    violation of the guarantee**: the `occurrence_id` is a deterministic PRIMARY KEY, so a crash between
    the enqueue commit and the advance re-derives the identical key and reads `AlreadyEnqueued` on the
    re-fire — no lost fire (enqueue commits *before* advance, and advance runs only on enqueue success)
    and no double fire. The one non-atomic consequence — a second producer-side execution row + a
    duplicate `queued` audit on the re-fire — is suppressed at the producer (the re-fire cancels its
    duplicate execution row and does not re-audit). Restoring literal same-txn atomicity via
    `claim_and_enqueue_on` is tracked (#4165) as a cleanliness improvement, not a correctness fix.
- **Receiver idempotency:** the **agent** dedups on `command_id` at the true endpoint (the gateway
  forwards transparently, no gateway-side dedup today), so an at-least-once re-drive is effectively-once
  — **contingent on WS-0** making the agent's dedup durable (today's `dedup_current_`/`dedup_previous_`
  are in-memory and cleared on reconnect, `agent.cpp` `dedup_current_.clear()`).
- **Fencing token in the claim transaction:** every claim CAS checks the leader's fencing token, so a
  stale ex-leader cannot commit a claim even before it notices its lock dropped. A boolean "I am
  leader" cached outside the lock connection is prohibited.
- **`PolicyEvaluator` remediation is redesigned** (WS-3 3.4 LANDED): it now claims each target durably
  before dispatching the fix via `PolicyStore::claim_remediation` (a durable per-(policy,agent) CAS
  guarding `remediation_claim_at`, migration v2), dispatches only to the claimed subset, and releases
  the claim at FixWait maturation or when an undelivered target's stranded-fixing sweep window expires.
  The mechanism is a plain guarded-column CAS on an ordinary pooled connection, NOT the leader epoch
  fence — the operator-synchronous remediation path runs on any replica and must never be leader-gated.
  Both code-level findings (6a) are addressed: (i) `dispatch_instruction` now threads `sent_count`
  through so "all targets offline" is a real signal; (ii) failed delivery does not burn a retry
  attempt — a claimed-but-undelivered target (offline / quarantined / plugin-absent) releases the
  claim without consuming the attempt, so retry logic stays correct under HA. Behavioral change
  operators may notice: a `remediate()` for a target that has exhausted its fix-retry cap is now
  refused at claim time (HTTP 409, message: "remediation already in flight or retry cap reached for
  this policy") rather than dispatching a wasted extra fix.
- Already-correct guards (Deployment CAS, retention/rotation advisory locks) stay as
  defense-in-depth; idempotent/read-only loops run leader-only with no claim.

**Status (WS-3): 3.1 done (#4011); 3.2 done (#4134); 3.3 done (#4169); 3.4 LANDED.** `leader_elector.{hpp,cpp}`
exists (the fenced-lock primitive) and is wired in `ServerImpl` for the leader-election loop (3.2).
The transactional command outbox (3.3) has merged; `PolicyEvaluator` remediation redesign (3.4)
has landed with the durable per-(policy,agent) claim.

### 7. Gateway cluster topology + routing (Q7)
**Independent gateway clusters, one per trust zone / region** (internal-vs-external is a trust
boundary; Erlang distribution's shared-cookie mesh must not span a DMZ or WAN). Zone/region is the
cluster unit; intra-zone scale is more nodes.

- **Fenced agent→cluster routing directory in Postgres.** The record is
  `(agent_id, cluster_id, gateway_node, connection_epoch, session_id, lease_until)`, written on
  `ProxyRegister` with **conditional (CAS) register/deregister** keyed on `connection_epoch` — a
  delayed replay from an *older* connection **cannot overwrite** a newer re-home (the bug an
  unconditional self-healing write would create). A lease that expires without renewal marks the
  route stale.
- **Net-new intra-cluster routing (corrected claim).** Today `yuzu_gw_router:send_command` resolves an
  agent via node-local ETS (`yuzu_gw_registry.erl:90`) and returns `not_connected` on a miss — a
  targeted command landing on the wrong node of the right cluster fails even though a sibling holds
  the stream. **`pg` provides broadcast groups, not per-agent location transparency.** So each cluster
  needs a distributed agent→node lookup (a per-agent `pg` group, a global registry, or fan-and-filter)
  — explicit net-new work in workstream 4, **not** an existing property.
- **Southbound (gateway→core):** each cluster's upstream targets **core** on a dedicated **core
  service endpoint (its own VIP or node list), distinct from the operator-plane LB** — the gateway
  gRPC surface is core's (B7), not presentation's and not the operator LB's. Generalizes the existing
  single-upstream + circuit-breaker + `ProxyRegister`-replay path from one address to the core tier.
- **Northbound (server→gateway):** the minting server reads the directory and dials the owning
  cluster; an undeliverable command (cluster unreachable, stale/expired lease, agent mid-migration)
  stays `pending` in the outbox (§6) and is re-driven — with receiver dedup absorbing any double
  delivery during a re-home race.
- **`gateway_node` convergence is a first-class requirement (finding 6b).** Today an agent's
  proxied-vs-direct routing hinges on `gateway_node` being populated by a **single `NotifyStreamStatus`
  gRPC call** succeeding (`GatewayUpstreamServiceImpl::NotifyStreamStatus`, which calls
  `registry_.set_gateway_node`, `gateway_service_impl.cpp:637`/`:660`); if that notification is lost, dispatch
  falls through to a **direct-stream branch that never reaches the proxied agent**. With
  gateway-fronting mandatory, WS-4 must make this **converge, not depend on one delivery** — a periodic
  reconcile that re-derives the fenced directory after a **gateway restart, a core restart, and a
  dropped registration notification**, not only the re-home race.
- **Agent-side:** agents are **pinned to their zone's cluster** (no cross-zone failover). Within a
  cluster they connect through a **cluster-front (VIP / DNS-multi / node list)** and reconnect on node
  loss. Both gateway endpoints are addressable by **VIP or node list — support both**.

**Status (WS-4): 4.1 done; 4.2a (writer-path hardening) done; 4.2b (Tasks A–D: store layer, per-site
fail-closed posture + renew correlation, dispatch-wiring, `route_unreadable` consumer + alert rule) done
— see below.** The fenced agent→cluster routing directory exists (`GatewayRouteStore`,
`gateway_route_store.{hpp,cpp}`, Postgres schema `gateway_route_store`) and is written on the
gateway-upstream connect/disconnect/heartbeat paths. **The directory is no longer literally INERT** —
Task C wired `GatewayRouteStore::lookup_routes` into confined dispatch as a FALLBACK-ONLY consult
(`dispatch_route_fallback.hpp`'s `GatewayRouteFallback`): one batched read per arm walk, fired only for
candidates the local `AgentRegistry` has no live session for, and every send still passes the existing
`authz::in_scope` confinement intersection before it goes out — the reader only supplies a `cluster_id`
for an already-confined send, never bypasses it. **This changes ZERO monolith routing outcomes**: a
direct-connected agent never gets a `GatewayRouteStore` row (only the gateway-service writer path
writes rows), so on today's single-replica monolith a local miss means the agent is genuinely absent and
the fallback consult only ever CONFIRMS "no route." Proven in Task C's own test suite ([dispatch] 2163
assertions unchanged-green plus a decoy-directory-row test where a locally-known agent ignores a
deliberately-wrong directory row). A routable local-miss queues via the new
`AgentRegistry::send_via_directory` onto `gw_pending_`, carrying an optional `cluster_id` that is INERT
until 4.3 (one `gw_mgmt_stub_` today, so multi-cluster fanout does not exist yet). The epoch in "delayed
replay from an older connection cannot overwrite a newer re-home" is a **server-internal** monotonic
counter minted at `ProxyRegister` (never on the wire) that orders a fresh registration against the
existing row via a guarded upsert; concretely, the delayed-replay scenario this closes is the gateway's
circuit-recovery ProxyRegister REPLAY, which now carries the agent's existing `x-yuzu-session-id`
outgoing metadata so the server re-announces (reuses the session) rather than minting a new one. Every
post-register write (`announce_connected`/`deregister`/`renew_leases`) is instead guarded by
**`session_id` equality** — the epoch settles who WINS a fresh registration race, `session_id` settles
who may touch the row afterward. The wire gained only `StreamStatusNotification.cluster_id`. Posture was
fail-open on every runtime write failure through 4.2a; slice **4.2a** hardened the writer path itself
(tombstone semantics, a stale-route reaper, a fresh-epoch-clobber fix, guard-rejection visibility) but
deliberately deferred the fail-closed flip to **4.2b**. **4.2b Task B landed that flip as a PER-SITE
contract, not a uniform one**: `register_fresh` (the row-CREATING write) is fail-closed, the other five
writes stay fail-open (see the design-obligations bullets below for the full rationale). **4.2b Task D**
consumed the degraded-read case Task C defined (`ConfinedDispatchOutcome::route_unreadable`): the
command-outbox delivery loop now RESCHEDULES on it (a new
`yuzu_server_command_outbox_deliver_retry_cause_total{cause}` counter separates the two causes), and it
is discriminated at all FOUR operator-facing zero-reach cascade sites that can actually reach it
(#3424/#3511: `mcp_server.cpp`/`command_routes.cpp`/`workflow_routes.cpp`/`dashboard_routes.cpp`) —
`server.cpp`'s legacy-forward site is Broadcast-only and correctly carries no `route_unreadable` branch
(`ArmDispatchResult::route_unreadable` can never be set on that path) — plus two
additional `ConfinedDispatchOutcome` consumers a grep of every `containment_unreadable` site caught
(`deployment_engine.cpp`, `policy_evaluator.cpp`). **`route_unreadable` is deliberately NOT
interchangeable with `containment_unreadable`** (Gate-8 finding UP-1): a fail-closed containment gate
withholds every id BEFORE its send, forcing `sent == 0`, whereas a degraded directory read leaves the
dispatch arm walk running — so a locally-connected device is genuinely sent while a directory-only
device lands in `not_sent`. The command outbox can therefore reschedule the whole occurrence safely (it
re-drives the STABLE `command_id`, so a re-send is absorbed by WS-0 receiver dedup and the terminal
outcome replayed), but the two store consumers must NOT treat it all-or-nothing: `deployment_engine`
lets a `route_unreadable` device revert INDIVIDUALLY via `not_sent` (a whole-batch revert would send an
already-executing installer back a step and re-dispatch it next tick under a FRESH `command_id` that
dedup cannot absorb — a double-execution), and `policy_evaluator` reports genuinely-delivered devices as
delivered rather than whole-batch-undelivered. `YuzuGatewayRouteWriteFailed` (#4246 #1's alert-rule half)
and `YuzuGatewayRouteUnreadable` (the closest available signal for #4246 #8's alert-rule half) both ship
with this slice in `docs/prometheus/yuzu-alerts.yml`'s `yuzu-gateway` group — see the design-obligations
bullets below. **What remains OUT of scope for 4.2b**: multi-cluster gateway fanout (4.3, today one
`gw_mgmt_stub_`), the durable cross-replica session lookup (#4246 #3, re-homed to WS-5) — the reader
stays FALLBACK-ONLY and behaviorally inert until that lands and makes a local miss actually mean
something on a multi-replica deployment — and `gateway_node` convergence reconcile (4.4). The #4324
per-home stream-generation fence (re-scoped from #4246 #4) is now CLOSED and MERGED to `origin/dev`
(PR #4492, `c37306113`, 2026-09-17 — see the #4324 status paragraph below); 4.2b's review RE-VERIFIED the once-per-session property this section
already established before landing the reader (see the design-obligations bullet on #4 above and the
4.2b status paragraph below for the re-verification citation), and #4324's own slice re-verified it a
second time before making the fence live (`governance.d/ha-ws4-4324-stream-fence-reverification.md`).

**4.2 design obligations surfaced by the 4.1 governance review (load-bearing now that 4.2b Task C made
the directory dispatch-authoritative, fallback-only; the "cannot overwrite a newer re-home" guarantee
above is precise only for *overwrite*, and only intra-replica with a live session). Tracked as `#4246`;
**slice 4.2a closed items #2, #5, #7, #8's counter half, and #9**, **4.2b Task B closed #10 and
partially closed #1**, **4.2b Task D shipped the #1 and (partial, via `route_unreadable`) #8
alert-rule halves** (#4 RE-SCOPED, not closed — see its bullet):**
- **Epoch orders by server PROCESSING time, not connection recency** (#4246 #2 — **CLOSED, 4.2a**). The
  `nextval` is minted when a ProxyRegister is *handled*. A zombie/delayed replay whose original session
  has already left the in-memory `gateway_sessions_` map (post-DISCONNECTED, a replica restart, or a
  cross-replica fan-out) previously fell into the FRESH branch, minted a *higher* epoch, and WON the
  CAS. **4.2a closes this**: `ProxyRegister`'s mechanism (c) branch — a presented session unknown to
  this replica's `gateway_sessions_` — now renews the PRESENTED session in the directory instead of
  calling `register_fresh`, so it never mints a fresh epoch or reaches the clobbering branch. The
  session-id-minting/`gateway_sessions_`-population half of the gap (the S′-vs-S response desync) is
  unchanged — see the next-but-one bullet.
- **The re-announce REUSES the session id, so a late DISCONNECTED for that same id could tombstone the
  live re-homed route** (#4246 #4 — **RE-SCOPED to #4324, CLOSED end-to-end as of that slice** (pending
  merge on `feat/ha-ws4-4324-stream-fence`, tasks `46f1e72b6`/`4b248b504`/`feabccea7`) — see the #4324
  status paragraph below for the closing mechanism; the historical analysis that follows records why the
  gap was unreachable under the shipped gateway protocol at the time it was re-scoped, not the current
  state). The MECHANISM is real and confirmed: `deregister`
  (`gateway_route_store.cpp`) predicates its tombstone only on `agent_id AND session_id` with no
  per-home discriminator; the re-announce reuses the session id; and the in-memory teardown
  (`gateway_service_impl.cpp` `clear_stream_if_session`/`remove_agent_if_session`/`gateway_sessions_.erase`)
  is likewise session-keyed. What 4.2a's TOMBSTONE actually closed is the OPPOSITE direction — item #5,
  the late-`CONNECTED` resurrection: `deregister` now nulls `session_id`/`lease_until`/`cluster_id`/
  `gateway_node` (retaining `connection_epoch`) instead of deleting, so a late CONNECTED for a now-gone
  session no-ops against the tombstone (see the `announce_connected` fallback-INSERT bullet below). It
  does NOT fence a same-session late-`DISCONNECTED` against a newer re-home, because the SQL has no
  per-home generation. **This direction has no producer under the shipped gateway** and so is
  unreachable today: `CONNECTED(S)` is emitted at most ONCE per session (`yuzu_gw_agent.erl:129`, in a
  single-shot process; the `connecting(cast,{stream_ready,_})` re-attach clause at `:143` has no
  PRODUCTION sender (only the gen_statem unit test casts it) and in any case emits no `CONNECTED`; every
  stream loss runs `do_cleanup` → the one `DISCONNECTED` at `:331` and stops). At-most-once is
  *guaranteed*, not incidental: admission funnels through `yuzu_gw_registry:take_pending/1`, which uses
  `ets:take/2` — a single ATOMIC retrieve-and-delete — so of N concurrent `Subscribe`s presenting the
  same session id exactly one consumes the pending registration and spawns an agent (the others get
  `undefined`); a per-`Subscribe` process races here on a `public` ETS table with no other serialization,
  and this atomicity is the whole guarantee (a non-atomic lookup-then-delete previously let two win — PR
  #4299 round 6). Pinned by the concurrent-barrier test in `yuzu_gw_registry_tests.erl` (exactly one
  winner across many barrier-released rounds; verified RED on the old lookup+delete). A
  normal agent reconnect uses `proxy_register/1` → plain `do_rpc` with NO `x-yuzu-session-id`
  (`yuzu_gw_upstream.erl:174-181`), so it takes the server's FRESH branch and is minted a new session
  `S'` (a late `DISCONNECTED(S)` then misses the `S'` row — `session_mismatch`, expected); only the
  circuit-recovery REPLAY (`do_rpc_replay`, `:547-550`) re-announces `S` — and BOTH replay branches
  (presented-session-known AND the presented-but-unknown "mechanism (c)", a replica restart) re-announce
  via `renew_leases`, never `register_fresh`, emitting NO `CONNECTED`. `renew_leases` is session-guarded
  (`WHERE session_id = ANY(...)`), so it can neither resurrect a tombstone (whose `session_id` is NULL)
  nor clobber a newer session's row; in either arrival order the route is correctly torn down — a
  delivered `DISCONNECTED(S)` tombstones it, and a `DISCONNECTED(S)` that `yuzu_gw_upstream` drops
  (circuit-open, or the `MAX_NOTIFY_INFLIGHT` inflight cap) leaves it to lease-expiry + the stale-lease
  reaper — and nothing resurrects a newer placement because none exists under a reused `S`. So there is
  AT MOST ONE `CONNECTED(S)` and one `DISCONNECTED(S)` per session (an untrappable process/node kill or a
  dropped notification only shrinks that count); the only reorder is item #5, which IS closed. The
  invariant to hold: **`session_id` ≡ exactly one gateway stream placement.** The per-home generation fence
  (a token stamped on both `CONNECTED`/`DISCONNECTED` — a `NotifyStreamStatus` protocol change, spanning
  the legacy in-memory teardown path too, NOT a store-only change) is deferred to the first slice that
  introduces a same-session re-CONNECT (4.3 intra-cluster re-home / 4.4 convergence / #6 replay-response
  writeback). **4.2b's review RE-VERIFIED this once-per-session property before landing Task C's
  dispatch wiring** (`governance.d/ha-ws4-42b-4324-reverification.md`): the single `CONNECTED` emit site
  is unchanged (`yuzu_gw_agent.erl:129`, a single-shot process), admission still funnels through
  `yuzu_gw_registry:take_pending/1`'s atomic `ets:take/2` (unchanged by the merged 4.2a, PR #4299), and
  the concurrent-barrier test in `yuzu_gw_registry_tests.erl` (exactly one winner across many
  barrier-released rounds) is still present and green. Tracked in #4324 (re-scoped from #4246 item #4) —
  4.2b landed only the re-verification; **the per-home fence itself is CLOSED as of #4324's own slice,
  MERGED to `origin/dev`** (PR #4492, `c37306113`, 2026-09-17; see the #4324 status paragraph below):
  `StreamStatusNotification.stream_home_id`
  (field 8, opaque per-connection-instance id minted once per `yuzu_gw_agent` process, task 1,
  `46f1e72b6`), `GatewayRouteStore`'s asymmetric tombstone predicate on the new nullable
  `stream_home_id` column (task 2, `4b248b504`, migration v3), and `gateway_service_impl.cpp`'s
  `NotifyStreamStatus` DISCONNECTED branch resolving an identical fence against `AgentRegistry`'s
  in-memory `gateway_stream_home_id` once, before the registry-clear/store-deregister/session-map-erase
  effects run (task 3, `feabccea7`). #4324's own review re-verified the once-per-session property a
  second time before landing this wiring (`governance.d/ha-ws4-4324-stream-fence-reverification.md`).
  Deliberately NOT closed by #4324: a stale `DISCONNECTED(home1)` landing BEFORE the matching live
  `CONNECTED(home2)` (two independent RPCs, no ordering guarantee) still tombstones the row, and
  `announce_connected`'s `ON CONFLICT DO NOTHING` fallback cannot re-arm a tombstoned row — left for 4.3
  (see `gateway_route_store.hpp`'s file-header FORWARD NOTE). The `duplicate_connected` positive
  tripwire on `yuzu_server_gateway_route_desync_total{op="notify_stream_status"}` that #4324's own issue
  checklist deferred is tracked separately as `#4464`.
- **The re-announce/"known-session" check is PER-REPLICA in-memory** (`gateway_sessions_`) (#4246 #3 —
  **DEFERRED**, re-homed to its own slice under WS-5 shared agent presence, ADR §7a); under
  active-active a replay routed to a non-owning replica always takes the fresh branch. A durable
  cross-replica session lookup is required before the guarantee holds on more than one replica.
- **Re-announce refreshes LIVENESS (lease), not PLACEMENT** — `cluster_id`/`gateway_node` are not
  re-read on the replay branch, and a fresh re-register COALESCE-preserves the OLD cluster/node until a
  CONNECTED `announce_connected` lands; a 4.2 reader must not trust placement from a replay/fail-open
  window. Unaffected by 4.2a.
- **A stale-lease reaper is required** before 4.2 (#4246 #7 — **CLOSED, 4.2a**) — a missed DISCONNECT
  leaves an orphan lease (growth is PK-bounded, so not a capacity risk, but a dead route reads live).
  **4.2a closes this**: `GatewayRouteStore::reap_stale_routes()`, a clock-guarded background pass
  (`docs/clock-guarded-retention.md`'s adoption register has the full record) on a ~5-minute cadence,
  sweeps (a) leases expired past a 180s grace window (2× the 90s TTL) — tombstoned, not deleted — and
  (b) NULL-lease rows (tombstones, or a `register_fresh` that never got an `announce_connected`) past a
  300s purge age — hard-deleted.
- **`announce_connected`'s fallback INSERT can RESURRECT a row after `deregister`** when CONNECTED and
  DISCONNECTED race (#4246 #5 — **CLOSED, 4.2a**) — the gateway spawns one sender process per
  notification, no arrival-order guarantee: a late CONNECTED for a just-deregistered session used to
  re-insert `(epoch 0, session S, fresh lease)` for a dead stream. **4.2a closes this** via the same
  `deregister` tombstone change above: the fallback INSERT is `ON CONFLICT (agent_id) DO NOTHING`, and
  against an EXISTING tombstoned row it now no-ops instead of reviving a dead route.
- **The gateway discards the replay `ProxyRegister` response, so a server-minted fresh session desyncs
  silently** (#4246 #6 — **DEFERRED to 4.4**). When the presented session is unknown (core restart /
  replica failover / post-DISCONNECT eviction) the server mints a NEW session and returns it, but the
  gateway's replay path ignores the response and keeps stamping the OLD session id on every
  notify/heartbeat → `renew`/`announce`/`deregister` all miss, the route is stale and wrong-sessioned
  until the agent reconnects or the 4.4 reconcile runs. 4.2a's mechanism (c) (see above) renews the
  *presented* session server-side rather than clobbering it, which narrows the blast radius, but the
  gateway-side session-id writeback itself remains 4.4's fix.
- **Guard-rejection no-ops are unobserved** (#4246 #8 — **counter half CLOSED, 4.2a; alert-rule half
  PARTIALLY CLOSED, 4.2b**). The 4.1 fail-open counter covers only Postgres WRITE FAILURES; a systemic
  guard-rejection desync (e.g. every `renew` matching 0 rows, every `announce` no-opping) moved neither
  a log nor a metric. **4.2a closes the counter half**: `yuzu_server_gateway_route_desync_total{op,
  outcome}` (`op` ∈ `renew_leases`\|`announce_connected`\|`deregister`\|`notify_stream_status`,
  `outcome` ∈ `shortfall`\|`session_mismatch`\|`unknown_session`) — see
  `docs/observability-conventions.md` and `docs/user-manual/metrics.md`. **4.2b ships
  `YuzuGatewayRouteUnreadable`** (`docs/prometheus/yuzu-alerts.yml`, `yuzu-gateway` group), keyed on
  `yuzu_server_command_outbox_deliver_retry_cause_total{cause="route_unreadable"}` (Task D) — the
  closest available signal, since a *degraded directory read* during dispatch is the operationally
  actionable half of "desync." This is deliberately NOT a direct alert on
  `yuzu_server_gateway_route_desync_total`'s guard-rejection outcomes: that counter is expected at a
  low background rate (a post-restart/failover baseline rise, a redelivered `DISCONNECTED`) and a
  threshold that doesn't page on those needs real fleet data first — same reasoning as the #913
  OTA-bounds alert-threshold lesson. The desync counter itself still has no dedicated alert.
- **Correlate `agent_id` on `renew_leases`** (#4246 #10 — **CLOSED, 4.2b Task B**) — renew used to match
  `session_id` alone (defense-in-depth gap against a compromised gateway renewing a foreign session).
  `renew_leases` now takes PARALLEL `agent_ids`/`session_ids` arrays and its SQL correlates on BOTH
  columns (`r.agent_id = t.agent_id AND r.session_id = t.session_id`, a `unnest()` join) — a renew
  presenting the right session but the wrong agent_id now matches zero rows. All three call sites
  (ProxyRegister's two renew branches, BatchHeartbeat) thread the resolved `agent_id` through — the
  DURABLE `(agent_id, session_id)` binding already stored in the directory is the trust anchor, so a
  correlation is deliberately checked against it rather than trusting any caller-supplied value; the
  wire's `HeartbeatRequest` carries no `agent_id` at all (only `session_id`), so `BatchHeartbeat`
  resolves it from the SAME per-replica in-memory `gateway_sessions_` map the #4246 #3 known-session
  check above already uses. This means #10's correlation inherits THAT bullet's limitation, not a new
  one: a heartbeat for a session this replica doesn't locally know is excluded from the renew batch
  (surfaced via `yuzu_server_gateway_route_desync_total{op="renew_leases",outcome="unknown_session"}`,
  new in this slice, rather than silently dropped) and stays that way until the #4246 #3 durable
  cross-replica session lookup lands under WS-5. Unreachable on today's single-replica monolith.
- **Ship the write-failure fail-closed posture + alert rule** (#4246 #1 — **CLOSED, 4.2b**). The flip
  landed as a **per-site contract, not a uniform flip**: `record_route_store_failure`'s six call sites
  keep DIFFERENT postures by design — `register_fresh` (ProxyRegister's fresh-registration branch), the
  ONE row-CREATING write, is fail-CLOSED (returns `UNAVAILABLE`, mirroring the existing #3401
  `register_agent` precedent); the other five (`announce_connected`, both ProxyRegister `renew_leases`
  branches, BatchHeartbeat's `renew_leases`, `deregister`) stay fail-OPEN — see
  `record_route_store_failure`'s header comment (gateway_service_impl.cpp) for the per-site rationale.
  The metrics-doc entries for both counter families exist (`docs/observability-conventions.md`,
  `docs/user-manual/metrics.md`). **The alert rule shipped in 4.2b**: `YuzuGatewayRouteWriteFailed`
  (`docs/prometheus/yuzu-alerts.yml`, `yuzu-gateway` group), a rate-based alert on
  `yuzu_server_gateway_route_write_failed_total{op,reason}` — conservative/INITIAL thresholds, per the
  #913 OTA-bounds lesson that alert thresholds are the top source of external-review findings, to be
  tuned against real fleet data once it exists.

**Status (4.2a, 2026-09-11): writer-path hardening DONE** — `deregister` tombstone semantics,
`reap_stale_routes` (scheduled `ReplicaSafe` in `background_jobs.hpp`, WS-10 classification), the
mechanism-(c) unknown-presented-session fix, the `yuzu_server_gateway_route_desync_total` counter, and
the hot-path/reaper write-timeout split (500ms/2000ms) (#4246 #9 — **CLOSED, 4.2a**) all landed in that
slice.

**Status (4.2b, 2026-09-14): store-layer, writer-path posture, dispatch-wiring, and the
`route_unreadable` consumer all DONE (Tasks A–D).** Task A made `announce_connected` the sole writer of
placement (`register_fresh` NULLs `cluster_id`/`gateway_node` on a winning re-register) and added the
batched `lookup_routes` read. Task B landed the per-site fail-closed contract above (#4246 #1, later
fully closed by Task D's alert rule) and the `agent_id` renew correlation (#4246 #10, CLOSED). **Task C
wired the reader into confined dispatch, FALLBACK-ONLY** — local `AgentRegistry` first, the directory
consulted only on a local-registry miss, agent→cluster granularity — which **changes ZERO monolith
routing outcomes** because a direct-connected agent never has a directory row; confinement
(`authz::in_scope`) is checked before every send regardless of where the routing information came from.
**Task D consumed the resulting `route_unreadable` outcome** (a degraded directory READ, the systemic
sibling of `containment_unreadable`): the outbox delivery loop RESCHEDULES on it instead of marking
`no_agents_reached`, it is discriminated at the FOUR operator-facing zero-reach cascade sites
(#3424/#3511: `mcp_server.cpp`/`command_routes.cpp`/`workflow_routes.cpp`/`dashboard_routes.cpp`;
`server.cpp`'s legacy-forward is Broadcast-only, wires no route fallback, and correctly has no branch)
plus the `deployment_engine.cpp`/`policy_evaluator.cpp` consumers, and the `YuzuGatewayRouteWriteFailed` /
`YuzuGatewayRouteUnreadable` alert rules shipped (`docs/prometheus/yuzu-alerts.yml`). 4.2b's review also
RE-VERIFIED the once-per-session property (#4324) before this wiring landed — see the design-obligations
bullet above. **The directory is no longer literally inert, but it is still BEHAVIORALLY inert on the
monolith** — the fallback path only ever fires for a candidate genuinely absent from the local registry,
and no such candidate today has a directory row to find, so there is no observable routing-outcome
change to validate (see the WS-9 note on `docs/ha-delivery-matrix.md`'s WS-4 row: a failover scenario
for this reader has nothing to exercise until it becomes behaviorally live). Remaining WS-4 sub-work: 4.3
(net-new distributed intra-cluster agent→node routing, multi-cluster fanout — today one
`gw_mgmt_stub_`; 4.3 also owns the pre-CONNECT-race ordering gap #4324 deliberately left open, see its
status paragraph below), the durable cross-replica session lookup (#4246 #3, re-homed to WS-5 — this is
also what makes the reader behaviorally live, since only then can a directory row outlive the writing
replica's own in-memory registry), and 4.4 (`gateway_node` convergence reconcile, replay-response
writeback). The #4324 per-home stream-generation fence itself is now CLOSED — see below.

**4.3a update (2026-09-18): the intra-cluster half of 4.3 is DONE** — per-agent `pg`-group agent→node
lookup within one Erlang gateway cluster (`yuzu_gw_registry.erl`'s `lookup/1`/`lookup_remote/1`), the
`fanout_terminal` cross-node-routing fix (`yuzu_gw_agent.erl`), and `remote_dispatched` telemetry
(`yuzu_gw_router.erl`) — component-complete-and-INERT pending `#4555` (gateway multi-node cluster
formation, entirely unimplemented in production). The pre-CONNECT-race ordering gap is **NOT**
"deliberately left open" as this paragraph previously stated — it is RESOLVED as unreachable BY
INVARIANT (see the #4324 status paragraph's PR-review-fix note below for the full resolution).
Remaining WS-4 work is the REST of 4.3 (cross-cluster gateway fan-out — today one `gw_mgmt_stub_` —
**and** `#4555` cluster formation itself, not fan-out logic alone) and 4.4.

**Status (#4324, MERGED to `origin/dev` — PR #4492, `c37306113`, 2026-09-17T22:05:58Z): the per-home
stream-generation fence is CLOSED end-to-end**, three tasks: task 1 (`46f1e72b6`) adds
`StreamStatusNotification.stream_home_id = 8` to the canonical proto and both gateway-vendored
mirrors — an opaque id the gateway mints once per `yuzu_gw_agent` process instance
(`string:lowercase(binary:encode_hex(crypto:strong_rand_bytes(16)))`, 32 hex chars) and stamps on both
the CONNECTED and DISCONNECTED notification that instance ever sends; task 2 (`4b248b504`) adds a
nullable `agent_routes.stream_home_id` column (migration v3) plus the ASYMMETRIC tombstone predicate
**`stream_home_id IS NULL OR stream_home_id = $3`** (fixed pre-merge, see the PR-review-fix note below —
an earlier, buggy form of this predicate required the incoming value to also be empty) to
`GatewayRouteStore::deregister` — a STAMPED stored home id requires an EXACT match to be torn down,
never a row a stamped CONNECTED has since re-homed, which is what makes this safe across a
rolling gateway upgrade (mixed old/new-build nodes is the normal state of one); task 3 (`feabccea7`)
wires the caller's real `stream_home_id` through `AgentRegistry::set_gateway_route`/a new
`gateway_stream_home_id()` accessor and restructures `gateway_service_impl.cpp`'s `NotifyStreamStatus`
DISCONNECTED branch to resolve the fence ONCE, at the top, before any of the three teardown effects
(registry clear, store deregister, `gateway_sessions_`/`lost_race_sessions_` erase) run — a
design-review-mandated structural fix: fencing only a subset of the three is WORSE than the pre-#4324
unfenced behavior (it would leave a live re-homed session permanently untearable by its own future
events, a stale-placement trap). An oversized incoming `stream_home_id` (>64 bytes) is treated as
malformed and clamped to empty rather than rejected or used unbounded, counted via new
`yuzu_server_gateway_route_desync_total{op="announce_connected"\|"deregister",outcome="malformed_home_id"}`;
a genuine stale-home mismatch counts as
`{op="deregister",outcome="stale_home"}`. A regression test proving the core scenario end-to-end landed
in `tests/unit/server/test_gateway_route_wiring.cpp`. This slice's review RE-VERIFIED the
once-per-session property a second time before making the fence live
(`governance.d/ha-ws4-4324-stream-fence-reverification.md`) — no regression found, same conclusion as
4.2b's own re-verification. **PR-review fix, pre-merge (HIGH)**: external reviewer FortitudeEtc
(Codex+Kimi panel, with empirical reproduction) found the task-2 predicate's ORIGINAL form —
`stream_home_id = $3 OR (stream_home_id IS NULL AND $3 = '')` — wrongly required the incoming value to
also be empty before a stored-NULL row admitted it. Under the single-producer invariant a stored-NULL
home does not only mean "legacy, never stamped" — it can equally mean "this session's own
`announce_connected` (from CONNECTED) hasn't run yet," since the gateway dispatches CONNECTED and
DISCONNECTED as two independently `spawn_monitor`'d RPC workers with no ordering guarantee between
them. So an ORDINARY connect/disconnect (no re-home, just the first and only pair for a brand-new
session) could have its DISCONNECTED reach the server before its own paired CONNECTED; the original
predicate rejected that stamped, legitimate DISCONNECTED, the deregister/fence silently no-opped, and
the delayed CONNECTED then published a route for an already-dead stream — a regression vs. the
pre-#4324 unfenced behavior, reachable under ordinary operational churn with only the first pair
(distinct from, and reachable without, the FORWARD NOTE gaps below, which all require a second
CONNECTED/DISCONNECTED pair for the same session). Fixed to `stream_home_id IS NULL OR stream_home_id
= $3` (commit `f7f12bd59`), mirrored identically in the in-memory fence
(`gateway_service_impl.cpp`'s `home_matches`); a targeted Gate 8 re-review then caught a second stale
copy of the old predicate formula on `deregister()`'s own declaration comment (`5160e0eeb`, doc-only).
Both commits landed pre-merge in the same PR #4492. **Deliberately NOT closed by #4324**: if a stale `DISCONNECTED(home1)`
arrives BEFORE a live re-home's `CONNECTED(home2)` — two independent RPCs, no ordering guarantee
between them — the tombstone still wins and `announce_connected`'s `ON CONFLICT DO NOTHING` fallback
cannot re-arm a tombstoned row, so the re-home is silently unroutable in the directory until the next
full `ProxyRegister`. **Resolution UPDATED (WS-4 4.3a design review, 2026-09-18)**: the previously-stated
"`register_fresh`'s ordered epoch or an explicit re-arm path" was the WRONG mechanism — a
gateway-synthesized fresh session on re-home starves the agent's own heartbeat lease renewal,
reproducing the `#4246` #6 desync deliberately. `gateway_route_store.hpp`'s file-header FORWARD NOTE
now states the actual resolution: this gap is unreachable BY INVARIANT (agent-driven reconnect + the
gateway's `NOT_FOUND` refusal on an unknown session mean no producer of a same-session different-home
`CONNECTED` exists or is planned), backed by a standing design constraint on 4.3/4.4 plus a
server-side tripwire (folds into `#4464`), not a new CAS primitive. See that file's FORWARD NOTE for
the full resolution. The
`duplicate_connected` positive tripwire on
`yuzu_server_gateway_route_desync_total{op="notify_stream_status"}` that #4324's own issue checklist
explicitly deferred (it needs a `gateway_sessions_` value-type change reaching several call sites) is
tracked separately as `#4464`, filed alongside this slice's docs pass.

### 7a. Shared agent presence / health / scope population (new, per review)
`AgentRegistry` is **more than a stream router** — it is also the authoritative **live-agent set,
plugin/help catalogue, session lookup, and the population that scope evaluation runs over**, and scope
eval **drops agents absent from the local live registry** (`agent_registry.hpp:279`). Under
gateway-fronting a gateway replays only to its *currently-selected* upstream, so a second active
server would otherwise see a partial fleet and **mis-target scopes / under-report health**. Therefore
HA requires **shared agent presence**: liveness, per-agent plugin capability, and the scope-evaluation
population become **cross-instance state** (Postgres presence/health tables fed by gateway
registration/heartbeat, **read by every core replica**; presentation obtains it through core's API),
so scope resolution and the `yuzu_agents_connected` gauge are coherent across the core tier rather
than per-instance. This is its own workstream, not a
side-effect of the routing directory.

### 7b. Gateway cluster formation mechanism (`#4555` design, 2026-09-18)
`#4555` established that gateway multi-node cluster formation is **entirely unimplemented** — no
`net_kernel`/`net_adm`/peer-discovery code exists anywhere in `gateway/`, `gateway/config/vm.args.src`
hardcodes `-name yuzu_gw1@127.0.0.1` with a comment telling the operator to hand-edit it per node, and
`docs/erlang-gateway-blueprint.md`'s three named discovery options (static seed nodes / Kubernetes
headless service / AWS Cloud Map or Consul) are documented target-state, never built. This makes 4.3a's
`pg`-based cross-node routing (§7 above) component-complete-and-inert: `pg` group membership only
replicates across *connected* distributed-Erlang nodes, and nothing connects any today. This subsection
records the mechanism-choice decisions for closing that gap, made via a structured design interview
(`/grill-with-docs`) rather than picking from the blueprint's three options by inspection.

**Decision: target only the static/DNS-based discovery family for v1 — no Kubernetes or cloud-registry
discovery.** Yuzu ships zero Kubernetes deployment artifacts (no manifests, no Helm chart) anywhere in
the repo; every shipped topology is Docker Compose plus native Linux/Windows/macOS packaging, and the
precedent for "how a multi-node HA component ships" (WS-7, HA Postgres) is a Compose profile
(Patroni+etcd+HAProxy), not a Kubernetes one. Building Kubernetes- or cloud-provider-specific discovery
against a deployment target this repo cannot validate would be speculative work; the blueprint's Option
B/C remain a documented, explicitly deferred, pluggable future seam (same shape as the coordination
substrate's own Postgres-default-pluggable-for-SaaS pattern, §3 above) rather than v1 scope.

**Decision: peer discovery resolves DNS A records for a configurable seed name, not Kubernetes-specific
`inet_res` code.** The blueprint frames "static seed nodes" and "Kubernetes headless service via
`inet_res`" as separate options, but the underlying *mechanism* of the latter is just "resolve a DNS
name, get back multiple A records" — Docker Compose's own embedded DNS already does exactly this for a
scaled service (`docker compose up --scale gateway=N` resolves the service name to one A record per
replica) with zero Kubernetes-specific code and zero new infrastructure. A gateway node therefore
resolves a seed name (`YUZU_GW_SEED_DNS_NAME`, default `gateway` — matching the reference Compose
service name) to a set of addresses and attempts `net_kernel:connect_node/1` against each. This name is
a **separate config value from `cluster_id`** — `cluster_id` is a logical/database identifier an
operator names freely (a key into the Postgres routing directory), while the seed name is constrained by
whatever the deployment's actual DNS/Compose naming is; coupling the two forces an operator's freely-chosen
logical name to also be infrastructure's literal hostname (or vice versa). A separate
`YUZU_GW_SEED_NODES` env var (an explicit comma-separated address list), when set, **replaces DNS
resolution outright rather than merging with it** — a merge would let two independently-configured
sources silently interact (a leftover test override quietly contributing addresses alongside a working
DNS setup); "when set, this wins outright, full stop" is a simpler invariant, covering the air-gapped /
no-DNS / hand-pinned-IPs deployment case.

**Decision: plain A records, not TXT.** A TXT record could carry an explicit, free-form peer list
(including full node names, not just addresses) — but this only has value if a node's identity needs
more than its address. It doesn't (see below): once every replica shares one fixed short name and
differs only by address, an A record already carries exactly the needed information, and choosing TXT
would forfeit the "free with Compose's `--scale`" property (Compose auto-populates A records for a
scaled service; nothing auto-populates a TXT record, so an operator would be back to hand-maintaining a
list on every scale change — the static-list option this decision otherwise avoids, just relocated into
DNS).

**Decision: gateway node identity becomes dynamic — fixed short name, host part resolved at boot —
rather than the current hardcoded-per-node scheme.** `vm.args.src`'s literal-per-node `-name` is
incompatible with Compose's `--scale`: every scaled replica boots from the identical image and
environment, so they cannot each carry a distinct hardcoded name. Gateway nodes are genuinely
interchangeable (no operator-assigned per-node identity is needed beyond address), so the fix is
foundational rather than incidental to discovery: every node uses the same short name (e.g. `yuzu_gw`),
with the host part **auto-detected at boot** via the node's own resolvable hostname (which, under
Docker/Compose, already resolves back to the container's own address with zero configuration) — overridable
by an explicit `YUZU_GW_ADVERTISE_ADDR` env var for a bare-VM/multi-NIC deployment where auto-detection
is ambiguous, or a container behind NAT where the internal address isn't what peers should dial. The
override silently wins when set, the same "sensible auto-default, explicit env var wins" shape
`YUZU_GW_CLUSTER_ID` already uses.

**Decision: fail-open on discovery failure, with an indefinite fixed-interval retry — no backoff.** A
node that resolves zero peers at boot (DNS failure, empty result, timeout) boots anyway as a
standalone/single-member cluster and keeps retrying in the background, rather than refusing to start.
The gateway's job is agent-facing availability; per-cluster clustering is an internal routing
optimization the gateway does not need in order to correctly serve the agents already connected to it,
and `#4555` must be a strict improvement over today's zero-clustering behavior, never a new way for a
discovery hiccup to become an agent-facing outage. The retry loop uses a **fixed interval, indefinitely**
(matching this codebase's existing retry idiom — `await_net_kernel_start`, `await_connected`,
`await_lookup` are all fixed-interval, not exponential backoff) rather than exponential backoff: DNS
query volume at this scale is negligible, while slow convergence after a deliberate operator scale-up
is the failure mode that actually matters operationally.

**Decision: `#4555` is boot-time formation only — periodic re-resolution and ongoing membership
convergence are explicitly 4.4's scope, not this slice's.** Erlang distribution connections are
symmetric once established: a newly-added node resolves its own peer list at *its own* boot and dials
outward, so already-running nodes see it without needing to poll for it themselves, and a departing
node is handled by Erlang's own connection-loss detection (`net_ticktime`), not by discovery at all.
Periodic re-resolution to catch a peer that failed to find *this* node first (DNS propagation lag, a
transient failure on the new node's own boot) is real but is convergence/health-tracking work the
delivery matrix already scopes to 4.4 (`gateway_node` convergence + replay-session writeback) and the
blueprint's own planned `yuzu_gw_cluster` adjacency-table gen_server — `#4555` stays scoped to exactly
what its name says.

**Decision: ship one minimal metric now** (a connected-peer-count gauge, e.g.
`yuzu_gw_cluster_peers_connected`), rather than deferring all observability to WS-11. Fail-open boot
semantics mean a misconfigured seed name fails *silently* by design — the node boots fine and serves its
own agents fine — so without a signal, an operator has no way to notice a cluster that's supposed to
have three members is actually running as three isolated singles. WS-11 (leader epoch, replica lag,
split-brain alerting) remains the home for cross-cutting HA-state observability; this is one narrow
gauge closing the one silent-failure mode this specific mechanism introduces.

### 8. PKI / CA high availability (Q8)
Collapse CA HA into the KEK problem, with the versioning/rollout gaps review surfaced:
- **CA root key → `SecretCodec`-wrapped blob in Postgres** (ADR-0010); distributing the key reduces
  to **KEK availability**.
- **`CaStore` → Postgres**; **durable CRL numbering** via a Postgres sequence — but numbering alone
  is insufficient: **CRL publication becomes an explicit durable state machine** (allocate → sign →
  store → make-current) with a fencing rule, since a sequence prevents collisions yet can leave gaps
  and does not make publication atomic (`ca_store.cpp:605`).
- **Enrollment tokens + pending-agents → Postgres**, off the on-disk config files.
- **KEK is versioned.** Local `KeyProvider` file replicated at provisioning is the default, **but
  "any instance signs" holds only for an instance carrying the current KEK version** — so the design
  includes KEK **version rollout, rollback, and node-admission** semantics (an instance without the
  current version must not silently produce unverifiable material). KMS/HSM via the existing seam is
  optional (SaaS / high-security).

### 9. SQLite tail migration (Q9)
ADR-0006 Update already mandates every server store migrate to Postgres; HA makes the remaining tail
mandatory and reprioritized. Rule: runtime-mutable state → Postgres; only idempotent external caches
may stay per-instance. **Per-store status is the live `docs/postgres-migration-ladder.md`, not this
ADR** (finding nit 2) — a point-in-time list here drifts (several named stores have already migrated),
and a workstream cannot start before its store's migration lands anyway, so sequencing self-enforces.
This ADR states the *criteria* that make a store an **HA-critical prerequisite** rather than an
enumeration:

**HA-critical criteria (any one qualifies a store for the front of the ladder):**
1. **New HA machinery lives in it** — `execution_tracker` + command-correlation (with **atomic counter
   SQL**, §5); `schedule_engine`/schedules (occurrence-claim CAS + outbox, §6); `ca_store` +
   enrollment + pending-agents (§8). These are HA-specific and named here because they don't merely
   migrate, they change shape.
2. **Runtime-mutable AND cross-instance-referenced** — a write on A that must resolve on B or dispatch
   fails: `instruction_store` (`create_definition()` on POST) **with `product_pack_store`** (an
   instruction referencing a runtime-imported pack), `tag_store` (scope resolution),
   `device_token_store` (agent auth), `baseline_store`. (`ConcurrencyManager` — deliberately deleted,
   not migrated, per ADR-1007: the "fleet-wide limits" modes it would have enforced attach only to
   catalog-only definitions with no live dispatch path. The real per-device claim table this ADR
   replaces it with lives inside `execution_tracker`'s schema, already covered by criterion 1 above.)
3. **Security/enforcement state** — divergence is a *security* bug, not cosmetic: `quarantine_store`
   (a device quarantined via A must not look healthy on B), `software_deployment_store` (destructive
   deployment actions), `policy_store` + `approval_manager`/`workflow_engine` (an approval on A must
   bind the executor on B).

Any store matching **none** of these three follows the ladder at normal priority (its divergence is
tolerable until it migrates). `runtime_config_store` / `webhook_store` sit here but **promote** the
moment a workstream shows a cross-instance correctness dependency.

**NVD/CVE (`nvd_db`) — withdrawn from this list (finding 1).** NVD sync/matching moves OUT of the
server into the UCE engine (ADR-0023 / ADR-1005 Phase 7), so it is **not** a `yuzu` store to
leader-sync; its HA is an engine-tier concern (see *Deployment topology and replication axes*).

### 10. Postgres HA — agnostic server, pinned coordination connections (Q10)
- **Core stays agnostic to *how* Postgres HA is achieved** (core is the only `yuzu` client; the
  coordination connections below are core's). Failover discovery via **multi-host DSN
  + `target_session_attrs=read-write`**; also works behind a Patroni VIP / primary-following router.
  Patroni (self-managed) / managed service (SaaS) recommended, not mandated.
- **Pooler collision.** `LISTEN`/`NOTIFY` and **session-scoped** advisory locks (KEK op,
  token-rotation, the **leader lock**) require backend affinity and break behind a transaction-mode
  pooler. Yuzu's own `pg_pool` is the pool; **no external transaction-mode pooler is required or
  assumed.** The coordination connections (NOTIFY listener, leader lock, session-lock holders) are
  each a **dedicated, never-recycled, lifetime-owned connection with connection-loss fencing** —
  **not** an ordinary recycling pool lease (`pg_pool` is checkout-per-operation, `pg_pool.hpp:156`;
  a recycled connection would drop the lock). Where a deployment adds a pooler for the request path,
  it must not front these connections.
- **Reads: primary-only by default.** Read-replica routing explicitly deferred.

### 11. Delivery — shipped HA profiles + selectable durability (Q10/Q11)
Yuzu ships Postgres, so HA Postgres is a delivery artifact we own.
- **Shipped HA-PG profile (opt-in Compose profile): Patroni + etcd + HAProxy**, containerized — the
  customer selects a profile, not a DCS project. **HAProxy-to-primary is connection routing, not
  transaction pooling** — it preserves backend affinity, compatible with §10.
- **Durability is a selectable profile, default = 3-node quorum** (1 primary + **2** sync standbys,
  `synchronous_standby_names = ANY 1 (s1,s2)`): RPO=0 while ≥1 standby is up; writes stall only if
  **both** standbys are lost (quorum lost → fail-closed by design). This replaces the earlier
  unconditional 2-node RPO=0, which stalled all writes on a single standby blip — *below* the
  single-Postgres baseline. An **async/degrade profile** (lower latency, bounded loss window) is a
  documented opt-out.

  > **Implementation note (WS-7, 2026-08).** The fail-closed-on-quorum-loss default above is realised
  > in Patroni by `synchronous_mode_strict`. Kickoff measurement found strict mode **blocks writes for
  > minutes after even a *single*-node failover** (the promoted primary waits for its surviving standby
  > to re-establish sync) — empirically at odds with §13's ~10–30 s RTO target; the two cannot both be
  > honoured today. WS-7 therefore **ships the async/degrade profile as the DEFAULT** (`YUZU_PG_SYNC_STRICT`
  > default off: RPO=0 while ≥1 standby is available — the common single-failover case — degrading to
  > async only on total standby loss), with strict fail-closed as a documented, operator-selectable
  > opt-in. Reconciling strict-mode failover timing (and asserting both behaviours in the harness) is a
  > **WS-9** item. Until then, the *shipped default* is the async profile, not the fail-closed one this
  > section describes. **"3 nodes" means 3 distinct hosts / failure domains (finding 2).** Vanilla
  Docker Compose has **no cross-host placement primitive** — it cannot pin anti-affinity across
  physical hosts — so the **single-host Compose profile delivers container/process redundancy only,
  NOT host-level HA**, and co-locating all three would quietly void the §13 RPO=0-across-host-failure
  claim. Host-level HA requires **multi-host placement** (Docker **Swarm** mode, **Kubernetes**, or
  manual multi-host provisioning); that placement is an **operator responsibility, documented
  separately** in the delivery runbook — the Compose profile alone must not be presented as
  host-HA.
- **Single-PG stays the default (non-HA) profile.** All four topologies supported: BYO-single, BYO-HA,
  shipped-single, shipped-HA.
- **Shipped operator-plane LB** in the HA profile, with **BYO-LB / VIP / DNS round-robin** supported.

### 12. Ingress / LB + health contract + MCP (Q11)
- **Scope: operator/API plane incl. MCP + streaming.** MCP behind active–active pulls MCP state into
  §4/§5, **held as core-owned durable state**: the **MCP session registry → durable (core)** and the
  **MCP replay ring → the durable outbox (core)**, exposed to presentation through a **core replay/
  session API + the core→presentation event spine** (cursor owned by core). A presentation-terminated
  MCP stream that drops resumes on a different presentation replica by re-attaching to core via
  `Last-Event-ID` — presentation never touches the Postgres ring directly. `StreamBudget` stays a
  per-**presentation-replica** cap (it bounds held-open connections at the termination point). **This
  move inherits, not supersedes, the ADR-1005 execution-plan Decision 15
  pre-commitments (a)–(k) (finding 5)** — principal-bound sessions, live credential revalidation on
  resume, bounded rings, honest replay-gap signalling, pin lifecycle (incl. the open pin-lifecycle
  item), and the shared `StreamBudget` — which the in-memory design shipped; the durable
  implementation must carry every one of them forward.
- **Health contract, per tier:** `/livez` (alive — restart) vs `/readyz` (ready — stop routing to me).
  **Presentation `/readyz`** gates the **operator LB**; **core `/readyz`** gates **presentation→core
  routing** and must go red when core cannot reach `yuzu` (ADR-0031: an LB/router must never be green
  while core is down, or it routes to a surface that cannot serve). **Draining:** fail `/readyz`, let
  the fronting layer drain, then stop.
- **BYO-LB documentation deliverable:** no idle-timeout on held-open SSE/MCP streams; no response
  buffering; health targets `/readyz`; draining; optional stickiness (locality only); TLS stance.
  Owned by `docs-writer` + `release-deploy`.

### 13. HA guarantees — RTO/RPO (Q12)
Proposed targets for the team to ratify:
- **Presentation-replica loss:** RTO ≈ 0 (operator LB removes it on `/readyz`; sessions/streams are
  durable/relayed, so a client reconnects to a surviving presentation replica).
- **Core-replica loss:** RTO ≈ 0 for request-serving (presentation→core routing drops the dead core
  replica on core `/readyz`) plus the leadership re-election gap for background work (§6); in-flight
  commands re-drive from the outbox. Note the operator LB removing a *presentation* replica does **not**
  repair a *core* outage — those are distinct readiness signals.
- **Postgres-primary failover:** RTO = failover time (Patroni ~10–30s). **RPO = 0 while the
  synchronous-commit quorum holds** (default 3-node profile, §11); the guarantee is
  "no acknowledged-write loss while quorum exists," **not** "writes always available" — quorum loss
  blocks writes deliberately. Async profile is a documented opt-out with a bounded loss window.

### 14. Testing — failover harness (Q12)
A **failover test harness** stands up the Patroni+etcd+HAProxy stack and **injects a primary kill
mid-test**, asserting: pool reconnects to the promoted primary; **operator sessions survive** (§4);
**leader re-elects with no double-dispatch under a fencing-token check** (§6); **outbox re-drive is
effectively-once at the receiver** (§5/§6); NOTIFY listeners **cursor-poll forward** and lose no
committed events (§5); in-flight commands re-drive (§7); **directory re-home races do not lose or
duplicate** (§7). It must also cover **standby loss** (quorum-degrade behavior, §11). Owned by
`build-ci` + `release-deploy`; scenarios by `chaos-injector`.

## Decomposition into child workstreams

This ADR records the model and principles. Each area becomes a child ADR/issue:

0. **WS-0 — Durable agent-side command idempotency + outcome replay (prerequisite).** Replace the
   in-memory `dedup_current_`/`dedup_previous_` (cleared on reconnect, `agent.cpp:2484`) with a durable
   per-agent store keyed on `command_id` that **both** suppresses re-execution **and replays the stored
   terminal outcome** on a duplicate (today a dup returns a bare `REJECTED`, `agent.cpp:2497`, losing
   the original result when the first ack was lost). **Gates the end-to-end guarantee of WS-1/WS-3** —
   the server outbox is meaningless if the receiver forgets, and effectively-once is only "effect-once,
   result-maybe-lost" without outcome replay.
1. **Server-plane state → Postgres** — sessions (§4), execution/correlation with atomic counters (§5),
   the HA-critical store subset incl. quarantine + software-deployment + product-pack (§9).
2. **Durable event outbox + NOTIFY fan-out** (§5), the **core→presentation event spine** (a versioned,
   resumable SSE/gRPC stream core exposes so DB-less presentation can relay events — an ADR-0031
   prerequisite, not optional), and **MCP session/replay durability** (§12).
3. **Coordination seam** — fenced `LeaderElector` + signal channel with reconnect cursor-poll (§3);
   the **leader + transactional-outbox + receiver-idempotency** worker refactor incl. policy
   remediation (§6).
4. **Gateway routing + multi-cluster topology** — fenced agent→cluster directory **and net-new
   distributed intra-cluster agent→node routing** (§7).
5. **Shared agent presence / health / scope population** (§7a).
6. **PKI/CA HA** — CA key to `SecretCodec`, CRL publication state machine, KEK versioning/rollout,
   enrollment to PG (§8).
7. **HA-PG delivery** — Patroni+etcd+HAProxy profile with **selectable durability (3-node quorum
   default)** + operator-plane LB (§11).
8. **Health contract + BYO-LB doc** (§12).
9. **Failover test harness** incl. quorum-degrade + re-home-race cases (§14).
10. **Background-job replica-safety classification (finding 4).** Active–active means every *existing*
    wall-clock retention/reaper pass inherits the clock-guard **SINGLE-WRITER** rule (shared reading +
    anomaly-dedup rows under an ADR-0012 advisory lock), not just the new event outbox. Classify every
    background job as **fenced-leader-only**, **independently replica-safe**, or **disabled-until-fixed**;
    bring the #2508 not-yet-compliant passes (`app_perf_*`, `PreflightRunStore`, `DeploymentRunStore`,
    and the `concurrency_claims` stale-claim reconciler added by ADR-1007 — clock-guard-compliant on
    all seven parts, including a persisted anchor and dedup fact-set in `retention_meta` across
    restarts [part 2], but not yet SINGLE-WRITER-safe: it has no `pg_advisory_lock`/
    `pg_try_advisory_lock` around its shared read-decide-write sequence, unlike `audit_store.cpp`'s
    `pg_try_advisory_xact_lock('audit_store:reap')` — a materially smaller gap than the other three
    siblings here, which issue bare wall-clock deletes with no clock-guard shape at all)
    to the guarded shape *before* a second replica exists. HA turns that backlog into a correctness
    prerequisite. **Deliverable is a checked-in, exhaustive background-job table** (job → one of
    fenced-leader-only / independently-replica-safe / disabled-until-fixed) kept in the tree and
    CI-auditable — not just the classifying principle, so a newly-added job cannot silently escape
    classification (nit).

## Consequences

- The `NOTIFY` + session-advisory-lock + leader-lock design **precludes a transaction-mode pooler on
  the coordination connections**, and those connections must be dedicated and never-recycled.
- The SQLite→Postgres tail migration is **on the critical path**, now including the enforcement stores.
- HA deployments **require the gateway** and take on **net-new distributed intra-cluster routing** and
  **shared presence state** — the honestly-priced cost of gateway-fronting.
- We take on **operating a shipped HA-PG stack** (Patroni/etcd/HAProxy) with a **3-node quorum**
  default footprint.
- We accept a **session-expiry monotonicity regression** on the DB host in exchange for shareable
  durable sessions (§4).
- The **effectively-once** guarantee is contingent on **WS-0** (durable agent dedup); until it lands
  the guarantee is at-least-once across an agent reconnect (§6, *Guarantees*).
- Two **routed-concern rows are superseded** and must be edited in the same change: the AuthDB
  "sessions in-memory only" row and the clock-guarded-retention "NOT the `auth_db` session sweep"
  carve-out (§4). The session sweep joins the clock-guarded set.
- **Engine-tier availability is a separate axis** from `yuzu`-database availability; NVD/CVE HA is an
  engine concern, not a server-store concern (*Deployment topology*, §9).

## Supersedes

- `docs/operations/disaster-recovery.md` (active-passive / NFS / SQLite-Litestream — pre-Postgres).
- `docs/operations/capacity-planning.md` "Yuzu is single-server by design (SQLite)".
- The **AuthDB routed-concern row** clause "Sessions are in-memory-only — no durable session surface
  on this store" (§4).
- The **clock-guarded-retention routed-concern** carve-out excluding the `auth_db` session sweep as
  "immune by construction" — no longer true once sessions are durable wall-clock rows (§4).

## Deferred / out of scope

- **Read-replica query routing** (§10) — later, opt-in, per-query-class.
- **Second coordination backend** (Redis/NATS) (§3) — built only when SaaS scale demands it.
- **Cross-zone agent failover** (§7) — deliberately not offered.
- **Finer intra-zone gateway sharding** (§7) — handled by adding nodes.

## Review findings incorporated — round 1 (pre-open)

Both reviewers verified the ADR's factual predicates (SQLite tail, in-process maps, `crl_publish_mu_`,
the DeploymentEngine claim-CAS, gateway replay) and the "no new SPOF" argument as **correct**, and
judged the direction sound. Blocking corrections folded in above:

- **Intra-cluster routing is net-new, not free** (`pg` is broadcast-only; per-agent is node-local
  ETS) — §2 re-priced, §7 corrected, workstream 4 re-scoped.
- **Routing directory fenced** with connection-epoch/lease + CAS register/deregister — §7.
- **`AgentRegistry` presence/scope-population is shared state**, a new workstream — §7a.
- **Exactly-once replaced by transactional-outbox + claim-before-side-effect + receiver idempotency**;
  policy remediation redesigned — §6, *Guarantees*.
- **RPO=0 made a selectable profile with a 3-node quorum default** (single standby loss no longer
  stalls writes) — §11/§13.
- **Session move owns its reversal**; false "better by construction" dropped; wall-clock regression on
  elevation/step-up mitigated — §4.
- **Coordination connections dedicated/never-recycled; leader fencing token in the claim txn** —
  §6/§10.
- **NOTIFY reconnect cursor-poll + outbox atomicity** made invariants — §5.
- **`quarantine_store`, `software_deployment_store`, `product_pack_store` promoted to HA-critical**;
  atomic-counter rule added — §9/§5.
- **CRL publication state machine + KEK versioning/rollout** — §8.

## Review findings incorporated — round 2 (PR #3320)

The `CHANGES_REQUESTED` review (findings verified against `origin/dev`) is addressed above:

1. **Topology reconciled with ADR-0031/0032/0033 + NVD pulled out of the server.** New *Deployment
   topology and replication axes* section defines presentation / core / gateway / engine as separate
   replication axes with distinct databases; "Server tier" reconciled with the three-binary model
   (LB-vs-tier boundary refined further in round 3); NVD moved to the engine tier and withdrawn from §9.
2. **Durable agent-side idempotency made an explicit prerequisite (WS-0)**, since today's agent dedup
   is in-memory and cleared on reconnect (`agent.cpp:2484`) — the effectively-once claim no longer
   assumes it.
3. **Fencing token made explicit** — a monotonic leader epoch checked in the claim transaction, §3/§6.
4. **Superseded invariant docs listed** (AuthDB in-memory-sessions row; clock-guard `auth_db`-sweep
   carve-out), and a new **WS-10** classifies every background job for replica-safety and brings the
   #2508 wall-clock passes to the clock-guard shape before a second replica exists.
5. **§12 states it inherits** ADR-1005 Decision 15 pre-commitments (a)–(k), not supersedes them.
6. **Code-level obligations wired into the workstreams** — WS-3 threads `dispatch_fn`'s discarded
   `sent_count` and preserves the "don't burn a capped retry on a failed dispatch" reason
   (`policy_evaluator.cpp:281`); WS-4 makes `gateway_node` *converge* rather than depend on a single
   `NotifyStreamStatus`.
- **Nits:** 3-node quorum pinned to distinct hosts/failure domains (§11); §9 now cites the live
  migration ladder instead of a drifting store list.

## Review findings incorporated — round 3 (PR #3320)

Second `CHANGES_REQUESTED` pass, tightly scoped; all four + the nit addressed:

1. **LB fronts presentation, not core.** The topology section and the `Server tier` glossary term are
   corrected: presentation terminates HTTP/SSE/MCP and fronts the operator-plane LB (ADR-0031); core
   is the API authority / sole `yuzu`-writer / coordination owner **behind** presentation. "Server
   tier" = presentation + core as two axes. This also reconciles with Context §2 ("presentation scales
   horizontally").
2. **Compose ≠ host HA.** §11 no longer claims the Compose profile "pins anti-affinity" — plain
   Compose has no cross-host placement; the single-host profile gives container/process redundancy
   only, and host-level HA requires Swarm/Kubernetes/manual multi-host placement, an operator
   responsibility documented separately.
3. **Gateway does not dedup.** *Guarantees* and §6 now say the **agent** dedups at the true endpoint
   (verified `yuzu_gw_agent.erl` forwards unconditionally); gateway-side dedup is an optional future
   optimization, not a claimed property.
4. **Citations corrected at this commit:** discarded dispatch return is
   `PolicyEvaluator::dispatch_instruction` (`policy_evaluator.cpp:281`); the `gateway_node` populate is
   `GatewayUpstreamServiceImpl::NotifyStreamStatus` → `set_gateway_node` (`:637`/`:660`) — cited by
   symbol to resist drift.
- **Nit:** WS-10's deliverable is now an explicit **checked-in, CI-auditable background-job table**, not
  just the classifying principle.

## Review findings incorporated — round 4 (self-review before push)

A `gpt-5.6-sol` adversarial pass on the round-3 edits (run before pushing) caught that the
LB-fronts-presentation correction had not been *propagated* — several sections still assigned
core-only work to the DB-less presentation tier. Fixed:

- **Boundary rule added** to the topology section: only **core** touches `yuzu` (reads/writes,
  `LISTEN`/`NOTIFY`, locks, outbox, **session validation**); **presentation is DB-less** and reaches
  durable state only through core's API + a **core→presentation event spine**. This governs every
  section.
- **§5** — the outbox is `LISTEN`ed/polled by **core**, which re-publishes onto the event spine;
  presentation relays, never reads `yuzu`. **§4** — core validates sessions; presentation forwards the
  credential. **§12** — MCP session/replay is core-owned durable state exposed via a core replay API;
  cursor owned by core; `StreamBudget` is a per-presentation-replica cap. **§7a** — presence read by
  every core replica. **§7 southbound** — gateway gRPC terminates on a **core** service endpoint,
  distinct from the operator LB.
- **Effectively-once deepened (new finding):** a duplicate returns bare `REJECTED` (`agent.cpp:2497`),
  which suppresses re-execution but **loses the original result** if the first ack was lost — so **WS-0
  must retain and replay the terminal outcome**, else the honest guarantee is "effect-once,
  result-maybe-lost." Reflected in *Guarantees*, §6, WS-0.
- **Health split by tier** (§12/§13): presentation `/readyz` gates the operator LB; core `/readyz`
  gates presentation→core routing; a presentation removal does not repair a core outage.
- **WS-2** now names the **core→presentation event spine** as an ADR-0031 prerequisite.
- Wording: "gateway forwards **transparently (unconditionally)**" (not "idempotently"); coordination
  language qualified to **core** (§6/§10, `CONTEXT.md`); stale round-2 citation/phrasing corrected.
