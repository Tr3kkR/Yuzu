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
- **Receiver idempotency:** the **agent** dedups on `command_id` at the true endpoint (the gateway
  forwards transparently, no gateway-side dedup today), so an at-least-once re-drive is effectively-once
  — **contingent on WS-0** making the agent's dedup durable (today's `dedup_current_`/`dedup_previous_`
  are in-memory and cleared on reconnect, `agent.cpp` `dedup_current_.clear()`).
- **Fencing token in the claim transaction:** every claim CAS checks the leader's fencing token, so a
  stale ex-leader cannot commit a claim even before it notices its lock dropped. A boolean "I am
  leader" cached outside the lock connection is prohibited.
- **`PolicyEvaluator` remediation is redesigned** (it currently dispatches the fix *before* recording
  `fixing`, `policy_evaluator.cpp:421`, under process-local mutex/maps): it gets a durable occurrence
  key, claim-before-dispatch, and outbox delivery — the same shape — so two stale leaders or two
  concurrent operator remediations cannot both fire. **Two code-level obligations for WS-3 (finding
  6a):** (i) `dispatch_instruction` currently **discards** `CommandDispatchFn`'s
  `(execution_id, sent_count)` return (`PolicyEvaluator::dispatch_instruction`,
  `policy_evaluator.cpp:281`) and always yields a non-empty
  execid regardless of whether any target was reached — the redesign must thread `sent_count` through
  so "all targets offline" is a real signal; (ii) it must **preserve the reason** the current code
  dispatches before recording `fixing` — a *failed* dispatch must not burn a capped retry attempt, or
  the agent eventually auto-locks to `error` with no fix ever sent. Claim-before-side-effect must
  distinguish "occurrence claimed and delivered" from "occurrence claimed but delivery failed → retry,
  don't consume the attempt."
- Already-correct guards (Deployment CAS, retention/rotation advisory locks) stay as
  defense-in-depth; idempotent/read-only loops run leader-only with no claim.

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
