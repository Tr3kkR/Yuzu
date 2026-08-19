# High Availability Architecture

---
status: proposed
owner: Fraser Jarvis (@fjarvis)
---

**Authors:** Fraser Jarvis (@fjarvis)
**Review:** hardened after adversarial review by the `enterprise-architect` validator and
`gpt-5.6-sol` (both read the codebase); see *Guarantees and non-guarantees* and *Review findings
incorporated* below.

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

## Guarantees and non-guarantees

- **Command dispatch: effectively-once.** At-least-once delivery via a transactional outbox +
  claim-before-side-effect, made effectively-once by **receiver-side idempotency** — the gateway and
  agent dedup on a stable `command_id`. We do **not** promise exactly-once (a crash between claim
  commit and RPC send is unavoidable; the receiver's dedup is what closes it).
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
Narrow interfaces — a **fenced** `LeaderElector` (advisory-lock backed, issues a fencing token) and a
cross-instance signal/event channel (`NOTIFY`-as-hint over a durable outbox table with a **mandatory
reconnect cursor-poll + periodic safety poll**). Ship only the Postgres implementation; a SaaS
backend (Redis/NATS) drops in without touching call sites. Constraints this imposes (backend
affinity, no transaction-mode pooler on coordination connections) are in §10.

### 4. Operator sessions — durable in Postgres, absolute wall-clock (Q4)
Sessions move from the in-memory map (`AuthManager::sessions_`, `steady_clock`) to durable Postgres
rows any instance can validate, executing the ADR-0031 direction. **This ADR explicitly reverses the
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

### 5. Event / SSE fan-out — durable outbox + NOTIFY-as-hint (Q5)
`ExecutionEventBus` becomes a **local** fan-out fed by a **dedicated append-only Postgres event
outbox** with **durable monotonic event IDs** (replacing the per-process channel counters,
`execution_event_bus.cpp:62`). Invariants (per review):
- **Atomic outbox write:** the source-state mutation and the event-row insert commit in **one
  transaction**; `NOTIFY` fires after commit. A crash therefore never leaves state without its event
  or vice versa.
- **Delivery:** every server `LISTEN`s and, **on every (re)connect to the promoted primary, polls the
  outbox forward from its last-seen cursor**, plus a periodic safety poll — NOTIFYs issued around a
  failover are lost and must not be relied on. Consumers replay via `Last-Event-ID` / `?since=` and
  **tolerate duplicates** (at-least-once).
- The outbox inherits the **clock-guarded retention** rules (routed concern).

**Load-bearing prerequisite:** cross-instance correlation requires execution state in Postgres.
`execution_tracker` (SQLite) and `cmd_execution_ids_` (in-process map, `agent_service_impl.hpp:330`)
migrate to Postgres, and their counter updates (`agents_responded` / `agents_success`) MUST be
**atomic SQL** (`SET x = x+1` / `RETURNING`), never app-side read-modify-write — the hazard class
CLAUDE.md already flags for `sqlite3_changes()` (concurrent responses now land on multiple
instances).

### 6. Background workers — fenced leader + transactional outbox (Q6)
A single instance holds the **fenced** leader lock and runs the singleton loops. The correctness
model, corrected per review — a claim alone does **not** give exactly-once, because a crash between
claim-commit and the external send is unavoidable:
- **Claim-before-side-effect is the invariant** (as `DeploymentEngine` already does,
  `deployment_engine.cpp:125` — claim `staged→executing`, *then* dispatch). Any refactor that
  dispatches before the occurrence-CAS re-opens double-fire and is prohibited.
- **Transactional outbox:** a side-effecting dispatch commits a `pending` outbound-command row (with a
  **stable occurrence/command ID**) in the same transaction as the state transition; a claimed
  delivery loop drives `pending → sent`. A crash re-drives from `pending`.
- **Receiver idempotency:** the gateway and agent dedup on `command_id`, so an at-least-once re-drive
  is effectively-once at the endpoint.
- **Fencing token in the claim transaction:** every claim CAS checks the leader's fencing token, so a
  stale ex-leader cannot commit a claim even before it notices its lock dropped. A boolean "I am
  leader" cached outside the lock connection is prohibited.
- **`PolicyEvaluator` remediation is redesigned** (it currently dispatches the fix *before* recording
  `fixing`, `policy_evaluator.cpp:421`, under process-local mutex/maps): it gets a durable occurrence
  key, claim-before-dispatch, and outbox delivery — the same shape — so two stale leaders or two
  concurrent operator remediations cannot both fire.
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
- **Southbound (gateway→server):** each cluster's upstream targets the **server tier** (VIP or node
  list), generalizing the existing single-upstream + circuit-breaker + `ProxyRegister`-replay path.
- **Northbound (server→gateway):** the minting server reads the directory and dials the owning
  cluster; an undeliverable command (cluster unreachable, stale/expired lease, agent mid-migration)
  stays `pending` in the outbox (§6) and is re-driven — with receiver dedup absorbing any double
  delivery during a re-home race.
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
registration/heartbeat, read by every server), so scope resolution and the `yuzu_agents_connected`
gauge are coherent across the tier rather than per-instance. This is its own workstream, not a
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
mandatory and reprioritized. Rule: runtime-mutable state → Postgres; only idempotent
external caches may stay per-instance.

**HA-critical subset (prerequisites, sequenced first)** — revised per review to include the
enforcement/recovery stores:
- `execution_tracker` + command-correlation, with **atomic counter SQL** (§5)
- `schedule_engine`/schedules with the occurrence-claim CAS and outbox (§6)
- `ca_store` + enrollment + pending-agents (§8)
- `instruction_store` (runtime-mutable: `create_definition()` on POST, `create/delete_definition`,
  `create_set`) **and `product_pack_store`** — an instruction/set referencing a runtime-imported pack
  on instance A must resolve on B, else dispatch fails (a day-one correctness bug, not divergence)
- `policy_store`, `approval_manager`/`workflow_engine`, `concurrency_manager`
- `device_token_store`, `tag_store`, `baseline_store`
- **`quarantine_store`** — security-enforcement state (`Security:Read`); a device quarantined via A
  but healthy-looking on B is a security divergence, not cosmetic
- **`software_deployment_store`** — governs destructive/enforcement deployment actions

**Normal-priority (existing ladder):** `license_store`, `patch_manager`, `webhook_store`,
`runtime_config_store`, `offload_target_store`, `update_registry`, `analytics_event_store`,
`directory_sync`. (`runtime_config_store` / `webhook_store` affect posture and durable side effects —
promote if a workstream shows a cross-instance correctness dependency.)

**NVD/CVE cache** (`nvd_db`, the sole idempotent external cache): **leader syncs to shared Postgres**,
all instances read from PG.

### 10. Postgres HA — agnostic server, pinned coordination connections (Q10)
- **Server stays agnostic to *how* Postgres HA is achieved.** Failover discovery via **multi-host DSN
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
- **Single-PG stays the default (non-HA) profile.** All four topologies supported: BYO-single, BYO-HA,
  shipped-single, shipped-HA.
- **Shipped operator-plane LB** in the HA profile, with **BYO-LB / VIP / DNS round-robin** supported.

### 12. Ingress / LB + health contract + MCP (Q11)
- **Scope: operator/API plane incl. MCP + streaming.** MCP behind active–active pulls MCP state into
  §4/§5: the **MCP session registry → durable**, the **MCP replay ring → the durable outbox** — a
  dropped MCP stream resumes on a different instance via `Last-Event-ID`. `StreamBudget` stays a
  per-instance cap.
- **Health contract:** `/livez` (alive — restart) vs `/readyz` (ready — remove from LB). **Draining:**
  fail `/readyz`, let the LB drain, then stop.
- **BYO-LB documentation deliverable:** no idle-timeout on held-open SSE/MCP streams; no response
  buffering; health targets `/readyz`; draining; optional stickiness (locality only); TLS stance.
  Owned by `docs-writer` + `release-deploy`.

### 13. HA guarantees — RTO/RPO (Q12)
Proposed targets for the team to ratify:
- **Server-instance loss:** RTO ≈ 0 for the tier (LB removes the dead instance; sessions/events/
  commands durable and resume elsewhere; in-flight commands re-drive from the outbox).
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

1. **Server-plane state → Postgres** — sessions (§4), execution/correlation with atomic counters (§5),
   the HA-critical store subset incl. quarantine + software-deployment + product-pack (§9).
2. **Durable event outbox + NOTIFY fan-out** (§5) and **MCP session/replay durability** (§12).
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

## Supersedes

- `docs/operations/disaster-recovery.md` (active-passive / NFS / SQLite-Litestream — pre-Postgres).
- `docs/operations/capacity-planning.md` "Yuzu is single-server by design (SQLite)".

## Deferred / out of scope

- **Read-replica query routing** (§10) — later, opt-in, per-query-class.
- **Second coordination backend** (Redis/NATS) (§3) — built only when SaaS scale demands it.
- **Cross-zone agent failover** (§7) — deliberately not offered.
- **Finer intra-zone gateway sharding** (§7) — handled by adding nodes.

## Review findings incorporated

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
