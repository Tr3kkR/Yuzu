# High Availability — Delivery Matrix

The delivery spine for **ADR-2002 (High Availability Architecture)**. ADR-2002 records the *model and
principles*; this matrix tracks *what ships, in what order, who reviews it, and how we know it's done*.
Workstreams WS-0…WS-10 come from ADR-2002 §Decomposition; WS-11…WS-14 are delivery/ops workstreams the
three-model adversarial review (Fable + gpt-5.6-sol + Kimi-K2.7) surfaced as missing. If a row here
disagrees with ADR-2002, the ADR wins.

**Companion docs:** `docs/adr/2002-high-availability-architecture.md` (the decisions),
`docs/postgres-migration-ladder.md` (authoritative per-store migration status),
`docs/adr-1005-execution-plan.md` (presentation/core/engine split + engine-tier + MCP Decision-15 work
this matrix *shares*, not duplicates).

## Two independent axes (read first)

- **Server-tier HA** — N presentation + core replicas (WS-0…WS-6, WS-8, WS-10, WS-11, WS-13).
- **Storage HA** — HA Postgres (WS-7). A single Postgres is a valid, supported deployment; **server-tier
  HA does not require it.**

"HA" as a customer claim = **both** axes + WS-9 (validation) + WS-11/WS-12 (operability).

## ⚠️ The safe-to-scale gate (read before sequencing)

**Do not equate "Phase A done" with "safe to run a second replica."** The three-model review's
strongest, unanimous finding: a second server replica is safe **only after the full prerequisite set
lands** —

> **Gate — a second server replica may be enabled only when: WS-0, WS-1, WS-2(outbox), WS-3, WS-4,
> WS-5, WS-6, WS-10 are done, and WS-8's per-tier `/readyz` exists.**

Miss any one and the failure is not cosmetic: without **WS-3** (fenced leader) both replicas run the
singleton workers → **double-dispatch of destructive commands** (software-deployment, quarantine,
policy-remediation); without **WS-4/WS-5** commands can't reach agents / scope evaluation drops agents
on the replica that lacks the local stream → mis-targeting; without **WS-6** CRL numbering / enrollment
diverge across replicas. **WS-7 (HA Postgres) is NOT in this set** — it gates the *storage* axis (no
SPOF / RPO=0), not the second *server* replica (which is safe against a single Postgres). The
"Gates 2nd replica?" column below encodes this per row.

## Is the presentation/core split a prerequisite? (the reviewers split on this)

- **Fable / Sol:** No — active-active is achievable on the **monolith** once the seams above are
  externalized. The single in-process thing that can't go active-active (the direct agent `Subscribe`
  stream) is solved by **gateway-fronting (WS-4)**, not the split. The split's only true artifacts —
  the **core→presentation event spine** and **tier-split `/readyz`** — are *no-ops on the monolith*
  (presentation+core co-located) and correctly defer to ADR-1005.
- **Kimi (dissent):** the split is a hard safety prerequisite.
- **Working position (this matrix):** monolith active-active is the target; the split is an
  optimization, **not** a gate. The seam deliverables that only matter post-split (WS-2b spine,
  WS-8 tier-split readyz) are marked *defers to ADR-1005*. **This is the #1 item to confirm with the
  ADR-1005 owners before Phase B starts** — if Kimi is right, Phase B reshuffles onto the split.

## Status legend

**Status:** `planned` · `in-progress` · `blocked` · `done`. **Prio (build-effort tier):** P0 · P1 · P2.
**Gates 2nd replica?** whether the safe-to-scale gate above depends on this row (the load-bearing
column — distinct from Prio).

## The matrix

| WS | Delivers | Current state (symbol / cite at HEAD) | Depends on | Gates 2nd replica? | Reviewers (routed) | Prio | Status |
|----|----------|--------------------------------------|-----------|:---:|--------------------|------|--------|
| **WS-0** | Durable agent-side command idempotency **+ terminal-outcome replay** (dup replays stored result, not bare `REJECTED`) | **Shipped**: `CommandDedupStore` (`command_dedup_store.{hpp,cpp}`, agent SQLite `command_dedup.db`, `synchronous=FULL`, terminal-only ring); wired in `agent.cpp` claim/`record_command_terminal`/release. Follow-ups open: stale-in-flight reconciliation, fleet-side observability (WS-11) | — | **Y** | `cpp-safety` + `cpp-expert` | P0 | **done (PR #3662 merged to dev)** |
| **WS-1** | Server-plane state → Postgres. **Milestones:** (1a) sessions (DB-time); (1b) `execution_tracker` + command-correlation w/ atomic counters; (1c) HA-critical store subset | **1a DONE** (durable `SessionStore`, write-through + generation validate-cache, AND DB-clock authority: timestamps authored from Postgres `now()` in-SQL, `find` returns `db_now_ms` in the same read, adjudication derives a local monotonic `steady_clock` deadline with clamped ceilings + a wall suspend-backstop — `session_store.{hpp,cpp}`, `auth.cpp`, #3715; cross-host skew fixed, the multi-replica prerequisite closed). **1b DONE**: `execution_tracker` migrated to Postgres (ADR-0065, atomic in-transaction counter recompute); command-correlation moved off the in-proc `cmd_execution_ids_` map into `ExecutionTracker`'s PG-backed `command_execution` table (`record_command_execution`/`lookup_execution_id`, clock-guarded retention sweep) — a response landing on any server replica now resolves. **1c DONE**: ADR-2002 §9 deliberately states *criteria* for "HA-critical," not a fixed store list ("a point-in-time list here drifts"); every store matching those criteria (`execution_tracker`, `schedule_engine`, `ca_store`, `instruction_store`+`product_pack_store`, `tag_store`, `device_token_store`, `baseline_store`, `quarantine_store`, `software_deployment_store`, `policy_store`+`approval_manager`/`workflow_engine`) shows `Migrated Postgres` on `docs/postgres-migration-ladder.md` as of Wave 4's close (2026-08-30), each with its HA-shaping work (atomic-counter SQL, advisory-lock coordination, race-safe upserts) folded into its own per-store ADR rather than deferred. The two ladder exceptions (`nvd_db`, `ConcurrencyManager`) are both explicitly out of HA scope per ADR-2002 §9 itself. **WS-1 is fully closed.** | migration ladder (per store; **serializes at the migration-version counter**, not fully parallel) | **Y** | `authdb`+`security-guardian` (1a); `architect`+`sre`+`cpp-safety` (1b/1c) | P0 | **done — 1a+1b+1c (#3702, #3715, HA WS-1(1b), 1c subsumed by the general Postgres-migration Wave 4 close)** |
| **WS-2** | (**2a**) durable **event outbox** + NOTIFY fan-out [monolith-OK]; (**2b**) **core→presentation event spine** [*defers to ADR-1005 split*]; MCP session/replay durability | `ExecutionEventBus` in-proc; per-proc channel counter (`execution_event_bus.cpp:73`); MCP session/ring in-mem | 2a: WS-1(1b). 2b: **ADR-1005 split** | **Y** (2a) | `architect`+`sre`+`security-guardian`(MCP)+`docs-writer` | P1 | planned |
| **WS-3** | Coordination seam: **fenced `LeaderElector`** (monotonic epoch checked in claim txn) + leader/**transactional-outbox**/receiver-idempotency worker refactor incl. policy remediation | Workers dispatch per-proc, no cross-instance guard; Deployment CAS + sweep advisory locks already correct | **WS-0, WS-1, WS-2(2a outbox)** | **Y** | `architect`+`cpp-safety`+`security-guardian` | P1 | planned |
| **WS-4** | Gateway routing + multi-cluster: fenced `agent→cluster` directory, **net-new distributed intra-cluster agent→node routing**, `gateway_node` convergence | `pg` broadcast-only; per-agent lookup node-local ETS (`yuzu_gw_registry.erl:90`); `gateway_node`+caps now via `set_gateway_route` (single call; NotifyStreamStatus `:637`/`:660`) | **WS-1, WS-3, WS-0** (its no-loss/no-dup DoD needs the outbox + receiver dedup) | **Y** | `gateway-erlang`+`security-guardian`+`architect`+**`cpp-safety`** | P1 | planned |
| **WS-5** | Shared agent presence / health / **scope-eval population** across core replicas | `AgentRegistry` per-proc; scope eval drops agents absent from local live registry (`agent_registry.hpp:648`) | **WS-4, WS-1, WS-3, WS-10** (scope-eval is a background job; its replica-safety class must be fixed first) | **Y** | `security-guardian`+`architect`+**`sre`**+`docs-writer` | P1 | planned |
| **WS-6** | PKI/CA HA: CA key → `SecretCodec` blob in PG, `CaStore` → PG, **durable CRL numbering + publication state machine**, KEK versioning/rollout/rollback, enrollment → PG | CA key on local disk (`key_provider.hpp:148`); CRL numbering in-proc `crl_publish_mu_` (#1240 UP-4); enrollment on-disk | **WS-1(`ca_store`), WS-3** (fenced leader for CRL publish/enrollment) | **Y** | `security-guardian`+`cpp-safety`+`docs-writer` | P1 | planned |
| **WS-7** | **HA-PG delivery**: shipped Patroni+etcd+HAProxy Compose profile, **selectable durability (3-node quorum default, distinct failure domains)**, operator-plane LB profile | **Shipped**: `deploy/docker/docker-compose.ha-postgres.yml` + `deploy/docker/ha-postgres/` (Patroni entrypoint, HAProxy, Dockerfile); single `postgres:18` compose remains available as the non-HA default deployment | — (storage axis; parallel) | **N** (gates storage-HA / RPO=0 claim, not the 2nd server replica) | `release-deploy`+`build-ci`+`sre` | P1 | **done (PR #3627 merged to dev)** |
| **WS-8** | Per-tier health contract (`/livez` vs `/readyz`; presentation `/readyz`→operator LB, core `/readyz`→presentation→core routing). **BYO-LB doc** + LB/session semantics (sticky-vs-stateless, TLS termination, long-lived-stream failover) | Four health paths exist; contract not tier-split | conceptual on WS-1/WS-2; **readyz needed before LB fronts replicas** | **Y** (readyz) | `docs-writer`+`release-deploy`+`sre` | P0 (readyz) / P2 (BYO doc) | planned |
| **WS-9** | **Failover test harness** — **continuous, incremental scenarios added as each feature lands** (not a final gate): sessions survive, leader re-elect no double-dispatch, outbox effectively-once, cursor-poll no lost events, re-home races, quorum-degrade, standby loss | Single-container test PG only | scenarios track WS-0…WS-7 as they land; stack needs WS-7 | N | `build-ci`+`release-deploy`; scenarios by `chaos-injector` | P1 (continuous) | planned |
| **WS-10** | **Background-job replica-safety classification** — checked-in, CI-auditable table (job → fenced-leader-only / independently-replica-safe / disabled-until-fixed); bring #2508 wall-clock passes to clock-guard | No classification; `app_perf_*`/`PreflightRunStore`/`DeploymentRunStore` not clock-guard-compliant (#2508) | audit + `disable-until-fixed` need nothing; **`fenced-leader-only` enforcement needs WS-3** | **Y** | `cpp-safety`+`sre`+`compliance-officer` | P0 | planned |
| **WS-11** | **HA-state observability** (NEW): leader identity/epoch, replica lag, quorum state, outbox backlog, failover duration, routing re-homes, split-brain alerts — Prometheus metrics + alert rules | None; ADR gestures at DB-clock monitoring (§4) + gauge coherence (§7a) only | WS-3, WS-7 | N (but ship *with* the 2nd replica — operating blind otherwise) | `sre`+`docs-writer` (+ the alert-rule gate, `docs/observability-conventions.md`) | P1 | planned |
| **WS-12** | **Single→HA cutover + DR (NEW):** runbook to move an existing single-Postgres/single-server deployment to shipped HA-PG + gateway-front reconfiguration rollout; **backup/PITR/WAL under HA-PG** (replaces the superseded `disaster-recovery.md`) | ADR supersedes `disaster-recovery.md` but nothing replaces backup/PITR | WS-7 | N | `release-deploy`+`sre`+`docs-writer` | P1 | planned |
| **WS-13** | **Agent-side gateway failover rollout (NEW):** agent endpoint discovery/failover (agent takes one `server_address` → one channel, `agent.cpp:1384`) + fleet rollout flipping direct-connect fleets to gateway-front | Single configured endpoint; no failover | WS-4 | Y (for gateway-fronted fleets) | `cross-platform`+`security-guardian` (agent) | P1 | planned |
| **WS-14** | **Coordination-substrate security & capacity review (NEW):** threat review of advisory locks / etcd / Patroni / HAProxy / fencing tokens; capacity + failure-domain + sync-quorum latency validation | None | WS-3, WS-7 | N | `security-guardian`+`sre` | P2 | planned |

## Delivery phases (dependency-ordered)

Prio is build-effort; the **safe-to-scale gate** above is the real constraint. Phases:

1. **Phase A — Foundation (build now, in parallel where the ladder allows):**
   `WS-1` (state → PG; milestones 1a/1b/1c pace on the migration ladder — *not* fully parallel),
   `WS-0` (agent idempotency+replay), `WS-2a` (durable outbox), `WS-10` (job-safety audit), and
   `WS-7` (HA-PG delivery — storage axis, fully parallel; unblocks WS-9's stack).
2. **Phase B — Multi-instance safety mechanisms (ALL required before a 2nd replica):**
   `WS-3` (fenced leader), `WS-4` (gateway routing), `WS-5` (presence), `WS-6` (PKI), `WS-8`-readyz,
   `WS-13` (agent gateway-front rollout, for gateway-fronted fleets). **Confirm the split question
   before starting** (see above).
3. **Phase C — Enable, validate, operate:**
   flip on the second replica; `WS-9` runs continuously throughout B/C; `WS-11` (observability) ships
   *with* the second replica; `WS-12` (cutover/DR), `WS-14` (security/capacity). `WS-2b` (spine) and
   `WS-8` tier-split readyz land with the ADR-1005 split.

## Shared with ADR-1005 (do not duplicate)

HA defers to the accepted presentation/core/engine decomposition:
- **Engine-tier HA** (UCE replicas/jobs, engine DB, leader-among-engines) — incl. **NVD/CVE sync**,
  withdrawn from WS-1 (ADR-0023 / ADR-1005 Phase 7).
- **MCP Decision-15 pre-commitments (a)–(k)** — WS-2's MCP durability *inherits* these; the open
  pin-lifecycle item is tracked there.
- The **presentation/core split** — WS-2b and WS-8 tier-split readyz land with it; the monolith
  satisfies the pre-split rows by co-location (no separate presentation to violate the boundary).

## Definition of done (per WS)

Each WS is done when its ADR-2002 guarantee holds **and has a WS-9 scenario that passes** (WS-9 is
continuous, so this is not circular): effectively-once (WS-0/1/3) — one effect **and** the original
outcome across an agent bounce + a primary failover; events (WS-2) — no committed event lost across
failover, replay from cursor on a *different* replica; leadership (WS-3) — no double-dispatch under
forced split-brain; routing (WS-4) — no lost/dup command across re-home / gateway restart / core
restart / dropped `set_gateway_route`; durability (WS-7) — RPO=0 across a host failure with 3-node
quorum on **distinct failure domains**, quorum-loss blocks writes (fail-closed).

## Maintenance

Update **Status** as workstreams move; keep **Current state** cites in step with the code — **prefer
symbol names, they drift** (the three-model review already found `agent.cpp`/`agent_registry.hpp` line
numbers had moved since the ADR was written). Store rows defer to `docs/postgres-migration-ladder.md`.
ADR-2002 governs on any conflict.
