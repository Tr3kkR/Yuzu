---
name: ha
description: High Availability control plane for Yuzu — the canonical entry point for any work on ADR-2002 (active-active server tier, gateway-fronted routing, Postgres-backed coordination seam, HA Postgres storage). Use when the user says "/ha", "/high-availability", "/ha-matrix", asks to plan or implement an HA workstream (WS-0…WS-14), asks "what's our HA gap" or "is it safe to run a second replica yet", asks to audit HA readiness, or starts work touching the coordination seam (leader election / fenced epochs / transactional outbox), gateway intra-cluster routing, shared `AgentRegistry` presence, PKI/CA HA, or the `deploy/docker/*ha*` / `scripts/ha/` surface. The skill bundles the two-axis model, the safe-to-scale gate, the delivery matrix (current-state + reviewers + status), the per-workstream workflow, and the load order for the routed reference docs.
---

# High Availability skill

The single entry point for any HA work in Yuzu. Bundles three things:

1. **The model** — the two independent axes and the safe-to-scale gate (get
   this wrong and a second replica double-dispatches destructive commands).
2. **The delivery matrix** — every workstream WS-0…WS-14: what it delivers,
   current state, dependencies, whether it gates a second replica, routed
   reviewers, and status.
3. **Gap/priority + workflow** — what to build next and the standard
   procedure for landing a workstream slice.

This skill does NOT replace ADR-2002 or the routed docs. It tells you which
to load, in which order, and what to confirm before you start cutting code.
**On any conflict, ADR-2002 governs the model and
`docs/ha-delivery-matrix.md` governs delivery** — this file is a pointer and
loses to both.

---

## Usage

```
/ha                       # default: print the matrix + the safe-to-scale gate, ask which WS to work on
/ha audit                 # snapshot of HA readiness — which WS are done, whether a 2nd replica is safe yet
/ha plan <WS>             # plan-only walk-through for a single workstream (e.g. WS-3, WS-7)
/ha implement <WS>        # full workflow: plan → governance → implement → test → docs for one WS slice
```

If invoked without a subcommand, default to printing **the matrix (Section 2)
+ the safe-to-scale gate (Section 1)** and asking which workstream to work on.

---

## 1. The model — read before sequencing anything

Authoritative reference: `docs/adr/2002-high-availability-architecture.md`
(the decisions) and `docs/ha-delivery-matrix.md` (the delivery spine). Read
them before this skill claims anything is "done."

### 1a. Two independent axes

- **Server-tier HA** — N presentation + core replicas (WS-0…WS-6, WS-8,
  WS-10, WS-11, WS-13).
- **Storage HA** — HA Postgres (WS-7). **A single Postgres is a valid,
  supported deployment; server-tier HA does not require it.**

"HA" as a *customer claim* = **both** axes + WS-9 (validation) + WS-11/WS-12
(operability). Do not conflate the axes: WS-7 shipping does not make the
server tier highly available, and a second replica is safe against a single
Postgres.

### 1b. ⚠️ The safe-to-scale gate (the load-bearing constraint)

**Do not equate "Phase A done" with "safe to run a second replica."** The
three-model adversarial review's strongest, unanimous finding:

> **A second server replica may be enabled only when WS-0, WS-1, WS-2(2a
> outbox), WS-3, WS-4, WS-5, WS-6, WS-10 are done, AND WS-8's per-tier
> `/readyz` exists.**

Miss any one and the failure is **not cosmetic**:
- No **WS-3** (fenced leader) → both replicas run the singleton workers →
  **double-dispatch of destructive commands** (software-deployment,
  quarantine, policy-remediation).
- No **WS-4/WS-5** → commands can't reach agents / scope evaluation drops
  agents on the replica lacking the local stream → **mis-targeting**.
- No **WS-6** → CRL numbering / enrollment **diverge** across replicas.

**WS-7 (HA Postgres) is NOT in this gate set** — it gates the storage axis
(no SPOF / RPO=0), not the second server replica. The "Gates 2nd replica?"
column in the matrix encodes this per row.

### 1c. Split ↔ HA — RATIFIED: decoupled (the split is NOT a prerequisite)

**Is the presentation/core split (ADR-0031) a prerequisite for active-active?
No — decoupled. Ratified by the ADR-1005 owner (Dave Rae), 2026-09-07.** Monolith
active-active is the target; the split is a parallel programme, not a gate for a
2nd replica. The one in-process blocker (direct agent `Subscribe` stream) is solved
by **gateway-fronting (WS-4)**, not the split.
- **Kimi's dissent (recorded, rebutted):** Kimi called the split a hard safety
  prerequisite. Every safety property it could mean — singleton double-dispatch
  (WS-3), in-memory sessions (WS-1a, **done**), stream routing (WS-4) — is closed in
  the monolith. What the split buys is presentation scale-out + separate readiness
  signals: **capacity, not safety.**
- **One-way dependency:** the split *consumes* HA (inherits WS-1 sessions, rides
  WS-2a's durable `event_outbox` for its event spine, takes MCP replay durability from
  WS-2b) — never the reverse. WS-2b spine and WS-8 tier-split `/readyz` are no-ops on
  the monolith and land with the split. Delivery lives in its own control plane:
  `docs/presentation-core-split-delivery-matrix.md` (the `/split` skill).

### 1d. Non-obvious model decisions (survived two+ adversarial reviews)

- **Coordination = a narrow seam, Postgres-backed by default** — fenced
  advisory-lock leader + LISTEN/NOTIFY-as-hint over a durable outbox +
  reconnect cursor-poll; pluggable for SaaS; ship one impl. No new SPOF
  (Postgres already bounds availability, ADR-0007 fail-closed).
- **Effectively-once, NOT exactly-once** — transactional outbox +
  claim-before-side-effect + receiver-side idempotency (agent/gateway dedup on
  `command_id`). A dup must **replay the terminal outcome**, never return a
  bare `REJECTED` (that is the "effect-once, result-maybe-lost" bug WS-0 closes).
- **Intra-cluster gateway routing is net-new work** — OTP `pg` is
  broadcast-only; per-agent lookup is node-local ETS. "pg finds the exact
  node" is false; per-agent distributed routing must be built (WS-4).
- **The routing directory must be fenced** — (agent_id, connection_epoch,
  cluster_id, session_id, lease_until) with CAS register/deregister, else a
  stale replay overwrites a newer re-home.
- **Sessions → durable Postgres (DB wall-clock)** reverses the as-built
  in-memory-monotonic design and owns the regression risk on JIT-elevation /
  MFA windows.
- **Durability is selectable; default 3-node quorum** (1 primary + 2 sync
  standbys, ANY 1) on **distinct failure domains** — unconditional 2-node
  RPO=0 was a footgun (single standby loss stalls all writes).
- **Model:** hybrid, general product capability (on-prem-first + SaaS-later),
  NOT one customer. **Gateway-fronting is mandatory in HA** (direct-connect
  kept for single-node). Don't assume HA Postgres.

---

## 2. The delivery matrix — current state, reviewers, status

Source of truth: `docs/ha-delivery-matrix.md`. Read it before this skill
claims a status. WS-0…WS-10 come from ADR-2002 §Decomposition; WS-11…WS-14 are
delivery/ops workstreams the three-model review surfaced as missing.

**Verified 2026-09-10 (against `origin/dev`): DONE — WS-0 (#3662), WS-1 (1a+1b+1c),
WS-2a (2a-1 + 2a-2 #3924), WS-3 (3.1–3.4 — #4011/#4134/#4169/#4194), WS-7 (#3627),
WS-10 10.1/10.2. In flight: WS-4 (4.1 built — fenced agent→cluster routing directory,
INERT — not yet merged to `origin/dev`). Next gate items: WS-4 (4.2-4.4), WS-5, WS-6,
WS-8-readyz.**

> **⚠️ Standing instruction — update on close.** Every PR that closes or materially
> changes the status of a workstream here MUST update its row **and** re-stamp the
> Verified line in the SAME PR (source of truth: `docs/ha-delivery-matrix.md`; this
> table mirrors it). A matrix from a stale checkout is worse than none — treat status
> drift as a review-blocking defect, exactly like a stale doc comment. (This skill was
> itself found 557 commits stale once; hence the mandate.)

**`Gates?`** = does the safe-to-scale gate depend on this row (distinct from Prio).

| WS | Delivers | Depends on | Gates? | Routed reviewers | Prio | Status |
|----|----------|-----------|:---:|------------------|------|--------|
| **WS-0** | Durable agent-side command idempotency **+ terminal-outcome replay** (dup replays stored result, not bare `REJECTED`) | — | **Y** | `cpp-safety`+`cpp-expert` | P0 | **done (PR #3662 merged)** |
| **WS-1** | Server-plane state → Postgres: (1a) sessions DB-time; (1b) `execution_tracker`+command-correlation atomic counters; (1c) HA-critical store subset | migration ladder (serializes at the migration-version counter) | **Y** | `authdb`+`security-guardian` (1a); `architect`+`sre`+`cpp-safety` (1b/1c) | P0 | **done — 1a+1b+1c** |
| **WS-2** | (2a) durable **event outbox** + NOTIFY fan-out [monolith-OK]; (2b) **core→presentation event spine** [*defers to ADR-1005*]; MCP session/replay durability | 2a: WS-1(1b); 2b: ADR-1005 split | **Y** (2a) | `architect`+`sre`+`security-guardian`(MCP)+`docs-writer` | P1 | **2a done (2a-1 + 2a-2 #3924); 2b/MCP outstanding** |
| **WS-3** | Coordination seam: **fenced `LeaderElector`** (monotonic epoch in claim txn) + leader/**transactional-outbox**/receiver-idempotency worker refactor incl. policy remediation | **WS-0, WS-1, WS-2(2a)** | **Y** | `architect`+`cpp-safety`+`security-guardian` | P1 | **3.1 done (#4011); 3.2 done (#4134); 3.3 done (#4169); 3.4 done (#4194)** |
| **WS-4** | Gateway routing + multi-cluster: fenced `agent→cluster` directory, **net-new distributed intra-cluster agent→node routing**, `gateway_node` convergence | **WS-1, WS-3, WS-0** | **Y** | `gateway-erlang`+`security-guardian`+`architect`+`cpp-safety` | P1 | **in progress (4.1 done)** |
| **WS-5** | Shared agent presence / health / **scope-eval population** across core replicas | **WS-4, WS-1, WS-3, WS-10** | **Y** | `security-guardian`+`architect`+`sre`+`docs-writer` | P1 | planned |
| **WS-6** | PKI/CA HA: CA key → `SecretCodec` blob in PG, `CaStore` → PG, **durable CRL numbering + publication state machine**, KEK versioning/rollout/rollback, enrollment → PG | **WS-1(`ca_store`), WS-3** | **Y** | `security-guardian`+`cpp-safety`+`docs-writer` | P1 | planned |
| **WS-7** | **HA-PG delivery**: Patroni+etcd+HAProxy Compose profile, selectable durability (3-node quorum default, distinct failure domains), operator-plane LB profile | — (storage axis; parallel) | **N** | `release-deploy`+`build-ci`+`sre` | P1 | **done (PR #3627 merged to dev)** |
| **WS-8** | Per-tier health contract (`/livez` vs `/readyz`; presentation→operator LB, core→presentation routing). **BYO-LB doc** + LB/session semantics | conceptual on WS-1/WS-2; readyz before LB fronts replicas | **Y** (readyz) | `docs-writer`+`release-deploy`+`sre` | P0 readyz / P2 doc | planned |
| **WS-9** | **Failover test harness** — continuous, incremental scenarios added as each feature lands (not a final gate): session survival, no double-dispatch, effectively-once, cursor-poll no-loss, re-home races, quorum-degrade, standby loss | scenarios track WS-0…WS-7 as they land | N | `build-ci`+`release-deploy`; scenarios by `chaos-injector` | P1 (continuous) | planned |
| **WS-10** | **Background-job replica-safety classification** — checked-in, CI-auditable table (job → fenced-leader-only / replica-safe / disabled-until-fixed); bring #2508 wall-clock passes to clock-guard | audit+disable need nothing; `fenced-leader-only` enforcement needs WS-3 | **Y** | `cpp-safety`+`sre`+`compliance-officer` | P0 | **10.1/10.2 done (#4092); 10.3 enforcement wired by WS-3 3.2** |
| **WS-11** | **HA-state observability** (NEW): leader identity/epoch, replica lag, quorum state, outbox backlog, failover duration, routing re-homes, split-brain alerts — Prometheus metrics + rules | WS-3, WS-7 | N (ship *with* the 2nd replica) | `sre`+`docs-writer` (+ alert-rule gate) | P1 | planned |
| **WS-12** | **Single→HA cutover + DR** (NEW): runbook to move an existing single deployment to HA-PG + gateway-front rollout; **backup/PITR/WAL under HA-PG** (replaces superseded `disaster-recovery.md`) | WS-7 | N | `release-deploy`+`sre`+`docs-writer` | P1 | planned |
| **WS-13** | **Agent-side gateway failover rollout** (NEW): agent endpoint discovery/failover + fleet rollout flipping direct-connect fleets to gateway-front | WS-4 | Y (gateway-fronted fleets) | `cross-platform`+`security-guardian` | P1 | planned |
| **WS-14** | **Coordination-substrate security & capacity review** (NEW): threat review of advisory locks / etcd / Patroni / HAProxy / fencing tokens; capacity + failure-domain + sync-quorum latency validation | WS-3, WS-7 | N | `security-guardian`+`sre` | P2 | planned |

### Hard invariants that must NOT regress when landing any WS

Pulled from ADR-2002 and the matrix's Definition-of-Done. Every WS PR checks:

- **Effectively-once, not exactly-once** — one effect *and* the original
  outcome across an agent bounce + a primary failover. A dup never loses the
  first result.
- **Fenced leadership** — a monotonic epoch is checked inside the claim
  transaction; a stale leader's writes are rejected. No singleton worker runs
  without holding the fence.
- **No committed event lost across failover** — events are durable (outbox)
  and replayable from a cursor on a *different* replica.
- **Routing directory is fenced** with CAS register/deregister — no stale
  replay overwrites a newer re-home.
- **RPO=0 across a host failure with 3-node quorum on distinct failure
  domains; quorum loss blocks writes (fail-closed)** — unless the operator has
  explicitly opted into degrade-to-async (WS-7's `YUZU_PG_SYNC_STRICT`).
- **A new background job is classified** (fenced-leader-only / replica-safe /
  disabled) in the WS-10 table before it can run under active-active.
- **Every WS is done only when it has a passing WS-9 scenario** (WS-9 is
  continuous, so this is not circular).

---

## 3. Gap / priority — what to build next

Prio in the matrix is **build-effort**; the **safe-to-scale gate** is the real
constraint. Delivery phases (dependency-ordered):

1. **Phase A — Foundation (build now, parallel where the ladder allows):**
   `WS-1` (state→PG; 1a/1b/1c pace on the migration ladder, *not* fully
   parallel), `WS-0` (agent idempotency+replay), `WS-2a` (durable outbox),
   `WS-10` (job-safety audit), and `WS-7` (HA-PG — storage axis, fully
   parallel; **DONE, PR #3627 merged**, unblocks WS-9's stack).
2. **Phase B — Multi-instance safety (ALL required before a 2nd replica):**
   `WS-3` (fenced leader), `WS-4` (gateway routing), `WS-5` (presence),
   `WS-6` (PKI), `WS-8`-readyz, `WS-13` (agent gateway-front rollout).
   **The split question (§1c) is RESOLVED — decoupled, ratified by the ADR-1005 owner (Dave Rae, 2026-09-07); the split does not gate a 2nd replica.**
3. **Phase C — Enable, validate, operate:** flip on the second replica;
   `WS-9` runs continuously throughout B/C; `WS-11` ships *with* the second
   replica; then `WS-12` (cutover/DR), `WS-14` (security/capacity). `WS-2b`
   (spine) and `WS-8` tier-split readyz land with the ADR-1005 split.

**Suggested next slices** (as of 2026-09-07 — `docs/ha-delivery-matrix.md` row
cites are authoritative):
- **Done:** WS-0 (#3662), WS-1 (1a+1b+1c), WS-2a (2a-1 + 2a-2 #3924), WS-3 3.1
  (#4011), WS-7 (#3627), WS-10 10.1/10.2. The storage axis is complete.
- The **highest-leverage next** is **WS-3 3.2** (gate the singleton loops
  leader-only) — it unblocks WS-10's `fenced-leader-only` enforcement (10.3) and
  WS-5's presence work. Then the remaining gate set: **WS-4** (gateway routing),
  **WS-5** (presence), **WS-6** (PKI), **WS-8**-readyz (P0). A loss-free
  cross-replica reconnect (durable outbox replay) is the open 2a-2 follow-up.

**Shared with ADR-1005 (do not duplicate):** engine-tier HA (incl. NVD/CVE
sync, withdrawn from WS-1), the MCP Decision-15 pre-commitments WS-2 inherits,
and the presentation/core split (WS-2b + WS-8 tier-split readyz land with it).

---

## 4. Standard workflow for a workstream slice

For every WS in the matrix:

1. **Read first, in order:**
   - This skill (gap framing + the safe-to-scale gate).
   - `docs/ha-delivery-matrix.md` for the row's current-state cites +
     dependencies + reviewers.
   - `docs/adr/2002-high-availability-architecture.md` for the decision the
     slice must satisfy (the ADR governs on any conflict).
   - `docs/postgres-migration-ladder.md` for any WS-1/store-migration slice
     (it is the authoritative per-store status).
   - `docs/adr-1005-execution-plan.md` if the slice touches a shared seam
     (presentation/core split, engine tier, MCP Decision-15).

2. **Plan.** Produce a short plan covering: the ADR-2002 guarantee it delivers;
   whether it is in the safe-to-scale gate set; schema changes (via
   `MigrationRunner` / the PG store playbook); the fence/epoch or
   idempotency/outbox mechanism if applicable; and the **WS-9 scenario** it
   must add (a WS is not done without one).

3. **The split question (§1c) is RESOLVED** — decoupled, ratified by the ADR-1005
   owner (Dave Rae, 2026-09-07). Phase-B proceeds on the monolith track; no per-slice re-confirmation needed.

4. **Implement** as a focused PR per slice, in an isolated worktree off `dev`.
   Drive schema through `MigrationRunner` / `docs/postgres-store-playbook.md`,
   fencing through the `LeaderElector` epoch contract, and receiver dedup
   through the agent/gateway `command_id` path.

5. **Test.** Run `/test` before commit; add the WS-9 failover scenario and run
   the failover harness (`scripts/ha/` for the storage axis). Note WS-7-class
   deploy-only changes are a `/test` no-op — CI's build legs + the harness are
   the real gate there.

6. **Governance.** Run `/governance dev..HEAD` before pushing — the routed
   reviewers in the WS row are unconditional (e.g. `cpp-safety` on any fencing
   /ownership change, `security-guardian` on the coordination substrate,
   `gateway-erlang` on WS-4). CRITICAL/HIGH block merge. **Self-adversarial
   review (Sol / Kimi) before pushing review-fixes on HA work** — it has
   repeatedly caught blocking findings a reviewer would hit next round.

7. **Docs + evidence.** docs-writer picks up user-manual / ops-runbook updates
   in Gate 2; ship them in the same PR. For the coordination substrate,
   WS-14's threat/capacity notes and a `docs/security-reviews/` record apply.

---

## 5. Cross-references

- **The decisions:** `docs/adr/2002-high-availability-architecture.md`
- **The delivery spine (authoritative status):** `docs/ha-delivery-matrix.md`
- **Per-store migration status:** `docs/postgres-migration-ladder.md`
- **PG store authoring recipe:** `docs/postgres-store-playbook.md`
- **Shared decomposition / engine tier / MCP Decision-15:**
  `docs/adr-1005-execution-plan.md` + `docs/adr/003{1,2,3}-*.md`
- **WS-7 shipped surface:** `deploy/docker/docker-compose.ha-postgres.yml`,
  `deploy/docker/ha-postgres/`, `scripts/ha/`,
  `docs/user-manual/ha-postgres.md`, `docs/ha-postgres-ws7-plan.md`
- **Routed reviewers** are per-row in the matrix; the coordination-substrate
  concern routes `security-guardian` + `architect`.
