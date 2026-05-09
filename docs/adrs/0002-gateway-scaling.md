# ADR-0002: Gateway scaling — direction toward WhatsApp/RabbitMQ density tier

- **Status**: Proposed — design direction; commits no code yet.
- **Accepted-by**: pending project-lead sign-off.
- **Date**: 2026-05-09
- **Tracking issue**: TBD (umbrella issue to be filed as a follow-up to
  this ADR; referenced in the implementation plan section below).
- **Related**:
  - ADR-0001 (QUIC transport — msquic + quicer). The gateway QUIC bring-up
    is PR 4 of that workstream and is the natural inflection point for
    the scaling work this ADR describes.
  - `.claude/projects/-Users-nathan-Yuzu/memory/project_gateway_scalability_workstream.md`
    (private project memory — informal decomposition that fed this ADR).
  - #904 / governance UP-14 (server-side bounded bidi dispatcher pool)
    closed the **server**'s thread-fanout problem on 2026-05-09; this
    ADR is its sibling for the **gateway**.
  - `docs/capability-map.md` Reliability / Scalability section.
  - `docs/enterprise-readiness-soc2-first-customer.md` Workstream D.
- **Supersedes**: nothing. This is the first explicit scaling ADR for
  the gateway.

## Context

Yuzu's production topology has two fanout tiers:

```
agents (10² … 10⁶)  →  gateway (Erlang/OTP, 1..N nodes)  →  server (C++, single-node)
```

Long-lived bidi RPCs (`Subscribe`, `DownloadUpdate`) carry the bulk of
the connection budget. The agent's `Subscribe` stream is open for the
lifetime of the connection — same shape as a WhatsApp client or a
RabbitMQ consumer. At enterprise scale this is **the** scaling axis;
short-lived unary RPCs (Register, Heartbeat, ReportInventory) are
trivial by comparison.

### Where each tier stands today

* **Server (C++):** as of #904 (2026-05-09) the agent-facing transport
  listener uses a bounded bidi-handler thread pool sized at start by
  `ListenerOptions::bidi_dispatcher_pool_size`. Default
  `clamp(64, hardware_concurrency × 8, 4096)`; saturation rejects with
  `StatusCode::ResourceExhausted`. Gateway-mode deployments don't
  pressure this pool because the gateway terminates Subscribe per-fleet
  and only one upstream stream per gateway node reaches the server.
  The server's bounded pool is a per-node ceiling, not a fleet ceiling.
* **Gateway (Erlang/OTP):** today uses `grpcbox` for the gRPC server
  surface, with a per-RPC Erlang process spawned by grpcbox's stream
  handler. The gateway has not been load-tested above ~10² simulated
  agents in CI; production deployments to date have been small
  (development clusters, design partners). The single-node ceiling is
  **unmeasured** but bounded by:
  - grpcbox's accept-pool / stream-process model (opaque to us).
  - BEAM's `+P` process limit (default `262_144`; raisable to `134_217_728`).
  - File-descriptor limits (per-systemd-unit, per-cgroup).
  - TCP socket buffer sizing (per-socket, default ~256 KiB on Linux).
  - prometheus_httpd label cardinality (per-agent labels would explode).

### Industry reference points

| System | Connection density per node | Architecture notes |
|---|---|---|
| WhatsApp (2012) | ~2M concurrent TCP per FreeBSD Erlang node | Rick Reed's @scale talk; tuned BEAM (`+K true`, `+P 16M`, scheduler pinning), tuned FreeBSD (`kern.maxfiles`, jumbo frames, NIC IRQ pinning), per-connection Erlang process (~2 KiB heap with `fullsweep_after, 10`). |
| RabbitMQ (current) | ~100K AMQP connections per node | `file_handle_cache`, `vm_memory_high_watermark`, Erlang-distribution tuning. |
| Redis | N/A (single-threaded event loop, ~10⁵ ops/sec) | Different architecture; not a direct comparison for long-lived bidi. |

The applicable target tier is **WhatsApp** — long-lived stateful bidi
streams over TLS, with per-connection identity. RabbitMQ is the floor;
WhatsApp is the headroom we want.

### Why this needs an ADR now

Three reasons converge:

1. **The QUIC migration (#376) is the inflection point.** PR 4 of #376
   replaces grpcbox in the gateway with quicer (raw QUIC NIF). Once
   grpcbox is gone we own the connection lifecycle from the UDP socket
   up — buffer sizes, stream cancellation, accept-pool topology, and
   process-to-stream mapping are all directly tunable. This is a
   **one-time** opportunity: if we lock in scaling decisions before
   PR 4 lands, PR 4 becomes the design vehicle. If we wait, we'll
   re-do the work twice.
2. **#904 closed the server-side fanout.** The bounded dispatcher pool
   means server scaling is now operator-controlled. The gateway is the
   next ceiling and is the one that matters at enterprise scale —
   gateway-mode is the production topology for fleets >~2K agents.
3. **Pilot customer pipeline** (Workstream G of the enterprise readiness
   plan) brings 10⁴–10⁵ agent counts into testing horizon over the
   next 1–2 quarters. The gateway must be load-validated before any
   pilot signs an SLA.

## Decision drivers

In rough priority order:

1. **Connection density per node.** Target is WhatsApp tier (~10⁶ per
   node). Hard floor is RabbitMQ tier (~10⁵).
2. **Operational simplicity.** Single-node deployments must remain
   trivial (`docker run` works). Clustering is opt-in for very large
   fleets, not mandatory.
3. **Process model.** Erlang is committed (no migration off OTP planned
   or considered). Within Erlang, the choice is process-per-connection
   (matches WhatsApp's design) vs a gen_statem dispatcher fronting a
   small worker pool (RabbitMQ-ish). The per-connection model wins on
   isolation and fault containment; the dispatcher model wins on
   memory at extreme density. **Bias: process-per-connection** because
   isolation is load-bearing for the agent-management workload (one
   agent's misbehaviour cannot affect others).
4. **grpcbox dependency.** grpcbox is a constraint we want to remove.
   It abstracts the connection model, the stream cancellation
   semantics, and the buffer tuning surface — which is convenient for
   small-scale gRPC services and a liability for high-density bidi.
   The QUIC migration removes it as a side effect; this ADR aligns the
   scaling work with that removal.
5. **Compatibility with the C++ server's bounded pool.** Gateway must
   not push more upstream concurrent Subscribe streams than the
   server's pool can absorb. Today the server default is
   ≤4096 streams. The gateway either multiplexes (one upstream stream
   per gateway node, fanning out N agent streams downstream) or
   coordinates with operator pool sizing.
6. **Observability without cardinality explosion.** prometheus_httpd
   labels must NOT include `agent_id` or any 10⁶-cardinality
   dimension. Per-agent state lives in ETS / per-process state, not
   in metric labels.
7. **Soak verifiability.** Whatever architecture lands MUST be
   validatable by an in-tree synthetic-agent simulator running in CI
   (with ≥10⁴ simulated agents per driver box, scaling to 10⁵ in a
   nightly job).

## Decision

**Direction (proposed):**

* **A. Process-per-connection on quicer.** Once PR 4 of #376 lands,
  each agent QUIC connection is owned by a dedicated `gen_statem`
  process under a `simple_one_for_one` supervisor. The `gen_statem`
  drives the Subscribe bidi stream and any short-lived unary RPCs
  multiplexed over the same QUIC connection. State: `~2-4 KiB` heap
  per process post-hibernate, matching the WhatsApp envelope.
* **B. Single-node first; clustering second.** Optimise the single-node
  ceiling to ~10⁶ agents before introducing clustering. Clustering is
  scoped as a follow-up ADR (ADR-0003 or similar) and is gated on a
  demonstrated single-node ceiling that warrants horizontal scale.
* **C. Soak harness in tree.** A synthetic-agent simulator written in
  Erlang (one BEAM process per simulated agent, identical to
  production agent behaviour at the wire level) lives in
  `gateway/test/load/`. CI runs a 10⁴-agent variant on each PR;
  nightly runs a 10⁵-agent variant. The harness drives Subscribe +
  Heartbeat + occasional command round-trips and asserts:
  - p99 dispatch latency under 100 ms.
  - Process count stable (no leaks).
  - VmRSS growth bounded by `O(N_agents × known-per-process-budget)`.
  - prometheus_httpd `/metrics` scrape latency under 1 s.

**Rejected — option (D) "external proxy".** A reverse proxy
(HAProxy, envoy) in front of the gateway would terminate TLS and fan
out to a smaller pool of gateway worker connections. This trades one
scaling problem for another (the proxy's connection density), adds an
operational dependency, and breaks per-connection identity at the
gateway. Not pursued.

**Rejected — option (E) "stay on grpcbox forever".** grpcbox does not
expose the surface we need (per-stream buffer tuning, accept-pool
sizing, send-completion ordering control) and the QUIC migration is
removing it anyway. Continuing to invest in grpcbox-bound scaling work
would be thrown away at PR 4.

**Conditional accept.** This decision becomes binding when:

1. The QUIC spike's gateway side (PR 0 covered the C++ side; gateway
   PR 0' is implicit) demonstrates quicer can carry ≥10⁴ concurrent
   bidi streams without process-table or socket-table exhaustion at
   default tuning.
2. A first-pass soak harness (10⁴ agents) runs green on a developer
   box with default tuning.
3. Project lead sign-off on the workstream decomposition below.

## Workstream decomposition

Eight items. Each is a sub-issue of the umbrella tracking issue. Order
matters where noted; otherwise items can ship in any sequence.

| # | Item | Hard predecessor | Notes |
|---|---|---|---|
| 1 | **BEAM startup tuning audit + bake.** `gateway/config/vm.args` review: `+P 16M`, `+Q 65536`, `+K true`, `+sbt db`, `+sbwt very_short`, `+swt very_low`. Bake into `release.yml` so CI artifacts ship with the tuned values. | none | Cheapest item; do first to establish the baseline ceiling. |
| 2 | **Per-process memory tuning.** `{fullsweep_after, 10}` or `hibernate_after` on the per-agent gen_statem. Goal: ≤4 KiB heap per idle agent process. | item 1 | Validate via `erlang:process_info/2` post-hibernate in soak. |
| 3 | **Soak harness in `gateway/test/load/`.** Synthetic agents driving Subscribe + Heartbeat + command round-trip; CI gate at 10⁴, nightly at 10⁵. | items 1+2 | Prerequisite for every later item — no PR after item 3 may regress soak. |
| 4 | **TCP / QUIC socket-options profile.** `{nodelay, true}`, send/recv buffer sizes (~256K target after measurement, NOT default), keepalive cadence aligned to heartbeat. Document under `docs/gateway-tuning.md`. | item 3 | Profile **before** prescribing — the WhatsApp numbers are FreeBSD; Linux defaults differ. |
| 5 | **Supervisor topology audit.** Per-agent processes MUST live under `simple_one_for_one`. `one_for_one` with millions of children is a known footgun (linear restart-strategy walks, ets writes per child). | item 3 | Walk every supervisor in `gateway/apps/yuzu_gw/src/`. |
| 6 | **grpcbox removal (rolls into PR 4 of #376).** Replace grpcbox with quicer + a thin yuzu_gw dispatcher. The dispatcher owns the connection-to-process mapping; per-connection gen_statem replaces grpcbox's per-RPC process. ADR-0001 already commits to this; ADR-0002 only adds the explicit scaling-driven rationale. | items 1-3 | This is the inflection — every scaling item below this row depends on owning the connection lifecycle directly. |
| 7 | **Observability under load.** prometheus_httpd label-cardinality budget; ETS sizing for per-agent state if any; msacc traces on schedulers; `/metrics` scrape latency budget. | items 3+6 | Pin a cardinality-explosion test in soak — `/metrics` must scrape under 1 s with 10⁵ agents. |
| 8 | **Cluster-mode ADR (follow-up, not in this ADR's scope).** When item 6 has demonstrated single-node ceiling and the operator demand justifies horizontal scale, write ADR-000N for clustering. Likely libcluster + consistent-hash agent_id → gateway node, with partition handling. | items 6+7 + measured demand | One-way door — do NOT pre-commit topology before measurement. |

Hard not-doing-now (tracked separately or deferred):

* **OS migration to FreeBSD.** WhatsApp's 2M-per-node was on FreeBSD;
  Yuzu is Linux-first. Linux can hit similar density (~10⁶) with
  tuned `epoll`, but the FreeBSD ceiling will remain higher. Not
  pursuing FreeBSD as a target OS.
* **Erlang distribution between gateway nodes.** Cluster-mode
  workstream — see item 8.
* **Replacing the C++ server's bounded pool.** #904 is sufficient;
  gateway-mode termination keeps server-side concurrency bounded by
  gateway count (small) regardless of fleet size.

## Consequences

### Positive

1. **Predictable single-node density.** With items 1-5 + 7 in place,
   the gateway has a measured ceiling tied to BEAM/Linux tuning, not
   grpcbox's opaque accept-pool model.
2. **Direct QUIC stream control post-item 6.** Per-stream send buffer
   sizing, application-level back-pressure (the `quicer:async_send` SYNC
   bit caveat from the spike), and idle-stream timeouts are all
   directly addressable rather than mediated by grpcbox.
3. **Operational floor.** Even if the project never reaches 10⁶ per
   node in deployment, items 1-5 lift the floor from "untested" to
   "10⁵-validated", which is sufficient for the foreseeable pilot
   pipeline (Workstream G).
4. **Compose with #904.** The bounded server pool gives operators a
   visible and tunable ceiling; the gateway scaling work gives them
   the headroom that lets the server pool stay at its default in
   gateway-mode.

### Negative / costs

1. **Soak harness is real engineering.** A 10⁵-agent simulator in
   Erlang is non-trivial. Estimated effort: 1-2 weeks of focused work
   for items 1-3 combined; nightly CI infrastructure adds runner cost.
2. **Tuning is environment-specific.** Item 4's socket-buffer numbers
   are not portable across cloud providers (AWS ENA, GCP gVNIC, Azure
   accelerated networking each have different defaults). Document
   ranges, not magic numbers.
3. **prometheus_httpd cardinality discipline is forever.** Once the
   soak harness exists, every new metric must be scrutinised for
   per-agent labels. No exceptions, no "just for debugging".
4. **PR 4 of #376 grows in scope.** The grpcbox removal already lives
   there; the scaling decisions in items 1, 2, 4, 5 may need to land
   in PR 4 (rather than as separate PRs) to avoid a scaling regression
   between the grpcbox-era code and the post-grpcbox code. Plan for a
   larger-than-typical PR 4 review.

### Mitigation matrix

| Risk | Mitigation |
|---|---|
| Soak harness becomes flaky and is silenced | Pin nightly soak as a **release-gate** (no merge to main if soak is broken, mirroring the `nightly-broken` discipline); per-component pass-fail attribution so a flake's source is debuggable, not a black-box red. |
| Single-node ceiling is below 10⁵ even after items 1-5 | Item 8 (clustering) is escalated from "follow-up" to "concurrent". The bias toward single-node first is a soft preference, not a hard one — measurement decides. |
| grpcbox removal breaks an unanticipated grpc-only invariant | PR 4 of #376 lands behind a feature flag (`--transport grpc`) for the dual-stack period (PR 5 / PR 6 of #376). Rollback is a flag flip. |
| QUIC NIF crash takes BEAM down (per ADR-0001 rejected-alternatives caveat) | Crash-isolation supervisor trees: quicer NIF processes live under their own dedicated supervisor; a NIF crash kills only the affected gen_statem, not the whole BEAM. Validated in soak by injecting `quicer:close_connection/1` mid-stream and asserting BEAM stays up. Inherits ADR-0001 §"Mitigation matrix" "quicer NIF crash takes BEAM VM down" row. |
| Linux distro defaults bite us in pilot | `docs/gateway-tuning.md` ships sysctl + ulimit recipes per supported distro (Ubuntu 24.04, RHEL 9, Amazon Linux 2023). Pilot deployments require operator sign-off on the tuning checklist. |
| FreeBSD demand from a customer | Document in `docs/gateway-tuning.md` that FreeBSD has been measured higher in the literature but is not Yuzu-supported; offer a pilot-engineering escalation path. |

## Implementation status

| Item | Status |
|---|---|
| ADR drafted | **2026-05-09** (this document) |
| Project-lead sign-off | Pending |
| Umbrella tracking issue filed | Pending |
| Item 1 (BEAM startup tuning) | Not started |
| Item 2 (per-process memory) | Not started |
| Item 3 (soak harness) | Not started |
| Item 4 (socket profile) | Not started |
| Item 5 (supervisor audit) | Not started |
| Item 6 (grpcbox removal — PR 4 of #376) | Pending — predecessor PRs 1c-4..1c-6 of #376 still in flight |
| Item 7 (observability under load) | Not started |
| Item 8 (clustering ADR) | Deferred per workstream ordering |

## Validation gate

This ADR's decision becomes binding when:

1. **Soak harness greenlit at 10⁴.** Item 3 lands and a developer-box
   run holds 10⁴ simulated agents under default tuning for 1 hour
   without process-table growth, RSS growth above linear, or scheduler
   utilisation drift.
2. **Item 6 design review passed.** PR 4 of #376's design doc covers
   the connection-to-process mapping, the per-stream send-back-pressure
   model (using the `quicer:async_send` SYNC bit per ADR-0001 spike
   caveats), and the idle-stream timeout. Reviewer: cpp-expert +
   gateway-erlang agents + project lead.
3. **No nightly-broken outstanding** on `feat/quic-transport` or `main`
   for the 24h preceding sign-off.

## Spike-style evidence capture (Workstream D pattern, lifted from ADR-0001)

When the soak harness lands (item 3), it MUST persist evidence under
`docs/spike-results/0002-gateway-scaling/` mirroring the ADR-0001 spike
layout:

* `README.md` — methodology, tuning applied, results summary.
* Raw `.jsonl` per-run logs (timestamp, agent_count, process_count,
  rss_kb, p99_latency_ms, schedulers_utilization).
* Plots / summary charts where helpful (PNG; small, < 200 KiB).
* Caveats section — what didn't work, what surprised us, what's known
  to be flaky and why.

This gives future Claude sessions and SOC 2 auditors a tamper-evident
record of the scaling validation, identical pattern to PR 0 of #376.

## Release communication checklist

When item 6 ships (grpcbox removal as part of PR 4 of #376), release
notes MUST include:

* Operator-visible tuning changes (vm.args defaults shipped).
* Required cgroup / ulimit / sysctl changes for high-density
  deployments (linking `docs/gateway-tuning.md`).
* Migration path for design-partner clusters that depended on grpcbox-
  specific behaviour (none expected, but flag for review during PR 4).
* Compose-file updates if the gateway needs new ulimits (likely yes,
  mirroring the server's #904 changes).

This complements ADR-0001's existing release-communication checklist
for the C++ side of the QUIC migration; release notes for the cut
that contains PR 4 should reference both.

## References

* ADR-0001 — `docs/adrs/0001-quic-transport-msquic-quicer.md`. The
  gateway QUIC bring-up (PR 4 of #376) is item 6 of this ADR's
  workstream.
* `docs/spike-results/0001-quic-transport/README.md` — quicer caveats
  from the C++ side (4-element event tuples, async_send SYNC bit).
  Item 6 inherits these.
* WhatsApp engineering blog (Reed, 2012) — "Scaling to Millions of
  Simultaneous Connections" @scale talk; canonical reference for the
  WhatsApp tier numbers cited above.
* RabbitMQ documentation — "Networking and RabbitMQ" tuning guide;
  source for the ~100K floor cited above.
* `docs/capability-map.md` Reliability / Scalability section.
* `docs/enterprise-readiness-soc2-first-customer.md` Workstream D.
* `docs/user-manual/server-admin.md` "Bidi dispatcher pool sizing"
  (#904 / 2026-05-09) — the server-side counterpart to this ADR's
  gateway-side scaling story.
