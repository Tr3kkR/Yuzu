# Erlang OTP Gateway Blueprint Review and Scale Recommendations

## Scope Reviewed

- `docs/erlang-gateway-blueprint.md`

This review focuses on the target operating model of **millions of agents** and
**hundreds of plugins**, with parity ambitions for the leading commercial
endpoint-management platforms in this class, including command and control, inventory, vulnerability scanning,
and anti-virus workflows.

## Executive Assessment

The blueprint is directionally strong and makes the right strategic split:
keeping the C++ server as control-plane authority while moving persistent
agent-stream fanout and aggregation to Erlang/OTP. The per-agent process model,
ETS+pg routing, and phased migration are appropriate for very large concurrency.

However, at the stated target scale, the design needs additional rigor in six
areas:

1. **Bounded backpressure and overload policy** (mailboxes, stream writes,
   operator requests).
2. **Failure-domain containment** (cluster partitions, node churn, reconnect
   storms).
3. **Protocol and payload contracts** for plugin heterogeneity at scale.
4. **Security hardening and tenant isolation** for high-risk actions (AV,
   remediation, script exec).
5. **Data-plane decomposition** for heavy workflows (vuln scans/AV content,
   artifacts, long-running jobs).
6. **SLO-driven capacity validation** beyond high-level memory estimates.

## Strengths

- **Correct separation of control vs command planes** to remove the C++
  single-process bottleneck.
- **One process per agent** is an excellent fit for this connection model.
- **Supervision-first model** provides blast-radius control and better MTTR.
- **Phased migration** reduces operational risk and allows side-by-side
  correctness validation.
- **Telemetry-first mindset** is present and should be expanded into explicit
  SLOs.

## Key Risks and Critique

### 1) Broadcast fanout can still collapse under burst load

The router currently fans out directly to all targets. At million-agent scale,
"O(n) dispatch now" can saturate schedulers, mailbox queues, and network buffers
when large broadcasts overlap.

**Recommendation:** add a hierarchical fanout model:

- global command coordinator
- per-node shard coordinators
- per-plugin/segment cohorts

and enforce command admission limits (token bucket + priority queues).

### 2) Mailbox growth is under-specified

The design notes backpressure, but does not define strict queue bounds per agent
process or operator stream.

**Recommendation:** define hard limits and policies:

- per-agent max queued command frames
- per-command max in-flight responses
- drop/defer/retry semantics by command class
- operator-facing partial-result semantics when limits are hit

### 3) Erlang distribution assumptions are optimistic for very large clusters

Native distribution and pg are productive, but full-mesh and high churn can
become operationally sensitive at large node counts.

**Recommendation:**

- keep gateway clusters small cells (e.g., 5-20 nodes) per region/tenant
- avoid giant global clusters
- add explicit anti-entropy and membership health checks
- test network partitions and split-brain behavior continuously

### 4) Plugin model needs explicit versioned capability contracts

Hundreds of plugins imply schema drift, phased rollouts, and partial support
across fleets.

**Recommendation:** add a capability registry model:

- plugin id + semantic version + action matrix
- required parameters schema + response schema hash
- compatibility policy (min/max supported versions)
- gateway-side routing filters by capability and version

### 5) Long-running and heavy jobs should not stay on request streams

Vuln scanning and AV workloads produce large result sets and can run for long
durations.

**Recommendation:** split command control from data/artifact flow:

- command channel: start/stop/status
- result channel: chunked upload to object storage or ingestion pipeline
- event channel: lifecycle and progress updates

This avoids huge gRPC stream pressure and improves retry behavior.

### 6) Security model should be expanded for high-impact remote actions

For enterprise-class action breadth, authZ granularity and safety controls become
as important as scale.

**Recommendation:**

- command-level RBAC/ABAC with policy evaluation per target cohort
- dual-approval / just-in-time elevation for destructive actions
- signed command envelopes + replay protection
- tamper-evident audit trail with immutable event sink
- per-tenant cryptographic separation where applicable

### 7) Reconnect storm handling is missing concrete algorithms

Node drains and failures can trigger synchronized reconnect bursts.

**Recommendation:**

- randomized reconnect jitter guidance for agents
- gateway-side accept-rate shaping
- staged GOAWAY and draining windows
- precomputed rebalance plans per ring change

### 8) Capacity section needs empirical validation framework

Static estimates are useful but insufficient for production commitments.

**Recommendation:** define test envelopes and SLOs:

- sustained connected agents/node
- p95/p99 command dispatch latency by fanout size
- p99 response aggregation completion time
- upstream control-plane RPC budget
- failure-recovery targets (node loss, partition, rolling deploy)

## Suggested Architecture Additions

1. **Cell-based topology**
   - Region -> Tenant/Environment Cell -> Gateway Cluster.
   - Keeps blast radius bounded and capacity predictable.

2. **Workload classes**
   - Class A: real-time commands (short-lived).
   - Class B: inventory/state collection.
   - Class C: heavy scans/remediation.
   - Each class gets independent quotas, queueing, and SLOs.

3. **Command orchestration service**
   - Move campaign logic (waves, canaries, retries, deadline policies)
     out of the hot path router.

4. **Artifact/result pipeline**
   - Dedicated service path for large payloads with compression,
     deduplication, retention, and malware-safe handling.

5. **Plugin lifecycle governance**
   - Signing, attestations, staged rollout, rollback, and health gates for
     plugin binaries and schemas.

## Concrete Improvements to the Blueprint Document

- Add a section: **Overload & Backpressure Policy** (with numeric defaults).
- Add a section: **Failure Mode Matrix** (node loss, partition, upstream down,
  cert rotation failure, storage outage).
- Add a section: **Multi-tenant Isolation Model**.
- Add a section: **Plugin Capability Registry and Versioning**.
- Add a section: **Heavy Workload Data Plane** for AV/vuln scan output.
- Add a section: **SLOs and Load-Test Exit Criteria** for each migration phase.

## Recommended Next Steps (Implementation Sequence)

1. Build a minimal gateway prototype with per-agent processes + bounded queues.
2. Add synthetic load generation and chaos scenarios before production cutover.
3. Introduce capability registry and command schema validation.
4. Implement heavy-job split plane for vulnerability and AV workflows.
5. Roll out by small cells with explicit SLO gates between phases.

## Bottom Line

The Erlang/OTP direction is the right foundation for the stated scale goals.
To reach enterprise-class breadth in one platform, the design should now
add explicit overload controls, workload separation, versioned plugin
capabilities, stronger authZ/audit controls, and SLO-driven validation.
