---
status: proposed
date: 2026-06-20
owner: Nathan Dornbrook (platform)
deciders: Nathan Dornbrook; Yuzu architecture planning session 2026-06-20
scope: platform / SRE / enterprise deployment - large global enterprise HA, regional control planes, gateway HA, server HA, and DR
builds-on: docs/adr/0006-server-postgresql-substrate.md, docs/adr/0007-server-single-backend-no-sqlite-fallback.md, docs/adr/0008-postgres-substrate-architecture.md, docs/adr/0011-live-query-bundle-server-fanout.md
---

# 0012 - Large global enterprise HA: regional cells, durable command ownership, and warm-region DR

## Context

Yuzu's first enterprise HA design must be sized for a large global enterprise,
not a small single-region SaaS tenant. The target deployment class has roughly
**2,200 locations across 56 countries**, **1.2 million active devices**, and
**210,000 staff**. That scale changes the availability baseline: a single
highly available region is not enough. Multiple warm regions are required from
the first implementation.

Endpoint management is operational infrastructure for a customer like this. Yuzu
will be the control plane through which humans and Agentic Colleagues query,
command, scan, patch, quarantine, enforce policy, and observe endpoint posture.
When the control plane is down, staff fall back to manual triage, duplicated
regional work, spreadsheet-driven chasing, delayed remediation, and slower
incident containment. That translates directly into wage cost, security exposure,
and lost confidence in agentic operations.

Commercial endpoint platforms already train enterprises to expect availability as
part of the product. Microsoft Intune, Tanium Cloud, Jamf Cloud, CrowdStrike, and
Workspace ONE sell a managed control plane or cloud-connected operational fabric
where customers expect service health, regional resilience, documented SLAs/SLOs,
and supportable disaster recovery. Their availability model is usually opaque to
the customer. Yuzu's opportunity is to provide an enterprise-grade HA posture that
is **inspectable, self-hostable, and compatible with regulated customer control**,
while preserving Yuzu's low-latency command path for Agentic Colleagues.

Yuzu already has two architectural advantages that make this tractable:

- [ADR-0006](0006-server-postgresql-substrate.md),
  [ADR-0007](0007-server-single-backend-no-sqlite-fallback.md), and
  [ADR-0008](0008-postgres-substrate-architecture.md) make Postgres the server
  substrate. This gives Yuzu one durable relational substrate for leases,
  command ownership, presence, backup, replication, and point-in-time recovery.
- The Erlang gateway split moves long-lived agent streams out of the C++ server
  and into an OTP layer that is naturally suited to many concurrent connections,
  supervision, backpressure, and node-local process ownership.

The missing HA work is therefore not "make one process redundant." It is:

- durable ownership of accepted command work;
- fenced gateway and agent presence;
- horizontally safe server replicas;
- warm-region recovery from the first version;
- operational proof through SLOs, runbooks, drills, and evidence.

## Decision

Yuzu will implement a **large-global-enterprise HA profile** as the first HA
target, not a smaller single-region-only profile.

The primary deployment shape is **macro-regional cells**:

- EMEA;
- APAC;
- Americas.

Each macro-region has an active regional Yuzu cell. Each active cell has at
least one warm standby region. Detailed endpoint telemetry, command state,
response data, audit logs, Guardian/DEX/TAR data, and policy execution state stay
inside the assigned macro-region by default. Global views are built from
aggregates, metadata, and explicit federated reads.

Warm-region failover is **manual promote** in v1. Automatic promotion and
active-active multi-region writes are rejected for the first implementation
because they introduce split-brain, command-ordering, audit, RBAC, and residency
risks that are not required to meet the first enterprise HA need.

The reliability target for the profile is:

- **99.95% regional control-plane availability target** for API, dashboard, MCP,
  enrollment, and command admission in a healthy regional cell.
- **Node/AZ failure transparent** within a regional cell.
- **Manual regional DR RTO <= 30 minutes** for warm-region promotion.
- **Regional DR RPO <= 5 minutes** for replicated non-command telemetry and
  control-plane state.
- **Accepted-command durability:** once a command is admitted in the source
  regional cell, it is durable in that cell's Postgres command mailbox. Delivery
  remains at-least-once with idempotent execution and response recording.

## Architecture

### Regional cell

Each regional cell contains:

- 3+ Erlang gateway nodes, active-active across zones;
- 2+ `yuzu-server` replicas behind regional load balancers;
- one HA Postgres primary with same-region synchronous standby;
- async replication to the warm standby region;
- Prometheus/Grafana/Alertmanager or equivalent customer monitoring;
- log/audit export to the customer's SIEM;
- backup, PITR, and restore tooling;
- a regional object/artifact store for packages and release assets where needed.

The cell is the unit of detailed data residency, failure isolation, command
ownership, and operational runbook execution.

### Gateway layer

Gateways own live agent streams only. They do not own durable command truth.

Each gateway publishes a regional heartbeat with:

- `gateway_id`;
- `region_id` and `cell_id`;
- zone;
- advertised agent addresses;
- build/protocol version;
- active stream count;
- queue depth and mailbox pressure;
- BEAM process/mailbox pressure;
- memory and file-descriptor pressure;
- upstream server/Postgres health;
- accepted organizations/tenants;
- drain state;
- last health epoch.

Agents receive a signed regional gateway directory during registration/config
refresh. Directory entries include:

- `gateway_id`;
- address;
- region/cell/zone;
- priority;
- weight;
- health epoch;
- load score;
- drain flag;
- TTL;
- signature metadata.

Agent gateway selection uses:

- sticky rendezvous-style selection on `(org_id, agent_id)`;
- measured latency/EWMA where available;
- recent failure penalty;
- gateway drain/health state;
- gateway load score;
- jittered exponential backoff.

When a gateway dies, live streams die and agents reconnect to another gateway.
Yuzu does not attempt live gRPC stream migration.

### Durable presence

Postgres stores fenced presence:

- `ha.gateway_nodes`: current gateway health and load by regional cell.
- `ha.agent_presence`: current agent stream owner by `agent_id`, `gateway_id`,
  `session_id`, and monotonic `connection_epoch`.

All presence mutations are fenced by epoch. A stale gateway cannot clear or
overwrite a newer connection. Presence is an operational routing hint, not a
proof that a command completed.

### Durable command mailbox

Accepted commands are represented in Postgres before delivery:

- `command.commands`: command metadata, origin, RBAC/audit context, scope, TTL,
  and status.
- `command.targets`: per-agent target rows with status, attempts, lease owner,
  lease expiry, current gateway epoch, and terminal state.
- `command.responses`: response chunks keyed by `command_id`, `agent_id`, and
  sequence/idempotency key.

Gateways claim target rows for agents they currently hold. Claims use bounded
leases and fencing. Gateway death or regional drain causes leases to expire and
work to be reclaimed after the agent reconnects.

Delivery is **at-least-once**. Exactly-once network delivery is not promised.
Correctness comes from idempotent command IDs, response dedupe, and terminal
state transitions in Postgres.

### Server layer

`yuzu-server` replicas are horizontally safe:

- any replica can serve REST, HTMX, MCP, enrollment, command admission, command
  collation, and dashboard reads;
- accepted work is stored before delivery;
- bundle manifests move to durable Postgres storage as required by
  [ADR-0011](0011-live-query-bundle-server-fanout.md)'s HA follow-up;
- singleton background jobs use Postgres advisory locks or row leases;
- server process-local state is cache only for HA-sensitive flows.

Singleton jobs include:

- scheduler ticks;
- policy evaluator loops;
- cleanup/reaper jobs;
- migrations/backfills;
- bundle manifest sweeps;
- NVD/sync-like jobs where duplicate work would be harmful;
- regional replication or promotion bookkeeping.

### Postgres layer

Each regional cell uses a customer-managed or managed-service Postgres HA
deployment:

- one writable primary;
- synchronous same-region standby for HA;
- async warm-region replica for DR;
- PITR enabled;
- tested backups;
- monitored replication lag;
- explicit promotion runbook.

Multi-primary writes are out of scope for v1. They would require conflict
resolution across commands, audit events, RBAC changes, enrollment state, policy
updates, and response ingestion. That complexity is not needed for the first
large-enterprise HA target.

### Global plane

Yuzu adds a thin global coordination/read plane. It owns:

- tenant/org metadata;
- region assignment;
- global routing metadata;
- regional health summary;
- aggregate fleet posture;
- global SLO dashboards;
- break-glass discovery pointers.

It does **not** own live command delivery or detailed endpoint telemetry. Detailed
data stays in regional cells unless a customer explicitly enables a federated or
exported global view.

## Correctness invariants

1. A gateway owns live streams only; Postgres owns accepted work.
2. A server replica may disappear after admitting a command; another replica
   must still collate and observe it.
3. A gateway may disappear after claiming delivery; lease expiry and agent
   reconnect must make the target deliverable again.
4. A stale gateway cannot clear or overwrite a newer agent presence row.
5. A command target is always one of: pending, leased, delivered/running,
   terminal, expired, or cancelled.
6. Delivery is at-least-once; command IDs and response sequence keys make
   duplicates safe.
7. A regional failover must fence the old primary before the standby accepts
   writes.
8. Global aggregate views must not become an undeclared path for detailed
   regional data exfiltration.

## Operational requirements

The HA profile is not complete until the following are shipped with it:

- SLO definitions for API/MCP availability, command admission, command dispatch
  latency, gateway reconnect, mailbox age, command success, and DR readiness.
- Regional dashboards for gateways, servers, Postgres, replication lag, command
  leases, reconnect rate, mailbox backlog, and error-budget burn.
- Alerts for SLO burn, Postgres lag, gateway pressure, reconnect storms,
  lease backlog, stuck singleton jobs, failed backups, failed restore drills,
  and standby promotion readiness.
- Runbooks for gateway loss, gateway drain, server loss, Postgres failover,
  warm-region promotion, reconnect storm, backup restore, regional isolation,
  and post-failover reconciliation.
- Evidence artifacts for SOC 2 Availability: SLO reports, incident records,
  restore drill logs, backup logs, promotion drill logs, capacity plans, and
  change approvals.
- Scale tests from 10k to 100k to 1.2M simulated agents.
- Chaos tests for gateway kill, server kill, Postgres primary failover, stale
  epoch replay, duplicate response replay, and regional promotion.

## Consequences

- HA becomes a multi-quarter platform program, not a gateway-only feature.
- New server-side stores and HA-sensitive state default to Postgres per
  ADR-0006/0007/0008.
- Existing SQLite-backed server stores on HA-sensitive paths must migrate or be
  explicitly classified as non-HA/blocking for the Enterprise HA profile.
- Agent config/register protocol grows a gateway directory and regional
  assignment surface.
- Gateway upstream protocol grows heartbeat/load/drain publication.
- Command dispatch moves from in-memory routing to durable mailbox ownership.
- Operations becomes part of the product surface: dashboards, runbooks, drills,
  and evidence are deliverables, not afterthoughts.
- The product gains a marketable advantage: enterprise-grade HA that is
  self-hostable, auditable, and designed for Agentic Colleagues rather than a
  black-box SaaS control plane.

## Options considered

### Single-region HA first

Rejected. It is insufficient for a large global enterprise footprint and would force a
second architecture pass immediately. Multiple warm regions are required from
the first implementation.

### Global active primary

Rejected. A single global write region simplifies state but creates latency,
residency, and blast-radius problems for 56 countries.

### Country-level cells from v1

Deferred. Country-level residency may be needed for specific jurisdictions, but
making 56 country cells the first target would create excessive operational and
deployment complexity. Macro-regional cells are the v1 default; strict country
residency is a later extension.

### Active-active multi-region writes

Rejected for v1. The conflict model is too expensive for the first HA target:
commands, responses, audit, RBAC, enrollment, policy state, and approval
workflows all need deterministic conflict semantics.

### Gateway gossip as durable truth

Rejected. Erlang adjacency and `pg` are useful for fast local routing and
cluster awareness, but command ownership and recovery need durable Postgres
state with leases and fencing.

### In-memory command ownership

Rejected for Enterprise HA. In-memory queues may exist as bounded performance
caches, but accepted work must survive server/gateway process loss.

## Implementation ladder

1. Define Enterprise HA SLOs, evidence requirements, and `/readyz` semantics.
2. Add signed gateway directory publication and agent-side multi-gateway
   failover.
3. Add gateway heartbeat/load/drain publication.
4. Add durable gateway and agent presence with epoch fencing.
5. Add durable command mailbox and per-target leases.
6. Move bundle manifests to Postgres.
7. Make server replicas horizontally safe by fencing singleton jobs.
8. Package a 3-zone regional cell deployment.
9. Add warm-region replication, promotion tooling, and standby readiness checks.
10. Add the thin global aggregate/routing plane.
11. Run scale and chaos proof against large-enterprise-size assumptions.

## References

- Microsoft Intune overview: https://learn.microsoft.com/en-us/intune/fundamentals/what-is-intune
- Kamailio dispatcher: https://www.kamailio.org/docs/modules/stable/modules/dispatcher.html
- Kamailio DMQ: https://www.kamailio.org/docs/modules/stable/modules/dmq.html
- gRPC custom load balancing: https://grpc.io/docs/guides/custom-load-balancing/
- PostgreSQL high availability: https://www.postgresql.org/docs/current/high-availability.html
