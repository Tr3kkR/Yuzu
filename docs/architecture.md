# Yuzu Architecture

This document describes how Yuzu's components interact, the data flows between them, and the design rationale behind each subsystem.

## Component Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                              Yuzu Server                                 │
│                                                                         │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────┐  ┌─────────────┐ │
│  │  gRPC       │  │  HTTP/REST   │  │  Auth        │  │  Metrics    │ │
│  │  Services   │  │  API + HTMX  │  │  Manager     │  │  /metrics   │ │
│  │             │  │  Dashboard   │  │  (RBAC)      │  │             │ │
│  └──────┬──────┘  └──────┬───────┘  └──────┬───────┘  └─────────────┘ │
│         │                │                  │                           │
│  ┌──────▼──────────────────▼──────────────────▼───────────────────────┐ │
│  │                     Server Core                                    │ │
│  │  ┌──────────────┐  ┌────────────┐  ┌────────────┐  ┌───────────┐ │ │
│  │  │ Agent        │  │ Instruction│  │ Response   │  │ Audit     │ │ │
│  │  │ Registry     │  │ Engine     │  │ Store      │  │ Log       │ │ │
│  │  └──────────────┘  └────────────┘  └────────────┘  └───────────┘ │ │
│  │  ┌──────────────┐  ┌────────────┐  ┌────────────┐  ┌───────────┐ │ │
│  │  │ Scope        │  │ Policy     │  │ Scheduler  │  │ Event     │ │ │
│  │  │ Engine       │  │ Engine     │  │            │  │ Bus       │ │ │
│  │  └──────────────┘  └────────────┘  └────────────┘  └───────────┘ │ │
│  │  ┌──────────────┐  ┌────────────┐  ┌────────────┐               │ │
│  │  │ Management   │  │ NVD Sync   │  │ Content    │               │ │
│  │  │ Groups       │  │            │  │ Repository │               │ │
│  │  └──────────────┘  └────────────┘  └────────────┘               │ │
│  └────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────┘
         │                                              │
    gRPC/mTLS                                     HTTP/REST
    (agents)                                    (browsers, API)
         │                                              │
    ┌────▼────┐                                    ┌────▼────┐
    │  Agent  │                                    │  Users  │
    │  Fleet  │                                    │  & API  │
    └─────────┘                                    │ Clients │
                                                   └─────────┘
```

## Data Flows

### 1. Agent Registration and Enrollment

```
Agent                           Server
  │                               │
  │──── Register(AgentInfo) ────►│  Contains: agent_id, hostname, OS, arch,
  │     + enrollment_token       │  plugins list, enrollment_token
  │                               │
  │                               ├── Validate enrollment token (Tier 2)
  │                               ├── OR check auto-approve rules
  │                               ├── OR add to pending queue (Tier 1)
  │                               │
  │◄── RegisterResponse ─────────│  Contains: session_id, enrollment_status
  │     (enrolled/pending/denied) │  (enrolled → proceed, pending → retry later)
  │                               │
  │──── Subscribe() ─────────────│  Bidirectional stream opens
  │     (bidi stream)             │  Server stores stream pointer in registry
```

**Why bidirectional streaming?** Polling-based command delivery (the legacy `Heartbeat` + `ExecuteCommand` pattern) introduces latency proportional to the heartbeat interval. The `Subscribe` RPC keeps a persistent stream open so the server can push commands immediately. This is critical for security response (quarantine a device NOW) and interactive querying.

**Why three enrollment tiers?** Different organizations have different security postures. Startup labs want zero-friction onboarding (Tier 2 tokens). Enterprises need approval workflows (Tier 1 manual). High-security environments need hardware attestation (Tier 3 platform trust).

### 2. Command Dispatch and Response Collection

```
Dashboard/API           Server                    Agent
     │                    │                         │
     │── SendCommand ───►│                         │
     │   (plugin, action, │                         │
     │    params, scope)  │                         │
     │                    ├── Scope engine evaluates │
     │                    │   which agents match     │
     │                    │                         │
     │                    │── CommandRequest ──────►│
     │                    │   (via Subscribe stream) │
     │                    │                         ├── Find plugin by name
     │                    │                         ├── Spawn execution thread
     │                    │                         ├── Call plugin execute()
     │                    │                         │
     │                    │◄── CommandResponse ─────│  Streamed: status, output chunks
     │                    │    (streaming)           │
     │                    ├── Store in Response Store│
     │                    ├── Aggregate if defined   │
     │                    │                         │
     │◄── SSE event ─────│                         │
     │   (real-time UI)   │                         │
```

**Why stream responses?** Plugins may produce output incrementally (e.g., scanning a filesystem). Streaming delivers results to the dashboard as they arrive rather than waiting for completion. This is also why the Response Store must handle appending partial results.

**Why a scope engine?** "Run this on all Windows 10 agents in the London office" is a common operation. Without a scope engine, the operator must manually list agent IDs. The scope engine evaluates an expression tree against the agent registry (OS type, tags, management group membership, FQDN pattern) and returns matching agents.

### 3. Instruction Definitions and Lifecycle

```
Admin                    Server
  │                        │
  │── Create Definition ──►│  Named, versioned template:
  │   (name, version,      │  - plugin + action + param schema
  │    param schema,        │  - response schema (typed columns)
  │    response schema,     │  - aggregation rules
  │    aggregation,         │  - TTL ranges
  │    instruction set)     │  - instruction type (question/action)
  │                        │
  │── Run Instruction ────►│  Instantiate definition with:
  │   (definition name,     │  - parameter values
  │    scope expression,    │  - scope expression (who to target)
  │    parameter values)    │  - approved (or enters approval queue)
  │                        │
  │                        ├── Check approval workflow
  │                        ├── Evaluate scope → target agents
  │                        ├── Dispatch to agents
  │                        ├── Collect responses
  │                        ├── Aggregate server-side
  │                        │
  │◄── Results ────────────│  Raw + aggregated, filterable, paginated
```

**Why instruction definitions?** Ad-hoc commands are powerful but dangerous at scale. Definitions provide:
- **Parameter validation** — prevent typos and invalid inputs
- **Response schemas** — typed columns enable aggregation, filtering, and downstream analytics
- **Versioning** — track which version of an instruction was run
- **Permission scoping** — assign to instruction sets with role-based access
- **Scheduling** — can't schedule an ad-hoc command; need a named definition

**Why server-side aggregation?** When 10,000 agents respond to "what antivirus is installed?", the operator doesn't want 10,000 rows. They want "8,200 have Defender, 1,500 have CrowdStrike, 300 have nothing." Aggregation (group-by + count/sum/min/max) runs server-side as responses arrive.

### 4. Policy Engine (Guaranteed State)

```
Admin                    Server                    Agent
  │                        │                         │
  │── Create Fragment ────►│  Check/Fix code block   │
  │── Create Rule ────────►│  Fragment + triggers     │
  │── Assign to Group ────►│  Policy → mgmt group    │
  │── Deploy ─────────────►│  Compile, hash, push    │
  │                        │                         │
  │                        │── Policy Document ─────►│  Agent receives rules + triggers
  │                        │                         │
  │                        │                         ├── Register triggers (interval,
  │                        │                         │   file change, service, etc.)
  │                        │                         │
  │                        │       [trigger fires]   │
  │                        │                         ├── Evaluate check instruction
  │                        │                         ├── If failed → run fix instruction
  │                        │                         ├── Report status to server
  │                        │                         │
  │                        │◄── Status Report ───────│  Rule statuses:
  │                        │                         │  CheckPassed, CheckFailed,
  │                        │                         │  FixPassed, FixErrored, etc.
  │                        │
  │◄── Compliance Dashboard│  Fleet compliance posture
```

**Why local evaluation?** If the server evaluates compliance, it must query every agent on every check interval — that's O(agents × rules × frequency) network round trips. Local evaluation means the agent watches for changes (via triggers) and only reports when something changes. This scales to hundreds of thousands of agents.

**Why triggers instead of polling?** Polling ("check every 5 minutes") wastes resources when nothing changes and misses changes between polls. Triggers (file watcher, service status change, event log) react to actual changes in near real time. Interval triggers are available as a fallback for things that can't be event-driven.

**Why separate check and fix?** Not all rules should auto-remediate. A check-only rule reports compliance status without modifying the system. A fix rule can attempt remediation but reports whether the fix succeeded. This separation supports audit-only mode (check only) and enforcement mode (check + fix).

### 5. Authentication, RBAC, and Access Control

```
User/API Client          Server
     │                     │
     │── Login ───────────►│  Session cookie (browser)
     │   or Bearer token    │  or API token (automation)
     │                     │
     │── Any Request ─────►│
     │                     ├── Authenticate (session or token)
     │                     ├── Identify principal
     │                     ├── Look up roles for principal
     │                     ├── For each role: check permissions
     │                     │   against (securable type, operation)
     │                     ├── Filter results by management group
     │                     │   visibility
     │                     │
     │◄── Response ────────│  Only data the principal can see
```

**Why management-group-scoped RBAC?** In large organizations, the London admin shouldn't see New York's devices, and vice versa. Management groups partition the fleet. Role assignments are scoped to groups (Principal + Role + ManagementGroup triple), so "Alice is Admin for London" and "Bob is Viewer for All" are both expressible.

### 6. Metrics and Observability

```
Agent                           Server                        External
  │                               │                             │
  │  yuzu_agent_commands_total    │  yuzu_server_agents_total   │
  │  yuzu_agent_plugins_loaded    │  yuzu_server_grpc_latency   │
  │  yuzu_agent_uptime_seconds    │  yuzu_server_responses_total│
  │                               │                             │
  │───── /metrics ───────────────►│                             │
  │  (Prometheus scrapes agent)   │───── /metrics ─────────────►│ Prometheus
  │                               │  (Prometheus scrapes server)│    │
  │                               │                             │    ▼
  │                               │                             │ Grafana
  │                               │                             │
  │                               │── Audit events ────────────►│ Splunk HEC
  │                               │── Webhooks ────────────────►│ ClickHouse
  │                               │── Response data ───────────►│ (via REST API)
```

**Why Prometheus-native?** Prometheus is the de facto standard for infrastructure metrics. By exposing `/metrics` in Prometheus exposition format, Yuzu integrates with existing monitoring stacks (Grafana, Alertmanager, Thanos) without custom adapters.

**Why design for ClickHouse/Splunk?** Endpoint management platforms generate massive volumes of structured data (inventory, command responses, compliance events). ClickHouse excels at columnar analytics over this data. Splunk excels at correlation and search. By using typed schemas, consistent timestamps, and structured JSON events, Yuzu data is immediately useful in these systems without ETL transformation.

## Storage Architecture

| Component | Backend | Purpose |
|---|---|---|
| Agent identity | SQLite (`agent.db`) | Persistent agent_id, enrollment state |
| Agent KV storage | SQLite (`agent.db`) | Cross-instruction persistent state |
| Server responses | SQLite (sharded) | Command response persistence with TTL |
| Server audit | SQLite | User action audit trail |
| Server config | Config files (`.cfg`) | Users, tokens, enrollment, settings |
| NVD/CVE data | SQLite | Vulnerability database |
| Policy state | SQLite | Rule evaluation history, compliance |

**Why SQLite everywhere?** Zero configuration, single-file deployment, fast reads, supports concurrent readers with WAL mode. For the agent (which must be lightweight), SQLite adds ~600KB to the binary and requires no external database. For the server, SQLite scales to millions of rows per shard. If the server outgrows SQLite, the storage layer can be swapped to PostgreSQL with minimal code change — the query patterns are simple (insert, filter, paginate).

## Plugin Architecture

```
Agent Process
  │
  ├── Plugin Loader
  │   ├── dlopen("hardware.so") → yuzu_plugin_descriptor()
  │   ├── dlopen("network.so")  → yuzu_plugin_descriptor()
  │   └── dlopen("custom.so")   → yuzu_plugin_descriptor()
  │
  ├── Plugin Registry (name → descriptor)
  │
  └── Command Dispatch
      └── execute(plugin_name, action, params)
          └── descriptor.execute(ctx, action, params, param_count)
              └── ctx->write_output("result data")
```

**Why a C ABI?** The plugin boundary must survive compiler version changes, standard library changes, and even language changes. A C ABI is the only binary-stable interface on all platforms. The C++ wrapper (`plugin.hpp`) provides ergonomic CRTP-based development while generating the C trampolines automatically via `YUZU_PLUGIN_EXPORT`.

**Why in-process plugins?** Out-of-process plugins (like VS Code extensions) add IPC overhead and deployment complexity. Endpoint management plugins are typically small, focused, and trusted (shipped by the vendor). In-process loading via `dlopen`/`LoadLibrary` gives sub-microsecond dispatch and zero serialization overhead.

## Security Model

| Layer | Mechanism | Purpose |
|---|---|---|
| Agent ↔ Server transport | mTLS (gRPC) | Mutual authentication, encrypted channel |
| Agent enrollment | 3-tier (manual, token, platform) | Flexible trust model |
| Dashboard auth | PBKDF2 sessions + OIDC | Human authentication |
| API auth | Bearer tokens | Automation authentication |
| Authorization | RBAC (principals, roles, permissions) | Fine-grained access control |
| Scope isolation | Management groups | Limit visibility per role assignment |
| Audit | Append-only audit log | Accountability and compliance |
| Secrets | Secure erase after use | Private keys zeroed in memory |

## Wire Protocol

All agent ↔ server communication uses Protocol Buffers v3 over gRPC with optional TLS. The proto files in `proto/` are the single source of truth:

- `yuzu/agent/v1/agent.proto` — AgentService (Register, Heartbeat, ExecuteCommand, Subscribe, ReportInventory)
- `yuzu/server/v1/management.proto` — ManagementService (ListAgents, GetAgent, SendCommand, WatchEvents, QueryInventory)
- `yuzu/gateway/v1/gateway.proto` — GatewayUpstream (ProxyRegister, BatchHeartbeat, ProxyInventory, NotifyStreamStatus)
- `yuzu/common/v1/common.proto` — Shared types (Platform, PluginInfo, ErrorDetail, Timestamp)

**Why Protobuf over JSON?** Protobuf is ~5x smaller on the wire and ~10x faster to parse than JSON. At 10,000 agents sending heartbeats every 30 seconds, this matters. Protobuf also provides schema evolution (add fields without breaking existing clients) and strongly typed codegen.
