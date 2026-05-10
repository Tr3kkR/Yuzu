# Yuzu Architecture

This document describes how Yuzu's components interact, the data flows between them, and the design rationale behind each subsystem.

## Component Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                              Yuzu Server                                │
│                                                                         │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────┐  ┌─────────────┐   │
│  │  gRPC       │  │  HTTP/REST   │  │  Auth        │  │  Metrics    │   │
│  │  Services   │  │  API + HTMX  │  │  Manager     │  │  /metrics   │   │
│  │             │  │  Dashboard   │  │  (RBAC)      │  │             │   │
│  └──────┬──────┘  └──────┬───────┘  └───────┬──────┘  └─────────────┘   │
│         │         ┌──────────────┐          │                           │
│         │         │  MCP Server  │  (JSON-RPC 2.0, AI tool use)         │
│         │         │  /mcp/v1/    │          │                           │
│         │         └──────────────┘          │                           │
│         │                │                  │                           │
│  ┌──────▼────────────────▼──────────────────▼─────────────────────────┐ │
│  │                     Server Core                                    │ │
│  │  ┌──────────────┐  ┌────────────┐  ┌────────────┐  ┌───────────┐   │ │
│  │  │ Agent        │  │ Instruction│  │ Response   │  │ Audit     │   │ │
│  │  │ Registry     │  │ Engine     │  │ Store      │  │ Log       │   │ │
│  │  └──────────────┘  └────────────┘  └────────────┘  └───────────┘   │ │
│  │  ┌──────────────┐  ┌────────────┐  ┌────────────┐  ┌───────────┐   │ │
│  │  │ Scope        │  │ Policy     │  │ Scheduler  │  │ Event     │   │ │
│  │  │ Engine       │  │ Engine     │  │            │  │ Bus       │   │ │
│  │  └──────────────┘  └────────────┘  └────────────┘  └───────────┘   │ │
│  │  ┌──────────────┐  ┌────────────┐  ┌────────────┐                  │ │
│  │  │ Management   │  │ NVD Sync   │  │ Content    │                  │ │
│  │  │ Groups       │  │            │  │ Repository │                  │ │
│  │  └──────────────┘  └────────────┘  └────────────┘                  │ │
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
  │──── Register(AgentInfo) ────► │  Contains: agent_id, hostname, OS, arch,
  │     + enrollment_token        │  plugins list, enrollment_token
  │                               │
  │                               ├── Validate enrollment token (Tier 2)
  │                               ├── OR check auto-approve rules
  │                               ├── OR add to pending queue (Tier 1)
  │                               │
  │◄── RegisterResponse ───────── │  Contains: session_id, enrollment_status
  │     (enrolled/pending/denied) │  (enrolled → proceed, pending → retry later)
  │                               │
  │──── Subscribe() ───────────── │  Bidirectional stream opens
  │     (bidi stream)             │  Server stores stream pointer in registry
```

**Why bidirectional streaming?** Polling-based command delivery (the legacy `Heartbeat` + `ExecuteCommand` pattern) introduces latency proportional to the heartbeat interval. The `Subscribe` RPC keeps a persistent stream open so the server can push commands immediately. This is critical for security response (quarantine a device NOW) and interactive querying. The difference from latency in commands manifests most in iterative situations such as LLM instrumented surfaces such as the MCP that Yuzu exposes; LLMs are naive and ‘walk up’ discovery of the correct course of action, iterated over failure. We want to make those failures as fast as possible - and successes as fast as possible as well - in order to allow agentic workloads to be performant.

**Why three enrollment tiers?** Different organizations have different security postures. Startup labs want zero-friction onboarding (Tier 2 tokens). Enterprises need approval workflows (Tier 1 manual). High-security environments need hardware attestation (Tier 3 platform trust).

### 2. Command Dispatch and Response Collection

```
Dashboard/API           Server                     Agent
     │                    │                          │
     │── SendCommand ───► │                          │
     │   (plugin, action, │                          │
     │    params, scope)  │                          │
     │                    ├── Scope engine evaluates │
     │                    │   which agents match     │
     │                    │                          │
     │                    │── CommandRequest ───────►│
     │                    │   (via Subscribe stream) │
     │                    │                          ├── Find plugin by name
     │                    │                          ├── Spawn execution thread
     │                    │                          ├── Call plugin execute()
     │                    │                          │
     │                    │◄── CommandResponse ──────│  Streamed: status, output chunks
     │                    │    (streaming)           │
     │                    ├── Store in Response Store│
     │                    ├── Aggregate if defined   │
     │                    │                          │
     │◄── SSE event ──────│                          │
     │   (real-time UI)   │                          │
```

**Why stream responses?** Plugins may produce output incrementally (e.g., scanning a filesystem). Streaming delivers results to the dashboard as they arrive rather than waiting for completion. This is also why the Response Store must handle appending partial results.

**Why a scope engine?** "Run this on all Windows 10 agents in the London office" is a common operation. Without a scope engine, the operator must manually list agent IDs. The scope engine evaluates an expression tree against the agent registry (OS type, tags, management group membership, FQDN pattern) and returns matching agents.

### 3. Instruction Definitions and Lifecycle

```
Admin                    Server
  │                         │
  │── Create Definition ───►│  Named, versioned template:
  │   (name, version,       │  - plugin + action + param schema
  │    param schema,        │  - response schema (typed columns)
  │    response schema,     │  - aggregation rules
  │    aggregation,         │  - TTL ranges
  │    instruction set)     │  - instruction type (question/action)
  │                         │
  │── Run Instruction ─────►│  Instantiate definition with:
  │   (definition name,     │  - parameter values
  │    scope expression,    │  - scope expression (who to target)
  │    parameter values)    │  - approved (or enters approval queue)
  │                         │
  │                         ├── Check approval workflow
  │                         ├── Evaluate scope → target agents
  │                         ├── Dispatch to agents
  │                         ├── Collect responses
  │                         ├── Aggregate server-side
  │                         │
  │◄── Results ─────────────│  Raw + aggregated, filterable, paginated
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
  │── Create Rule ────────►│  Fragment + triggers    │
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
     │   or Bearer token   │  or API token (automation)
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

### 7. Fleet Visualization (3D)

```
Operator                     Server                                  Agent
   │                           │                                       │
   │── GET /viz/fleet ────────►│  Auth gate; emit static HTML shell    │
   │   (browser)               │  (Cache-Control: no-cache, no-store)  │
   │                           │                                       │
   │◄── HTML shell ────────────│  importmap → /static/three.module.min.js
   │                           │             /static/three-orbit-controls.js
   │                           │             /static/yuzu-viz.js (renderer)
   │                           │                                       │
   │── GET /api/v1/viz/fleet/topology
   │   (or /fragments/...)     │                                       │
   │                           ├── Kill switch (--viz-disable)?  503   │
   │                           ├── Store null?                   503   │
   │                           ├── RBAC (Response.Read)?         403   │
   │                           ├── Parse params (machines_max,         │
   │                           │   include_vuln, fresh)                │
   │                           ├── FleetTopologyStore::get(...)        │
   │                           │     ├── cache hit (5 s TTL) → return  │
   │                           │     └── miss → single-flight refill:  │
   │                           │           dispatch tar.fleet_snapshot │
   │                           │           via fetcher seam            │
   │                           │                                       │
   │                           │── tar.fleet_snapshot ────────────────►│
   │                           │   (CommandRequest, fan-out per agent) │
   │                           │                                       ├── Collect
   │                           │                                       │   processes,
   │                           │                                       │   connections,
   │                           │                                       │   local_ips
   │                           │◄── CommandResponse (per agent) ───────│
   │                           │                                       │
   │                           ├── ResponseStore correlation by command_id
   │                           ├── 5 s aggregation timeout (partial OK)
   │                           ├── Categorise processes (Database / Browser /
   │                           │   Web / Runtime / System / Other) via
   │                           │   process_category.hpp heuristics
   │                           ├── Resolve cross-machine connections by
   │                           │   matching remote_addr against the
   │                           │   union of every agent's local_ips
   │                           ├── machines_max cap (default 5000,
   │                           │   ceiling 100000) — over cap → 413
   │                           ├── Audit emit (viz.fleet_topology +
   │                           │   viz.fleet_topology.invalidate when
   │                           │   ?fresh=1)
   │                           │
   │◄── JSON envelope ─────────│  fleet_topology.v1 — agents[], processes[],
   │   (or <script>-wrapped    │  connections[], categorisation, vuln overlay
   │    fragment)              │  if ?include_vuln=1
   │
   │── render() ───────────────┐
   │   (renderer module)       │  WebGLRenderer + OrbitControls camera +
   │                           │  WASD pan; machine cubes (one per agent,
   │                           │  deterministic FNV-1a grid, per-OS
   │                           │  palette) + Sprite hostname labels +
   │                           │  Raycaster hover tooltip; PR-7+ adds
   │                           │  process nodes, connection edges, vuln
   │                           │  overlays.
```

**Why a separate page route + REST surface?** Dashboard parity (agentic-first invariant A1) means every dashboard action must have a REST equivalent. The page (`/viz/fleet`) is the HTML shell + static asset bundle that browsers load; the REST endpoints (`/api/v1/viz/fleet/topology` and the `/fragments/...` companion) are what the renderer (and any LLM client / automation) actually call for data. Both go through the same `FleetTopologyStore`, the same kill-switch, RBAC, and audit gates.

**Why store-side categorisation?** The TAR (Telemetry, Acquisition, Response) plugin on each agent ships a flat process list with `cmdline` and `path`. Categorising client-side would mean every browser holds its own copy of the heuristics; doing it on the server lets the JSON envelope carry a single canonical category per process and lets the rules evolve without a renderer roll-out.

**Why a single-flight cache?** A topology fetch fans out to every agent in scope, so concurrent operator requests would otherwise dispatch N parallel `tar.fleet_snapshot` storms. The store coalesces concurrent misses onto one refill goroutine; in-flight waiters block on a condition variable up to a bounded timeout; subsequent gets within the 5 s TTL hit the cache.

**Why ES modules + importmap rather than UMD?** Three.js dropped UMD in r150+ — modern releases only publish `three.module.min.js`. The page declares an importmap mapping the bare specifier `"three"` to the vendored bundle, so OrbitControls' own `import { ... } from 'three'` resolves through the same map without a build-time bundler. Browser support floor: Chrome 89 / Firefox 108 / Safari 16.4 (importmap), all comfortably below the dashboard's existing baseline.

**Why a kill switch?** WebGL has a much larger attack surface than HTML, the renderer module is large (~6 KB hand-written + ~717 KB vendored), and the data path fans out to every agent. Operators who never use the feature should be able to disable it cleanly. `--viz-disable` (or `YUZU_VIZ_DISABLE=1`) makes both the page and the REST surface return 503 with an audit row, ahead of any RBAC check (tier-before-permission per `docs/auth-architecture.md` §3).

**Static-asset packaging.** The renderer was Pattern-A (hand-written `yuzu_viz_js_bundle.cpp`) through PR 5; at PR 6 the bundle exceeded MSVC's 16,380-byte raw-string-literal limit (C2026), and the renderer source migrated to `server/core/static/yuzu-viz.js` with `embed_js.py` codegen (Pattern B), matching the Three.js and OrbitControls pattern. The page HTML remains a Pattern-A hand-written TU (`viz_page_ui.cpp`). Vendored Three.js core and OrbitControls are Pattern-B over `vendor/three.module.min.js` and `vendor/three-orbit-controls.js`. See `docs/cpp-conventions.md` "Static-asset translation units" for when to use each pattern; `static/` houses our authoritative assets, `vendor/` houses upstream drops.

**Extension seam.** PR 6 filled the renderer's `mount() → buildScene()` callouts with machine cubes + Sprite hostname labels + Raycaster hover tooltip. PR 7+ fills the same seam with process nodes (interior of the cube), edges (intra-machine + cross-machine), and a vulnerability overlay when `?include_vuln=1`. The store, REST surface, audit, and kill switch are stable; renderer ships incrementally without further surface changes.

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
