# Yuzu Gateway

The Yuzu gateway is an Erlang/OTP application that sits between agents and the
C++ server, enabling the platform to scale beyond the connection limits of a
single server process.

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture) -- PARTIALLY IMPLEMENTED
- [Core Proxy Functions](#core-proxy-functions) -- PARTIALLY IMPLEMENTED
- [GatewayUpstream Service](#gatewayupstream-service) -- PARTIALLY IMPLEMENTED
- [Configuration](#configuration)
- [Building and Testing](#building-and-testing)
- [Gateway Clustering](#gateway-clustering) -- PLANNED
- [Prometheus Metrics](#prometheus-metrics) -- PARTIALLY IMPLEMENTED
- [Reference](#reference)

---

## Overview

**Status: PARTIALLY IMPLEMENTED**

At scale, the C++ server's single-process gRPC architecture hits limits:
each Subscribe bidi stream holds a per-agent mutex, and broadcast operations
iterate all agents serially. At millions of agents this creates lock convoys,
thread exhaustion, and single-box ceilings.

The gateway solves this by owning the **command fanout plane** (Subscribe
bidi streams to agents, command dispatch, response aggregation) while the
C++ server retains the **control plane** (enrollment, auth, inventory,
dashboard, REST API).

The key scaling insight is that Erlang can sustain millions of lightweight
processes, each holding the state for one agent's bidi stream, with no
mutexes -- message passing provides serialization.

---

## Architecture

**Status: PARTIALLY IMPLEMENTED**

```
Operators (browser, REST API, CLI)
    |
    v
+-----------------------------------------------+
|           yuzu-gateway (Erlang/OTP)            |
|                                                |
|   +----------+  +----------+  +----------+    |
|   | gw_node1 |  | gw_node2 |  | gw_nodeN |    |
|   +----------+  +----------+  +----------+    |
|        |              |             |          |
|    agent_proc     agent_proc   agent_proc      |
|    agent_proc     agent_proc   agent_proc      |
+--------+--------------+------------+----------+
         |              |            |
         v              v            v
    +---------+    +---------+  +---------+
    | Agent 1 |    | Agent 2 |  | Agent M |
    +---------+    +---------+  +---------+
         |              |            |
         +--------------+------------+
                        |
                        | Register, Heartbeat, Inventory
                        v
               +------------------+
               |  yuzu-server     |
               |  (C++ control    |
               |   plane)         |
               +------------------+
```

**Plane separation:**

| Plane | Owner | Responsibilities |
|---|---|---|
| Control | yuzu-server (C++) | Register, Heartbeat, enrollment, auth, inventory, dashboard, REST API, mTLS termination |
| Command | yuzu-gateway (Erlang) | Subscribe bidi streams, SendCommand fanout, response aggregation, streaming relay |

### OTP Process Model

Each connected agent is represented by a single Erlang process (`yuzu_gw_agent`,
a `gen_statem` state machine). The process owns the gRPC stream writer handle;
all writes to that agent go through its mailbox with no mutex contention.

**Agent process states:**

| State | Description |
|---|---|
| `connecting` | Agent called Register; forwarded to upstream server; awaiting session_id |
| `streaming` | Bidi stream active; agent process owns the stream writer |
| `disconnected` | Stream broken or heartbeat timeout; cleanup and termination |

Memory per agent process is approximately 2 KB base plus the pending command
map. At 1 million agents this is 2--4 GB, trivially shardable across a cluster.

### Module Inventory

The gateway source lives in `gateway/apps/yuzu_gw/src/`:

| Module | Role |
|---|---|
| `yuzu_gw_app` | OTP application behaviour |
| `yuzu_gw_sup` | Top-level supervisor |
| `yuzu_gw_agent_sup` | `simple_one_for_one` supervisor for agent processes |
| `yuzu_gw_agent` | `gen_statem`: one process per agent bidi stream |
| `yuzu_gw_registry` | Process groups + ETS routing table |
| `yuzu_gw_router` | Command fanout coordinator |
| `yuzu_gw_upstream` | gRPC client pool to the C++ server |
| `yuzu_gw_agent_service` | Agent-facing gRPC server (AgentService proxy) |
| `yuzu_gw_mgmt_service` | Operator-facing gRPC server (ManagementService proxy) |
| `yuzu_gw_telemetry` | Telemetry event definitions and handlers |
| `yuzu_gw_gauge` | Periodic gauge emission for Prometheus |
| `yuzu_gw_proto` | Protobuf encode/decode wrappers |

---

## Core Proxy Functions

**Status: PARTIALLY IMPLEMENTED**

### Register Proxy

When an agent calls `Register`, the gateway's `yuzu_gw_agent_service` forwards
the request to the C++ server via `yuzu_gw_upstream:proxy_register/1`. The
server handles enrollment logic (token validation, pending approval queue)
and returns a `RegisterResponse` with a session ID. The gateway relays the
response to the agent and starts an agent process.

### Heartbeat Batching

Individual agent heartbeats are not forwarded one-by-one. Instead,
`yuzu_gw_upstream` buffers heartbeats and sends them in a single
`BatchHeartbeat` RPC at a configurable interval (default: 10 seconds).

This reduces upstream load from O(agents/interval) to O(nodes/interval).

On RPC failure, heartbeat buffers are retained (capped at 10,000) for retry
on the next flush cycle rather than being silently discarded.

### Subscribe Stream Proxy

The gateway owns the agent's Subscribe bidi stream. When an operator sends a
command via `SendCommand`, the `yuzu_gw_router` fans it out to the target
agent processes, which write to their respective streams. Responses flow back
through the agent process mailbox to the router and are aggregated for the
operator.

### Inventory Proxy

Full inventory reports from agents are forwarded to the C++ server via
`ProxyInventory` for storage and querying.

### Stream Status Notification

When an agent's Subscribe stream connects or disconnects at the gateway, a
`NotifyStreamStatus` RPC informs the C++ server so it can update its
connectivity records.

---

## GatewayUpstream Service

**Status: PARTIALLY IMPLEMENTED**

The `GatewayUpstream` service is a gRPC service exposed by the C++ server
specifically for gateway communication. It is defined in
`proto/yuzu/gateway/v1/gateway.proto`.

### RPCs

| RPC | Request | Response | Purpose |
|---|---|---|---|
| `ProxyRegister` | `RegisterRequest` | `RegisterResponse` | Forward agent registration to control plane |
| `BatchHeartbeat` | `BatchHeartbeatRequest` | `BatchHeartbeatResponse` | Aggregated heartbeats from all agents on one gateway node |
| `ProxyInventory` | `InventoryReport` | `InventoryAck` | Forward inventory reports to storage layer |
| `NotifyStreamStatus` | `StreamStatusNotification` | `StreamStatusAck` | Inform server of agent connect/disconnect events |

### BatchHeartbeat Message

```protobuf
message BatchHeartbeatRequest {
  repeated HeartbeatRequest heartbeats = 1;
  string gateway_node = 2;
}

message BatchHeartbeatResponse {
  int32 acknowledged_count = 1;
}
```

### StreamStatusNotification Message

```protobuf
message StreamStatusNotification {
  string agent_id   = 1;
  string session_id = 2;
  enum Event {
    CONNECTED    = 0;
    DISCONNECTED = 1;
  }
  Event event       = 3;
  string peer_addr  = 4;
  string gateway_node = 5;
}
```

---

## Configuration

The gateway is configured via `gateway/config/sys.config`. Key settings:

```erlang
{yuzu_gw, [
    %% Agent-facing gRPC (agents connect here)
    {agent_listen_addr, "0.0.0.0"},
    {agent_listen_port, 50051},

    %% Operator-facing gRPC (dashboard/CLI)
    {mgmt_listen_addr, "0.0.0.0"},
    {mgmt_listen_port, 50052},

    %% Upstream C++ server (GatewayUpstream service)
    {upstream_addr, "127.0.0.1"},
    {upstream_port, 50054},

    %% Upstream connection pool size
    {upstream_pool_size, 16},

    %% Heartbeat batching interval (ms)
    {heartbeat_batch_interval_ms, 10000},

    %% Default command timeout (seconds)
    {default_command_timeout_s, 300},

    %% Prometheus metrics HTTP port
    {prometheus_port, 9568},

    %% Agent telemetry gauge emission interval (ms)
    {telemetry_gauge_interval_ms, 10000},

    %% Consistent hash ring: virtual nodes per physical node
    {hash_ring_vnodes, 256}
]}
```

### TLS Configuration (Optional)

To enable mTLS between agents and the gateway, add the `tls` key:

```erlang
{tls, [
    {certfile, "/etc/yuzu/gateway.crt"},
    {keyfile,  "/etc/yuzu/gateway.key"},
    {cacertfile, "/etc/yuzu/ca.crt"},
    {verify, verify_peer},
    {fail_if_no_peer_cert, true}
]}
```

### Server-Side Setup

The C++ server must be started with the `--gateway-upstream` flag specifying
the address and port for the GatewayUpstream service. This port must match
`upstream_port` in `sys.config`:

```bash
yuzu-server --gateway-upstream "0.0.0.0:50054"
```

---

## Building and Testing

### Prerequisites

- Erlang/OTP 26 or later
- rebar3

### Build

```bash
cd gateway
rebar3 compile
```

### Run Tests

```bash
cd gateway
rebar3 ct --dir apps/yuzu_gw/test
```

To run a specific test suite:

```bash
rebar3 ct --dir apps/yuzu_gw/test --suite yuzu_gw_agent_SUITE
```

### Create a Release

```bash
cd gateway
rebar3 release
```

The release is written to `_build/default/rel/yuzu_gw/`.

### Production Release

```bash
cd gateway
rebar3 as prod release
```

Production releases include the Erlang runtime (`include_erts: true`) for
self-contained deployment.

### Run the Release

```bash
_build/default/rel/yuzu_gw/bin/yuzu_gw foreground
```

### Interactive Shell (Development)

```bash
cd gateway
rebar3 shell
```

This starts the gateway with all applications loaded, useful for debugging.

### Dependencies

| Dependency | Version | Purpose |
|---|---|---|
| grpcbox | 0.17.1 | gRPC server and client (HTTP/2, protobuf) |
| gpb | 4.21.2 | Protobuf compiler and runtime |
| telemetry | 1.3.0 | Metrics event API |
| prometheus | 4.11.0 | Prometheus exposition |
| prometheus_httpd | 2.1.2 | HTTP endpoint for Prometheus scraping |
| recon | 2.5.5 | Production introspection |
| gproc | 1.0.0 | Extended process registry |

Test-only dependencies (loaded in the `test` profile):

| Dependency | Version | Purpose |
|---|---|---|
| meck | 0.9.2 | Mocking framework |
| proper | 1.4.0 | Property-based testing |

---

## Gateway Clustering

> **Status: PLANNED -- NOT YET IMPLEMENTED (Issue 7.1.1)**

The current gateway runs as a single Erlang node. Planned clustering support
will enable multiple gateway nodes to form a distributed cluster for
horizontal scaling and fault tolerance.

### Planned Features

**Adjacency table:** Each gateway node maintains a routing table mapping agent
IDs to the owning node. When a command targets an agent on a different node,
the router forwards it via Erlang distribution.

**Load shedding via GOAWAY:** When a gateway node is overloaded, it sends
HTTP/2 GOAWAY frames to agents, causing them to reconnect. A load balancer
directs them to less-loaded nodes.

**Agent absorption:** When a gateway node shuts down (planned or crash), its
agents reconnect and are absorbed by the remaining nodes. The adjacency table
is updated via Erlang's node monitoring (`net_kernel:monitor_nodes/1`).

**Latency-based redistribution:** Agents periodically report their round-trip
latency to the gateway. If a closer node is available, the agent is migrated
via a controlled GOAWAY + reconnect cycle.

**Stability mechanisms:**
- Cooldown period after redistribution to prevent oscillation.
- Hysteresis thresholds -- an agent is only migrated if the latency improvement
  exceeds a configurable minimum.
- Rate limiting on GOAWAY frames to prevent thundering herd.

---

## Prometheus Metrics

**Status: PARTIALLY IMPLEMENTED**

The gateway exposes Prometheus metrics on a configurable HTTP port (default:
9568). The `yuzu_gw_telemetry` module defines telemetry events, and
`yuzu_gw_gauge` periodically emits gauge values.

### Available Metrics

| Metric | Type | Description |
|---|---|---|
| `yuzu_gw_agents_connected` | gauge | Number of currently connected agents |
| `yuzu_gw_commands_dispatched_total` | counter | Total commands dispatched to agents |
| `yuzu_gw_commands_completed_total` | counter | Total commands completed (by status) |
| `yuzu_gw_heartbeats_batched_total` | counter | Total heartbeats sent in batch RPCs |
| `yuzu_gw_upstream_rpc_duration_seconds` | histogram | Upstream RPC latency by method |
| `yuzu_gw_upstream_rpc_errors_total` | counter | Upstream RPC failures by method |

### Planned Metrics (Not Yet Implemented)

| Metric | Type | Description |
|---|---|---|
| `yuzu_gw_cluster_nodes` | gauge | Number of nodes in the gateway cluster |
| `yuzu_gw_agent_migrations_total` | counter | Agents migrated between nodes |
| `yuzu_gw_goaway_sent_total` | counter | GOAWAY frames sent for load shedding |

### Scrape Configuration

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'yuzu-gateway'
    static_configs:
      - targets: ['gateway-host:9568']
    scrape_interval: 15s
```

---

## Reference

- `docs/erlang-gateway-blueprint.md` -- Full architecture blueprint with
  detailed process model, message flow diagrams, and design rationale.
- `proto/yuzu/gateway/v1/gateway.proto` -- GatewayUpstream protobuf definition.
- `gateway/config/sys.config` -- Default configuration.
- `gateway/config/vm.args` -- Erlang VM arguments.
- `gateway/rebar.config` -- Build configuration and dependencies.
