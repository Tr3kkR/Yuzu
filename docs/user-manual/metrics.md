# Prometheus Metrics and Observability

Yuzu exposes a Prometheus-compatible `/metrics` endpoint on the server and
provides real-time event streaming for dashboard live updates. This page covers
how to scrape metrics, what is exposed, and how to connect Grafana or other
monitoring tools.

## Metrics endpoint

### GET /metrics

Returns all server and connected-agent metrics in Prometheus exposition format.
This endpoint does **not** require authentication --- it is exempted from the
auth middleware so that Prometheus can scrape it without session cookies.

```bash
curl -s 'http://localhost:8080/metrics'
```

**Example response (excerpt):**

```
# HELP yuzu_server_http_requests_total Total HTTP requests handled
# TYPE yuzu_server_http_requests_total counter
yuzu_server_http_requests_total{method="GET",status="200"} 1542
yuzu_server_http_requests_total{method="POST",status="200"} 87
yuzu_server_http_requests_total{method="GET",status="404"} 12

# HELP yuzu_server_http_request_duration_seconds HTTP request latency
# TYPE yuzu_server_http_request_duration_seconds histogram
yuzu_server_http_request_duration_seconds_bucket{method="GET",le="0.005"} 920
yuzu_server_http_request_duration_seconds_bucket{method="GET",le="0.01"} 1100
yuzu_server_http_request_duration_seconds_bucket{method="GET",le="0.025"} 1350
yuzu_server_http_request_duration_seconds_bucket{method="GET",le="0.05"} 1450
yuzu_server_http_request_duration_seconds_bucket{method="GET",le="0.1"} 1500
yuzu_server_http_request_duration_seconds_bucket{method="GET",le="0.25"} 1530
yuzu_server_http_request_duration_seconds_bucket{method="GET",le="0.5"} 1540
yuzu_server_http_request_duration_seconds_bucket{method="GET",le="1.0"} 1542
yuzu_server_http_request_duration_seconds_bucket{method="GET",le="2.5"} 1542
yuzu_server_http_request_duration_seconds_bucket{method="GET",le="5.0"} 1542
yuzu_server_http_request_duration_seconds_bucket{method="GET",le="10.0"} 1542
yuzu_server_http_request_duration_seconds_bucket{method="GET",le="+Inf"} 1542
yuzu_server_http_request_duration_seconds_sum{method="GET"} 12.345
yuzu_server_http_request_duration_seconds_count{method="GET"} 1542

# HELP yuzu_server_connected_agents Number of currently connected agents
# TYPE yuzu_server_connected_agents gauge
yuzu_server_connected_agents 47
```

## Naming conventions

All Yuzu metrics follow a consistent naming scheme.

| Prefix | Source | Examples |
|---|---|---|
| `yuzu_server_` | Server process | `yuzu_server_http_requests_total`, `yuzu_server_connected_agents` |
| `yuzu_agent_` | Agent process | `yuzu_agent_plugin_executions_total`, `yuzu_agent_heartbeat_latency_seconds` |

## Labels

Metrics carry a standard set of labels for filtering and grouping in queries.

| Label | Description | Example values |
|---|---|---|
| `agent_id` | Unique agent identifier | `agent-001`, `dc2-web-14` |
| `plugin` | Plugin that produced the metric | `hardware_info`, `network_info` |
| `method` | HTTP method or RPC name | `GET`, `POST`, `Heartbeat` |
| `status` | HTTP status code or outcome | `200`, `500`, `success`, `failure` |
| `os` | Agent operating system | `windows`, `linux`, `darwin` |
| `arch` | Agent CPU architecture | `x64`, `arm64` |

## Histogram buckets

All histogram metrics use the same default bucket boundaries (in seconds):

```
0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0
```

These buckets are suitable for request latency tracking. The range covers
sub-millisecond local operations through multi-second network calls.

## Prometheus scrape configuration

Add Yuzu to your Prometheus `prometheus.yml`. The `/metrics` endpoint is
unauthenticated, so no credentials are needed:

```yaml
scrape_configs:
  - job_name: 'yuzu-server'
    static_configs:
      - targets: ['localhost:8080']
    metrics_path: /metrics
    scheme: http
```

**Multiple servers:**

```yaml
scrape_configs:
  - job_name: 'yuzu-server'
    static_configs:
      - targets:
          - 'yuzu-primary.example.com:8080'
          - 'yuzu-secondary.example.com:8080'
    metrics_path: /metrics
    scheme: https
```

### Verifying the scrape

After adding the configuration, confirm that Prometheus is scraping
successfully:

```bash
# Check target status
curl -s 'http://localhost:9090/api/v1/targets' | jq '.data.activeTargets[] | select(.labels.job == "yuzu-server")'

# Query a metric
curl -s 'http://localhost:9090/api/v1/query?query=yuzu_server_connected_agents' | jq .
```

## Real-time event stream

### GET /events

The server exposes a Server-Sent Events (SSE) endpoint for real-time updates.
The dashboard uses this for live agent status, but any SSE client can consume
it. This endpoint requires authentication (session cookie).

```bash
curl -s -b cookies.txt -N 'http://localhost:8080/events'
```

**Example output:**

```
event: agent-online
data: agent-001

event: agent-offline
data: agent-003

event: command-status
data: cmd-20240319-001|success

event: output
data: agent-001|hardware_info|{"cpu":"Intel i7","ram_gb":32}
```

**Event types:**

| Event | Data format | Description |
|---|---|---|
| `agent-online` | `{agent_id}` | An agent established a gRPC connection |
| `agent-offline` | `{agent_id}` | An agent connection was lost |
| `pending-agent` | `{agent_id}` | An agent is awaiting enrollment approval |
| `command-status` | `{command_id}\|{status}` | An instruction finished executing |
| `output` | `{agent_id}\|{plugin}\|{data}` | Streaming output from an instruction |
| `timing` | `{command_id}\|{metric}={value}\|{phase}` | Execution timing data |

Note: event data is plain text (not JSON). Fields are pipe-delimited where
multiple values are present.

### Agent lifecycle via WatchEvents RPC

The gRPC `WatchEvents` RPC provides the same lifecycle events (connect,
disconnect, plugin load) over a bidirectional stream. This is used internally
by the gateway and can be consumed by custom integrations that prefer gRPC over
SSE.

## Management group metrics

The server exposes two gauges for management group telemetry. These are
refreshed on every `/metrics` scrape.

| Metric | Type | Description |
|---|---|---|
| `yuzu_server_management_groups_total` | gauge | Total number of management groups (including the root "All Devices" group) |
| `yuzu_server_group_members_total` | gauge | Total membership records across all management groups |

**Example output:**

```
# HELP yuzu_server_management_groups_total Total number of management groups
# TYPE yuzu_server_management_groups_total gauge
yuzu_server_management_groups_total 5

# HELP yuzu_server_group_members_total Total members across all management groups
# TYPE yuzu_server_group_members_total gauge
yuzu_server_group_members_total 42
```

**Useful PromQL queries:**

```promql
# Total management groups
yuzu_server_management_groups_total

# Average members per group
yuzu_server_group_members_total / yuzu_server_management_groups_total

# Alert if no management groups exist (store may be down)
yuzu_server_management_groups_total == 0
```

## Useful PromQL queries

### Fleet overview

```promql
# Total connected agents
yuzu_server_connected_agents

# Connected agents by OS
count by (os) (yuzu_agent_info)

# Connected agents by architecture
count by (arch) (yuzu_agent_info)
```

### Request performance

```promql
# Request rate (per second, 5-minute window)
rate(yuzu_server_http_requests_total[5m])

# 95th percentile latency
histogram_quantile(0.95, rate(yuzu_server_http_request_duration_seconds_bucket[5m]))

# Error rate (percentage of 5xx responses)
sum(rate(yuzu_server_http_requests_total{status=~"5.."}[5m]))
/ sum(rate(yuzu_server_http_requests_total[5m])) * 100
```

### Agent health

```promql
# Agents with heartbeat latency over 5 seconds
yuzu_agent_heartbeat_latency_seconds > 5

# Plugin execution failure rate by plugin
sum by (plugin) (rate(yuzu_agent_plugin_executions_total{status="failure"}[5m]))
/ sum by (plugin) (rate(yuzu_agent_plugin_executions_total[5m])) * 100
```

### Instruction throughput

```promql
# Instructions completed per minute
rate(yuzu_server_instructions_completed_total[5m]) * 60

# Average instruction duration
rate(yuzu_server_instruction_duration_seconds_sum[5m])
/ rate(yuzu_server_instruction_duration_seconds_count[5m])
```

## Grafana integration

Import the Prometheus data source into Grafana and use the PromQL queries
above to build dashboards. A typical Yuzu dashboard includes:

| Panel | Visualization | Query |
|---|---|---|
| Connected agents | Stat / single value | `yuzu_server_connected_agents` |
| Agents by OS | Pie chart | `count by (os) (yuzu_agent_info)` |
| Request rate | Time series | `rate(yuzu_server_http_requests_total[5m])` |
| Request latency (p95) | Time series | `histogram_quantile(0.95, ...)` |
| Error rate | Time series | `5xx / total * 100` |
| Instruction throughput | Time series | `rate(yuzu_server_instructions_completed_total[5m])` |

### Alerting rules

Example Prometheus alerting rules for Yuzu:

```yaml
groups:
  - name: yuzu
    rules:
      - alert: YuzuNoAgentsConnected
        expr: yuzu_server_connected_agents == 0
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "No agents connected to Yuzu server"

      - alert: YuzuHighErrorRate
        expr: >
          sum(rate(yuzu_server_http_requests_total{status=~"5.."}[5m]))
          / sum(rate(yuzu_server_http_requests_total[5m])) > 0.05
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "Yuzu server error rate above 5%"

      - alert: YuzuHighLatency
        expr: >
          histogram_quantile(0.95,
            rate(yuzu_server_http_request_duration_seconds_bucket[5m])
          ) > 2.0
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "Yuzu server p95 latency above 2 seconds"
```

## Planned features

| Feature | Roadmap | Description |
|---|---|---|
| System health dashboard | Phase 7, Issue 7.2 | Server CPU, memory, connection counts, queue depths |
| Topology map | Phase 7 | Visual map of server nodes, gateways, and agent counts |
| Grafana dashboard templates | Planned | Pre-built JSON dashboard files in `docs/grafana/` |
