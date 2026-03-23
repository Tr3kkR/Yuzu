# Yuzu Grafana Dashboard Templates

This directory contains Grafana dashboard JSON files and documentation for monitoring a Yuzu deployment with Prometheus.

## Prometheus Metric Families

Yuzu exposes Prometheus metrics from the server, agent, and gateway components. All metrics use the `yuzu_` prefix. The following families are available for dashboard construction.

### Server Metrics (`yuzu_server_*`)

| Metric | Type | Description |
|---|---|---|
| `yuzu_server_cert_reloads_total` | counter | Number of successful HTTPS certificate hot-reloads |
| `yuzu_server_cert_reload_failures_total` | counter | Number of failed certificate reload attempts |
| `yuzu_server_http_requests_total` | counter | Total HTTP requests, labeled by `method`, `path`, `status` |
| `yuzu_server_http_request_duration_seconds` | histogram | HTTP request latency, labeled by `method`, `path` |
| `yuzu_server_grpc_sessions_active` | gauge | Number of active gRPC agent sessions |
| `yuzu_server_response_store_writes_total` | counter | Total writes to the response store |
| `yuzu_server_response_store_write_failures_total` | counter | Failed response store writes |
| `yuzu_server_audit_events_total` | counter | Total audit events recorded |

### Agent Metrics (`yuzu_agent_*`)

| Metric | Type | Description |
|---|---|---|
| `yuzu_agent_plugin_executions_total` | counter | Plugin action executions, labeled by `plugin`, `action`, `status` |
| `yuzu_agent_plugin_execution_duration_seconds` | histogram | Plugin execution latency, labeled by `plugin`, `action` |
| `yuzu_agent_trigger_fires_total` | counter | Trigger engine fires, labeled by `trigger_type` |
| `yuzu_agent_heartbeat_sent_total` | counter | Heartbeats sent to the server |
| `yuzu_agent_kv_operations_total` | counter | KV store operations, labeled by `operation` (get, put, delete) |

### Gateway Metrics (`yuzu_gw_*`)

| Metric | Type | Description |
|---|---|---|
| `yuzu_gw_agent_connections_active` | gauge | Current number of connected agents |
| `yuzu_gw_agent_connections_total` | counter | Total agent connections since startup |
| `yuzu_gw_commands_forwarded_total` | counter | Commands forwarded from server to agents |
| `yuzu_gw_commands_failed_total` | counter | Commands that failed to forward |
| `yuzu_gw_backpressure_events_total` | counter | Backpressure events (agent send buffer full) |
| `yuzu_gw_upstream_latency_seconds` | histogram | Latency of upstream (gateway-to-server) RPCs |

### Command Metrics (`yuzu_commands_*`)

| Metric | Type | Description |
|---|---|---|
| `yuzu_commands_completed_total` | counter | Commands completed, labeled by `plugin`, `status` |
| `yuzu_commands_duration_seconds` | histogram | End-to-end command duration, labeled by `plugin` |
| `yuzu_commands_in_flight` | gauge | Commands currently in progress |

### Fleet Metrics (`yuzu_agents_*`)

| Metric | Type | Description |
|---|---|---|
| `yuzu_agents_connected` | gauge | Number of agents currently connected |
| `yuzu_agents_registered_total` | counter | Total agents registered since server startup |
| `yuzu_agents_heartbeats_received_total` | counter | Total heartbeats received from all agents |

## Available Dashboards

| File | Description |
|---|---|
| [yuzu-overview.json](yuzu-overview.json) | Overview dashboard with agent fleet, command throughput, latency, and heartbeat panels |

## Importing Dashboards

1. Open Grafana and navigate to **Dashboards > Import**.
2. Click **Upload JSON file** and select the `.json` file from this directory.
3. Select your Prometheus data source when prompted.
4. Click **Import**.

The dashboards assume a Prometheus data source named `Prometheus`. If your data source has a different name, update the `datasource` fields in the JSON before importing, or select the correct source during import.

## Scrape Configuration

Add the following targets to your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'yuzu-server'
    static_configs:
      - targets: ['localhost:8080']
    metrics_path: '/metrics'

  - job_name: 'yuzu-gateway'
    static_configs:
      - targets: ['localhost:9568']
    metrics_path: '/metrics'

  - job_name: 'yuzu-agent'
    static_configs:
      - targets: ['localhost:9100']
    metrics_path: '/metrics'
```

Adjust addresses and ports to match your deployment. For Docker Compose deployments, the `deploy/docker/docker-compose.yml` file includes a pre-configured Prometheus instance.
