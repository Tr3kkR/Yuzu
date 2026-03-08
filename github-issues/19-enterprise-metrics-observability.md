---
title: "[P2/ENT] Add Prometheus metrics and structured logging"
labels: enhancement, enterprise, P2, observability
assignees: ""
---

## Summary

There are no metrics, no structured logging, and no OpenTelemetry integration. Enterprise deployments require observability for monitoring, alerting, and troubleshooting.

## Deliverables

### 1. Prometheus metrics endpoint

Expose `GET /metrics` on the web server (or a dedicated metrics port):

**Server metrics:**
| Metric | Type | Description |
|--------|------|-------------|
| `yuzu_agents_connected` | Gauge | Currently connected agents |
| `yuzu_agents_registered_total` | Counter | Total agent registrations |
| `yuzu_commands_dispatched_total` | Counter | Commands sent (by plugin, action) |
| `yuzu_commands_completed_total` | Counter | Commands completed (by status) |
| `yuzu_command_duration_seconds` | Histogram | Command execution latency |
| `yuzu_grpc_requests_total` | Counter | gRPC requests (by method, status) |
| `yuzu_http_requests_total` | Counter | HTTP requests (by path, status) |

**Agent metrics:**
| Metric | Type | Description |
|--------|------|-------------|
| `yuzu_agent_uptime_seconds` | Gauge | Agent uptime |
| `yuzu_agent_commands_executed_total` | Counter | Commands executed (by plugin) |
| `yuzu_agent_plugins_loaded` | Gauge | Number of loaded plugins |

Use `prometheus-cpp` library (add to vcpkg.json).

### 2. Structured JSON logging

Add `--log-format json` flag:

```json
{"timestamp":"2026-03-08T10:00:00.123Z","level":"info","component":"server","event":"agent_registered","agent_id":"abc-123","hostname":"prod-01"}
```

spdlog supports custom formatters — create a JSON formatter.

### 3. OpenTelemetry traces (stretch)

Instrument gRPC calls with OpenTelemetry for distributed tracing across agent-server communication.

## Acceptance Criteria

- [ ] `/metrics` endpoint returns Prometheus text format
- [ ] Core server and agent metrics exposed
- [ ] `--log-format json` enables structured JSON logging
- [ ] Grafana dashboard template provided (`deploy/grafana/`)
- [ ] Alert rules for agent disconnection and command failures
