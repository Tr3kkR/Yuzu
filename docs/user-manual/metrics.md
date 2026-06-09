# Prometheus Metrics and Observability

Yuzu exposes a Prometheus-compatible `/metrics` endpoint on the server and
provides real-time event streaming for dashboard live updates. This page covers
how to scrape metrics, what is exposed, and how to connect Grafana or other
monitoring tools.

## Metrics endpoint

### GET /metrics

Returns all server and connected-agent metrics in Prometheus exposition format.
Localhost requests (`127.0.0.1`, `::1`) are always unauthenticated for
Prometheus scraping. Remote requests require authentication by default. Use
`--metrics-no-auth` (env: `YUZU_METRICS_NO_AUTH`) to allow unauthenticated
remote access for external monitoring infrastructure.

```bash
curl -s 'http://localhost:8080/metrics'
```

**Example response (excerpt):**

```
# HELP yuzu_http_requests_total Total HTTP requests handled
# TYPE yuzu_http_requests_total counter
yuzu_http_requests_total{method="GET",status="200"} 1542
yuzu_http_requests_total{method="POST",status="200"} 87
yuzu_http_requests_total{method="GET",status="404"} 12

# HELP yuzu_command_duration_seconds Command execution latency in seconds
# TYPE yuzu_command_duration_seconds histogram
yuzu_command_duration_seconds_bucket{le="0.005"} 12
yuzu_command_duration_seconds_bucket{le="0.01"} 47
yuzu_command_duration_seconds_bucket{le="0.025"} 180
yuzu_command_duration_seconds_bucket{le="0.05"} 540
yuzu_command_duration_seconds_bucket{le="0.1"} 980
yuzu_command_duration_seconds_bucket{le="0.25"} 1320
yuzu_command_duration_seconds_bucket{le="0.5"} 1480
yuzu_command_duration_seconds_bucket{le="1.0"} 1530
yuzu_command_duration_seconds_bucket{le="2.5"} 1541
yuzu_command_duration_seconds_bucket{le="5.0"} 1542
yuzu_command_duration_seconds_bucket{le="10.0"} 1542
yuzu_command_duration_seconds_bucket{le="+Inf"} 1542
yuzu_command_duration_seconds_sum 198.74
yuzu_command_duration_seconds_count 1542

# HELP yuzu_agents_connected Number of currently connected agents
# TYPE yuzu_agents_connected gauge
yuzu_agents_connected 47
```

## Naming conventions

All Yuzu metrics follow a consistent naming scheme.

| Prefix | Source | Examples |
|---|---|---|
| `yuzu_server_` | Server process | `yuzu_server_uptime_seconds`, `yuzu_server_open_connections` |
| `yuzu_server_cert_` | Certificate reload | `yuzu_server_cert_reloads_total`, `yuzu_server_cert_reload_failures_total` |
| `yuzu_agent_` | Agent process | `yuzu_agent_commands_executed_total`, `yuzu_agent_uptime_seconds` |
| `yuzu_viz_` | Fleet visualization (`/api/v1/viz/fleet/topology` + heartbeat push ingestion) | `yuzu_viz_topology_request_seconds`, `yuzu_viz_topology_pushed_total`, `yuzu_viz_topology_push_rejected_total`, `yuzu_viz_pushed_cap_evictions_total`, `yuzu_viz_pushed_map_size` |

## Fleet visualization metrics

The fleet-visualization REST surface (PR 3 of feat/viz-engine ladder; see [REST API §Fleet Visualization](rest-api.md)) exposes the following metrics. Routes share one `FleetTopologyStore` cache; all metrics are process-global.

| Metric | Type | Description |
|---|---|---|
| `yuzu_viz_topology_request_seconds` | histogram | End-to-end request latency on the success path (200). Default bucket boundaries above. Cache-hit p99 should be <100 ms; cache-miss p99 is bounded by the 5 s fetcher deadline + 0.5 s overhead. |
| `yuzu_viz_topology_fetch_duration_seconds` | histogram | Duration of the inner agent-dispatch path (`tar.fleet_snapshot` fan-out + response aggregation), measured only on cache-miss refills. Distinguishes "agent dispatch is slow" from "the rest of the request is slow" (auth, RBAC, response serialisation, network egress). Observed even on fetcher exception so a hung fetcher produces a visible upper-bound observation. |
| `yuzu_viz_cache_hit_total` | counter | Increments on each request that observed a TTL-fresh slot. Pair with `yuzu_viz_cache_miss_total` to compute hit rate. |
| `yuzu_viz_cache_miss_total` | counter | Increments on each request that triggered a refill. With a 60 s TTL and 1 RPS dashboard polling, expect ~1/60 of all requests. |
| `yuzu_viz_oversize_response_total` | counter | Increments on each `413` response (snapshot exceeded `machines_max`). Operator misconfiguration signal. |
| `yuzu_viz_agent_dispatch_timeout_total` | counter | Increments per agent that was dispatched `tar.fleet_snapshot` but didn't respond within the 5 s deadline. A non-zero rate signals partial fleet outage. |
| `yuzu_viz_refill_oversize_drops_total` | gauge | Refills whose serialised size exceeded `max_snapshot_bytes` (256 MiB default). The result is returned to the caller but NOT cached, so the next request re-runs the full fetcher. Non-zero indicates a misbehaving agent or an undersized cap. |
| `yuzu_viz_refill_wait_timeouts_total` | gauge | Single-flight waiters that timed out on `cv.wait_for` before the refill completed. Non-zero indicates the fetcher is exceeding its deadline. |
| `yuzu_viz_refill_waiters_total` | gauge | Number of fetch waiters that piggybacked on an in-flight refill (single-flight wins). High values indicate stampede risk on `/viz/fleet`. |
| `yuzu_viz_local_edges_dropped_total` | gauge | `EdgeScope::Local` connection edges dropped before serialisation because no reciprocal half was visible in the same agent payload. Non-zero is expected under normal churn (kernel race during socket teardown, the agent's 4096-connection cap cutting a partner); a sustained spike vs steady-state indicates systematic loss. |
| `yuzu_viz_topology_pushed_total` | counter | Agent-pushed `fleet_snapshot.v1` payloads accepted into the `FleetTopologyStore`. Labelled `via=direct\|gateway` (direct `HeartbeatRequest` vs gateway `BatchHeartbeat`); sum across the label for fleet-wide push volume. |
| `yuzu_viz_topology_push_parse_errors_total` | counter | Agent-pushed payloads rejected by the shared parser (oversized, row-cap exceeded, malformed JSON). Labelled `via=direct\|gateway`. |
| `yuzu_viz_topology_push_rejected_total` | gauge | Pushes rejected by the IP-spoof guard because a claimed `local_ip` is owned by a live agent. A non-zero rate signals a spoofing campaign or a NAT/DHCP misconfiguration. |
| `yuzu_viz_pushed_cap_evictions_total` | gauge | `pushed_` map entries evicted because the map was at `kPushedMapHardCap` (100000) when a new agent pushed. Non-zero means the fleet outgrew the cap or a cap-flood attack is evicting legitimate agents — cross-check with the `topology.push.evicted_for_cap` audit events. |
| `yuzu_viz_pushed_map_size` | gauge | Current occupancy of the `pushed_` map. Primary memory-pressure signal — alert before it approaches the 100000 hard cap. |

## Subscribe peer-binding security counters

The per-session peer-IP binding for the agent `Subscribe` RPC (#826/#1058/#1059, NAT-aware relaxation #1128) emits two paired counters. Both carry the `event="security"` SIEM-routing label and should be read together — a spike in one alone vs both together carries very different meaning.

| Metric | Type | Labels | Description |
|---|---|---|---|
| `yuzu_grpc_subscribe_peer_mismatch_total` | counter | `event="security"`, `gateway_mode=true\|false` | A Subscribe attempt was **rejected** because its source IP did not match the IP recorded at `Register` time and no accommodation applied. `gateway_mode` reflects whether the server is running with `--gateway-mode`. The audit row `session.peer_mismatch result=denied` (see [audit-log.md](audit-log.md)) carries the forensic detail. |
| `yuzu_grpc_subscribe_peer_advisory_total` | counter | `event="security"`, `reason="mtls_identity_match"\|"trusted_nat_cidr"`, `gateway_mode=true\|false` | A Subscribe peer-IP mismatch was **tolerated** (stream established) under a NAT-aware accommodation (#1128). `reason` distinguishes the two opt-in accommodations: `mtls_identity_match` (via `--nat-trust-mtls-identity`), `trusted_nat_cidr` (both IPs in one `--trusted-nat-cidr` range). The audit row is `session.peer_mismatch result=ok outcome=advisory`. |

**Read-together interpretation.** Both counters share the `event` and `gateway_mode` labels so an analyst can join them by operator-mode dimension. A spike in `_peer_advisory_total` alone is expected multi-egress churn in NAT-relaxed deployments and is not actionable. A spike in BOTH simultaneously is the actionable signal: it can indicate a stolen-session replay landing inside a trusted range, where the legitimate agent triggers the reject and the attacker (also in-range) is admitted via advisory. The `AgentSubscribePeerAdvisoryCorrelatedSpike` alert below encodes exactly that pattern.

### Recommended alerts

```yaml
- alert: VizFleetDispatchTimeoutsRising
  expr: rate(yuzu_viz_agent_dispatch_timeout_total[5m]) > 5
  for: 5m
  annotations:
    summary: "Fleet topology fetcher is timing out per-agent (partial fleet outage)"

- alert: VizFleetSlowRequests
  expr: histogram_quantile(0.99, sum(rate(yuzu_viz_topology_request_seconds_bucket[5m])) by (le)) > 5.5
  for: 10m

- alert: VizFleetSlowAgentDispatch
  expr: histogram_quantile(0.99, sum(rate(yuzu_viz_topology_fetch_duration_seconds_bucket[5m])) by (le)) > 5.0
  for: 10m
  annotations:
    summary: "Fleet topology agent-dispatch p99 above the 5 s fetcher deadline; agents may be unresponsive"

- alert: VizFleetRefillOversizeDrops
  expr: increase(yuzu_viz_refill_oversize_drops_total[10m]) > 0
  annotations:
    summary: "FleetTopologyStore is dropping refills above 256 MiB cap; raise --max-snapshot-bytes or scope down the fleet"

- alert: VizFleetPushRejections
  expr: increase(yuzu_viz_topology_push_rejected_total[10m]) > 0
  annotations:
    summary: "Fleet-snapshot pushes rejected by the IP-spoof guard — spoofing campaign or NAT/DHCP misconfiguration"

- alert: VizFleetCapEvictions
  expr: increase(yuzu_viz_pushed_cap_evictions_total[10m]) > 0
  annotations:
    summary: "FleetTopologyStore is evicting agents at the 100000-entry hard cap — fleet outgrew the cap or a cap-flood attack is in progress"

- alert: VizFleetPushedMapNearCap
  expr: yuzu_viz_pushed_map_size > 80000
  for: 10m
  annotations:
    summary: "FleetTopologyStore pushed_ map above 80% of the 100000 hard cap; evictions imminent"

# Stolen-session signals (event="security" — routed to the SIEM via Prometheus;
# see observability-conventions.md). The audit rows session.peer_mismatch /
# session.identity_mismatch carry the forensic detail.
- alert: AgentSubscribePeerMismatch
  expr: increase(yuzu_grpc_subscribe_peer_mismatch_total{event="security"}[5m]) > 0
  annotations:
    summary: "Subscribe peer-IP mismatch (#1059) — possible stolen session_id replayed from a new IP"

- alert: AgentSubscribeIdentityMismatch
  expr: increase(yuzu_grpc_subscribe_identity_mismatch_total{event="security"}[5m]) > 0
  annotations:
    summary: "Subscribe mTLS identity mismatch (#1118) — possible stolen session_id replayed with a non-matching client cert"

# NAT-aware tolerated mismatch (#1128). yuzu_grpc_subscribe_peer_advisory_total
# {event="security",reason="mtls_identity_match|trusted_nat_cidr"} counts peer-IP
# mismatches that were DOWNGRADED to advisory (not rejected) under a NAT
# accommodation. A spike here ALONE is expected churn in multi-egress NAT
# deployments — do NOT alert on it bare. The actionable signal is the
# correlated form: advisory AND rejected mismatches rising together can mean a
# stolen-session replay landing inside a trusted range.
- alert: AgentSubscribePeerAdvisoryCorrelatedSpike
  expr: >
    increase(yuzu_grpc_subscribe_peer_advisory_total{event="security"}[5m]) > 0
    and increase(yuzu_grpc_subscribe_peer_mismatch_total{event="security"}[5m]) > 0
  annotations:
    summary: "Tolerated NAT peer-mismatches (#1128) coincide with rejected mismatches — investigate the reject events for a possible stolen-session replay inside a trusted range"

# Operator-visibility guard for --nat-trust-mtls-identity. Sustained
# mtls_identity_match advisories mean the (opt-in, off-by-default) mTLS-identity
# NAT accommodation is active — confirm it was enabled intentionally AND that
# client certs are PER-AGENT (a shared fleet cert makes this a replay bypass,
# gov UP-2). Long window: this should be rare; a steady stream is worth a look.
- alert: AgentSubscribeMtlsIdentityAdvisoryActive
  expr: increase(yuzu_grpc_subscribe_peer_advisory_total{event="security",reason="mtls_identity_match"}[30m]) > 0
  for: 30m
  annotations:
    summary: "--nat-trust-mtls-identity is relaxing peer-IP binding via mTLS-identity match — verify it was enabled deliberately and that client certs are per-agent (shared cert = session-replay bypass)"

- alert: AgentRegisterDeniedFlood
  expr: rate(yuzu_register_denied_total{event="security"}[5m]) > 1
  for: 5m
  annotations:
    summary: "Admin-denied identity repeatedly attempting Register (#1067) — credential-abuse / denied-flood signal"
```

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

Add Yuzu to your Prometheus `prometheus.yml`. For local scrapers, no
credentials are needed. Remote scrapers need `--metrics-no-auth` on the
server or must provide authentication:

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
curl -s 'http://localhost:9090/api/v1/query?query=yuzu_agents_connected' | jq .
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

## Guardian metrics

| Metric | Type | Description |
|---|---|---|
| `yuzu_server_guardian_baselines_total` | gauge | Number of persisted Guardian Baselines. Refreshed on every `/metrics` scrape. |
| `yuzu_fleet_agents_crash_observer_disarmed` | gauge | Windows agents (DEX enabled) whose process-crash recorder is not currently armed — it failed to arm at startup, or its subscription died at runtime (EventLog restart / channel ACL change). `> 0` means crash telemetry is silently off on that many endpoints. Agents off Windows or started with `--dex-disable` are excluded, so this is a genuine fault count. Rolled up from agent heartbeats; see the `YuzuCrashObserverDisarmed` alert. Note: it does **not** detect a host where Windows Error Reporting is disabled (the recorder stays armed but no Event 1000 is ever written). |
| `yuzu_fleet_crashes_observed_total` | gauge | Fleet-wide sum of process crashes observed by DEX recorders since each agent started. **A gauge, not a monotonic counter** — it resets when an agent restarts, so do not apply `rate()`/`increase()`; per-crash detail (process, module, exception code) lives in the Guardian events store, query via `GET /api/v1/guaranteed-state/events?rule_id=__observation__`. |

Broader Guardian metrics — rule push counts, agent apply latency, parse errors, and a fleet compliance-state distribution (compliant/drifted/error/unknown) — are on the roadmap alongside agent-side enforcement metrics.

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
yuzu_agents_connected

# Connected agents by OS
sum by (os) (yuzu_fleet_agents_by_os)

# Connected agents by architecture
sum by (arch) (yuzu_fleet_agents_by_arch)
```

### Request performance

```promql
# Request rate (per second, 5-minute window)
rate(yuzu_http_requests_total[5m])

# 95th percentile command-execution latency
# (the server emits no general HTTP request-duration histogram; command duration
#  is its primary latency SLI — see also auth-login and viz-topology histograms)
histogram_quantile(0.95, sum(rate(yuzu_command_duration_seconds_bucket[5m])) by (le))

# Error rate (percentage of 5xx responses)
sum(rate(yuzu_http_requests_total{status=~"5.."}[5m]))
/ sum(rate(yuzu_http_requests_total[5m])) * 100
```

### Agent health

```promql
# Healthy agents reported via heartbeat status_tags.
# (Agents have no Prometheus endpoint, so there is no per-agent heartbeat-latency
#  series; the server re-exports fleet health as this gauge.)
yuzu_fleet_agents_healthy

# Plugin execution failure rate by plugin
sum by (plugin) (rate(yuzu_agent_commands_executed_total{status="failure"}[5m]))
/ sum by (plugin) (rate(yuzu_agent_commands_executed_total[5m])) * 100
```

### Plugin load + signing rejections (`yuzu_agent_plugin_rejected_total`)

Counter incremented every time the agent rejects a plugin at scan time
**before** the plugin's code runs. The `reason` label is bounded to a
fixed set of stable string prefixes — alert rules SHOULD pin against
the literal label values, not substring matches.

| Reason label | Meaning | Operator action |
|---|---|---|
| `reserved_name` | Plugin declared a reserved name (`__guard__`, `__system__`, `__update__`). Possible plugin-author error or a malicious shadowing attempt (#453). | Investigate the plugin source / drop. |
| `load_failed` | `dlopen` / `LoadLibrary` failed, missing `yuzu_plugin_descriptor` export, or ABI version mismatch. | Check the agent log for the dlopen error and rebuild the plugin against the current SDK ABI. |
| `signature_missing` | `--plugin-trust-bundle` is set, `--plugin-require-signature` is set, and a plugin has no `<plugin>.so.sig` sibling. | Sign the plugin, deploy the `.sig` alongside, or relax the require flag. |
| `signature_invalid` | `.sig` file exists but the CMS verification failed at the signature/digest layer (most commonly: the plugin file was modified after signing). | Re-sign the plugin or investigate tampering. |
| `signature_untrusted_chain` | The signing cert does not chain to a CA in the operator's trust bundle, OR the leaf cert lacks `EKU=codeSigning`, OR the cert chain has expired. | Verify the bundle includes the right CA root; re-issue a leaf with `extendedKeyUsage=codeSigning`; rotate expired CAs. |

```promql
# WARN: any plugin rejected for an invalid signature in the last 5 min
# (most often: tampered file in the plugin dir).
increase(yuzu_agent_plugin_rejected_total{reason="signature_invalid"}[5m]) > 0

# CRITICAL: chain validation failure means a plugin was signed against
# a CA the operator's trust bundle doesn't anchor — supply-chain signal,
# or an expired/revoked operator CA.
increase(yuzu_agent_plugin_rejected_total{reason="signature_untrusted_chain"}[5m]) > 0

# Volume tracker: missing-sig rejections during a signing rollout
# (transitional → enforced). Expect this to be non-zero only during
# rollout, then drop to 0 once every plugin has a .sig sibling.
sum by (instance) (increase(yuzu_agent_plugin_rejected_total{reason="signature_missing"}[1h]))

# Reserved-name attempts (#453) — should be 0 in normal operation.
increase(yuzu_agent_plugin_rejected_total{reason="reserved_name"}[5m]) > 0
```

### Instruction throughput

```promql
# Instructions completed per minute
rate(yuzu_commands_completed_total[5m]) * 60

# Average instruction duration
rate(yuzu_command_duration_seconds_sum[5m])
/ rate(yuzu_command_duration_seconds_count[5m])
```

## Grafana integration

Yuzu ships pre-built Grafana dashboards. The operational set lives in
`deploy/grafana/` (`yuzu-dashboard`, `yuzu-fleet-dashboard`, and
`yuzu-gateway-dashboard` over Prometheus, plus `yuzu-analytics-dashboard` over
ClickHouse) and is auto-provisioned by the UAT / full-UAT rigs; a standalone
Prometheus import template is at `docs/grafana/yuzu-overview.json`. See
[`docs/grafana/README.md`](../grafana/README.md) for the full list and import
instructions.

To build your own, import the Prometheus data source into Grafana and use the
PromQL queries above. A typical Yuzu dashboard includes:

| Panel | Visualization | Query |
|---|---|---|
| Connected agents | Stat / single value | `yuzu_agents_connected` |
| Agents by OS | Pie chart | `sum by (os) (yuzu_fleet_agents_by_os)` |
| Request rate | Time series | `rate(yuzu_http_requests_total[5m])` |
| Command latency (p95) | Time series | `histogram_quantile(0.95, sum(rate(yuzu_command_duration_seconds_bucket[5m])) by (le))` |
| Error rate | Time series | `5xx / total * 100` |
| Instruction throughput | Time series | `rate(yuzu_commands_completed_total[5m])` |

### Alerting rules

Example Prometheus alerting rules for Yuzu:

```yaml
groups:
  - name: yuzu
    rules:
      - alert: YuzuNoAgentsConnected
        expr: yuzu_agents_connected == 0
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "No agents connected to Yuzu server"

      - alert: YuzuHighErrorRate
        expr: >
          sum(rate(yuzu_http_requests_total{status=~"5.."}[5m]))
          / sum(rate(yuzu_http_requests_total[5m])) > 0.05
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "Yuzu server error rate above 5%"

      - alert: YuzuHighCommandLatency
        expr: |
          histogram_quantile(0.99, sum(rate(yuzu_command_duration_seconds_bucket[5m])) by (le)) > 10
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Command p99 latency exceeds 10 seconds"
```

## Security considerations

### Fleet metadata in metrics labels

The `/metrics` endpoint exposes aggregated fleet composition data through gauge metrics:

| Metric | Labels | Information exposed |
|---|---|---|
| `yuzu_fleet_agents_by_os` | `os` | OS distribution (windows, linux, darwin counts) |
| `yuzu_fleet_agents_by_arch` | `arch` | CPU architecture distribution (x64, arm64 counts) |
| `yuzu_fleet_agents_by_version` | `version` | Agent version inventory |

This data reveals your fleet's attack surface to anyone who can reach the metrics endpoint. An attacker who learns that 80% of your fleet runs Windows x64 with agent v0.4.2 can target known vulnerabilities for that specific combination.

**Mitigations (in order of preference):**

1. **Keep the default** — remote `/metrics` access requires authentication. Localhost is always open for co-located Prometheus.
2. **Restrict network access** — if Prometheus scrapes remotely, use firewall rules or a reverse proxy with authentication in front of the metrics endpoint.
3. **Use `--metrics-no-auth` with caution** — only enable unauthenticated remote access when the metrics endpoint is on a trusted monitoring network, not exposed to the general corporate network or internet.
4. **API token auth** — when available (Phase 3), create a dedicated metrics-scraper API token with read-only scope.

> **Default posture:** The server binds to `127.0.0.1` and requires auth for remote `/metrics` access. No action is needed if you scrape from localhost.

## Planned features

| Feature | Roadmap | Description |
|---|---|---|
| System health dashboard | Phase 7, Issue 7.2 | Server CPU, memory, connection counts, queue depths |
| Topology map | Phase 7 | Visual map of server nodes, gateways, and agent counts |
