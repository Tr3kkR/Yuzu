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
# HELP yuzu_http_requests_total Total HTTP requests by method, status, and principal_class
# TYPE yuzu_http_requests_total counter
yuzu_http_requests_total{method="GET",status="200",principal_class="human"} 1542
yuzu_http_requests_total{method="POST",status="200",principal_class="agent"} 87
yuzu_http_requests_total{method="GET",status="404",principal_class="none"} 12
yuzu_http_requests_total{method="POST",status="200",principal_class="engine"} 34

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

## Internal-CA / default-certificate metrics

| Metric | Type | Description |
|---|---|---|
| `yuzu_server_default_certs_active` | gauge | `1` when the server is running with built-in per-install **default** certificates, `0` otherwise. Alert on `== 1` for any production deployment — defaults are convenience certs and should be replaced (see `security-hardening.md`). |
| `yuzu_server_cert_expiry_timestamp_seconds{cert="default-ca"}` | gauge | Unix timestamp (seconds) at which the default cert set expires (the leaves are sized to the CA's `notAfter`, so `cert="default-ca"` is the binding expiry). Default certs are 10-year with **no auto-renewal**; the `yuzu-tls` alert rules (`YuzuCertificateExpiringSoon` warn @7d, `YuzuCertificateExpiryCritical` crit @1d in `docs/prometheus/yuzu-alerts.yml`) fire on `value - time() < window`. |

## SSO login metrics

Every SAML and OIDC login attempt — success or failure — increments its provider's login counter. Both counters carry a uniform `{result, role}` label set on every series (including error paths), so a dashboard can group by either label without hitting an unlabelled/labelled split.

| Metric | Type | Meaning |
|---|---|---|
| `yuzu_auth_saml_login_total{result, role}` | counter | SAML `/saml/acs` outcomes. `result` is `ok` or `error`. `role` is the resolved session role (`admin` / `user`) on `result="ok"`, and `role="none"` on every `result="error"` series (no session was ever created, so there is no role to attribute the failure to). |
| `yuzu_auth_oidc_login_total{result, role}` | counter | OIDC `/auth/callback` outcomes. Same `{result, role}` shape as the SAML counter above — `role="none"` on all error-path increments (IdP-returned error, missing `code`/`state`, and token-exchange/claim-validation failure). |
| `yuzu_saml_group_cap_truncated_total` | counter, no labels | Bumped once per SAML login (not once per dropped group value) when the assertion's `groups` attribute exceeded the 64-value cap and real group values were dropped. A non-zero rate means some SAML-asserted group-based RBAC role mappings may not be taking effect for the affected principal — check the assertion's attribute statement. OIDC has no equivalent counter: OIDC group claims are bounded by JWT/ID-token size rather than a fixed value-count cap, so the two providers hit different limits and are not expected to have parity here. |

## DEX live-read metrics

The synchronous live-read endpoint (`POST /api/v1/dex/devices/{id}/live`) is bounded by a server-wide concurrency cap; these metrics surface its saturation and outcomes.

| Metric | Type | Meaning |
|---|---|---|
| `yuzu_server_live_requests_total{kind, outcome}` | counter | Live-read requests by `kind` (`uptime` / `processes` / `unknown`) and terminal HTTP `outcome` (`200` / `400` / `403` / `429` / `500` / `502` / `503` / `504`). A rising `outcome="429"` rate means the concurrency cap is shedding load. |
| `yuzu_server_live_inflight` | gauge | Current in-flight synchronous live-read polls. Approaching the cap (default 4) indicates saturation; sustained at the cap alongside 429s means the live surface is a bottleneck. |

## Engine-principal revalidation-cache metrics

Every held-open SSE stream re-validates its credential on each ~3 s pump tick. For a stream authenticated by an **engine** principal that check consults `EnginePrincipalStore`, and these metrics show whether it is being served from the short-TTL liveness cache (#2367) or reaching Postgres. The cache exists to keep that per-tick load off the connection pool, where it was previously self-amplifying under a pool brownout.

| Metric | Type | Meaning |
|---|---|---|
| `yuzu_server_engine_revalidate_cache_hits_total` | counter | Liveness re-checks answered from cache — no Postgres read. In steady state hits should dominate misses by roughly `TTL / tick`. |
| `yuzu_server_engine_revalidate_cache_misses_total` | counter | Re-checks that read through to Postgres (cold, expired, or invalidated by a revoke). A rate approaching one per stream per tick means the cache is not doing its job — look for a revoke loop or a clock problem. |
| `yuzu_server_engine_revalidate_cache_size` | gauge | Principals with a live (unexpired) entry. Bounded by construction; sustained residence at the ceiling means engine-principal churn worth investigating. |
| `yuzu_server_engine_revalidate_backoff_suppressed_total` | counter | Re-checks answered `StoreUnreachable` from the failure backoff **without** taking a pool lease. **This is the brownout signal**: it only moves while the store is unreachable, and while it moves the per-tick retry amplifier is being held off. Any movement means the store is unreachable — see the `EngineRevalidateStoreUnreachable` alert and `docs/ops-runbooks/engine-principal-store-recovery.md`. Read it alongside `yuzu_pg_acquire_wait_seconds` and `yuzu_mcp_stream_closes_total{reason="auth_unavailable"}` — streams are riding their grace windows and some will end. |

This cache covers only the ENGINE half of stream re-validation; the API-token half has its own (`yuzu_server_token_cache_*`).

## MCP transport metrics

Request-body rejections at the `/mcp/` ingress (#2437). The label set is
CLOSED and pre-seeded at boot, so `absent()` alerting stays meaningful.

| Metric | Type | Description |
|---|---|---|
| `yuzu_mcp_body_too_large_total{reason}` | counter | `/mcp/v1/` requests rejected at the transport before the body was read (#2437). `reason=over_cap` is a declared `Content-Length` above 4 MiB (`413`); `reason=unmeasurable` is a body this server will not admit because it cannot size it in advance — any `Transfer-Encoding`, any non-`identity` `Content-Encoding` (httplib decompresses before its size check), or a POST/PUT/PATCH with no `Content-Length` (`411`). Pre-auth, so there is no principal and no audit row: the throttled `[#2437]` warn in the journal carries the sanitized method/path/source address. |

## MCP input-bounds metrics

Argument rejections on the MCP surface (#2405, #2437). Label sets are CLOSED
and pre-seeded at boot, so `absent()` alerting stays meaningful.

| Metric | Type | Description |
|---|---|---|
| `yuzu_mcp_tool_args_invalid_total{tool}` | counter | Calls denied by the C8 pre-approval schema gate: arguments did not match the tool's served `inputSchema`, checked before an approval ticket is minted or consumed (#2405). `tool` is bounded to the approval-gated set. |
| `yuzu_mcp_tool_args_too_large_total{tool,reason}` | counter | Calls denied by a handler-side input bound (#2437), on every tier including operator. `reason` is a closed set: `ident_len`, `scope_len`, `scope_type`, `scope_empty`, `param_count`, `param_key_len`, `param_value_len`, `agent_ids_count`, `agent_id_len`, `agent_id_type`, `agent_ids_type`, `agent_ids_empty`, `ident_empty`. The paired audit row is `mcp.<tool>|denied` with detail `input bound exceeded: <reason> correlation_id=<cid>`, carrying the same correlation id as the client's error envelope. |

## Audit-store metrics

The audit store is the SOC 2 evidence chain, so both its write path and its
retention path are scraped. The retention clock guard these describe is
documented in `docs/user-manual/audit-log.md`.

| Metric | Type | Meaning |
|---|---|---|
| `yuzu_server_audit_events_total{result}` | counter | Audit events written, bucketed by `result` (`success` / `failure` / `denied` / `other`). |
| `yuzu_server_audit_emit_failed_total` | counter | Events that failed to persist. Non-zero means audit persistence is failing. Behavioural-PII routes fail closed with `503` when it hits them, but the counter also moves for fire-and-forget background writers (agent enrolment, schedule execution) that return no status to anyone; see the `YuzuAuditPersistFailures` alert. |
| `yuzu_server_audit_clock_anomaly_skips_total` | counter | Retention passes **declined**. Triggers: the pass would have expired every datable row; the gap since the previous pass exceeded a fixed 7 days; or the stored reading was not usable -- *ahead* of the clock, negative, present but not an integer, or unreadable. Reducing `audit_retention_days` also declines a pass by design, because it narrows the survivor horizon. Not proof of tampering -- a backward NTP correction produces the first, and a dead-CMOS boot produces the second. Elapsed time cannot separate a forward jump from an outage that long - read it as "the clock moved, **or** the server was down that long". Nothing was deleted. |
| `yuzu_server_audit_cleanup_failed_total` | counter | Retention passes that did not fully do their job: an unreadable probe, a failed delete, a refused implausible clock, a closed store, or an exception caught at the thread boundary. **One of the seven sites fires after a SUCCESSFUL delete** (the post-delete backlog probe), so this means "retention is not fully healthy", not "nothing was deleted". |
| `yuzu_server_audit_retention_cap_reached_total` | counter | Passes that hit the per-pass delete cap, leaving a backlog. Sustained growth means expiry is outrunning the drain. This is the failure the cap itself introduces; neither counter above moves in that state. |
| `yuzu_server_audit_rows_deleted_total` | counter | Rows deleted by retention. Read alongside the cap counter to tell a draining backlog from a stuck one. |
| `yuzu_server_audit_retention_index_ok` | gauge | `1` while the retention index exists. Evaluated once at startup, so it cannot detect an index dropped at runtime. `0` means every cleanup pass full-scans `audit_events` under the exclusive store lock, and that cost grows with the table - the one condition that makes the pass's lock hold unbounded. Alert on `== 0`. |
| `yuzu_server_audit_retention_persist_failed_total` | counter | Failures to persist the retention clock reading. Sustained non-zero means clock-anomaly detection will not survive a restart. |
| `yuzu_server_audit_retention_passes_total` | counter | Retention passes **attempted**, including declined and failed ones. Alert on this NOT increasing: every other *counter* here is silence-means-healthy, so a cleanup thread that never runs leaves all six flat at 0 (`retention_index_ok` is a startup-evaluated gauge and is the exception) - identical to a quiet, healthy store, while `audit.db` grows without bound. |
| `yuzu_server_audit_retention_last_pass_unixtime` | gauge | Wall-clock reading of the most recent pass; `0` if none has run in this process. Read WITH the counter above: stale here while that RISES means the reaper is alive but refusing an implausible clock -- a different fault from stopped. |

**Alert on absence, not just on rising counters.** Five of these fire on something going
wrong; `..._retention_passes_total` is the only one that catches the reaper not running at
all, which is the state in which none of the other *counter*-driven rules can fire (the
`retention_index_ok` gauge rule is evaluated at startup and is unaffected). The `YuzuAuditRetentionNotRunning`
rule covers it.

The skips and failed counters must be alerted on separately and never collapsed:
both leave rows undeleted, so an audit table that never shrinks looks identical
either way. Only the pair distinguishes "the guard is protecting the table" from
"cleanup is broken".

## MCP progress-bridge metrics

The MCP Streamable-HTTP progress bridge projects live `notifications/progress` onto a
session's `GET` stream when `execute_instruction` is called with a `_meta.progressToken`
(see `docs/user-manual/mcp.md`). It is in-memory and bounded (256 correlation records).

| Metric | Type | Meaning |
|---|---|---|
| `yuzu_mcp_bridge_records_active` | gauge | Correlation records currently live (global cap 256). Approaching the cap means new progress requests will degrade to the plain path. |
| `yuzu_mcp_bridge_reject_total{reason}` | counter | Reservation rejections, by closed-set `reason` (`disabled` / `unknown_session` / `shutdown` / `duplicate_request_id` / `global_cap` / `pin_slots`). A rising `global_cap` rate means the bridge is at capacity. |
| `yuzu_mcp_bridge_degrade_total{reason}` | counter | `execute_instruction` progress requests that silently fell back to the plain (poll) path, by `reason` (`reserve_rejected` - a reservation was rejected, with the finer reason in `reject_total`; `reserve_threw` / `no_execution_row` / `subscribe_failed` / `arm_threw` - an allocation/tracker failure). The plain response is self-sufficient (carries `execution_id`); a non-zero rate is a reliability signal, not an error. |
| `yuzu_mcp_bridge_listener_failures_total` | counter | Bus-listener copy failures contained at the noexcept boundary (the event was not latched). The durable `execution_id` fetch is the backstop. Should be ~0. |
| `yuzu_mcp_bridge_mailbox_drops_total` | counter | Oldest-progress frames dropped from a record's bounded 16-slot arming mailbox (a fast producer outrunning the projector); terminals are never dropped. |
| `yuzu_mcp_bridge_projector_cycles_total` | counter | Projector wake cycles - an event-driven liveness signal. `yuzu_mcp_bridge_records_active > 0` with a flat rate here means the projector thread is wedged. |
| `yuzu_mcp_stream_terminal_publish_failures_total` | counter | Terminal-frame publish failures seen by the bridge's `publish_final → fallback → poison` ladder. Non-zero means a client-visible result could not be delivered on the stream (recoverable by `execution_id`). Alert-worthy. |
| `yuzu_mcp_stream_final_unpinned_total` | counter | Committed terminal frames that found no free pin slot and were published **unpinned** (a real terminal is committed rather than lost to preserve a pin). Not expected: the bridge caps streamed records per session at the pin count, so any non-zero value means that admission accounting was violated and the affected final is evictable from the replay ring - still recoverable by `execution_id`. Alert on `> 0`. |

All reason-label sets are closed (every value is a static literal seeded to 0 at boot),
so `absent()`/`rate()` alerting is meaningful on a healthy server.

## Pre-flight runner metrics

| Metric | Type | Meaning |
|---|---|---|
| `yuzu_preflight_tick_errors_total` | counter | Exceptions caught by the background `PreflightRunner`'s per-tick try/catch (60 s cadence). A rising rate means pre-flight runs are not being re-dispatched/settled — check the server log. |

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

- alert: EngineRevalidateStoreUnreachable
  expr: increase(yuzu_server_engine_revalidate_backoff_suppressed_total[10m]) > 0
  labels:
    severity: warning
  annotations:
    summary: "Engine-principal liveness re-checks are being answered from the failure backoff - the principal store is unreachable and engine streams are riding their grace windows"
    description: "This counter only moves while the store cannot be reached. First rule out real impact: a flat yuzu_mcp_stream_closes_total{reason=\"auth_unavailable\"} means the backoff is absorbing the blip and no streams have ended. Then correlate with yuzu_pg_acquire_wait_seconds and yuzu_pg_pool_in_use for pool exhaustion. Runbook: docs/ops-runbooks/engine-principal-store-recovery.md."

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
| `principal_class` | Actor class on HTTP request counts (closed set, ADR-1005). `human`/`agent`/`none` classify by credential presentation (traffic shape); `engine` classifies the RESOLVED session (a resolved engine-principal request) — see `docs/observability-conventions.md` for the hybrid-basis contract. Never an authorization signal. As of PR 4.5, `agent` no longer includes engine-principal traffic — a panel/alert summing `agent` across the 4.5 deploy boundary shows a step-down that is a reclassification artifact, not a traffic change. | `human`, `agent`, `none`, `engine` |

## On-behalf-of rejection metric (ADR-1005)

```
# HELP yuzu_onbehalf_rejected_total Requests rejected for carrying a reserved on-behalf-of header/metadata key (ADR-1005) by surface
# TYPE yuzu_onbehalf_rejected_total counter
yuzu_onbehalf_rejected_total{surface="http",event="security"} 0
yuzu_onbehalf_rejected_total{surface="grpc",event="security"} 0
```

Both series are pre-seeded to `0` at startup, so `absent()` alerts stay
meaningful. Any non-zero value means a client asserted it was acting on
another principal's behalf via a reserved header (HTTP `403`) or gRPC
metadata key (call cancelled) — see `docs/auth-architecture.md`
("On-behalf-of assertions rejected") for the reserved-name list. This event
deliberately has **no audit row**: the rejection fires pre-authentication, so
there is no resolved principal to attribute — the metric (with
`event="security"`, SIEM-routable per the observability conventions) is the
signal. Alert on `increase(yuzu_onbehalf_rejected_total[1h]) > 0` if you want
notification of any attempt.

## Per-principal quota metric (PR 4.4, ADR-1005 class engine principals)

```
# HELP yuzu_server_principal_quota_exhausted_total Per-principal quota-cap exhaustions by side and limit dimension
# TYPE yuzu_server_principal_quota_exhausted_total counter
yuzu_server_principal_quota_exhausted_total{side="engine",limit="concurrency"} 0
yuzu_server_principal_quota_exhausted_total{side="engine",limit="rate"} 0
yuzu_server_principal_quota_exhausted_total{side="operator",limit="concurrency"} 0
yuzu_server_principal_quota_exhausted_total{side="operator",limit="rate"} 0

# HELP yuzu_server_principal_quota_admits_total Per-principal quota-cap admits (successful try_acquire) by side
# TYPE yuzu_server_principal_quota_admits_total counter
yuzu_server_principal_quota_admits_total{side="engine"} 0
yuzu_server_principal_quota_admits_total{side="operator"} 0
```

All 4 `exhausted_total` series (the closed `side` × `limit` cross-product)
are pre-seeded to `0` at startup, so `absent()` alerts stay meaningful. The
gate applies only to `principal_kind=="engine"` sessions (username
`engine:<slug>`) at the server's single pre-routing chokepoint —
human/agent/anonymous traffic never touches it. `side` distinguishes which
principal's budget was debited (`engine` is the only value emitted in PR
4.4; `operator` is pre-seeded but dormant — it activates in Phase 5 when
delegation debits the delegating operator's side too). `limit` distinguishes
which of the two independent caps rejected the request: `concurrency`
(in-flight requests, tunable via
`--principal-max-concurrency`/`YUZU_PRINCIPAL_MAX_CONCURRENCY`, default 16)
or `rate` (token-bucket requests/second, tunable via
`--principal-rate-limit`/`YUZU_PRINCIPAL_RATE_LIMIT`, default 20.0/s, burst
= 2x rate). Neither label carries `principal_id` — bounded cardinality only.
This is an **operational** counter, not `event="security"` — a quota cap
hit is expected steady-state behaviour for a busy engine principal, not an
attack signal — and it deliberately has **no audit row** for the same
high-frequency-operational reason (see `docs/user-manual/audit-log.md`).

`yuzu_server_principal_quota_admits_total{side}` is the admits companion —
every request that clears **both** the concurrency and rate checks
increments it once. It exists so the exhaustion *rate* is computable rather
than just the raw exhaustion count: `exhausted / (exhausted + admits)`. A
raw exhaustion counter alone can't distinguish "an engine principal is
hitting its cap on a small fraction of a huge request volume" (healthy, cap
doing its job) from "almost everything this engine principal sends is being
rejected" (self-brick, usually right after a config change that set the cap
too low) — the ratio against admits is what tells them apart. Both series
are pre-seeded to `0` at startup for the same reason; `side="engine"` is the
only value emitted today (`side="operator"` is pre-seeded but dormant until
Phase 5, same as the exhaustion counter). **Streaming requests are
included** — a streaming request now takes a concurrency slot (held for the
stream's lifetime) plus the rate debit, same as any other engine request
(UP-1 hardening fix; see the streaming note below) — so a streaming request
is counted here exactly like any other admitted engine request.

**Streaming/SSE note (UP-1).** Streaming/SSE requests are **not** exempt
from either dimension of this cap — they take a concurrency slot held for
the stream's lifetime (released when the stream ends), plus the rate debit,
the same two caps as any other engine request. An earlier revision of this
primitive treated streaming as rate-only and concurrency-exempt, which left
an engine principal able to open an unbounded number of concurrent streams;
that gap is closed.

**Per-instance caveat:** the cap is enforced in one process's memory. A
multi-replica deployment's **effective ceiling is `configured_cap x
replica_count`**, not the configured cap alone — each replica enforces the
cap independently against its own share of traffic, so N replicas give each
engine principal up to N x the configured per-replica cap in aggregate, not
one fleet-wide budget. Durable, cross-instance quota is a Phase-8 follow-up.
When alerting or sizing a cap for a multi-replica deployment, account for
this multiplier — a cap sized for the single-instance default may be far too
generous fleet-wide. Alert on `increase(yuzu_server_principal_quota_exhausted_total{side="engine"}[1h]) > 0`
if you want notification that an engine principal is regularly hitting its
cap (may indicate the cap is tuned too low for its workload, or a runaway
caller).

## Engine-credential confirm metric (#2404)

```
# HELP yuzu_engine_principal_confirm_total Engine-credential rotation confirm outcomes by surface (rest|mcp) and result (success|conflict|client_error|transient); store-reaching calls only, pre-store denials excluded (#2404)
# TYPE yuzu_engine_principal_confirm_total counter
yuzu_engine_principal_confirm_total{surface="rest",result="success"} 0
yuzu_engine_principal_confirm_total{surface="rest",result="conflict"} 0
yuzu_engine_principal_confirm_total{surface="rest",result="client_error"} 0
yuzu_engine_principal_confirm_total{surface="rest",result="transient"} 0
yuzu_engine_principal_confirm_total{surface="mcp",result="success"} 0
yuzu_engine_principal_confirm_total{surface="mcp",result="conflict"} 0
yuzu_engine_principal_confirm_total{surface="mcp",result="client_error"} 0
yuzu_engine_principal_confirm_total{surface="mcp",result="transient"} 0
```

All 8 series (the closed `surface` × `result` cross-product) are pre-seeded to
`0` at startup so `absent()` alerts stay meaningful. The family makes a
credential-**confirm** retry storm alertable, which `yuzu_http_requests_total`
cannot show (it has no per-route label). `result` mirrors the shared
store-error taxonomy (`engine_store_error_class.hpp`): `conflict` is a terminal
409/kInvalidParams (a replay after the rotation already resolved, a moved-on
pin, or unresolved rotation metadata — the client must not blindly retry),
`client_error` is a 400 (more-than-two or non-engine active credentials),
`transient` is a retryable 503 (store unavailable, lock contention, a persist
failure, or the ambiguous empty/malformed-pair "no in-flight rotation"), and
`success` is a completed confirm.

**Scope contract.** Counted only when a confirm reaches `ApiTokenStore::confirm_rotation`
**or** trips the store-open guard (which increments `result="transient"`);
pre-store denials — permission, MFA step-up, input validation, and the MCP
supervised approval-gate's consumed-ticket replay (`approval already used`) —
are deliberately **excluded**, so the label set stays a fact about store
outcomes rather than a catch-all endpoint tally. The increment is stamped
**before** the audit emission, so an audit-store failure cannot suppress it.
Wired on **both** surfaces (the `surface` label prevents double-count) because
either a REST or an agentic MCP client can drive the #2404 replay shape.

**Operational, not `event="security"`.** A replay conflict is an expected
agent-retry pattern, not an attack signal; the counter carries no `principal_id`
label (bounded cardinality only) — pair it with the
`engine_principal.credential.confirm` audit rows for per-principal forensics
(metric-is-the-signal / audit-row-is-the-evidence). A useful alert is
`increase(yuzu_engine_principal_confirm_total{result="conflict"}[15m]) > <n>`
to catch a client stuck replaying a resolved confirm, and
`increase(...{result="transient"}[15m])` for a genuine store-health storm.

**Semantics for alert authors:** this counts confirm **attempts** that reach
the store, not logical rotations — a client retrying a `transient` blip 20 times
before it succeeds adds 20 to `transient` for one rotation. Pick the threshold
`<n>` relative to your fleet's typical retry count, not your rotation cadence.
Also cross-reference `yuzu_engine_principal_rotation_sweep_failures_total`: a
`result="conflict"` cluster correlating with a non-zero, sustained sweep-failure
count is the prolonged-sweep-outage signature (a predecessor's overlap window
never closes, so a confirm surfaces the `unresolved rotation metadata` state) —
**inspect the credential before revoking**, since in that state the sole active
credential is the good survivor.

## Access review metrics

Periodic access reviews (SOC 2 CC6.2, `docs/auth-architecture.md` "Periodic
access reviews") shipped with zero metrics; the hardening round added four
bounded-label series wired at the REST handlers (`rest_api_v1.cpp`) only —
the MCP twins are not double-counted.

```
# HELP yuzu_access_review_export_total Access review evidence exports (GET /api/v1/access-reviews/export), by format
# TYPE yuzu_access_review_export_total counter
yuzu_access_review_export_total{format="json"} 0
yuzu_access_review_export_total{format="csv"} 0

# HELP yuzu_access_review_export_duration_seconds Latency of the cross-principal grant-population read (build_access_review) behind GET /api/v1/access-reviews/export
# TYPE yuzu_access_review_export_duration_seconds histogram

# HELP yuzu_access_review_campaigns_opened_total Access review campaigns opened (POST /api/v1/access-reviews)
# TYPE yuzu_access_review_campaigns_opened_total counter
yuzu_access_review_campaigns_opened_total 0

# HELP yuzu_access_review_attestations_total Access review reviewer decisions recorded (POST /api/v1/access-reviews/{id}/attestations), by decision
# TYPE yuzu_access_review_attestations_total counter
yuzu_access_review_attestations_total{decision="attested"} 0
yuzu_access_review_attestations_total{decision="flagged_revoke"} 0
```

- **`yuzu_access_review_export_total{format}`** — counter, `format` ∈
  {`json`, `csv`}, pre-seeded to `0` at startup. Increments once per
  successful `GET /api/v1/access-reviews/export` call, split by which
  format was requested — a sustained shift toward `csv` typically means an
  auditor/spreadsheet workflow is in play.
- **`yuzu_access_review_export_duration_seconds`** — histogram (default
  bucket ladder, see "Histogram buckets" below), the wall-clock time of the
  cross-principal grant-population read (`build_access_review`) behind the
  export, timed regardless of success/failure outcome — a slow/failing read
  is exactly what an operator debugging a `503` needs latency evidence for.
- **`yuzu_access_review_campaigns_opened_total`** — counter, no labels.
  Increments once per successful `POST /api/v1/access-reviews` — the rate
  this fires at is the empirical "how often does the org actually run a
  review" cadence signal (compare against the org's stated review policy).
- **`yuzu_access_review_attestations_total{decision}`** — counter,
  `decision` ∈ {`attested`, `flagged_revoke`}, pre-seeded to `0` at startup.
  Increments once per successful `POST
  /api/v1/access-reviews/{id}/attestations` call, split by the reviewer's
  decision. `flagged_revoke` counts recorded evidence only — it never
  itself revokes anything (flag ≠ revoke, see `docs/auth-architecture.md`);
  a rising `flagged_revoke` count is a worklist size for whoever acts on
  the flags, not an automatic remediation trigger.

None of the four carries `event="security"` — a review export or an
attestation decision is expected, privileged, self-audited operator
activity (own audit rows: `access_review.exported`, `.campaign_opened`,
`.attested`/`.flagged`), not an anomaly signal. Bounded-label series
(`format`, `decision`) are pre-seeded to `0` at startup per the standing
convention in `docs/observability-conventions.md`, so `absent()`-style
alerts stay meaningful.

## Histogram buckets

Most histogram metrics use the same default bucket boundaries (in seconds); a few carry a custom
ladder called out in their own row (including `yuzu_server_guardian_event_store_duration_seconds`
at 0.1ms-10s and `yuzu_pg_acquire_wait_seconds` into the 10-60s tail). The default:

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

## Fleet performance gauges (DEX)

Published on every fleet-health sweep (~15 s). A metric nobody reported is
**absent**, never zero; values are validated server-side (forged non-finite /
out-of-range readings are rejected).

| Metric | Type | Description |
|---|---|---|
| `yuzu_fleet_perf_reporting` | gauge | Devices contributing at least one perf metric this sweep (the same any-of-three definition the `/dex` Performance tab's Reporting card uses) |
| `yuzu_fleet_perf_cpu_pct{stat}` | gauge | Fleet CPU busy %, `stat` = `avg` / `p50` / `p90` / `max` |
| `yuzu_fleet_perf_commit_pct{stat}` | gauge | Fleet memory commit % of limit, same `stat` labels |
| `yuzu_fleet_perf_disk_lat_ms{stat}` | gauge | Fleet per-IO disk service time (ms), same `stat` labels |

**Per-cohort export (opt-in)** — published only when a cohort export tag key
is configured (Settings → DEX alerts; `runtime_config` key
`dex_cohort_export_key`):

| Metric | Type | Description |
|---|---|---|
| `yuzu_fleet_perf_cohort_cpu_pct{cohort,stat}` | gauge | Per-cohort CPU busy % |
| `yuzu_fleet_perf_cohort_commit_pct{cohort,stat}` | gauge | Per-cohort memory commit % |
| `yuzu_fleet_perf_cohort_disk_lat_ms{cohort,stat}` | gauge | Per-cohort disk latency (ms) |
| `yuzu_fleet_perf_cohort_reporting{cohort}` | gauge | Reporting devices per exported cohort |
| `yuzu_fleet_perf_cohort_clipped` | gauge | Exportable cohorts dropped by the top-50 cardinality cap (a measured 0 when nothing was cut; **absent when the export is off** — use this gauge, not `absent()` on the cohort families, as the export-liveness probe) |

Cohorts under 10 reporting devices and cohorts beyond the top-50-by-population
cap never export; devices without the key export as `cohort="(untagged)"`.
Families clear on every sweep — series go absent, never stale. Alerting
recipe: `max_over_time(yuzu_fleet_perf_cohort_clipped[1m])` for liveness,
`yuzu_fleet_perf_cohort_clipped > 0 for 5m` for cap pressure; with the ~15 s
sweep cadence, scrape at ≤10 s intervals when the export is enabled. See the
label-exposure note under Security considerations before choosing a key.

## Fleet network gauges

Published on every fleet-health sweep (~15 s), fed from the `yuzu.net_*`
heartbeat tags (device-aggregate facts only — no per-destination data). A metric
nobody reported is **absent**, never zero. **Linux, Windows, and macOS agents
emit network facts** — macOS throughput only (retransmit + RTT deferred; see
[Network Quality](network.md) → Platform coverage). Windows reports throughput and an interval
retransmit rate but not RTT (per-connection RTT needs ESTATS — a later slice), so
`yuzu_fleet_net_rtt_ms` stays Linux-only for now (see
[Network Quality](network.md) → Platform coverage). The same numbers feed the
`/network` Overview cards, via the shared validators, so the gauges and the page
cannot disagree.

**Caveat — RTT is coarse.** `yuzu_fleet_net_rtt_ms` is a device-aggregate median
across whatever TCP connections are open (loopback / LAN / internet blended), so
treat it as a rough signal, not per-flow truth; actionable per-destination /
per-app latency is a later warehouse-tier slice.

**The `yuzu_fleet_net_*` series carry an `os` label** (`windows` / `linux` / …,
matching `yuzu_fleet_agents_by_os`) so reporting, RTT, and throughput are split
per OS, never blended — query and alert per OS (`sum(...)` a count for a fleet
total). **The retransmit rate is the exception:** the Windows rate is *system-wide*,
biased low, and not yet loss-validated (#1465), so it is **withheld from the gauge
entirely** (it still shows on the `/network` page + REST, caveated) —
`yuzu_fleet_net_retrans_pct` carries **only loss-validated OSes (Linux today)**.

| Metric | Type | Description |
|---|---|---|
| `yuzu_fleet_net_reporting{os}` | gauge | Devices **of that OS** whose latest heartbeat carried at least one network fact (the same any-of definition the `/network` Overview Reporting card uses) |
| `yuzu_fleet_net_retrans_reporting{os}` | gauge | Devices **of that OS** that contributed an interval retransmit **rate to the gauge** this cycle — a subset of `_reporting{os}` (a device can report RTT while its retransmit window is still warming). Denominator for `_retrans_pct{stat,os}`. Only loss-validated OSes appear (Linux today); a Windows device reports a retransmit fact but it is withheld from the gauge, so Windows is absent here |
| `yuzu_fleet_net_degraded{os}` | gauge | **Dormant (measurement-first).** Agents no longer emit the `net_degraded` fact — the old absolute-ratio threshold was empirically disproven, and a calibrated threshold needs real-fleet baseline data (a later slice). **Absent** unless some agent of that OS still emits the tag (e.g. mid rolling-upgrade) — treat absent as "not classified", never 0 as "healthy". Revived when the degraded classification lands |
| `yuzu_fleet_net_rtt_ms{stat,os}` | gauge | Fleet smoothed RTT in ms, `stat` = `avg` / `p50` / `p90` / `max`. RTT is reported by Linux only today, so `os="linux"` is the only series present |
| `yuzu_fleet_net_retrans_pct{stat,os}` | gauge | Fleet TCP **interval** retransmit rate %, `stat` + `os` labels. Per device this is ΔΣretransmits / ΔΣsegments smoothed over the last few heartbeats (recent-window loss), **not** the lifetime ratio. **Loss-validated OSes only:** Linux is a per-connection-sum rate (netem-validated). The Windows rate is **system-wide** (loopback-inclusive, biased low, not yet validated — see network.md and #1465) and is **withheld from this gauge** (it shows on the `/network` page + REST, caveated) until validated — so today `os="linux"` is the only series. When Windows is validated it joins as its own `os` series; never alert on a cross-OS aggregate |
| `yuzu_fleet_net_throughput_bps{stat,os}` | gauge | Fleet device network throughput in bytes/s (rx+tx, non-loopback), `stat` + `os` labels |

Network sampling shares the `--dex-disable` agent flag; disabling DEX also
disables the network heartbeat tags. **All six `yuzu_fleet_net_*` families are
cleared on every sweep and re-emitted per reporting OS** — a `(metric, os)`
nobody reported is absent, never stale or a fabricated 0 (`_degraded{os}` only
appears if an agent of that OS still emits the retired tag).

## SparkEngine fleet gauges

Published on every fleet-health sweep (~15 s), fed from the `yuzu.spark_*`
heartbeat tags. SparkEngine (ADR-0021 Stage-2) is the next-generation event-driven
detection engine; at **rung 1 it runs observe-only** (no consumer arms rules), so
every mechanism- and consumer-health counter below is **0** in production today —
`_reporting`, `_disabled`, `_failed` and `_mechanisms` are the four that carry live
signal, and none of them depends on a consumer being armed; the rest go live when
rung 2 arms real rules. A `(metric, os[, mechanism])` nobody reported is **absent**,
never a fabricated 0 (all eleven families are cleared and re-emitted every sweep, the
same idiom as `yuzu_fleet_net_*`). An agent started with `--spark-disable` reports
`spark_running=0` + `spark_disabled=1`: it is absent from `_reporting` and counted in
`_disabled`. An agent whose engine was enabled but **threw at boot** reports
`spark_running=0` with no `spark_disabled` key, and is counted in `_failed` — that
split is what makes a fleet-wide spark boot failure visible at all.

**All series carry an `os` label** — `file` and `registry` mechanisms are
Windows-only, `service` is Windows + Linux, macOS has none — so **query and alert
per OS, never `sum without(os)`** (a cross-OS aggregate is meaningless for a
single-platform mechanism). The four mechanism counters additionally carry a
`mechanism` label (`file` / `registry` / `service`). The mechanism counters are
fleet **sums of monotonic per-agent counters**, so a bare `> 0` alert **latches**
until the reporting agent restarts — the shipped **counter** alert templates
(disabled until rung 2) use `increase(...[15m]) > 0` instead. One rule ships
**active** today: `YuzuSparkBootFailed` on `_failed` (a per-sweep state gauge,
latch-free) — warning severity, 30m hold (see `docs/prometheus/yuzu-alerts.yml`,
group `yuzu-fleet-spark-rung1`).

**Staged-rollout example:** these series only exist for agents that have been
upgraded to a spark-capable (rung-1+) build. During a phased agent rollout of a
2,000-endpoint Linux fleet with 500 agents upgraded,
`yuzu_fleet_spark_reporting{os="linux"}` reads **500, not 2,000** — the other
1,500 agents are ABSENT (pre-rung-1), which is expected and is not a failure.
`_reporting` approaches the enrolled count as the rollout completes; only
`_failed` indicates something wrong.

| Metric | Type | Description |
|---|---|---|
| `yuzu_fleet_spark_reporting{os}` | gauge | Agents **of that OS** whose latest heartbeat reported the engine running (`spark_running=1`) — the denominator for the engine-level counters |
| `yuzu_fleet_spark_disabled{os}` | gauge | Agents **of that OS** running with the engine deliberately off (`--spark-disable`). An operator decision — expected to be non-zero in some fleets. **Do not alert on it** |
| `yuzu_fleet_spark_failed{os}` | gauge | Agents **of that OS** where the engine was ENABLED but boot-time instantiation **threw**, so the agent degraded to no-spark. Distinct from `_disabled` on purpose: this is a fault, not a choice — **alert on it** (the shipped `YuzuSparkBootFailed` rule does, warning severity). Without this series a fleet-wide spark boot failure would be invisible (a failed agent would look exactly like one that was never asked to run it) |
| `yuzu_fleet_spark_mechanisms{os,mechanism}` | gauge | Agents **of that OS** whose spark capability includes that mechanism (from the `spark_mechs` CSV). Counts only mechanisms that are registered **and functional**: one that started but could not bind its OS facility — most commonly a **containerised Linux host, which has no systemd system bus** — is reported inert and **excluded**, because every watch on it would be refused. An OS with agents in `_reporting` but no `{mechanism}` series either does not support it (e.g. no `file` on `linux`) or cannot use it there |
| `yuzu_fleet_spark_armed_faulted{os}` | gauge | Fleet sum of armed watches a mechanism reported deaf. A **live** gauge (recovers when the watch recovers), not cumulative — `> 0` means detection is silently down for that many watches. 0 at rung 1 (nothing armed) |
| `yuzu_fleet_spark_watch_rejected{os,mechanism}` | gauge | Fleet sum of cumulative watch-cap rejections (a rule that could not arm — denial-of-detection). 0 at rung 1 |
| `yuzu_fleet_spark_quarantined{os,mechanism}` | gauge | Fleet sum of cumulative mechanism quarantines — a structural leak that should stay 0. 0 at rung 1 |
| `yuzu_fleet_spark_slow_op{os,mechanism}` | gauge | Fleet sum of cumulative slow watch/unwatch ops (a stalled/contended watcher). 0 at rung 1 |
| `yuzu_fleet_spark_watch_faults{os}` | gauge | Fleet sum of cumulative post-arm watch-fault edges (`watch_faults_total`). 0 at rung 1 |
| `yuzu_fleet_spark_queued_dropped{os}` | gauge | Fleet sum of cumulative queued events dropped (bounded-queue overflow + shutdown). On the enforce lane (rung 3) a drop is a silent compliance failure. 0 at rung 1 |
| `yuzu_fleet_spark_consumer_errors{os}` | gauge | Fleet sum of cumulative queued handlers that threw (`consumer_errors_total`). 0 at rung 1 |

See [Guaranteed State → SparkEngine](guaranteed-state.md#sparkengine--the-next-generation-detection-engine-observe-only)
for the observe-only migration, the `--spark-disable` flag, and the per-rung
enforcement-posture table.

## Guardian metrics

| Metric | Type | Description |
|---|---|---|
| `yuzu_server_guardian_baselines_total` | gauge | Number of persisted Guardian Baselines. Refreshed on every `/metrics` scrape. |
| `yuzu_server_guardian_events_total` | gauge | Guardian events currently persisted in the store (post-reap). |
| `yuzu_server_guardian_events_written_total` | counter | Cumulative Guardian events ever written (pre-reap). Exposed as TYPE `counter` via `describe()`; the value is read from the store each scrape and set through the gauge API (the `Counter` type has no `set()`), and resets to the store's current total on restart. |
| `yuzu_server_guardian_events_dropped_total` | counter | Cumulative Guardian events dropped at ingest on an `event_id` PK/UNIQUE conflict where the incoming payload **MISMATCHES** the stored row — a forged-id pre-claim (#1360), or an agent `event_seq_` reset / clock skew carrying a *different* event. Benign idempotent redeliveries (matching payload) are **not** counted here; they are on `yuzu_server_guardian_events_redelivered_total`. `> 0` therefore distinguishes "no drift observed" from "drift silently discarded" **and** flags a possible forged-id campaign — a CC7.3 evidence signal; investigate a sustained climb, don't just widen the threshold. Exposed as TYPE `counter`, but **resets on server restart** (in-memory atomic), so alert on `increase(...[1h])` over a window. The bundled `YuzuGuardianEventsDropped` alert fires at **> 5 / 1h**: because reconnect churn no longer lands here, this is a low, security-relevant threshold, not a reconnect-baseline knob (see `docs/prometheus/yuzu-alerts.yml`). |
| `yuzu_server_guardian_events_redelivered_total` | counter | Cumulative **idempotent redeliveries** at ingest — an `event_id` PK conflict where the incoming payload **matches** the stored row across every immutable agent-supplied field. This is the durable agent lifecycle journal's expected crash-durable, duplicate-tolerant, bounded-retry redelivery (it re-sends on every reconnect) - not a guarantee of eventual delivery: an un-acked record that ages out of the 7-day retention window is a rare, counted loss, not silent - counted by `yuzu.guardian_journal_evicted_no_send_evidence`, an agent heartbeat `status_tag` (not itself a Prometheus series scraped here). That counter is in-memory only and resets on agent restart, so it is not a durable audit trail, and today there is no dashboard, REST, or MCP surface exposing it at all, per-agent or fleet-wide (tracked under #2298; see [Reconnect replay traffic](guaranteed-state.md#reconnect-replay-traffic-durable-lifecycle-journal) for the full network-flows picture). The event is not re-written, the DEX observers are not re-fired, and the compliance signal is untouched. **High is normal after an agent outage/reconnect — it is NOT a loss signal** (that is `..._events_dropped_total`). Exposed as TYPE `counter`; resets on server restart. |
| `yuzu_server_guardian_events_ingest_errors_total` | counter | Cumulative **operational** Guardian ingest faults — a failed `BEGIN`/`prepare`/`INSERT`/`COMMIT`, or a redelivery-compare `SELECT` that could not run (NOMEM/IOERR). A sustained rate means the ingest machinery is broken and event_id conflicts are going **unclassified**, so a genuine forged-id collision can escape `..._events_dropped_total` — hence the bundled `YuzuGuardianIngestErrors` alert (`increase(...[15m]) > 0`). Excludes malformed embedded-NUL input (rejected at the boundary; attacker-drivable, so kept off this operational signal). Resets on server restart. |
| `yuzu_server_guardian_events_reaped_total` | counter | Cumulative Guardian event rows deleted by the retention reaper (disposal evidence). Exposed as TYPE `counter` (store-read value set via the gauge API, like the other `_total` counters here). |
| `yuzu_server_guardian_event_store_duration_seconds{status}` | histogram | Server-side latency of `insert_event_classified` (the classify+store SQLite operation) for one Guardian event, split by outcome `status` (`inserted`/`redelivered`/`conflict`/`error`). Only `redelivered`/`conflict` execute the redelivery byte-compare; `inserted` does projection+commit - so read the series per-status, not as an aggregate. Covers the direct-Subscribe and gateway-proxied ingest paths. Custom buckets `0.1ms-10s` (sub-ms SQLite resolution + the seconds tail for Postgres / lock contention). Born at server start (all four status series present on `/metrics` from boot). This is a **validation** signal for the planned off-write-path compare (#2298) - it confirms a benchmarked gain survives real traffic; it is **not** the go/no-go decision, which needs a controlled concurrent benchmark (an aggregate histogram can't attribute latency to compare-CPU vs lock-wait vs transaction work). |
| `yuzu_fleet_agents_dex_observer_disarmed` | gauge | Windows agents (DEX enabled) whose DEX signal observer is not currently healthy — it failed to arm at startup, or a channel subscription died at runtime (EventLog restart / channel ACL change). `> 0` means reliability telemetry is off or degraded on that many endpoints. Agents off Windows or started with `--dex-disable` are excluded, so this is a genuine fault count. Rolled up from agent heartbeats. Note: it does **not** detect a host where the underlying reporter is disabled (e.g. Windows Error Reporting off → no Event 1000, observer still armed). |
| `yuzu_fleet_dex_observed_total` | gauge | Fleet-wide sum of DEX signals observed (all obs_types) since each agent started. **A gauge, not a monotonic counter** — it resets when an agent restarts, so do not apply `rate()`/`increase()`; per-signal detail lives in the Guardian events store (`GET /api/v1/guaranteed-state/events?rule_id=__observation__`) and the `/dex` dashboard. |
| `yuzu_server_guardian_proj_failures_total` | counter | DEX observation projection failures. The source event is always preserved (degrade-don't-destroy); only the derived read-model row is lost. `> 0` means `/dex` is under-counting — investigate (commonly a stale-schema dev DB). |
| `yuzu_server_guardian_observations_reaped_total` | counter | Cumulative DEX observation rows deleted by the retention reaper (disposal evidence for the behavioral-PII projection). Exposed as TYPE `counter` (store-read value set via the gauge API, like `events_written_total`). |

Broader Guardian metrics — rule push counts, agent apply latency, parse errors, and a fleet compliance-state distribution (compliant/drifted/error/unknown) — are on the roadmap alongside agent-side enforcement metrics.

### Guardian journal fleet gauges

Published on every fleet-health sweep (~15 s), fed from the
`yuzu.guardian_journal_*` heartbeat tags. These roll the **durable lifecycle-audit
journal**'s per-agent integrity counters up fleet-wide, so a lost Guardian lifecycle
record is visible on `/metrics` (and to any evidence automation that scrapes it)
instead of only in
one endpoint's heartbeat.

**All series are unlabelled.** Unlike `yuzu_fleet_net_*` / `yuzu_fleet_spark_*`, there
is no `os` or `stat` split: these are integrity and loss signals, where the fleet
question is *"did any endpoint lose a lifecycle record"* - a flat sum answers that and
a percentile obscures it. One consequence worth having: no agent-controlled label
means no cardinality exposure at all.

**What absence means, mechanically.** For the **counter families**, the agent emits a
journal tag **only when the counter is non-zero**, and every family is cleared and
re-published each sweep. So an absent family means: *no retained agent's latest
heartbeat carried a value for it that passed the forged-value parse.* (The three
`_seconds_max` age gauges at the end of the table have their own emission posture -
see their rows; the cleared-and-republished-per-sweep rule applies to them too.) Both edges matter and both are pinned by tests - a
non-conforming agent's explicit `"0"` parses and **publishes** the family at `0`, while
a rejected non-zero value (over the plausibility ceiling, say) leaves it **absent** and
increments `_tag_rejected`. What the rollup avoids is publishing a fabricated `0` for a
family nobody reported, which would read as "checked, nothing lost" when nothing was
checked.

This page deliberately stops there. It tells you what each gauge counts and when it is
emitted, not what a reading proves about fleet health - the interpretation belongs with
whoever enables alerting at the `prefer_spark` cutover, against a live journal.

**The counter rows are `gauge`-typed fleet sums, and they are monitor-only.** No
churn-robust *new-increment* alert exists over an unlabelled fleet sum of per-agent
cumulative counters: the sum cannot tell a new increment from a returning agent. The
full analysis - why `increase()`/`rate()`, `delta()` and bare `> 0` each fail, what the
rising-edge template does and does not buy, and the enable-time prerequisites - is
stated once, in the `yuzu-guardian-journal` preamble in `docs/prometheus/yuzu-alerts.yml`,
alongside the disabled templates themselves. Graph these, review them after an incident,
do not page on them. **The three `_seconds_max` age rows are structurally different**:
a fleet MAX of live ages with a meaningful absolute threshold, where a plain `> X for: Y`
IS sound (see the commented staleness examples in the same alerts file) - do not apply
the counter family's monitor-only reasoning to them wholesale, and equally do not apply
an "any journal series > 0" panel to the family, since ~30 s is a *healthy* staleness
reading.

**Two meta-signals are the exception.** `yuzu_fleet_guardian_journal_reporting` and
`..._tag_rejected` are server-owned counts published on **every completed sweep,
including at `0`**, unlike the 30. Two consequences, and the second is easy to miss:

- `_reporting == 0` while `yuzu_fleet_agents_healthy > 0` narrows the pipeline-dark
  question - but only once Guardian is actually deployed, since the sparse writer means
  `0` also covers "nothing has been journalled anywhere since restart".
- Because they are never cleared, the registry retains their last value indefinitely, so
  **neither their absence nor a `0` detects a stalled sweep** - a stall freezes the
  previous sample in place. Use `yuzu_server_reaper_sweep_duration_seconds` for sweep
  liveness.

**Two caveats that apply however you consume these.** An agent ageing out of the 90 s
staleness window drops its counters from the fleet sum without the underlying loss having
healed. After a server restart the series rebuild as agents heartbeat back in, which takes
longer than one sweep (the sweep is 15 s; the agent heartbeat interval defaults to 30 s). Treat the metric
as a signal and the audit trail as the evidence.

**Known limitations - read before citing these as assurance.** The signal is
*self-reported by the endpoint whose audit trail is in question*. Fabrication is
possible (a forged plausible value from an enrolled agent sets the gauge) and so is
suppression (an agent that simply stops emitting is indistinguishable from a healthy
quiet one). The series are unlabelled, so a raised value cannot name the affected
endpoints, and no operator surface exposes per-agent `yuzu.guardian_journal_*` tags
today - building one is a prerequisite for enabling any alert here. Treat this as a
best-effort compensating indicator, not independent evidence of audit-trail
completeness.

**Timing after cutover.** The journal keeps 7 days of batches, so the eviction counters
(`_evicted_*`) are structurally silent for roughly the first week after `prefer_spark`
flips - absence in that window is guaranteed rather than evidentiary. After it, a mass
reboot or OTA can produce a large step in `_evicted_no_send_evidence` about a retention
window later that is population churn, not a new incident.

> **Selector caveat.** Three counters in this family break the `yuzu_fleet_guardian_journal_*`
> naming pattern - `yuzu_fleet_guardian_send_exceptions`, `yuzu_fleet_guardian_drain_exceptions`,
> and `yuzu_fleet_guardian_sweep_exceptions` (their wire tags likewise drop the `_journal_`
> infix, sitting beside `drain_exceptions`). A PromQL selector like
> `{__name__=~"^yuzu_fleet_guardian_journal_"}` silently omits all three. Match
> `^yuzu_fleet_guardian_` if you mean the whole family - and note that EITHER selector
> now also sweeps in the three `_seconds_max` age gauges, which are MAX-rolled live ages
> (not sums of counters): exclude `_seconds_max$` from any panel or rule that assumes
> "non-zero means something was lost".

| Metric | Type | Description |
|---|---|---|
| `yuzu_fleet_guardian_journal_stage_dropped` | gauge | Fleet sum of records dropped at staging - the pending reserve overflowed. A **loss** channel - these records never reached the journal. THREE causes, and they need different responses: sustained write failure (see `_write_failures`); capacity refusal (see `_write_capacity_rejected`); and, since #2299, simply out-running the heartbeat's per-tick persist bounds - up to 4 batches / 1024 records per tick, which in the byte-split regime is the lower figure by far. On that third path `_write_failures` and `_write_capacity_rejected` are both **zero** and nothing is broken; compare `_batches_written`'s rate against the per-tick ceiling before concluding the alert is faulty. Monitor-only |
| `yuzu_fleet_guardian_journal_stage_failures` | gauge | Fleet sum of disarm records that could not be built post-teardown. A **loss** channel: the lifecycle end of a rule is unrecorded |
| `yuzu_fleet_guardian_journal_field_rejected` | gauge | Fleet sum of records kept out by a field failing validation (embedded NUL, oversized, non-UTF-8). A **loss** channel and a malformed-input signal |
| `yuzu_fleet_guardian_journal_clock_rejected` | gauge | Fleet sum of records kept out by a skewed clock (timestamp ≤ 0). A **loss** channel, and the fleet's clock-health canary - a journal timestamp that cannot be trusted is not admissible evidence |
| `yuzu_fleet_guardian_journal_pending` | gauge | Fleet sum of records staged but **not yet persisted**. A **live depth** gauge *per agent* - it drains as the backlog clears - but what is published is the fleet **sum**, which at 10k agents is non-zero essentially always, so `> 0` fires permanently on a healthy fleet and is **not** a valid alert. Monitor-only, like the rest of the family. Sustained depth is the leading indicator of the `_stage_dropped` loss that follows when the reserve overflows |
| `yuzu_fleet_guardian_journal_batches_written` | gauge | Fleet sum of batches successfully persisted. A cumulative process-lifetime count: non-zero means that agent's journal has persisted at least one batch since it last restarted. It resets to 0 on agent restart, and a journal whose every write fails never sets it, so do not read it as liveness. Unit is **batches** of up to 256 records |
| `yuzu_fleet_guardian_journal_write_failures` | gauge | Fleet sum of failed batch writes. Records stay staged and retry, so this is not itself loss - sustained failure fills the pending reserve, after which staging overflow increments `_stage_dropped`. It leads `_stage_dropped` **on that path only**: `_field_rejected` and `_clock_rejected` move without it, and the capacity-refusal path can reach `_stage_dropped` without a single write failure |
| `yuzu_fleet_guardian_journal_key_collisions` | gauge | Fleet sum of batch key collisions. Should stay 0; any value is an accounting or id-generation bug surfacing - investigate, do not threshold |
| `yuzu_fleet_guardian_journal_quarantined` | gauge | Fleet sum of batches moved aside as unreadable/corrupt. Degrade-don't-destroy: the batch is preserved for forensics but its records are **not** replayed, so `> 0` means the server is missing lifecycle evidence that still exists on the endpoint. Unit is **batches** of up to 256 records |
| `yuzu_fleet_guardian_journal_quarantine_failures` | gauge | Fleet sum of quarantine attempts that themselves failed - strictly worse than `_quarantined`: the corrupt batch could not even be set aside, so it may be re-hit every maintenance tick |
| `yuzu_fleet_guardian_journal_quarantine_capacity_evicted` | gauge | Fleet sum of quarantined batches shed at the quarantine cap. **Terminal loss** - forensic evidence that had been preserved is now gone. Unit is **batches** of up to 256 records |
| `yuzu_fleet_guardian_journal_pruned` | gauge | Fleet sum of batches deleted by retention (routine disposal evidence). Expected non-zero on a working fleet; read it as **activity context** for the failure counters beside it, not as a denominator and not as an alert. Unit is **batches** of up to 256 records |
| `yuzu_fleet_guardian_journal_prune_failures` | gauge | Fleet sum of retention prune failures. Retention not running means the journal grows toward its byte/count cap, where new writes start being refused - see `_write_capacity_rejected` |
| `yuzu_fleet_guardian_journal_write_capacity_rejected` | gauge | Fleet sum of new batches **refused** because the journal is at its byte/count cap. **Not itself loss**: the refused batch stays staged and the maintenance tick retries it once a later prune frees capacity. Records are lost only if staging then overflows - see `_stage_dropped`. Unit is **batches** of up to 256 records |
| `yuzu_fleet_guardian_journal_gauge_underflow` | gauge | Fleet sum of times an agent's write-ceiling check read the journal size gauge as **negative** (UP-2 / #2303). Correct operation never underflows, so **any non-zero is a real size-accounting bug** on that endpoint: persist then fails **closed** (defers to RAM staging) until a prune rebase restores the gauge. Matters because `_batch_count` **clamps a negative to 0** - the endpoint reads as a healthy empty journal while refusing writes, so this is the only signal that de-camouflages that state |
| `yuzu_fleet_guardian_journal_bytes` | gauge | Fleet sum of live on-disk journal size in bytes. A **live** gauge. Capacity signal - a value climbing toward (agents × per-endpoint cap) predicts `_write_capacity_rejected` |
| `yuzu_fleet_guardian_journal_batch_count` | gauge | Fleet sum of live batch count. A **live** gauge - the count-cap twin of `_bytes`; either ceiling alone can start refusing writes |
| `yuzu_fleet_guardian_journal_pages` | gauge | Fleet sum of replay paging passes. Activity, not health - the denominator that tells you replay is running at all |
| `yuzu_fleet_guardian_journal_records_paged` | gauge | Fleet sum of journalled records newly enqueued into the replay window. Activity signal for how much backlog is being re-delivered |
| `yuzu_fleet_guardian_journal_sent_labels` | gauge | Fleet sum of sent-labels written, in **batches** (best-effort delivery evidence). **Not** a valid denominator for the eviction counters despite the matching unit: labels are counted in the current agent process, while evictions cover batches written up to 7 days earlier across a churning fleet, so after a restart the numerator can exceed it. Read as activity, never as a rate base |
| `yuzu_fleet_guardian_journal_evicted_sent_unacked` | gauge | Fleet sum of **batches** aged out of the journal **with** a sent-label but no ack (each batch holds up to 256 records). **Monitor, do not page**: their records were sent and are very likely stored server-side; only the ack did not come back. Read against its no-evidence sibling |
| `yuzu_fleet_guardian_journal_evicted_no_send_evidence` | gauge | Fleet sum of **batches** aged out with **no** sent-label - no evidence their records were ever transmitted (each batch holds up to 256 records, so this understates the record count). This is the **integrity-gap** counter: `> 0` suggests lifecycle audit records were lost between endpoint and server. A CC7.3-relevant evidence signal. Treat a rise as a **ticket to investigate**, not an incident-register entry: classification is **best-effort** (a crash between the send and the sent-label write counts a sent batch as no-evidence), so a mass reboot or OTA manufactures a large benign step about a retention window later. Do not escalate until agent-side corroboration or magnitude analysis rules out that artifact class. Monitor-only. Since #2299 also cross-check `yuzu_fleet_guardian_journal_quarantined`: corrupt-VALUE quarantine moved to the replay pass, so a corrupt batch the rotation never reaches before it ages out is counted here instead - both are lost evidence, but this no longer separates "never delivered" from "never deliverable". |
| `yuzu_fleet_guardian_journal_evicted_unclassified` | gauge | Fleet sum of **batches** aged out whose sent/unsent disposition was **permanently unknown** - the third, mutually-exclusive eviction outcome. It exists for accounting exactness: `pruned == evicted_sent_unacked + evicted_no_send_evidence + evicted_unclassified` every pass, which is what lets `_evicted_no_send_evidence` be read as a trustworthy **floor** on lost evidence rather than a value a mid-pass shutdown could silently shrink. **Neither loss nor success.** Three causes: a stop landing **before classification begins** (right after the delete, before the sent-label scan) counts the whole evict set here - at most **once** per process lifetime, since the stop latches (since #2470 a stop landing DURING scan-OK classification no longer counts here: the determinable remainder is classified from the already-materialized scan; only a stop mid-**fallback** loop, where the scan already failed, still truncates its remainder to unknown); an **unreadable** sent-label on the scan-failure fallback (paired with a same-pass `_prune_failures` increment - a repeated climber, unlike the single shutdown bump); and a mid-classification `bad_alloc`, whose remainder lands here while the throw itself is counted as `_maint_exceptions`. Monitor-only. Unit is **batches** of up to 256 records |
| `yuzu_fleet_guardian_journal_maint_exceptions` | gauge | Fleet sum of exceptions swallowed by the journal maintenance tick (page/flush). Swallowed so maintenance cannot kill the agent - which is exactly why they must be visible here: a climbing value means maintenance is failing silently and the counters beside it are **understating** reality |
| `yuzu_fleet_guardian_journal_backpressure_drops` | gauge | Fleet sum of lifecycle-audit entries **rejected** at outbox enqueue for capacity. A **loss** channel: arm/disarm still succeeds, but the audit record of it is dropped. A non-zero value means the audit trail is missing lifecycle edges under sustained delivery backpressure |
| `yuzu_fleet_guardian_send_exceptions` | gauge | Fleet sum of per-entry drain **sends** that threw. Finer-grained than `_drain_exceptions`: one entry couldn't be serialized/sent, so that log's drain stops and jams delivery behind it. Spans the lifecycle log and the general outbox. **Wire key `yuzu.guardian_send_exceptions` (no `_journal_` infix)** |
| `yuzu_fleet_guardian_drain_exceptions` | gauge | Fleet sum of firewalled throws in the outbox **delivery** machinery on the drain worker. Distinct from the journal counters: events are buffered but not shipping - a delivery fault, not a retention or audit-trail fault. **Wire key `yuzu.guardian_drain_exceptions` (no `_journal_` infix)** |
| `yuzu_fleet_guardian_sweep_exceptions` | gauge | Fleet sum of firewalled throws in the convergence **sweep** lanes. Drift detection is degraded (the endpoint may miss policy violations) while the audit trail itself is unaffected. **Wire key `yuzu.guardian_sweep_exceptions` (no `_journal_` infix)** |
| `yuzu_fleet_guardian_journal_page_stale_seconds_max` | gauge | Fleet **MAX** (worst endpoint, `_max` suffix - not a sum like the rest of the family; two 30 s-stale agents are not one 60 s-stale agent) of seconds since the drain worker's last **replay-progressing or verified-idle** page pass, seeded from worker start. A **replay-progress** gauge (#2452): the drain worker advances it only on a pass that placed records OR ran a full candidate scan finding a clean, unblocked, uncorrupted, readable idle backlog (one positive `progress_or_verified_idle` signal, mirroring the prune side). So it grows without bound not only on a dead or permanently-throwing worker but on any page pass that cannot make progress - deferred for lack of a paging token, falling back on a failed sent-label scan, hitting a candidate/value read failure, unable to latch its boot-prune barrier (journal scan failing from boot), **blocked because the send window is saturated (headroom)**, or **quarantining every candidate on a mass-corruption endpoint** - so it reads as an ever-growing age whenever replay is genuinely stalled, not only when the loop is dead. A pass that placed records, or that positively established there was nothing to page, reads fresh (real progress is never treated as stale just because one candidate read failed). Unlike the counters, the wire tag is emitted every heartbeat **including `0`** while the worker is live, and is **absent entirely** while dormant (`prefer_spark` off). Expect it to hover around the 30 s page cadence on a healthy fleet |
| `yuzu_fleet_guardian_journal_prune_stale_seconds_max` | gauge | Fleet **MAX** of seconds since the drain worker's last prune pass that **actually ran retention** - applied the delete OR verified nothing was eligible - the prune sibling of `_page_stale_seconds_max`, separate because the cadences differ (120 s vs 30 s) and stall independently. A growing value means retention is not running on some endpoint - the loop is dead/throwing, its journal scan is failing every pass (`_prune_failures` climbing), **its retention DELETE is failing every pass** (disk-full / perms; also `_prune_failures`), a stop keeps aborting it before the delete, it keeps **declining age eviction of expired rows on a clock anomaly**, or it **cannot quarantine a stuck malformed key** (`_quarantine_failures`) - and the journal grows toward its cap, where writes start being refused (`_write_capacity_rejected`). (A forward-clock-jump wipe is the one case that still reads fresh here, since the delete did succeed - the clock guard, not this gauge, owns that.) Expect ~120 s on a healthy fleet. Same emit-including-`0` / absent-while-dormant posture as its page sibling |
| `yuzu_fleet_guardian_journal_headroom_blocked_seconds_max` | gauge | Fleet **MAX** of the age of the oldest current **headroom-blocked replay-congestion episode** (#2364): somewhere a journal batch could not be placed in the send window for lack of room, continuously since the value's start. Episode-scoped and sampled at pass granularity: clears only after a proven block-free sweep of all of that journal's *candidates* (the batches a replay pass currently considers - unexpired, unquarantined journal batches), resets on agent restart, and a forced (boot/reconnect) pass can start an episode from already-delivered batches - read it as **replay-window congestion**, not proof of unsent loss. Its loss-relevant threshold is the 7-day retention window (604 800 s): an episode approaching that means never-sent records on that endpoint are nearing deletion - read with `_evicted_no_send_evidence`. **Caveat**: a clear can *coincide* with the blocked batch's own terminal eviction (an evicted batch stops being a candidate, so coverage completes) - corroborate a clear against `_evicted_no_send_evidence` before reading it as recovery. **Sparse**: absent means no endpoint is blocked |
| `yuzu_fleet_guardian_journal_reporting` | gauge | Agents whose latest heartbeat carried at least one **parseable** journal tag - the coverage denominator the 30 counters lack. **Published every sweep including `0`**, unlike them. Read `0` carefully: the writer is sparse, so this counts agents with a **non-zero** counter, not agents whose journal works - `0` means either the telemetry path is dark **or** nothing has been journalled anywhere since restart (a live journal on a fleet with no deployed Guardian rules reads `0` legitimately). It narrows the overloaded absence of the 30; it does not resolve it. **Counts the 30 counter tags only - an agent reporting only the three `_seconds` age tags does not count here** |
| `yuzu_fleet_guardian_journal_tag_rejected` | gauge | Journal tags **present** on a heartbeat this sweep but rejected by the forged-value parse (non-numeric, negative, over 10 digits, or above the plausibility ceiling). **Published every sweep including `0`**. Without it a rejected value is a silent drop - if the rejecting agent were the only reporter, its family goes absent and absent reads as clean. `> 0` means some agent is shipping malformed journal telemetry |

## NVD CVE sync metrics

The server maintains a local mirror of the NVD (National Vulnerability Database)
CVE catalog (see [NVD CVE sync](server-admin.md#nvd-cve-sync) for the sync flags).
These metrics surface the catalog's size, backfill progress, and sync-window
health. The gauges are refreshed on every `/metrics` scrape.

| Metric | Type | Description |
|---|---|---|
| `yuzu_nvd_total_cves` | gauge | Distinct CVEs in the local NVD catalog. Grows as the newest-first backfill walks history, then holds steady with periodic freshness re-checks. |
| `yuzu_nvd_backfill_complete` | gauge | `1` when the newest-first NVD backfill has reached its floor (`--nvd-backfill-years`), else `0`. `0` for an extended period on a fresh server without an API key is expected — the backfill is rate-limited (see below). |
| `yuzu_nvd_sync_failures_total{reason}` | counter | NVD sync window failures, labelled by `reason` ∈ {`connection`, `http_429`, `http_403`, `http_other`, `parse`}. All five `reason` series are initialised to `0` at startup, so the counter (and its HELP/TYPE) is present on a healthy server — `absent()`-style alerts stay meaningful and Grafana never shows "No data" until the first failure. A shutdown-triggered cancel is deliberately **not** counted. |

**Reading the `reason` label:** `http_429` is rate-limiting (backed off and retried
automatically — expected during a large backfill without an API key, not a fault);
`http_403` is a bad or revoked `--nvd-api-key` (not retried — rotate the key);
`connection` is an egress/network failure to `services.nvd.nist.gov`; `http_other`
is any other non-2xx status; `parse` is a malformed response body. See
[Rate-limit and auth-error handling](server-admin.md#nvd-cve-sync) for operator guidance.

**Alerting.** Only `http_403` is unambiguously operator-actionable, so page on it and
merely record the rest:

```
# Page: bad/revoked API key — sync makes no progress until rotated
increase(yuzu_nvd_sync_failures_total{reason="http_403"}[1h]) > 0
# Do NOT page on http_429 — it is expected rate-limiting, self-heals via backoff.
```

Note that `http_429` **will** climb during a first-run full backfill on a server with no
`--nvd-api-key` (each window that exhausts its retry budget increments it before the next
tick retries) — that is expected first-run behaviour, not a regression. A sustained
`yuzu_nvd_backfill_complete == 0` (see above) is the durable "mirror stuck" signal, not the
failures counter on its own. Under `--no-nvd-sync`/`YUZU_NO_NVD_SYNC`, `yuzu_nvd_backfill_complete`
is **absent** (never emitted), not `0` — an `absent()`-style alert built on this series should
account for the deliberately-disabled case, not just the stuck case.

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

### Guardian durable-journal health (heartbeat `status_tags`)

> **Not yet active in a shipped release.** The Guardian durable journal and the worker that
> maintains it are wired but DORMANT: they run only once the Spark detection path becomes the
> authoritative backend, and that flag is off in every released agent. Until then none of the
> counters below can be anything but absent, and the failure modes described - a wedged journal,
> a dead maintenance worker, a clock anomaly - are not reachable. This section is written for
> the release that turns it on; treat it as reference, not as something to alert on today.

The agent has no Prometheus endpoint, so the Guardian lifecycle journal reports through
heartbeat `status_tags`. Emission is SPARSE - a quiescent or inert journal ships no tags at
all, so absence means "nothing to report", not "not collected". One exception: the two
`_stale_seconds` age tags below are emitted every heartbeat **including `0`** while the drain
worker is live (a zero age is a real "fresh" reading), and are absent only while the journal
path is dormant.

| Tag | Meaning | What to do |
|---|---|---|
| `yuzu.guardian_journal_maint_exceptions` | Cumulative JOURNAL passes that threw and were firewalled: the heartbeat's retry-persist plus the drain worker's retention prune and replay paging. Convergence sweeps are NOT included - they have their own tag below. Nonzero means the journal path hit an exception (typically `bad_alloc` under memory pressure) and was contained rather than terminating the agent. It covers the firewalled journal paths - persist on the heartbeat, at boot re-arm, on rule-apply and at shutdown; the reconnect kick; and the worker's retention and replay passes - plus one increment for the drain worker's own loop terminating, which stops outbox DELIVERY too. That last case is named in a `critical` log line and, unlike the others, increments once and never again. | Investigate endpoint memory pressure. A steadily climbing value with a growing `yuzu.guardian_journal_bytes` means retention is not keeping up. A value that increments exactly once and then stays flat while the journal grows is the loop-termination case; check the agent log for the `critical` line and restart the daemon. |
| `yuzu.guardian_journal_write_capacity_rejected` | Records refused because the journal is at its hard write ceiling. | Check whether prune is failing (`yuzu.guardian_journal_prune_failures`) or the store is unwritable. |
| `yuzu.guardian_journal_gauge_underflow` | The write-ceiling check read the live size gauge as **negative** - a size-accounting bug. Persist then fails **closed** (RAM staging only) until a prune rebase restores the gauge. `yuzu.guardian_journal_batch_count` clamps the negative to 0, so the journal looks empty while it is actually refusing writes; this tag is the only signal of that state. | Any nonzero is a real bug - capture the agent log and file it. A sustained climb alongside `yuzu.guardian_journal_stage_dropped` means the underflow is now costing records. |
| `yuzu.guardian_journal_prune_failures` | Retention passes that could not read the journal. | A sustained nonzero value means the shared `kv_store.db` is busy or corrupt. |
| `yuzu.guardian_journal_page_read_failures` | Replay READS that could not read the journal - the candidate scan (at most once per pass) plus, since #2299, each per-candidate value read a pass attempts (bounded by the 128-candidate cap). The unit is failed READS, not failed passes: one pass can add several, so do not read a rate off this as a pass-failure rate. | Separate from `prune_failures` on purpose: retention can be succeeding while replay is stalled, in which case records are being deleted on schedule and shipped never. A sustained nonzero value with a healthy `prune_failures` is the worse of the two. |
| `yuzu.guardian_journal_clock_jump_skips` | Retention passes that declined to age-evict because the pass would have aged out the ENTIRE journal at once. | NOT an error: the journal deliberately kept evidence it would otherwise have deleted. It fires when such a pass follows one that was not already working off a backlog, so it reports the ONSET of the condition, not every pass of it. The usual cause is a clock that moved - a VM restored from an old snapshot, or a bad NTP correction - but a legitimately long-offline endpoint whose whole (small) journal expired together looks identical. Check the endpoint's clock first. If it jumped forward, replay keeps ATTEMPTING delivery of the survivors either way - the paced ageing-out deliberately stops treating them as unshippable - but the per-pass cap keeps deleting the oldest ones out from under it, and deletion currently outruns replay by roughly five to one. Correcting the clock is what stops that race rather than what starts delivery, and it takes effect on the next retention pass. Expect a burst of redelivered events during a paced ageing-out; the server de-duplicates them. Note the cap applies to AGE only - if the journal is also over its COUNT ceiling, that ceiling is uncapped and trims the oldest batches in a single pass regardless. |
| `yuzu.guardian_journal_evicted_no_send_evidence` | Batches aged out with no record of ever being sent - a possible audit gap. | Correlate with connectivity outages for that endpoint. A spike alongside `yuzu.guardian_journal_clock_jump_skips` means the endpoint's clock moved rather than that the link was down - check the clock before concluding evidence was genuinely lost. Since #2299 also cross-check `yuzu.guardian_journal_quarantined`: quarantine of a corrupt-VALUE batch moved to the replay pass, so a corrupt batch the replay rotation never reaches before it ages out is counted HERE rather than as quarantined. Both are genuinely lost evidence, but on a mass-corruption endpoint this counter no longer separates "never delivered" from "never deliverable". |
| `yuzu.guardian_journal_evicted_unclassified` | Batches aged out whose sent/unsent disposition was never determined - the third eviction outcome, mutually exclusive with the two above. It makes the eviction accounting exact (`pruned` == the three summed), so `_evicted_no_send_evidence` reads as a floor rather than an undercount. **Neither** an audit gap **nor** a delivered batch. | Read by cause. A single one-off increment coinciding with an agent shutdown is the stop-before-classification case (benign, at most once per process lifetime; since #2470 a stop during scan-OK classification no longer lands here - only a stop mid-fallback-loop does). A value that climbs with `yuzu.guardian_journal_prune_failures` is the unreadable-sent-label case - investigate the shared `kv_store.db` as for that counter. A jump alongside `yuzu.guardian_journal_maint_exceptions` is a mid-classification `bad_alloc` (memory pressure) - the remainder is accounted here and the throw counted there. In-memory only; resets on restart, and the shutdown-skip increment may not survive to a final heartbeat. |
| `yuzu.guardian_drain_exceptions` | Firewalled throws in the outbox DELIVERY machinery on the drain worker. | Events are buffered but not shipping. Distinct from the journal counter - delivery failing and retention failing need different responses. |
| `yuzu.guardian_send_exceptions` | Per-entry drain **sends** that threw - finer-grained than `_drain_exceptions`: a single entry could not be serialized/sent, so its log's head is retained and that drain **stops**, jamming delivery behind a permanently-failing entry. Spans the lifecycle log and the general outbox. | A sustained nonzero value with otherwise-healthy streaming means an entry is stuck at the head; capture the agent log for that entry. |
| `yuzu.guardian_journal_backpressure_drops` | Lifecycle-audit entries **rejected** at outbox enqueue because it was at capacity. A **loss** channel: the arm/disarm still succeeds (the audit trail never blocks a real detection-capability change) but the record of that change is dropped. | A nonzero value means the audit trail is missing lifecycle edges under sustained delivery backpressure - investigate why delivery is not draining. |
| `yuzu.guardian_sweep_exceptions` | Firewalled throws in the convergence SWEEP lanes. | Drift DETECTION is degraded (the endpoint may miss policy violations); the audit trail itself is unaffected. |
| `yuzu.guardian_journal_bytes` / `yuzu.guardian_journal_batch_count` | Current on-disk size and batch count of the journal. Gauges, not counters. | Not independently actionable - use them to interpret the rows above (a climbing size alongside `prune_failures` means retention is not keeping up). |
| `yuzu.guardian_journal_page_stale_seconds` / `yuzu.guardian_journal_prune_stale_seconds` | Seconds since the drain worker's last page pass that made **replay progress or verified there was none** / last prune pass that **actually ran retention** (applied the delete or verified nothing eligible), seeded from worker start. **Replay/retention-progress** gauges (flip item 6, #2452): a dead, hung, or permanently-throwing worker reads as an ever-growing age - AND so does one whose page passes are token-starved, read-failing, boot-barrier-stalled, **window-blocked (headroom)**, or **quarantine-only (mass corruption)**, or whose prune **scan, DELETE, or completion** is failing (scan-fail / delete-fail / stop-aborted), **declining age eviction of expired rows on a clock anomaly**, or **unable to quarantine a stuck malformed key**. Each gate is a single positive signal (`progress_or_verified_idle` for page, `progress_or_verified` for prune), so any no-work exit reads stale by construction. A pass that placed records / evicted rows, or positively established there was nothing to do, still reads fresh (a forward-clock-jump WIPE is the one prune case that reads fresh despite an anomaly - the delete did succeed, so the clock guard, not this gauge, owns it). Emitted every heartbeat **including `0`** while the worker is live; absent while dormant. Two tags because the cadences differ (30 s page / 120 s prune) and stall independently. | Healthy readings hover around each pass's cadence. A steadily growing age with climbing `maint_exceptions` means every pass is throwing now; with a **flat** `maint_exceptions` the worker is hung, its loop died earlier (loop death increments that counter exactly once and logs a `critical` line - check the agent log), **or** its passes are stalling short of progress - read alongside `page_read_failures` / `prune_failures` and `deferred`-class signals to tell which. Either way the journal is unmaintained - see the restart caveat below. |
| `yuzu.guardian_journal_headroom_blocked_seconds` | Age of the current headroom-blocked **replay-congestion episode** (#2364): a journal batch could not be placed in the send window for lack of room, continuously since the value's start. Sampled at pass granularity; clears only after a proven block-free sweep of all candidates (the batches a replay pass currently considers); resets on agent restart; a forced (boot/reconnect) pass can start an episode from already-delivered batches. **Sparse**: absent = no current episode. | Sustained growth means the send window is not draining while a backlog waits - check connectivity and the delivery counters. The loss-relevant threshold is the 7-day retention window (604 800 s): an episode approaching it means never-sent records are nearing deletion (`_evicted_no_send_evidence`). A clear can coincide with the blocked batch's own eviction - corroborate against `_evicted_no_send_evidence` before reading a clear as recovery. |

**A gap the age gauges close (formerly "Known gap"):** the counter tags alone cannot
distinguish a healthy idle worker from a dead one - they are sparse, so a worker that stops
before doing any work reads exactly like one with nothing to do, and a worker that HANGS (blocked
indefinitely on a store call) throws nothing for the firewall to catch. The `_stale_seconds`
gauges above are the fix (flip items 6/14): they are seeded at worker **start** and re-stamped
only by a pass that made real progress or positively verified there was nothing to do (#2452) -
for page, records placed OR a completed scan of a clean, unblocked, uncorrupted, readable backlog;
for prune, retention applied (the delete succeeded) OR a clean scan verifying nothing was eligible.
So not just dead, hung, and permanently-throwing workers but also token-starved, read-failing,
window-blocked (headroom), and mass-corruption (quarantine-only) page workers, and scan-failing /
delete-failing / stop-aborted / clock-declining / quarantine-stuck prune workers, all read as an
ever-growing age - and because they
are emitted including `0`, "fresh" is a real reading, not an absence. What they still cannot show is a worker that **never started at all**: no worker
means the tags are absent, which post-cutover is itself the anomaly to look for on a rule-bearing
agent. There is no restart primitive short of restarting the agent daemon, and a restart is not
free: records already written to the journal survive it, but `GuardianEngine`'s shutdown holds
its lock while it joins the drain worker, so a stop arriving while that worker is hung rather
than dead can itself be cut short by a supervisor's stop timeout. Prefer a graceful stop, and
confirm the process exited on its own rather than being killed.

Note the tag KEY is not always the internal field name - the audit-gap row above is emitted
as `..._evicted_no_send_evidence` though the field is `evicted_without_send_evidence`. Grep
heartbeat payloads for the key in this table, not for the field name; the emitter in
`agents/core/src/guardian_journal_heartbeat.hpp` is authoritative.

This table covers the actionable subset. The emitters ship about thirty
`yuzu.guardian_journal_*` tags in total (the counters sparsely - only non-zero ones - plus the
age tags per their own posture above), so a tag absent from this table is not necessarily
absent from the payload.

Counters are cumulative for the agent process and reset on restart.

### How long Guardian audit evidence is retained ON the endpoint

The durable lifecycle journal keeps records locally until they are replayed to the server,
bounded by whichever of these is reached first:

| Cap | Value | Behaviour at the cap |
|---|---|---|
| Age | 7 days | Older batches are evicted on the next retention pass |
| Batch count | 1000 (soft) / 2000 (hard ceiling) | Oldest-first eviction at the soft cap; writes are REFUSED at the hard ceiling |
| Size | 32 MiB (soft) / 64 MiB (hard ceiling) | As above |

Eviction is keyed off each batch's recorded wall-clock timestamp, so the window survives a
reboot. This is the ENDPOINT-side window only - once records reach the server they follow the
server's own retention (see `guaranteed-state.md`). An endpoint offline for longer than the
age cap, or generating more than the count/size caps allow, will have the excess evicted
locally; `yuzu.guardian_journal_evicted_no_send_evidence` counts the batches that aged out
with no evidence of ever having been sent.

### Plugin load + signing rejections (`yuzu_agent_plugin_rejected_total`)

Counter incremented every time the agent rejects a plugin at scan time
**before** the plugin's code runs. The `reason` label is bounded to a
fixed set of stable string prefixes — alert rules SHOULD pin against
the literal label values, not substring matches.

| Reason label | Meaning | Operator action |
|---|---|---|
| `reserved_name` | Plugin declared a reserved name (`__guard__`, `__system__`, `__update__`, `__guardian_journal__`, `__guardian__`, `__sync__`). Possible plugin-author error or a malicious shadowing attempt (#453; the `kv_store`-namespace names added in #2303). | Investigate the plugin source / drop. |
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
| `yuzu_fleet_perf_cohort_*` | `cohort` | **Operator tag values** (only when the opt-in cohort export key is set — Settings → DEX alerts). Cohort labels carry the raw tag values of the exported key; if those values encode personnel-relevant or confidential groupings (`department`, `cost-center`, owner names…), they flow to whatever scrapes `/metrics`, including third-party monitoring stacks. **Choose export keys whose values are non-sensitive organizational identifiers** (hardware model, image name). |

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
