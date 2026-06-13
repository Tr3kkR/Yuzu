# Observability Conventions — Yuzu

The `sre` and `architect` agents load this document on any change that adds, removes, or modifies metrics, audit events, or lifecycle events. CLAUDE.md keeps a one-line pointer.

## Prometheus metrics

- All metrics use the `yuzu_` prefix.
  - Server metrics: `yuzu_server_*`
  - Agent metrics: `yuzu_agent_*`
- **Consistent label set:** `agent_id`, `plugin`, `method`, `status`, `os`, `arch`. Avoid one-off labels — they prevent cross-cutting Grafana queries.
- **Histogram buckets** (default for latency-style histograms): `0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0`.
- Health endpoints (`/livez`, `/readyz`, `/healthz`) reflect every component's health and are scrapable.
- **Security events route to the SIEM via Prometheus, not directly.** We do not write security events to a SIEM sink from the app. Emit them through the Prometheus counter with an `event="security"` label; Splunk (and every other SIEM) has a Prometheus receiver and filters on `event`. This keeps a single egress path and lets the SIEM, not the app, decide what to ingest. Examples: `yuzu_grpc_subscribe_peer_mismatch_total{event="security",gateway_mode="false"}` (IP-binding stolen-session signal, #1059) and `yuzu_grpc_subscribe_identity_mismatch_total{event="security"}` (mTLS-identity stolen-session signal, #1118 — no `gateway_mode` label, since the mTLS check is gateway-mode-independent). Pair the metric (real-time SIEM/alerting) with the audit row (forensic detail): **the metric is the signal, the audit row is the evidence.**

`yuzu_grpc_subscribe_peer_advisory_total{event="security",reason="mtls_identity_match|trusted_nat_cidr"}` (#1128) is the **tolerated** counterpart of `_peer_mismatch_total`: a Subscribe peer-IP mismatch that was downgraded to advisory (not rejected) under a NAT-aware accommodation. It pairs with a `session.peer_mismatch` audit row carrying `result="ok"` and `outcome=advisory` (vs the reject row's `result="denied"`). Read the two metrics together — a spike in `_advisory_total` alone is benign multi-egress churn; a spike in both `_advisory_total` and `_mismatch_total` is worth investigating. The `reason` label distinguishes which accommodation fired.

## Audit events

Structured JSON envelope:

```json
{
  "timestamp": "2026-04-18T12:34:56.789Z",
  "principal": "alice",
  "action": "noun.verb",
  "target_type": "User",
  "target_id": "bob",
  "result": "ok|denied|error",
  "detail": "free-form context"
}
```

- Suitable for direct delivery to Splunk HEC or generic webhook sinks.
- Indexed by `timestamp` and `principal` for efficient queries.
- Denied operations MUST emit an audit event — `spdlog::warn` alone breaks the SOC 2 CC7.2 evidence chain.

## Event format (envelope)

All events — lifecycle, compliance, audit, system — follow a common envelope so downstream parsers can demultiplex by `event_type` without per-source schemas:

```json
{
  "event_type": "...",
  "timestamp": "...",
  "source": "server|agent|gateway",
  "payload": { ... }
}
```

## Response schemas

All instruction response data must be **typed** for downstream consumption (ClickHouse, Splunk, etc.). Permitted column types:

- `bool`, `int32`, `int64`, `string`, `datetime`, `guid`, `clob`

`clob` is reserved for large text fields with configurable truncation. See `docs/data-architecture.md` for the analytics-integration view.

## Where to find dashboards

- Grafana dashboards: `deploy/grafana/*.json` (operational set, auto-provisioned into the UAT/full-UAT Grafana — Prometheus-backed `yuzu-{dashboard,fleet,gateway}` plus the ClickHouse-backed `yuzu-analytics`); `docs/grafana/yuzu-overview.json` (standalone Prometheus import template). See `docs/grafana/README.md`.
- Prometheus alert rules: `docs/prometheus/yuzu-alerts.yml`; scrape-config example: `docs/grafana/README.md`
- ClickHouse ingest setup: `docs/clickhouse-setup.md`
