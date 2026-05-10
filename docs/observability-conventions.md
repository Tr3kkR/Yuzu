# Observability Conventions — Yuzu

The `sre` and `architect` agents load this document on any change that adds, removes, or modifies metrics, audit events, or lifecycle events. CLAUDE.md keeps a one-line pointer.

## Prometheus metrics

- All metrics use the `yuzu_` prefix.
  - Server metrics: `yuzu_server_*`
  - Agent metrics: `yuzu_agent_*`
- **Consistent base label set:** `agent_id`, `plugin`, `method`, `status`, `os`, `arch`. Avoid one-off labels — they prevent cross-cutting Grafana queries.
- **Transport-layer extension labels** (introduced with the transport abstraction): `direction` ∈ {sent, received, opened, closed}, `kind` ∈ {std_exception, non_std_exception, dispatcher_internal}, `reason` ∈ {channel_fault, peer_halfclose, stream_open_failed, enrollment_pending}, `phase` ∈ {write, read}. All bounded-cardinality and operator-controlled (or hard-coded enum), never attacker-supplied. Used on `yuzu_server_transport_*`, `yuzu_agent_ota_chunk_deadline_total`, `yuzu_agent_reconnections_total`. Adding a new transport-layer label here MUST keep the cardinality bounded — if the label value comes from the wire, validate it against an allowlist before passing to `metrics_.counter(..., {{label, value}})`.
- **Histogram buckets** (default for latency-style histograms): `0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0`.
- Health endpoints (`/livez`, `/readyz`, `/healthz`) reflect every component's health and are scrapable.

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

- Grafana dashboard templates: `docs/grafana/`
- Prometheus scrape config examples: `docs/prometheus/`
- ClickHouse ingest setup: `docs/clickhouse-setup.md`
