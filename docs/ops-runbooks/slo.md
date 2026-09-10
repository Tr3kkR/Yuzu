# Service Level Objectives — Yuzu Server

Workstream D (Reliability, Availability, and Operational Readiness),
`docs/enterprise-readiness-soc2-first-customer.md` §3.4. Five SLOs, one per
required signal (`/readyz` availability, command dispatch latency, agent
heartbeat freshness, audit write success, PostgreSQL substrate degrade
events). Four of the five metrics are verified present in `server/core/src`
(grep citation on each) — none of those four is aspirational. **The fifth,
§1's `up{job="yuzu-server"}`, is a Prometheus *scrape* metric, not
something Yuzu itself emits** — verified present in the scrape config
(`deploy/prometheus/prometheus.yml` / `prometheus-uat.yml` /
`prometheus-full-uat.yml`), a different kind of verification than a grep
hit in `server/core/src`. Said explicitly in §1 below; do not read this
paragraph's "verified present" as covering all five uniformly.

**PO decision 2026-09-07** — the targets in this document were set by the
product owner on that date and are to be **re-baselined after 90 days of
production data**. No production Yuzu fleet exists yet (`docs/capability-map.md`
context), so every "Current measurement" line below reads **not yet
baselined**; this document exists so a customer's security reviewer sees a
target and a real alert wired to it, not a promise with nothing behind it.

Windows are 30-day rolling unless stated otherwise. "Burn" means the rate at
which the SLO's error budget is being consumed, not the raw threshold alone —
each section names the existing Prometheus alert (`docs/prometheus/yuzu-alerts.yml`)
that pages on it, or says explicitly that no alert ships yet.

---

## 1. `/readyz` availability

**Metric:** no direct `/readyz`-content probe is shipped today (confirmed:
no blackbox_exporter anywhere in `deploy/`, no `up`-based dead-man's-switch
for the server process — `docs/ops-runbooks/audit-store-clock-guard.md`
names this gap explicitly under `YuzuServerRestartLoop`: *"There is no
dead-man's-switch (`up == 0`) rule for the server process in this file
today (tracked: #2956)"* (quoted verbatim as that doc currently reads).
**Correction (2026-09-10, governance-reproduced, C2-3):** #2956 is
CLOSED, and a prior revision of this document redirected the citation to
#2459 — but #2459 does not name this gap either (verified). Treat this gap
as **untracked; proposed** until a real tracking issue exists — do not cite
either #2956 or #2459 as the live tracker. The practical proxy is
Prometheus's own scrape
health of the `/metrics` endpoint on the same server process: `up{job="yuzu-server"}`
(`deploy/prometheus/prometheus.yml` / `prometheus-uat.yml` / `prometheus-full-uat.yml`,
job name `yuzu-server`). This proves the HTTP listener is alive; it does
**not** prove `/readyz`'s own conjunctive store-health checks pass (a server
that is up but reporting a degraded store — e.g. `stores.audit` closed —
would still show `up == 1` here). Closing that gap needs a blackbox-exporter
job scraping `/readyz` directly and asserting on HTTP status, which is not
part of this change — untracked; proposed (see the correction above).

**Target:** **99.5% / 30d for a single-replica deployment** (~3h39m of
allowed downtime/month) — what ships today. Target rises to **99.9% / 30d**
once ADR-2002 Phase B (second replica, `docs/user-manual/ha-postgres.md`)
lands; a single server process is a single point of failure for the
dashboard/REST/gRPC listener regardless of how available the PostgreSQL
substrate underneath it is (HA-Postgres protects the data plane, not this
listener — see that doc's "What you get").

**Window:** 30-day rolling.

**Alert:** none shipped today for this specific signal. **PROPOSED** (not in
`docs/prometheus/yuzu-alerts.yml` — that file is not owned by this change):

```yaml
# PROPOSED — NOT SHIPPED. Mirrors YuzuGatewayDown's up{job=~".*gateway.*"}==0
# pattern (docs/prometheus/yuzu-alerts.yml) applied to the server job. The
# gap this closes is untracked (neither #2956, closed, nor #2459 names it —
# see the correction above) — proposed for the PO/workflow owner to route
# into the real file and file a tracking issue for.
- alert: YuzuServerDown
  expr: up{job="yuzu-server"} == 0
  for: 2m
  labels:
    severity: critical
  annotations:
    summary: "Yuzu server metrics endpoint is down"
    description: >-
      Prometheus cannot scrape the Yuzu server (:8080/:8443). Every dashboard,
      REST, and MCP request is failing while this holds.
```

**Current measurement:** not yet baselined.

---

## 2. Command dispatch latency (p99)

**Metric:** `yuzu_command_duration_seconds` — histogram, described
`server/core/src/server.cpp:555`, observed at
`server/core/src/agent_service_impl.cpp:1438` and `:1726`.

**Target:** p99 < 10s for ≥99% of 5-minute windows / 30d.

**Window:** 30-day rolling, evaluated over 5-minute buckets (matches the
alert's own window below).

**Alert:** existing — `YuzuHighCommandLatency`
(`docs/prometheus/yuzu-alerts.yml`):

```yaml
- alert: YuzuHighCommandLatency
  expr: |
    histogram_quantile(0.99, sum(rate(yuzu_command_duration_seconds_bucket[5m])) by (le)) > 10
  for: 5m
  labels:
    severity: warning
```

**Current measurement:** not yet baselined.

---

## 3. Agent heartbeat freshness

**Metric:** `yuzu_agents_connected` − `yuzu_fleet_agents_healthy` (both
gauges, `server/core/src/agent_registry.cpp:191,349,369` and `:2237`
respectively; described `server.cpp:498`). A positive value means agents are
connected but not producing a recent heartbeat. **Caveat:** the two gauges
are independently updated (connect/disconnect events vs. a periodic
healthy-count recomputation), so under churn — agents connecting and
disconnecting in the same window the healthy-count sweep runs — the raw
difference can transiently go **negative** (a stale, higher `healthy` count
briefly outpacing a just-dropped `connected` count). That's harmless for
the existing `> 0` alert threshold below (a negative value also fails
`> 0`, so it never falsely pages), but an SLO **error-budget quantity**
built from this metric should use `clamp_min(yuzu_agents_connected -
yuzu_fleet_agents_healthy, 0)` — treat "stale-connected agents" as never
less than zero — rather than the raw signed difference, which would
otherwise let a negative reading offset/cancel a real positive reading when
averaged over a window.

**Target:** 0 stale-connected agents for ≥99.5% of time / 30d (computed on
the `clamp_min(..., 0)` form above).

**Window:** 30-day rolling.

**Alert:** existing — `YuzuAgentDisconnected`
(`docs/prometheus/yuzu-alerts.yml`):

```yaml
- alert: YuzuAgentDisconnected
  expr: |
    (yuzu_agents_connected - yuzu_fleet_agents_healthy) > 0
  for: 2m
  labels:
    severity: warning
```

There is also a fleet-drop companion, `YuzuAgentFleetDrop` (>20% drop in
connected count over 5m, `severity: critical`), which is a different signal
(mass disconnection, not staleness) and not part of this SLO.

**Current measurement:** not yet baselined.

---

## 4. Audit write success

**Metric:** `yuzu_server_audit_emit_failed_total` (gauge-published counter,
`server/core/src/server.cpp:7830`, described `:2388`) and
`yuzu_server_audit_events_total{result}` (success/failure/denied/other,
`server.cpp:7821-7827`) for the write-outcome breakdown.

**Target:** **0 emit failures / 30d — a fail-closed CONTROL, not a
percentage (SLO = 100%).** Per ADR-0040, every behavioural-PII REST route
using fail-closed audit-on-open (`guardian.device.view`, `dex.device.view`,
`dex.signal.view`, `dex.perf.device.view`, `network.device.view`) returns
`503` and withholds data the moment `yuzu_server_audit_emit_failed_total`
rises — the system already treats any audit-write failure as an outage of
those routes rather than a tolerable degradation, so the SLO mirrors that
design rather than inventing a softer target.

**Window:** 30-day rolling; the underlying alert pages within minutes of any
single failure (see below) — this is not a budget that "burns slowly."

**Alert:** existing — `YuzuAuditPersistFailures`
(`docs/prometheus/yuzu-alerts.yml`, `severity: critical`):

```yaml
- alert: YuzuAuditPersistFailures
  expr: |
    increase(yuzu_server_audit_emit_failed_total[5m]) > 0
  for: 2m
  labels:
    severity: critical
```

Runbook: `docs/ops-runbooks/audit-store-clock-guard.md` (`YuzuAuditPersistFailures`
section) — also covers the retention-side clock guard family, which bounds
blast radius on the deletion path but is a separate control from write
success.

**Current measurement:** not yet baselined.

---

## 5. PostgreSQL substrate degrade events

Three related metrics, all described/incremented in
`server/core/src/server.cpp` (`:1653`, `:1657`, `:1662`, `:1670`, `:1677`,
`:3937`, `:3951`) — split into three targets per PO ruling, since pool
saturation, acquire latency, and hard connect failure are different failure
modes with different tolerances.

### 5a. Pool saturation

**Metric:** `yuzu_pg_pool_in_use` / `yuzu_pg_pool_size` (gauges).
**Target:** <90% saturated for ≥99% of time / 30d.
**Alert:** existing — `YuzuPgPoolSaturated`:

```yaml
- alert: YuzuPgPoolSaturated
  expr: |
    yuzu_pg_pool_in_use / yuzu_pg_pool_size > 0.9
  for: 5m
  labels:
    severity: warning
```

### 5b. Acquire-wait latency

**Metric:** `yuzu_pg_acquire_wait_seconds` (histogram).
**Target:** p99 < 200ms for ≥99% of time / 30d — the heartbeat upsert deadline
is 250ms, so this is the leading indicator before persistence starts dropping
(per the alert's own comment).
**Alert:** existing — `YuzuPgAcquireWaitHigh`:

```yaml
- alert: YuzuPgAcquireWaitHigh
  expr: |
    histogram_quantile(0.99, rate(yuzu_pg_acquire_wait_seconds_bucket[5m])) > 0.2
  for: 5m
  labels:
    severity: warning
```

### 5c. Connect failures

**Metric:** `yuzu_pg_connect_failed_total` (counter).
**Target:** report the raw count; target **0 sustained (>2 minute) failure
episodes / 30d** — a single transient blip (e.g. one dropped TCP connection
that reconnects on the next pool acquire) is not treated as an SLO breach,
only a failure episode that outlasts the alert's own `for: 2m` window is.
**Alert:** existing — `YuzuPgConnectFailing`, `severity: critical`:

```yaml
- alert: YuzuPgConnectFailing
  expr: |
    rate(yuzu_pg_connect_failed_total[5m]) > 0
  for: 2m
  labels:
    severity: critical
```

**Current measurement (all three):** not yet baselined.

---

## Verifying this file's claims

**Correction (2026-09-10, governance-reproduced, C2-4):** this section
previously pointed at `docs/ops-runbooks/restore-drill-2026-09.md` for the
exact `promtool` invocation — that invocation is not in that file. The
actual command, run against this repo (no local `promtool` binary
required):

```bash
docker run --rm --entrypoint /bin/promtool \
  -v "$PWD/docs/prometheus:/r" \
  prom/prometheus:v3.2.1@sha256:6927e0919a144aa7616fd0137d4816816d42f6b816de3af269ab065250859a62 \
  check rules /r/yuzu-alerts.yml
```
Expected output: `SUCCESS: 116 rules found` (115 alert rules + 1 recording
rule — see `docs/enterprise-readiness-soc2-first-customer.md` §3.4 for
where that count is cross-checked against a raw `grep -c` of the file).
See #2857 for why no shipped stack evaluates these rules at runtime yet —
`deploy/docker/docker-compose.observability.yml` is the first one that
does, for the UAT rig.

## Related

- `docs/ops-runbooks/audit-store-clock-guard.md` — the audit-write and
  retention alert family in detail.
- `docs/user-manual/ha-postgres.md` — the separate, more specific RTO/RPO
  figures for the optional Patroni-managed HA-Postgres profile (failover
  RTO **~30-40 seconds** per that doc's own "What you get" section —
  correction, governance arch2-3: a prior revision said "~15-40s" here,
  which matched no source in this repo), RPO=0 under `quorum3`. Those numbers describe the
  **PostgreSQL substrate's own** failover; they are not a substitute for
  §5 above (the *server's* pool-level view of that substrate) or for §1
  (the server listener's own availability, which HA-Postgres does not
  address at all — see §1's ADR-2002 Phase B note).
- `docs/ops-runbooks/restore-drill-2026-09.md` — the executed backup/restore
  drill and its measured RTO/RPO for the non-HA, single-replica deployment
  this document's §1 target describes.
- The server dead-man's-switch gap this document's §1 proposed alert would
  close is **untracked** — `docs/ops-runbooks/audit-store-clock-guard.md`
  cites #2956 for it, which is closed and does not (re-)name a live
  successor; #2459 was checked and does not name this gap either (see §1's
  correction). File a tracking issue rather than citing either number.
