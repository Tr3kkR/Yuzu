# Runbook: Transport saturation + agent channel-fault alerts

This runbook covers the three Grafana alerts that fire on the agent-listener transport surface:

- `YuzuBidiPoolSaturationRejects` (warning) — bidi dispatcher pool rejecting new calls
- `YuzuBidiPoolNearSaturation` (critical) — pool slot residency >80% for 5 m
- `YuzuAgentChannelFaultRate` (warning) — fleet-wide reconnect rate with `reason="channel_fault"` exceeds 0.5/s

All three are operator-actionable. None are paging-suppressible by silencing alone — silencing leaves the underlying capacity / TLS / network issue unaddressed.

---

## Diagnostic preamble (run for any of the three alerts)

```bash
# 1. Listener health: is the agent listener accepting calls at all?
curl -fsS http://<server>:8080/readyz | jq .

# 2. Pool state at the time the alert fired:
yuzu_server_transport_bidi_pool_size      # configured cap
yuzu_server_transport_bidi_pool_in_flight # slot residency
yuzu_server_transport_bidi_pool_saturated_total  # lifetime reject count

# 3. Recent dispatcher throw counter — distinguishes capacity from internal-error:
rate(yuzu_server_transport_dispatcher_throws_total{kind="dispatcher_internal"}[5m])
# If this is non-zero alongside saturation, you have BOTH internal failures
# AND saturation — internal failures are the priority because they may be
# the root cause of the saturation.

# 4. Server log for the alert window:
journalctl -u yuzu-server --since '5m ago' | grep -E 'bidi|saturat|deadline|rate.limit'
```

---

## YuzuBidiPoolSaturationRejects (warning)

**Trigger:** `rate(yuzu_server_transport_bidi_pool_saturated_total[1m]) > 0` sustained for 1 m.

**Meaning:** The agent listener is rejecting incoming bidi RPCs (Subscribe / DownloadUpdate) with `ResourceExhausted "transport: bidi dispatcher saturated"`. The pool reached its configured cap (`--bidi-dispatcher-pool-size`) and has no slot for new calls.

**First-fire pilot experience:** rare but expected on under-sized direct-connect deployments at fleet-scale. Acceptable on day-1 if the operator is in the process of sizing the pool; concerning if it persists past steady-state.

### Triage

1. **Is `dispatcher_throws_total{kind=dispatcher_internal}` rising at the same rate?**
   - **Yes**: this is NOT a capacity issue, it's an internal failure that's been re-counted as a saturation reject (the legacy compatibility increment). Investigate the throw-counter rate for the underlying cause; check for recent code changes that introduced an exception in the dispatcher path. Skip to the dispatcher-internal section below.
   - **No**: legitimate pool saturation. Continue.

2. **Compare `bidi_pool_in_flight / bidi_pool_size`:** if the ratio is at or near 1.0, the pool is genuinely full. Proceed.

3. **Identify which `method` is rejecting:** `yuzu_server_transport_bidi_pool_saturated_total` is labeled by method. Subscribe rejects are usually fleet-scale (every agent has one); DownloadUpdate rejects are bursty (correlated with OTA rollout).

4. **Capacity decision:**
   - **Direct-connect deployment** (no gateway): raise `--bidi-dispatcher-pool-size` per `docs/user-manual/server-admin.md` "Bidi dispatcher pool sizing". Default auto-compute = `clamp(64, hardware_concurrency × 8, 4096)`; for fleets above ~2K direct-connect agents you must set explicitly. Verify cgroup `TasksMax` / `LimitNPROC` / `pids_limit` is high enough (the pool will hit those before its configured cap if cgroups are tight).
   - **Gateway-mode deployment**: this alert SHOULD NOT fire — the gateway terminates Subscribe per-fleet and the server only sees one upstream per gateway node. If it fires anyway, you may have routed direct-connect traffic accidentally; check `--gateway-upstream` and `--gateway-mode` flags and the agent config's `--server-address` to confirm agents are pointing at the gateway, not the server.

### Mitigation

- **Immediate**: front the listener with the gateway (deploy `yuzu-gateway` and reroute agents). The gateway absorbs Subscribe per-fleet and reduces direct server load to one upstream stream per gateway node.
- **Short-term**: raise `--bidi-dispatcher-pool-size` to expected concurrent agent count + 20% headroom + DownloadUpdate budget. Restart server. Monitor `bidi_pool_in_flight` to confirm headroom.
- **Long-term**: capacity-plan based on `yuzu_server_transport_bidi_pool_in_flight` p99 over 7 d; the pool size should comfortably exceed p99 at all times.

---

## YuzuBidiPoolNearSaturation (critical, paging)

**Trigger:** `bidi_pool_in_flight / bidi_pool_size > 0.8` sustained for 5 m.

**Meaning:** The pool slot residency (queued calls + active handlers — see `docs/user-manual/metrics.md`) has been above 80% for >5 m. Saturation rejects are imminent if the trend continues.

**First-fire pilot experience:** distinguishes a slow-creep capacity issue from a sudden burst. By the time this fires, you have ~1 m of slack before `YuzuBidiPoolSaturationRejects` joins it.

### Triage

Same as `YuzuBidiPoolSaturationRejects` above, but you have a few minutes of headroom to act before rejects start firing.

1. Check whether `bidi_pool_in_flight` is increasing, plateauing, or oscillating. A plateau at 0.8-0.9 is sustainable until something changes; a steady increase will hit 1.0 soon.

2. Capacity decision identical to the saturation-rejects case. The earlier you act, the less reject noise and dropped agent calls.

### Why critical?

This alert is rated `severity: critical` because it page-precedes a customer-visible outage (Subscribe rejects mean agents can't pick up commands). The `YuzuBidiPoolSaturationRejects` warning fires at the cliff edge; this critical fires while there is still time to act.

---

## YuzuAgentChannelFaultRate (warning)

**Trigger:** `rate(yuzu_agent_reconnections_total{reason="channel_fault"}[5m]) > 0.5` sustained for 5 m.

**Meaning:** Across the fleet, agents are reconnecting at >0.5/s with reason `channel_fault` (Register RPC failed OR Subscribe stream final_status was non-Ok — both transport-level errors). This typically signals one of:

- TLS certificate rotation has gone wrong — agents can't validate the server cert or the server can't validate agent certs.
- The listener is in a restart loop (server crashed / OOM / cgroup-killed).
- A network partition is dropping mTLS handshakes.

**First-fire pilot experience:** the most operator-actionable of the three. A fleet-wide TLS regression would otherwise be invisible until pilot operators report "agents stopped checking in".

### Triage

1. **First, separate transport-level from auth-level**: check the same query for `reason="enrollment_pending"`. If both are firing, you have an enrollment-approval backlog AND a transport regression — handle the enrollment side via Settings > Pending Enrollments, then return here.

2. **Check listener health**: `curl -fsS http://<server>:8080/readyz | jq .`. If readyz is non-200, the listener itself is unhealthy. Check `journalctl -u yuzu-server --since '10m ago'` for crash / OOM / cgroup-kill logs.

3. **Check TLS material**: when did you last rotate certs? Was the rotation propagated to all agents? `openssl s_client -connect <server>:50051 -showcerts` to inspect what the server presents; compare to what agents have provisioned (cert expiry / SAN / chain).

4. **Check correlated metrics**:
   - `yuzu_agent_reconnections_total{reason="stream_open_failed"}` — if this is also high, the listener is rejecting mTLS handshakes (auth side) or the dispatcher pool is saturated.
   - `yuzu_server_transport_dispatcher_throws_total` — if dispatcher is throwing, the transport itself is sick.

### Mitigation

- **TLS regression**: roll back the cert rotation; investigate before re-rotating. Agents will reconnect within a few seconds.
- **Listener restart loop**: investigate the crash cause; the listener will not stop crashing on its own.
- **Network partition**: out-of-band; the alert will clear when connectivity restores.
- **Fleet-wide cert expiry**: the certs should have been renewed via the cert-rotation process before expiry — investigate why automation missed.

---

## Common: dispatcher_internal throws

`yuzu_server_transport_dispatcher_throws_total{kind="dispatcher_internal"}` increments on:

- The legacy "saturation reject" path (still fires alongside `bidi_pool_saturated_total` for backward dashboard compatibility — this is NOT a bug).
- A handler-construction exception (rare; usually means a recent code change is unstable).
- A CallContext-population failure (very rare).

If the rate is `> rate(bidi_pool_saturated_total)`, the difference is internal-error — investigate the server log around the increment. Code change in the last day is the most likely cause; consider rollback while diagnosing.

---

## When to escalate

- Any alert sustained for >30 m without trending toward resolution.
- `dispatcher_throws_total{kind=non_std_exception}` non-zero — this is a bug, not a capacity issue, and should be filed against the engineering team immediately with the server log.
- `bidi_pool_in_flight` sustained at exactly `bidi_pool_size` for >10 m WITHOUT corresponding new connection attempts — possible thread-pool deadlock; collect a `gdb -p $(pidof yuzu-server)` thread dump and escalate.

---

## References

- `docs/user-manual/server-admin.md` — bidi pool sizing + per-peer rate limit + chunk-write deadline
- `docs/user-manual/metrics.md` — full transport metric families + label sets
- `deploy/grafana/yuzu-alerts.yml` — alert source-of-truth
- `transport/include/yuzu/transport/transport.hpp` — TransportMetricSink contract
- ADR-0001 — transport abstraction + mitigation matrix
