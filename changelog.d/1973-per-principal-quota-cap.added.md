- **Per-principal quota cap for engine principals (#1973).** Every
  `principal_kind=="engine"` session is now capped at the server's single
  pre-routing chokepoint on two independent dimensions — in-flight
  concurrency (`--principal-max-concurrency`/`YUZU_PRINCIPAL_MAX_CONCURRENCY`,
  default 16) and per-principal token-bucket rate
  (`--principal-rate-limit`/`YUZU_PRINCIPAL_RATE_LIMIT`, default 20/s, burst
  2x rate). Exhausting either cap returns HTTP `429` + `Retry-After` — the A4
  error envelope on REST, a JSON-RPC `id: null` error (code `-32010`) on MCP
  — and increments the pre-seeded, bounded-label
  `yuzu_server_principal_quota_exhausted_total{side,limit}` counter (a
  companion `yuzu_server_principal_quota_admits_total{side}` counts every
  admitted request, so the exhaustion rate is computable); human,
  device-agent, and anonymous traffic is unaffected. Both dimensions apply
  to streaming/SSE requests too — a streaming request holds its concurrency
  slot for the stream's lifetime rather than being rate-capped only. This
  closes the ADR-1005 interlock requiring a minimum per-principal cap before
  any engine principal may be enabled in production. The cap is
  per-server-process (a multi-replica deployment's effective ceiling is
  `configured_cap x replica_count`; durable cross-instance quota is a future
  follow-up), and a rejection is metric-only with no audit row (a
  high-frequency operational event, not a lifecycle action). See
  `docs/user-manual/engine-principals.md` "Per-principal quota cap".
