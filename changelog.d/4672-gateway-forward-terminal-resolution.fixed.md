- **`forward_gateway_pending`'s terminal-failure branches now resolve the dispatching
  operator's `command_id` instead of leaving it stuck forever (#4672).** Every terminal-failure
  branch (`unauthenticated` — the #1422 mgmt-plane peer pin rejects; exhausted `unavailable`
  retries; `unknown_cluster` — no configured `--gateway-cluster-addr` for the target's cluster;
  and a response stream that produced no legitimate resolution for the targeted agent —
  "agent_mismatch") previously logged, incremented `yuzu_server_gateway_forward_total`, and
  silently dropped the command; the executions drawer and any API caller polling that
  `command_id` saw it idle at RUNNING (or never resolve at all) with no terminal signal. Each
  branch now synthesizes a terminal `FAILURE` response (`build_gateway_forward_terminal_failure`,
  a new pure, unit-tested builder in `gateway_mgmt_stub_pool.hpp`) and applies it through the
  same `process_gateway_response` path a real gateway response already uses, so the command
  resolves via the established `notify_exec_tracker` terminal-write mechanism exactly once.
  Durable outbox re-drive with backoff (ADR-2002 §7's original design note) is deliberately NOT
  wired for this path — see `docs/adr/2002-high-availability-architecture.md` §7e for the two
  reasons (a granularity mismatch with the WS-3 3.3 command outbox's leader-gated producer
  contract, and the pre-existing #3279 detached-thread lifetime hazard this fix does not widen) —
  and is tracked as a documented follow-up once #3279 closes.
