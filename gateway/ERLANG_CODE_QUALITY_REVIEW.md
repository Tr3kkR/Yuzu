# Erlang Code Quality Review (current branch)

> **2026-03-26 Delta:** The RC sprint (commits `4bdae88`, `73b1d65`, `c8f74fc`) addressed gateway findings C1-C3 and H12-H16 from the RC assessment. Specific resolutions: TLS for upstream gRPC (finding 1 context), health endpoints added, circuit breaker with backoff, command duration metrics now calculated (finding 6), pg:start_link safety (finding 7), graceful shutdown, and .appup files. Findings 2 (persistent_term), 3 (unbounded spawn), 4 (error tuple shape), and 5 (hostname field) should be re-evaluated against current code.

## Scope
Reviewed all Erlang modules under `apps/yuzu_gw/src` for architecture, OTP usage, correctness risks, and operability.

## Overall assessment
**Rating: 6.5/10 (good OTP structure, but several high-impact correctness and scalability gaps).**

The branch shows strong direction: clear OTP decomposition, separation of concerns, and thoughtful telemetry hooks. However, a few implementation details create significant production risk under high fanout and long-lived operation.

## Strengths
- Clean OTP decomposition (`agent`, `router`, `registry`, `upstream`, top-level supervisors).
- Agent lifecycle modeled explicitly with `gen_statem` and clear state transitions.
- Command fanout and upstream concerns are separated cleanly.
- Telemetry and Prometheus integration is broad and structured.
- Defensive handling of mixed map key styles (`atom`/`binary`) across protocol boundaries.

## Findings

### High severity
1. **Fanout completion accounting appears incomplete/inactive.**
   - `yuzu_gw_router` expects `handle_info({fanout_terminal, FanoutRef, _AgentId}, ...)` to finalize fanouts early.
   - No module currently sends `fanout_terminal`; only `command_response`/`command_error` are emitted.
   - Practical effect: most fanouts complete only by timeout, degrading UX and inflating timeout metrics.

2. **`persistent_term` is used for per-agent transient registration state.**
   - Pending register/subscription correlation is stored in `persistent_term` and erased later.
   - `persistent_term` is optimized for rare updates and global reads; frequent churn (agent reconnects) can induce VM-wide update costs.
   - Better fit: ETS table owned by a process, with TTL/cleanup.

3. **Unbounded spawned process for stream status notifications.**
   - `notify_stream_status` spawns a new process per event.
   - Under churn (connect/disconnect storms), this can create avoidable process pressure and bursty upstream load.
   - Consider worker pool, bounded queue, or sending through the upstream gen_server mailbox with backpressure/timeout policy.

### Medium severity
4. **Inconsistent command error tuple shape.**
   - In `connecting`, dispatch rejection sends `{command_error, not_connected}`.
   - Elsewhere, callers expect `{command_error, FanoutRef, AgentId, Reason}`.
   - This inconsistency can cause dropped/misinterpreted failures in management streaming paths.

5. **ListAgents summary data appears semantically wrong/incomplete.**
   - `list_agents/2` builds summaries using keys like `hostname` from registry rows that only contain `agent_id/pid/node/session/plugins/connected_at`.
   - Hostname therefore defaults empty and can mislead API consumers.

6. **Duration metric for completed commands is currently hard-coded to `0`.**
   - `yuzu_gw_agent` emits `command.completed` with `duration_ms => 0`.
   - This makes command-duration histograms low-value despite having robust metric plumbing.

7. **Potentially unsafe app startup sequence with `pg:start_link/1`.**
   - `yuzu_gw_app:start/2` calls `pg:start_link(yuzu_gw)` directly and ignores already-started/error cases.
   - If scope/process state differs across restart scenarios, startup behavior could be brittle.

### Low severity / maintainability
8. **`simple_one_for_one` supervisor strategy is legacy.**
   - Works today, but modern dynamic supervision is encouraged and easier to evolve.

9. **Some fields are tracked but not used effectively.**
   - Example: router record field naming (`stream_ref`) stores a fanout ref, which is confusing for future maintainers.

## Recommended priorities
1. Implement (or remove and replace) `fanout_terminal` path so fanouts complete on terminal responses.
2. Replace pending-session `persistent_term` usage with ETS + TTL cleanup.
3. Normalize command error tuple contracts across modules.
4. Record true command durations (e.g., dispatch timestamp map keyed by command_id).
5. Replace per-event `spawn` for upstream notifications with bounded concurrency.

## Final verdict
The branch has a solid OTP foundation and good observability intent, but it is not yet production-ready for very large fleets without addressing fanout completion, transient-state storage strategy, and churn-path backpressure.
