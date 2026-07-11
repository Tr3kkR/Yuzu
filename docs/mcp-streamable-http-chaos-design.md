---
status: accepted (Gate 5 output, governance run 2026-07-11)
scope: chaos test design for ADR-0022 execution-plan track 2f (MCP Streamable HTTP transport, Decision 15)
---

# Chaos Test Design — MCP Streamable HTTP (track 2f)

Gate 5 synthesis from the 2026-07-11 governance run on the Decision 15 docs commit. Each track 2f implementation PR **must carry the automated reproductions mapped to it below** (P0 = blocks that PR's merge); the letters refer to Decision 15's pre-commitments (a)–(k) in `docs/adr-0022-execution-plan.md`.

## Scenarios

- **CH-1 — Terminal never arrives + cap expiry** (verifies f). Kill the sole target agent mid-`execute_instruction`-with-progressToken; short test cap. Success: stream ends with a machine-parseable A4-shaped final frame carrying partial status + "execution continues server-side", structurally distinguishable from success; `get_execution_status(execution_id)` still serves durable state. **P0 PR 3.**
- **CH-2 — Ring wrap + mid-stream disconnect + resume** (verifies d+f). Sever TCP mid-progress, wrap the replay ring while disconnected, let execution finish. (a) In-window resume replays missed frames AND the final JSON-RPC response (pending final frame survives eviction — bounded: one per streamed request). (b) Past-window resume → 404 → re-initialize, never a silent gap; result fetchable by `execution_id`. **P0 PR 2; re-run at PR 3** (final-frame exemption exists only once the bridge does).
- **CH-3 — Restart + duplicate-dispatch temptation** (verifies g+j). Restart server with live session + in-flight streamed mutating tool; real client (MCP inspector, mcp-remote) hits 404. Success: client re-initializes; mutating execution count unchanged (no blind re-POST); fresh per-session event ids, no cross-restart `Last-Event-ID` collision honored. **Id-namespace half P0 PR 2; real-client half P0 PR 5.**
- **CH-4 — Revocation vs auth-backend outage** (verifies c+i). N live streams, ≥2 principals; (a) revoke one token; (b) blackhole the auth backend. Success: (a) revoked principal's streams terminate within one heartbeat tick, others survive; (b) no stream dies inside the grace window during an outage; post-grace terminations carry a distinct reason; re-validation QPS is O(cache-refresh), not O(streams×tick). **P0 PR 2; metric assertions re-run P0 PR 4.**
- **CH-5 — Cap exhaustion on shared token** (verifies d+h+j). Drive one principal to the per-principal cap, a second to the global cap. Success: cap+1 `initialize` rejected with an A4 error; no live session/stream evicted; streamed POSTs debit the same budget as GET channels. **P0 PR 2** (session-cap-rejection half P0 at **PR 1** if session caps ship there — PR 1's `mcp.session.reject` cap-hit audit verb implies they do).
- **CH-6 — Worker-pool starvation** (verifies h). Saturate held-open responses (GET + streamed POSTs) at exactly the caps; drive plain REST + legacy plain-POST MCP concurrently. Success: plain-path latency within no-stream baseline (caps provably below the httplib pool size with margin); zero timeouts. **P0 PR 2.**
- **CH-7 — Kill switch + bounded shutdown**. (a) SIGTERM with live streams + in-flight bridge subscription → stop closes/joins all streams within a bound, no hang (cf. the PR #1311 shutdown-deadlock lesson), no orphaned `ExecutionEventBus` subscriber. (b) Restart under `--mcp-no-streaming`, client presents a prior session id → defined, documented response. (c) `--mcp-disable` stub answers GET/DELETE. **(b)+(c) P0 PR 1; (a) P0 PR 4.**
- **CH-8 — Session fixation + cross-principal oracle** (verifies a). `initialize` carrying a client-supplied `Mcp-Session-Id` is never adopted (fresh ≥128-bit id minted); principal-A's valid id under principal-B's token returns a 404 byte-identical to unknown-id, no gross timing divergence; per-request token auth enforced on every method. **Critical, P0 PR 1.**
- **CH-9 — Origin misconfig not silent** (verifies e). Hostile / absent / allowlisted Origin plus an empty/typo'd allowlist, across POST/GET/DELETE. Hostile rejected on every method; absent allowed (credential required); every reject visible in reason-labeled metrics. **Behavior P0 PR 1; metric assertion P0 PR 4.**
- **CH-10 — Reverse-proxy SSE buffering.** Stream through nginx with default buffering; reproduce the stall, prove the documented proxy config fixes it; heartbeats let the server detect the dead channel. **P1 PR 5.**
- **CH-11 — Strict-client 202 empty body.** A strict JSON-RPC client library sends a notification; 202-with-empty-body accepted without parse error. **P0 PR 5.**
- **CH-12 — Cancelled ≠ cancelled** (verifies j). `notifications/cancelled` mid-execution: close-frame states execution continues; execution completes and is durably recorded; cancellation audited. **Frame P0 PR 3; audit assertion P0 PR 4.**
- **CH-13 — Session soak** (verifies d). Nightly: thousands of mint/expire cycles + ring churn + compound CH-2+CH-4 (ring wrap + disconnect + revocation-during-resume); RSS bounded, TTL reaps idle sessions. **P2 nightly.**

## Accepted risk (no scenario)

Dual-stack replay-window divergence (`/api/v1/events` vs the MCP session ring retaining different histories for one execution): accepted — durable stores remain the forensic truth; PR 5 documents it in one sentence.
