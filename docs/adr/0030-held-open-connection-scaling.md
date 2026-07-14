---
status: proposed
date: 2026-07-13
owner: "@dgr (Dave Rae)"
depends-on: >-
  1005-headless-platform-use-case-engines (the machine-consumer surface this streaming
  transport serves; Decision 15 of `docs/adr-1005-execution-plan.md` is the MCP Streamable
  HTTP transport whose PR-2 rung exposed the ceiling recorded here).
related: >-
  #2056 (concurrent-stream caps for `GET /api/v1/events` — the follow-up this ADR
  supersedes in scope: the answer is not "cap the siblings too", it is "stop rationing a
  self-inflicted scarcity"). ADR-0031 (presentation / core / engine as separate binaries —
  the decomposition that makes the durable fix in Decision 4 reachable: presentation becomes
  its own binary, so its runtime is a free choice). `docs/architecture.md`
  (Operator/Server/Agent/Gateway boundaries this ADR would move). The Erlang gateway
  (`docs/erlang-gateway-build.md`) remains the **southbound** fleet edge and is unchanged by
  this ADR.
---

# ADR-0030 — Held-open connections must not own a worker thread

## Context

The server's HTTP surface is cpp-httplib, which is **thread-per-connection**. A response
held open — any Server-Sent Events stream — occupies one worker thread for its entire life,
blocked in `cv.wait_for`. It is not doing work; it is *waiting*, and it is waiting while
holding a thread.

Four surfaces hold responses open today, all on the same shared pool:

| Surface | Auth | Purpose |
|---|---|---|
| `GET /mcp/v1/` | token (principal-bound session) | the MCP Streamable HTTP channel (track 2f PR 2) |
| `GET /api/v1/events` | token (`Execution:Read`) | the agentic execution-event stream |
| `GET /sse/executions/{id}` | cookie | the dashboard executions drawer |
| `GET /events` | **none** | the legacy dashboard live-update stream |

**Provenance.** Every claim below about `StreamBudget`, the `GET /mcp/v1/` channel and the
admission arithmetic is stated **as of `feat/mcp-streamable-http-pr2` @ 3bac4647** — the branch
this ADR lives on. `stream_budget.hpp` and the MCP GET channel do not exist on `dev`, so a
reader checking these claims against a `dev` checkout will not find them; check them against
that branch.

Track 2f PR 2 added the first admission budget for these (`stream_budget.hpp`), and in doing
so did the arithmetic nobody had done before. The result is the reason this ADR exists:

- httplib's default pool is `max(8, cores−1)` base, growing to 4× that. On an ordinary
  8-core host that is **32 threads**.
- Holding back a plain-REST reserve (8) and allowing for the one draining provider a stream
  can leave behind during a takeover (×2), the affordable number of concurrent streams is
  **12**.
- The platform's own design notes size it for **"hundreds of agentic clients per server"**
  (`server/core/src/event_bus.hpp:83`).

**The transport can serve 12. The platform is designed for hundreds.** The cap is not a
safety feature; it is the visible edge of a self-inflicted scarcity. Rationing it more
carefully — capping the other three surfaces so they cannot starve each other — makes the
accounting honest but leaves the ceiling exactly where it is.

A second fact, surfaced by the same arithmetic: `GET /events` performs **no authentication**
and enqueues without a cap. An unauthenticated caller can therefore pin worker threads and
grow an unbounded per-connection queue. That is a pre-auth denial-of-service on today's
`dev`, independent of anything in track 2f, and it is filed separately — but it is the
sharpest illustration of why "a held-open connection costs a thread" is the wrong primitive
to build a fleet-scale platform on.

**Who should hold these connections was never asked.** Track 2f's design record mentions the
Erlang gateway exactly twice, both times to *rule it out as a risk* ("the Erlang gateway has
no `/mcp` routing — verified"; "Gateway unaffected"). The question asked was "does this break
the gateway?" The question never asked was "should the C++ server be **holding** these
connections at all?" That omission is the substance of this ADR. The answer it records
(Decision 4) is **the presentation binary** — not the gateway, which stays southbound.

## Decision

**1. One admission budget across every held-open response, as a guard rail — not a ration.**
The invariant worth stating is: *held-open connections can never starve plain
request/response traffic.* That cannot be stated truthfully with per-surface silos, so every
surface that holds a response open takes a lease from the same counter
(`yuzu::server::detail::StreamBudget`). This is Decision 15(h) of the ADR-1005 execution
plan, and it is correct.

**2. Derive the worker pool from the intended stream count — not the cap from the accidental
pool.** This inverts the arrow. A thread blocked in `cv.wait_for` burns **zero CPU** — the only
periodic cost is one wakeup per heartbeat interval per stream — and its resident cost is a
fraction of the 8 MB stack, which is virtual. What that fraction actually *is* on our
platforms is **not yet measured, and this ADR does not estimate it**: a **measured
per-held-stream RSS baseline (Linux glibc, MSVC, macOS) is required before anyone sizes
`--max-sse-streams` or a worker pool off it.** Sizing a fleet-scale resource off an
unmeasured constant is how the 12-stream ceiling happened in the first place. The shape of
the rule stands regardless of the number:

```
workers = kMaxProvidersPerStream × target_streams + plain_rest_reserve
```

The operator declares the streams they intend to serve; the pool is sized to honour it. The
budget then binds only under abuse or genuine over-subscription, which is what a cap is for.

**3. Expose utilisation, not per-surface counters.** The number an operator needs is
*held-open responses ÷ pool capacity* — it is the signal that says "raise the target", and no
per-surface gauge can express it.

**4. Record the ceiling, and name the durable fix.** (2) buys one to two thousand streams
before thread memory and scheduler pressure become the binding constraint (the exact figure
awaits the measured baseline in (2)). Beyond that, the answer is not a bigger pool — it is to
**stop owning a thread per stream**. The durable fix is **an asynchronous presentation
binary**:

- **Hold the connections in presentation, on an async C++ runtime (Drogon).** ADR-0031 splits
  presentation into its own binary, which makes its runtime a free choice; Drogon's
  non-blocking event loop and coroutines remove the thread-per-held-stream cost **in-language**
  — the existing HTMX renderers and MCP framing port across without a ~5k-line re-home into
  another runtime, and N stateless presentation replicas can sit behind the one MCP origin.
  Core's HTTP runtime can remain as it is, behind short-lived bounded calls. This is ballot
  A3 (amended), and it is **conditional on the G10 build canary**: Drogon is a heavyweight new
  dependency landing on the most fragile part of the build (Windows MSVC static linking, the
  #375 history), so it faces a vcpkg-port canary across the full matrix before it is ratified.
  Durable session identity and the replay ring live in core/Postgres, not in presentation.
- **Not the Erlang gateway.** The BEAM would win the same ceiling, but it would mean re-homing
  the MCP framing and the HTMX renderers into a second language. The gateway stays what it is:
  the **southbound** fleet edge, unchanged by this ADR.
- **Not a reverse proxy.** An SSE proxy (nginx/envoy) holds one upstream connection per client,
  so the C++ pool still pins a thread per stream — and buffering proxies break SSE outright.
  The connection-holder must speak MCP itself.

**Constraint that shapes the choice:** the MCP spec requires POST and GET on the **same
endpoint** (`/mcp/v1/`). Streaming therefore cannot be moved to a side port or a separate
component on its own — it moves with the **whole** MCP surface, and that surface is
presentation. This is why the durable fix is a property of the presentation binary rather
than a box inserted in front of the server.

## Consequences

- Track 2f PR 2 implements (1), (2) and (3). The MCP stream cap stops being a capacity limit
  (12) and becomes an anti-abuse backstop against a pool sized for the declared workload.
- The dashboard and `/api/v1/events` are bounded for the first time — closing a starvation
  path that exists on `dev` today, before MCP streaming ships at all.
- (4) is **not** built here. It rides ADR-0031's decomposition (presentation as its own
  binary) and the G10 Drogon build canary; it needs its own governance and a migration that
  strands no existing deployment. The Erlang gateway's role does not change.
- Until (4) lands, the honest statement to an operator is: *streams are cheap but not free;
  size `--max-sse-streams` for your fleet **off a measured baseline, not an estimate**, watch
  utilisation, and know the ceiling is thread-count.*

## Alternatives considered

- **Cap the sibling surfaces and stop there** (the original #2056 shape). Makes the
  accounting truthful and the guarantee real, but leaves the ceiling at 12 on a default box.
  Rejected as insufficient on its own; adopted as one half of the answer, alongside (2).
- **Raise the pool without a shared budget.** Removes the immediate pain and leaves no
  guarantee at all: with no counter across surfaces, nothing prevents held-open connections
  from consuming the whole pool. Rejected — a bigger unbounded resource is still unbounded.
- **Long-poll instead of SSE.** Would avoid holding a thread indefinitely, but the MCP spec
  mandates the SSE channel with `Last-Event-ID` resume, and long-poll re-introduces the gap
  semantics the replay ring exists to eliminate. Rejected.
- **Move only the dashboard's streams off the pool.** Halves the problem and leaves the
  agentic surface — the one the platform's scale target is actually about — on the ceiling.
  Rejected.
