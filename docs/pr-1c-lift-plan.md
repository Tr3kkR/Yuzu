# PR 1c — lift production call sites onto `yuzu::transport`

Tracking: #376 PR 1c row of `docs/adrs/0001-quic-transport-msquic-quicer.md`.

## Goal

Replace direct `grpc::*` use in production call sites with the abstraction
landed in PR 1a/1b. Once this lands the gRPC backend becomes plug-replaceable
by the msquic backend (PR 3) without touching `agent.cpp`, `server.cpp`,
`agent_service_impl.cpp`, `agent_registry.cpp`, or `gateway_service_impl.cpp`.

The refactor is wire-equivalent **through PR 1c-6** — no behaviour change,
no protocol change, no operator-visible flag change for the *retained*
surfaces. The wire-equivalence framing was softened at PR 1c-5 (#376
grill-me 2026-05-11): native-QUIC patterns (per-command stream IDs,
persistent multiplexed channels, 0-RTT resumption, stream priority) are
the *purpose* of moving off gRPC, not gRPC-equivalent semantics encoded
on QUIC. Designing those patterns now — before msquic is exercised —
produces primitives that don't survive contact with the real wire. The
native-QUIC redesign therefore lands in a dedicated PR post-PR-3
(msquic backend), at which point the abstraction shape can be A/B-tested
against actual QUIC features.

PR 1c-5 itself drops `:50052` and the four `--management*` CLI flags
atomically (BREAKING change — no operator-facing :50052 to deprecate
gradually since the `ManagementService` C++ impl has been an empty
placeholder since v0.1).

CI must remain green at every sub-PR merge; the existing UAT
(`scripts/start-UAT.sh`) is the integration ledger.

## Scope inventory

### RPCs to lift (16 total)

| Service | RPC | Kind | Direction | Touches |
|---|---|---|---|---|
| `yuzu.agent.v1.AgentService` | Register | unary | agent → server | agent.cpp client; agent_service_impl.cpp server |
| | Heartbeat | unary | agent → server | agent.cpp; agent_service_impl |
| | ExecuteCommand | server-stream | mgmt → server (AgentService) | server.cpp callout (rare); agent_service_impl |
| | Subscribe | bidi | agent ↔ server | agent.cpp (PRIMARY); agent_service_impl |
| | ReportInventory | unary | agent → server | agent.cpp; agent_service_impl |
| | CheckForUpdate | unary | agent → server | agent.cpp; agent_service_impl |
| | DownloadUpdate | server-stream | agent → server | agent.cpp; agent_service_impl |
| `yuzu.server.v1.ManagementService` | ListAgents | unary | mgmt client → server | server.cpp impl |
| | GetAgent | unary | mgmt | server.cpp impl |
| | SendCommand | server-stream | mgmt → server (fanout to agents) | server.cpp; agent_registry forwarder |
| | WatchEvents | server-stream | mgmt | server.cpp |
| | QueryInventory | unary | mgmt | server.cpp |
| `yuzu.gateway.v1.GatewayUpstream` | ProxyRegister | unary | gateway → server | gateway_service_impl |
| | BatchHeartbeat | unary | gateway → server | gateway_service_impl |
| | ProxyInventory | unary | gateway → server | gateway_service_impl |
| | NotifyStreamStatus | unary | gateway → server | gateway_service_impl |

Server-streaming RPCs use `BidiStream` with the read-half disabled by an
immediate `writes_done()` from the client — `transport.hpp` describes this
pattern explicitly.

### Direct gRPC use to remove

* `agents/core/src/agent.cpp` — `grpc::ChannelArguments`, `grpc::ChannelCredentials`,
  `grpc::CreateCustomChannel`, `pb::AgentService::Stub`, `grpc::ClientContext`,
  `grpc::ClientReaderWriter` (Subscribe), reconnect loop wired around `grpc::Channel::WaitForConnected`.
* `server/core/src/server.cpp` — `grpc::EnableDefaultHealthCheckService`,
  `grpc::ServerCredentials`, `grpc::SslServerCredentialsOptions`,
  `grpc::ServerBuilder`, `grpc::Server` (×2: agent_server_, mgmt_server_),
  `gw_mgmt_channel_` (gateway forwarding).
* `server/core/src/agent_service_impl.{hpp,cpp}` — `pb::AgentService::Service` inheritance;
  every method takes `grpc::ServerContext*` + grpc::Status. Replace with
  free-standing handler functions registered as transport handlers.
* `server/core/src/agent_registry.cpp` — `gw_mgmt_stub_->SendCommand()` for gateway
  forwarding; `subscribe_streams_` map of `grpc::ServerReaderWriter`.
* `server/core/src/gateway_service_impl.{hpp,cpp}` — `gw::GatewayUpstream::Service`
  + `::yuzu::server::v1::ManagementService::Service` inheritance.

## Sub-PR ladder

Each sub-PR is independently mergeable, leaves CI green, and keeps the rest
of the codebase on the existing path. No long-lived feature branch within
the branch — land one, rebase the next.

### PR 1c-1 — Adapter shim + ProtoMessage codegen helpers

> **Merged 2026-05-08.** Adapter helpers shipped in
> `transport/include/yuzu/transport/proto_adapter.hpp`
> (`register_unary_pb<Req,Resp>`, `OwnedProtoMessage<T>`, `read_pb`/
> `write_pb`), not the originally-planned per-side
> `server/core/src/transport_adapters.{hpp,cpp}` /
> `agents/core/src/transport_adapters.{hpp,cpp}` files. The per-side
> files were not needed because the typed-proto wrap was generic
> enough to live alongside the abstraction.

* Add `server/core/src/transport_adapters.{hpp,cpp}` (and matching
  `agents/core/src/transport_adapters.{hpp,cpp}`) that wrap the
  per-RPC pb message-pair construction so handler bodies stay tidy:
  ```cpp
  template <typename Req, typename Resp, typename Fn>
  UnaryHandler make_unary_handler(Fn&& f);  // f: (CallContext, Req&, Resp&) -> Status
  ```
* Define helpers for `register_unary_pb<RegisterRequest, RegisterResponse>(listener, "yuzu.agent.v1.AgentService/Register", f)`.
* No call-site changes yet. Tests: round-trip a no-op handler through
  the adapter to prove the templates compile + dispatch correctly.
* Risk: low. Pure addition.

### PR 1c-2 — Server-side: lift `agent_service_impl` (agent-facing service)

> **Merged 2026-05-08** (commits d19680b + f8b944d). Plan/actual
> divergences worth noting:
> * **YUZU_ALLOW_INSECURE_TLS gate** stayed at the CLI layer (`main.cpp`)
>   — `cfg_.allow_one_way_tls` is passed as a bool argument to the new
>   `build_transport_credentials()`. The transport layer never reads
>   the env-var directly; the abstraction boundary is honoured.
> * **`grpc::EnableDefaultHealthCheckService(true)` deletion**: confirmed
>   removed. Yuzu does not consume gRPC health checks; readiness is HTTP
>   `/readyz` (which now also gates on `agent_listener_->is_serving()`
>   per gov round 7 SRE OBS-1).
> * **Mgmt + gateway-upstream services** stayed on `grpc::ServerBuilder`
>   bound to their own ports — PR 1c-5 lifts those next. Two listener
>   objects with parallel shutdown until 1c-5 unifies them.


* Drop `pb::AgentService::Service` inheritance from `AgentServiceImpl`.
  Keep the class as a stateful holder of dependencies (response_store,
  rbac, audit, scope_engine, agent_registry, etc.).
* Replace `grpc::Status Register(grpc::ServerContext*, const RegisterRequest*, RegisterResponse*)`
  with `transport::Status Register(const CallContext&, const RegisterRequest&, RegisterResponse&)`,
  and so on for every method. Internals unchanged.
* Add a `register_with(transport::ServerListener& listener)` method that
  calls `listener.register_unary` / `listener.register_bidi_stream` for
  each RPC, wrapping the methods in lambdas that pull the typed proto out
  of the `SerializableMessage` adapter.
* Delete `grpc::EnableDefaultHealthCheckService(true)` — emulate via a
  no-op (Yuzu does not currently use gRPC health checks; readiness lives
  on the HTTP side via /readyz).
* `server.cpp`: replace `grpc::ServerBuilder` for `agent_server_` with a
  `transport::make_server_listener(Backend::Grpc)` + `agent_listener_->start(...)`.
  mTLS material flows through `transport::Credentials`.
* `Subscribe` (bidi): the agent_registry's `subscribe_streams_` becomes a
  map of `BidiStream*` (handler argument); handlers are pure C++ — no
  more `grpc::ServerReaderWriter` references.
* peer_san_identities: populate from gRPC's auth_context inside the
  GrpcServerListener (governance round 5 deferred). For PR 1c add a
  hook in `transport::CallContext` and have the gRPC backend fill it from
  `grpc::AuthContext::FindPropertyValues("x509_subject_alternative_name")`.
* YUZU_ALLOW_INSECURE_TLS gate: read inside transport per ADR row.
  Move the existing `server/core/src/insecure_tls_gate.hpp` consult into
  `Credentials` validation.
* Tests: extend integration tests to exercise Register + Heartbeat through
  the new path. UAT must round-trip.
* Risk: moderate. Touches the server's primary RPC handlers but leaves
  agent.cpp untouched (still on raw gRPC stub against the same wire).

### PR 1c-3 — Agent-side: lift `agent.cpp` (Register, Heartbeat, ReportInventory, CheckForUpdate)

* Replace `grpc::CreateCustomChannel` with `transport::make_channel(Backend::Grpc, ...)`.
* `pb::AgentService::Stub` goes away; calls become
  `channel->unary("yuzu.agent.v1.AgentService/Heartbeat", ctx, req, resp)`.
* Reconnect loop pivots from the existing exponential-backoff loop onto
  `BackoffPolicy` + `Channel::wait_for_connected()`.
* Cancel paths (`subscribe_ctx_.TryCancel()` / `heartbeat_ctx_.TryCancel()`)
  pivot onto `std::stop_source` threaded into `CallContext::cancel`.
* Defer Subscribe to the next sub-PR.
* Tests: add agent-side integration test that drives Heartbeat through
  a stub server using the abstraction; UAT.
* Risk: moderate.

### PR 1c-4 — Agent-side: lift Subscribe bidi + DownloadUpdate server-stream

* Replace `grpc::ClientReaderWriter` with `BidiStream`.
* Subscribe is the most critical path on this whole branch — every
  command dispatch flows through it. Round-trip tests must include
  multi-frame fan-out, peer-FIN handling, replay timing window
  (existing logic), and graceful reconnect.
* DownloadUpdate adapts naturally — agent calls `bidi_stream(...)`, then
  `writes_done()` and reads chunks until peer half-close.
* Risk: high — the Subscribe migration is the canonical bug-prone point.
  Land with the dual-stack `--transport=grpc` flag still defaulting to
  grpc backend, and the equivalent server side already on transport
  abstraction (PR 1c-2 is a hard predecessor).
* **Status**: PR 1c-4 COMPLETE as of 2026-05-10. Commits: (i) `0b5f89c`
  #916 contract softening, (ii) `7269ba7` Subscribe + DownloadUpdate lift,
  hardening rounds `98f25f9` + `3e14517`, keepalive migration `1c05ce7`
  (closes SRE-1), (iii) cleanup. Tests at
  `tests/unit/test_agent_subscribe_lift.cpp` (5 cases / 102 assertions).
* **Hard predecessors** (all closed as of 2026-05-09):
  - ✅ **UP-14** (per-call dispatcher-thread fanout) — closed by **#904**
    bounded dispatcher pool (2026-05-09). Subscribe lift no longer
    spawns a per-stream OS thread on the server; pool size is operator-
    controlled via `ListenerOptions::bidi_dispatcher_pool_size`.
  - ✅ **#902** (UP-8) — DownloadUpdate idle-read deadline at the
    transport layer. Closed 2026-05-09 by adding an optional
    `std::chrono::milliseconds deadline` parameter to
    `BidiStream::read` (default zero = no deadline) and arming
    `DownloadUpdate`'s request-frame read with 30 s. Pool slots
    release after the idle deadline so legitimate concurrent calls
    are no longer starved by stalled peers. Tests at
    `tests/unit/transport/test_transport_smoke.cpp` `[transport][bidi][deadline]`:
    server-side timeout, client-side timeout, happy-path no-fire.
    Wire-status caveat on the gRPC backend documented in the
    `BidiStream` contract block in
    `transport/include/yuzu/transport/transport.hpp`: `TryCancel`
    forces peer-observed status to `Cancelled` regardless of the
    handler-supplied final status; the local `DeadlineExceeded`
    signal via `final_status()` is what frees the pool slot.
  - ✅ `parse_target_address` agent-side test coverage — closed
    2026-05-09 by `1af8ab5` (`tests/unit/test_parse_target_address.cpp`,
    22 cases / 44 assertions; rejection-path matrix + IPv6 happy
    paths + `static_assert(noexcept(...))` contract pin).
  - ✅ Heartbeat per-cycle `stop_source` round-trip test — closed
    2026-05-09 by `tests/unit/test_heartbeat_cancel_pattern.cpp`
    (3 tests, 24 assertions, tag `[agent][heartbeat][cancel]`). The
    suite pins the three production invariants the agent.cpp
    connection loop relies on: (a) `std::optional<std::stop_source>::emplace`
    REPLACES on each cycle so the new heartbeat thread observes a
    fresh, not-stop_requested token; (b) an in-flight unary
    threading its `CallContext::cancel` from the per-cycle source
    returns `Cancelled` promptly when `request_stop()` fires (via
    `GrpcChannel::unary`'s `stop_callback` → `gctx_.TryCancel()`
    chain); (c) cycle-1's `request_stop` does not leak into a real
    cycle-2 unary dispatched with the freshly-`emplace`d source.
    The suite documents that the gRPC backend's
    `populate_call_context_from_grpc` does not currently wire a
    server-side stop_token; the `transport.hpp` contract has been
    softened to backend-best-effort (#916) so this gap is intentional
    rather than a deviation. Server handlers detect peer disconnect via
    `BidiStream::read()` returning false, which is the canonical
    cross-backend pattern.

#### PR 1c-4 governance follow-ups (shipped 2026-05-10)

After PR 1c-4 merged, a closet-clean session shipped 6 follow-up
commits closing the deferred governance backlog (range `62bf9d2..06cf8d5`),
followed by `/governance` Round-1 hardening (`7cf8126`) which closed
the BLOCKING items the closet-clean session itself produced.

| Issue | Commit | Description |
|---|---|---|
| #915 (P1) | `4fb435c` | Negative-deadline contract clarified to clamp-to-zero (UP-110 / arch-S1) |
| #929 (P2) | `4fb435c` | `[[nodiscard]]` on `read_pb` / `write_pb` |
| #926 (P2) | `4f1d2c5` | qe S-2 nullptr open_bidi unit test |
| #927 (P2) | `4f1d2c5` | qe S-3 concurrent shared-stream writes unit test |
| #914 (P1) | `0143cee` | NTP-step sanity log on unary DeadlineExceeded + MSVC chrono doc |
| #911 (P0) | `d34a091` | `BidiStream::write` per-frame deadline; server `DownloadUpdate` 30 s chunk-write deadline; agent `Updater` 5 s request-frame write deadline |
| #924 (SRE-2) | `d34a091` | Agent OTA chunk-deadline counter (`yuzu_agent_ota_chunk_deadline_total{phase}`) |
| #912 (P0) | `edcea4b` | `TransportMetricSink` saturation hooks + `bidi_pool_size`/`in_flight`/`saturated_total` metrics |
| #905 | `edcea4b` | `ServerTransportMetricSink` wiring at agent-listener creation |
| #925 (SRE-3) | `edcea4b` + `7cf8126` | Reconnect-reason label split (channel_fault / peer_halfclose / stream_open_failed / enrollment_pending) + 3 Grafana alerts |
| #913 (P0) | `06cf8d5` | Per-peer DownloadUpdate token bucket rate limit (UP-116) |
| #916 | `0b5f89c` | Server-side `CallContext::cancel` contract softened to backend-best-effort — closed on GitHub manually |

Round-1 hardening (`7cf8126`) closed all BLOCKING governance items
(4 docs + 1 metric describe dedup + 1 test-coverage drift) and folded
in the load-bearing SHOULDs (in_flight contract drift, enrollment_pending
4th label, alert annotation language). Remaining SHOULD/NICE items
filed as **#932-#938**:

| Issue | Description |
|---|---|
| #932 | UP-209 final_status wedge on dead server (P1) |
| #933 | architect S-1 admit_download_update public surface (P2) |
| #934 | UP-206 slow-link compound lockout — operator-tunable deadline + don't-consume-token-on-deadline (P1) |
| #935 | sec MEDIUM-1 + UP-201/2/3/5 + sre Q10 — bucket cap + size metric + multi-server HA gap (P1) |
| #936 | qe Q4/Q5/Q6 — ServerTransportMetricSink + OTA counter + reason-label test coverage (P2) |
| #937 | doc SHOULD-FIX backlog (P2) |
| #938 | code SHOULD/NICE backlog (P2) |

### PR 1c-5 — Server-side: lift `gateway_service_impl` + drop `ManagementServiceImpl` + lift `gw_mgmt_channel_`

> **Merged 2026-05-11.** Three actions in one commit chain:
>
> 1. `GatewayUpstreamServiceImpl` lifted onto `transport::ServerListener`
>    (4 unary RPCs via `register_unary_pb<>`).
> 2. `ManagementServiceImpl` **deleted** — placeholder, never had method
>    overrides, every RPC returned `UNIMPLEMENTED`. The four `--management*`
>    CLI flags and the four `mgmt_tls_*` ServerConfig fields are dropped
>    atomically. BREAKING change (CHANGELOG entry).
> 3. `gw_mgmt_stub_` lifted onto `transport::Channel`; `forward_gateway_pending`
>    rewritten as a `bidi_stream` with immediate `writes_done()` on the
>    request side (server-streaming-as-bidi). Retry: **D.1** — detached
>    `std::thread` per command preserved (maps onto a per-command QUIC
>    stream post-PR-3); on `Unavailable`, `AgentRegistry::reenqueue_gateway_pending(gp)`
>    increments `gp.attempts` and re-queues (3-strike cap); non-`Unavailable`
>    failures drop with `yuzu_gateway_forward_dropped_total{reason=...}`.
> 4. Shutdown unified to two sequential `transport::ServerListener::shutdown()`
>    calls (agent then gateway-upstream); the 5s `mgmt_server_->Shutdown(deadline)`
>    workaround is gone.
>
> Wire-equivalence framing softened — see the Goal section. Native-QUIC
> redesign moved to a post-PR-3 PR.

* Risk: moderate. Gateway-mode only; UAT covers it. CI matrix re-runs
  the integration script with `--management` removed.

### PR 1c-6 — Cleanup + #896 readiness probe + #897 trailing-metadata scrub

* #896: wire `is_serving() && bound_endpoint().port != 0` into /readyz.
  Today's /readyz signal predates the abstraction; align it.
* #897: extend the inbound-scrub helper to trailing metadata (matching
  `Status::detail` policy) once the gRPC server-side delivers it through
  the abstraction in PR 1c-2.
* Delete dead helpers: any remaining `grpc::*` includes in lifted files.
* Risk: low.

## Acceptance criteria per sub-PR

* `meson compile -C build-<os>` clean on Linux, macOS, Windows.
* `meson test -C build-<os> --suite server --suite agent --suite transport` all green.
* `bash scripts/start-UAT.sh` round-trips: register, heartbeat, command
  fanout, gateway path, inventory.
* Governance pipeline (`/governance <range>`) green — no CRITICAL/HIGH
  findings.

## Order of operations + branch topology

The branch is `feat/quic-transport`. Each sub-PR is a commit (or commit
chain) on this branch. We **do not** open separate PRs against `main`
during the lift — the whole branch lands in a single grand merge after
PR 9.

Ordering is hard-sequential because of cross-side dependencies:
1. 1c-1 (adapter helpers)
2. 1c-2 (server-side lift) — must precede 1c-3/1c-4 (agent-side lift sees the same wire)
3. 1c-3 (agent unary lift)
4. 1c-4 (agent Subscribe lift) — server-side for Subscribe lives in 1c-2
5. 1c-5 (gateway / management lift)
6. 1c-6 (readiness probe + cleanup)

## Constraints carried in from earlier sub-PRs

These come from the standing transport contracts and must be honoured by
every sub-PR that adds a new call site:

* **Status::detail symmetric scrub** — both backends route through
  `yuzu::transport::sanitise_status_detail`. Every new handler that emits
  a Status MUST have its detail go through the helper or hit the round-5
  cons-G4-1 audit footprint.
* **`bound_endpoint()` requires `is_serving()` cross-check** — readiness
  callers gate on the conjunction (governance UP-40 / SRE-O2). #896
  closes the production readiness wiring in 1c-6.
* **`on_unexpected_dispatch_throw(backend, method, kind)`** —
  `TransportMetricSink` integration is required so the operator-visible
  dispatcher-throw signal works for production traffic, not just tests.
  Sub-PR 1c-2 wires the server's `prometheus-cpp` registry into a sink
  that fans out to existing `yuzu_server_transport_*` counters.

## Open questions

1. **Backoff policy**: agent.cpp's existing reconnect uses 2^n with a
   5-minute cap. `BackoffPolicy` defaults to multiplier 1.6, max 30 s.
   Decide in 1c-3 whether to bump `BackoffPolicy` defaults or keep the
   agent-side wrapper. Bias: bump defaults — gateway also wants longer
   max delays.
2. **gRPC channel args** (`GRPC_ARG_KEEPALIVE_*`): not exposed in the
   abstraction. Either widen `BackoffPolicy` / add a `KeepaliveOptions`
   struct, OR keep the args inside the gRPC backend with sensible defaults
   that match agent.cpp:614-618. Bias: latter — msquic has different
   keepalive primitives; abstracting now is premature.
3. **Health check service**: gRPC's default health-check is currently
   enabled. Yuzu does not consume it (we have HTTP /readyz). Confirm in
   1c-2 we can drop it without breaking any out-of-tree tooling.

## Memory + tracking

When a sub-PR lands, update both:
* `docs/adrs/0001-quic-transport-msquic-quicer.md` — PR 1c row sub-bullets
* `~/.claude/projects/-Users-nathan-Yuzu/memory/project_quic_transport_branch_2026-05-08.md`
  — branch state + next concrete step
