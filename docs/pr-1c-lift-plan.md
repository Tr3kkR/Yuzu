# PR 1c — lift production call sites onto `yuzu::transport`

Tracking: #376 PR 1c row of `docs/adrs/0001-quic-transport-msquic-quicer.md`.

## Goal

Replace direct `grpc::*` use in production call sites with the abstraction
landed in PR 1a/1b. Once this lands the gRPC backend becomes plug-replaceable
by the msquic backend (PR 3) without touching `agent.cpp`, `server.cpp`,
`agent_service_impl.cpp`, `agent_registry.cpp`, or `gateway_service_impl.cpp`.

The refactor is wire-equivalent — no behaviour change, no protocol change,
no operator-visible flag change. CI must remain green at every sub-PR
merge; the existing UAT (`scripts/start-UAT.sh`) is the integration ledger.

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

### PR 1c-5 — Server-side: lift `gateway_service_impl` + `ManagementServiceImpl` + gw_mgmt_channel_

* Same pattern as 1c-2 for the management + gateway-upstream services.
* `agent_registry::gw_mgmt_stub_` becomes a `transport::Channel` for the
  gateway's `ManagementService::SendCommand` server-stream.
* Forwarding pumping (`forward_gateway_pending`) becomes a `BidiStream`
  read-loop with writes_done() on the client side.
* Risk: moderate. Gateway-mode only; UAT covers it.

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
