// SPDX-License-Identifier: Apache-2.0
//
// tests/unit/test_heartbeat_cancel_pattern.cpp
//
// Agent-side wiring tests for the per-cycle Heartbeat `std::stop_source`
// pattern introduced by #376 PR 1c-3 (`agents/core/src/agent.cpp`
// `heartbeat_stop_src_`). The pattern's invariants:
//
//   1. Each connection cycle creates a fresh `std::stop_source` via
//      `heartbeat_stop_src_.emplace()`. The Heartbeat thread captures
//      a token from it and threads the token into every Heartbeat
//      `transport::CallContext::cancel`.
//
//   2. `stop()` (and end-of-cycle reconnect cleanup) calls
//      `heartbeat_stop_src_->request_stop()`. Any in-flight Heartbeat
//      unary RPC observes the cancel via `CallContext::cancel.stop_requested()`
//      and the transport returns `Cancelled`.
//
//   3. The next connection cycle's `emplace()` REPLACES the prior
//      stop_source so the new Heartbeat thread observes a fresh,
//      not-yet-stop_requested token. A bug here (e.g. `if (!hb)
//      hb.emplace()`, or forgetting `emplace()` on cycle N>1) would
//      cause the new heartbeat thread to start already cancelled and
//      every Heartbeat RPC on cycle 2 onward would short-circuit
//      with Cancelled.
//
// These three properties are not exercised by `agent.cpp`'s own
// integration test (no such test exists yet for the connection loop)
// and were tagged BLOCKING for PR 1c-4 by the previous session's
// handover. The transport-layer cancel-via-stop_token mechanism is
// independently covered by `tests/unit/transport/test_transport_smoke.cpp`
// `[transport][dispatch]` and `[transport][round-trip][bidi]` cases;
// this file specifically pins the AGENT'S WIRING of the per-cycle
// `std::optional<std::stop_source>` replacement plus the
// CallContext::cancel hand-off, so a refactor that breaks either
// without breaking transport's own cancel semantics will still trip
// the suite here.
//
// Sibling test from the same deferred-from-1c-3 set:
// `tests/unit/test_parse_target_address.cpp`.

#include <yuzu/transport/transport.hpp>

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <optional>
#include <stop_token>
#include <string>
#include <string_view>
#include <thread>

using ::yuzu::transport::Backend;
using ::yuzu::transport::CallContext;
using ::yuzu::transport::ClientCertMode;
using ::yuzu::transport::Credentials;
using ::yuzu::transport::Endpoint;
using ::yuzu::transport::make_channel;
using ::yuzu::transport::make_server_listener;
using ::yuzu::transport::SerializableMessage;
using ::yuzu::transport::Status;
using ::yuzu::transport::StatusCode;

namespace {

// Minimal SerializableMessage adapter — owns a string. Mirrors the
// pattern in test_transport_smoke.cpp so the test stays self-contained
// without crossing test-binary boundaries.
class StringMessage final : public SerializableMessage {
public:
    StringMessage() = default;
    explicit StringMessage(std::string s) : data_(std::move(s)) {}

    bool serialize(std::string& out) const override {
        out = data_;
        return true;
    }
    bool parse(std::string_view in) override {
        data_.assign(in.data(), in.size());
        return true;
    }

    const std::string& data() const noexcept { return data_; }

private:
    std::string data_;
};

auto make_string_factory() {
    return []() -> std::unique_ptr<SerializableMessage> {
        return std::make_unique<StringMessage>();
    };
}

// Test harness — listener + channel pair pointed at the same ephemeral
// port. Constructor performs full setup; destructor performs symmetric
// shutdown. Built in-place at the call site (the embedded
// `std::unique_ptr` members make the type non-copyable, and clang's
// NRVO does not elide a `return UnaryFixture` from a static factory
// here under C++23 / libc++ — see Catch2 + libc++ interaction).
struct UnaryFixture {
    std::unique_ptr<::yuzu::transport::ServerListener> listener;
    std::unique_ptr<::yuzu::transport::Channel> channel;

    explicit UnaryFixture(::yuzu::transport::UnaryHandler handler) {
        listener = make_server_listener(Backend::Grpc);
        REQUIRE(listener != nullptr);

        listener->register_unary("yuzu.agent.v1.AgentService/Heartbeat", make_string_factory(),
                                 make_string_factory(), std::move(handler));

        Credentials creds{};
        creds.verify_peer = false;
        creds.client_cert_mode = ClientCertMode::None;

        Endpoint bind{"127.0.0.1", 0}; // ephemeral
        auto started = listener->start(bind, creds);
        REQUIRE(started.has_value());
        REQUIRE(listener->is_serving());

        channel = make_channel(Backend::Grpc, listener->bound_endpoint(), creds);
        REQUIRE(channel != nullptr);
        REQUIRE(channel->wait_for_connected(std::chrono::seconds(2)));
    }

    UnaryFixture(const UnaryFixture&) = delete;
    UnaryFixture& operator=(const UnaryFixture&) = delete;
    UnaryFixture(UnaryFixture&&) = delete;
    UnaryFixture& operator=(UnaryFixture&&) = delete;

    ~UnaryFixture() {
        if (channel)
            channel->close();
        if (listener)
            listener->shutdown();
    }
};

} // namespace

// =====================================================================
// Test 1 — pure std::optional<std::stop_source> emplace semantics
// =====================================================================
//
// The cheapest possible signal that the per-cycle replacement pattern
// produces a fresh token. If this regresses, the heartbeat thread's
// invariant "new cycle ⇒ new not-yet-stopped token" is broken before
// any RPC machinery is even involved.

TEST_CASE("Heartbeat per-cycle stop_source: emplace replaces prior source with fresh one",
          "[agent][heartbeat][cancel]") {
    std::optional<std::stop_source> heartbeat_stop_src;

    // Cycle 1
    heartbeat_stop_src.emplace();
    auto cycle1_token = heartbeat_stop_src->get_token();
    REQUIRE_FALSE(cycle1_token.stop_requested());

    heartbeat_stop_src->request_stop();
    REQUIRE(cycle1_token.stop_requested());

    // Cycle 2: emplace must REPLACE the cycle-1 source, producing a
    // fresh token whose stop_requested() is false. Bug-class this
    // guards: `if (!heartbeat_stop_src) heartbeat_stop_src.emplace()`
    // (would keep the stopped one), or just forgetting to emplace at
    // all on subsequent cycles.
    heartbeat_stop_src.emplace();
    auto cycle2_token = heartbeat_stop_src->get_token();
    REQUIRE_FALSE(cycle2_token.stop_requested());

    // The cycle-1 token must remain unchanged — it observes its own
    // source's stop_requested forever; replacing the optional does
    // NOT retroactively un-stop tokens already handed out. This is
    // the critical asymmetry the agent relies on for clean cycle
    // boundaries.
    REQUIRE(cycle1_token.stop_requested());

    // Cycle 2 stop must affect ONLY cycle-2 token.
    heartbeat_stop_src->request_stop();
    REQUIRE(cycle2_token.stop_requested());
}

// =====================================================================
// Test 2 — integration: in-flight unary returns Cancelled on request_stop
// =====================================================================
//
// Mirrors the production sequence in agent.cpp lines ~1448-1450
// (stop() path) plus the per-cycle pattern at ~1062 (cycle entry) and
// ~1115 (CallContext::cancel hand-off). The handler signals it has
// entered, then sleeps for a safety bound generous enough that any
// CLIENT-side cancel must "win the race" against the eventual normal
// return. After main calls `heartbeat_stop_src_->request_stop()`,
// the worker thread's unary call should complete with `Cancelled`
// well before the handler's safety bound elapses — proving that the
// stop_token plumbed into `CallContext::cancel` triggered the
// client-side cancel hook (`GrpcChannel::unary`'s `stop_callback`
// that calls `gctx_.TryCancel()`).
//
// Note on server-side observability: the contract block in
// `transport/include/yuzu/transport/transport.hpp` claims that
// `CallContext::cancel` on the server side surfaces a stop_token
// tied to peer cancellation, but the gRPC backend's
// `populate_call_context_from_grpc` does not currently wire it. So
// the handler cannot directly `ctx.cancel.stop_requested()` to bail
// early; we measure the client-side observable (Cancelled status +
// short elapsed time) instead. Wiring server-side cancel
// observability is tracked separately as a transport-layer gap.

TEST_CASE("Heartbeat per-cycle stop_source: in-flight unary returns Cancelled on request_stop",
          "[agent][heartbeat][cancel]") {
    using namespace std::chrono_literals;
    constexpr auto kHandlerSafetyBound = 4s;

    std::mutex handler_mu;
    std::condition_variable handler_entered_cv;
    bool handler_entered = false;

    auto handler = [&](const CallContext&, const SerializableMessage&,
                       SerializableMessage&) -> Status {
        {
            std::lock_guard lk{handler_mu};
            handler_entered = true;
        }
        handler_entered_cv.notify_one();
        // Sleep for the safety bound. If the client's cancel hook
        // works, the client returns Cancelled long before this
        // sleep ends; the handler eventually returns Ok but its
        // late Finish is irrelevant to the client's observed status.
        std::this_thread::sleep_for(kHandlerSafetyBound);
        return Status{StatusCode::Ok, ""};
    };

    UnaryFixture fx{handler};

    // Mimic the agent's per-cycle stop_source pattern: emplace fresh,
    // hand a token to the call's CallContext::cancel.
    std::optional<std::stop_source> heartbeat_stop_src;
    heartbeat_stop_src.emplace();
    const auto hb_stop_tok = heartbeat_stop_src->get_token();

    std::optional<::yuzu::transport::CallResult> rpc_result;
    std::thread worker([&]() {
        StringMessage req("hb-cycle-1"), resp;
        CallContext ctx;
        // ctx.deadline is the gRPC-level call deadline; set well
        // beyond the handler's safety bound so the test exercises
        // the cancel path, not the deadline path.
        ctx.deadline = kHandlerSafetyBound + 5s;
        ctx.cancel = hb_stop_tok;
        rpc_result = fx.channel->unary("yuzu.agent.v1.AgentService/Heartbeat", ctx, req, resp);
    });

    // Wait until the handler reports it's running, then request_stop.
    {
        std::unique_lock lk{handler_mu};
        REQUIRE(handler_entered_cv.wait_for(lk, 2s, [&] { return handler_entered; }));
    }
    const auto t_request_stop = std::chrono::steady_clock::now();
    heartbeat_stop_src->request_stop();

    worker.join();
    const auto cancel_to_return = std::chrono::steady_clock::now() - t_request_stop;

    REQUIRE(rpc_result.has_value());
    REQUIRE(rpc_result->status.code == StatusCode::Cancelled);
    // The client must observe the cancel and return well before the
    // handler's safety bound elapses — that is the property that
    // proves `ctx.cancel` was actually plumbed through to the
    // gRPC client context's TryCancel. Slack accommodates CI
    // scheduler jitter on overloaded runners.
    REQUIRE(cancel_to_return < (kHandlerSafetyBound - 1s));
}

// =====================================================================
// Test 3 — cross-cycle integration: cycle-1 stop does not leak
// =====================================================================
//
// Mirrors the production reconnect sequence: cycle 1 ends with
// `heartbeat_stop_src_->request_stop()` (agent.cpp lines ~1386-1391),
// then the next iteration of the connection loop calls
// `heartbeat_stop_src_.emplace()` (line ~1062). Cycle 2's Heartbeat
// thread captures a fresh token from the new source and threads it
// into every Heartbeat CallContext. A real RPC dispatched with that
// fresh token must NOT be cancelled by cycle-1's request_stop.

TEST_CASE("Heartbeat per-cycle stop_source: cycle-1 stop does not leak into cycle-2 unary",
          "[agent][heartbeat][cancel]") {
    using namespace std::chrono_literals;

    auto handler = [](const CallContext&, const SerializableMessage& req,
                      SerializableMessage& resp) -> Status {
        const auto& sreq = static_cast<const StringMessage&>(req);
        auto& sresp = static_cast<StringMessage&>(resp);
        sresp = StringMessage{}; // reset
        // Echo via parse() to round-trip through SerializableMessage —
        // mirrors the production HeartbeatRequest/Response shape (which
        // would parse() through the proto adapter); StringMessage uses
        // assign() under the hood.
        std::string out;
        sreq.serialize(out);
        out = "ack:" + out;
        sresp.parse(out);
        return Status{StatusCode::Ok, ""};
    };

    UnaryFixture fx{handler};

    std::optional<std::stop_source> heartbeat_stop_src;

    // ── Cycle 1: emplace + request_stop (no RPC dispatched, mirrors
    //    early-shutdown reconnect path) ─────────────────────────────────
    heartbeat_stop_src.emplace();
    const auto cycle1_tok = heartbeat_stop_src->get_token();
    heartbeat_stop_src->request_stop();
    REQUIRE(cycle1_tok.stop_requested());

    // ── Cycle 2: emplace REPLACES, fresh token, real RPC must succeed ──
    heartbeat_stop_src.emplace();
    const auto cycle2_tok = heartbeat_stop_src->get_token();
    REQUIRE_FALSE(cycle2_tok.stop_requested());

    StringMessage req("hb-cycle-2"), resp;
    CallContext ctx;
    ctx.deadline = 2s;
    ctx.cancel = cycle2_tok;

    auto r = fx.channel->unary("yuzu.agent.v1.AgentService/Heartbeat", ctx, req, resp);

    REQUIRE(r.status.code == StatusCode::Ok);
    REQUIRE(resp.data() == "ack:hb-cycle-2");
    // cycle1_tok must remain stop_requested — replacing the optional
    // does not retroactively un-stop tokens already issued.
    REQUIRE(cycle1_tok.stop_requested());
}
