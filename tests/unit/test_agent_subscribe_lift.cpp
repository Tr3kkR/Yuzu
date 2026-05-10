// SPDX-License-Identifier: Apache-2.0
//
// tests/unit/test_agent_subscribe_lift.cpp
//
// In-proc gRPC integration tests for #376 PR 1c-4 — the agent-side
// Subscribe (bidi) + DownloadUpdate (server-streaming-via-bidi) lift
// onto `yuzu::transport::Channel`. These tests exercise the *lift
// patterns* the agent + updater use, not the agent's full code path:
//
//   1. Subscribe proto round-trip — multi-frame fan-out from server,
//      response from agent, validates `transport::read_pb` /
//      `transport::write_pb` correctly serialise the agent's wire
//      types (`agent_pb::CommandRequest` / `agent_pb::CommandResponse`) through
//      the abstraction.
//
//   2. Subscribe per-cycle `stop_source` plumbing — `request_stop()`
//      on the source threaded into `CallContext::cancel` unblocks a
//      parked `read_pb` and surfaces `Cancelled` via `final_status()`.
//      Mirrors the agent.cpp `subscribe_stop_src_` pattern (canonical
//      cycle-entry: `subscribe_stop_src_.emplace()`; canonical
//      shutdown: `subscribe_stop_src_->request_stop()`).
//
//   3. Subscribe reconnect cycle — cycle-1 source is request_stop()'d
//      and reset; cycle-2 emplace produces a fresh, not-yet-stopped
//      token; second `bidi_stream` opens cleanly and a frame round-
//      trips on the new stream. Pins the across-cycle invariant
//      required by Q9 of the PR 1c-4 design grilling.
//
//   4. DownloadUpdate happy path — write request, writes_done(), read
//      N chunks until peer half-close, verify `final_status() == Ok`.
//      Validates the server-streaming-via-bidi pattern that
//      `updater.cpp` uses post-lift.
//
//   5. DownloadUpdate per-chunk read deadline — server stalls after
//      one chunk; agent's deadline-armed `read_pb` returns false and
//      `final_status()` reports `DeadlineExceeded`. Uses a short
//      200 ms deadline for test speed; production updater.cpp uses
//      30 s (PR 1c-4 design grilling Q7).
//
// The transport's bidi+cancel+deadline mechanisms themselves are
// independently covered by `tests/unit/transport/test_transport_smoke.cpp`
// `[transport][round-trip][bidi]` and `[transport][bidi][deadline]`.
// This file specifically pins the AGENT'S USE of those primitives in
// the shapes Subscribe + DownloadUpdate take.

#include <yuzu/transport/proto_adapter.hpp>
#include <yuzu/transport/transport.hpp>

// Generated proto headers (flat output via proto/gen_proto.py).
#include "agent.pb.h"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <optional>
#include <stop_token>
#include <string>
#include <thread>

// Note: `pb` clashes with `google::protobuf::internal::pb` (extension_set.h)
// when both are in scope, so use `agent_pb` instead.
namespace agent_pb = ::yuzu::agent::v1;
using ::yuzu::transport::Backend;
using ::yuzu::transport::BidiStream;
using ::yuzu::transport::CallContext;
using ::yuzu::transport::ClientCertMode;
using ::yuzu::transport::Credentials;
using ::yuzu::transport::Endpoint;
using ::yuzu::transport::make_channel;
using ::yuzu::transport::make_server_listener;
using ::yuzu::transport::ServerListener;
using ::yuzu::transport::Status;
using ::yuzu::transport::StatusCode;

namespace {

// In-proc fixture: gRPC listener + matching channel. One handler is
// registered per fixture; the test scopes the lifetime by holding the
// fixture in a unique_ptr so its destructor runs before another test
// starts a fresh listener.
struct BidiFixture {
    std::unique_ptr<ServerListener> listener;
    std::unique_ptr<::yuzu::transport::Channel> channel;

    BidiFixture(std::string method, ::yuzu::transport::BidiStreamHandler handler) {
        listener = make_server_listener(Backend::Grpc);
        REQUIRE(listener != nullptr);
        listener->register_bidi_stream(std::move(method), std::move(handler));

        Credentials creds{};
        creds.verify_peer = false;
        creds.client_cert_mode = ClientCertMode::None;

        Endpoint bind{"127.0.0.1", 0};
        REQUIRE(listener->start(bind, creds).has_value());
        REQUIRE(listener->is_serving());

        channel = make_channel(Backend::Grpc, listener->bound_endpoint(), creds);
        REQUIRE(channel != nullptr);
        REQUIRE(channel->wait_for_connected(std::chrono::seconds(2)));
    }

    BidiFixture(const BidiFixture&) = delete;
    BidiFixture& operator=(const BidiFixture&) = delete;
    BidiFixture(BidiFixture&&) = delete;
    BidiFixture& operator=(BidiFixture&&) = delete;

    ~BidiFixture() {
        if (channel)
            channel->close();
        if (listener)
            listener->shutdown();
    }
};

} // namespace

// =====================================================================
// Test 1 — Subscribe proto round-trip with multi-frame fan-out
// =====================================================================

TEST_CASE("Subscribe lift: multi-frame fan-out round-trips proto messages",
          "[agent][subscribe][lift]") {
    constexpr int kFrameCount = 8;

    BidiFixture fx{"yuzu.agent.v1.AgentService/Subscribe",
                   [&](const CallContext&, BidiStream& stream) -> Status {
                       // Mirror the server's lifted Subscribe handler in shape:
                       // read CommandResponse, write CommandRequest. Here we use
                       // a deterministic pair-and-respond loop so the test can
                       // assert order + content.
                       for (int i = 0; i < kFrameCount; ++i) {
                           agent_pb::CommandResponse resp;
                           if (!::yuzu::transport::read_pb(stream, resp))
                               return Status{StatusCode::Internal, "server-side read failed"};

                           agent_pb::CommandRequest req;
                           req.set_command_id("server:" + resp.command_id());
                           req.set_plugin("echo");
                           if (!::yuzu::transport::write_pb(stream, req))
                               return Status{StatusCode::Internal, "server-side write failed"};
                       }
                       return Status{StatusCode::Ok, ""};
                   }};

    CallContext ctx;
    ctx.deadline = std::chrono::seconds(5);
    auto stream = fx.channel->bidi_stream("yuzu.agent.v1.AgentService/Subscribe", ctx);
    REQUIRE(stream != nullptr);

    for (int i = 0; i < kFrameCount; ++i) {
        agent_pb::CommandResponse resp;
        resp.set_command_id("agent:" + std::to_string(i));
        resp.set_status(agent_pb::CommandResponse::SUCCESS);
        REQUIRE(::yuzu::transport::write_pb(*stream, resp));

        agent_pb::CommandRequest req;
        REQUIRE(::yuzu::transport::read_pb(*stream, req));
        REQUIRE(req.command_id() == "server:agent:" + std::to_string(i));
        REQUIRE(req.plugin() == "echo");
    }

    stream->writes_done();
    agent_pb::CommandRequest drain;
    REQUIRE_FALSE(::yuzu::transport::read_pb(*stream, drain));
    REQUIRE(stream->final_status().code == StatusCode::Ok);
}

// =====================================================================
// Test 2 — Subscribe per-cycle stop_source plumbing
// =====================================================================
//
// Pin the agent.cpp `subscribe_stop_src_` pattern: the token threaded
// into `CallContext::cancel` propagates through the transport's
// stop_callback hook and unblocks a parked `read_pb`. The handler
// blocks indefinitely on the server side (no writes) so the only way
// the client's read_pb returns is via the cancel signal.

TEST_CASE("Subscribe lift: request_stop on per-cycle source unblocks parked read_pb",
          "[agent][subscribe][lift][cancel]") {
    using namespace std::chrono_literals;
    constexpr auto kHandlerSafetyBound = 4s;

    std::mutex handler_mu;
    std::condition_variable handler_entered_cv;
    bool handler_entered = false;

    BidiFixture fx{
        "yuzu.agent.v1.AgentService/Subscribe",
        [&](const CallContext&, BidiStream& stream) -> Status {
            {
                std::lock_guard lk{handler_mu};
                handler_entered = true;
            }
            handler_entered_cv.notify_one();
            // Block up to safety-bound; we expect the client
            // to cancel well before this. read_pb on the
            // handler side returns false when the peer side
            // closes the stream (cancel is delivered as a
            // peer-cancel via `gctx_.TryCancel()`).
            agent_pb::CommandResponse resp;
            (void)::yuzu::transport::read_pb(
                stream, resp,
                std::chrono::duration_cast<std::chrono::milliseconds>(kHandlerSafetyBound));
            return Status{StatusCode::Ok, ""};
        }};

    // Cycle-entry pattern: emplace a fresh stop_source and thread its
    // token into CallContext::cancel.
    std::optional<std::stop_source> subscribe_stop_src;
    subscribe_stop_src.emplace();

    CallContext ctx;
    ctx.cancel = subscribe_stop_src->get_token();
    ctx.deadline = std::chrono::milliseconds(0); // no whole-call deadline

    auto stream = fx.channel->bidi_stream("yuzu.agent.v1.AgentService/Subscribe", ctx);
    REQUIRE(stream != nullptr);

    // Wait until the server-side handler is parked in read_pb so we
    // know cancellation actually has something to interrupt.
    {
        std::unique_lock lk{handler_mu};
        REQUIRE(
            handler_entered_cv.wait_for(lk, kHandlerSafetyBound, [&] { return handler_entered; }));
    }

    auto cancel_start = std::chrono::steady_clock::now();
    subscribe_stop_src->request_stop();

    // Parked read_pb on the client must observe the cancel and return
    // false. Use a deadline-armed read so a regression that broke the
    // cancel plumbing doesn't hang the test forever.
    agent_pb::CommandRequest req;
    bool got_frame = ::yuzu::transport::read_pb(
        *stream, req, std::chrono::duration_cast<std::chrono::milliseconds>(kHandlerSafetyBound));
    REQUIRE_FALSE(got_frame);

    auto cancel_elapsed = std::chrono::steady_clock::now() - cancel_start;
    REQUIRE(cancel_elapsed < kHandlerSafetyBound);

    Status final = stream->final_status();
    // Either Cancelled (cancel beat the read deadline) or
    // DeadlineExceeded (deadline beat cancel) is acceptable; what we
    // care about is that read_pb returned false PROMPTLY, not that the
    // wire status is one specific value.
    REQUIRE((final.code == StatusCode::Cancelled || final.code == StatusCode::DeadlineExceeded));
}

// =====================================================================
// Test 3 — Subscribe reconnect cycle
// =====================================================================
//
// Required by PR 1c-4 design grilling Q9: open Subscribe, drop it,
// reopen, verify a frame dispatched on the second stream arrives.
// Exercises the across-cycle invariant the agent.cpp connection loop
// relies on (`subscribe_stop_src_.reset()` at end of cycle,
// `.emplace()` at start of next cycle, fresh token per cycle).

TEST_CASE("Subscribe lift: reconnect cycle — second stream after request_stop on first works",
          "[agent][subscribe][lift][reconnect]") {
    BidiFixture fx{"yuzu.agent.v1.AgentService/Subscribe",
                   [](const CallContext&, BidiStream& stream) -> Status {
                       // Read one frame, write one frame, return Ok.
                       // Each connection cycle is a single round-trip.
                       agent_pb::CommandResponse resp;
                       if (!::yuzu::transport::read_pb(stream, resp))
                           return Status{StatusCode::Cancelled, "no frame"};

                       agent_pb::CommandRequest req;
                       req.set_command_id("ack:" + resp.command_id());
                       (void)::yuzu::transport::write_pb(stream, req);
                       return Status{StatusCode::Ok, ""};
                   }};

    // ── Cycle 1 ──
    std::optional<std::stop_source> subscribe_stop_src;
    subscribe_stop_src.emplace();
    auto cycle1_token = subscribe_stop_src->get_token();
    REQUIRE_FALSE(cycle1_token.stop_requested());

    CallContext c1_ctx;
    c1_ctx.cancel = cycle1_token;
    c1_ctx.deadline = std::chrono::seconds(5);
    auto s1 = fx.channel->bidi_stream("yuzu.agent.v1.AgentService/Subscribe", c1_ctx);
    REQUIRE(s1 != nullptr);

    agent_pb::CommandResponse c1_resp;
    c1_resp.set_command_id("c1");
    c1_resp.set_status(agent_pb::CommandResponse::SUCCESS);
    REQUIRE(::yuzu::transport::write_pb(*s1, c1_resp));
    agent_pb::CommandRequest c1_req;
    REQUIRE(::yuzu::transport::read_pb(*s1, c1_req));
    REQUIRE(c1_req.command_id() == "ack:c1");

    // End-of-cycle cleanup: request_stop, reset, simulate the agent's
    // reconnect path. The cycle-1 token observes its own stop forever;
    // cycle-2 must produce a fresh source.
    subscribe_stop_src->request_stop();
    REQUIRE(cycle1_token.stop_requested());
    s1->writes_done();
    agent_pb::CommandRequest drain;
    (void)::yuzu::transport::read_pb(*s1, drain);
    s1.reset();
    subscribe_stop_src.reset();

    // ── Cycle 2 ──
    subscribe_stop_src.emplace();
    auto cycle2_token = subscribe_stop_src->get_token();
    REQUIRE_FALSE(cycle2_token.stop_requested());
    // Cycle-1 token still observes its prior stop — replacing the
    // optional does NOT retroactively un-stop tokens already handed out.
    REQUIRE(cycle1_token.stop_requested());

    CallContext c2_ctx;
    c2_ctx.cancel = cycle2_token;
    c2_ctx.deadline = std::chrono::seconds(5);
    auto s2 = fx.channel->bidi_stream("yuzu.agent.v1.AgentService/Subscribe", c2_ctx);
    REQUIRE(s2 != nullptr);

    agent_pb::CommandResponse c2_resp;
    c2_resp.set_command_id("c2");
    c2_resp.set_status(agent_pb::CommandResponse::SUCCESS);
    REQUIRE(::yuzu::transport::write_pb(*s2, c2_resp));
    agent_pb::CommandRequest c2_req;
    REQUIRE(::yuzu::transport::read_pb(*s2, c2_req));
    REQUIRE(c2_req.command_id() == "ack:c2");

    s2->writes_done();
    (void)::yuzu::transport::read_pb(*s2, drain);
    REQUIRE(s2->final_status().code == StatusCode::Ok);
}

// =====================================================================
// Test 4 — DownloadUpdate happy path
// =====================================================================
//
// Validates the server-streaming-via-bidi pattern updater.cpp uses
// post-lift: client writes one DownloadUpdateRequest, calls
// writes_done(), reads N DownloadUpdateChunk frames until peer half-
// close, expects final_status == Ok.

TEST_CASE("DownloadUpdate lift: write request + writes_done + read chunks happy path",
          "[agent][download][lift]") {
    constexpr int kChunkCount = 4;
    constexpr std::size_t kChunkSize = 1024;

    BidiFixture fx{"yuzu.agent.v1.AgentService/DownloadUpdate",
                   [&](const CallContext&, BidiStream& stream) -> Status {
                       agent_pb::DownloadUpdateRequest req;
                       if (!::yuzu::transport::read_pb(stream, req))
                           return Status{StatusCode::InvalidArgument, "no request frame"};
                       // Write kChunkCount chunks of synthetic data.
                       for (int i = 0; i < kChunkCount; ++i) {
                           agent_pb::DownloadUpdateChunk chunk;
                           std::string data(kChunkSize, static_cast<char>('A' + i));
                           chunk.set_data(std::move(data));
                           chunk.set_offset(static_cast<int64_t>(i * kChunkSize));
                           chunk.set_total_size(kChunkCount * kChunkSize);
                           if (!::yuzu::transport::write_pb(stream, chunk))
                               return Status{StatusCode::Internal, "write failed"};
                       }
                       return Status{StatusCode::Ok, ""};
                   }};

    // Mirror updater.cpp's pattern.
    CallContext ctx{};
    ctx.deadline = std::chrono::seconds(5);
    auto stream = fx.channel->bidi_stream("yuzu.agent.v1.AgentService/DownloadUpdate", ctx);
    REQUIRE(stream != nullptr);

    agent_pb::DownloadUpdateRequest req;
    req.set_agent_id("test-agent");
    req.set_version("1.2.3");
    req.mutable_platform()->set_os("linux");
    req.mutable_platform()->set_arch("x86_64");
    REQUIRE(::yuzu::transport::write_pb(*stream, req));
    stream->writes_done();

    constexpr auto kChunkReadDeadline = std::chrono::seconds(2);
    int chunks_received = 0;
    int64_t total_bytes = 0;
    agent_pb::DownloadUpdateChunk chunk;
    while (::yuzu::transport::read_pb(*stream, chunk, kChunkReadDeadline)) {
        REQUIRE(chunk.data().size() == kChunkSize);
        REQUIRE(chunk.offset() == static_cast<int64_t>(chunks_received * kChunkSize));
        // Each chunk's first byte is the per-chunk filler.
        REQUIRE(chunk.data()[0] == static_cast<char>('A' + chunks_received));
        total_bytes += static_cast<int64_t>(chunk.data().size());
        ++chunks_received;
    }
    REQUIRE(chunks_received == kChunkCount);
    REQUIRE(total_bytes == kChunkCount * kChunkSize);
    REQUIRE(stream->final_status().code == StatusCode::Ok);
}

// =====================================================================
// Test 5 — DownloadUpdate per-chunk read deadline expiry
// =====================================================================
//
// Pins the per-chunk idle deadline pattern updater.cpp uses (PR 1c-4
// design grilling Q7 → 30s in production). This test uses 200 ms for
// speed; what's being validated is that an idle period > deadline
// causes read_pb to return false and final_status to report
// DeadlineExceeded, matching the BidiStream contract block in
// transport.hpp.

TEST_CASE("DownloadUpdate lift: per-chunk read deadline expires when server stalls mid-stream",
          "[agent][download][lift][deadline]") {
    using namespace std::chrono_literals;
    constexpr auto kClientChunkDeadline = 200ms;
    constexpr auto kHandlerSafetyBound = 4s; // generous upper bound

    BidiFixture fx{
        "yuzu.agent.v1.AgentService/DownloadUpdate",
        [&](const CallContext&, BidiStream& stream) -> Status {
            agent_pb::DownloadUpdateRequest req;
            if (!::yuzu::transport::read_pb(stream, req))
                return Status{StatusCode::InvalidArgument, "no request frame"};
            // Write ONE chunk, then park the handler on a deadline-
            // armed read. The client doesn't write anything more (it
            // already called writes_done), so the server's read sits
            // until the client side cancels via its deadline-expiry
            // (cancel propagates to a peer-side cancel that surfaces
            // as ok=false on the handler's read tag). This lets the
            // handler exit cleanly without trying to call Finish on a
            // peer-cancelled stream — which gRPC asserts.
            agent_pb::DownloadUpdateChunk first;
            first.set_data(std::string(64, 'X'));
            first.set_offset(0);
            first.set_total_size(128);
            (void)::yuzu::transport::write_pb(stream, first);

            agent_pb::DownloadUpdateRequest tail;
            (void)::yuzu::transport::read_pb(
                stream, tail,
                std::chrono::duration_cast<std::chrono::milliseconds>(kHandlerSafetyBound));
            return Status{StatusCode::Cancelled, ""};
        }};

    CallContext ctx{};
    ctx.deadline = std::chrono::seconds(5);
    auto stream = fx.channel->bidi_stream("yuzu.agent.v1.AgentService/DownloadUpdate", ctx);
    REQUIRE(stream != nullptr);

    agent_pb::DownloadUpdateRequest req;
    req.set_agent_id("test-agent");
    req.set_version("1.2.3");
    REQUIRE(::yuzu::transport::write_pb(*stream, req));
    stream->writes_done();

    // First chunk arrives.
    agent_pb::DownloadUpdateChunk chunk;
    REQUIRE(::yuzu::transport::read_pb(*stream, chunk, kClientChunkDeadline));
    REQUIRE(chunk.data().size() == 64);

    // Second chunk does not arrive within the deadline.
    auto t0 = std::chrono::steady_clock::now();
    bool got_second = ::yuzu::transport::read_pb(*stream, chunk, kClientChunkDeadline);
    auto elapsed = std::chrono::steady_clock::now() - t0;
    REQUIRE_FALSE(got_second);
    // Generous upper bound — what matters is the deadline fired and
    // returned promptly, not a tight numeric bound.
    REQUIRE(elapsed < 1500ms);
    // Either DeadlineExceeded (deadline-marker preserved through
    // final_status) or Cancelled (gRPC wire-status caveat — handler-
    // returned cancel raced with the local deadline marker) is
    // acceptable; both prove the deadline fired and unblocked the
    // read. The canonical signal that the deadline was THE cause is
    // the elapsed-time bound above, not the precise StatusCode.
    Status final = stream->final_status();
    REQUIRE((final.code == StatusCode::DeadlineExceeded || final.code == StatusCode::Cancelled));
}

// =====================================================================
// qe S-2 (#926) — Channel::bidi_stream returns nullptr after close()
// =====================================================================
//
// The agent connection loop checks `if (!stream)` after `bidi_stream()`
// and treats nullptr as a transient open-failure (increments reconnect
// counter, sleeps, retries). The branch exists in agents/core/src/agent.cpp
// but had no direct unit test before this case. We exercise it via
// channel->close(): after the channel is closed, GrpcChannel::bidi_stream
// returns nullptr (transport/src/grpc/grpc_channel.cpp:825) — the same
// shape an agent observes during a transient transport-layer failure.
TEST_CASE("Channel::bidi_stream returns nullptr after close (qe S-2 / #926)",
          "[agent][subscribe][lift][nullptr]") {
    using namespace std::chrono_literals;

    BidiFixture fx{"yuzu.agent.v1.AgentService/Subscribe",
                   [](const CallContext&, BidiStream& stream) -> Status {
                       agent_pb::CommandResponse drop;
                       (void)::yuzu::transport::read_pb(stream, drop);
                       return Status{StatusCode::Ok, ""};
                   }};

    // Sanity: channel is healthy and bidi_stream succeeds before close.
    CallContext ctx{};
    ctx.deadline = std::chrono::seconds(5);
    auto live = fx.channel->bidi_stream("yuzu.agent.v1.AgentService/Subscribe", ctx);
    REQUIRE(live != nullptr);
    live.reset(); // Close the live stream before closing the channel.

    // Close the channel. The agent connection loop calls this on the
    // shutdown path; we exercise the same code transition.
    fx.channel->close();

    // bidi_stream() now MUST return nullptr — the canonical "transport-
    // layer transient failure" signal the agent's nullptr-branch handles.
    auto dead = fx.channel->bidi_stream("yuzu.agent.v1.AgentService/Subscribe", ctx);
    REQUIRE(dead == nullptr);

    // Calling again is idempotent and still returns nullptr — no
    // exceptions, no use-after-free.
    auto dead2 = fx.channel->bidi_stream("yuzu.agent.v1.AgentService/Subscribe", ctx);
    REQUIRE(dead2 == nullptr);
}

// =====================================================================
// qe S-3 (#927) — concurrent-write through shared_ptr<BidiStream>
// =====================================================================
//
// PR 1c-4 made the agent's Subscribe stream a `std::shared_ptr<BidiStream>`
// shared across the OutputCallback worker pool + the connection loop;
// concurrent `write()` calls are serialised externally via
// `stream_write_mu_` (transport.hpp:446 — BidiStream is single-writer
// thread-compatible, so callers MUST serialise). This test pins the
// invariant: N writer threads × M frames each, all serialised through
// one external mutex, produce no torn frames and no out-of-order
// sequence numbers.
//
// Catch2 thread-safety note (#918): REQUIRE/CHECK from spawned threads
// is unsafe. All cross-thread observations are collected into atomics
// or main-thread-owned containers; assertions live on the main thread.
TEST_CASE("Concurrent writes through shared BidiStream are torn-frame-free "
          "(qe S-3 / #927)",
          "[agent][subscribe][lift][concurrent]") {
    using namespace std::chrono_literals;

    constexpr int kWriters = 4;
    constexpr int kFramesPerWriter = 200;
    constexpr int kTotalFrames = kWriters * kFramesPerWriter;

    // Server collects every received frame's command_id payload into
    // a vector and exits when it has seen kTotalFrames.
    std::mutex received_mu;
    std::vector<std::string> received;
    received.reserve(kTotalFrames);
    std::atomic<int> received_count{0};

    BidiFixture fx{"yuzu.agent.v1.AgentService/Subscribe",
                   [&](const CallContext&, BidiStream& stream) -> Status {
                       agent_pb::CommandResponse frame;
                       while (::yuzu::transport::read_pb(stream, frame)) {
                           {
                               std::lock_guard lk(received_mu);
                               received.push_back(frame.command_id());
                           }
                           if (received_count.fetch_add(1, std::memory_order_acq_rel) + 1 >=
                               kTotalFrames) {
                               break;
                           }
                       }
                       return Status{StatusCode::Ok, ""};
                   }};

    CallContext ctx{};
    ctx.deadline = std::chrono::seconds(30);
    auto raw = fx.channel->bidi_stream("yuzu.agent.v1.AgentService/Subscribe", ctx);
    REQUIRE(raw != nullptr);
    std::shared_ptr<BidiStream> shared{std::move(raw)};

    // External mutex matching agent.cpp::stream_write_mu_ semantics.
    std::mutex stream_write_mu;

    // Worker pool: each thread writes kFramesPerWriter frames whose
    // command_id encodes the writer id + sequence number ("w<W>:s<N>")
    // so the server can verify no torn frames (every received id is
    // parseable + within the expected ranges).
    std::vector<std::thread> writers;
    writers.reserve(kWriters);
    std::atomic<int> writer_failures{0};
    for (int w = 0; w < kWriters; ++w) {
        writers.emplace_back([w, shared, &stream_write_mu, &writer_failures] {
            for (int s = 0; s < kFramesPerWriter; ++s) {
                agent_pb::CommandResponse frame;
                frame.set_command_id("w" + std::to_string(w) + ":s" + std::to_string(s));
                std::lock_guard lk(stream_write_mu);
                if (!::yuzu::transport::write_pb(*shared, frame)) {
                    writer_failures.fetch_add(1, std::memory_order_relaxed);
                    return;
                }
            }
        });
    }
    for (auto& t : writers)
        t.join();
    shared->writes_done();

    // Drain server-side reply (the handler exits once it sees
    // kTotalFrames; the client side just observes peer half-close).
    agent_pb::CommandResponse drain;
    (void)::yuzu::transport::read_pb(*shared, drain);
    Status final = shared->final_status();

    REQUIRE(writer_failures.load(std::memory_order_acquire) == 0);
    REQUIRE(received_count.load(std::memory_order_acquire) == kTotalFrames);
    REQUIRE(final.code == StatusCode::Ok);

    // Verify no torn frames: every received command_id is parseable as
    // "w<W>:s<N>" with W in [0, kWriters) and N in [0, kFramesPerWriter).
    // Per-writer sequence ordering is a secondary invariant: writes from
    // a single thread MUST appear in s-ascending order on the wire (the
    // mutex is the only ordering primitive between writers, so within
    // one writer the program order is preserved).
    std::vector<int> last_seen_per_writer(kWriters, -1);
    int parse_failures = 0;
    int order_violations = 0;
    {
        std::lock_guard lk(received_mu);
        for (const auto& id : received) {
            int w = -1;
            int s = -1;
            if (std::sscanf(id.c_str(), "w%d:s%d", &w, &s) != 2 || w < 0 || w >= kWriters ||
                s < 0 || s >= kFramesPerWriter) {
                ++parse_failures;
                continue;
            }
            if (s <= last_seen_per_writer[w]) {
                ++order_violations;
            } else {
                last_seen_per_writer[w] = s;
            }
        }
    }
    REQUIRE(parse_failures == 0);
    REQUIRE(order_violations == 0);
    for (int w = 0; w < kWriters; ++w) {
        REQUIRE(last_seen_per_writer[w] == kFramesPerWriter - 1);
    }
}
