// MCP progress bridge (track 2f PR 3) - the consumer-side projection of the
// ExecutionEventBus onto the MCP session's SSE surfaces.
//
// Part 1: the pure JSON-RPC helpers (progressToken extraction, the
// notifications/progress builder). Part 2: the McpStreamBridge core - records,
// copy-only listener, projector thread, arm/cancel/abandon arbitration, sweep
// (pin-ack / session-death / pressure), charge accounting, shutdown. The
// concurrency-heavy cases (flip-drain, arm-vs-abandon race, pressure-vs-terminal
// property, dtor safety) are the TSan leg's primary targets.

#include <catch2/catch_test_macros.hpp>

#include "../../../server/core/src/mcp_jsonrpc.hpp"
#include "../../../server/core/src/mcp_session.hpp"
#include "../../../server/core/src/mcp_stream.hpp"
#include "../../../server/core/src/mcp_stream_bridge.hpp"

#include <yuzu/metrics.hpp>

#include <nlohmann/json.hpp>

#include <atomic>
#include <chrono>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace mcp = yuzu::server::mcp;
using nlohmann::json;

TEST_CASE("extract_progress_token - accepts string and integer tokens verbatim",
          "[mcp][bridge][2f]") {
    SECTION("string token") {
        auto p = json::parse(R"({"_meta":{"progressToken":"abc-123"}})");
        auto tok = mcp::extract_progress_token(p);
        REQUIRE(tok.has_value());
        CHECK(tok->is_string());
        CHECK(tok->get<std::string>() == "abc-123");
    }
    SECTION("integer token") {
        auto p = json::parse(R"({"_meta":{"progressToken":42}})");
        auto tok = mcp::extract_progress_token(p);
        REQUIRE(tok.has_value());
        CHECK(tok->is_number_integer());
        CHECK(tok->get<int>() == 42);
    }
    SECTION("negative integer token") {
        auto p = json::parse(R"({"_meta":{"progressToken":-7}})");
        auto tok = mcp::extract_progress_token(p);
        REQUIRE(tok.has_value());
        CHECK(tok->get<int>() == -7);
    }
}

TEST_CASE("extract_progress_token - anything not string|integer is ignored (no error)",
          "[mcp][bridge][2f]") {
    // The spec lets a server decline to emit progress, so an unusable or absent token is
    // simply "no progress requested" - never a parse failure.
    CHECK_FALSE(mcp::extract_progress_token(json::parse(R"({})")).has_value());
    CHECK_FALSE(mcp::extract_progress_token(json::parse(R"({"_meta":{}})")).has_value());
    CHECK_FALSE(mcp::extract_progress_token(json::parse(R"({"_meta":42})")).has_value());
    CHECK_FALSE(mcp::extract_progress_token(json::parse(R"({"_meta":{"progressToken":3.14}})"))
                    .has_value()); // float rejected
    CHECK_FALSE(mcp::extract_progress_token(json::parse(R"({"_meta":{"progressToken":true}})"))
                    .has_value());
    CHECK_FALSE(mcp::extract_progress_token(json::parse(R"({"_meta":{"progressToken":null}})"))
                    .has_value());
    CHECK_FALSE(mcp::extract_progress_token(json::parse(R"({"_meta":{"progressToken":{}}})"))
                    .has_value());
    CHECK_FALSE(mcp::extract_progress_token(json::parse(R"([1,2,3])")).has_value()); // non-object
}

TEST_CASE("progress_notification - token echoed verbatim, shape is valid JSON-RPC",
          "[mcp][bridge][2f]") {
    SECTION("string token stays a string; execution_id in _meta") {
        auto tok = json("tok-abc");
        auto msg = mcp::progress_notification(tok, /*progress=*/3, /*total=*/5, "3/5 responded",
                                              "exec-xyz");
        auto parsed = json::parse(msg); // must be well-formed
        CHECK(parsed["jsonrpc"] == "2.0");
        CHECK(parsed["method"] == "notifications/progress");
        CHECK(parsed["params"]["progressToken"] == "tok-abc"); // string, not "\"tok-abc\""
        CHECK(parsed["params"]["progressToken"].is_string());
        CHECK(parsed["params"]["progress"] == 3);
        CHECK(parsed["params"]["total"] == 5);
        CHECK(parsed["params"]["message"] == "3/5 responded");
        CHECK(parsed["params"]["_meta"]["yuzu.execution_id"] == "exec-xyz");
        CHECK_FALSE(parsed.contains("id")); // a notification has no id
    }
    SECTION("integer token is emitted as a number, never stringified") {
        auto tok = json(99);
        auto parsed = json::parse(
            mcp::progress_notification(tok, 1, 1, "done", "exec-1"));
        CHECK(parsed["params"]["progressToken"].is_number_integer());
        CHECK(parsed["params"]["progressToken"] == 99);
    }
    SECTION("message with quotes/newlines is escaped into valid JSON") {
        auto tok = json("t");
        auto parsed = json::parse(
            mcp::progress_notification(tok, 0, 0, "line\"one\"\nline two", "exec-1"));
        CHECK(parsed["params"]["message"] == "line\"one\"\nline two");
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Part 2 - the bridge core (rung 3a.6)
// ═══════════════════════════════════════════════════════════════════════════

namespace {

using yuzu::server::ExecutionEventBus;
using Bridge = mcp::McpStreamBridge;

/// Poll an eventually-true condition - the projector is asynchronous. Generous
/// deadline, tight step: never false-RED on a loaded CI box, fast when green.
template <typename F>
bool poll_until(F&& f, std::chrono::milliseconds deadline = std::chrono::seconds(5)) {
    const auto until = std::chrono::steady_clock::now() + deadline;
    while (std::chrono::steady_clock::now() < until) {
        if (f()) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    return f();
}

/// Everything a bridge test needs, destruction-ordered so the bridge (declared
/// last) shuts down while the bus/registry are still alive - the production
/// stop() ordering (bridge reset BEFORE bus reset).
struct Fx {
    yuzu::MetricsRegistry reg;
    ExecutionEventBus bus;
    std::chrono::steady_clock::time_point base = std::chrono::steady_clock::now();
    std::shared_ptr<std::atomic<std::int64_t>> clock_s =
        std::make_shared<std::atomic<std::int64_t>>(0);
    mcp::McpSessionRegistry sessions;
    std::mutex audit_mu;
    std::vector<std::pair<std::string, std::string>> audits;  // (action, detail)
    std::optional<Bridge> bridge;                             // optional: dtor-order tests

    explicit Fx(Bridge::Config cfg = {})
        : sessions(mcp::McpSessionRegistry::Config{},
                   [b = base, c = clock_s] { return b + std::chrono::seconds(c->load()); }, &reg) {
        bridge.emplace(&bus, &sessions, &reg,
                       [this](const std::string& action, const std::string&,
                              const std::string& detail) {
                           std::lock_guard<std::mutex> lk(audit_mu);
                           audits.emplace_back(action, detail);
                       },
                       cfg);
    }

    struct Session {
        std::string id;
        std::shared_ptr<mcp::McpStreamState> stream;
    };
    Session make_session(const std::string& principal = "alice") {
        auto minted = sessions.mint(principal);
        REQUIRE(minted.ok);
        auto stream = sessions.stream_for(minted.session_id, principal);
        REQUIRE(stream != nullptr);
        return {minted.session_id, std::move(stream)};
    }

    std::size_t audit_count(const std::string& action) {
        std::lock_guard<std::mutex> lk(audit_mu);
        std::size_t n = 0;
        for (const auto& [a, d] : audits) {
            if (a == action) {
                ++n;
            }
        }
        return n;
    }
};

/// Snapshot the session ring by attaching at a cursor and copying the replayed
/// sink queue; detaches before returning so later attaches see a free slot.
/// NOTE: a cursor >= a pinned id UNPINS that final (consumption proof) - tests
/// that must not disturb pins snapshot from cursor 0 only when they own the
/// consequences, or use `peek_from` past nothing.
std::vector<mcp::sse_bus::SseEvent> ring_frames(mcp::McpStreamState& st,
                                                         const std::string& principal,
                                                         std::uint64_t cursor = 0) {
    auto att = st.attach_and_replay(cursor, nullptr, principal);
    REQUIRE(att.status == mcp::McpStreamState::AttachStatus::kAttached);
    std::vector<mcp::sse_bus::SseEvent> out;
    {
        std::lock_guard<std::mutex> lk(att.sink->sse->mu);
        out.assign(att.sink->sse->queue.begin(), att.sink->sse->queue.end());
    }
    st.detach(att.sink);
    return out;
}

std::size_t count_method(const std::vector<mcp::sse_bus::SseEvent>& frames,
                         const std::string& method) {
    std::size_t n = 0;
    for (const auto& f : frames) {
        auto j = json::parse(f.data, nullptr, /*allow_exceptions=*/false);
        if (j.is_object() && j.value("method", "") == method) {
            ++n;
        }
    }
    return n;
}

std::size_t count_results(const std::vector<mcp::sse_bus::SseEvent>& frames) {
    std::size_t n = 0;
    for (const auto& f : frames) {
        auto j = json::parse(f.data, nullptr, /*allow_exceptions=*/false);
        if (j.is_object() && j.contains("result")) {
            ++n;
        }
    }
    return n;
}

std::size_t count_error_code(const std::vector<mcp::sse_bus::SseEvent>& frames,
                             int code) {
    std::size_t n = 0;
    for (const auto& f : frames) {
        auto j = json::parse(f.data, nullptr, /*allow_exceptions=*/false);
        if (j.is_object() && j.contains("error") && j["error"].value("code", 0) == code) {
            ++n;
        }
    }
    return n;
}

const std::string kProgress13 = R"({"agents_responded":1,"agents_targeted":3})";
const std::string kCompleted = R"({"status":"completed","agents_success":3,"agents_failure":0})";

}  // namespace

TEST_CASE("bridge reserve - every reject reason is truthful and counted", "[mcp][bridge][2f]") {
    SECTION("null bus ⇒ disabled") {
        yuzu::MetricsRegistry reg;
        mcp::McpSessionRegistry sessions{mcp::McpSessionRegistry::Config{}, {}, &reg};
        Bridge b{nullptr, &sessions, &reg};
        auto r = b.reserve("s", "alice", json(1), std::nullopt, false);
        CHECK_FALSE(r.ok);
        CHECK(std::string(r.reject_reason) == "disabled");
        CHECK(reg.counter("yuzu_mcp_bridge_reject_total", {{"reason", "disabled"}}).value() == 1.0);
    }
    SECTION("unknown session / wrong principal ⇒ unknown_session (no oracle)") {
        Fx fx;
        auto s = fx.make_session();
        CHECK(std::string(fx.bridge->reserve("nope", "alice", json(1), std::nullopt, false)
                              .reject_reason) == "unknown_session");
        CHECK(std::string(fx.bridge->reserve(s.id, "mallory", json(1), std::nullopt, false)
                              .reject_reason) == "unknown_session");
    }
    SECTION("duplicate key, global cap, pin slots; abandon frees them") {
        Fx fx{Bridge::Config{.global_record_cap = 5, .ring_only_pressure_cap = 64}};
        auto s = fx.make_session();
        REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), true).ok);
        CHECK(std::string(fx.bridge->reserve(s.id, "alice", json(1), json("t"), true)
                              .reject_reason) == "duplicate_request_id");
        // string "1" is a DIFFERENT key from integer 1
        REQUIRE(fx.bridge->reserve(s.id, "alice", json("1"), json("t"), true).ok);
        REQUIRE(fx.bridge->reserve(s.id, "alice", json(2), json("t"), true).ok);
        REQUIRE(fx.bridge->reserve(s.id, "alice", json(3), json("t"), true).ok);
        // 4 streamed records on one session: pin slots exhausted
        CHECK(std::string(fx.bridge->reserve(s.id, "alice", json(4), json("t"), true)
                              .reject_reason) == "pin_slots");
        // …but a GET-only record is bounded by the global cap only
        REQUIRE(fx.bridge->reserve(s.id, "alice", json(5), json("t"), false).ok);
        CHECK(std::string(fx.bridge->reserve(s.id, "alice", json(6), json("t"), false)
                              .reject_reason) == "global_cap");
        CHECK(fx.reg.counter("yuzu_mcp_bridge_reject_total", {{"reason", "pin_slots"}}).value() ==
              1.0);
        // abandon a streamed record: both the pin-slot charge and the map slot free up
        REQUIRE(fx.bridge->abandon(s.id, json(1)));
        CHECK(fx.bridge->reserve(s.id, "alice", json(4), json("t"), true).ok);
    }
}

TEST_CASE("bridge arming latch + abandon containment", "[mcp][bridge][2f]") {
    Fx fx;
    auto s = fx.make_session();
    REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), true).ok);
    REQUIRE(fx.bridge->subscribe(s.id, json(1), "exec-a"));
    CHECK(fx.bus.subscriber_count("exec-a") == 1);

    fx.bus.publish("exec-a", "execution-progress", kProgress13);
    fx.bus.publish("exec-a", "execution-progress", kProgress13);
    fx.bus.publish("exec-a", "agent-transition", "{}");  // never projected
    // kArming latches: nothing reaches the ring no matter how long we wait.
    CHECK_FALSE(poll_until([&] { return s.stream->next_event_id() > 1; },
                           std::chrono::milliseconds(100)));

    REQUIRE(fx.bridge->abandon(s.id, json(1)));
    CHECK(fx.bus.subscriber_count("exec-a") == 0);
    CHECK(fx.bridge->record_count() == 0);
    CHECK(s.stream->next_event_id() == 1);  // ring untouched
    CHECK(fx.bridge->reserve(s.id, "alice", json(1), json("t"), true).ok);  // key freed
}

TEST_CASE("bridge GET-only lifecycle - live progress, no final, no pin", "[mcp][bridge][2f]") {
    Fx fx;
    auto s = fx.make_session();
    REQUIRE(fx.bridge->reserve(s.id, "alice", json(7), json(42), false).ok);
    REQUIRE(fx.bridge->subscribe(s.id, json(7), "exec-g"));
    REQUIRE(fx.bridge->arm(s.id, json(7), Bridge::ArmMode::kGetOnly) == Bridge::ArmOutcome::kArmed);

    fx.bus.publish("exec-g", "execution-progress", kProgress13);
    REQUIRE(poll_until([&] { return s.stream->next_event_id() > 1; }));
    {
        auto frames = ring_frames(*s.stream, "alice");
        REQUIRE(frames.size() == 1);
        auto j = json::parse(frames[0].data);
        CHECK(j["method"] == "notifications/progress");
        CHECK(j["params"]["progressToken"] == 42);
        CHECK(j["params"]["progress"] == 1);
        CHECK(j["params"]["total"] == 3);
        CHECK(j["params"]["_meta"]["yuzu.execution_id"] == "exec-g");
    }

    fx.bus.publish("exec-g", "execution-completed", kCompleted, /*is_terminal=*/true);
    fx.bus.publish("exec-g", "execution-completed", kCompleted, /*is_terminal=*/true);  // dup
    REQUIRE(poll_until([&] {
        auto ph = fx.bridge->phase_for(s.id, json(7));
        return ph.has_value() && *ph == Bridge::Phase::kDone;
    }));
    CHECK(s.stream->pinned_count() == 0);  // GET-only: NO final, NO pin
    {
        auto frames = ring_frames(*s.stream, "alice");
        CHECK(count_results(frames) == 0);
        CHECK(count_method(frames, "notifications/progress") == frames.size());
    }
    fx.bridge->sweep();
    CHECK(fx.bridge->record_count() == 0);
}

TEST_CASE("bridge parked terminal - one pinned final, result_base merged, final is last",
          "[mcp][bridge][2f]") {
    Fx fx;
    auto s = fx.make_session();
    const std::string base =
        R"({"content":[{"type":"text","text":"{\"execution_id\":\"exec-p\"}"}]})";
    REQUIRE(fx.bridge->reserve(s.id, "alice", json(9), json("tok"), true).ok);
    REQUIRE(fx.bridge->subscribe(s.id, json(9), "exec-p"));
    REQUIRE(fx.bridge->arm(s.id, json(9), Bridge::ArmMode::kStreaming, base) ==
            Bridge::ArmOutcome::kArmed);
    REQUIRE(fx.bridge->on_post_closed(s.id, json(9)));

    fx.bus.publish("exec-p", "execution-completed", kCompleted, /*is_terminal=*/true);
    fx.bus.publish("exec-p", "execution-completed", R"({"status":"failed"})",
                   /*is_terminal=*/true);  // dup - must be ignored (write-once terminal)
    REQUIRE(poll_until([&] { return s.stream->pinned_count() == 1; }));

    auto frames = ring_frames(*s.stream, "alice");
    REQUIRE(count_results(frames) == 1);
    auto fin = json::parse(frames.back().data);  // the final is LAST
    REQUIRE(fin.contains("result"));
    CHECK(fin["id"] == 9);
    // B5: today's nested result shape survives; additions are TOP-LEVEL result keys.
    CHECK(fin["result"]["content"][0]["type"] == "text");
    CHECK(fin["result"]["status"] == "completed");
    CHECK(fin["result"]["agents_success"] == 3);
    CHECK(fin["result"]["agents_failure"] == 0);
    CHECK_FALSE(fin["result"]["content"][0].contains("status"));

    // A7: post-terminal progress (a real publisher sequence) is dropped.
    const auto frames_before = frames.size();
    fx.bus.publish("exec-p", "execution-progress", kProgress13);
    CHECK_FALSE(poll_until([&] { return s.stream->next_event_id() > frames_before + 1; },
                           std::chrono::milliseconds(100)));
}

TEST_CASE("bridge flip-and-drain - no frame strands across arm (H2)", "[mcp][bridge][2f]") {
    Fx fx;
    auto s = fx.make_session();
    REQUIRE(fx.bridge->reserve(s.id, "alice", json(2), json("t"), false).ok);
    REQUIRE(fx.bridge->subscribe(s.id, json(2), "exec-h"));
    for (int i = 0; i < 4; ++i) {
        fx.bus.publish("exec-h", "execution-progress", kProgress13);  // latched pre-arm
    }
    std::atomic<bool> go{false};
    auto publisher = std::async(std::launch::async, [&] {
        go.store(true, std::memory_order_release);
        for (int i = 0; i < 8; ++i) {
            fx.bus.publish("exec-h", "execution-progress", kProgress13);
        }
    });
    while (!go.load(std::memory_order_acquire)) {
        std::this_thread::yield();
    }
    REQUIRE(fx.bridge->arm(s.id, json(2), Bridge::ArmMode::kGetOnly) == Bridge::ArmOutcome::kArmed);
    publisher.get();
    // Eventual totality: every one of the 12 frames reaches the ring - whether it
    // landed pre-flip (drained by the handoff wake) or post-flip (listener wake).
    REQUIRE(poll_until([&] { return s.stream->next_event_id() == 13; }));
    CHECK(count_method(ring_frames(*s.stream, "alice"), "notifications/progress") == 12);
}

TEST_CASE("bridge listener fault - contained, counted, one-shot", "[mcp][bridge][2f]") {
    Fx fx;
    auto s = fx.make_session();
    REQUIRE(fx.bridge->reserve(s.id, "alice", json(3), json("t"), false).ok);
    REQUIRE(fx.bridge->subscribe(s.id, json(3), "exec-f"));
    REQUIRE(fx.bridge->arm(s.id, json(3), Bridge::ArmMode::kGetOnly) == Bridge::ArmOutcome::kArmed);

    fx.bridge->inject_listener_fault_for_test();
    fx.bus.publish("exec-f", "execution-progress", kProgress13);  // eaten by the fault
    // The bus survives (the boundary held) and the next publish delivers normally.
    fx.bus.publish("exec-f", "execution-progress", kProgress13);
    REQUIRE(poll_until([&] { return s.stream->next_event_id() > 1; }));
    CHECK(ring_frames(*s.stream, "alice").size() == 1);  // exactly one frame - one was eaten
    // The failure is counted record-locally and flushed by the projector.
    REQUIRE(poll_until(
        [&] { return fx.reg.counter("yuzu_mcp_bridge_listener_failures_total").value() == 1.0; }));
}

TEST_CASE("bridge immediate terminal via replay - subscribe after completion",
          "[mcp][bridge][2f]") {
    Fx fx;
    auto s = fx.make_session();
    // The execution completed BEFORE anyone subscribed (the operator-cancel /
    // instant-execution class). subscribe_and_replay(0) routes the buffered
    // terminal through the normal listener.
    fx.bus.publish("exec-i", "execution-completed", kCompleted, /*is_terminal=*/true);
    REQUIRE(fx.bridge->reserve(s.id, "alice", json(4), json("t"), true).ok);
    REQUIRE(fx.bridge->subscribe(s.id, json(4), "exec-i"));
    REQUIRE(fx.bridge->arm(s.id, json(4), Bridge::ArmMode::kStreaming) ==
            Bridge::ArmOutcome::kArmed);
    REQUIRE(fx.bridge->on_post_closed(s.id, json(4)));
    REQUIRE(poll_until([&] { return s.stream->pinned_count() == 1; }));
    CHECK(count_results(ring_frames(*s.stream, "alice")) == 1);
}

TEST_CASE("bridge second-thread terminal vs park (TSan)", "[mcp][bridge][2f]") {
    Fx fx;
    auto s = fx.make_session();
    REQUIRE(fx.bridge->reserve(s.id, "alice", json(5), json("t"), true).ok);
    REQUIRE(fx.bridge->subscribe(s.id, json(5), "exec-t"));
    auto flood = std::async(std::launch::async, [&] {
        for (int i = 0; i < 50; ++i) {
            fx.bus.publish("exec-t", "execution-progress", kProgress13);
        }
        fx.bus.publish("exec-t", "execution-completed", kCompleted, /*is_terminal=*/true);
    });
    REQUIRE(fx.bridge->arm(s.id, json(5), Bridge::ArmMode::kStreaming) ==
            Bridge::ArmOutcome::kArmed);
    REQUIRE(fx.bridge->on_post_closed(s.id, json(5)));
    flood.get();
    REQUIRE(poll_until([&] { return s.stream->pinned_count() == 1; }));
    auto frames = ring_frames(*s.stream, "alice");
    CHECK(count_results(frames) == 1);
    // The final is last on the ring, whatever subset of the flood survived the
    // bounded mailbox.
    CHECK(json::parse(frames.back().data).contains("result"));
}

TEST_CASE("bridge pin-ack sweep - resume consumption frees streamed admission",
          "[mcp][bridge][2f]") {
    Fx fx;
    auto s = fx.make_session();
    std::vector<std::uint64_t> pinned;
    for (int i = 1; i <= 4; ++i) {
        const std::string exec = "exec-pin-" + std::to_string(i);
        REQUIRE(fx.bridge->reserve(s.id, "alice", json(i), json("t"), true).ok);
        REQUIRE(fx.bridge->subscribe(s.id, json(i), exec));
        REQUIRE(fx.bridge->arm(s.id, json(i), Bridge::ArmMode::kStreaming) ==
                Bridge::ArmOutcome::kArmed);
        REQUIRE(fx.bridge->on_post_closed(s.id, json(i)));
        fx.bus.publish(exec, "execution-completed", kCompleted, /*is_terminal=*/true);
        REQUIRE(poll_until(
            [&, i] { return s.stream->pinned_count() == static_cast<std::size_t>(i); }));
    }
    CHECK(std::string(fx.bridge->reserve(s.id, "alice", json(5), json("t"), true).reject_reason) ==
          "pin_slots");

    // Find the SMALLEST pinned id and consume exactly it via a resume cursor
    // (Last-Event-ID >= pinned_id is the consumption proof).
    std::uint64_t smallest = 0;
    for (std::uint64_t id = 1; id < s.stream->next_event_id(); ++id) {
        if (s.stream->is_pinned(id)) {
            smallest = id;
            break;
        }
    }
    REQUIRE(smallest != 0);
    auto att = s.stream->attach_and_replay(smallest, nullptr, "alice");
    REQUIRE(att.status == mcp::McpStreamState::AttachStatus::kAttached);
    s.stream->detach(att.sink);
    CHECK(s.stream->pinned_count() == 3);

    fx.bridge->sweep();  // pin-ack teardown reaps the consumed record
    CHECK(fx.bridge->record_count() == 3);
    CHECK(fx.bridge->reserve(s.id, "alice", json(5), json("t"), true).ok);
    CHECK(fx.audit_count("mcp.bridge.pin_acked") == 1);
}

TEST_CASE("bridge pressure - oldest without a terminal gets -32014; a real final is never lost",
          "[mcp][bridge][2f]") {
    SECTION("victim without a terminal: synthesized, pinned, carries the durable handle") {
        Fx fx{Bridge::Config{.global_record_cap = 256, .ring_only_pressure_cap = 1}};
        auto s = fx.make_session();
        // Record A (older): parked, never completes.
        REQUIRE(fx.bridge->reserve(s.id, "alice", json("a"), json("t"), true).ok);
        REQUIRE(fx.bridge->subscribe(s.id, json("a"), "exec-old"));
        REQUIRE(fx.bridge->arm(s.id, json("a"), Bridge::ArmMode::kStreaming) ==
                Bridge::ArmOutcome::kArmed);
        REQUIRE(fx.bridge->on_post_closed(s.id, json("a")));
        // Record B (newer): parked with a real pinned final.
        REQUIRE(fx.bridge->reserve(s.id, "alice", json("b"), json("t"), true).ok);
        REQUIRE(fx.bridge->subscribe(s.id, json("b"), "exec-new"));
        REQUIRE(fx.bridge->arm(s.id, json("b"), Bridge::ArmMode::kStreaming) ==
                Bridge::ArmOutcome::kArmed);
        REQUIRE(fx.bridge->on_post_closed(s.id, json("b")));
        fx.bus.publish("exec-new", "execution-completed", kCompleted, /*is_terminal=*/true);
        REQUIRE(poll_until([&] { return s.stream->pinned_count() == 1; }));

        REQUIRE(fx.bridge->ring_only_count() == 2);
        fx.bridge->sweep();
        CHECK(fx.bridge->ring_only_count() == 1);
        CHECK_FALSE(fx.bridge->phase_for(s.id, json("a")).has_value());  // A erased
        CHECK(fx.bridge->phase_for(s.id, json("b")).has_value());        // B untouched

        auto frames = ring_frames(*s.stream, "alice");
        REQUIRE(count_error_code(frames, mcp::kMcpTerminalUnavailable) == 1);
        for (const auto& f : frames) {
            auto j = json::parse(f.data);
            if (j.contains("error")) {
                CHECK(j["id"] == "a");  // echoed request id
                const auto& data = j["error"]["data"];  // A4 object, embedded raw
                REQUIRE(data.is_object());
                CHECK(data["execution_id"] == "exec-old");
                CHECK(data.contains("correlation_id"));
                CHECK(s.stream->is_pinned(f.id));  // resume-replayable
            }
        }
        CHECK(fx.audit_count("mcp.bridge.forced_expire") == 1);
        // Real final of B still pinned and present.
        CHECK(count_results(frames) == 1);
        CHECK(s.stream->pinned_count() == 2);  // B's real final + A's synthesized one
    }
    SECTION("victim WITH a settled real final: torn down, NO synthesis, pin survives") {
        Fx fx{Bridge::Config{.global_record_cap = 256, .ring_only_pressure_cap = 0}};
        auto s = fx.make_session();
        REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), true).ok);
        REQUIRE(fx.bridge->subscribe(s.id, json(1), "exec-s"));
        REQUIRE(fx.bridge->arm(s.id, json(1), Bridge::ArmMode::kStreaming) ==
                Bridge::ArmOutcome::kArmed);
        REQUIRE(fx.bridge->on_post_closed(s.id, json(1)));
        fx.bus.publish("exec-s", "execution-completed", kCompleted, /*is_terminal=*/true);
        REQUIRE(poll_until([&] { return s.stream->pinned_count() == 1; }));
        std::uint64_t final_id = 0;
        for (std::uint64_t id = 1; id < s.stream->next_event_id(); ++id) {
            if (s.stream->is_pinned(id)) {
                final_id = id;
            }
        }
        REQUIRE(final_id != 0);

        REQUIRE(poll_until([&] {
            fx.bridge->sweep();
            return fx.bridge->record_count() == 0;
        }));
        auto frames = ring_frames(*s.stream, "alice");
        CHECK(count_error_code(frames, mcp::kMcpTerminalUnavailable) == 0);  // no synthesis
        CHECK(count_results(frames) == 1);
        CHECK(s.stream->is_pinned(final_id));  // truth stays in the ring
    }
    SECTION("terminal racing the pressure sweep: the real result always wins") {
        // Property form of the E1/D1 barrier: publish the terminal while sweeps
        // hammer the victim. Whatever interleaving occurs, the invariant is ONE
        // real final, ZERO -32014, and the record eventually reaped.
        Fx fx{Bridge::Config{.global_record_cap = 256, .ring_only_pressure_cap = 0}};
        auto s = fx.make_session();
        REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), true).ok);
        REQUIRE(fx.bridge->subscribe(s.id, json(1), "exec-r"));
        REQUIRE(fx.bridge->arm(s.id, json(1), Bridge::ArmMode::kStreaming) ==
                Bridge::ArmOutcome::kArmed);
        for (int i = 0; i < 3; ++i) {
            fx.bus.publish("exec-r", "execution-progress", kProgress13);
        }
        REQUIRE(fx.bridge->on_post_closed(s.id, json(1)));
        // Bounded sweeper: a regression that never reaps must FAIL FAST (a wall-
        // clock deadline), not hang CI forever (governance quality).
        auto sweeper = std::async(std::launch::async, [&] {
            const auto until = std::chrono::steady_clock::now() + std::chrono::seconds(5);
            while (fx.bridge->record_count() != 0) {
                if (std::chrono::steady_clock::now() >= until) {
                    return false;
                }
                fx.bridge->sweep();
                std::this_thread::yield();
            }
            return true;
        });
        fx.bus.publish("exec-r", "execution-completed", kCompleted, /*is_terminal=*/true);
        REQUIRE(sweeper.get());  // reaped within the deadline
        auto frames = ring_frames(*s.stream, "alice");
        CHECK(count_error_code(frames, mcp::kMcpTerminalUnavailable) == 0);
        CHECK(count_results(frames) == 1);
    }
}

TEST_CASE("bridge session-death sweep - non-touching exists, registry untouched",
          "[mcp][bridge][2f]") {
    Fx fx;
    auto s = fx.make_session();
    REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), true).ok);
    REQUIRE(fx.bridge->subscribe(s.id, json(1), "exec-d"));
    REQUIRE(fx.bridge->arm(s.id, json(1), Bridge::ArmMode::kStreaming) ==
            Bridge::ArmOutcome::kArmed);
    REQUIRE(fx.bridge->on_post_closed(s.id, json(1)));

    fx.clock_s->store(1801);  // idle_ttl (1800 s) + 1: expired, but NOTHING has touched it
    fx.bridge->sweep();
    CHECK(fx.bridge->record_count() == 0);
    CHECK(fx.audit_count("mcp.bridge.session_dead") == 1);
    // The sweep classified via exists() WITHOUT gc'ing the registry - the dead
    // entry (and its stream/pins) waits for a touching call or gc(). That gap is
    // exactly why the 3a.7 tick must pair sweep() with McpSessionRegistry::gc().
    CHECK(fx.sessions.active_count() == 1);
    fx.sessions.gc();
    CHECK(fx.sessions.active_count() == 0);
}

TEST_CASE("bridge cancel arbitration (C1) - pending intent, arm/abandon decide",
          "[mcp][bridge][2f]") {
    SECTION("cancel then arm(kStreaming): degrade to GET-only, charge freed, audited once") {
        Fx fx;
        auto s = fx.make_session();
        REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), true).ok);
        REQUIRE(fx.bridge->subscribe(s.id, json(1), "exec-c"));
        CHECK(fx.bridge->request_cancel(s.id, json(1)) == Bridge::CancelOutcome::kAcceptedPending);
        CHECK(fx.bridge->request_cancel(s.id, json(1)) == Bridge::CancelOutcome::kNoOp);  // dup
        CHECK(fx.audit_count("mcp.bridge.cancel") == 0);  // C1: no audit before the win

        CHECK(fx.bridge->arm(s.id, json(1), Bridge::ArmMode::kStreaming) ==
              Bridge::ArmOutcome::kDegradedGetOnly);
        CHECK(fx.audit_count("mcp.bridge.cancel") == 1);
        auto ph = fx.bridge->phase_for(s.id, json(1));
        REQUIRE(ph.has_value());
        CHECK(*ph == Bridge::Phase::kArmedGetOnly);
        CHECK(fx.bus.subscriber_count("exec-c") == 1);  // subscription retained

        // The streamed charge was released: four MORE streamed records fit.
        for (int i = 2; i <= 5; ++i) {
            REQUIRE(fx.bridge->reserve(s.id, "alice", json(i), json("t"), true).ok);
        }
        // GET-only lifecycle to completion: no pin ever.
        fx.bus.publish("exec-c", "execution-completed", kCompleted, /*is_terminal=*/true);
        REQUIRE(poll_until([&] {
            auto p = fx.bridge->phase_for(s.id, json(1));
            return p.has_value() && *p == Bridge::Phase::kDone;
        }));
        CHECK(s.stream->pinned_count() == 0);
    }
    SECTION("cancel then abandon: abandon wins, the pending cancel dies unaudited") {
        Fx fx;
        auto s = fx.make_session();
        REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), true).ok);
        CHECK(fx.bridge->request_cancel(s.id, json(1)) == Bridge::CancelOutcome::kAcceptedPending);
        REQUIRE(fx.bridge->abandon(s.id, json(1)));
        CHECK(fx.audit_count("mcp.bridge.cancel") == 0);  // no cancel audit for a dead request
        CHECK(fx.bridge->record_count() == 0);
        CHECK(fx.bridge->arm(s.id, json(1), Bridge::ArmMode::kStreaming) ==
              Bridge::ArmOutcome::kNotFound);
    }
    SECTION("cancel after arm: kNoOp (nothing to detach in 3a)") {
        Fx fx;
        auto s = fx.make_session();
        REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), false).ok);
        REQUIRE(fx.bridge->arm(s.id, json(1), Bridge::ArmMode::kGetOnly) ==
                Bridge::ArmOutcome::kArmed);
        CHECK(fx.bridge->request_cancel(s.id, json(1)) == Bridge::CancelOutcome::kNoOp);
    }
    SECTION("arm-vs-abandon race: exactly one arbitration winner (TSan)") {
        Fx fx;
        auto s = fx.make_session();
        for (int i = 0; i < 50; ++i) {
            REQUIRE(fx.bridge->reserve(s.id, "alice", json(i), json("t"), false).ok);
            std::atomic<bool> go{false};
            auto armer = std::async(std::launch::async, [&] {
                while (!go.load(std::memory_order_acquire)) {
                    std::this_thread::yield();
                }
                return fx.bridge->arm(s.id, json(i), Bridge::ArmMode::kGetOnly);
            });
            auto abandoner = std::async(std::launch::async, [&] {
                go.store(true, std::memory_order_release);
                return fx.bridge->abandon(s.id, json(i));
            });
            const auto armed = armer.get();
            const bool abandoned = abandoner.get();
            // Exactly one wins the kArming exit.
            CHECK((armed == Bridge::ArmOutcome::kArmed) == !abandoned);
            if (abandoned) {
                CHECK((armed == Bridge::ArmOutcome::kAborted ||
                       armed == Bridge::ArmOutcome::kNotFound));
                CHECK_FALSE(fx.bridge->phase_for(s.id, json(i)).has_value());
            } else {
                REQUIRE(fx.bridge->abandon(s.id, json(i)) == false);  // arm won: abandon inert
                auto ph = fx.bridge->phase_for(s.id, json(i));
                REQUIRE(ph.has_value());
                CHECK(*ph == Bridge::Phase::kArmedGetOnly);
            }
        }
    }
}

TEST_CASE("McpSessionRegistry::exists - non-touching, non-erasing, no oracle",
          "[mcp][bridge][2f][session]") {
    yuzu::MetricsRegistry reg;
    auto base = std::chrono::steady_clock::now();
    auto offset = std::make_shared<std::atomic<std::int64_t>>(0);
    mcp::McpSessionRegistry sessions{
        mcp::McpSessionRegistry::Config{},
        [base, offset] { return base + std::chrono::seconds(offset->load()); }, &reg};
    auto minted = sessions.mint("alice");
    REQUIRE(minted.ok);
    const auto& id = minted.session_id;

    CHECK(sessions.exists(id, "alice"));
    CHECK_FALSE(sessions.exists(id, "mallory"));   // foreign principal reads as absent
    CHECK_FALSE(sessions.exists("nope", "alice"));

    // Boundary: age == idle_ttl is still alive (gc expires strictly greater).
    offset->store(1800);
    CHECK(sessions.exists(id, "alice"));
    // Hammer exists() at the boundary, then step past it: if exists() slid
    // last_seen, these reads would have kept the session alive forever.
    for (int i = 0; i < 5; ++i) {
        CHECK(sessions.exists(id, "alice"));
    }
    offset->store(1801);
    CHECK_FALSE(sessions.exists(id, "alice"));
    // …and it erased NOTHING: the entry is still in the map until a touching
    // call runs gc.
    CHECK(sessions.active_count() == 1);
    CHECK(sessions.validate_and_touch(id, "alice") ==
          mcp::McpSessionRegistry::ValidateResult::kUnknown);
    CHECK(sessions.active_count() == 0);
}

TEST_CASE("bridge mailbox bounds - drop-oldest progress, terminal never dropped",
          "[mcp][bridge][2f]") {
    Fx fx;
    auto s = fx.make_session();
    REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), false).ok);
    REQUIRE(fx.bridge->subscribe(s.id, json(1), "exec-m"));
    // 20 progress frames latch during kArming into the 16-slot ring; the 4
    // OLDEST are dropped. Stamp each with a distinct agents_responded.
    for (int i = 1; i <= 20; ++i) {
        fx.bus.publish("exec-m", "execution-progress",
                       R"({"agents_responded":)" + std::to_string(i) +
                           R"(,"agents_targeted":20})");
    }
    fx.bus.publish("exec-m", "execution-completed", kCompleted, /*is_terminal=*/true);
    REQUIRE(fx.bridge->arm(s.id, json(1), Bridge::ArmMode::kGetOnly) == Bridge::ArmOutcome::kArmed);
    REQUIRE(poll_until([&] {
        auto ph = fx.bridge->phase_for(s.id, json(1));
        return ph.has_value() && *ph == Bridge::Phase::kDone;  // terminal survived the deluge
    }));
    auto frames = ring_frames(*s.stream, "alice");
    REQUIRE(frames.size() == 16);  // newest 16, in order; GET-only ⇒ no final frame
    CHECK(json::parse(frames.front().data)["params"]["progress"] == 5);
    CHECK(json::parse(frames.back().data)["params"]["progress"] == 20);
    REQUIRE(poll_until(
        [&] { return fx.reg.counter("yuzu_mcp_bridge_mailbox_drops_total").value() == 4.0; }));
}

TEST_CASE("bridge shutdown - idempotent, dtor-safe, gates every mutator", "[mcp][bridge][2f]") {
    SECTION("explicit shutdown twice, then destruction") {
        Fx fx;
        auto s = fx.make_session();
        REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), true).ok);
        REQUIRE(fx.bridge->subscribe(s.id, json(1), "exec-z"));
        fx.bridge->shutdown();
        fx.bridge->shutdown();  // idempotent
        CHECK(fx.bus.subscriber_count("exec-z") == 0);
        CHECK(std::string(fx.bridge->reserve(s.id, "alice", json(2), json("t"), false)
                              .reject_reason) == "shutdown");
        CHECK(fx.bridge->arm(s.id, json(1), Bridge::ArmMode::kGetOnly) ==
              Bridge::ArmOutcome::kNotFound);
        CHECK_FALSE(fx.bridge->abandon(s.id, json(1)));
        CHECK_FALSE(fx.bridge->on_post_closed(s.id, json(1)));
        CHECK(fx.bridge->request_cancel(s.id, json(1)) == Bridge::CancelOutcome::kNoOp);
        fx.bridge->sweep();  // no-op, no crash
        fx.bridge.reset();   // dtor after explicit shutdown: no double teardown
    }
    SECTION("destruction WITHOUT explicit shutdown joins and unsubscribes") {
        Fx fx;
        auto s = fx.make_session();
        REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), true).ok);
        REQUIRE(fx.bridge->subscribe(s.id, json(1), "exec-y"));
        fx.bus.publish("exec-y", "execution-progress", kProgress13);
        fx.bridge.reset();  // ~McpStreamBridge → shutdown(): joins projector, unsubscribes
        CHECK(fx.bus.subscriber_count("exec-y") == 0);
    }
}

TEST_CASE("bridge double terminal-publish failure - poison, counted, charge freed",
          "[mcp][bridge][2f]") {
    Fx fx;
    auto s = fx.make_session();
    REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), true).ok);
    REQUIRE(fx.bridge->subscribe(s.id, json(1), "exec-x"));
    REQUIRE(fx.bridge->arm(s.id, json(1), Bridge::ArmMode::kStreaming) ==
            Bridge::ArmOutcome::kArmed);
    REQUIRE(fx.bridge->on_post_closed(s.id, json(1)));
    // Both the real final AND the fallback retry fail pre-commit - only the
    // repeat-count seam can arm this, both publishes happen in ONE projector pass.
    s.stream->inject_publish_fault_for_test(mcp::McpStreamState::PublishFault::kPreCommit, 2);
    fx.bus.publish("exec-x", "execution-completed", kCompleted, /*is_terminal=*/true);
    REQUIRE(poll_until([&] {
        auto att = s.stream->attach_and_replay(0, nullptr, "alice");
        const bool poisoned = att.status == mcp::McpStreamState::AttachStatus::kPoisoned;
        if (att.sink) {
            s.stream->detach(att.sink);
        }
        return poisoned;
    }));
    CHECK(fx.reg.counter("yuzu_mcp_stream_terminal_publish_failures_total").value() >= 2.0);
    // The charge settled pinless: the session's four streamed slots are free again.
    for (int i = 2; i <= 5; ++i) {
        REQUIRE(fx.bridge->reserve(s.id, "alice", json(i), json("t"), true).ok);
    }
}

TEST_CASE("bridge observability faults - outcomes unchanged, deltas restored (D3/C5)",
          "[mcp][bridge][2f]") {
    Fx fx;
    auto s = fx.make_session();
    SECTION("a reject is still a reject when its counter throws") {
        fx.bridge->inject_observability_fault_for_test(1);
        auto r = fx.bridge->reserve("nope", "alice", json(1), std::nullopt, false);
        CHECK_FALSE(r.ok);
        CHECK(std::string(r.reject_reason) == "unknown_session");
        CHECK(fx.reg.counter("yuzu_mcp_bridge_reject_total", {{"reason", "unknown_session"}})
                  .value() == 0.0);  // the increment failed - silently, by design
    }
    SECTION("a transiently failing flush restores the delta for a later pass") {
        REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), false).ok);
        REQUIRE(fx.bridge->subscribe(s.id, json(1), "exec-o"));
        // Latch 20 progress frames during kArming so the 16-slot mailbox
        // genuinely overflows (4 drops) - arming AFTER would let the projector
        // keep pace and never drop.
        for (int i = 1; i <= 20; ++i) {
            fx.bus.publish("exec-o", "execution-progress", kProgress13);
        }
        // Fault every observability call across the drain: the 4-drop delta must
        // NOT be lost - it parks (restored) and lands once the fault clears.
        fx.bridge->inject_observability_fault_for_test(1000);
        REQUIRE(fx.bridge->arm(s.id, json(1), Bridge::ArmMode::kGetOnly) ==
                Bridge::ArmOutcome::kArmed);
        REQUIRE(poll_until([&] { return s.stream->next_event_id() > 16; }));
        fx.bridge->inject_observability_fault_for_test(0);  // heal
        // Another wake flushes the restored/pending delta.
        fx.bus.publish("exec-o", "execution-progress", kProgress13);
        REQUIRE(poll_until(
            [&] { return fx.reg.counter("yuzu_mcp_bridge_mailbox_drops_total").value() >= 4.0; }));
    }
}

TEST_CASE("bridge arm() throw leaves the record cleanly abandonable (Sol finding 2)",
          "[mcp][bridge][2f]") {
    // A pre-flip allocation failure in arm() (result_base copy / fallback build)
    // must throw WITHOUT having mutated the record, so it stays kArming and the
    // handler's guard can abandon it - no leaked global slot, no half-armed state.
    Fx fx;
    auto s = fx.make_session();
    REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), true).ok);
    REQUIRE(fx.bridge->subscribe(s.id, json(1), "exec-af"));
    fx.bridge->inject_arm_fault_for_test();
    CHECK_THROWS_AS(fx.bridge->arm(s.id, json(1), Bridge::ArmMode::kGetOnly),
                    std::bad_alloc);
    // Still kArming - the throw was pre-flip, nothing changed.
    auto ph = fx.bridge->phase_for(s.id, json(1));
    REQUIRE(ph.has_value());
    CHECK(*ph == Bridge::Phase::kArming);
    // abandon cleans it, the subscription is torn down, the slot frees.
    REQUIRE(fx.bridge->abandon(s.id, json(1)));
    CHECK(fx.bridge->record_count() == 0);
    CHECK(fx.bus.subscriber_count("exec-af") == 0);
    // The one-shot fault cleared: a fresh reserve+arm now succeeds.
    REQUIRE(fx.bridge->reserve(s.id, "alice", json(2), json("t"), true).ok);
    REQUIRE(fx.bridge->subscribe(s.id, json(2), "exec-af2"));
    CHECK(fx.bridge->arm(s.id, json(2), Bridge::ArmMode::kGetOnly) == Bridge::ArmOutcome::kArmed);
}

TEST_CASE("bridge reserve()/subscribe() throw is contained by the caller (Sol/quality)",
          "[mcp][bridge][2f]") {
    // The reserve/subscribe fault seams model an allocation failure; the bridge
    // methods propagate (the execute_instruction handler catches + degrades - see
    // the handler test). Bridge-level: prove the throw leaves no half-state.
    Fx fx;
    auto s = fx.make_session();
    SECTION("reserve throw leaves no record") {
        fx.bridge->inject_reserve_fault_for_test();
        CHECK_THROWS_AS(fx.bridge->reserve(s.id, "alice", json(1), json("t"), false),
                        std::bad_alloc);
        CHECK(fx.bridge->record_count() == 0);  // threw after admission, before insert
        // one-shot cleared: a fresh reserve succeeds
        CHECK(fx.bridge->reserve(s.id, "alice", json(1), json("t"), false).ok);
    }
    SECTION("subscribe throw leaves the record unsubscribed (caller abandons)") {
        REQUIRE(fx.bridge->reserve(s.id, "alice", json(2), json("t"), false).ok);
        fx.bridge->inject_subscribe_fault_for_test();
        CHECK_THROWS_AS(fx.bridge->subscribe(s.id, json(2), "exec-sf"), std::bad_alloc);
        CHECK(fx.bus.subscriber_count("exec-sf") == 0);  // no listener installed
        // The record is still kArming; abandon cleans it (the handler's path).
        REQUIRE(fx.bridge->abandon(s.id, json(2)));
        CHECK(fx.bridge->record_count() == 0);
    }
}

TEST_CASE("bridge kArming reaper - an orphaned reserved record is reclaimed (cpp-safety)",
          "[mcp][bridge][2f]") {
    // Models the double-bad_alloc corner: a record reserved but never armed (its
    // handler died between reserve and abandon). sweep() must reap it once it
    // ages past arming_reap_after, so the global slot is not leaked forever.
    Fx fx{Bridge::Config{.global_record_cap = 256,
                         .ring_only_pressure_cap = 64,
                         .arming_reap_after = std::chrono::seconds(100)}};
    // Injected clock so the age test is deterministic (no real sleep).
    auto base = std::chrono::steady_clock::now();
    auto offset = std::make_shared<std::atomic<std::int64_t>>(0);
    fx.bridge->set_clock_for_test(
        [base, offset] { return base + std::chrono::seconds(offset->load()); });

    auto s = fx.make_session();
    REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), true).ok);
    REQUIRE(fx.bridge->subscribe(s.id, json(1), "exec-orphan"));
    // Never armed. Before the threshold, sweep leaves it (it's "in flight").
    fx.bridge->sweep();
    CHECK(fx.bridge->record_count() == 1);
    auto ph = fx.bridge->phase_for(s.id, json(1));
    REQUIRE(ph.has_value());
    CHECK(*ph == Bridge::Phase::kArming);

    // Advance past the reap threshold: sweep reclaims it (unsubscribed, erased).
    offset->store(101);
    fx.bridge->sweep();
    CHECK(fx.bridge->record_count() == 0);
    CHECK(fx.bus.subscriber_count("exec-orphan") == 0);
    CHECK(fx.audit_count("mcp.bridge.arming_reaped") == 1);

    // A record that IS armed within the window is never reaped by age.
    REQUIRE(fx.bridge->reserve(s.id, "alice", json(2), json("t"), false).ok);
    REQUIRE(fx.bridge->arm(s.id, json(2), Bridge::ArmMode::kGetOnly) == Bridge::ArmOutcome::kArmed);
    offset->store(500);
    fx.bridge->sweep();  // kArmedGetOnly is NOT kArming - age reaper does not touch it
    auto ph2 = fx.bridge->phase_for(s.id, json(2));
    REQUIRE(ph2.has_value());
    CHECK(*ph2 != Bridge::Phase::kAborted);
}

TEST_CASE("bridge concurrent publish during shutdown - unsubscribe waits out listeners (TSan)",
          "[mcp][bridge][2f]") {
    // The teardown safety argument ("unsubscribe() waits out in-flight listeners")
    // under REAL contention: a publisher hammers the bus while the bridge is
    // destroyed. Primary value is the TSan leg (no UAF, no race, no lost throw).
    Fx fx;
    auto s = fx.make_session();
    REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), false).ok);
    REQUIRE(fx.bridge->subscribe(s.id, json(1), "exec-cs"));
    REQUIRE(fx.bridge->arm(s.id, json(1), Bridge::ArmMode::kGetOnly) == Bridge::ArmOutcome::kArmed);

    std::atomic<bool> stop{false};
    auto flood = std::async(std::launch::async, [&] {
        while (!stop.load(std::memory_order_acquire)) {
            fx.bus.publish("exec-cs", "execution-progress", kProgress13);
        }
    });
    // Let some frames flow, then destroy the bridge concurrently with the flood.
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
    fx.bridge.reset();  // ~McpStreamBridge -> shutdown(): joins projector, unsubscribes
    stop.store(true, std::memory_order_release);
    flood.get();
    CHECK(fx.bus.subscriber_count("exec-cs") == 0);  // unsubscribed cleanly
}

TEST_CASE("bridge sweep races the projector on a charged (streamed) record (TSan)",
          "[mcp][bridge][2f]") {
    // The streamed-charge ledger is exercised only on the kRingOnly path (3b-dead
    // in production, test-reachable). Race sweep against the projector settling a
    // real terminal on such a record: no double-teardown, no lost/duplicate
    // final, charge released exactly once. TSan is the point.
    Fx fx{Bridge::Config{.global_record_cap = 256, .ring_only_pressure_cap = 0}};
    auto s = fx.make_session();
    REQUIRE(fx.bridge->reserve(s.id, "alice", json(1), json("t"), true).ok);  // streamed_intent
    REQUIRE(fx.bridge->subscribe(s.id, json(1), "exec-cr"));
    REQUIRE(fx.bridge->arm(s.id, json(1), Bridge::ArmMode::kStreaming) == Bridge::ArmOutcome::kArmed);
    REQUIRE(fx.bridge->on_post_closed(s.id, json(1)));  // -> kRingOnly, charged

    auto sweeper = std::async(std::launch::async, [&] {
        const auto until = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (fx.bridge->record_count() != 0 && std::chrono::steady_clock::now() < until) {
            fx.bridge->sweep();
            std::this_thread::yield();
        }
    });
    fx.bus.publish("exec-cr", "execution-completed", kCompleted, /*is_terminal=*/true);
    sweeper.get();
    auto frames = ring_frames(*s.stream, "alice");
    CHECK(count_results(frames) == 1);        // exactly one real final
    CHECK(s.stream->pinned_count() == 1);     // its pin survives the torn-down record (spec E3)
    // Charge released EXACTLY ONCE. Admission = pinned_count() + streamed_unpinned:
    // the 1 orphan pin holds one slot, so EXACTLY 3 fresh streamed reserves fit
    // (1 + 3 == cap 4) and the 4th is rejected. If the charge had leaked (stuck
    // held) only 2 would fit; if double-released, the accounting would be wrong.
    REQUIRE(fx.bridge->reserve(s.id, "alice", json(2), json("t"), true).ok);
    REQUIRE(fx.bridge->reserve(s.id, "alice", json(3), json("t"), true).ok);
    REQUIRE(fx.bridge->reserve(s.id, "alice", json(4), json("t"), true).ok);
    CHECK(std::string(fx.bridge->reserve(s.id, "alice", json(5), json("t"), true).reject_reason) ==
          "pin_slots");
}
