// MCP GET SSE channel — replay ring, stream budget, and pump lifecycle
// (ADR-1005 Decision 15, track 2f PR 2). Maps to the P0 chaos scenarios this
// rung must carry: CH-2 (ring wrap + resume), CH-3 (per-session id namespace),
// CH-4 (revocation vs auth-backend outage), CH-5 (cap exhaustion), CH-6
// (worker-pool budget math).
//
// Everything here drives McpStreamState / McpStreamPump / StreamBudget directly:
// the pump takes a WriteFn rather than an httplib::DataSink precisely so the
// stream lifecycle is testable without an httplib acceptor thread (#438).

#include <catch2/catch_test_macros.hpp>

#include "../../../server/core/src/mcp_session.hpp"
#include "../../../server/core/src/mcp_stream.hpp"
#include "../../../server/core/src/stream_budget.hpp"

#include <yuzu/server/auth.hpp>

#include <atomic>
#include <string>
#include <thread>
#include <vector>

namespace mcp = yuzu::server::mcp;
namespace detail = yuzu::server::detail;

namespace {

/// Captures everything the pump writes, so a test can assert on the wire bytes.
struct FakeWire {
    std::string out;
    bool alive = true;

    mcp::McpStreamPump::WriteFn writer() {
        return [this](const char* p, std::size_t n) {
            if (!alive) {
                return false; // simulate a dead peer
            }
            out.append(p, n);
            return true;
        };
    }

    bool contains(std::string_view needle) const { return out.find(needle) != std::string::npos; }
};

mcp::McpStreamPump::Config fast_cfg(std::chrono::milliseconds grace = std::chrono::seconds(60)) {
    mcp::McpStreamPump::Config cfg;
    cfg.tick = std::chrono::milliseconds(10); // don't sleep 3 s in a unit test
    cfg.revalidate_grace = grace;
    return cfg;
}

} // namespace

// ── StreamBudget (CH-5, CH-6) ───────────────────────────────────────────────

TEST_CASE("StreamBudget: per-principal cap rejects the newcomer, never a live lease",
          "[mcp][stream][ch5]") {
    detail::StreamBudget budget{{.global_cap = 10}};
    constexpr std::size_t kPerPrincipal = 2;

    auto a = budget.try_acquire(detail::SseSurface::kMcpGet, "alice", kPerPrincipal);
    auto b = budget.try_acquire(detail::SseSurface::kMcpGet, "alice", kPerPrincipal);
    REQUIRE(a.lease);
    REQUIRE(b.lease);

    auto c = budget.try_acquire(detail::SseSurface::kMcpGet, "alice", kPerPrincipal);
    CHECK_FALSE(c.lease);
    CHECK(std::string(c.reject_reason) == detail::StreamBudget::kRejectPerPrincipal);
    // The two live leases are untouched — a cap hit denies the new stream, it does
    // not tear down streams that were already admitted.
    CHECK(budget.active_for(detail::SseSurface::kMcpGet, "alice") == 2);
    CHECK(a.lease);
    CHECK(b.lease);

    // A different principal is unaffected by alice's cap.
    auto d = budget.try_acquire(detail::SseSurface::kMcpGet, "bob", kPerPrincipal);
    CHECK(d.lease);
    CHECK(budget.active() == 3);
}

TEST_CASE("StreamBudget: global cap rejects across principals", "[mcp][stream][ch5]") {
    detail::StreamBudget budget{{.global_cap = 2}};
    constexpr std::size_t kPerPrincipal = 8;
    auto a = budget.try_acquire(detail::SseSurface::kMcpGet, "alice", kPerPrincipal);
    auto b = budget.try_acquire(detail::SseSurface::kMcpGet, "bob", kPerPrincipal);
    REQUIRE(a.lease);
    REQUIRE(b.lease);

    auto c = budget.try_acquire(detail::SseSurface::kMcpGet, "carol", kPerPrincipal);
    CHECK_FALSE(c.lease);
    CHECK(std::string(c.reject_reason) == detail::StreamBudget::kRejectGlobal);
}

TEST_CASE("StreamBudget: a lease returns its slot exactly once", "[mcp][stream][ch5]") {
    detail::StreamBudget budget{{.global_cap = 1}};
    constexpr std::size_t kPerPrincipal = 1;
    {
        auto a = budget.try_acquire(detail::SseSurface::kMcpGet, "alice", kPerPrincipal);
        REQUIRE(a.lease);
        CHECK(budget.active() == 1);
        a.lease.release();
        CHECK(budget.active() == 0);
        a.lease.release(); // idempotent — the destructor must not double-release
        CHECK(budget.active() == 0);
    }
    CHECK(budget.active() == 0);
    // Slot is genuinely free again.
    auto b = budget.try_acquire(detail::SseSurface::kMcpGet, "bob", kPerPrincipal);
    CHECK(b.lease);
}

TEST_CASE("StreamBudget: the per-principal map is bounded by LIVE principals",
          "[mcp][stream][ch5]") {
    detail::StreamBudget budget{{.global_cap = 100}};
    constexpr std::size_t kPerPrincipal = 1;
    for (int i = 0; i < 50; ++i) {
        auto lease = budget.try_acquire(detail::SseSurface::kMcpGet, "principal-" + std::to_string(i), kPerPrincipal);
        CHECK(lease.lease);
    } // each lease dies here
    // A per-principal entry that never erased at zero would leave 50 rows behind
    // for 50 principals that have long since disconnected.
    CHECK(budget.active() == 0);
    CHECK(budget.active_for(detail::SseSurface::kMcpGet, "principal-7") == 0);
}

TEST_CASE("derive_stream_budget: caps are clamped to what the worker pool can spare",
          "[mcp][stream][ch6]") {
    // Each permitted stream must be able to pin kMaxProvidersPerStream (2) workers —
    // a takeover leaves the superseded provider draining while its replacement runs —
    // so the affordable count is (pool - reserve) / 2, not (pool - reserve).
    // Smallest pool httplib will ever hand us: base 8 → max 32. (32-8)/2 = 12.
    CHECK(detail::derive_stream_budget(32, 8, 16) == 12);
    CHECK(detail::derive_stream_budget(32, 8, 8) == 8); // under the affordable count: honoured
    // An operator asking for more than the pool can spare gets clamped, not obeyed.
    CHECK(detail::derive_stream_budget(32, 8, 64) == 12);
    CHECK(detail::derive_stream_budget(64, 8, 64) == 28);
    // Degenerate pools cannot spare anything — streams are refused rather than
    // allowed to eat the plain-REST reserve.
    CHECK(detail::derive_stream_budget(8, 8, 16) == 0);
    CHECK(detail::derive_stream_budget(4, 8, 16) == 0);
    CHECK(detail::derive_stream_budget(0, 8, 16) == 0);
    // The floor on --http-worker-threads must ITSELF afford at least one stream, so
    // streaming cannot be silently disabled by a knob that reads like a tuning
    // parameter. Asserted UNSCALED: the old form multiplied the floor by 4, modelling
    // httplib's retired "base 8 grows to max 32" behaviour. The pool is now pinned
    // (pool_base == pool_max), so that factor was fiction — and it hid a real dead
    // zone, because the floor was 8, kPlainRestReserveDefault is 8, and (8-8)/2 == 0.
    CHECK(detail::derive_stream_budget(detail::kMinHttpWorkerThreads,
                                       detail::kPlainRestReserveDefault, 16) > 0);
    // Sweep every pinned value an operator could plausibly pass: each is clamped up to
    // the floor first, so none of them may yield a zero budget. This is the regression
    // guard — `--http-worker-threads 8` used to 429 every streaming surface server-wide.
    for (std::size_t pinned = 1; pinned <= 32; ++pinned) {
        const std::size_t pool = std::max(pinned, detail::kMinHttpWorkerThreads);
        INFO("pinned --http-worker-threads=" << pinned << " -> pool " << pool);
        CHECK(detail::derive_stream_budget(pool, detail::kPlainRestReserveDefault, 16) > 0);
    }
}

// ── Replay ring + resume (CH-2, CH-3) ───────────────────────────────────────

TEST_CASE("McpStreamState: event ids are per-session and start at 1 (CH-3)",
          "[mcp][stream][ch3]") {
    mcp::McpStreamState a;
    mcp::McpStreamState b;

    CHECK(a.publish("message", "one") == 1);
    CHECK(a.publish("message", "two") == 2);
    // A second session's namespace is independent — ids are NEVER global, so a
    // client resuming session B with an id it saw on session A cannot be served
    // another session's frames.
    CHECK(b.publish("message", "other") == 1);
    CHECK(a.next_event_id() == 3);
    CHECK(b.next_event_id() == 2);
}

TEST_CASE("McpStreamState: a fresh attach replays only the frames after the cursor (CH-2)",
          "[mcp][stream][ch2]") {
    mcp::McpStreamState state;
    for (int i = 1; i <= 5; ++i) {
        state.publish("message", "frame-" + std::to_string(i));
    }

    auto attached = state.attach_and_replay(/*last_event_id=*/3, nullptr, "alice");
    REQUIRE(attached.status == mcp::McpStreamState::AttachStatus::kAttached);
    REQUIRE(attached.sink);

    std::lock_guard<std::mutex> lk(attached.sink->sse->mu);
    REQUIRE(attached.sink->sse->queue.size() == 2); // 4 and 5 only — no duplicates
    // The id rides on the frame, not packed into the payload (a stringly-typed id
    // meant re-parsing it inside the content provider, where a throw is terminate).
    CHECK(attached.sink->sse->queue.front().id == 4);
    CHECK(attached.sink->sse->queue.front().data == "frame-4");
    CHECK(attached.sink->sse->queue.back().id == 5);
    CHECK(attached.sink->sse->queue.back().data == "frame-5");
}

TEST_CASE("McpStreamState: cursor 0 replays the whole surviving window (CH-2)",
          "[mcp][stream][ch2]") {
    mcp::McpStreamState state{/*ring_cap=*/3};
    for (int i = 1; i <= 5; ++i) {
        state.publish("message", "f" + std::to_string(i));
    }
    CHECK(state.evictions_total() == 2); // 1 and 2 evicted

    auto attached = state.attach_and_replay(0, nullptr, "alice");
    REQUIRE(attached.status == mcp::McpStreamState::AttachStatus::kAttached);
    std::lock_guard<std::mutex> lk(attached.sink->sse->mu);
    CHECK(attached.sink->sse->queue.size() == 3); // whatever the ring still holds
}

TEST_CASE("McpStreamState: a cursor past the ring window is a GAP, not a silent skip (CH-2)",
          "[mcp][stream][ch2]") {
    mcp::McpStreamState state{/*ring_cap=*/2};
    for (int i = 1; i <= 5; ++i) {
        state.publish("message", "f" + std::to_string(i));
    }
    // Ring holds 4,5. A client resuming from 1 missed 2 and 3, which are GONE. The
    // only honest answers are "here is your gap" or "re-initialize"; we take the
    // latter, and the caller turns it into a 404.
    CHECK(state.attach_and_replay(1, nullptr, "alice").status ==
          mcp::McpStreamState::AttachStatus::kGap);
    CHECK(state.attach_and_replay(2, nullptr, "alice").status ==
          mcp::McpStreamState::AttachStatus::kGap);
    // The boundary cursor (the frame right before the oldest we still hold) IS
    // serviceable — everything after it survives.
    CHECK(state.attach_and_replay(3, nullptr, "alice").status ==
          mcp::McpStreamState::AttachStatus::kAttached);
}

TEST_CASE("McpStreamState: a bogus future cursor takes the same path as an evicted one",
          "[mcp][stream][ch2]") {
    mcp::McpStreamState state;
    state.publish("message", "only");
    // A client claiming an id we have never issued is not resumable either. Same
    // recovery (re-initialize), and crucially the SAME answer — so the response
    // cannot be used to probe how many events a session has emitted.
    CHECK(state.attach_and_replay(99, nullptr, "alice").status ==
          mcp::McpStreamState::AttachStatus::kGap);
}

TEST_CASE("McpStreamState: a live sink receives published frames", "[mcp][stream]") {
    mcp::McpStreamState state;
    auto attached = state.attach_and_replay(0, nullptr, "alice");
    REQUIRE(attached.status == mcp::McpStreamState::AttachStatus::kAttached);

    state.publish("message", "live-frame");
    std::lock_guard<std::mutex> lk(attached.sink->sse->mu);
    REQUIRE(attached.sink->sse->queue.size() == 1);
    CHECK(attached.sink->sse->queue.front().id == 1);
    CHECK(attached.sink->sse->queue.front().data == "live-frame");
}

// ── Takeover + budget interaction (CH-5) ────────────────────────────────────

TEST_CASE("McpStreamState: a takeover is admitted at a full cap but is still COUNTED (CH-5)",
          "[mcp][stream][ch5]") {
    detail::StreamBudget budget{{.global_cap = 1}};
    constexpr std::size_t kPerPrincipal = 1;
    mcp::McpStreamState state;

    auto first = state.attach_and_replay(0, &budget, "alice");
    REQUIRE(first.status == mcp::McpStreamState::AttachStatus::kAttached);
    CHECK(budget.active() == 1);

    // The budget is full. A reconnect on the SAME session must still succeed: the
    // common second GET is a client re-attaching across a zombie TCP the server has
    // not noticed yet, and making it wait for its own zombie to time out would turn
    // the cap into a self-inflicted lockout.
    auto second = state.attach_and_replay(0, &budget, "alice");
    REQUIRE(second.status == mcp::McpStreamState::AttachStatus::kAttached);
    CHECK(second.generation > first.generation);

    // …but it takes its OWN lease. The superseded provider goes on pinning its worker
    // until it drains, and an UNCOUNTED pinned worker is exactly the hole the budget
    // exists to close: with lease inheritance, one client hammering GET on one session
    // could exhaust the pool while the gauge still read 1.
    CHECK(budget.active() == 2);

    // The superseded sink is closed with a reason the old provider will report.
    CHECK(first.sink->sse->closed.load());
    CHECK(first.sink->close_reason.load() == mcp::McpStreamClose::kSuperseded);
    CHECK(state.has_draining_sink());

    // Each sink returns its own worker.
    state.detach(first.sink);
    CHECK(budget.active() == 1);
    CHECK_FALSE(state.has_draining_sink());

    state.detach(second.sink);
    CHECK(budget.active() == 0);
}

TEST_CASE("McpStreamState: a second takeover is refused while the handover is pending (CH-5)",
          "[mcp][stream][ch5]") {
    // This is what BOUNDS the pool. A takeover skips the cap check, so without this
    // rule a client could hammer GET on one session and pin providers without limit —
    // each superseded one still holds a worker until it drains, and a peer with a
    // closed TCP window can stall that for the whole write timeout.
    detail::StreamBudget budget{{.global_cap = 100}};
    constexpr std::size_t kPerPrincipal = 100;
    mcp::McpStreamState state;

    auto first = state.attach_and_replay(0, &budget, "alice");
    REQUIRE(first.status == mcp::McpStreamState::AttachStatus::kAttached);
    auto second = state.attach_and_replay(0, &budget, "alice");
    REQUIRE(second.status == mcp::McpStreamState::AttachStatus::kAttached);

    // `first` has not detached yet, so the session already has its one draining sink.
    auto third = state.attach_and_replay(0, &budget, "alice");
    CHECK(third.status == mcp::McpStreamState::AttachStatus::kHandoverPending);
    CHECK_FALSE(third.sink);
    CHECK(budget.active() == 2); // never more than kMaxProvidersPerStream per session

    // Once the superseded provider drains, a takeover is allowed again.
    state.detach(first.sink);
    auto fourth = state.attach_and_replay(0, &budget, "alice");
    CHECK(fourth.status == mcp::McpStreamState::AttachStatus::kAttached);
    CHECK(budget.active() == 2);
}

TEST_CASE("McpStreamState: closing a sink wakes its pump immediately, not a tick later",
          "[mcp][stream][race]") {
    // Regression for a lost wakeup: `closed` is the pump's wait PREDICATE, so it must
    // be modified while holding the sink mutex. Storing it atomically outside the lock
    // and then notifying races the pump's release-and-block — the notify lands on an
    // empty wait queue and the provider sleeps the FULL tick. That is not just latency:
    // the superseded provider keeps pinning a worker for the whole 3 s.
    auto state = std::make_shared<mcp::McpStreamState>();
    auto attached = state->attach_and_replay(0, nullptr, "alice");
    REQUIRE(attached.status == mcp::McpStreamState::AttachStatus::kAttached);

    mcp::McpStreamPump::Config cfg;
    cfg.tick = std::chrono::seconds(30); // a wakeup that RELIES on the tick would hang
    mcp::McpStreamPump pump{attached.sink, state, attached.generation,
                            [] { return mcp::StreamRevalidate::kValid; }, [] { return true; }, cfg};

    std::atomic<bool> returned{false};
    FakeWire wire;
    std::thread pumper([&] {
        pump.pump_once(wire.writer());
        returned.store(true);
    });

    // Give the pump time to reach its wait, then close.
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    state->close(mcp::McpStreamClose::kSessionTerminated);
    pumper.join();

    CHECK(returned.load());
    CHECK(attached.sink->close_reason.load() == mcp::McpStreamClose::kSessionTerminated);
}

TEST_CASE("McpStreamState: a cap hit rejects the attach and leaves the ring intact",
          "[mcp][stream][ch5]") {
    // Global headroom to spare, so the PER-PRINCIPAL cap is the only constraint
    // that binds — and the reject reason must name that one, not the global cap it
    // is nowhere near (an operator raising the wrong knob fixes nothing).
    detail::StreamBudget budget{{.global_cap = 8}};
    constexpr std::size_t kPerPrincipal = 1; // the surface's own anti-monopoly policy
    mcp::McpStreamState busy;
    auto held = busy.attach_and_replay(0, &budget, "alice", kPerPrincipal);
    REQUIRE(held.status == mcp::McpStreamState::AttachStatus::kAttached);

    mcp::McpStreamState other;
    auto rejected = other.attach_and_replay(0, &budget, "alice", kPerPrincipal);
    CHECK(rejected.status == mcp::McpStreamState::AttachStatus::kStreamCapHit);
    CHECK(std::string(rejected.reject_reason) == detail::StreamBudget::kRejectPerPrincipal);
    CHECK_FALSE(rejected.sink);
    CHECK_FALSE(other.has_live_sink());
    CHECK(held.sink->close_reason.load() == mcp::McpStreamClose::kNone); // untouched
}

// ── Pump: heartbeats, revocation, grace window (CH-4) ───────────────────────

TEST_CASE("McpStreamPump: a healthy tick emits queued frames then a heartbeat",
          "[mcp][stream]") {
    auto state = std::make_shared<mcp::McpStreamState>();
    state->publish("message", R"({"ok":true})");
    auto attached = state->attach_and_replay(0, nullptr, "alice");
    REQUIRE(attached.status == mcp::McpStreamState::AttachStatus::kAttached);

    mcp::McpStreamPump pump{attached.sink, state, attached.generation,
                            [] { return mcp::StreamRevalidate::kValid; }, [] { return true; },
                            fast_cfg()};
    FakeWire wire;
    CHECK(pump.pump_once(wire.writer()));

    // The frame carries its id (that is what makes Last-Event-ID resume possible)…
    CHECK(wire.contains("id: 1\n"));
    CHECK(wire.contains("event: message\n"));
    CHECK(wire.contains(R"(data: {"ok":true})"));
    // …and the heartbeat deliberately does not (resuming onto a heartbeat's id
    // would skip real frames).
    CHECK(wire.contains("event: heartbeat\n"));
}

TEST_CASE("McpStreamPump/CH-4: a revoked credential kills the stream within one tick",
          "[mcp][stream][ch4]") {
    auto state = std::make_shared<mcp::McpStreamState>();
    auto attached = state->attach_and_replay(0, nullptr, "alice");
    REQUIRE(attached.status == mcp::McpStreamState::AttachStatus::kAttached);

    mcp::McpStreamPump pump{attached.sink, state, attached.generation,
                            [] { return mcp::StreamRevalidate::kRevoked; }, [] { return true; },
                            fast_cfg()};
    FakeWire wire;
    CHECK_FALSE(pump.pump_once(wire.writer())); // provider ends
    // The client is TOLD why — a revoked stream must not look like a clean EOF.
    CHECK(wire.contains(R"("reason":"credential_revoked")"));
    CHECK(attached.sink->close_reason.load() == mcp::McpStreamClose::kCredentialRevoked);
}

TEST_CASE("McpStreamPump/CH-4: an auth-backend outage buys a bounded grace window, not a kill",
          "[mcp][stream][ch4]") {
    auto state = std::make_shared<mcp::McpStreamState>();
    auto attached = state->attach_and_replay(0, nullptr, "alice");
    REQUIRE(attached.status == mcp::McpStreamState::AttachStatus::kAttached);

    auto clock_now = std::chrono::steady_clock::now();
    const auto grace = std::chrono::milliseconds(1000);
    mcp::McpStreamPump pump{
        attached.sink,   state, attached.generation,
        [] { return mcp::StreamRevalidate::kIndeterminate; },
        [] { return true; }, fast_cfg(grace), [&clock_now] { return clock_now; }};

    FakeWire wire;
    // Inside the window the stream SURVIVES: an unreachable auth backend is not
    // evidence of revocation, and cutting every live stream on a blip is the
    // failure mode this window exists to prevent.
    CHECK(pump.pump_once(wire.writer()));
    clock_now += std::chrono::milliseconds(500);
    CHECK(pump.pump_once(wire.writer()));

    // Past the window it dies — the grace is bounded, not indefinite.
    clock_now += std::chrono::milliseconds(1000);
    CHECK_FALSE(pump.pump_once(wire.writer()));
    // …and with a reason DISTINCT from revocation, so an operator can tell a
    // security event from an outage.
    CHECK(wire.contains(R"("reason":"auth_unavailable")"));
    CHECK(attached.sink->close_reason.load() == mcp::McpStreamClose::kAuthUnavailable);
}

TEST_CASE("McpStreamPump/CH-4: a recovered backend resets the grace window",
          "[mcp][stream][ch4]") {
    auto state = std::make_shared<mcp::McpStreamState>();
    auto attached = state->attach_and_replay(0, nullptr, "alice");
    auto clock_now = std::chrono::steady_clock::now();
    auto verdict = mcp::StreamRevalidate::kIndeterminate;

    mcp::McpStreamPump pump{attached.sink,
                            state,
                            attached.generation,
                            [&verdict] { return verdict; },
                            [] { return true; },
                            fast_cfg(std::chrono::milliseconds(1000)),
                            [&clock_now] { return clock_now; }};
    FakeWire wire;
    CHECK(pump.pump_once(wire.writer()));      // grace starts
    clock_now += std::chrono::milliseconds(900);
    verdict = mcp::StreamRevalidate::kValid;   // backend came back
    CHECK(pump.pump_once(wire.writer()));
    verdict = mcp::StreamRevalidate::kIndeterminate; // it flaps again
    clock_now += std::chrono::milliseconds(900);
    // If the window had NOT reset, this tick would be past the deadline and kill a
    // stream whose credential was verified 900 ms ago.
    CHECK(pump.pump_once(wire.writer()));
}

TEST_CASE("McpStreamPump: a terminated session ends the stream with its own reason",
          "[mcp][stream]") {
    auto state = std::make_shared<mcp::McpStreamState>();
    auto attached = state->attach_and_replay(0, nullptr, "alice");

    mcp::McpStreamPump pump{attached.sink, state, attached.generation,
                            [] { return mcp::StreamRevalidate::kValid; },
                            [] { return false; }, // DELETE / idle GC removed the session
                            fast_cfg()};
    FakeWire wire;
    CHECK_FALSE(pump.pump_once(wire.writer()));
    CHECK(wire.contains(R"("reason":"session_terminated")"));
}

TEST_CASE("McpStreamPump: a superseded pump exits WITHOUT writing a close frame",
          "[mcp][stream]") {
    auto state = std::make_shared<mcp::McpStreamState>();
    auto first = state->attach_and_replay(0, nullptr, "alice");
    mcp::McpStreamPump pump{first.sink, state, first.generation,
                            [] { return mcp::StreamRevalidate::kValid; }, [] { return true; },
                            fast_cfg()};

    auto second = state->attach_and_replay(0, nullptr, "alice"); // takeover
    REQUIRE(second.status == mcp::McpStreamState::AttachStatus::kAttached);

    FakeWire wire;
    CHECK_FALSE(pump.pump_once(wire.writer()));

    // No final frame, deliberately. The client already has a newer stream on this
    // session, so the only thing that can still be listening on THIS socket is the
    // stalled peer that provoked the takeover — and writing to it would block this
    // worker for the full write timeout while its lease is still charged. That
    // blocking write was the mechanism by which a rapid-reconnect client could pin
    // the pool.
    CHECK(wire.out.empty());
    CHECK(first.sink->close_reason.load() == mcp::McpStreamClose::kSuperseded);
}

TEST_CASE("McpStreamPump: a dead peer ends the stream", "[mcp][stream]") {
    auto state = std::make_shared<mcp::McpStreamState>();
    auto attached = state->attach_and_replay(0, nullptr, "alice");
    mcp::McpStreamPump pump{attached.sink, state, attached.generation,
                            [] { return mcp::StreamRevalidate::kValid; }, [] { return true; },
                            fast_cfg()};
    FakeWire wire;
    wire.alive = false; // every write fails, as on a closed socket
    CHECK_FALSE(pump.pump_once(wire.writer()));
}

TEST_CASE("McpStreamPump: a sink-queue overflow tells the client to resume, not nothing",
          "[mcp][stream]") {
    // Ring 2 == sink cap 2. Publish 4 frames while attached: the sink's drop-oldest
    // guard fires. The client must LEARN it lost frames (they are still in the ring,
    // so a Last-Event-ID reconnect can replay them) rather than see a silent hole.
    auto state = std::make_shared<mcp::McpStreamState>(/*ring_cap=*/2);
    auto attached = state->attach_and_replay(0, nullptr, "alice");
    for (int i = 0; i < 4; ++i) {
        state->publish("message", "f" + std::to_string(i));
    }
    REQUIRE(attached.sink->sse->dropped_total.load() > 0);

    mcp::McpStreamPump pump{attached.sink, state, attached.generation,
                            [] { return mcp::StreamRevalidate::kValid; }, [] { return true; },
                            fast_cfg()};
    FakeWire wire;
    CHECK(pump.pump_once(wire.writer()));
    CHECK(wire.contains("event: events-dropped"));
    CHECK(wire.contains("Last-Event-ID"));
}

// ── Registry ↔ stream lifecycle ─────────────────────────────────────────────

TEST_CASE("McpSessionRegistry: terminate closes the session's live stream",
          "[mcp][session][stream]") {
    mcp::McpSessionRegistry reg;
    const auto minted = reg.mint("alice");
    REQUIRE(minted.ok);

    auto stream = reg.stream_for(minted.session_id, "alice");
    REQUIRE(stream);
    auto attached = stream->attach_and_replay(0, nullptr, "alice");
    REQUIRE(attached.status == mcp::McpStreamState::AttachStatus::kAttached);

    REQUIRE(reg.terminate(minted.session_id, "alice"));
    // The provider is woken and given a reason — a DELETE must not present as a
    // bare connection drop.
    CHECK(attached.sink->sse->closed.load());
    CHECK(attached.sink->close_reason.load() == mcp::McpStreamClose::kSessionTerminated);
}

TEST_CASE("McpSessionRegistry: stream_for is principal-bound (no oracle)",
          "[mcp][session][stream]") {
    mcp::McpSessionRegistry reg;
    const auto minted = reg.mint("alice");
    REQUIRE(minted.ok);

    CHECK(reg.stream_for(minted.session_id, "alice"));
    // A real session id under the wrong principal answers exactly as a made-up one
    // does — nullptr, no signal that the id exists.
    CHECK_FALSE(reg.stream_for(minted.session_id, "mallory"));
    CHECK_FALSE(reg.stream_for(std::string(32, 'f'), "mallory"));
}

TEST_CASE("McpSessionRegistry: idle GC closes the stream of a reaped session",
          "[mcp][session][stream]") {
    auto clock_now = std::chrono::steady_clock::now();
    mcp::McpSessionRegistry reg{{.idle_ttl = std::chrono::seconds(30)},
                                [&clock_now] { return clock_now; }};
    const auto minted = reg.mint("alice");
    REQUIRE(minted.ok);
    auto stream = reg.stream_for(minted.session_id, "alice");
    auto attached = stream->attach_and_replay(0, nullptr, "alice");
    REQUIRE(attached.status == mcp::McpStreamState::AttachStatus::kAttached);

    clock_now += std::chrono::seconds(31);
    reg.gc();

    CHECK(reg.active_count() == 0);
    CHECK(attached.sink->sse->closed.load());
    CHECK(attached.sink->close_reason.load() == mcp::McpStreamClose::kSessionTerminated);
    // The state itself is still alive — the provider holds a reference, so the
    // registry's erase can never pull the rug from under a running pump.
    CHECK(stream->has_live_sink());
}

TEST_CASE("McpSessionRegistry: a live stream's ticking keeps its session young",
          "[mcp][session][stream]") {
    // The pump calls validate_and_touch every tick, which slides the TTL. That is
    // why a live stream needs no GC exemption: it stays young while it is genuinely
    // alive, and a zombie peer stops ticking and gets reaped on the normal schedule.
    auto clock_now = std::chrono::steady_clock::now();
    mcp::McpSessionRegistry reg{{.idle_ttl = std::chrono::seconds(30)},
                                [&clock_now] { return clock_now; }};
    const auto minted = reg.mint("alice");
    REQUIRE(minted.ok);

    for (int i = 0; i < 4; ++i) {
        clock_now += std::chrono::seconds(20);
        CHECK(reg.validate_and_touch(minted.session_id, "alice") ==
              mcp::McpSessionRegistry::ValidateResult::kValid);
    }
    CHECK(reg.active_count() == 1); // 80 s elapsed, TTL 30 s, still alive

    clock_now += std::chrono::seconds(31); // the ticking stops (peer went away)
    reg.gc();
    CHECK(reg.active_count() == 0);
}

// ── Concurrency (TSan net) ──────────────────────────────────────────────────

TEST_CASE("McpStreamState: concurrent publish / attach / detach / close is race-free",
          "[mcp][stream][race]") {
    auto state = std::make_shared<mcp::McpStreamState>(/*ring_cap=*/16);
    detail::StreamBudget budget{{.global_cap = 64}};
    constexpr std::size_t kPerPrincipal = 64;
    std::atomic<bool> stop{false};
    std::vector<std::thread> threads;

    threads.emplace_back([&] {
        for (int i = 0; i < 400; ++i) {
            state->publish("message", "f" + std::to_string(i));
        }
        stop.store(true);
    });
    for (int t = 0; t < 4; ++t) {
        threads.emplace_back([&] {
            while (!stop.load()) {
                auto a = state->attach_and_replay(0, &budget, "alice");
                if (a.status == mcp::McpStreamState::AttachStatus::kAttached) {
                    state->detach(a.sink);
                }
            }
        });
    }
    threads.emplace_back([&] {
        while (!stop.load()) {
            state->close(mcp::McpStreamClose::kSessionTerminated);
        }
    });
    for (auto& th : threads) {
        th.join();
    }

    CHECK(state->next_event_id() == 401);
    // THE accounting invariant: one lease per pinned provider, no more and no fewer.
    // A leak here is invisible in testing and fatal in production — MCP streaming
    // would slowly die over a server's uptime as slots were never returned.
    const std::size_t providers = (state->has_live_sink() ? 1u : 0u) +
                                  (state->has_draining_sink() ? 1u : 0u);
    CHECK(budget.active() == providers);
}

TEST_CASE("McpSessionRegistry: concurrent mint / stream_for / terminate is race-free",
          "[mcp][session][stream][race]") {
    mcp::McpSessionRegistry reg;
    std::vector<std::thread> threads;
    std::atomic<int> minted{0};

    for (int t = 0; t < 8; ++t) {
        threads.emplace_back([&, t] {
            const std::string principal = "p" + std::to_string(t % 3);
            for (int i = 0; i < 100; ++i) {
                auto m = reg.mint(principal);
                if (!m.ok) {
                    continue;
                }
                ++minted;
                if (auto s = reg.stream_for(m.session_id, principal)) {
                    s->publish("message", "x");
                }
                reg.terminate(m.session_id, principal);
            }
        });
    }
    for (auto& th : threads) {
        th.join();
    }
    CHECK(minted.load() > 0);
    CHECK(reg.active_count() == 0);
}

// ── The exception boundary (an escaped throw here is std::terminate) ─────────

TEST_CASE("McpStreamPump: an exception from re-validation ends the stream, never escapes",
          "[mcp][stream]") {
    // httplib runs a chunked content provider from a bare ThreadPool task — outside the
    // try/catch that wraps routing() — so an exception escaping pump_once is
    // std::terminate, not a 500 (#2037's failure class). Re-validation reaches SQLite and
    // the auth manager, both of which can throw, so this boundary is load-bearing.
    auto state = std::make_shared<mcp::McpStreamState>();
    auto attached = state->attach_and_replay(0, nullptr, "alice");
    REQUIRE(attached.status == mcp::McpStreamState::AttachStatus::kAttached);

    mcp::McpStreamPump pump{attached.sink,
                            state,
                            attached.generation,
                            []() -> mcp::StreamRevalidate { throw std::runtime_error("auth blew up"); },
                            [] { return true; },
                            fast_cfg()};
    FakeWire wire;
    CHECK_NOTHROW(pump.pump_once(wire.writer()));
    CHECK_FALSE(pump.pump_once(wire.writer())); // and the stream is over

    // The fault is recorded as OURS. Auditing it as a client disconnect would send the
    // operator looking at the client for a server bug.
    CHECK(attached.sink->close_reason.load() == mcp::McpStreamClose::kInternalError);
}

TEST_CASE("McpStreamPump: the exception boundary holds with no metrics registry wired",
          "[mcp][stream]") {
    // The catch handler's own metric/log calls allocate — and it exists precisely because
    // we may be out of memory. Exercise the null-metrics branch too, so the guard is
    // covered on both.
    auto state = std::make_shared<mcp::McpStreamState>(mcp::kMcpRingCapDefault, nullptr);
    auto attached = state->attach_and_replay(0, nullptr, "alice");
    mcp::McpStreamPump pump{attached.sink,
                            state,
                            attached.generation,
                            []() -> mcp::StreamRevalidate { throw std::bad_alloc(); },
                            [] { return true; },
                            fast_cfg()};
    FakeWire wire;
    CHECK_NOTHROW(pump.pump_once(wire.writer()));
    CHECK(attached.sink->close_reason.load() == mcp::McpStreamClose::kInternalError);
}

TEST_CASE("McpStreamState: an oversized frame is replaced, not corrupted",
          "[mcp][stream]") {
    // Byte-truncating a JSON payload yields a guaranteed-unparseable frame — which would
    // then be handed to the live sink AND stored in the ring under an id, so every resume
    // would faithfully re-serve the same garbage. Substitute a well-formed notice instead.
    mcp::McpStreamState state{/*ring_cap=*/8, nullptr, /*ring_bytes_cap=*/256};
    state.publish("message", std::string(4096, 'x'));

    auto attached = state.attach_and_replay(0, nullptr, "alice");
    REQUIRE(attached.status == mcp::McpStreamState::AttachStatus::kAttached);
    std::lock_guard<std::mutex> lk(attached.sink->sse->mu);
    REQUIRE(attached.sink->sse->queue.size() == 1);
    const auto& frame = attached.sink->sse->queue.front();
    CHECK(frame.data.find("frame_too_large") != std::string::npos);
    CHECK(frame.data.find("execution_id") != std::string::npos);
    CHECK(frame.data.size() <= 256);
    CHECK(frame.data.find(std::string(64, 'x')) == std::string::npos); // no raw payload
}
