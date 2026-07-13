// CH-6 — worker-pool starvation. The P0 chaos gate for track 2f PR 2.
//
// The gate (docs/mcp-streamable-http-chaos-design.md): "Saturate held-open responses at
// exactly the caps; drive plain REST concurrently. Success: plain-path latency within the
// no-stream baseline; zero timeouts."
//
// This file exists because the previous "CH-6 coverage" tested `derive_stream_budget()`
// arithmetic — which proves the sums are right, and proves nothing at all about whether a
// saturated server still answers. A regression that leaves a streaming route unleased, or
// shrinks the reserve, sails straight through an arithmetic test. So this one stands up a
// REAL httplib server, fills every stream slot with real held-open connections, and then
// asks the server a plain question and insists on an answer.
//
// It is the one place in the server suite that runs a live acceptor thread, which is exactly
// what #438 forbids under ThreadSanitizer (httplib's acceptor trips TSan's interceptors on
// teardown). So it compiles OUT under TSan rather than being tagged out — a tag can be
// forgotten by whoever next writes the CI invocation; `#if` cannot.

#if !defined(__SANITIZE_THREAD__)

#include <catch2/catch_test_macros.hpp>

#include "../../../server/core/src/stream_budget.hpp"

#include <httplib.h>

#include <atomic>
#include <chrono>
#include <string>
#include <thread>
#include <vector>

namespace detail = yuzu::server::detail;

namespace {

/// A minimal stand-in for the real server's shape: one httplib server, one shared worker
/// pool, a streaming route that leases from the budget, and a plain route that does not.
/// The point is the POOL, not the routes — every held-open response pins a worker whichever
/// surface serves it, and that is the property under test.
struct SaturationRig {
    static constexpr std::size_t kStreams = 4;   // the budget's global cap
    static constexpr std::size_t kReserve = 4;   // workers held back for plain traffic

    detail::StreamBudget budget{{.global_cap = kStreams}};
    httplib::Server svr;
    std::thread listener;
    int port = 0;
    std::atomic<bool> release_streams{false};

    SaturationRig() {
        // The pool is derived from the stream target, exactly as server.cpp does it.
        const std::size_t pool = detail::derive_worker_pool(kStreams, kReserve);
        svr.new_task_queue = [pool] { return new httplib::ThreadPool(pool, pool); };

        // The streaming route: leases, then holds the connection open until released.
        svr.Get("/stream", [this](const httplib::Request&, httplib::Response& res) {
            auto lease = std::make_shared<detail::StreamBudget::Lease>();
            auto admitted =
                budget.try_acquire(detail::SseSurface::kMcpGet, "agentic-client", /*cap=*/0);
            if (!admitted.lease) {
                res.status = 429;
                res.set_content("cap", "text/plain");
                return;
            }
            *lease = std::move(admitted.lease);
            res.set_chunked_content_provider(
                "text/event-stream",
                [this](std::size_t, httplib::DataSink& sink) {
                    // Hold the worker, exactly as a real SSE provider does.
                    std::this_thread::sleep_for(std::chrono::milliseconds(20));
                    if (release_streams.load()) {
                        return false;
                    }
                    static constexpr char kBeat[] = "event: heartbeat\ndata: \n\n";
                    return sink.write(kBeat, sizeof(kBeat) - 1);
                },
                [lease](bool) { /* lease returns the worker here */ });
        });

        // The plain route: the traffic that must never be starved.
        svr.Get("/plain", [](const httplib::Request&, httplib::Response& res) {
            res.set_content("ok", "text/plain");
        });

        port = svr.bind_to_any_port("127.0.0.1");
        listener = std::thread([this] { svr.listen_after_bind(); });
        while (!svr.is_running()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    }

    ~SaturationRig() {
        release_streams.store(true);
        svr.stop();
        if (listener.joinable()) {
            listener.join();
        }
    }
};

} // namespace

TEST_CASE("CH-6: a server saturated with held-open streams still answers plain requests",
          "[sse][ch6][saturation]") {
    SaturationRig rig;

    // Fill every stream slot with a REAL held-open connection. Each one pins a worker.
    std::vector<std::thread> streamers;
    std::atomic<int> attached{0};
    for (std::size_t i = 0; i < SaturationRig::kStreams; ++i) {
        streamers.emplace_back([&rig, &attached] {
            httplib::Client cli("127.0.0.1", rig.port);
            cli.set_read_timeout(10, 0);
            attached.fetch_add(1);
            // Bleeds heartbeats until the rig tears down; the connection — and its worker —
            // is held for the whole test.
            cli.Get("/stream", [](const char*, std::size_t) { return true; });
        });
    }
    while (attached.load() < static_cast<int>(SaturationRig::kStreams)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(150)); // let them all attach

    CHECK(rig.budget.active() == SaturationRig::kStreams); // genuinely saturated

    // THE ASSERTION. With every stream slot taken, plain traffic must still be served —
    // promptly, and every time. This is what the plain-REST reserve is FOR, and it is the
    // property that no amount of budget arithmetic can demonstrate.
    for (int i = 0; i < 5; ++i) {
        httplib::Client cli("127.0.0.1", rig.port);
        cli.set_read_timeout(5, 0);
        const auto start = std::chrono::steady_clock::now();
        auto res = cli.Get("/plain");
        const auto elapsed = std::chrono::steady_clock::now() - start;

        REQUIRE(res); // not a timeout, not a refused connection
        CHECK(res->status == 200);
        CHECK(res->body == "ok");
        CHECK(elapsed < std::chrono::seconds(2)); // no queueing behind the streams
    }

    // And the cap holds: a stream beyond the budget is REJECTED, not admitted to starve the
    // pool. Reject-not-evict — the four live streams are untouched.
    {
        httplib::Client cli("127.0.0.1", rig.port);
        cli.set_read_timeout(5, 0);
        auto res = cli.Get("/stream");
        REQUIRE(res);
        CHECK(res->status == 429);
        CHECK(rig.budget.active() == SaturationRig::kStreams);
    }

    rig.release_streams.store(true);
    for (auto& t : streamers) {
        t.join();
    }
}

TEST_CASE("CH-6: every held-open response returns its worker on teardown",
          "[sse][ch6][saturation]") {
    // A leaked lease is invisible in normal testing and fatal over a server's uptime: the
    // budget tightens by one every time a client disconnects, until streaming stops working
    // and nothing in the logs says why.
    SaturationRig rig;

    for (int round = 0; round < 3; ++round) {
        std::vector<std::thread> streamers;
        std::atomic<int> attached{0};
        rig.release_streams.store(false);
        for (std::size_t i = 0; i < SaturationRig::kStreams; ++i) {
            streamers.emplace_back([&rig, &attached] {
                httplib::Client cli("127.0.0.1", rig.port);
                cli.set_read_timeout(10, 0);
                attached.fetch_add(1);
                cli.Get("/stream", [](const char*, std::size_t) { return true; });
            });
        }
        while (attached.load() < static_cast<int>(SaturationRig::kStreams)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(150));
        CHECK(rig.budget.active() == SaturationRig::kStreams);

        rig.release_streams.store(true);
        for (auto& t : streamers) {
            t.join();
        }
        // Every worker comes back — round after round, with no drift.
        for (int spin = 0; spin < 200 && rig.budget.active() != 0; ++spin) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        INFO("round " << round);
        CHECK(rig.budget.active() == 0);
    }
}

#endif // !__SANITIZE_THREAD__
