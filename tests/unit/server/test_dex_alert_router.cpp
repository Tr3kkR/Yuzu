/**
 * test_dex_alert_router.cpp — operator-routed per-signal alerting (BRD F1).
 *
 * Covers: routed-vs-unrouted gating, the per-(type, agent) cooldown, the
 * rolling-minute fan-out budget, the cooldown-map capacity bound, live route
 * swaps, and the JSON config round-trip (defensive parse of operator/config
 * bytes).
 */

#include "dex_alert_router.hpp"

#include <catch2/catch_test_macros.hpp>

#include <stdexcept>
#include <string>
#include <vector>

using namespace yuzu::server;

namespace {

struct Harness {
    DexAlertRouter router;
    std::vector<RoutedSignalAlert> fired;

    explicit Harness(DexAlertRouterConfig cfg = {}) : router(cfg) {
        router.set_on_alert([this](const RoutedSignalAlert& a) { fired.push_back(a); });
    }
};

} // namespace

TEST_CASE("router: nothing routed by default — no alert ever fires", "[dex][f1][router]") {
    Harness h;
    h.router.observe("os.bugcheck", "", "agent-1", 1000);
    h.router.observe("process.crashed", "chrome.exe", "agent-2", 1001);
    CHECK(h.fired.empty());
}

TEST_CASE("router: a routed type fires once per (type, agent) per cooldown",
          "[dex][f1][router]") {
    Harness h;
    h.router.set_routes({"os.bugcheck"});

    h.router.observe("os.bugcheck", "", "agent-1", 1000);
    REQUIRE(h.fired.size() == 1);
    CHECK(h.fired[0].obs_type == "os.bugcheck");
    CHECK(h.fired[0].agent_id == "agent-1");

    // Same device inside the cooldown: suppressed.
    h.router.observe("os.bugcheck", "", "agent-1", 1000 + 1800);
    CHECK(h.fired.size() == 1);
    // A DIFFERENT device fires independently.
    h.router.observe("os.bugcheck", "", "agent-2", 1000 + 1800);
    CHECK(h.fired.size() == 2);
    // Same device after the cooldown: fires again.
    h.router.observe("os.bugcheck", "", "agent-1", 1000 + 3601);
    CHECK(h.fired.size() == 3);
    // An unrouted type stays silent throughout.
    h.router.observe("process.hung", "x", "agent-1", 1000 + 3700);
    CHECK(h.fired.size() == 3);
}

TEST_CASE("router: subject rides through to the alert payload", "[dex][f1][router]") {
    Harness h;
    h.router.set_routes({"perf.cpu_sustained"});
    h.router.observe("perf.cpu_sustained", "cpu", "WS-1", 50);
    REQUIRE(h.fired.size() == 1);
    CHECK(h.fired[0].subject == "cpu");
}

TEST_CASE("router: live route swap applies immediately, de-routed types go quiet",
          "[dex][f1][router]") {
    Harness h;
    h.router.set_routes({"os.bugcheck"});
    h.router.observe("os.bugcheck", "", "a1", 100);
    CHECK(h.fired.size() == 1);

    h.router.set_routes({"disk.smart_failure"}); // settings POST mid-flight
    h.router.observe("os.bugcheck", "", "a2", 101); // no longer routed
    CHECK(h.fired.size() == 1);
    h.router.observe("disk.smart_failure", "PhysicalDrive0", "a2", 102);
    CHECK(h.fired.size() == 2);
    CHECK(h.router.routes().count("disk.smart_failure") == 1);
}

TEST_CASE("router: rolling-minute budget clips a storm but does NOT arm cooldowns",
          "[dex][f1][router]") {
    DexAlertRouterConfig cfg;
    cfg.max_fires_per_minute = 3;
    Harness h(cfg);
    h.router.set_routes({"os.bugcheck"});

    // 5 distinct devices in the same minute: only 3 alerts leave.
    for (int i = 0; i < 5; ++i)
        h.router.observe("os.bugcheck", "", "agent-" + std::to_string(i), 1000 + i);
    CHECK(h.fired.size() == 3);

    // Next minute: the clipped devices fire on their NEXT sighting — the
    // budget drop deliberately left their cooldowns unarmed.
    h.router.observe("os.bugcheck", "", "agent-3", 1061);
    h.router.observe("os.bugcheck", "", "agent-4", 1062);
    CHECK(h.fired.size() == 5);
}

TEST_CASE("router: cooldown map is bounded — eviction frees room, never blocks a fresh alert",
          "[dex][f1][router]") {
    DexAlertRouterConfig cfg;
    cfg.max_entries = 4;
    cfg.max_fires_per_minute = 1000;
    Harness h(cfg);
    h.router.set_routes({"t"});

    for (int i = 0; i < 10; ++i)
        h.router.observe("t", "", "agent-" + std::to_string(i), 1000 + i);
    // Every distinct device fired despite the 4-entry map (stalest evicted).
    CHECK(h.fired.size() == 10);
}

TEST_CASE("router: config JSON round-trip + defensive parse", "[dex][f1][router][parse]") {
    // Round-trip is stable and sorted.
    const auto json = routed_types_to_json({"os.bugcheck", "perf.cpu_sustained"});
    const auto back = parse_routed_types(json);
    CHECK(back.size() == 2);
    CHECK(back.count("os.bugcheck") == 1);
    CHECK(back.count("perf.cpu_sustained") == 1);
    CHECK(routed_types_to_json(back) == json);

    // Garbage in, empty out — a corrupted config row must not throw or grow.
    CHECK(parse_routed_types("").empty());
    CHECK(parse_routed_types("not json").empty());
    CHECK(parse_routed_types("{\"a\":1}").empty());
    CHECK(parse_routed_types("[1, 2, null, {}]").empty());
    // Oversized entries are skipped; the array is clamped at 512.
    CHECK(parse_routed_types("[\"" + std::string(200, 'x') + "\"]").empty());
    // Exact length fence: kMaxTypeLen=128 is "max 128 chars" (size() > 128
    // rejects), so 128 is admitted and 129 rejected (gov QE S2).
    CHECK(parse_routed_types("[\"" + std::string(128, 'a') + "\"]").size() == 1);
    CHECK(parse_routed_types("[\"" + std::string(129, 'a') + "\"]").empty());
    std::string big = "[";
    for (int i = 0; i < 600; ++i)
        big += (i ? ",\"" : "\"") + std::to_string(i) + "\"";
    big += "]";
    CHECK(parse_routed_types(big).size() == 512);
}

TEST_CASE("router: a throwing alert sink never escapes observe() (UP-1)",
          "[dex][f1][router]") {
    // observe() runs on the gRPC ingest thread inside a sync handler with no
    // catch-all — a throwing sink (SQLITE_BUSY, webhook closed mid-fire) must
    // be swallowed, not propagate and tear down the agent's Subscribe stream.
    DexAlertRouter router;
    router.set_routes({"os.bugcheck"});
    int calls = 0;
    router.set_on_alert([&](const RoutedSignalAlert&) {
        ++calls;
        throw std::runtime_error("sink boom");
    });
    CHECK_NOTHROW(router.observe("os.bugcheck", "", "agent-1", 1000));
    CHECK(calls == 1); // the sink WAS invoked; the throw was contained
    // The cooldown armed despite the failed delivery — a second sighting within
    // the cooldown is suppressed (documented lost-alert tradeoff).
    CHECK_NOTHROW(router.observe("os.bugcheck", "", "agent-1", 1001));
    CHECK(calls == 1);
}
