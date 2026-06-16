/// @file test_device_routes.cpp
/// Route-level tests for the shared device page's "Get live info" surface —
/// the dispatch/poll routes (/fragments/device/live{,/run,/result}). Driven
/// in-process through TestRouteSink (no httplib acceptor, #438), with stub
/// auth/perm/dispatch/responses/audit fns.
///
/// These complement the pure-renderer tests in test_device_ui.cpp: the renderer
/// tests are data-in/HTML-out, but the result-route poll keeps POINTERS into the
/// responses vector across the scan loop — a use-after-free crashed the server
/// the instant live output arrived (the temporary returned by responses_fn_ was
/// iterated directly). The "data renders" sections below drive that exact path,
/// so the bug is caught here (deterministically under ASan in nightly CI).

#include "device_routes.hpp"
#include "test_route_sink.hpp"

#include <catch2/catch_test_macros.hpp>

#include <optional>
#include <string>
#include <utility>
#include <vector>

using namespace yuzu::server;

namespace {

// A live-route harness: stub fns + a registered DeviceRoutes over a TestRouteSink.
struct LiveHarness {
    yuzu::server::test::TestRouteSink sink;
    DeviceRoutes routes;

    int dispatched = 0;
    int fake_sent = 1;
    std::string seen_plugin, seen_action, seen_id;
    std::vector<DexAgentResponse> fake_rows; // what the response store "has"
    std::string audited;                     // "action|result|target_id"
    bool allow_execute = true;

    LiveHarness() {
        auto okAuth = [](const httplib::Request&, httplib::Response&) {
            return std::optional<auth::Session>(auth::Session{});
        };
        // Read is always allowed; Execute is toggled by allow_execute.
        auto perm = [this](const httplib::Request&, httplib::Response&, const std::string&,
                           const std::string& op) {
            return op == "Execute" ? allow_execute : true;
        };
        auto devices = []() { return std::vector<DeviceRow>{}; };
        auto dispatch = [this](const std::string& plugin, const std::string& action,
                               const std::vector<std::string>& ids, const std::string&,
                               const std::unordered_map<std::string, std::string>&)
            -> std::pair<std::string, int> {
            ++dispatched;
            seen_plugin = plugin;
            seen_action = action;
            seen_id = ids.empty() ? "" : ids.front();
            // command_id prefix MUST be <plugin>- so the result route accepts it.
            return {plugin + "-test", fake_sent};
        };
        auto responses = [this](const std::string&) { return fake_rows; };
        auto audit = [this](const httplib::Request&, const std::string& a, const std::string& r,
                            const std::string&, const std::string& tid, const std::string&) {
            audited = a + "|" + r + "|" + tid;
        };
        // store is unused by the live routes — pass nullptr deliberately.
        routes.register_routes(sink, okAuth, perm, devices, /*store=*/nullptr, dispatch, responses,
                               audit);
    }
};

} // namespace

TEST_CASE("device live shell: serves one auto-firing run panel per kind", "[device][routes]") {
    LiveHarness h;
    auto r = h.sink.Get("/fragments/device/live?id=a-1");
    REQUIRE(r);
    CHECK(r->status == 200);
    CHECK(r->body.find("/fragments/device/live/run?id=a-1&amp;kind=uptime") != std::string::npos);
    CHECK(r->body.find("/fragments/device/live/run?id=a-1&amp;kind=processes") != std::string::npos);
}

TEST_CASE("device live run: dispatches the right plugin and audits per-kind", "[device][routes]") {
    SECTION("uptime -> os_info/uptime, audited as device.live.uptime") {
        LiveHarness h;
        auto r = h.sink.Get("/fragments/device/live/run?id=a-1&kind=uptime");
        REQUIRE(r);
        CHECK(h.dispatched == 1);
        CHECK(h.seen_plugin == "os_info");
        CHECK(h.seen_action == "uptime");
        CHECK(h.seen_id == "a-1");
        // Polling stub points back at the result route with the command_id + kind.
        CHECK(r->body.find("/fragments/device/live/result?command_id=os_info-test") !=
              std::string::npos);
        CHECK(r->body.find("kind=uptime") != std::string::npos);
        // Usage vs machine-health audit split (works-council posture).
        CHECK(h.audited == "device.live.uptime|success|a-1");
    }
    SECTION("processes -> processes/list_hashed, audited as device.live.processes") {
        LiveHarness h;
        auto r = h.sink.Get("/fragments/device/live/run?id=a-1&kind=processes");
        REQUIRE(r);
        CHECK(h.seen_plugin == "processes");
        CHECK(h.seen_action == "list_hashed"); // hashed variant carries the SHA-256
        CHECK(h.audited == "device.live.processes|success|a-1");
    }
    SECTION("offline device (sent=0): honest note, no polling, no auto-fire") {
        LiveHarness h;
        h.fake_sent = 0;
        auto r = h.sink.Get("/fragments/device/live/run?id=a-1&kind=uptime");
        REQUIRE(r);
        CHECK(r->body.find("Device offline") != std::string::npos);
        CHECK(r->body.find("hx-trigger") == std::string::npos);
        CHECK(h.audited == "device.live.uptime|no_agents|a-1");
    }
    SECTION("unknown kind is rejected (allowlist) before any dispatch") {
        LiveHarness h;
        auto r = h.sink.Get("/fragments/device/live/run?id=a-1&kind=bogus");
        REQUIRE(r);
        CHECK(r->status == 400);
        CHECK(h.dispatched == 0);
    }
    SECTION("Execute denied: honest note, no dispatch") {
        LiveHarness h;
        h.allow_execute = false;
        auto r = h.sink.Get("/fragments/device/live/run?id=a-1&kind=uptime");
        REQUIRE(r);
        CHECK(r->body.find("Execute") != std::string::npos);
        CHECK(h.dispatched == 0);
    }
}

// The regression centrepiece: the result poll keeps pointers into the responses
// vector across the scan, then renders AFTER the loop. Iterating the temporary
// (the original bug) is a use-after-free; these sections drive that path with
// real output and assert the rendered result.
TEST_CASE("device live result: output renders, server survives the poll", "[device][routes]") {
    SECTION("uptime output -> value tile, polling stops") {
        LiveHarness h;
        h.fake_rows = {{"a-1", 0, "uptime_seconds|181740\nuptime_display|2d 2h 29m", ""}};
        auto r = h.sink.Get(
            "/fragments/device/live/result?command_id=os_info-test&agent_id=a-1&kind=uptime&n=1");
        REQUIRE(r);
        CHECK(r->body.find("2d 2h 29m") != std::string::npos);
        CHECK(r->body.find("Uptime") != std::string::npos);
        CHECK(r->body.find("hx-trigger") == std::string::npos); // resolved, no re-poll
    }
    SECTION("processes output -> PID/name/hash table (proc|pid|name|sha256|path)") {
        LiveHarness h;
        h.fake_rows = {{"a-1", 0,
                        "proc|0|[System Process]||\n"
                        "proc|4|System||\n"
                        "proc|123|sh|"
                        "deadbeefcafe0000111122223333444455556666777788889999aaaabbbbccccdddd|"
                        "/bin/sh",
                        ""}};
        auto r = h.sink.Get(
            "/fragments/device/live/result?command_id=processes-test&agent_id=a-1&kind=processes&n=1");
        REQUIRE(r);
        CHECK(r->body.find("running processes") != std::string::npos);
        CHECK(r->body.find("[System Process]") != std::string::npos);
        CHECK(r->body.find("123") != std::string::npos);
        CHECK(r->body.find("deadbeefcafe0000") != std::string::npos); // truncated hash rendered
        CHECK(r->body.find("/bin/sh") != std::string::npos);          // path rendered
    }
    SECTION("pending (no rows yet) -> re-poll with n+1") {
        LiveHarness h; // fake_rows empty
        auto r = h.sink.Get(
            "/fragments/device/live/result?command_id=os_info-test&agent_id=a-1&kind=uptime&n=1");
        REQUIRE(r);
        CHECK(r->body.find("&amp;n=2") != std::string::npos);
    }
    SECTION("another agent's rows never render here") {
        LiveHarness h;
        h.fake_rows = {{"OTHER", 0, "uptime_display|9d 9h", ""}};
        auto r = h.sink.Get(
            "/fragments/device/live/result?command_id=os_info-test&agent_id=a-1&kind=uptime&n=1");
        REQUIRE(r);
        CHECK(r->body.find("9d 9h") == std::string::npos); // filtered by agent_id
    }
    SECTION("agent error payload is surfaced, escaped") {
        LiveHarness h;
        h.fake_rows = {{"a-1", 0, "error|<b>boom</b>", ""}};
        auto r = h.sink.Get(
            "/fragments/device/live/result?command_id=os_info-test&agent_id=a-1&kind=uptime&n=1");
        REQUIRE(r);
        CHECK(r->body.find("reported an error") != std::string::npos);
        CHECK(r->body.find("<b>boom</b>") == std::string::npos); // escaped, not raw
    }
    SECTION("terminal failure frame -> honest failure note") {
        LiveHarness h;
        h.fake_rows = {{"a-1", 2, "", "plugin crashed"}}; // status>=2, no output
        auto r = h.sink.Get(
            "/fragments/device/live/result?command_id=os_info-test&agent_id=a-1&kind=uptime&n=1");
        REQUIRE(r);
        CHECK(r->body.find("failed on the device") != std::string::npos);
    }
    SECTION("command_id whose prefix doesn't match the kind's plugin is rejected") {
        LiveHarness h;
        // kind=uptime expects os_info-; a tar- id must not be pollable here.
        auto r = h.sink.Get(
            "/fragments/device/live/result?command_id=tar-deadbeef&agent_id=a-1&kind=uptime&n=1");
        REQUIRE(r);
        CHECK(r->status == 400);
    }
    SECTION("timeout (attempt cap) is honest, stops polling") {
        LiveHarness h; // empty rows
        auto r = h.sink.Get(
            "/fragments/device/live/result?command_id=os_info-test&agent_id=a-1&kind=uptime&n=20");
        REQUIRE(r);
        CHECK(r->body.find("timed out") != std::string::npos);
        CHECK(r->body.find("hx-trigger") == std::string::npos);
    }
}
