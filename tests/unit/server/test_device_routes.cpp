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
#include "guaranteed_state_store.hpp"
#include "test_route_sink.hpp"

#include <catch2/catch_test_macros.hpp>

#include <optional>
#include <stdexcept>
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
        auto perm = [](const httplib::Request&, httplib::Response&, const std::string&,
                       const std::string&) { return true; };
        // The live routes gate per-device via scoped_perm (not the unscoped perm):
        // Read always allowed; Execute toggled by allow_execute.
        auto scoped_perm = [this](const httplib::Request&, httplib::Response&, const std::string&,
                                  const std::string& op, const std::string&) {
            return op == "Execute" ? allow_execute : true;
        };
        auto devices = [](const std::string&) { return std::vector<DeviceRow>{}; };
        auto lookup = [](const std::string&) -> std::optional<DeviceRow> { return std::nullopt; };
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
                            const std::string&, const std::string& tid,
                            const std::string&) -> bool {
            audited = a + "|" + r + "|" + tid;
            return true; // DexRoutes::AuditFn (aliased by DeviceRoutes) is bool-returning (#1549)
        };
        // store is unused by the live routes — pass nullptr deliberately.
        routes.register_routes(sink, okAuth, perm, scoped_perm, devices, lookup, /*store=*/nullptr,
                               dispatch, responses, audit);
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
        // Usage vs machine-health audit split (works-council posture). The result
        // is "dispatched" (not "success") — the outcome isn't known at dispatch time
        // and this stays in lockstep with the REST sibling.
        CHECK(h.audited == "device.live.uptime|dispatched|a-1");
    }
    SECTION("processes -> processes/list_hashed, audited as device.live.processes") {
        LiveHarness h;
        auto r = h.sink.Get("/fragments/device/live/run?id=a-1&kind=processes");
        REQUIRE(r);
        CHECK(h.seen_plugin == "processes");
        CHECK(h.seen_action == "list_hashed"); // hashed variant carries the SHA-256
        CHECK(h.audited == "device.live.processes|dispatched|a-1");
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
    SECTION("terminal SUCCESS with empty output renders now, no false timeout (UP-1)") {
        LiveHarness h;
        h.fake_rows = {{"a-1", 1, "", ""}}; // SUCCESS (status 1), no output
        auto r = h.sink.Get(
            "/fragments/device/live/result?command_id=processes-test&agent_id=a-1&kind=processes&n=1");
        REQUIRE(r);
        CHECK(r->body.find("No processes returned") != std::string::npos); // empty result rendered
        CHECK(r->body.find("hx-trigger") == std::string::npos);            // not re-polled
        CHECK(r->body.find("timed out") == std::string::npos);             // NOT a false timeout
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
            "/fragments/device/live/result?command_id=os_info-test&agent_id=a-1&kind=uptime&n=40");
        REQUIRE(r);
        CHECK(r->body.find("timed out") != std::string::npos);
        CHECK(r->body.find("hx-trigger") == std::string::npos);
    }
    SECTION("below the attempt cap keeps polling (cap raised for hash latency)") {
        LiveHarness h; // empty rows
        auto r = h.sink.Get(
            "/fragments/device/live/result?command_id=os_info-test&agent_id=a-1&kind=uptime&n=20");
        REQUIRE(r);
        CHECK(r->body.find("timed out") == std::string::npos); // 20 < 40 -> still polling
        CHECK(r->body.find("&amp;n=21") != std::string::npos);
    }
}

// The DEX/Guardian device lenses render per-device behavioral/compliance PII, so
// they must gate GuaranteedState:Read and audit-on-open (parity with the sibling
// /fragments/dex/device). Governance Gate-2/3/4 BLOCKING.
TEST_CASE("device lenses: Read-gated + audited on open", "[device][routes]") {
    GuaranteedStateStore store(":memory:");
    auto okAuth = [](const httplib::Request&, httplib::Response&) {
        return std::optional<auth::Session>(auth::Session{});
    };
    bool allow_read = true;
    auto perm = [](const httplib::Request&, httplib::Response&, const std::string&,
                   const std::string&) { return true; };
    // The lenses gate per-device via scoped_perm; Read toggled by allow_read.
    auto scoped_perm = [&allow_read](const httplib::Request&, httplib::Response& res,
                                     const std::string&, const std::string& op, const std::string&) {
        if (op == "Read" && !allow_read) { res.status = 403; return false; }
        return true;
    };
    auto devices = [](const std::string&) { return std::vector<DeviceRow>{}; };
    auto lookup = [](const std::string&) -> std::optional<DeviceRow> { return std::nullopt; };
    std::vector<std::string> audited;
    bool audit_ok = true;      // flip to simulate a dropped evidence row (#1647)
    bool audit_throws = false; // flip to simulate a bad_alloc-class throw from audit_fn (#1647)
    auto audit = [&](const httplib::Request&, const std::string& a, const std::string&,
                     const std::string&, const std::string& tid, const std::string&) -> bool {
        audited.push_back(a + "|" + tid);
        // DexRoutes::AuditFn (aliased by DeviceRoutes) is bool-returning (#1549).
        if (audit_throws)
            throw std::runtime_error("audit DB write blew up");
        return audit_ok;
    };
    yuzu::server::test::TestRouteSink sink;
    DeviceRoutes routes;
    routes.register_routes(sink, okAuth, perm, scoped_perm, devices, lookup, &store, {}, {}, audit);

    SECTION("Read denied -> 403, nothing rendered, no audit") {
        allow_read = false;
        auto dex = sink.Get("/fragments/device/dex?id=a-1");
        REQUIRE(dex);
        CHECK(dex->status == 403);
        auto gd = sink.Get("/fragments/device/guardian?id=a-1");
        REQUIRE(gd);
        CHECK(gd->status == 403);
        CHECK(audited.empty());
    }
    SECTION("Read allowed -> audited on open with the right verb") {
        allow_read = true;
        sink.Get("/fragments/device/dex?id=a-1");
        sink.Get("/fragments/device/guardian?id=a-1");
        bool saw_dex = false, saw_guardian = false;
        for (const auto& a : audited) {
            if (a == "dex.device.view|a-1") saw_dex = true;
            if (a == "guardian.device.view|a-1") saw_guardian = true;
        }
        CHECK(saw_dex);
        CHECK(saw_guardian);
    }
    // #1647: a per-device behavioural-PII lens whose audit row silently fails to
    // persist must surface the gap (Sec-Audit-Failed) — but as an HTML dashboard
    // surface it SET-AND-PROCEEDS (a transient audit hiccup must not blank the
    // operator's lens, unlike the strict REST per-device endpoints that fail closed).
    SECTION("audit-persist failure -> Sec-Audit-Failed header, fragment still renders") {
        allow_read = true;
        audit_ok = false; // the evidence row cannot persist
        auto dex = sink.Get("/fragments/device/dex?id=a-1");
        REQUIRE(dex);
        CHECK(dex->status == 200); // set-and-proceed
        CHECK(dex->get_header_value("Sec-Audit-Failed") == "true");
        auto gd = sink.Get("/fragments/device/guardian?id=a-1");
        REQUIRE(gd);
        CHECK(gd->status == 200);
        CHECK(gd->get_header_value("Sec-Audit-Failed") == "true");
    }
    // #1647 item 1: a bad_alloc-class throw out of audit_fn was previously silent
    // (no try/catch). The shared helper catches it, logs, flags the header, and the
    // handler still returns a response instead of letting the throw escape.
    SECTION("a throwing audit_fn is caught + flagged, never escapes the handler") {
        allow_read = true;
        audit_throws = true;
        auto dex = sink.Get("/fragments/device/dex?id=a-1");
        REQUIRE(dex);
        CHECK(dex->status == 200);
        CHECK(dex->get_header_value("Sec-Audit-Failed") == "true");
        auto gd = sink.Get("/fragments/device/guardian?id=a-1");
        REQUIRE(gd);
        CHECK(gd->status == 200);
        CHECK(gd->get_header_value("Sec-Audit-Failed") == "true");
    }
}

// SCOPE-ESCAPE regression (governance Gate-2/4 BLOCKING; both adversarial reviewers
// found it independently). Every per-device route must refuse a device OUTSIDE the
// caller's management scope: not listed, not openable, no per-device PII read, and
// — the load-bearing security property — NO live command dispatched to it.
// scoped_perm_fn_ is the chokepoint (here it denies "other-team", allows "mine");
// the list provider is already per-operator scoped.
TEST_CASE("device routes: out-of-scope device is not listed/openable/live-queryable",
          "[device][routes][scope]") {
    GuaranteedStateStore store(":memory:");
    auto okAuth = [](const httplib::Request&, httplib::Response&) {
        return std::optional<auth::Session>(auth::Session{});
    };
    // Global Infrastructure:Read (the list gate) is granted.
    auto perm = [](const httplib::Request&, httplib::Response&, const std::string&,
                   const std::string&) { return true; };
    // Management-group scope: every op allowed EXCEPT on the out-of-scope agent.
    // "ancestor-child" is authorized (a parent-group role grants it) but is NOT in
    // the flat scoped LIST below — modelling the ancestor-walk divergence.
    auto scoped_perm = [](const httplib::Request&, httplib::Response& res, const std::string&,
                          const std::string&, const std::string& agent_id) {
        if (agent_id == "other-team") { res.status = 403; return false; }
        return true;
    };
    // The scoped LIST provider returns only the caller's DIRECT-group device — a flat
    // get_visible_agents JOIN has no ancestor walk, so "ancestor-child" is absent.
    auto devices = [](const std::string&) {
        DeviceRow d;
        d.agent_id = "mine";
        d.hostname = "mine-host";
        return std::vector<DeviceRow>{d};
    };
    // The UNSCOPED single-device resolver returns the identity row for any connected
    // device (authz is scoped_perm, applied first) — incl. the ancestor-authorized one.
    auto lookup = [](const std::string& id) -> std::optional<DeviceRow> {
        if (id == "mine" || id == "ancestor-child") {
            DeviceRow d;
            d.agent_id = id;
            d.hostname = id + "-host";
            return d;
        }
        return std::nullopt;
    };
    int dispatched = 0;
    auto dispatch = [&dispatched](const std::string& plugin, const std::string&,
                                  const std::vector<std::string>&, const std::string&,
                                  const std::unordered_map<std::string, std::string>&)
        -> std::pair<std::string, int> {
        ++dispatched;
        return {plugin + "-x", 1};
    };
    auto responses = [](const std::string&) { return std::vector<DexAgentResponse>{}; };
    std::vector<std::string> audited;
    auto audit = [&audited](const httplib::Request&, const std::string& a, const std::string&,
                            const std::string&, const std::string& tid,
                            const std::string&) -> bool {
        audited.push_back(a + "|" + tid);
        return true; // DexRoutes::AuditFn (aliased by DeviceRoutes) is bool-returning (#1549)
    };
    yuzu::server::test::TestRouteSink sink;
    DeviceRoutes routes;
    routes.register_routes(sink, okAuth, perm, scoped_perm, devices, lookup, &store, dispatch,
                           responses, audit);

    SECTION("list shows only the caller's visible device") {
        auto r = sink.Get("/fragments/devices/list");
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(r->body.find("mine-host") != std::string::npos);
        CHECK(r->body.find("other-team") == std::string::npos);
    }
    SECTION("out-of-scope device page is 403, not opened") {
        auto r = sink.Get("/fragments/device/page?id=other-team");
        REQUIRE(r);
        CHECK(r->status == 403);
    }
    SECTION("out-of-scope DEX lens is 403, no PII read (not audited)") {
        auto r = sink.Get("/fragments/device/dex?id=other-team");
        REQUIRE(r);
        CHECK(r->status == 403);
        CHECK(audited.empty());
    }
    SECTION("out-of-scope live dispatch is refused — NO command sent") {
        auto r = sink.Get("/fragments/device/live/run?id=other-team&kind=processes");
        REQUIRE(r);
        CHECK(dispatched == 0); // the security property: no cross-scope dispatch
        CHECK(r->status == 403);
    }
    SECTION("in-scope device stays openable + live-queryable") {
        auto pg = sink.Get("/fragments/device/page?id=mine");
        REQUIRE(pg);
        CHECK(pg->status == 200);
        auto run = sink.Get("/fragments/device/live/run?id=mine&kind=uptime");
        REQUIRE(run);
        CHECK(dispatched == 1); // in-scope dispatch proceeds
    }
    // Ancestor-authz regression: a device authorized by scoped_perm (e.g. via a
    // parent-group role) but ABSENT from the flat scoped list must still open — the
    // page row comes from the UNSCOPED lookup post-authz, not a re-scoped list scan.
    SECTION("ancestor-authorized device opens via unscoped lookup though not in the list") {
        auto pg = sink.Get("/fragments/device/page?id=ancestor-child");
        REQUIRE(pg);
        CHECK(pg->status == 200);
        CHECK(pg->body.find("ancestor-child-host") != std::string::npos); // row rendered
        // ...and it is NOT in the scoped list (proves list scoping is independent).
        auto list = sink.Get("/fragments/devices/list");
        REQUIRE(list);
        CHECK(list->body.find("ancestor-child") == std::string::npos);
    }
}
