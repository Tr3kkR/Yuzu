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

#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <unordered_map>
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
    std::string seen_plugin, seen_action, seen_id;            // LAST dispatch (compat)
    std::vector<std::pair<std::string, std::string>> seen_dispatches; // ALL (plugin,action)
    std::vector<DexAgentResponse> fake_rows;                  // default response store contents
    std::unordered_map<std::string, std::vector<DexAgentResponse>> rows_by_cmd; // per-command override
    std::string audited;                                      // "action|result|target_id"
    bool allow_execute = true;
    bool audit_ok = true;      // #1647: flip to drop the evidence row (audit_fn → false)
    bool audit_throws = false; // #1647: flip to throw a bad_alloc-class fault from audit_fn

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
            seen_dispatches.emplace_back(plugin, action);
            // command_id prefix MUST be <plugin>- so the result route accepts it.
            return {plugin + "-test", fake_sent};
        };
        auto responses = [this](const std::string& cmd, const std::string& /*agent_id*/) {
            // #1634: production scopes by agent_id at the store seam; the stub returns
            // by command_id and relies on the route's post-filter for isolation tests.
            auto it = rows_by_cmd.find(cmd);
            return it != rows_by_cmd.end() ? it->second : fake_rows;
        };
        auto audit = [this](const httplib::Request&, const std::string& a, const std::string& r,
                            const std::string&, const std::string& tid,
                            const std::string&) -> bool {
            audited = a + "|" + r + "|" + tid;
            // #1647: the row is recorded before the throw so `audited` still proves the
            // site was reached; the throw then exercises the shared helper's catch-arm.
            if (audit_throws)
                throw std::runtime_error("audit DB write blew up");
            return audit_ok; // DexRoutes::AuditFn (aliased by DeviceRoutes) is bool-returning (#1549)
        };
        // store is unused by the live routes — pass nullptr deliberately.
        routes.register_routes(sink, okAuth, perm, scoped_perm, devices, lookup, /*store=*/nullptr,
                               dispatch, responses, audit);
    }
};

} // namespace

TEST_CASE("device live shell: serves a collapsible card per kind + chrome", "[device][routes]") {
    LiveHarness h;
    auto r = h.sink.Get("/fragments/device/live?id=a-1");
    REQUIRE(r);
    CHECK(r->status == 200);
    // uptime is the hidden KPI loader; the cards cover the rest of the snapshot.
    CHECK(r->body.find("/fragments/device/live/run?id=a-1&amp;kind=uptime") != std::string::npos);
    CHECK(r->body.find("/fragments/device/live/run?id=a-1&amp;kind=process_tree") != std::string::npos);
    CHECK(r->body.find("/fragments/device/live/run?id=a-1&amp;kind=services") != std::string::npos);
    CHECK(r->body.find("/fragments/device/live/run?id=a-1&amp;kind=arp") != std::string::npos);
    CHECK(r->body.find("/fragments/device/live/run?id=a-1&amp;kind=dns_cache") != std::string::npos);
    CHECK(r->body.find("/fragments/device/live/run?id=a-1&amp;kind=capture_sources") != std::string::npos);
    // Snapshot chrome: collapsible cards + expand-all + pop-out (CSP-safe inline handlers).
    CHECK(r->body.find("class=\"ls-card\"") != std::string::npos);
    CHECK(r->body.find("lsToggleAll(this)") != std::string::npos);
    CHECK(r->body.find("lsPopOut(event,this)") != std::string::npos);
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

// #1647 catch-arm parity: the device.live.* DISPATCH audit set Sec-Audit-Failed on a
// returns-false but had NO try/catch — a throwing audit_fn escaped the handler (httplib
// → 500). Routed through the shared rest_audit.hpp chokepoint, a throw is now caught and
// flags the header, while the post-dispatch SET-AND-PROCEED posture is unchanged (the
// dispatch already happened; the panel still polls for the result).
TEST_CASE("device live run: audit-persist gap surfaces Sec-Audit-Failed, still polls",
          "[device][routes][audit]") {
    SECTION("a dropped audit row (audit_fn → false)") {
        LiveHarness h;
        h.audit_ok = false;
        auto r = h.sink.Get("/fragments/device/live/run?id=a-1&kind=uptime");
        REQUIRE(r);
        CHECK(r->status == 200); // set-and-proceed
        CHECK(r->get_header_value("Sec-Audit-Failed") == "true");
        CHECK(h.dispatched == 1); // the audit failure did not block the dispatch
        CHECK(r->body.find("/fragments/device/live/result") != std::string::npos);
    }
    SECTION("a throwing audit_fn is caught, never escapes the handler") {
        LiveHarness h;
        h.audit_throws = true;
        std::unique_ptr<httplib::Response> r;
        CHECK_NOTHROW(r = h.sink.Get("/fragments/device/live/run?id=a-1&kind=uptime"));
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(r->get_header_value("Sec-Audit-Failed") == "true");
        CHECK(h.dispatched == 1);
        CHECK(r->body.find("/fragments/device/live/result") != std::string::npos);
    }
    SECTION("clean path sets NO Sec-Audit-Failed header") {
        LiveHarness h; // audit_ok=true, audit_throws=false
        auto r = h.sink.Get("/fragments/device/live/run?id=a-1&kind=uptime");
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(r->get_header_value("Sec-Audit-Failed").empty());
        CHECK(h.audited == "device.live.uptime|dispatched|a-1");
    }
}

// The regression centrepiece: the result poll keeps pointers into the responses
// vector across the scan, then renders AFTER the loop. Iterating the temporary
// (the original bug) is a use-after-free; these sections drive that path with
// real output and assert the rendered result.
TEST_CASE("device live result: output renders, server survives the poll", "[device][routes]") {
    SECTION("uptime output -> KPI out-of-band swap, polling stops") {
        LiveHarness h;
        h.fake_rows = {{"a-1", 0, "uptime_seconds|181740\nuptime_display|2d 2h 29m", ""}};
        auto r = h.sink.Get(
            "/fragments/device/live/result?command_id=os_info-test&agent_id=a-1&kind=uptime&n=1");
        REQUIRE(r);
        CHECK(r->body.find("2d 2h 29m") != std::string::npos);
        CHECK(r->body.find("id=\"ls-kpi-uptime\"") != std::string::npos); // fills the KPI tile
        CHECK(r->body.find("hx-swap-oob=\"true\"") != std::string::npos);
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

// The expanded live-snapshot kinds each map to ONE real plugin action with its own
// audit verb. process_tree additionally dual-dispatches its connection join.
TEST_CASE("device live run: expanded kinds map to the right plugin/action + audit",
          "[device][routes]") {
    struct Case { const char* kind; const char* plugin; const char* action; const char* verb; };
    const Case cases[] = {
        {"services", "services", "list", "device.live.services"},
        {"users", "users", "logged_on", "device.live.users"},
        {"netconfig", "network_config", "ip_addresses", "device.live.netconfig"},
        {"arp", "network_config", "arp", "device.live.arp"},
        {"dns_cache", "network_config", "dns_cache", "device.live.dns_cache"},
        {"listening", "network_diag", "listening", "device.live.listening"},
        {"connections", "network_diag", "connections", "device.live.connections"},
        {"capture_sources", "tar", "status", "device.live.capture_sources"},
        {"disk", "disk_space", "free", "device.live.disk"},
    };
    for (const auto& c : cases) {
        LiveHarness h;
        auto r = h.sink.Get(std::string("/fragments/device/live/run?id=a-1&kind=") + c.kind);
        REQUIRE(r);
        CHECK(h.seen_plugin == c.plugin);
        CHECK(h.seen_action == c.action);
        // Post-dispatch audit result is "dispatched" (dev's #1549 convention; the
        // browser polls /result separately), uniform across all live kinds.
        CHECK(h.audited == std::string(c.verb) + "|dispatched|a-1");
    }
}

TEST_CASE("device live process_tree: dual-dispatch (list_tree + connections), joined",
          "[device][routes]") {
    SECTION("run dispatches BOTH the tree and the connections, audited as process_tree") {
        LiveHarness h;
        auto r = h.sink.Get("/fragments/device/live/run?id=a-1&kind=process_tree");
        REQUIRE(r);
        CHECK(h.dispatched == 2);
        bool tree = false, conns = false;
        for (const auto& [p, a] : h.seen_dispatches) {
            if (p == "processes" && a == "list_tree") tree = true;
            if (p == "network_diag" && a == "connections") conns = true;
        }
        CHECK(tree);
        CHECK(conns);
        CHECK(h.audited == "device.live.process_tree|dispatched|a-1");
        // The poll URL carries BOTH command ids so the result can join them.
        CHECK(r->body.find("command_id=processes-test") != std::string::npos);
        CHECK(r->body.find("command_id2=network_diag-test") != std::string::npos);
    }
    SECTION("result reconstructs the tree and joins connections by pid") {
        LiveHarness h;
        h.rows_by_cmd["processes-test"] = {
            {"a-1", 1, "proc|4|0|System||\nproc|800|4|svchost.exe|abc123|C:\\\\svchost.exe", ""}};
        h.rows_by_cmd["network_diag-test"] = {
            {"a-1", 1, "conn|tcp|10.0.0.5|52000|140.82.112.4|443|800", ""}};
        auto r = h.sink.Get("/fragments/device/live/result?command_id=processes-test"
                            "&command_id2=network_diag-test&agent_id=a-1&kind=process_tree&n=1");
        REQUIRE(r);
        CHECK(r->body.find("svchost.exe") != std::string::npos);
        CHECK(r->body.find("140.82.112.4:443") != std::string::npos); // joined connection chip
        CHECK(r->body.find("abc123") != std::string::npos);           // hash on the node
        CHECK(r->body.find("id=\"ls-kpi-procs\"") != std::string::npos); // OOB process count
    }
    SECTION("a network_diag- secondary id is the ONLY accepted command_id2 prefix") {
        LiveHarness h;
        // A foreign secondary prefix (e.g. tar-) must be rejected.
        auto r = h.sink.Get("/fragments/device/live/result?command_id=processes-test"
                            "&command_id2=tar-evil&agent_id=a-1&kind=process_tree&n=1");
        REQUIRE(r);
        CHECK(r->status == 400);
    }
    SECTION("secondary not ready: tree renders best-effort WITHOUT connections, no re-poll") {
        LiveHarness h;
        // Primary terminal-SUCCESS with output; secondary has no rows yet (empty).
        h.rows_by_cmd["processes-test"] = {{"a-1", 1, "proc|800|4|svchost.exe|abc|", ""}};
        // command_id2 present in the URL but rows_by_cmd has no network_diag-test entry → empty.
        auto r = h.sink.Get("/fragments/device/live/result?command_id=processes-test"
                            "&command_id2=network_diag-test&agent_id=a-1&kind=process_tree&n=1");
        REQUIRE(r);
        CHECK(r->body.find("svchost.exe") != std::string::npos); // tree still renders
        CHECK(r->body.find("tt-net") == std::string::npos);      // no connection chips (best-effort)
        CHECK(r->body.find("hx-trigger") == std::string::npos);  // primary terminal -> not re-polled
    }
}

// Result-route render coverage for the table kinds (the B1 macOS services field-shape
// divergence + the arp honest-error path were governance Gate-4 findings).
TEST_CASE("device live result: table kinds parse + render", "[device][routes]") {
    SECTION("services Windows 5-field shape: state + running count") {
        LiveHarness h;
        h.fake_rows = {{"a-1", 1, "svc|Spooler|Print Spooler|Running|Automatic\n"
                                  "svc|wuauserv|Windows Update|Stopped|Manual", ""}};
        auto r = h.sink.Get("/fragments/device/live/result?command_id=services-test"
                            "&agent_id=a-1&kind=services&n=1");
        REQUIRE(r);
        CHECK(r->body.find("Print Spooler") != std::string::npos);
        CHECK(r->body.find("1 run") != std::string::npos);      // OOB count: 1 running
        CHECK(r->body.find("id=\"ls-kpi-svc\"") != std::string::npos);
    }
    SECTION("services macOS 4-field svc|label|pid|status: State shows status, not PID (B1)") {
        LiveHarness h;
        h.fake_rows = {{"a-1", 1, "svc|com.apple.mdworker|1234|running", ""}};
        auto r = h.sink.Get("/fragments/device/live/result?command_id=services-test"
                            "&agent_id=a-1&kind=services&n=1");
        REQUIRE(r);
        CHECK(r->body.find("com.apple.mdworker") != std::string::npos);
        CHECK(r->body.find("running") != std::string::npos); // status, from f[3]
        CHECK(r->body.find("1 run") != std::string::npos);   // counted as running (not the PID)
    }
    SECTION("services Linux 4-field svc|name|status|desc: State shows status") {
        LiveHarness h;
        h.fake_rows = {{"a-1", 1, "svc|sshd|running|OpenSSH server", ""}};
        auto r = h.sink.Get("/fragments/device/live/result?command_id=services-test"
                            "&agent_id=a-1&kind=services&n=1");
        REQUIRE(r);
        CHECK(r->body.find("sshd") != std::string::npos);
        CHECK(r->body.find("running") != std::string::npos);
        CHECK(r->body.find("1 run") != std::string::npos);
    }
    SECTION("arp non-Windows error payload -> honest error note, not silent blank") {
        LiveHarness h;
        h.fake_rows = {{"a-1", 1, "error|arp not available on this platform", ""}};
        auto r = h.sink.Get("/fragments/device/live/result?command_id=network_config-test"
                            "&agent_id=a-1&kind=arp&n=1");
        REQUIRE(r);
        CHECK(r->body.find("reported an error") != std::string::npos);
        CHECK(r->body.find("not available on this platform") != std::string::npos);
    }
    SECTION("listening rows render with proto/port/pid") {
        LiveHarness h;
        h.fake_rows = {{"a-1", 1, "listen|tcp|0.0.0.0|445|4", ""}};
        auto r = h.sink.Get("/fragments/device/live/result?command_id=network_diag-test"
                            "&agent_id=a-1&kind=listening&n=1");
        REQUIRE(r);
        CHECK(r->body.find("445") != std::string::npos);
        CHECK(r->body.find("id=\"ls-kpi-listen\"") != std::string::npos);
    }
    SECTION("disk well-formed line: table + free-% KPI (100 - used)") {
        LiveHarness h;
        // 100 GiB total, 25 GiB free, 75% used.
        h.fake_rows = {{"a-1", 1, "disk|C:\\|107374182400|26843545600|75", ""}};
        auto r = h.sink.Get("/fragments/device/live/result?command_id=disk_space-test"
                            "&agent_id=a-1&kind=disk&n=1");
        REQUIRE(r);
        CHECK(r->body.find("id=\"ls-kpi-disk\"") != std::string::npos);
        CHECK(r->body.find("25%") != std::string::npos);       // KPI free% = 100 - 75
        CHECK(r->body.find("100.0 GiB") != std::string::npos); // human()-formatted total
    }
    SECTION("disk: short line skipped; unmeasured total<=0 dashed + off the KPI; bad field zeros") {
        LiveHarness h;
        // line1 (3 fields) -> skipped; line2 total 0 -> dash, excluded from worst-used;
        // line3 non-numeric pct -> zero-default, no crash, drives the KPI.
        h.fake_rows = {{"a-1", 1, "disk|C:\\|123\n"
                                  "disk|D:\\|0|0|0\n"
                                  "disk|/|107374182400|107374182400|x", ""}};
        auto r = h.sink.Get("/fragments/device/live/result?command_id=disk_space-test"
                            "&agent_id=a-1&kind=disk&n=1");
        REQUIRE(r);
        CHECK(r->body.find("&mdash;") != std::string::npos);        // D: total 0 -> dash
        CHECK(r->body.find("id=\"ls-cnt-disk\"") != std::string::npos);
        CHECK(r->body.find(">2<") != std::string::npos);            // 2 rows parsed (short line skipped)
    }
}

TEST_CASE("device live capture_sources: tar status -> read-only source table", "[device][routes]") {
    LiveHarness h;
    h.fake_rows = {{"a-1", 1,
                    "config|process_enabled|true\nconfig|process_live_rows|1234\n"
                    "config|arp_enabled|false\nconfig|arp_live_rows|0",
                    ""}};
    auto r = h.sink.Get("/fragments/device/live/result?command_id=tar-test"
                        "&agent_id=a-1&kind=capture_sources&n=1");
    REQUIRE(r);
    CHECK(r->body.find("$Process_Live") != std::string::npos);
    CHECK(r->body.find("1234") != std::string::npos);                  // live-row count
    CHECK(r->body.find("id=\"ls-cnt-capture_sources\"") != std::string::npos); // OOB "X of N on"
    CHECK(r->body.find("/tar") != std::string::npos);                  // configure-on-TAR link
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
    auto responses = [](const std::string&, const std::string&) {
        return std::vector<DexAgentResponse>{};
    };
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
