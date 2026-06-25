/**
 * test_tar_diff.cpp -- Unit tests for TAR diff engine
 *
 * Covers: process birth/death, network connect/disconnect, service state
 * changes, user login/logout, empty snapshots, command-line redaction.
 */

#include "tar_collectors.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <string>
#include <vector>

using namespace yuzu::tar;
using yuzu::agent::ProcessInfo;

// =============================================================================
// Process diff tests
// =============================================================================

TEST_CASE("TAR diff: process birth detected", "[tar][diff][process]") {
    std::vector<ProcessInfo> prev;
    std::vector<ProcessInfo> curr = {{42, 1, "firefox", "firefox --new-tab", "user1"}};

    auto events = compute_process_diff(prev, curr, 1000, 1);

    REQUIRE(events.size() == 1);
    CHECK(events[0].event_type == "process");
    CHECK(events[0].event_action == "started");
    CHECK(events[0].timestamp == 1000);
    CHECK(events[0].snapshot_id == 1);
    CHECK(events[0].detail_json.find("\"pid\":42") != std::string::npos);
    CHECK(events[0].detail_json.find("\"name\":\"firefox\"") != std::string::npos);
}

TEST_CASE("TAR diff: process death detected", "[tar][diff][process]") {
    std::vector<ProcessInfo> prev = {{42, 1, "firefox", "firefox --new-tab", "user1"}};
    std::vector<ProcessInfo> curr;

    auto events = compute_process_diff(prev, curr, 2000, 2);

    REQUIRE(events.size() == 1);
    CHECK(events[0].event_type == "process");
    CHECK(events[0].event_action == "stopped");
    CHECK(events[0].detail_json.find("\"pid\":42") != std::string::npos);
}

TEST_CASE("TAR diff: unchanged processes produce no events", "[tar][diff][process]") {
    std::vector<ProcessInfo> both = {
        {1, 0, "init", "/sbin/init", "root"},
        {42, 1, "firefox", "firefox", "user1"},
    };

    auto events = compute_process_diff(both, both, 3000, 3);
    CHECK(events.empty());
}

TEST_CASE("TAR diff: empty process snapshots produce no events", "[tar][diff][process]") {
    std::vector<ProcessInfo> empty;
    auto events = compute_process_diff(empty, empty, 4000, 4);
    CHECK(events.empty());
}

// =============================================================================
// Network diff tests
// =============================================================================

TEST_CASE("TAR diff: new connection detected", "[tar][diff][network]") {
    std::vector<NetConnection> prev;
    NetConnection nc;
    nc.proto = "tcp";
    nc.local_addr = "192.168.1.1";
    nc.local_port = 12345;
    nc.remote_addr = "10.0.0.1";
    nc.remote_port = 443;
    nc.state = "ESTABLISHED";
    nc.pid = 100;
    std::vector<NetConnection> curr = {nc};

    auto events = compute_network_diff(prev, curr, 5000, 5);

    REQUIRE(events.size() == 1);
    CHECK(events[0].event_type == "network");
    CHECK(events[0].event_action == "connected");
    CHECK(events[0].detail_json.find("\"proto\":\"tcp\"") != std::string::npos);
    CHECK(events[0].detail_json.find("\"remote_port\":443") != std::string::npos);
}

TEST_CASE("TAR diff: closed connection detected", "[tar][diff][network]") {
    NetConnection nc;
    nc.proto = "tcp";
    nc.local_addr = "192.168.1.1";
    nc.local_port = 12345;
    nc.remote_addr = "10.0.0.1";
    nc.remote_port = 443;
    nc.state = "ESTABLISHED";
    nc.pid = 100;
    std::vector<NetConnection> prev = {nc};
    std::vector<NetConnection> curr;

    auto events = compute_network_diff(prev, curr, 6000, 6);

    REQUIRE(events.size() == 1);
    CHECK(events[0].event_type == "network");
    CHECK(events[0].event_action == "disconnected");
}

TEST_CASE("TAR diff: empty network snapshots produce no events", "[tar][diff][network]") {
    std::vector<NetConnection> empty;
    auto events = compute_network_diff(empty, empty, 7000, 7);
    CHECK(events.empty());
}

TEST_CASE("TAR diff: remote_host appears in network event JSON", "[tar][diff][network]") {
    std::vector<NetConnection> prev;
    NetConnection nc;
    nc.proto = "tcp";
    nc.local_addr = "192.168.1.1";
    nc.local_port = 54321;
    nc.remote_addr = "93.184.216.34";
    nc.remote_host = "example.com";
    nc.remote_port = 443;
    nc.state = "ESTABLISHED";
    nc.pid = 200;
    nc.process_name = "curl";
    std::vector<NetConnection> curr = {nc};

    auto events = compute_network_diff(prev, curr, 8000, 8);

    REQUIRE(events.size() == 1);
    CHECK(events[0].event_action == "connected");
    CHECK(events[0].detail_json.find("\"remote_host\":\"example.com\"") != std::string::npos);
    CHECK(events[0].detail_json.find("\"remote_addr\":\"93.184.216.34\"") != std::string::npos);
}

TEST_CASE("TAR diff: empty remote_host produces empty string in JSON", "[tar][diff][network]") {
    std::vector<NetConnection> prev;
    NetConnection nc;
    nc.proto = "tcp";
    nc.local_addr = "10.0.0.1";
    nc.local_port = 12345;
    nc.remote_addr = "172.16.0.1";
    // remote_host left empty (no PTR record)
    nc.remote_port = 80;
    nc.state = "ESTABLISHED";
    nc.pid = 300;
    std::vector<NetConnection> curr = {nc};

    auto events = compute_network_diff(prev, curr, 9000, 9);

    REQUIRE(events.size() == 1);
    CHECK(events[0].detail_json.find("\"remote_host\":\"\"") != std::string::npos);
}

TEST_CASE("TAR diff: remote_host in disconnected event", "[tar][diff][network]") {
    NetConnection nc;
    nc.proto = "tcp";
    nc.local_addr = "10.0.0.1";
    nc.local_port = 12345;
    nc.remote_addr = "93.184.216.34";
    nc.remote_host = "example.com";
    nc.remote_port = 443;
    nc.state = "ESTABLISHED";
    nc.pid = 400;
    std::vector<NetConnection> prev = {nc};
    std::vector<NetConnection> curr;

    auto events = compute_network_diff(prev, curr, 10000, 10);

    REQUIRE(events.size() == 1);
    CHECK(events[0].event_action == "disconnected");
    CHECK(events[0].detail_json.find("\"remote_host\":\"example.com\"") != std::string::npos);
}

// =============================================================================
// Service diff tests
// =============================================================================

TEST_CASE("TAR diff: service state change detected", "[tar][diff][service]") {
    ServiceInfo running;
    running.name = "sshd";
    running.display_name = "OpenSSH Server";
    running.status = "running";
    running.startup_type = "automatic";

    ServiceInfo stopped = running;
    stopped.status = "stopped";

    std::vector<ServiceInfo> prev = {running};
    std::vector<ServiceInfo> curr = {stopped};

    auto events = compute_service_diff(prev, curr, 8000, 8);

    REQUIRE(events.size() == 1);
    CHECK(events[0].event_type == "service");
    CHECK(events[0].event_action == "state_changed");
    CHECK(events[0].detail_json.find("\"status\":\"stopped\"") != std::string::npos);
    CHECK(events[0].detail_json.find("\"prev_status\":\"running\"") != std::string::npos);
}

TEST_CASE("TAR diff: new service detected", "[tar][diff][service]") {
    std::vector<ServiceInfo> prev;
    ServiceInfo svc;
    svc.name = "nginx";
    svc.display_name = "NGINX";
    svc.status = "running";
    svc.startup_type = "automatic";
    std::vector<ServiceInfo> curr = {svc};

    auto events = compute_service_diff(prev, curr, 9000, 9);

    REQUIRE(events.size() == 1);
    CHECK(events[0].event_action == "started");
}

TEST_CASE("TAR diff: removed service detected", "[tar][diff][service]") {
    ServiceInfo svc;
    svc.name = "nginx";
    svc.display_name = "NGINX";
    svc.status = "running";
    svc.startup_type = "automatic";
    std::vector<ServiceInfo> prev = {svc};
    std::vector<ServiceInfo> curr;

    auto events = compute_service_diff(prev, curr, 10000, 10);

    REQUIRE(events.size() == 1);
    CHECK(events[0].event_action == "stopped");
}

// =============================================================================
// User diff tests
// =============================================================================

TEST_CASE("TAR diff: user login detected", "[tar][diff][user]") {
    std::vector<UserSession> prev;
    UserSession us;
    us.user = "admin";
    us.domain = "CORP";
    us.logon_type = "interactive";
    us.session_id = "1";
    std::vector<UserSession> curr = {us};

    auto events = compute_user_diff(prev, curr, 11000, 11);

    REQUIRE(events.size() == 1);
    CHECK(events[0].event_type == "user");
    CHECK(events[0].event_action == "login");
    CHECK(events[0].detail_json.find("\"user\":\"admin\"") != std::string::npos);
}

TEST_CASE("TAR diff: user logout detected", "[tar][diff][user]") {
    UserSession us;
    us.user = "admin";
    us.domain = "CORP";
    us.logon_type = "interactive";
    us.session_id = "1";
    std::vector<UserSession> prev = {us};
    std::vector<UserSession> curr;

    auto events = compute_user_diff(prev, curr, 12000, 12);

    REQUIRE(events.size() == 1);
    CHECK(events[0].event_type == "user");
    CHECK(events[0].event_action == "logout");
}

TEST_CASE("TAR diff: empty user snapshots produce no events", "[tar][diff][user]") {
    std::vector<UserSession> empty;
    auto events = compute_user_diff(empty, empty, 13000, 13);
    CHECK(events.empty());
}

// =============================================================================
// Redaction tests
// =============================================================================

TEST_CASE("TAR redaction: password in cmdline is redacted", "[tar][diff][redaction]") {
    auto patterns = kDefaultRedactionPatterns;

    CHECK(should_redact("myapp --password=hunter2", patterns));
    CHECK(should_redact("curl -H 'Authorization: Bearer TOKEN_VALUE'", patterns));
    CHECK(should_redact("export API_KEY=abc123", patterns));
    CHECK(should_redact("vault read secret/database", patterns));
    CHECK(should_redact("app --credential-file=/path", patterns));

    CHECK_FALSE(should_redact("ls -la /tmp", patterns));
    CHECK_FALSE(should_redact("firefox https://example.com", patterns));
    CHECK_FALSE(should_redact("", patterns));
}

TEST_CASE("TAR redaction: redact_cmdline returns sentinel", "[tar][diff][redaction]") {
    auto patterns = kDefaultRedactionPatterns;

    auto result = redact_cmdline("myapp --password=hunter2", patterns);
    CHECK(result == "[REDACTED by TAR]");

    auto safe = redact_cmdline("ls -la", patterns);
    CHECK(safe == "ls -la");
}

TEST_CASE("TAR diff: process with sensitive cmdline is redacted in events", "[tar][diff][redaction]") {
    std::vector<ProcessInfo> prev;
    std::vector<ProcessInfo> curr = {
        {99, 1, "myapp", "myapp --password=hunter2", "root"}};

    auto events = compute_process_diff(prev, curr, 14000, 14);

    REQUIRE(events.size() == 1);
    CHECK(events[0].detail_json.find("[REDACTED by TAR]") != std::string::npos);
    CHECK(events[0].detail_json.find("hunter2") == std::string::npos);
}

TEST_CASE("TAR redaction: ensure_redaction_defaults is fail-closed for every input (#1532)",
          "[tar][diff][redaction][issue1532]") {
    // fjarvis HIGH: no loaded set may disable the baseline redaction. load_redaction_patterns
    // routes the parse_pattern_config result through ensure_redaction_defaults; the fail-open
    // was that a valid array whose elements all get dropped (`[]`, `[1,2,3]`, all-over-long, or
    // `["*"]`) yields an EMPTY loaded vector. Prove every such loaded vector still redacts.
    auto contains_all_defaults = [](const std::vector<std::string>& v) {
        for (const auto& def : kDefaultRedactionPatterns)
            if (std::find(v.begin(), v.end(), def) == v.end())
                return false;
        return true;
    };

    SECTION("empty loaded set (the all-dropped / empty-array fail-open) still redacts") {
        auto merged = ensure_redaction_defaults({});
        CHECK(contains_all_defaults(merged));
        CHECK(should_redact("myapp --password=hunter2", merged));
        CHECK(should_redact("export API_KEY=abc123", merged));
        CHECK(should_redact("vault read secret/database", merged));
    }

    SECTION("operator-custom patterns are ADDED to, never REPLACE, the defaults") {
        auto merged = ensure_redaction_defaults({"*myorg_session*"});
        CHECK(contains_all_defaults(merged));
        CHECK(std::find(merged.begin(), merged.end(), "*myorg_session*") != merged.end());
        CHECK(should_redact("svc --myorg_session=xyz", merged)); // custom still applies
        CHECK(should_redact("svc --password=p", merged));        // default still applies
    }

    SECTION("a loaded set already holding a default is not duplicated") {
        auto merged = ensure_redaction_defaults({"*password*"});
        CHECK(contains_all_defaults(merged));
        CHECK(std::count(merged.begin(), merged.end(), std::string{"*password*"}) == 1);
    }
}

// =============================================================================
// L3: Edge case tests — empty redaction patterns, long cmdline, unicode username
// =============================================================================

TEST_CASE("TAR redaction: empty patterns list never redacts", "[tar][diff][redaction][edge]") {
    std::vector<std::string> empty_patterns;
    CHECK_FALSE(should_redact("myapp --password=hunter2", empty_patterns));
    CHECK_FALSE(should_redact("export API_KEY=abc123", empty_patterns));
    CHECK_FALSE(should_redact("", empty_patterns));

    auto result = redact_cmdline("myapp --password=hunter2", empty_patterns);
    CHECK(result == "myapp --password=hunter2");
}

TEST_CASE("TAR diff: long cmdline (1KB+) is handled correctly", "[tar][diff][process][edge]") {
    // Build a command line longer than 1KB
    std::string long_cmdline = "java -jar app.jar";
    for (int i = 0; i < 100; ++i) {
        long_cmdline += " --option-" + std::to_string(i) + "=value" + std::to_string(i);
    }
    REQUIRE(long_cmdline.size() > 1024);

    std::vector<ProcessInfo> prev;
    std::vector<ProcessInfo> curr = {{500, 1, "java", long_cmdline, "appuser"}};

    auto events = compute_process_diff(prev, curr, 15000, 15);

    REQUIRE(events.size() == 1);
    CHECK(events[0].event_type == "process");
    CHECK(events[0].event_action == "started");
    // The long cmdline should appear in detail_json (not truncated silently)
    CHECK(events[0].detail_json.find("java") != std::string::npos);
}

TEST_CASE("TAR diff: unicode username in process events", "[tar][diff][process][edge]") {
    std::vector<ProcessInfo> prev;
    // Use a username with multi-byte UTF-8 characters
    std::vector<ProcessInfo> curr = {
        {77, 1, "editor", "editor /tmp/file.txt", "\xc3\xa9\x6d\x69\x6c\x65"}};  // "emile" with accented e

    auto events = compute_process_diff(prev, curr, 16000, 16);

    REQUIRE(events.size() == 1);
    CHECK(events[0].event_type == "process");
    CHECK(events[0].event_action == "started");
    // The unicode username should be preserved in the JSON
    CHECK(events[0].detail_json.find("\xc3\xa9\x6d\x69\x6c\x65") != std::string::npos);
}

// ── #541: should_redact is case-insensitive SUBSTRING, not real glob ────────

TEST_CASE("TAR should_redact: case-insensitive substring, not glob", "[tar][diff][redact][issue541]") {
    // Plain substring containment, case-insensitive.
    CHECK(should_redact("PASSWORD=hunter2", {"password"}));
    CHECK(should_redact("api --Token=abc", {"token"}));
    CHECK_FALSE(should_redact("nothing here", {"secret"}));

    // Leading/trailing '*' are stripped to the core substring (a readability
    // affordance), then matched as substring.
    CHECK(should_redact("my secret value", {"*secret*"}));
    CHECK(should_redact("prefix-token", {"*token"}));

    // '?' and '[abc]' are LITERALS, not glob metacharacters.
    CHECK(should_redact("run with ?flag", {"?flag"}));      // literal '?'
    CHECK_FALSE(should_redact("run with xflag", {"?flag"})); // '?' is NOT "any char"
    CHECK(should_redact("path [abc] here", {"[abc]"}));      // literal bracket
    CHECK_FALSE(should_redact("path a here", {"[abc]"}));    // not a char class

    // A pattern that strips to an empty core matches nothing (no-op).
    CHECK_FALSE(should_redact("anything", {"*"}));
}

// =============================================================================
// Typed warehouse events — macOS names-only (B-heavy)
// =============================================================================

TEST_CASE("TAR compute_process_events: macOS is names-only; cmdline kept elsewhere",
          "[tar][diff][process]") {
    // On macOS the poll path blanks cmdline (parity with the Endpoint Security
    // stream and the works-council / data-minimization posture); Linux/Windows keep
    // the (redacted) command line. Locks the #if defined(__APPLE__) branch in
    // compute_process_events so the macOS names-only guarantee can't silently regress.
    std::vector<ProcessInfo> prev; // empty previous → current process is a 'started'
    std::vector<ProcessInfo> curr = {
        {4242, 1, "python3", "/usr/bin/python3 --token=secret", "alice"}};

    auto events = compute_process_events(prev, curr, 1000, 7, /*redaction_patterns=*/{});
    REQUIRE(events.size() == 1);
    CHECK(events[0].action == "started");
    CHECK(events[0].pid == 4242);
    CHECK(events[0].name == "python3");
#if defined(__APPLE__)
    CHECK(events[0].cmdline.empty()); // names-only on macOS — both ES stream and poll
#else
    CHECK(events[0].cmdline == "/usr/bin/python3 --token=secret"); // populated on Linux/Windows
#endif
}

// =============================================================================
// Software install/uninstall diff tests (compute_software_events)
// =============================================================================

namespace {
SoftwareInfo sw(std::string name, std::string version, std::string scope = "machine",
                std::string user = "") {
    SoftwareInfo s;
    s.name = std::move(name);
    s.version = std::move(version);
    s.publisher = "Acme";
    s.scope = std::move(scope);
    s.user = std::move(user);
    s.install_date = "20260101";
    return s;
}
} // namespace

TEST_CASE("TAR software diff: install detected", "[tar][diff][software]") {
    std::vector<SoftwareInfo> prev;
    std::vector<SoftwareInfo> curr = {sw("7-Zip", "23.01")};

    auto events = compute_software_events(prev, curr, 1000, 1);

    REQUIRE(events.size() == 1);
    CHECK(events[0].action == "installed");
    CHECK(events[0].name == "7-Zip");
    CHECK(events[0].version == "23.01");
    CHECK(events[0].prev_version.empty());
    CHECK(events[0].scope == "machine");
    CHECK(events[0].ts == 1000);
    CHECK(events[0].snapshot_id == 1);
}

TEST_CASE("TAR software diff: removal detected", "[tar][diff][software]") {
    std::vector<SoftwareInfo> prev = {sw("7-Zip", "23.01")};
    std::vector<SoftwareInfo> curr;

    auto events = compute_software_events(prev, curr, 2000, 2);

    REQUIRE(events.size() == 1);
    CHECK(events[0].action == "removed");
    CHECK(events[0].name == "7-Zip");
}

TEST_CASE("TAR software diff: version change is one upgrade, not remove+install",
          "[tar][diff][software]") {
    std::vector<SoftwareInfo> prev = {sw("7-Zip", "23.01")};
    std::vector<SoftwareInfo> curr = {sw("7-Zip", "24.00")};

    auto events = compute_software_events(prev, curr, 3000, 3);

    REQUIRE(events.size() == 1);
    CHECK(events[0].action == "upgraded");
    CHECK(events[0].version == "24.00");
    CHECK(events[0].prev_version == "23.01");
}

TEST_CASE("TAR software diff: same version produces no event", "[tar][diff][software]") {
    std::vector<SoftwareInfo> prev = {sw("7-Zip", "23.01")};
    std::vector<SoftwareInfo> curr = {sw("7-Zip", "23.01")};

    auto events = compute_software_events(prev, curr, 4000, 4);

    CHECK(events.empty());
}

TEST_CASE("TAR software diff: same name in machine vs user scope is independent",
          "[tar][diff][software]") {
    // A machine-scope and a per-user copy of the same product must not collapse:
    // removing the user copy is one 'removed' event, the machine copy is untouched.
    std::vector<SoftwareInfo> prev = {sw("VSCode", "1.90", "machine"),
                                      sw("VSCode", "1.90", "user", "alice")};
    std::vector<SoftwareInfo> curr = {sw("VSCode", "1.90", "machine")};

    auto events = compute_software_events(prev, curr, 5000, 5);

    REQUIRE(events.size() == 1);
    CHECK(events[0].action == "removed");
    CHECK(events[0].scope == "user");
    CHECK(events[0].user == "alice");
}

TEST_CASE("TAR software diff: two users' same app tracked separately",
          "[tar][diff][software]") {
    std::vector<SoftwareInfo> prev = {sw("Slack", "4.0", "user", "alice")};
    std::vector<SoftwareInfo> curr = {sw("Slack", "4.0", "user", "alice"),
                                      sw("Slack", "4.0", "user", "bob")};

    auto events = compute_software_events(prev, curr, 6000, 6);

    REQUIRE(events.size() == 1);
    CHECK(events[0].action == "installed");
    CHECK(events[0].user == "bob");
}

TEST_CASE("TAR software diff: empty snapshots produce no events (cold-start contract)",
          "[tar][diff][software]") {
    // The plugin seeds the baseline silently on first run; at the diff level an
    // empty-vs-empty comparison must produce nothing.
    std::vector<SoftwareInfo> prev;
    std::vector<SoftwareInfo> curr;

    auto events = compute_software_events(prev, curr, 7000, 7);

    CHECK(events.empty());
}

TEST_CASE("TAR software diff: carried-forward entries are inert while a sibling changes",
          "[tar][diff][software]") {
    // This is the load-bearing invariant behind the plugin's carry-forward of
    // logged-off users: an entry that is byte-identical in previous and current
    // (a carried offline user) must emit NO event, even when another entry in the
    // same snapshot genuinely changes. A spurious event here would be the
    // logon/logoff "flapping" the carry-forward design exists to prevent.
    std::vector<SoftwareInfo> prev = {sw("OfflineApp", "1.0", "user", "bob"),  // logged-off → carried
                                      sw("7-Zip", "23.01", "machine")};
    std::vector<SoftwareInfo> curr = {sw("OfflineApp", "1.0", "user", "bob"),  // carried unchanged
                                      sw("7-Zip", "24.00", "machine")};        // real upgrade

    auto events = compute_software_events(prev, curr, 8000, 8);

    REQUIRE(events.size() == 1); // only the machine upgrade — the carried user is inert
    CHECK(events[0].action == "upgraded");
    CHECK(events[0].scope == "machine");
    CHECK(events[0].name == "7-Zip");
}

// =============================================================================
// Steady-state snapshot assembly tests (assemble_steady_state_snapshot)
//
// These exercise the plugin's carry-forward ORCHESTRATION directly (the layer
// do_collect_software runs) rather than just the diff: a logged-off user's
// inventory is carried forward (no per-tick hive mount, no ghost events), a
// logged-on user's uninstall is NOT masked, and machine scope always comes from
// the fresh scan (never resurrected from the previous snapshot).
// =============================================================================

namespace {
bool snapshot_has(const std::vector<SoftwareInfo>& snap, const std::string& scope,
                  const std::string& user, const std::string& name) {
    return std::any_of(snap.begin(), snap.end(), [&](const SoftwareInfo& s) {
        return s.scope == scope && s.user == user && s.name == name;
    });
}
} // namespace

TEST_CASE("TAR software assembly: logged-off user carried forward, diff inert",
          "[tar][software][assembly]") {
    // bob is logged off this tick → his hive is not scanned, so his last-known
    // inventory is carried forward and must diff to nothing (the design's reason
    // for not re-mounting NTUSER.DAT every tick).
    std::vector<SoftwareInfo> previous = {sw("Slack", "4.0", "user", "bob"),
                                          sw("7-Zip", "23.01", "machine")};
    std::vector<SoftwareInfo> machine_and_loaded = {sw("7-Zip", "23.01", "machine")};
    std::vector<std::string> scanned; // bob NOT scanned (logged off)

    auto current = assemble_steady_state_snapshot(previous, machine_and_loaded, scanned);

    CHECK(snapshot_has(current, "user", "bob", "Slack")); // carried forward
    auto events = compute_software_events(previous, current, 1000, 1);
    CHECK(events.empty()); // no ghost remove for the logged-off user
}

TEST_CASE("TAR software assembly: logged-on user's uninstall is not masked",
          "[tar][software][assembly]") {
    // alice is logged on (scanned) and has uninstalled Slack — her hive WAS read
    // and returned nothing, so the prior entry must NOT be carried forward and the
    // diff must report a real 'removed'.
    std::vector<SoftwareInfo> previous = {sw("Slack", "4.0", "user", "alice")};
    std::vector<SoftwareInfo> machine_and_loaded; // alice scanned, no apps now
    std::vector<std::string> scanned = {"alice"};

    auto current = assemble_steady_state_snapshot(previous, machine_and_loaded, scanned);

    CHECK(current.empty()); // alice's stale entry is dropped, not carried
    auto events = compute_software_events(previous, current, 2000, 2);
    REQUIRE(events.size() == 1);
    CHECK(events[0].action == "removed");
    CHECK(events[0].user == "alice");
}

TEST_CASE("TAR software assembly: machine + loaded-user software pass through",
          "[tar][software][assembly]") {
    std::vector<SoftwareInfo> previous;
    std::vector<SoftwareInfo> machine_and_loaded = {sw("7-Zip", "23.01", "machine"),
                                                    sw("Slack", "4.0", "user", "alice")};
    std::vector<std::string> scanned = {"alice"};

    auto current = assemble_steady_state_snapshot(previous, machine_and_loaded, scanned);

    CHECK(current.size() == 2);
    CHECK(snapshot_has(current, "machine", "", "7-Zip"));
    CHECK(snapshot_has(current, "user", "alice", "Slack"));
}

TEST_CASE("TAR software assembly: empty scanned set carries all logged-off users forward",
          "[tar][software][assembly]") {
    // No hives loaded this tick (every user logged off): all prior user entries are
    // carried forward; machine scope still comes from the fresh scan.
    std::vector<SoftwareInfo> previous = {sw("Slack", "4.0", "user", "alice"),
                                          sw("Zoom", "5.0", "user", "bob")};
    std::vector<SoftwareInfo> machine_and_loaded = {sw("7-Zip", "23.01", "machine")};
    std::vector<std::string> scanned;

    auto current = assemble_steady_state_snapshot(previous, machine_and_loaded, scanned);

    CHECK(current.size() == 3); // 1 machine + 2 carried users
    auto events = compute_software_events(previous, current, 3000, 3);
    REQUIRE(events.size() == 1); // only the newly seen machine app
    CHECK(events[0].name == "7-Zip");
    CHECK(events[0].action == "installed");
}

TEST_CASE("TAR software assembly: stale machine entries are never resurrected",
          "[tar][software][assembly]") {
    // Carry-forward is user-scope ONLY. A machine app in `previous` but absent from
    // the fresh machine scan is a real uninstall → 'removed', not carried.
    std::vector<SoftwareInfo> previous = {sw("OldTool", "1.0", "machine")};
    std::vector<SoftwareInfo> machine_and_loaded; // fresh scan: OldTool gone
    std::vector<std::string> scanned;

    auto current = assemble_steady_state_snapshot(previous, machine_and_loaded, scanned);

    CHECK(current.empty());
    auto events = compute_software_events(previous, current, 4000, 4);
    REQUIRE(events.size() == 1);
    CHECK(events[0].action == "removed");
    CHECK(events[0].scope == "machine");
}

TEST_CASE("TAR software assembly: logged-on user's upgrade flows through (not masked)",
          "[tar][software][assembly]") {
    // alice is logged on (scanned) and bumped Slack 4.0 -> 4.1 — the fresh loaded
    // scan supplies the new version, the prior entry is NOT carried forward, so the
    // diff is a single 'upgraded', not a remove+install.
    std::vector<SoftwareInfo> previous = {sw("Slack", "4.0", "user", "alice")};
    std::vector<SoftwareInfo> machine_and_loaded = {sw("Slack", "4.1", "user", "alice")};
    std::vector<std::string> scanned = {"alice"};

    auto current = assemble_steady_state_snapshot(previous, machine_and_loaded, scanned);

    REQUIRE(current.size() == 1);
    CHECK(current[0].version == "4.1"); // fresh scan wins; no carried 4.0 duplicate
    auto events = compute_software_events(previous, current, 5000, 5);
    REQUIRE(events.size() == 1);
    CHECK(events[0].action == "upgraded");
    CHECK(events[0].version == "4.1");
    CHECK(events[0].prev_version == "4.0");
}

TEST_CASE("TAR software assembly: a scanned user is not double-carried",
          "[tar][software][assembly]") {
    // A user present in BOTH the fresh loaded scan AND `previous`, whose SID IS in
    // scanned_users, must appear exactly once in the assembled snapshot — the
    // carry-forward guard (`!scanned.contains`) excludes them, so no duplicate
    // (scope,user,name) entry is produced for the diff to fold.
    std::vector<SoftwareInfo> previous = {sw("Zoom", "5.0", "user", "alice")};
    std::vector<SoftwareInfo> machine_and_loaded = {sw("Zoom", "5.0", "user", "alice")};
    std::vector<std::string> scanned = {"alice"};

    auto current = assemble_steady_state_snapshot(previous, machine_and_loaded, scanned);

    REQUIRE(current.size() == 1); // single entry, not carried a second time
    auto events = compute_software_events(previous, current, 6000, 6);
    CHECK(events.empty()); // unchanged -> no event
}

// =============================================================================
// ARP diff tests (ADR-0015) — keyed on (iface, ip, mac); entry_type not keyed
// =============================================================================

TEST_CASE("ARP diff: appeared and removed bindings", "[tar][diff][arp]") {
    std::vector<ArpEntry> prev = {{"Ethernet", "192.168.1.1", "aa:bb:cc:dd:ee:ff", "dynamic"}};
    std::vector<ArpEntry> cur = {{"Ethernet", "192.168.1.1", "aa:bb:cc:dd:ee:ff", "dynamic"},
                                 {"Ethernet", "192.168.1.2", "11:22:33:44:55:66", "static"}};
    auto ev = compute_arp_events(prev, cur, 100, 7);
    REQUIRE(ev.size() == 1);
    CHECK(ev[0].action == "appeared");
    CHECK(ev[0].ip_address == "192.168.1.2");
    CHECK(ev[0].snapshot_id == 7);

    auto removed = compute_arp_events(cur, prev, 101, 8);
    REQUIRE(removed.size() == 1);
    CHECK(removed[0].action == "removed");
    CHECK(removed[0].ip_address == "192.168.1.2");
}

TEST_CASE("ARP diff: entry_type change on same binding is not churn", "[tar][diff][arp]") {
    std::vector<ArpEntry> prev = {{"Ethernet", "10.0.0.1", "aa:bb:cc:dd:ee:ff", "dynamic"}};
    std::vector<ArpEntry> cur = {{"Ethernet", "10.0.0.1", "aa:bb:cc:dd:ee:ff", "static"}};
    CHECK(compute_arp_events(prev, cur, 100, 1).empty());
}

// =============================================================================
// DNS diff tests (ADR-0015) — keyed on (name, type, data); TTL not keyed
// =============================================================================

TEST_CASE("DNS diff: appeared and removed resolutions", "[tar][diff][dns]") {
    std::vector<DnsEntry> prev = {{"example.com", "A", "93.184.216.34", 60, "cache"}};
    std::vector<DnsEntry> cur = {{"example.com", "A", "93.184.216.34", 60, "cache"},
                                 {"evil.test", "A", "10.0.0.9", 10, "cache"}};
    auto ev = compute_dns_events(prev, cur, 100, 5);
    REQUIRE(ev.size() == 1);
    CHECK(ev[0].action == "appeared");
    CHECK(ev[0].name == "evil.test");

    auto removed = compute_dns_events(cur, prev, 101, 6);
    REQUIRE(removed.size() == 1);
    CHECK(removed[0].action == "removed");
    CHECK(removed[0].name == "evil.test");
}

TEST_CASE("DNS diff: TTL decrement on same resolution is not churn", "[tar][diff][dns]") {
    std::vector<DnsEntry> prev = {{"example.com", "A", "93.184.216.34", 60, "cache"}};
    std::vector<DnsEntry> cur = {{"example.com", "A", "93.184.216.34", 30, "cache"}};
    CHECK(compute_dns_events(prev, cur, 100, 1).empty());
}
