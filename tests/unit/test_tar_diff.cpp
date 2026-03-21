/**
 * test_tar_diff.cpp -- Unit tests for TAR diff engine
 *
 * Covers: process birth/death, network connect/disconnect, service state
 * changes, user login/logout, empty snapshots, command-line redaction.
 */

#include "tar_collectors.hpp"

#include <catch2/catch_test_macros.hpp>

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
