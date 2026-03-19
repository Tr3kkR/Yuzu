/**
 * test_quarantine_store.cpp — Unit tests for device quarantine store
 */

#include "quarantine_store.hpp"

#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <string>

using namespace yuzu::server;

namespace {

struct TempDb {
    std::filesystem::path path;
    TempDb() : path(std::filesystem::temp_directory_path() / "test_quarantine.db") {
        std::filesystem::remove(path);
    }
    ~TempDb() { std::filesystem::remove(path); }
};

}  // namespace

TEST_CASE("QuarantineStore: quarantine and release device", "[quarantine][crud]") {
    TempDb tmp;
    QuarantineStore store(tmp.path);
    REQUIRE(store.is_open());

    auto result = store.quarantine_device("agent-001", "admin", "Suspicious activity", "10.0.0.1,10.0.0.2");
    REQUIRE(result.has_value());

    auto status = store.get_status("agent-001");
    REQUIRE(status.has_value());
    CHECK(status->status == "active");
    CHECK(status->quarantined_by == "admin");
    CHECK(status->reason == "Suspicious activity");
    CHECK(status->whitelist == "10.0.0.1,10.0.0.2");
    CHECK(status->quarantined_at > 0);

    auto release = store.release_device("agent-001");
    REQUIRE(release.has_value());

    auto after = store.get_status("agent-001");
    CHECK(!after.has_value());
}

TEST_CASE("QuarantineStore: double quarantine rejected", "[quarantine][crud]") {
    TempDb tmp;
    QuarantineStore store(tmp.path);

    store.quarantine_device("agent-001", "admin", "First", "");
    auto second = store.quarantine_device("agent-001", "admin", "Second", "");
    CHECK(!second.has_value());
}

TEST_CASE("QuarantineStore: release non-quarantined device", "[quarantine][crud]") {
    TempDb tmp;
    QuarantineStore store(tmp.path);

    auto result = store.release_device("agent-nonexistent");
    CHECK(!result.has_value());
}

TEST_CASE("QuarantineStore: list quarantined devices", "[quarantine][list]") {
    TempDb tmp;
    QuarantineStore store(tmp.path);

    store.quarantine_device("agent-001", "admin", "Reason 1", "");
    store.quarantine_device("agent-002", "admin", "Reason 2", "");

    auto list = store.list_quarantined();
    CHECK(list.size() == 2);

    store.release_device("agent-001");
    auto list2 = store.list_quarantined();
    CHECK(list2.size() == 1);
    CHECK(list2[0].agent_id == "agent-002");
}

TEST_CASE("QuarantineStore: history tracking", "[quarantine][history]") {
    TempDb tmp;
    QuarantineStore store(tmp.path);

    store.quarantine_device("agent-001", "admin", "First quarantine", "");
    store.release_device("agent-001");

    store.quarantine_device("agent-001", "security-team", "Second quarantine", "10.0.0.1");
    store.release_device("agent-001");

    auto history = store.get_history("agent-001");
    CHECK(history.size() == 2);
    // Most recent first
    CHECK(history[0].reason == "Second quarantine");
    CHECK(history[1].reason == "First quarantine");
}

TEST_CASE("QuarantineStore: non-quarantined device has no status", "[quarantine][status]") {
    TempDb tmp;
    QuarantineStore store(tmp.path);

    auto status = store.get_status("agent-clean");
    CHECK(!status.has_value());
}
