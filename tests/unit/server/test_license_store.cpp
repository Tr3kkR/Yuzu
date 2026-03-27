/**
 * test_license_store.cpp — Unit tests for LicenseStore
 *
 * Covers: activate, get_active, list, remove, validate, has_feature,
 * seat_count, days_remaining, alert dedup, and acknowledge_alert.
 */

#include "license_store.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <filesystem>
#include <string>

using namespace yuzu::server;

namespace {

struct TempDb {
    std::filesystem::path path;
    TempDb() : path(std::filesystem::temp_directory_path() / "test_license.db") {
        std::filesystem::remove(path);
    }
    ~TempDb() { std::filesystem::remove(path); }
};

int64_t now_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

License make_license(const std::string& org = "Acme Corp",
                      int64_t seats = 100,
                      int64_t expires_at = 0,
                      const std::string& edition = "enterprise",
                      const std::string& features = R"(["admin_read","remote_execute","policy_engine"])") {
    License lic;
    lic.organization = org;
    lic.seat_count = seats;
    lic.expires_at = expires_at;
    lic.edition = edition;
    lic.features_json = features;
    return lic;
}

} // namespace

// ============================================================================
// Activate and Get
// ============================================================================

TEST_CASE("LicenseStore: activate and get_active round-trip", "[license][crud]") {
    TempDb tmp;
    LicenseStore store(tmp.path);
    REQUIRE(store.is_open());

    auto future = now_epoch() + 86400 * 365; // 1 year
    auto lic = make_license("Acme Corp", 100, future, "enterprise");
    auto result = store.activate_license(lic, "LICENSE-KEY-ABC123");
    REQUIRE(result.has_value());
    CHECK(!result->empty());

    auto active = store.get_active_license();
    REQUIRE(active.has_value());
    CHECK(active->id == *result);
    CHECK(active->organization == "Acme Corp");
    CHECK(active->seat_count == 100);
    CHECK(active->edition == "enterprise");
    CHECK(active->status == "active");
    CHECK(active->expires_at == future);
}

TEST_CASE("LicenseStore: activate empty key fails", "[license][validation]") {
    TempDb tmp;
    LicenseStore store(tmp.path);
    REQUIRE(store.is_open());

    auto lic = make_license();
    auto result = store.activate_license(lic, "");
    CHECK(!result.has_value());
}

TEST_CASE("LicenseStore: activate empty organization fails", "[license][validation]") {
    TempDb tmp;
    LicenseStore store(tmp.path);
    REQUIRE(store.is_open());

    License lic;
    lic.organization = "";
    lic.seat_count = 50;
    auto result = store.activate_license(lic, "VALID-KEY-123");
    CHECK(!result.has_value());
}

TEST_CASE("LicenseStore: activate duplicate key fails", "[license][validation]") {
    TempDb tmp;
    LicenseStore store(tmp.path);
    REQUIRE(store.is_open());

    auto lic = make_license();
    auto first = store.activate_license(lic, "SAME-KEY-ABC");
    REQUIRE(first.has_value());

    auto second = store.activate_license(lic, "SAME-KEY-ABC");
    CHECK(!second.has_value());
}

// ============================================================================
// List and Remove
// ============================================================================

TEST_CASE("LicenseStore: list licenses", "[license][crud]") {
    TempDb tmp;
    LicenseStore store(tmp.path);
    REQUIRE(store.is_open());

    store.activate_license(make_license("Org A"), "KEY-A");
    store.activate_license(make_license("Org B"), "KEY-B");

    auto list = store.list_licenses();
    CHECK(list.size() == 2);
}

TEST_CASE("LicenseStore: remove license", "[license][crud]") {
    TempDb tmp;
    LicenseStore store(tmp.path);
    REQUIRE(store.is_open());

    auto result = store.activate_license(make_license(), "KEY-REMOVABLE");
    REQUIRE(result.has_value());

    bool removed = store.remove_license(*result);
    CHECK(removed);

    auto list = store.list_licenses();
    CHECK(list.empty());

    auto active = store.get_active_license();
    CHECK(!active.has_value());
}

TEST_CASE("LicenseStore: remove nonexistent license returns false", "[license][crud]") {
    TempDb tmp;
    LicenseStore store(tmp.path);
    REQUIRE(store.is_open());

    CHECK(!store.remove_license("nonexistent-id"));
}

// ============================================================================
// Status and Validate
// ============================================================================

TEST_CASE("LicenseStore: status active for valid license", "[license][status]") {
    TempDb tmp;
    LicenseStore store(tmp.path);
    REQUIRE(store.is_open());

    auto future = now_epoch() + 86400 * 365;
    store.activate_license(make_license("Acme", 100, future), "KEY-ACTIVE");

    auto status = store.get_status();
    CHECK(status == "active");
}

TEST_CASE("LicenseStore: status unlicensed when no license", "[license][status]") {
    TempDb tmp;
    LicenseStore store(tmp.path);
    REQUIRE(store.is_open());

    auto status = store.get_status();
    CHECK(status == "unlicensed");
}

TEST_CASE("LicenseStore: validate detects expired license", "[license][validate]") {
    TempDb tmp;
    LicenseStore store(tmp.path);
    REQUIRE(store.is_open());

    // License already expired
    auto past = now_epoch() - 86400;
    store.activate_license(make_license("Expired Org", 50, past), "KEY-EXPIRED");

    // Validate should detect expiry and update status
    store.validate(10);

    auto status = store.get_status();
    CHECK(status == "expired");

    auto alerts = store.list_alerts();
    CHECK(!alerts.empty());
    bool found_expired_alert = false;
    for (const auto& a : alerts) {
        if (a.alert_type == "expired") {
            found_expired_alert = true;
            break;
        }
    }
    CHECK(found_expired_alert);
}

TEST_CASE("LicenseStore: validate detects seat limit exceeded", "[license][validate]") {
    TempDb tmp;
    LicenseStore store(tmp.path);
    REQUIRE(store.is_open());

    auto future = now_epoch() + 86400 * 365;
    store.activate_license(make_license("Small Org", 10, future), "KEY-SEATS");

    // 15 agents exceed the 10-seat limit
    store.validate(15);

    auto status = store.get_status();
    CHECK(status == "exceeded");

    auto alerts = store.list_alerts();
    CHECK(!alerts.empty());
    bool found_exceeded = false;
    for (const auto& a : alerts) {
        if (a.alert_type == "exceeded") {
            found_exceeded = true;
            break;
        }
    }
    CHECK(found_exceeded);
}

TEST_CASE("LicenseStore: validate generates near-expiry warning", "[license][validate]") {
    TempDb tmp;
    LicenseStore store(tmp.path);
    REQUIRE(store.is_open());

    // License expires in 15 days (within 30-day warning window)
    auto near_expiry = now_epoch() + 86400 * 15;
    store.activate_license(make_license("Warning Org", 100, near_expiry), "KEY-NEAREXPIRY");

    store.validate(5);

    // Status should still be active (not expired yet)
    auto status = store.get_status();
    CHECK(status == "active");

    auto alerts = store.list_alerts();
    CHECK(!alerts.empty());
    bool found_warning = false;
    for (const auto& a : alerts) {
        if (a.alert_type == "expiry_warning") {
            found_warning = true;
            break;
        }
    }
    CHECK(found_warning);
}

// ============================================================================
// Feature checks
// ============================================================================

TEST_CASE("LicenseStore: has_feature exact match", "[license][feature]") {
    TempDb tmp;
    LicenseStore store(tmp.path);
    REQUIRE(store.is_open());

    auto future = now_epoch() + 86400 * 365;
    store.activate_license(
        make_license("Acme", 100, future, "enterprise",
                     R"(["admin_read","remote_execute","policy_engine"])"),
        "KEY-FEATURES");

    CHECK(store.has_feature("admin_read"));
    CHECK(store.has_feature("remote_execute"));
    CHECK(store.has_feature("policy_engine"));
}

TEST_CASE("LicenseStore: has_feature partial does NOT match", "[license][feature]") {
    TempDb tmp;
    LicenseStore store(tmp.path);
    REQUIRE(store.is_open());

    auto future = now_epoch() + 86400 * 365;
    store.activate_license(
        make_license("Acme", 100, future, "enterprise", R"(["admin_read"])"),
        "KEY-PARTIAL");

    // "admin" is NOT an exact match for "admin_read"
    CHECK(!store.has_feature("admin"));
    // "admin_read_write" is NOT a match for "admin_read"
    CHECK(!store.has_feature("admin_read_write"));
    // Exact match works
    CHECK(store.has_feature("admin_read"));
}

TEST_CASE("LicenseStore: has_feature empty returns false", "[license][feature]") {
    TempDb tmp;
    LicenseStore store(tmp.path);
    REQUIRE(store.is_open());

    auto future = now_epoch() + 86400 * 365;
    store.activate_license(make_license("Acme", 100, future), "KEY-EMPTY-CHECK");

    CHECK(!store.has_feature(""));
}

TEST_CASE("LicenseStore: has_feature with no license returns false", "[license][feature]") {
    TempDb tmp;
    LicenseStore store(tmp.path);
    REQUIRE(store.is_open());

    CHECK(!store.has_feature("some_feature"));
}

// ============================================================================
// Seat count and days remaining
// ============================================================================

TEST_CASE("LicenseStore: seat_count returns correct count", "[license][seats]") {
    TempDb tmp;
    LicenseStore store(tmp.path);
    REQUIRE(store.is_open());

    auto future = now_epoch() + 86400 * 365;
    store.activate_license(make_license("Acme", 250, future), "KEY-SEATS250");

    CHECK(store.seat_count() == 250);
}

TEST_CASE("LicenseStore: seat_count returns 0 when no license", "[license][seats]") {
    TempDb tmp;
    LicenseStore store(tmp.path);
    REQUIRE(store.is_open());

    CHECK(store.seat_count() == 0);
}

TEST_CASE("LicenseStore: days_remaining for valid license", "[license][expiry]") {
    TempDb tmp;
    LicenseStore store(tmp.path);
    REQUIRE(store.is_open());

    // Expires in exactly 90 days
    auto expires = now_epoch() + 86400 * 90;
    store.activate_license(make_license("Acme", 100, expires), "KEY-90DAYS");

    auto days = store.days_remaining();
    // Allow 1-day tolerance for timing edge cases
    CHECK(days >= 89);
    CHECK(days <= 90);
}

TEST_CASE("LicenseStore: days_remaining for perpetual license returns 0", "[license][expiry]") {
    TempDb tmp;
    LicenseStore store(tmp.path);
    REQUIRE(store.is_open());

    // expires_at = 0 means perpetual
    store.activate_license(make_license("Acme", 100, 0), "KEY-PERPETUAL");

    auto days = store.days_remaining();
    CHECK(days == 0);
}

TEST_CASE("LicenseStore: days_remaining when no license returns 0", "[license][expiry]") {
    TempDb tmp;
    LicenseStore store(tmp.path);
    REQUIRE(store.is_open());

    CHECK(store.days_remaining() == 0);
}

// ============================================================================
// Alert dedup and acknowledge
// ============================================================================

TEST_CASE("LicenseStore: alert dedup - validate twice produces one alert", "[license][alert]") {
    TempDb tmp;
    LicenseStore store(tmp.path);
    REQUIRE(store.is_open());

    // Already expired license
    auto past = now_epoch() - 86400;
    store.activate_license(make_license("Dedup Org", 50, past), "KEY-DEDUP");

    // Validate twice in quick succession
    store.validate(10);
    store.validate(10);

    // There should be only one "expired" alert (dedup within 24h)
    auto alerts = store.list_alerts();
    int expired_count = 0;
    for (const auto& a : alerts) {
        if (a.alert_type == "expired")
            ++expired_count;
    }
    CHECK(expired_count == 1);
}

TEST_CASE("LicenseStore: acknowledge alert", "[license][alert]") {
    TempDb tmp;
    LicenseStore store(tmp.path);
    REQUIRE(store.is_open());

    auto past = now_epoch() - 86400;
    store.activate_license(make_license("Ack Org", 50, past), "KEY-ACK");

    store.validate(10);

    auto alerts = store.list_alerts();
    REQUIRE(!alerts.empty());
    auto alert_id = alerts[0].id;
    CHECK(!alerts[0].acknowledged);

    bool acked = store.acknowledge_alert(alert_id);
    CHECK(acked);

    // Unacknowledged-only filter should exclude it
    auto unacked = store.list_alerts(true);
    for (const auto& a : unacked) {
        CHECK(a.id != alert_id);
    }

    // Full list should show it as acknowledged
    auto all = store.list_alerts(false);
    bool found = false;
    for (const auto& a : all) {
        if (a.id == alert_id) {
            CHECK(a.acknowledged);
            found = true;
        }
    }
    CHECK(found);
}

TEST_CASE("LicenseStore: acknowledge nonexistent alert returns false", "[license][alert]") {
    TempDb tmp;
    LicenseStore store(tmp.path);
    REQUIRE(store.is_open());

    CHECK(!store.acknowledge_alert(99999));
}

TEST_CASE("LicenseStore: remove license also removes alerts", "[license][crud]") {
    TempDb tmp;
    LicenseStore store(tmp.path);
    REQUIRE(store.is_open());

    auto past = now_epoch() - 86400;
    auto id = store.activate_license(make_license("Cleanup Org", 50, past), "KEY-CLEANUP");
    REQUIRE(id.has_value());

    store.validate(10);

    auto alerts_before = store.list_alerts();
    CHECK(!alerts_before.empty());

    store.remove_license(*id);

    auto alerts_after = store.list_alerts();
    CHECK(alerts_after.empty());
}
