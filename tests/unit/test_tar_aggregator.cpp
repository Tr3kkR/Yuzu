/**
 * test_tar_aggregator.cpp -- Unit tests for the TAR rollup + retention engine
 *
 * Anchors the contract documented in `tar_plugin.cpp` `configure` and
 * `docs/user-manual/tar.md`: disabling a source via `<source>_enabled=false`
 * leaves existing rows queryable. Without the per-source guard in
 * `run_retention()`, time-based retention drains the hourly tier within 24h,
 * the daily tier within 31d, and the monthly tier within ~365d after disable
 * — see issue #539 and the chaos-injector CHAOS-2 reproduction.
 */

#include "tar_aggregator.hpp"
#include "tar_db.hpp"
#include "tar_schema_registry.hpp"
#include "test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <format>
#include <string>
#include <string_view>

using namespace yuzu::tar;

namespace {

// Issue #539 anchor: 24h cutoff for the hourly tier in the schema registry.
// If the registry's `process_hourly` retention_default ever changes, the
// helpers below have to follow.
constexpr int64_t kHourlyCutoffSec = 24 * 3600;

int64_t row_count(TarDatabase& db, const std::string& table) {
    auto res = db.execute_query("SELECT COUNT(*) FROM " + table);
    REQUIRE(res.has_value());
    REQUIRE(res->rows.size() == 1);
    return std::stoll(res->rows[0][0]);
}

// Seed 48 hourly rows centered on t_now so half (h=0..23) fall inside the
// 24h retention window and half (h=24..47) fall outside it. With the source
// enabled, retention at t_now deletes the outside half only; with the source
// disabled, retention preserves all 48.
void seed_process_hourly(TarDatabase& db, int64_t t_now) {
    for (int h = 0; h < 48; ++h) {
        REQUIRE(db.execute_sql(std::format(
            "INSERT INTO process_hourly "
            "(hour_ts,name,user,start_count,stop_count) "
            "VALUES ({}, 'svc.exe', 'SYSTEM', 1, 1)",
            t_now - h * 3600)));
    }
}

void seed_tcp_hourly(TarDatabase& db, int64_t t_now) {
    for (int h = 0; h < 48; ++h) {
        REQUIRE(db.execute_sql(std::format(
            "INSERT INTO tcp_hourly "
            "(hour_ts,remote_addr,remote_port,proto,process_name,"
            "connect_count,disconnect_count) "
            "VALUES ({}, '10.0.0.1', 5000, 'tcp', 'sshd', 1, 1)",
            t_now - h * 3600)));
    }
}

} // namespace

// ── #539 anchor: retention pauses while a source is disabled ────────────────

TEST_CASE("TAR retention: disabled source preserves hourly rows past cutoff",
          "[tar][retention][issue539]") {
    // Reproduction of /governance chaos-injector CHAOS-2. Without the
    // per-source guard, two retention passes (t0+1h and t0+25h) drain
    // process_hourly entirely after the operator disables process_enabled
    // — even though the configure docstring promises queryability.
    yuzu::test::TempDbFile tmp{std::string_view{"tar-issue539-"}};
    auto opened = TarDatabase::open(tmp.path);
    REQUIRE(opened.has_value());
    TarDatabase db = std::move(*opened);
    REQUIRE(db.create_warehouse_tables());

    const int64_t t0 = 1'735'689'600;  // 2025-01-01 00:00:00 UTC
    seed_process_hourly(db, t0);
    REQUIRE(row_count(db, "process_hourly") == 48);

    db.set_config("process_enabled", "false");

    run_retention(db, t0 + 3600);
    run_retention(db, t0 + kHourlyCutoffSec + 3600);

    CHECK(row_count(db, "process_hourly") == 48);
}

TEST_CASE("TAR retention: enabled sources still age out past cutoff",
          "[tar][retention][issue539]") {
    // Counter-test: an enabled source must continue to age out, otherwise
    // the #539 fix would silently disable retention everywhere. With the
    // 48-row centered seed, exactly the rows with hour_ts < (t_now -
    // retention_default) are deleted.
    yuzu::test::TempDbFile tmp{std::string_view{"tar-issue539-enabled-"}};
    auto opened = TarDatabase::open(tmp.path);
    REQUIRE(opened.has_value());
    TarDatabase db = std::move(*opened);
    REQUIRE(db.create_warehouse_tables());

    const int64_t t_now = 1'735'689'600 + kHourlyCutoffSec;
    seed_process_hourly(db, t_now);

    REQUIRE(db.get_config("process_enabled", "true") == "true");

    run_retention(db, t_now);

    auto remaining = row_count(db, "process_hourly");
    CHECK(remaining > 0);
    CHECK(remaining < 48);
}

TEST_CASE("TAR retention: re-enabling a source resumes retention",
          "[tar][retention][issue539]") {
    // Operator journey: freeze for analysis, take an export, re-enable to
    // resume normal aging. The guard is purely config-driven, so flipping
    // <source>_enabled back to "true" must immediately re-arm time-based
    // retention on the next rollup tick.
    yuzu::test::TempDbFile tmp{std::string_view{"tar-issue539-resume-"}};
    auto opened = TarDatabase::open(tmp.path);
    REQUIRE(opened.has_value());
    TarDatabase db = std::move(*opened);
    REQUIRE(db.create_warehouse_tables());

    const int64_t t_now = 1'735'689'600 + kHourlyCutoffSec;
    seed_process_hourly(db, t_now);

    db.set_config("process_enabled", "false");
    run_retention(db, t_now);
    REQUIRE(row_count(db, "process_hourly") == 48);

    db.set_config("process_enabled", "true");
    run_retention(db, t_now);

    auto after_resume = row_count(db, "process_hourly");
    CHECK(after_resume > 0);
    CHECK(after_resume < 48);
}

TEST_CASE("TAR retention: disabling one source does not pause others",
          "[tar][retention][issue539]") {
    // Independence invariant: the guard is per-source. Disabling
    // process_enabled must not freeze tcp / service / user retention —
    // otherwise a future refactor could turn the per-source guard into a
    // global switch without deleting a named test.
    yuzu::test::TempDbFile tmp{std::string_view{"tar-issue539-isolation-"}};
    auto opened = TarDatabase::open(tmp.path);
    REQUIRE(opened.has_value());
    TarDatabase db = std::move(*opened);
    REQUIRE(db.create_warehouse_tables());

    const int64_t t_now = 1'735'689'600 + kHourlyCutoffSec;
    seed_process_hourly(db, t_now);
    seed_tcp_hourly(db, t_now);

    db.set_config("process_enabled", "false");
    // tcp_enabled left at default => "true"
    run_retention(db, t_now);

    CHECK(row_count(db, "process_hourly") == 48);   // disabled, preserved
    auto tcp_remaining = row_count(db, "tcp_hourly");
    CHECK(tcp_remaining > 0);                       // enabled, partially aged
    CHECK(tcp_remaining < 48);
}
