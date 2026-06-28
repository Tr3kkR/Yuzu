// AppPerfDailyStore (DEX app-perf-over-time B1) — the born-on-Postgres per-device
// daily projection: pure canon-merge, apply/read round-trip, ON-CONFLICT overwrite,
// canon-collision safety, 31-day retention prune, and delete_agent.

#include <catch2/catch_test_macros.hpp>

#include "app_perf_daily_store.hpp"
#include "pg/pg_pool.hpp"

#include "../test_helpers.hpp"

#include <chrono>
#include <cmath>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

using yuzu::server::AppPerfDailyRow;
using yuzu::server::AppPerfDailyStore;
using yuzu::server::canon_merge_daily;
using yuzu::server::pg::PgPool;

namespace {
std::int64_t today_utc() {
    const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();
    return (now / 86400) * 86400;
}
} // namespace

TEST_CASE("canon_merge_daily merges canon-collisions sample-weighted", "[app_perf][merge]") {
    std::vector<AppPerfDailyRow> rows = {
        {.app_name = "app", .version = "1.2.3", .day = 86400, .samples = 10, .instances_max = 2,
         .cpu_avg = 90.0, .cpu_max = 95.0, .ws_avg_bytes = 100, .ws_max_bytes = 200},
        {.app_name = "app", .version = "1.2.3.0", .day = 86400, .samples = 30, .instances_max = 5,
         .cpu_avg = 10.0, .cpu_max = 20.0, .ws_avg_bytes = 300, .ws_max_bytes = 400},
    };
    auto m = canon_merge_daily(std::move(rows));
    REQUIRE(m.size() == 1);
    CHECK(m[0].version == "1.2.3.0");
    CHECK(m[0].samples == 40);
    CHECK(std::abs(m[0].cpu_avg - 30.0) < 1e-9);
    CHECK(std::abs(m[0].cpu_max - 95.0) < 1e-9);
    CHECK(m[0].instances_max == 5);
    CHECK(m[0].ws_avg_bytes == 250);
    CHECK(m[0].ws_max_bytes == 400);
}

TEST_CASE("canon_merge_daily clamps cpu>100% and ws>1PiB (UP-1 per-row defense)",
          "[app_perf][merge]") {
    constexpr std::int64_t kPiB = std::int64_t{1} << 50; // the ws ceiling
    std::vector<AppPerfDailyRow> rows = {
        {.app_name = "x", .version = "1.0", .day = 86400, .samples = 1, .instances_max = 1,
         .cpu_avg = 1.0e9, .cpu_max = 1.0e9,
         .ws_avg_bytes = 9223372036854775807LL, .ws_max_bytes = 9223372036854775807LL}};
    auto m = canon_merge_daily(std::move(rows));
    REQUIRE(m.size() == 1);
    CHECK(m[0].cpu_avg == 100.0); // share-of-capacity percent ceiling
    CHECK(m[0].cpu_max == 100.0);
    CHECK(m[0].ws_avg_bytes == kPiB); // 1 PiB — keeps the rollup SUM(ws) from overflowing
    CHECK(m[0].ws_max_bytes == kPiB);
}

TEST_CASE("AppPerfDailyStore apply + read", "[pg][app_perf]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AppPerfDailyStore store{pool};
    REQUIRE(store.is_open());
    const std::int64_t day = today_utc() - 86400; // a completed day, within retention

    SECTION("stores rows read back app-ordered; unknown/empty agent = empty value not nullopt") {
        std::vector<AppPerfDailyRow> rows = {
            {.app_name = "chrome.exe", .version = "119.0.0.0", .day = day, .samples = 100,
             .instances_max = 8, .cpu_avg = 15.0, .cpu_max = 60.0, .ws_avg_bytes = 1000,
             .ws_max_bytes = 2000},
            {.app_name = "code.exe", .version = "1.85.0.0", .day = day, .samples = 50,
             .instances_max = 2, .cpu_avg = 5.0, .cpu_max = 20.0, .ws_avg_bytes = 500,
             .ws_max_bytes = 900},
        };
        CHECK(store.apply_daily("agent-a", rows));
        auto got = store.get_agent_app_perf("agent-a");
        REQUIRE(got.has_value());
        REQUIRE(got->size() == 2);
        CHECK((*got)[0].app_name == "chrome.exe"); // ORDER BY app_name
        CHECK((*got)[1].app_name == "code.exe");
        CHECK((*got)[0].samples == 100);
        CHECK(std::abs((*got)[0].cpu_avg - 15.0) < 1e-9);

        auto none = store.get_agent_app_perf("agent-unknown");
        REQUIRE(none.has_value()); // not a degrade — a genuine empty
        CHECK(none->empty());
        auto empty_id = store.get_agent_app_perf("");
        REQUIRE(empty_id.has_value());
        CHECK(empty_id->empty());
    }

    SECTION("re-apply same key overwrites (ON CONFLICT DO UPDATE)") {
        std::vector<AppPerfDailyRow> v1 = {
            {.app_name = "a", .version = "1.0.0.0", .day = day, .samples = 10, .instances_max = 1,
             .cpu_avg = 50.0, .cpu_max = 50.0, .ws_avg_bytes = 1, .ws_max_bytes = 1}};
        CHECK(store.apply_daily("agent-b", v1));
        std::vector<AppPerfDailyRow> v2 = {
            {.app_name = "a", .version = "1.0.0.0", .day = day, .samples = 99, .instances_max = 9,
             .cpu_avg = 9.0, .cpu_max = 9.0, .ws_avg_bytes = 9, .ws_max_bytes = 9}};
        CHECK(store.apply_daily("agent-b", v2));
        auto got = store.get_agent_app_perf("agent-b");
        REQUIRE(got.has_value());
        REQUIRE(got->size() == 1);
        CHECK((*got)[0].samples == 99); // latest wins
    }

    SECTION("canon-colliding rows store one merged row (no ON CONFLICT double-affect)") {
        std::vector<AppPerfDailyRow> rows = {
            {.app_name = "x", .version = "2.0", .day = day, .samples = 10, .instances_max = 1,
             .cpu_avg = 80.0, .cpu_max = 80.0, .ws_avg_bytes = 10, .ws_max_bytes = 10},
            {.app_name = "x", .version = "2.0.0.0", .day = day, .samples = 10, .instances_max = 1,
             .cpu_avg = 20.0, .cpu_max = 20.0, .ws_avg_bytes = 30, .ws_max_bytes = 30},
        };
        CHECK(store.apply_daily("agent-c", rows));
        auto got = store.get_agent_app_perf("agent-c");
        REQUIRE(got.has_value());
        REQUIRE(got->size() == 1);
        CHECK((*got)[0].version == "2.0.0.0");
        CHECK((*got)[0].samples == 20);
        CHECK(std::abs((*got)[0].cpu_avg - 50.0) < 1e-9); // (80*10 + 20*10)/20
    }

    SECTION("retention prunes rows older than 31 days on apply") {
        const std::int64_t old_day = today_utc() - 40 * 86400;
        std::vector<AppPerfDailyRow> rows = {
            {.app_name = "old", .version = "1.0.0.0", .day = old_day, .samples = 1,
             .instances_max = 1, .cpu_avg = 1.0, .cpu_max = 1.0, .ws_avg_bytes = 1, .ws_max_bytes = 1},
            {.app_name = "new", .version = "1.0.0.0", .day = day, .samples = 1, .instances_max = 1,
             .cpu_avg = 1.0, .cpu_max = 1.0, .ws_avg_bytes = 1, .ws_max_bytes = 1},
        };
        CHECK(store.apply_daily("agent-d", rows));
        auto got = store.get_agent_app_perf("agent-d");
        REQUIRE(got.has_value());
        REQUIRE(got->size() == 1);
        CHECK((*got)[0].app_name == "new"); // the 40-day-old row was pruned
    }

    SECTION("delete_agent removes all rows") {
        std::vector<AppPerfDailyRow> rows = {
            {.app_name = "a", .version = "1.0.0.0", .day = day, .samples = 1, .instances_max = 1,
             .cpu_avg = 1.0, .cpu_max = 1.0, .ws_avg_bytes = 1, .ws_max_bytes = 1}};
        CHECK(store.apply_daily("agent-e", rows));
        store.delete_agent("agent-e");
        auto got = store.get_agent_app_perf("agent-e");
        REQUIRE(got.has_value());
        CHECK(got->empty());
    }
}
