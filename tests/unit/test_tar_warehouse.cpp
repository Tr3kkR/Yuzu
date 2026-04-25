// test_tar_warehouse.cpp -- Issue #60 coverage gaps:
//
//  * every source/table combination is in the DDL,
//  * live-to-aggregate rollup SQL exists for every documented pair,
//  * retention independence across granularities (row-count vs time-based),
//  * restart double-capture caveat for TCP (documented behavior — no diff
//    is possible against an empty `previous` snapshot, so all current
//    connections appear as `connected`),
//  * midnight rollover and carry-over for User_Daily,
//  * schema validation: `columns_for_table` agrees with the GranularityDef
//    column list plus the implicit `id` PK.
//
// These are deliberately store-agnostic tests over the schema-registry API
// so they keep firing as new sources land.

#include "tar_collectors.hpp"
#include "tar_db.hpp"
#include "tar_schema_registry.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <set>
#include <string>
#include <vector>

using namespace yuzu::tar;

// ── DDL coverage ───────────────────────────────────────────────────────────

TEST_CASE("TAR warehouse DDL: every source/granularity has CREATE TABLE",
          "[tar][warehouse][issue60]") {
    auto ddl = generate_warehouse_ddl();
    REQUIRE_FALSE(ddl.empty());

    for (const auto& src : capture_sources()) {
        for (const auto& g : src.granularities) {
            std::string table = std::string{src.name} + "_" + std::string{g.suffix};
            std::string create = "CREATE TABLE IF NOT EXISTS " + table;
            INFO("expected DDL: " << create);
            CHECK(ddl.find(create) != std::string::npos);
        }
    }
}

TEST_CASE("TAR warehouse DDL: every source/granularity has a timestamp index",
          "[tar][warehouse][issue60]") {
    auto ddl = generate_warehouse_ddl();
    for (const auto& src : capture_sources()) {
        for (const auto& g : src.granularities) {
            std::string table = std::string{src.name} + "_" + std::string{g.suffix};
            std::string idx_prefix = "CREATE INDEX IF NOT EXISTS idx_" + table + "_";
            INFO("expected index prefix: " << idx_prefix);
            CHECK(ddl.find(idx_prefix) != std::string::npos);
        }
    }
}

// ── Schema validation ──────────────────────────────────────────────────────

TEST_CASE("TAR warehouse: columns_for_table includes id + every defined column",
          "[tar][warehouse][issue60]") {
    for (const auto& src : capture_sources()) {
        for (const auto& g : src.granularities) {
            std::string table = std::string{src.name} + "_" + std::string{g.suffix};
            auto cols = columns_for_table(table);
            REQUIRE_FALSE(cols.empty());

            // Implicit id PK is always first.
            CHECK(cols.front() == "id");

            // Every declared column must appear (id + N declared = cols.size).
            CHECK(cols.size() == g.columns.size() + 1);
            for (const auto& declared : g.columns) {
                INFO("table=" << table << " expected col=" << declared.name);
                CHECK(std::find(cols.begin(), cols.end(),
                                std::string{declared.name}) != cols.end());
            }
        }
    }
}

TEST_CASE("TAR warehouse: columns_for_table returns empty for unknown table",
          "[tar][warehouse][issue60]") {
    CHECK(columns_for_table("does_not_exist").empty());
}

// ── Dollar-name round trip ─────────────────────────────────────────────────

TEST_CASE("TAR warehouse: every dollar name translates back to a real table",
          "[tar][warehouse][issue60]") {
    auto names = all_dollar_names();
    REQUIRE_FALSE(names.empty());
    std::set<std::string> seen;
    for (const auto& dn : names) {
        auto translated = translate_dollar_name(dn);
        INFO("dollar name: " << dn);
        REQUIRE(translated.has_value());
        CHECK(!translated->empty());
        CHECK(seen.insert(*translated).second);  // every dollar name is unique
    }
}

TEST_CASE("TAR warehouse: unknown dollar name returns nullopt",
          "[tar][warehouse][issue60]") {
    CHECK_FALSE(translate_dollar_name("$Made_Up").has_value());
    CHECK_FALSE(translate_dollar_name("not a dollar name").has_value());
}

// ── Rollup SQL coverage ────────────────────────────────────────────────────

TEST_CASE("TAR warehouse rollups: process live -> hourly -> daily -> monthly",
          "[tar][warehouse][rollup][issue60]") {
    CHECK_FALSE(rollup_sql("process", "hourly").empty());
    CHECK_FALSE(rollup_sql("process", "daily").empty());
    CHECK_FALSE(rollup_sql("process", "monthly").empty());

    // Each rollup must cite the lower tier as its FROM and the upper tier
    // as its INSERT INTO target — otherwise we'd be aggregating from the
    // wrong place or writing to the wrong granularity.
    CHECK(rollup_sql("process", "hourly").find("FROM process_live") != std::string::npos);
    CHECK(rollup_sql("process", "daily").find("FROM process_hourly") != std::string::npos);
    CHECK(rollup_sql("process", "monthly").find("FROM process_daily") != std::string::npos);

    CHECK(rollup_sql("process", "hourly").find("INSERT INTO process_hourly") != std::string::npos);
    CHECK(rollup_sql("process", "daily").find("INSERT INTO process_daily") != std::string::npos);
    CHECK(rollup_sql("process", "monthly").find("INSERT INTO process_monthly") != std::string::npos);
}

TEST_CASE("TAR warehouse rollups: tcp live -> hourly -> daily -> monthly",
          "[tar][warehouse][rollup][issue60]") {
    CHECK(rollup_sql("tcp", "hourly").find("FROM tcp_live") != std::string::npos);
    CHECK(rollup_sql("tcp", "daily").find("FROM tcp_hourly") != std::string::npos);
    CHECK(rollup_sql("tcp", "monthly").find("FROM tcp_daily") != std::string::npos);
}

TEST_CASE("TAR warehouse rollups: service hourly only",
          "[tar][warehouse][rollup][issue60]") {
    CHECK_FALSE(rollup_sql("service", "hourly").empty());
    // Service does not roll up beyond hourly; daily/monthly should be empty.
    CHECK(rollup_sql("service", "daily").empty());
    CHECK(rollup_sql("service", "monthly").empty());
}

TEST_CASE("TAR warehouse rollups: user live -> daily (midnight rollover)",
          "[tar][warehouse][rollup][issue60]") {
    auto sql = rollup_sql("user", "daily");
    REQUIRE_FALSE(sql.empty());
    CHECK(sql.find("FROM user_live") != std::string::npos);
    CHECK(sql.find("INSERT INTO user_daily") != std::string::npos);

    // Midnight rollover correctness: the day boundary is `(ts / 86400) *
    // 86400`, which buckets all events on the same UTC day together.
    // Carry-over (login on day N still active on day N+1) yields a login
    // event on day N and no logout — the user appears in user_daily once,
    // with login_count=1 and logout_count=0. This is intentional: TAR
    // records *events*, not session durations.
    CHECK(sql.find("(ts / 86400) * 86400") != std::string::npos);
    CHECK(sql.find("login_count") != std::string::npos);
    CHECK(sql.find("logout_count") != std::string::npos);
}

TEST_CASE("TAR warehouse rollups: unknown source returns empty",
          "[tar][warehouse][rollup][issue60]") {
    CHECK(rollup_sql("nope", "hourly").empty());
    CHECK(rollup_sql("process", "yearly").empty());  // unsupported tier
}

// ── Retention independence across granularities ────────────────────────────

TEST_CASE("TAR warehouse retention: row-count tier uses OFFSET delete pattern",
          "[tar][warehouse][retention][issue60]") {
    // All `live` tiers are kRowCount in the current registry. Verify the
    // SQL uses the OFFSET-boundary pattern (H6) rather than NOT IN, which
    // is O(n*k) and broke under load.
    for (const auto& src : capture_sources()) {
        std::string table = std::string{src.name} + "_live";
        auto sql = retention_sql(table, /*now_epoch=*/1'700'000'000);
        INFO("table=" << table);
        REQUIRE_FALSE(sql.empty());
        CHECK(sql.find("OFFSET") != std::string::npos);
        CHECK(sql.find("DELETE FROM " + table) != std::string::npos);
    }
}

TEST_CASE("TAR warehouse retention: time-based tier uses ts cutoff",
          "[tar][warehouse][retention][issue60]") {
    // All non-live tiers are kTimeBased. Each must produce a DELETE with
    // a `< <cutoff>` predicate against the granularity's timestamp column.
    for (const auto& src : capture_sources()) {
        for (const auto& g : src.granularities) {
            if (g.suffix == "live") continue;
            std::string table = std::string{src.name} + "_" + std::string{g.suffix};
            auto sql = retention_sql(table, /*now_epoch=*/1'700'000'000);
            INFO("table=" << table);
            REQUIRE_FALSE(sql.empty());
            CHECK(sql.find("DELETE FROM " + table) != std::string::npos);
            CHECK(sql.find("<") != std::string::npos);
        }
    }
}

TEST_CASE("TAR warehouse retention: each granularity retains independently",
          "[tar][warehouse][retention][issue60]") {
    // Independence invariant: deleting from a daily table must not touch
    // the hourly table for the same source, and vice versa. The SQL is
    // single-table, so this is true by construction — but the test pins
    // the contract so a future "join cleanup" refactor cannot accidentally
    // couple them.
    for (const auto& src : capture_sources()) {
        for (const auto& g : src.granularities) {
            std::string table = std::string{src.name} + "_" + std::string{g.suffix};
            auto sql = retention_sql(table, /*now_epoch=*/1'700'000'000);
            REQUIRE_FALSE(sql.empty());
            // For every OTHER granularity in the same source, the SQL must
            // not name that table.
            for (const auto& other : src.granularities) {
                if (other.suffix == g.suffix) continue;
                std::string other_table = std::string{src.name} + "_" + std::string{other.suffix};
                INFO("retention sql for " << table << " must not mention " << other_table);
                CHECK(sql.find(other_table) == std::string::npos);
            }
        }
    }
}

// ── TCP restart / double-capture caveat ─────────────────────────────────────

TEST_CASE("TAR diff: TCP post-restart with empty previous yields all-connected",
          "[tar][diff][network][restart][issue60]") {
    // Documented caveat: after the agent restarts, the saved `network`
    // state in tar_state is empty (or stale). The first collect_fast
    // cycle compares an empty `previous` to a populated `current`, so
    // every currently-open connection emits a `connected` event. This
    // looks like a flood of "new" connections but is the correct
    // behavior — TAR has no way to know which were already open.
    //
    // This test pins the behavior so a future refactor that tries to
    // suppress the post-restart "flood" doesn't silently break the
    // forensic timeline.
    std::vector<NetConnection> previous;  // post-restart: empty
    std::vector<NetConnection> current = {
        {.proto = "tcp", .local_addr = "192.168.1.10", .remote_addr = "10.0.0.5",
         .remote_host = "", .local_port = 22, .remote_port = 50001,
         .state = "ESTABLISHED", .pid = 1234, .process_name = "sshd"},
        {.proto = "tcp", .local_addr = "192.168.1.10", .remote_addr = "10.0.0.6",
         .remote_host = "", .local_port = 443, .remote_port = 51022,
         .state = "ESTABLISHED", .pid = 5678, .process_name = "nginx"},
    };

    auto events = compute_network_diff(previous, current,
                                        /*timestamp=*/1'700'000'000,
                                        /*snapshot_id=*/1);

    REQUIRE(events.size() == 2);
    for (const auto& e : events) {
        CHECK(e.event_action == "connected");
    }
}
