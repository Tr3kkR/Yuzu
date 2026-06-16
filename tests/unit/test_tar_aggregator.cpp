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

// ── PR-A (#547): apply_source_enabled_transition + paused_at semantics ─────

TEST_CASE("TAR paused_at: enabled→disabled writes the timestamp",
          "[tar][paused_at][pr-a]") {
    // Operator transitions process_enabled from default ("true") to "false"
    // — paused_at must record the wall-clock now passed to the helper.
    yuzu::test::TempDbFile tmp{std::string_view{"tar-pra-disable-"}};
    auto opened = TarDatabase::open(tmp.path);
    REQUIRE(opened.has_value());
    TarDatabase db = std::move(*opened);
    REQUIRE(db.create_warehouse_tables());

    REQUIRE(db.get_config("process_enabled", "true") == "true");
    REQUIRE(db.get_config("process_paused_at", "0") == "0");

    const int64_t t_now = 1'735'689'600;
    apply_source_enabled_transition(db, "process", "false", t_now);

    CHECK(db.get_config("process_enabled", "true") == "false");
    CHECK(db.get_config("process_paused_at", "0") ==
          std::to_string(t_now));
}

TEST_CASE("TAR paused_at: disabled→enabled clears the timestamp to \"0\"",
          "[tar][paused_at][pr-a]") {
    // After re-enable, paused_at must read "0" (not absent — operators
    // distinguish "never paused" from "no key present"). The reverse
    // transition is the operator-journey close-out: freeze → export →
    // re-enable; the row drops out of the dashboard's retention-paused list.
    yuzu::test::TempDbFile tmp{std::string_view{"tar-pra-reenable-"}};
    auto opened = TarDatabase::open(tmp.path);
    REQUIRE(opened.has_value());
    TarDatabase db = std::move(*opened);
    REQUIRE(db.create_warehouse_tables());

    apply_source_enabled_transition(db, "tcp", "false", 1'735'689'600);
    REQUIRE(db.get_config("tcp_paused_at", "0") == "1735689600");

    apply_source_enabled_transition(db, "tcp", "true", 1'735'700'000);

    CHECK(db.get_config("tcp_enabled", "true") == "true");
    CHECK(db.get_config("tcp_paused_at", "0") == "0");
}

TEST_CASE("TAR paused_at: idempotent re-set leaves the timestamp untouched",
          "[tar][paused_at][pr-a]") {
    // If the operator submits configure with the same value the source
    // already holds, paused_at must NOT advance — otherwise repeated
    // configure round-trips would pretend the pause is fresher than it is,
    // misleading the retention-paused list's "paused since" column.
    yuzu::test::TempDbFile tmp{std::string_view{"tar-pra-idem-"}};
    auto opened = TarDatabase::open(tmp.path);
    REQUIRE(opened.has_value());
    TarDatabase db = std::move(*opened);
    REQUIRE(db.create_warehouse_tables());

    apply_source_enabled_transition(db, "service", "false", 1'735'689'600);
    REQUIRE(db.get_config("service_paused_at", "0") == "1735689600");

    apply_source_enabled_transition(db, "service", "false", 1'735'700'000);

    CHECK(db.get_config("service_paused_at", "0") == "1735689600");
}

TEST_CASE("TAR paused_at: per-source isolation",
          "[tar][paused_at][pr-a]") {
    // Disabling process must not touch tcp / service / user paused_at — the
    // PR-A retention-paused list relies on per-source rows being independent.
    yuzu::test::TempDbFile tmp{std::string_view{"tar-pra-iso-"}};
    auto opened = TarDatabase::open(tmp.path);
    REQUIRE(opened.has_value());
    TarDatabase db = std::move(*opened);
    REQUIRE(db.create_warehouse_tables());

    apply_source_enabled_transition(db, "process", "false", 1'735'689'600);

    CHECK(db.get_config("process_paused_at", "0") == "1735689600");
    CHECK(db.get_config("tcp_paused_at", "0") == "0");
    CHECK(db.get_config("service_paused_at", "0") == "0");
    CHECK(db.get_config("user_paused_at", "0") == "0");
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

// ── #541: configure-time pattern validation ────────────────────────────────

TEST_CASE("TAR validate_config_pattern enforces the length cap", "[tar][configure][issue541]") {
    const std::string ok(yuzu::tar::kMaxPatternLength, 'a');
    const std::string too_long(yuzu::tar::kMaxPatternLength + 1, 'a');
    CHECK_FALSE(yuzu::tar::validate_config_pattern(ok, /*require_min_core_len=*/false).has_value());
    CHECK(yuzu::tar::validate_config_pattern(too_long, false).has_value());
    CHECK(yuzu::tar::validate_config_pattern(too_long, true).has_value());
}

TEST_CASE("TAR validate_config_pattern enforces the min core length on the STRIPPED core",
          "[tar][configure][issue541]") {
    // require_min_core_len=true (process_stabilization_exclusions): the floor is
    // measured on the EFFECTIVE substring after stripping leading/trailing '*'.
    CHECK(yuzu::tar::validate_config_pattern("a", true).has_value());
    CHECK(yuzu::tar::validate_config_pattern("ab", true).has_value());
    CHECK_FALSE(yuzu::tar::validate_config_pattern("abc", true).has_value());
    // `*` does NOT bypass the floor — "*a*" strips to core "a" and would still
    // match almost every process (gov UP-2 / security MEDIUM-1).
    CHECK(yuzu::tar::validate_config_pattern("*a*", true).has_value());
    CHECK(yuzu::tar::validate_config_pattern("a*", true).has_value());
    CHECK(yuzu::tar::validate_config_pattern("*", true).has_value());   // core empty
    CHECK(yuzu::tar::validate_config_pattern("**", true).has_value());  // core empty
    // A long-enough core with wildcards is fine.
    CHECK_FALSE(yuzu::tar::validate_config_pattern("*abc*", true).has_value());
    CHECK_FALSE(yuzu::tar::validate_config_pattern("chrome-helper", true).has_value());

    // require_min_core_len=false (redaction_patterns): short patterns allowed —
    // a short redaction substring over-redacts, it does not silently drop events.
    CHECK_FALSE(yuzu::tar::validate_config_pattern("a", false).has_value());
    CHECK_FALSE(yuzu::tar::validate_config_pattern("*a*", false).has_value());
}

TEST_CASE("TAR parse_pattern_config clamps + sanitises at load (#541 UP-1)",
          "[tar][configure][issue541]") {
    using yuzu::tar::parse_pattern_config;

    // A non-array stored value → nullopt (caller falls back to its default).
    CHECK_FALSE(parse_pattern_config("not json").has_value());
    CHECK_FALSE(parse_pattern_config("\"a string\"").has_value());
    CHECK_FALSE(parse_pattern_config("{\"k\":1}").has_value());

    // Valid empty array → empty vector (explicit "no patterns", not the default).
    auto empty = parse_pattern_config("[]");
    REQUIRE(empty.has_value());
    CHECK(empty->empty());

    // Non-string / empty / over-long elements are dropped; valid ones kept.
    std::string over_long(yuzu::tar::kMaxPatternLength + 1, 'x');
    auto mixed = parse_pattern_config(
        std::format("[123, \"keep1\", \"\", \"{}\", true, \"keep2\"]", over_long));
    REQUIRE(mixed.has_value());
    REQUIRE(mixed->size() == 2);
    CHECK((*mixed)[0] == "keep1");
    CHECK((*mixed)[1] == "keep2");

    // Element-count cap: an array of 300 valid strings truncates to the cap.
    std::string big = "[";
    for (int i = 0; i < 300; ++i)
        big += (i ? ",\"pat" : "\"pat") + std::to_string(i) + "\"";
    big += "]";
    auto clamped = parse_pattern_config(big);
    REQUIRE(clamped.has_value());
    CHECK(clamped->size() == yuzu::tar::kMaxPatternArrayElements);
}
