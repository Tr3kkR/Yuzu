/**
 * tar_aggregator.cpp -- Rollup aggregation and retention engine
 *
 * Rollup chain: Live -> Hourly -> Daily -> Monthly
 * Each tier aggregates from the tier directly below it.
 * Rollup marks (last-processed timestamp) stored in tar_config.
 */

#include "tar_aggregator.hpp"
#include "tar_schema_registry.hpp"

#include <spdlog/spdlog.h>

#include <chrono>
#include <format>
#include <string>

namespace yuzu::tar {

namespace {

// Boundary computation helpers
int64_t hour_boundary(int64_t epoch)  { return (epoch / 3600) * 3600; }
int64_t day_boundary(int64_t epoch)   { return (epoch / 86400) * 86400; }

// M2: Use calendar-month boundary via gmtime instead of fixed 30-day approximation
int64_t month_boundary(int64_t epoch) {
    time_t t = static_cast<time_t>(epoch);
    struct tm tm_val{};
    gmtime_r(&t, &tm_val);
    tm_val.tm_mday = 1;
    tm_val.tm_hour = 0;
    tm_val.tm_min = 0;
    tm_val.tm_sec = 0;
    return static_cast<int64_t>(timegm(&tm_val));
}

// Maximum expected interval between rollup marks (H11: clock skew protection)
constexpr int64_t kMaxHourlyGap = 7200;     // 2 hours
constexpr int64_t kMaxDailyGap = 172800;    // 2 days
constexpr int64_t kMaxMonthlyGap = 5400000; // ~62 days

// Rollup one tier for one source.
// Returns true if any data was rolled up.
bool rollup_tier(TarDatabase& db, std::string_view source_name,
                 std::string_view target_suffix, int64_t now_epoch) {

    auto sql = rollup_sql(source_name, target_suffix);
    if (sql.empty())
        return false;

    int64_t boundary;
    int64_t max_gap;
    if (target_suffix == "hourly")       { boundary = hour_boundary(now_epoch);  max_gap = kMaxHourlyGap; }
    else if (target_suffix == "daily")   { boundary = day_boundary(now_epoch);   max_gap = kMaxDailyGap; }
    else if (target_suffix == "monthly") { boundary = month_boundary(now_epoch); max_gap = kMaxMonthlyGap; }
    else return false;

    auto mark_key = std::format("rollup_{}_{}_at", source_name, target_suffix);
    auto mark_str = db.get_config(mark_key, "0");
    int64_t last_mark = 0;
    try { last_mark = std::stoll(mark_str); } catch (...) {}

    if (last_mark >= boundary)
        return false;

    // H11: Clock skew protection — if the gap is abnormally large, clamp it
    if (boundary - last_mark > max_gap && last_mark > 0) {
        spdlog::warn("TAR rollup: {}_{} gap {}s exceeds max {}s, possible clock jump — clamping",
                      source_name, target_suffix, boundary - last_mark, max_gap);
        last_mark = boundary - max_gap;
    }

    bool ok = db.execute_sql_range(sql, last_mark, boundary);
    if (ok) {
        db.set_config(mark_key, std::to_string(boundary));
        spdlog::debug("TAR rollup: {}_{} processed [{}, {})", source_name, target_suffix,
                       last_mark, boundary);
    }

    return ok;
}

} // namespace

int run_aggregation(TarDatabase& db, int64_t now_epoch) {
    int ops = 0;

    struct RollupStep { std::string_view source; std::string_view target; };
    static const RollupStep steps[] = {
        {"process", "hourly"},
        {"process", "daily"},
        {"process", "monthly"},
        {"tcp", "hourly"},
        {"tcp", "daily"},
        {"tcp", "monthly"},
        {"service", "hourly"},
        {"user", "daily"},
    };

    for (const auto& step : steps) {
        if (rollup_tier(db, step.source, step.target, now_epoch))
            ++ops;
    }

    return ops;
}

void run_retention(TarDatabase& db, int64_t now_epoch) {
    // M17: Wrap all retention deletes in a single transaction to amortize fsync cost
    db.execute_sql("BEGIN TRANSACTION");

    for (const auto& src : capture_sources()) {
        for (const auto& g : src.granularities) {
            auto table_name = std::format("{}_{}", src.name, g.suffix);
            auto sql = retention_sql(table_name, now_epoch);
            if (!sql.empty()) {
                db.execute_sql(sql);
            }
        }
    }

    db.execute_sql("COMMIT");
}

} // namespace yuzu::tar
