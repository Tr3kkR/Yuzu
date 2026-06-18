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
#include <ctime>
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
#ifdef _WIN32
    gmtime_s(&tm_val, &t);
#else
    gmtime_r(&t, &tm_val);
#endif
    tm_val.tm_mday = 1;
    tm_val.tm_hour = 0;
    tm_val.tm_min = 0;
    tm_val.tm_sec = 0;
#ifdef _WIN32
    return static_cast<int64_t>(_mkgmtime(&tm_val));
#else
    return static_cast<int64_t>(timegm(&tm_val));
#endif
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
        {"perf", "hourly"},
        {"procperf", "hourly"},
    };

    for (const auto& step : steps) {
        if (rollup_tier(db, step.source, step.target, now_epoch))
            ++ops;
    }

    return ops;
}

bool apply_source_enabled_transition(TarDatabase& db,
                                      std::string_view source,
                                      std::string_view new_value,
                                      int64_t now_epoch) {
    auto enabled_key = std::format("{}_enabled", source);
    std::string prev = db.get_config(enabled_key, "true");
    auto paused_at_key = std::format("{}_paused_at", source);

    if (new_value == "false" && prev != "false") {
        // Enable→disable. #538/UP-1: clear the diff baseline FIRST and flip the
        // `_enabled` flag only if the clear actually persisted. `set_state` can
        // fail silently (SQLITE_BUSY / disk full); if we flipped the flag first
        // and the clear then failed, we'd have a DISABLED source with a STALE
        // baseline — and a later re-enable would emit exactly the ghost "stopped"
        // events this fix exists to prevent, while the operator saw success.
        // Clearing first makes the disable fail-safe: a failed clear leaves the
        // source ENABLED (its baseline still valid, collection continues) and we
        // report failure so the operator can retry. No-op for sources without a
        // snapshot-diff baseline (perf/procperf/netqual). The caller serialises
        // this whole call against the collectors via collect_mu_ (see do_configure).
        if (auto key = diff_state_key(source); !key.empty()) {
            if (!db.set_state(std::string{key}, ""))
                return false; // baseline NOT cleared → do not disable
        }
        db.set_config(enabled_key, std::string{new_value});
        db.set_config(paused_at_key, std::to_string(now_epoch));
        return true;
    }

    // All other transitions (idempotent set, disable→enable, first-ever set):
    // no baseline clear, so the flag write cannot leave inconsistent state.
    db.set_config(enabled_key, std::string{new_value});
    if (new_value == "true" && prev == "false") {
        db.set_config(paused_at_key, "0");
    }
    return true;
}

std::string_view diff_state_key(std::string_view source) {
    // Mapping is NOT 1:1 with the source name: tcp's baseline lives under
    // "network" (historical). Keep this the ONE home for the mapping — the
    // collectors (collect_fast/slow) and apply_source_enabled_transition both
    // route through here so the on-disable clear can never target the wrong key.
    if (source == "process") return "process";
    if (source == "tcp")     return "network";
    if (source == "service") return "service";
    if (source == "user")    return "user";
    // perf/procperf keep an in-memory previous reading; netqual is stateless.
    return {};
}

void run_retention(TarDatabase& db, int64_t now_epoch) {
    // M17: Wrap all retention deletes in a single transaction to amortize fsync cost
    db.execute_sql("BEGIN TRANSACTION");

    for (const auto& src : capture_sources()) {
        // #539: Skip retention for disabled sources. The configure docstring and
        // user-manual promise that disabling a collector "leaves existing rows
        // queryable." Without this guard, time-based retention drains hourly
        // within 24h, daily within 31d, monthly within ~365d after disable —
        // breaking the forensic-preservation use case. See issue #539.
        auto enabled_key = std::format("{}_enabled", src.name);
        if (db.get_config(enabled_key, "true") == "false")
            continue;
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
