#include "app_perf_rollup.hpp"

#include "app_perf_daily_store.hpp" // kRetentionDays (window bound static_assert)
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include <libpq-fe.h>
#include <spdlog/spdlog.h>

#include <chrono>
#include <cstdint>
#include <format>
#include <string>
#include <vector>

namespace yuzu::server {

// The re-roll window must never reach into days B1 has already pruned, or B2 would
// silently undercount (advisor guardrail).
static_assert(AppPerfRollup::kTrailingDays < AppPerfDailyStore::kRetentionDays,
              "app_perf re-roll window must stay strictly inside B1's retention");

namespace {

constexpr std::chrono::milliseconds kRollAcquireTimeout{5000};

// Generous, EXPLICIT bound for the per-day FILTER-aggregate (a background batch
// job, off the hot path; the (day, app_name, version) index keeps it fast, but it
// must never run unbounded). Above the pool's 30s default on purpose — a full
// fleet-day aggregate is allowed more room than a request.
constexpr const char* kRollStatementTimeout = "120s";

std::int64_t now_secs() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

template <typename T> std::vector<std::string> fmt_literals(const std::vector<T>& v) {
    std::vector<std::string> out;
    out.reserve(v.size());
    for (const T& x : v)
        out.push_back(std::format("{}", x)); // locale-independent numeric literal
    return out;
}

} // namespace

const std::vector<double>& AppPerfRollup::cpu_buckets() {
    // share-of-capacity %, low-end weighted (11 boundaries → 12 buckets).
    static const std::vector<double> kCpu = {0.5, 1, 2, 3, 5, 8, 12, 20, 30, 50, 75};
    return kCpu;
}

const std::vector<std::int64_t>& AppPerfRollup::ws_buckets() {
    // working-set bytes, log-scale 32 MiB … 8 GiB (9 boundaries → 10 buckets).
    static const std::vector<std::int64_t> kWs = {
        33554432,   67108864,   134217728,  268435456, 536870912,
        1073741824, 2147483648, 4294967296, 8589934592};
    return kWs;
}

std::string AppPerfRollup::build_hist_array_sql(const std::string& column,
                                                const std::vector<std::string>& b) {
    if (b.empty())
        return "ARRAY[COUNT(*)]::bigint[]"; // degenerate: one catch-all bucket
    std::string s = "ARRAY[";
    const std::size_t n = b.size();
    for (std::size_t k = 0; k <= n; ++k) { // N boundaries → N+1 half-open buckets
        if (k != 0)
            s += ", ";
        s += "COUNT(*) FILTER (WHERE ";
        if (k == 0)
            s += column + " < " + b[0];
        else if (k == n)
            s += column + " >= " + b[n - 1];
        else
            s += column + " >= " + b[k - 1] + " AND " + column + " < " + b[k];
        s += ")";
    }
    s += "]::bigint[]";
    return s;
}

AppPerfRollup::AppPerfRollup(pg::PgPool& pool) : pool_(pool) {
    const std::string cpu_hist = build_hist_array_sql("cpu_avg", fmt_literals(cpu_buckets()));
    const std::string ws_hist = build_hist_array_sql("ws_avg_bytes", fmt_literals(ws_buckets()));
    // $1 = day_start (UTC midnight epoch), $2 = updated_at (server now). Bucket
    // arrays + hist_version are baked-in code constants (never user input).
    // cpu_max/ws_max are the fleet max of the per-device daily AVERAGES (same metric
    // the histograms bucket), not the per-device intraday peak (a B1 drill detail).
    roll_sql_ =
        "INSERT INTO app_perf_fleet_store.app_perf_fleet "
        "(app_name, version, day, device_count, cpu_sum, cpu_max, ws_sum, ws_max, "
        " cpu_hist, ws_hist, hist_version, updated_at) "
        "SELECT app_name, version, day, COUNT(*), SUM(cpu_avg), MAX(cpu_avg), "
        "       SUM(ws_avg_bytes)::bigint, MAX(ws_avg_bytes), " +
        cpu_hist + ", " + ws_hist + ", " + std::to_string(kHistVersion) +
        ", $2::bigint "
        "FROM app_perf_daily_store.app_perf_daily WHERE day = $1::bigint "
        "GROUP BY app_name, version, day "
        "ON CONFLICT (app_name, version, day) DO UPDATE SET "
        "  device_count = EXCLUDED.device_count, cpu_sum = EXCLUDED.cpu_sum, "
        "  cpu_max = EXCLUDED.cpu_max, ws_sum = EXCLUDED.ws_sum, ws_max = EXCLUDED.ws_max, "
        "  cpu_hist = EXCLUDED.cpu_hist, ws_hist = EXCLUDED.ws_hist, "
        "  hist_version = EXCLUDED.hist_version, updated_at = EXCLUDED.updated_at";
}

bool AppPerfRollup::roll_day(std::int64_t day_start) {
    if (day_start <= 0)
        return false;
    const std::int64_t now = now_secs();
    const bool ok = pool_.with_txn_for(kRollAcquireTimeout, [&](PGconn* c) -> bool {
        pg::PgResult t = pg::exec_params(
            c, std::string("SET LOCAL statement_timeout = '").append(kRollStatementTimeout).append("'").c_str(),
            std::vector<std::string>{});
        if (t.status() != PGRES_COMMAND_OK)
            return false;
        pg::PgResult r = pg::exec_params(
            c, roll_sql_.c_str(),
            std::vector<std::string>{std::to_string(day_start), std::to_string(now)});
        return r.status() == PGRES_COMMAND_OK; // INSERT … SELECT → COMMAND_OK
    });
    if (!ok)
        spdlog::warn("AppPerfRollup: roll_day failed for day={}", day_start);
    return ok;
}

int AppPerfRollup::roll_window(std::int64_t now_secs_in) {
    const std::int64_t today = (now_secs_in / 86400) * 86400;
    int rolled = 0;
    for (int i = 1; i <= kTrailingDays; ++i) // completed days only (today excluded)
        if (roll_day(today - static_cast<std::int64_t>(i) * 86400))
            ++rolled;
    return rolled;
}

} // namespace yuzu::server
