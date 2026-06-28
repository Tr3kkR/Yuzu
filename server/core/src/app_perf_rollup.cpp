#include "app_perf_rollup.hpp"

#include "app_perf_daily_store.hpp" // kRetentionDays (window bound static_assert)
#include "app_perf_hist.hpp"        // THE shared bucket scheme (writer + reader)
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include <yuzu/metrics.hpp>

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

// Thin forwarders to the shared scheme (app_perf_hist.hpp) — the writer and the
// reader (dex_app_perf_model) interpret ONE definition. Kept public so the
// rollup tests can reference AppPerfRollup::cpu_buckets()/kHistVersion unchanged.
const std::vector<double>& AppPerfRollup::cpu_buckets() { return app_perf_cpu_buckets(); }

const std::vector<std::int64_t>& AppPerfRollup::ws_buckets() { return app_perf_ws_buckets(); }

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
        // Saturate the working-set SUM at INT64_MAX before the ::bigint cast: even with
        // the per-row clamp, an extreme fleet-day could overflow bigint and abort the
        // WHOLE day's roll-up (UP-1). LEAST keeps the statement COMMAND_OK; a saturated
        // (wrong-but-bounded) sum under attack beats a permanent B2 gap.
        "       LEAST(SUM(ws_avg_bytes), 9223372036854775807)::bigint, MAX(ws_avg_bytes), " +
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
    const auto t0 = std::chrono::steady_clock::now();
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
    // Liveness/health of the SOLE writer of the 180-day B2 trend store: without
    // this a stuck/failing rollup thread leaves B2 silently stale (sre BLOCKING).
    // A stale `yuzu_app_perf_rollup_last_success_timestamp` is the alertable signal.
    if (metrics_ != nullptr) {
        const double secs =
            std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
        metrics_->counter("yuzu_app_perf_rollup_total", {{"outcome", ok ? "success" : "fail"}})
            .increment();
        metrics_
            ->histogram("yuzu_app_perf_rollup_duration_seconds", {},
                        yuzu::Histogram::seconds_buckets_60s())
            .observe(secs);
        if (ok)
            metrics_->gauge("yuzu_app_perf_rollup_last_success_timestamp", {})
                .set(static_cast<double>(now));
    }
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
