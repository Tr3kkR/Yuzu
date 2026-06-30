#include "app_perf_group_reader.hpp"

#include "app_perf_fleet_store.hpp" // AppPerfFleetRow
#include "app_perf_hist.hpp"        // buckets + kAppPerfHistVersion
#include "app_perf_rollup.hpp"      // build_hist_array_sql (shared bucket-predicate SQL)
#include "pg/pg_array.hpp"          // pg::to_text_array
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include <yuzu/metrics.hpp>
#include <yuzu/version_string.hpp> // canon_version — match the stored key

#include <libpq-fe.h>
#include <spdlog/spdlog.h>

#include <chrono>
#include <cstdlib>
#include <format>
#include <string>
#include <vector>

namespace yuzu::server {

namespace {

constexpr std::chrono::milliseconds kQueryAcquireTimeout{3000};
// A group's (versions × 31 days) aggregate is small; this is unbounded-growth
// defence, matching the B1/B2 read caps.
constexpr int kQueryRowCap = 100000;

std::int64_t to_i64(const char* s) {
    if (s == nullptr || s[0] == '\0')
        return 0;
    return static_cast<std::int64_t>(std::strtoll(s, nullptr, 10));
}

double to_double(const char* s) {
    if (s == nullptr || s[0] == '\0')
        return 0.0;
    return std::strtod(s, nullptr);
}

// Parse a PostgreSQL bigint[] text rendering ("{1,2,3}" / "{}") — numeric only.
std::vector<std::int64_t> parse_bigint_array(const char* s) {
    std::vector<std::int64_t> out;
    if (s == nullptr)
        return out;
    const char* p = s;
    while (*p != '\0' && *p != '{')
        ++p;
    if (*p == '{')
        ++p;
    while (*p != '\0' && *p != '}') {
        char* end = nullptr;
        const long long v = std::strtoll(p, &end, 10);
        if (end == p)
            break;
        out.push_back(static_cast<std::int64_t>(v));
        p = end;
        while (*p == ',' || *p == ' ')
            ++p;
    }
    return out;
}

template <typename T> std::vector<std::string> fmt_literals(const std::vector<T>& v) {
    std::vector<std::string> out;
    out.reserve(v.size());
    for (const T& x : v)
        out.push_back(std::format("{}", x)); // locale-independent numeric literal
    return out;
}

void note_degrade(yuzu::MetricsRegistry* metrics, const char* reason) {
    if (metrics)
        metrics->counter("yuzu_app_perf_group_read_degrade_total", {{"reason", reason}}).increment();
}

} // namespace

AppPerfGroupReader::AppPerfGroupReader(pg::PgPool& pool) : pool_(pool) {
    // Bucket arrays + hist_version are baked-in code constants (never user input),
    // built once — IDENTICAL scheme to AppPerfRollup so a group histogram and a B2
    // histogram are directly comparable. $1 = member agent_id[], $2 = app_name.
    const std::string cpu_hist =
        AppPerfRollup::build_hist_array_sql("cpu_avg", fmt_literals(app_perf_cpu_buckets()));
    const std::string ws_hist =
        AppPerfRollup::build_hist_array_sql("ws_avg_bytes", fmt_literals(app_perf_ws_buckets()));
    select_prefix_ =
        "SELECT $2::text AS app_name, version, day, COUNT(*), SUM(cpu_avg), MAX(cpu_avg), "
        // Saturating SUM, mirroring AppPerfRollup (sibling parity): a forged
        // near-INT64_MAX ws across a huge group would otherwise overflow the
        // ::bigint cast and degrade the whole group read to nullopt. cpu_sum is
        // DOUBLE (saturates to Inf, isfinite-guarded on read), so no LEAST there.
        "LEAST(SUM(ws_avg_bytes), 9223372036854775807)::bigint, MAX(ws_avg_bytes), " +
        cpu_hist + ", " + ws_hist + ", " + std::to_string(kAppPerfHistVersion) +
        " FROM app_perf_daily_store.app_perf_daily "
        "WHERE agent_id = ANY($1::text[]) AND app_name = $2";
}

std::optional<std::vector<AppPerfFleetRow>>
AppPerfGroupReader::get_group_trend(const std::vector<std::string>& agent_ids,
                                    std::string_view app_name, std::string_view version) {
    std::vector<AppPerfFleetRow> out;
    if (agent_ids.empty() || app_name.empty())
        return out; // precondition miss, not a degrade

    auto lease = pool_.try_acquire_for(kQueryAcquireTimeout);
    if (!lease) {
        note_degrade(metrics_, "pool_acquire_timeout");
        spdlog::warn("AppPerfGroupReader: get_group_trend degraded — no connection ({})",
                     pool_.last_error());
        return std::nullopt;
    }

    // Member list → a Postgres text[] literal for ANY() (one bound param, bounded
    // by the caller's group size). to_text_array drops embedded NULs (not wire-
    // transmittable) — agent_ids never contain them.
    std::vector<std::string_view> views;
    views.reserve(agent_ids.size());
    for (const std::string& a : agent_ids)
        views.emplace_back(a);

    const std::string cversion = yuzu::util::canon_version(version);
    std::string sql = select_prefix_;
    std::vector<std::string> params;
    params.emplace_back(pg::to_text_array(views));
    params.emplace_back(app_name);
    if (!cversion.empty()) {
        sql += " AND version = $3";
        params.emplace_back(cversion);
    }
    sql += " GROUP BY version, day ORDER BY version, day LIMIT " + std::to_string(kQueryRowCap);

    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), params);
    if (res.status() != PGRES_TUPLES_OK) {
        note_degrade(metrics_, "query_error");
        spdlog::warn("AppPerfGroupReader: get_group_trend degraded — query failed: {}",
                     PQerrorMessage(lease.get()));
        return std::nullopt;
    }
    const int n = PQntuples(res.get());
    out.reserve(static_cast<std::size_t>(n));
    for (int i = 0; i < n; ++i) {
        AppPerfFleetRow r;
        r.app_name = PQgetvalue(res.get(), i, 0);
        r.version = PQgetvalue(res.get(), i, 1);
        r.day = to_i64(PQgetvalue(res.get(), i, 2));
        r.device_count = to_i64(PQgetvalue(res.get(), i, 3));
        r.cpu_sum = to_double(PQgetvalue(res.get(), i, 4));
        r.cpu_max = to_double(PQgetvalue(res.get(), i, 5));
        r.ws_sum = to_i64(PQgetvalue(res.get(), i, 6));
        r.ws_max = to_i64(PQgetvalue(res.get(), i, 7));
        r.cpu_hist = parse_bigint_array(PQgetvalue(res.get(), i, 8));
        r.ws_hist = parse_bigint_array(PQgetvalue(res.get(), i, 9));
        r.hist_version = static_cast<int>(to_i64(PQgetvalue(res.get(), i, 10)));
        out.push_back(std::move(r));
    }
    return out;
}

} // namespace yuzu::server
