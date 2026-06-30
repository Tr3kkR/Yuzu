#include "app_perf_cohort_reader.hpp"

#include "pg/pg_array.hpp" // pg::to_text_array
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include <yuzu/metrics.hpp>
#include <yuzu/version_string.hpp> // canon_version — match the stored key

#include <libpq-fe.h>
#include <spdlog/spdlog.h>

#include <chrono>
#include <cstdlib>
#include <string>
#include <vector>

namespace yuzu::server {

namespace {

constexpr std::chrono::milliseconds kQueryAcquireTimeout{3000};
// cohort × (two versions) × ≤31 days — small; this is unbounded-growth defence,
// matching the B1/B2/group read caps.
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

void note_degrade(yuzu::MetricsRegistry* metrics, const char* reason) {
    if (metrics)
        metrics->counter("yuzu_app_perf_cohort_read_degrade_total", {{"reason", reason}}).increment();
}

} // namespace

std::optional<std::vector<AppPerfCohortRow>>
AppPerfCohortReader::get_cohort_rows(const std::vector<std::string>& agent_ids,
                                     std::string_view app_name, std::string_view baseline_version,
                                     std::string_view candidate_version, bool& truncated) {
    truncated = false;
    std::vector<AppPerfCohortRow> out;
    if (agent_ids.empty() || app_name.empty())
        return out; // precondition miss, not a degrade

    auto lease = pool_.try_acquire_for(kQueryAcquireTimeout);
    if (!lease) {
        note_degrade(metrics_, "pool_acquire_timeout");
        spdlog::warn("AppPerfCohortReader: get_cohort_rows degraded — no connection ({})",
                     pool_.last_error());
        return std::nullopt;
    }

    // Member list → a Postgres text[] literal for ANY(). to_text_array drops
    // embedded NULs (not wire-transmittable); agent_ids never contain them.
    std::vector<std::string_view> member_views;
    member_views.reserve(agent_ids.size());
    for (const std::string& a : agent_ids)
        member_views.emplace_back(a);

    // Both versions canonicalized to match the stored key (the ingest path canons
    // too). The compare engine matches on these exact strings, so canon HERE keeps
    // the SQL filter and the in-engine pairing on one key.
    const std::string base_canon = yuzu::util::canon_version(baseline_version);
    const std::string cand_canon = yuzu::util::canon_version(candidate_version);
    const std::vector<std::string_view> version_views{base_canon, cand_canon};

    std::vector<std::string> params;
    params.emplace_back(pg::to_text_array(member_views)); // $1
    params.emplace_back(app_name);                        // $2
    params.emplace_back(pg::to_text_array(version_views)); // $3

    const std::string sql =
        "SELECT agent_id, version, day, samples, cpu_avg, ws_avg_bytes "
        "FROM app_perf_daily_store.app_perf_daily "
        "WHERE agent_id = ANY($1::text[]) AND app_name = $2 AND version = ANY($3::text[]) "
        "ORDER BY agent_id, version, day LIMIT " +
        std::to_string(kQueryRowCap);

    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), params);
    if (res.status() != PGRES_TUPLES_OK) {
        note_degrade(metrics_, "query_error");
        spdlog::warn("AppPerfCohortReader: get_cohort_rows degraded — query failed: {}",
                     PQerrorMessage(lease.get()));
        return std::nullopt;
    }
    const int n = PQntuples(res.get());
    if (n >= kQueryRowCap) {
        // The ORDER BY agent_id cap drops the last agents mid-machine → a machine
        // that ran both versions can be mis-read as baseline_only. Flag it so the
        // surfaces refuse to present the comparison as reliable (gov UP-1), and make
        // the truncation discoverable on an idle server (gov sre).
        truncated = true;
        if (metrics_)
            metrics_->counter("yuzu_app_perf_cohort_read_cap_hit_total", {}).increment();
        spdlog::warn("AppPerfCohortReader: cohort read hit the {}-row cap for app='{}' "
                     "({} members) — the comparison is truncated and may mis-pair machines; "
                     "narrow the group or shorten the window",
                     kQueryRowCap, app_name, agent_ids.size());
    }
    out.reserve(static_cast<std::size_t>(n));
    for (int i = 0; i < n; ++i) {
        AppPerfCohortRow r;
        r.agent_id = PQgetvalue(res.get(), i, 0);
        r.version = PQgetvalue(res.get(), i, 1);
        r.day = to_i64(PQgetvalue(res.get(), i, 2));
        r.samples = to_i64(PQgetvalue(res.get(), i, 3));
        r.cpu_avg = to_double(PQgetvalue(res.get(), i, 4));
        r.ws_avg_bytes = to_i64(PQgetvalue(res.get(), i, 5));
        out.push_back(std::move(r));
    }
    return out;
}

} // namespace yuzu::server
