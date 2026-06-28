#include "dex_app_perf_model.hpp"

#include "dex_perf_model.hpp" // kDexCohortFloor — the ONE cohort floor constant

#include <algorithm>
#include <cmath>
#include <utility>

namespace yuzu::server {

bool app_perf_param_valid(std::string_view s) {
    if (s.size() > kAppPerfParamCap)
        return false;
    for (const unsigned char c : s)
        if (c < 0x20) // C0 control incl. NUL (NUL truncates a bound libpq text param)
            return false;
    return true;
}

std::optional<HistPctile> percentile_from_hist(const std::vector<std::int64_t>& hist,
                                               const std::vector<double>& boundaries, double p) {
    // Scheme guard: N boundaries → N+1 buckets. A mismatch is a corrupt or
    // wrong-scheme row — withhold rather than read counts under wrong cut points.
    if (hist.size() != boundaries.size() + 1)
        return std::nullopt;

    std::int64_t total = 0;
    for (const std::int64_t c : hist)
        total += (c > 0 ? c : 0); // a negative count is corruption; ignore it
    if (total <= 0)
        return std::nullopt; // empty population — absent, never a fabricated 0

    p = std::clamp(p, 0.0, 1.0);
    // Nearest-rank DIRECTION, matching detail::nearest_rank: the 1-based rank
    // r = ceil(p·total), floored at 1 and capped at total. The percentile is the
    // value of the element at that rank; we return the lower edge of the bucket
    // that element lands in (bucket-resolution approximation).
    auto r = static_cast<std::int64_t>(std::ceil(p * static_cast<double>(total)));
    r = std::clamp<std::int64_t>(r, 1, total);

    const std::size_t n = boundaries.size(); // top (open) bucket index == n
    std::int64_t cum = 0;
    for (std::size_t b = 0; b < hist.size(); ++b) {
        const std::int64_t c = hist[b] > 0 ? hist[b] : 0;
        cum += c;
        if (cum >= r) {
            HistPctile out;
            // Lower edge: bucket 0 → metric floor 0; bucket b → boundaries[b-1];
            // top open bucket n → boundaries[n-1] as a FLOOR.
            if (b == 0)
                out.value = 0.0;
            else
                out.value = boundaries[b - 1];
            out.lower_bound = (b == n); // open top bucket → "≥ value"
            return out;
        }
    }
    // Unreachable when total > 0 (cum reaches total ≥ r), but stay defensive.
    return std::nullopt;
}

namespace {

// WS boundaries widened to double once (≤ 8 GiB is exact in double). Shared by
// every trend point so we don't rebuild the vector per row.
const std::vector<double>& ws_boundaries_d() {
    static const std::vector<double> kWs = [] {
        std::vector<double> v;
        for (const std::int64_t b : app_perf_ws_buckets())
            v.push_back(static_cast<double>(b));
        return v;
    }();
    return kWs;
}

// PURE: reduce B2 rows to trend points WITHOUT the floor — the exact mean +
// percentile + hist_version gate, one row in → one point out. The cohort floor is
// applied on top by the public fleet/group entry points so they share one
// histogram reading and one suppression rule.
std::vector<AppPerfTrendPoint> build_trend(const std::vector<AppPerfFleetRow>& rows) {
    std::vector<AppPerfTrendPoint> out;
    out.reserve(rows.size());
    for (const AppPerfFleetRow& row : rows) {
        AppPerfTrendPoint pt;
        pt.version = row.version;
        pt.day = row.day;
        pt.device_count = row.device_count;
        pt.cpu_max = row.cpu_max;
        pt.ws_max = row.ws_max;
        if (row.device_count > 0) {
            pt.cpu_mean = row.cpu_sum / static_cast<double>(row.device_count);
            // Integer mean of bytes — rounded, never a divide-by-zero.
            pt.ws_mean = static_cast<std::int64_t>(
                std::llround(static_cast<double>(row.ws_sum) /
                             static_cast<double>(row.device_count)));
        }
        // Withhold percentiles for a row built under a different scheme — never
        // reinterpret its counts under the current buckets.
        if (row.hist_version == kAppPerfHistVersion) {
            pt.cpu_p50 = percentile_from_hist(row.cpu_hist, app_perf_cpu_buckets(), 0.50);
            pt.cpu_p95 = percentile_from_hist(row.cpu_hist, app_perf_cpu_buckets(), 0.95);
            pt.ws_p50 = percentile_from_hist(row.ws_hist, ws_boundaries_d(), 0.50);
            pt.ws_p95 = percentile_from_hist(row.ws_hist, ws_boundaries_d(), 0.95);
        } else {
            pt.hist_stale = true;
        }
        out.push_back(std::move(pt));
    }
    return out;
}

// Sub-floor suppression: a (version, day) point covering fewer than `floor`
// devices is de-facto individual behaviour (singling-out — works-council / GDPR
// needs no name), so its stats are withheld and only the honest device_count
// survives. Applied to BOTH the fleet and group paths (a niche app on N<floor
// devices is just as identifying fleet-wide as inside a named group).
void apply_cohort_floor(std::vector<AppPerfTrendPoint>& points, std::int64_t floor) {
    for (AppPerfTrendPoint& pt : points) {
        if (pt.device_count < floor) {
            pt.suppressed = true;
            pt.cpu_mean = 0.0;
            pt.cpu_max = 0.0;
            pt.ws_mean = 0;
            pt.ws_max = 0;
            pt.cpu_p50.reset();
            pt.cpu_p95.reset();
            pt.ws_p50.reset();
            pt.ws_p95.reset();
        }
    }
}

} // namespace

std::vector<AppPerfTrendPoint> app_perf_fleet_trend(const std::vector<AppPerfFleetRow>& rows) {
    // The fleet trend floors at kDexCohortFloor too: a sub-floor (version, day) point
    // singles out one operator's exact CPU/mem even without an agent_id, so it is
    // withheld (count only) — the same protection the named-group path applies, NOT
    // a fleet-only exemption (governance compliance-HIGH / sec-MED).
    std::vector<AppPerfTrendPoint> points = build_trend(rows);
    apply_cohort_floor(points, kDexCohortFloor);
    return points;
}

std::vector<AppPerfVersionSummary>
app_perf_version_summaries(const std::vector<AppPerfTrendPoint>& points) {
    std::vector<AppPerfVersionSummary> out;
    // Per-version (day, cpu_mean) pairs, aligned with `out` by index — collected
    // here so the sparkline series can be sorted chronologically regardless of input
    // order. Index access (not a held pointer-into-vector) sidesteps any
    // use-after-realloc on push_back.
    std::vector<std::vector<std::pair<std::int64_t, double>>> series;
    for (const AppPerfTrendPoint& pt : points) {
        // Points are grouped by version (SQL ORDER BY version, day); the common path
        // extends the last summary. Fall back to a search so out-of-order input still
        // groups correctly (defence-in-depth, never a duplicate row).
        std::size_t idx = 0;
        bool found = false;
        if (!out.empty() && out.back().version == pt.version) {
            idx = out.size() - 1;
            found = true;
        } else {
            for (std::size_t k = 0; k < out.size(); ++k)
                if (out[k].version == pt.version) {
                    idx = k;
                    found = true;
                    break;
                }
        }
        if (!found) {
            AppPerfVersionSummary fresh;
            fresh.version = pt.version;
            out.push_back(std::move(fresh));
            series.emplace_back();
            idx = out.size() - 1;
        }
        AppPerfVersionSummary& s = out[idx];
        ++s.day_count;
        if (!pt.suppressed)
            series[idx].emplace_back(pt.day, pt.cpu_mean); // real means only; cleared days skipped
        // Headline = the latest day seen for this version (`>=` makes it order-robust
        // and keeps a single-day version honest).
        if (pt.day >= s.latest_day) {
            s.latest_day = pt.day;
            s.device_count = pt.device_count;
            s.suppressed = pt.suppressed;
            s.hist_stale = pt.hist_stale;
            s.cpu_mean = pt.cpu_mean;
            s.cpu_max = pt.cpu_max;
            s.cpu_p95 = pt.cpu_p95;
            s.ws_mean = pt.ws_mean;
        }
    }
    // Sort each version's series by day, then project to the chronological sparkline.
    for (std::size_t k = 0; k < out.size(); ++k) {
        auto& pairs = series[k];
        std::sort(pairs.begin(), pairs.end(),
                  [](const auto& a, const auto& b) { return a.first < b.first; });
        out[k].cpu_series.reserve(pairs.size());
        for (const auto& [day, mean] : pairs)
            out[k].cpu_series.push_back(mean);
    }
    return out;
}

std::vector<AppPerfTrendPoint> app_perf_group_trend(const std::vector<AppPerfFleetRow>& rows,
                                                    std::int64_t floor) {
    // Same build + suppression as the fleet path; the group passes its own floor
    // (kDexCohortFloor from the REST/MCP/dashboard callers). Shares one histogram
    // reading + one floor rule with the fleet path so the surfaces cannot disagree.
    std::vector<AppPerfTrendPoint> points = build_trend(rows);
    apply_cohort_floor(points, floor);
    return points;
}

} // namespace yuzu::server
