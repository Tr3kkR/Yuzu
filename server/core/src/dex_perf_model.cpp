#include "dex_perf_model.hpp"

#include "dex_perf_rules.hpp"

#include <algorithm>
#include <map>
#include <string>
#include <vector>

namespace yuzu::server {

namespace {

using detail::nearest_rank;

/// Build a DexPerfStat from raw values (unsorted). Returns nullopt when empty.
std::optional<DexPerfStat> make_stat(std::vector<double>& vals) {
    if (vals.empty())
        return std::nullopt;
    std::sort(vals.begin(), vals.end());
    double sum = 0.0;
    for (double v : vals)
        sum += v;
    DexPerfStat s;
    s.n = static_cast<int64_t>(vals.size());
    s.avg = sum / static_cast<double>(vals.size());
    s.p50 = nearest_rank(vals, 0.50);
    s.p90 = nearest_rank(vals, 0.90);
    s.max = vals.back();
    return s;
}

bool reports_any(const DexPerfDevice& d) {
    return d.cpu_pct.has_value() || d.commit_pct.has_value() || d.disk_lat_ms.has_value();
}

std::optional<double> metric_value(const DexPerfDevice& d, DexPerfMetric m) {
    switch (m) {
    case DexPerfMetric::kCommit:
        return d.commit_pct;
    case DexPerfMetric::kDiskLat:
        return d.disk_lat_ms;
    case DexPerfMetric::kCpu:
    default:
        return d.cpu_pct;
    }
}

} // namespace

DexPerfMetric dex_perf_metric_from_token(const std::string& token) {
    if (token == "commit")
        return DexPerfMetric::kCommit;
    if (token == "disk_lat")
        return DexPerfMetric::kDiskLat;
    return DexPerfMetric::kCpu;
}

const char* dex_perf_metric_token(DexPerfMetric m) {
    switch (m) {
    case DexPerfMetric::kCommit:
        return "commit";
    case DexPerfMetric::kDiskLat:
        return "disk_lat";
    case DexPerfMetric::kCpu:
    default:
        return "cpu";
    }
}

DexPerfFleetNow dex_perf_fleet_now(const DexPerfSnapshot& snap) {
    DexPerfFleetNow out;
    std::vector<double> cpu, commit, disk;
    for (const auto& d : snap.devices) {
        if (d.is_windows)
            ++out.windows_online;
        if (reports_any(d))
            ++out.reporting;
        if (d.cpu_pct)
            cpu.push_back(*d.cpu_pct);
        if (d.commit_pct)
            commit.push_back(*d.commit_pct);
        if (d.disk_lat_ms)
            disk.push_back(*d.disk_lat_ms);
    }
    out.cpu = make_stat(cpu);
    out.commit = make_stat(commit);
    out.disk_lat = make_stat(disk);
    return out;
}

std::vector<DexPerfCohortRow> dex_perf_cohorts(const DexPerfSnapshot& snap) {
    // Group REPORTING devices only — a cohort of enrolled-but-silent devices
    // has nothing to benchmark (they appear via the not-reporting drill).
    struct Acc {
        std::vector<double> cpu, commit, disk;
        int64_t devices{0};
    };
    std::map<std::string, Acc> groups; // ordered: deterministic output
    for (const auto& d : snap.devices) {
        if (!reports_any(d))
            continue;
        auto& g = groups[d.cohort];
        ++g.devices;
        if (d.cpu_pct)
            g.cpu.push_back(*d.cpu_pct);
        if (d.commit_pct)
            g.commit.push_back(*d.commit_pct);
        if (d.disk_lat_ms)
            g.disk.push_back(*d.disk_lat_ms);
    }

    std::vector<DexPerfCohortRow> rows;
    rows.reserve(groups.size());
    for (auto& [cohort, acc] : groups) {
        DexPerfCohortRow r;
        r.cohort = cohort;
        r.devices = acc.devices;
        if (acc.devices < kDexCohortFloor) {
            r.suppressed = true; // population shown, percentiles withheld
        } else {
            r.cpu = make_stat(acc.cpu);
            r.commit = make_stat(acc.commit);
            r.disk_lat = make_stat(acc.disk);
        }
        rows.push_back(std::move(r));
    }
    // Population-descending; the "(untagged)" residual (cohort == "") last so
    // it reads as the residual it is, not a competing cohort.
    std::stable_sort(rows.begin(), rows.end(),
                     [](const DexPerfCohortRow& a, const DexPerfCohortRow& b) {
                         const bool a_untagged = a.cohort.empty();
                         const bool b_untagged = b.cohort.empty();
                         if (a_untagged != b_untagged)
                             return b_untagged;
                         return a.devices > b.devices;
                     });
    return rows;
}

std::vector<DexPerfDeviceRow> dex_perf_device_list(const DexPerfSnapshot& snap, DexPerfMetric metric,
                                                   bool not_reporting,
                                                   const std::optional<std::string>& cohort_filter,
                                                   int limit) {
    if (limit <= 0)
        return {};

    // Percentile context: every reported value of the sort metric, fleet-wide
    // (NOT filtered) — "this device sits at the fleet's Nth percentile" must
    // mean the same thing from every drill.
    std::vector<double> fleet_vals;
    for (const auto& d : snap.devices)
        if (auto v = metric_value(d, metric))
            fleet_vals.push_back(*v);
    std::sort(fleet_vals.begin(), fleet_vals.end());

    auto fleet_pctile = [&](double v) -> int {
        if (fleet_vals.empty())
            return -1;
        // Rank = share of reported values <= v (nearest-rank inverse).
        const auto at_or_below = static_cast<double>(
            std::upper_bound(fleet_vals.begin(), fleet_vals.end(), v) - fleet_vals.begin());
        return static_cast<int>(at_or_below / static_cast<double>(fleet_vals.size()) * 100.0);
    };

    std::vector<DexPerfDeviceRow> rows;
    for (const auto& d : snap.devices) {
        if (cohort_filter && d.cohort != *cohort_filter)
            continue;
        if (not_reporting) {
            // The complement list: Windows devices (the only OS expected to
            // report today) that contributed nothing this cycle.
            if (!d.is_windows || reports_any(d))
                continue;
        } else {
            if (!metric_value(d, metric))
                continue;
        }
        DexPerfDeviceRow r;
        r.agent_id = d.agent_id;
        r.cohort = d.cohort;
        r.cpu_pct = d.cpu_pct;
        r.commit_pct = d.commit_pct;
        r.disk_lat_ms = d.disk_lat_ms;
        if (auto v = metric_value(d, metric))
            r.fleet_pctile = fleet_pctile(*v);
        rows.push_back(std::move(r));
    }

    if (not_reporting) {
        std::sort(rows.begin(), rows.end(), [](const DexPerfDeviceRow& a, const DexPerfDeviceRow& b) {
            return a.agent_id < b.agent_id;
        });
    } else {
        std::stable_sort(rows.begin(), rows.end(),
                         [&](const DexPerfDeviceRow& a, const DexPerfDeviceRow& b) {
                             // Both have the metric (filtered above); worst first.
                             double x = 0.0, y = 0.0;
                             switch (metric) {
                             case DexPerfMetric::kCommit:
                                 x = *a.commit_pct;
                                 y = *b.commit_pct;
                                 break;
                             case DexPerfMetric::kDiskLat:
                                 x = *a.disk_lat_ms;
                                 y = *b.disk_lat_ms;
                                 break;
                             case DexPerfMetric::kCpu:
                             default:
                                 x = *a.cpu_pct;
                                 y = *b.cpu_pct;
                                 break;
                             }
                             return x > y;
                         });
    }

    if (rows.size() > static_cast<std::size_t>(limit))
        rows.resize(static_cast<std::size_t>(limit));
    return rows;
}

} // namespace yuzu::server
