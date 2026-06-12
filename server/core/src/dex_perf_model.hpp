#pragma once

/// @file dex_perf_model.hpp
/// F2a fleet performance read model — PURE aggregation over per-device
/// current heartbeat perf samples (BRD rows 13–15 residual + 98–100/103
/// cohort benchmarking; docs/dex-brd-coverage.md F-row).
///
/// Everything here is computed at render/request time over registry heartbeat
/// state — ZERO new storage (the F2a decision; retained trend series are F2b,
/// blocked on the Postgres substrate). Validation and percentile ranking come
/// from dex_perf_rules.hpp, shared with the Prometheus rollup, so the fleet
/// cards and the `yuzu_fleet_perf_*` gauges can never disagree.
///
/// Honesty rules: a metric nobody reported is ABSENT (std::nullopt), never 0;
/// every aggregate carries its reporting population; cohorts below
/// kDexCohortFloor are suppressed ("n too small"), and devices without the
/// chosen tag key form an explicit "(untagged)" residual, never a silent
/// omission. A Cohort is a read-side analytical grouping over an
/// operator-chosen tag key (CONTEXT.md "Cohort") — no authorization meaning.

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace yuzu {
class MetricsRegistry;
}

namespace yuzu::server {

/// One device's current perf sample, joined with its resolved cohort value.
/// Values are already validated through dex_perf_rules.hpp by the provider;
/// nullopt = the device did not report that metric this cycle.
struct DexPerfDevice {
    std::string agent_id;
    bool is_windows{false}; ///< denominator scoping (perf collectors are Windows-only today)
    std::optional<double> cpu_pct;
    std::optional<double> commit_pct;
    std::optional<double> disk_lat_ms;
    std::string cohort; ///< resolved value for the requested tag key; "" = untagged
};

/// Provider result: every ONLINE agent (reporting or not — the not-reporting
/// drill needs the complement), plus the tag keys available for the cohort
/// picker. Assembled in server.cpp from AgentHealthStore + AgentRegistry +
/// TagStore; a struct (not store deps) keeps the model and renderers pure.
struct DexPerfSnapshot {
    std::vector<DexPerfDevice> devices;
    std::vector<std::string> available_keys; ///< distinct tag keys (cohort select options)
    std::string cohort_key;                  ///< the key `cohort` values were resolved for
};

/// Provider seam: resolve a snapshot for one cohort tag key ("" = no cohort
/// resolution needed). May be empty in tests / degraded wiring.
using DexPerfFn = std::function<DexPerfSnapshot(const std::string& cohort_key)>;

/// Statistical floor: cohorts with fewer reporting devices than this render
/// "n too small" instead of noisy percentiles. Deliberately a constant, not a
/// setting (grill 2026-06-12) — make it tunable only if a real fleet asks.
inline constexpr int64_t kDexCohortFloor = 10;

/// The conventional default cohort key (the asset-tagging recipe's key) —
/// the ONE spelling shared by the fragment, REST and MCP defaults so the
/// three surfaces cannot drift.
inline constexpr const char* kDexDefaultCohortKey = "model";

/// One metric's fleet stats. Only constructed when n > 0 (absent-not-zero).
struct DexPerfStat {
    double avg{0.0};
    double p50{0.0};
    double p90{0.0};
    double max{0.0};
    int64_t n{0};
};

/// Fleet-now: the same numbers the yuzu_fleet_perf_* gauges carry, plus the
/// honest denominators.
struct DexPerfFleetNow {
    std::optional<DexPerfStat> cpu;
    std::optional<DexPerfStat> commit;
    std::optional<DexPerfStat> disk_lat;
    int64_t reporting{0};      ///< devices contributing at least one metric
    int64_t windows_online{0}; ///< the coverage-honest denominator
};

DexPerfFleetNow dex_perf_fleet_now(const DexPerfSnapshot& snap);

/// One cohort row. `suppressed` rows carry `devices` but no stats.
/// The "(untagged)" residual has cohort == "" and sorts last.
struct DexPerfCohortRow {
    std::string cohort;
    int64_t devices{0}; ///< reporting devices in this cohort
    bool suppressed{false};
    std::optional<DexPerfStat> cpu;
    std::optional<DexPerfStat> commit;
    std::optional<DexPerfStat> disk_lat;
};

/// Group reporting devices by cohort value. Rows sorted by population
/// descending; the untagged residual (if any) always last.
std::vector<DexPerfCohortRow> dex_perf_cohorts(const DexPerfSnapshot& snap);

/// One row of the devices drill (worst-by-metric / cohort membership /
/// not-reporting). `fleet_pctile` is the device's nearest-rank percentile
/// position for the sort metric across all reporting devices (-1 when the
/// device did not report that metric, e.g. the not-reporting filter).
struct DexPerfDeviceRow {
    std::string agent_id;
    std::string cohort;
    std::optional<double> cpu_pct;
    std::optional<double> commit_pct;
    std::optional<double> disk_lat_ms;
    int fleet_pctile{-1};
};

/// Sort metrics for the devices drill. Anything else resolves to kCpu.
enum class DexPerfMetric { kCpu, kCommit, kDiskLat };
DexPerfMetric dex_perf_metric_from_token(const std::string& token);
const char* dex_perf_metric_token(DexPerfMetric m);

// ── PR3: per-cohort Prometheus export (Grafana) ──────────────────────────────

/// Cardinality cap for the cohort gauge export: top N cohorts by population.
/// Clipping is made visible via yuzu_fleet_perf_cohort_clipped, never silent.
inline constexpr int kDexCohortExportCap = 50;

/// Clear the five yuzu_fleet_perf_cohort_* families — series go ABSENT, never
/// stale (called every sweep; the disabled path stops here).
void dex_perf_clear_cohort_gauges(yuzu::MetricsRegistry& metrics);

/// Publish the per-cohort gauge families from cohort rows (clears first).
/// Suppressed (sub-floor) rows never export; rows beyond `cap` count into the
/// clipped gauge; the untagged residual exports as cohort="(untagged)".
/// `clipped` is a measured 0 when the export is active and nothing was cut.
void dex_perf_export_cohort_gauges(yuzu::MetricsRegistry& metrics,
                                   const std::vector<DexPerfCohortRow>& rows,
                                   int cap = kDexCohortExportCap);

/// One metric of a device's now-vs-now comparison (PR2 percentile strips):
/// the device's current heartbeat value against the CURRENT fleet and cohort
/// distributions from the same snapshot — no retained history, no extra
/// federated query (grill decision 7).
struct DexPerfMetricContext {
    std::optional<double> value;        ///< the device's current sample
    std::optional<DexPerfStat> fleet;   ///< fleet distribution (all reporters)
    std::optional<DexPerfStat> cohort;  ///< cohort distribution; nullopt below floor
    int fleet_pctile{-1};               ///< nearest-rank position; -1 = no value
    int cohort_pctile{-1};
};

/// A device's comparison context for the drill-down strips. `cohort` is the
/// device's value for snap.cohort_key (""= untagged); `cohort_n` counts the
/// cohort's REPORTING devices (the same count dex_perf_cohorts shows), and
/// cohort stats/percentiles are withheld below kDexCohortFloor — the floor
/// rule applies everywhere or nowhere.
struct DexPerfDeviceContext {
    bool found{false};     ///< agent_id present in the snapshot (online)
    bool reporting{false}; ///< contributed at least one metric this cycle
    std::string cohort;
    int64_t cohort_n{0};
    DexPerfMetricContext cpu;
    DexPerfMetricContext commit;
    DexPerfMetricContext disk_lat;
};

DexPerfDeviceContext dex_perf_device_context(const DexPerfSnapshot& snap,
                                             const std::string& agent_id);

/// The ONE device list that serves every drill (grill decision: metric card →
/// worst devices; Reporting card → not-reporting; cohort/untagged row → that
/// cohort's devices):
///  - `not_reporting=true`  → Windows devices with NO metric this cycle
///    (sorted by agent_id; metric/cohort filters still apply if given).
///  - `cohort_filter` set   → only devices whose resolved cohort equals it
///    ("" = the untagged residual). nullopt = no cohort filtering.
///  - otherwise             → devices reporting the sort metric, worst first.
/// `limit` caps rows (callers pass a validated 1..500).
std::vector<DexPerfDeviceRow> dex_perf_device_list(const DexPerfSnapshot& snap, DexPerfMetric metric,
                                                   bool not_reporting,
                                                   const std::optional<std::string>& cohort_filter,
                                                   int limit);

} // namespace yuzu::server
