#pragma once

/// @file app_perf_fleet_store.hpp
/// Born-on-Postgres fleet-aggregate app-performance store — layer **B2** of the
/// DEX app-perf-over-time feature (schema `app_perf_fleet_store`). One row per
/// `(app_name, version, day)`: the fleet roll-up of B1 (`AppPerfDailyStore`)
/// across all devices that ran that `(app, version)` that UTC day — device count,
/// exact CPU/working-set sums + maxima, and a fixed-bucket histogram of the
/// per-device daily values so fleet percentiles (p50/p95) are computable over a
/// long retention WITHOUT storing per-device rows. The trend/regression substrate
/// ("did v125 run hotter than v124 across the fleet").
///
/// ── Ownership (ADR-0012) ──
/// This class is a **single-schema owner**: it owns the `app_perf_fleet` schema
/// (migrations), its reads, and its prune. It does NOT write the table and NEVER
/// reaches into B1's schema. The B1→B2 roll-up is a **cross-store write** and is
/// therefore done by the dedicated query owner `AppPerfRollup` (one lease,
/// schema-qualified SQL spanning both schemas) — the ADR-0012 cross-store seam.
///
/// ── Histogram contract (read this before touching buckets) ──
///   - `cpu_hist` / `ws_hist` are per-bucket DEVICE COUNTS; they sum to
///     `device_count`. Bucket boundaries are a FROZEN code constant
///     (`AppPerfRollup::kCpuBuckets` / `kWsBuckets`) — half-open `[lo, hi)`.
///   - **Boundaries are immutable for the life of a stored row.** This is a 180-day
///     store; changing a boundary mid-retention would silently mix two
///     incompatible histogram schemes. `hist_version` stamps the scheme a row was
///     built under — a future boundary change MUST bump it (and readers filter by
///     it), never silently reinterpret old counts.
///   - Percentiles derived from these histograms are **bucket-resolution
///     approximations**, not exact — sufficient for "is v125 worse than v124",
///     not for an exact SLA number. The exact fleet mean (`cpu_sum/device_count`)
///     and exact `cpu_max`/`ws_max` are stored alongside for the cases that need them.
///
/// ── Failure posture (ADR-0012 §1) ──
///   - **Data:** a derived aggregate — B1 (and ultimately the agents) are the
///     source of truth; a lost B2 row is rebuilt by the next roll-up.
///   - **Reads:** AUTHORITATIVE — a store/pool/query failure returns
///     `std::nullopt` (logged), never a silent empty. Callers surface the degrade.
///   - **Prune:** best-effort (a background job; a missed prune retries next cycle).
///
/// Substrate contract (ADR-0008): holds a `pg::PgPool&`, migrates at construction
/// on a pinned lease, schema-qualifies every runtime statement. No read surface in
/// this slice — slice 2 (dashboard/REST/MCP) consumes it and ships REST+MCP
/// lockstep (agentic-first A1–A4).

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu {
class MetricsRegistry;
}

namespace yuzu::server::pg {
class PgPool;
}

namespace yuzu::server {

/// One fleet-aggregate row for an `(app, version, day)`. `cpu_sum`/`ws_sum` are the
/// fleet sums of per-device daily averages (fleet mean = sum / device_count);
/// `cpu_max`/`ws_max` the fleet maxima; `cpu_hist`/`ws_hist` per-bucket device
/// counts (sum to `device_count`) under scheme `hist_version`.
struct AppPerfFleetRow {
    std::string app_name;
    std::string version;
    std::int64_t day{0}; ///< UTC midnight epoch seconds
    std::int64_t device_count{0};
    double cpu_sum{0.0};
    double cpu_max{0.0};
    std::int64_t ws_sum{0};
    std::int64_t ws_max{0};
    std::vector<std::int64_t> cpu_hist;
    std::vector<std::int64_t> ws_hist;
    int hist_version{0};
};

/// One row of the app picker: an app with retained fleet data, plus how many
/// distinct versions it carries and the most recent UTC day it was seen.
struct AppPerfAppSummary {
    std::string app_name;
    std::int64_t versions{0}; ///< distinct retained versions
    std::int64_t last_day{0}; ///< most recent UTC-midnight epoch day with data
};

class AppPerfFleetStore {
public:
    /// Borrows the shared pool and runs the `app_perf_fleet_store` schema migration
    /// on a pinned lease. `is_open()` is false if the lease was empty or the
    /// migration failed (the server fails closed before reaching here).
    explicit AppPerfFleetStore(pg::PgPool& pool);

    AppPerfFleetStore(const AppPerfFleetStore&) = delete;
    AppPerfFleetStore& operator=(const AppPerfFleetStore&) = delete;

    [[nodiscard]] bool is_open() const noexcept { return open_; }

    /// Wire a metrics registry for the read-degrade counter
    /// (`yuzu_app_perf_fleet_read_degrade_total{reason}`). Set ONCE during
    /// single-threaded startup. Null (default) disables emission.
    void set_metrics(yuzu::MetricsRegistry* m) noexcept { metrics_ = m; }

    /// All retained fleet rows for one app, ordered `(version, day)`. `version`
    /// empty = all versions of the app; a non-empty `version` is canonicalized
    /// (`yuzu::util::canon_version`) to match the stored key exactly. AUTHORITATIVE
    /// read: `std::nullopt` on a store/pool/query degrade (distinct from an empty
    /// value = genuinely no rows). An empty `app_name` is a precondition miss →
    /// empty value. Capped.
    [[nodiscard]] std::optional<std::vector<AppPerfFleetRow>>
    get_app_fleet_perf(std::string_view app_name, std::string_view version);

    /// Distinct apps that currently have any retained fleet data — the app picker
    /// for the fleet-trend read surface (agentic-first A2: a worker discovers what
    /// is measurable instead of guessing `app=`). Ordered by `app_name`.
    /// AUTHORITATIVE read: `std::nullopt` on a degrade; an empty value = no app-perf
    /// data yet. Capped (`truncated` set when the cap clipped the list).
    [[nodiscard]] std::optional<std::vector<AppPerfAppSummary>> list_apps(bool& truncated);

    /// Delete rows with `day` strictly older than `before_day` (epoch seconds).
    /// Best-effort (called by the roll-up background thread). Uses the `(day)` index.
    void prune(std::int64_t before_day);

    /// Long-retention horizon for the fleet aggregate (vs B1's 31 days) — the trend
    /// window. The roll-up thread prunes `day < now_utc_day - kRetentionDays`.
    static constexpr int kRetentionDays = 180;

private:
    pg::PgPool& pool_;
    bool open_{false};
    yuzu::MetricsRegistry* metrics_{nullptr};
};

} // namespace yuzu::server
