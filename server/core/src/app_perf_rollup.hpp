#pragma once

/// @file app_perf_rollup.hpp
/// Cross-store query owner (ADR-0012 §3 cross-store seam) that rolls B1
/// (`AppPerfDailyStore`, schema `app_perf_daily_store`) up to B2
/// (`AppPerfFleetStore`, schema `app_perf_fleet_store`) for the DEX
/// app-perf-over-time feature. Per ADR-0012, a per-store class must never reach
/// into another store's schema; the B1→B2 aggregation spans two schemas, so it
/// lives here — a dedicated owner that takes ONE pool lease and issues
/// schema-qualified SQL across both schemas (it borrows the pool, never a store's
/// lease).
///
/// The whole aggregation is ONE server-side `INSERT … SELECT … ON CONFLICT` per
/// day — no per-device rows cross the wire — with the per-(app,version,day)
/// histogram built in SQL via `COUNT(*) FILTER (WHERE col ∈ bucket)` over frozen,
/// half-open `[lo, hi)` bucket boundaries (code constants below). Idempotent:
/// re-rolling a day overwrites its B2 row, so a trailing window safely absorbs
/// late-arriving B1.

#include "app_perf_hist.hpp" // THE shared bucket scheme + kAppPerfHistVersion

#include <cstdint>
#include <string>
#include <vector>

namespace yuzu::server::pg {
class PgPool;
}

namespace yuzu::server {

class AppPerfRollup {
public:
    /// Frozen histogram bucket boundaries — half-open `[lo, hi)`, IMMUTABLE for the
    /// life of a stored B2 row (a 180-day store; changing a boundary mid-retention
    /// silently mixes schemes — bump `kHistVersion` and have readers filter if ever
    /// changed). CPU = share-of-total-capacity percent, low-end weighted (most apps
    /// idle). WS = working-set bytes, log-scale. N boundaries → N+1 buckets.
    /// These forward to the shared scheme in `app_perf_hist.hpp` — the ONE
    /// definition the reader (`dex_app_perf_model`) interprets against.
    static const std::vector<double>& cpu_buckets();
    static const std::vector<std::int64_t>& ws_buckets();
    static constexpr int kHistVersion = kAppPerfHistVersion;

    /// Trailing completed UTC days re-aggregated each run, to absorb late-arriving
    /// B1 (the agent's 2-day window + missed syncs). MUST stay below B1's retention
    /// (`AppPerfDailyStore::kRetentionDays`) — rolling a day B1 has already pruned
    /// would silently undercount B2 (static_assert in the .cpp).
    static constexpr int kTrailingDays = 4;

    explicit AppPerfRollup(pg::PgPool& pool);

    /// Re-aggregate one completed UTC day (`day_start` = UTC midnight epoch) from
    /// B1 into B2, idempotent via ON CONFLICT. One lease, schema-qualified across
    /// both schemas, bounded `statement_timeout`. Returns false on lease/SQL error.
    bool roll_day(std::int64_t day_start);

    /// Roll the trailing `kTrailingDays` completed UTC days at `now_secs`. Returns
    /// the count of days rolled successfully.
    int roll_window(std::int64_t now_secs);

    /// PURE: the `ARRAY[COUNT(*) FILTER (WHERE <col> ∈ bucket) …]::bigint[]`
    /// expression for `column` over `boundary_literals` (already-formatted numeric
    /// SQL literals), half-open `[lo, hi)`. Exposed for unit-testing the bucket
    /// predicates independently of a database.
    static std::string build_hist_array_sql(const std::string& column,
                                            const std::vector<std::string>& boundary_literals);

private:
    pg::PgPool& pool_;
    std::string roll_sql_; ///< the day roll-up INSERT, built once from the bucket constants ($1=day, $2=now)
};

} // namespace yuzu::server
