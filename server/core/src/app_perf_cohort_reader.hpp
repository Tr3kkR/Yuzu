#pragma once

/// @file app_perf_cohort_reader.hpp
/// Reader for the `/auto` VERIFY cohort-paired before/after comparison: the RAW
/// B1 (`AppPerfDailyStore`, schema `app_perf_daily_store`) daily rows for a set of
/// member `agent_id`s and one app, **with `agent_id` preserved** so the pure
/// engine (`app_perf_compare.hpp`) can pair each machine's baseline-version window
/// against its own candidate-version window.
///
/// ── Why a dedicated reader, not the store's `get_agent_app_perf` ──
/// `AppPerfDailyStore::get_agent_app_perf` is per-AGENT and returns
/// `AppPerfDailyRow` (no id — it's implicit). VERIFY needs a COHORT read that keeps
/// the id, restricted to the two versions being compared. Like `AppPerfGroupReader`
/// this reader borrows the pool (never a store lease), reads exactly the B1 schema,
/// and is fed a member list the caller resolved from `ManagementGroupStore` — so
/// the two reads (members, then rows) are bounded single-store leases composed in
/// the provider, never one held across the other (ADR-0012 §1). It does NOT
/// aggregate (that's what distinguishes it from the group reader, which collapses
/// to a B2-shaped histogram row).
///
/// ── Failure posture (ADR-0012 §1) ──
///   - **Reads:** AUTHORITATIVE — `std::nullopt` on a pool/query degrade (logged),
///     never a silent empty. An empty member list or empty `app_name` is a
///     precondition miss → empty value, not a degrade.

#include "app_perf_compare.hpp" // AppPerfCohortRow (the engine input shape)

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

class AppPerfCohortReader {
public:
    /// Borrows the shared pool. No schema of its own (it reads B1's), so no
    /// migration; `is_open()` is always true once constructed.
    explicit AppPerfCohortReader(pg::PgPool& pool) : pool_(pool) {}

    AppPerfCohortReader(const AppPerfCohortReader&) = delete;
    AppPerfCohortReader& operator=(const AppPerfCohortReader&) = delete;

    /// Wire a metrics registry for the read-degrade counter
    /// (`yuzu_app_perf_cohort_read_degrade_total{reason}`). Set ONCE at startup.
    void set_metrics(yuzu::MetricsRegistry* m) noexcept { metrics_ = m; }

    /// Raw B1 rows for `agent_ids` × `app_name`, restricted to the two versions
    /// being compared (both canonicalized to match the stored key; a version may
    /// be empty for the "" unknown bucket) AND to the most-recent `window_days` days
    /// of each version PER MACHINE (a `ROW_NUMBER() OVER (PARTITION BY agent_id,
    /// version ORDER BY day DESC)` filter — the same per-machine-per-version window
    /// `reduce_version_window` applies, pushed into SQL so the row cap bites on the
    /// windowed set and "shorten the window" genuinely reduces the read; gov M1).
    /// Ordered `(agent_id, version, day)`, `agent_id` preserved. AUTHORITATIVE:
    /// `std::nullopt` on a pool/query degrade; empty value when `agent_ids`/`app_name`
    /// is empty or no rows match. `window_days <= 0` is treated as 1.
    ///
    /// `truncated` (out-param) is set true when the result hit the hard row cap. The
    /// cap drops the alphabetically-last `agent_id`s mid-machine, so a truncated read
    /// can MIS-classify a machine that ran both versions as `baseline_only` — the
    /// comparison must NOT be presented as reliable when truncated (gov UP-1). Callers
    /// surface it loudly (REST/MCP `truncated` field, dashboard warning), never silently.
    [[nodiscard]] std::optional<std::vector<AppPerfCohortRow>>
    get_cohort_rows(const std::vector<std::string>& agent_ids, std::string_view app_name,
                    std::string_view baseline_version, std::string_view candidate_version,
                    int window_days, bool& truncated);

private:
    pg::PgPool& pool_;
    yuzu::MetricsRegistry* metrics_{nullptr};
};

} // namespace yuzu::server
