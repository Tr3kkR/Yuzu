#pragma once

/// @file app_usage_store.hpp
/// Born-on-Postgres per-agent last-used app-usage store (wave 7 PR7.2, schema
/// `app_usage_store`): the projection for the `app_usage` daily-sync source
/// (ADR-0016 §5) — per-executable first/last-seen and a trailing-30-day
/// run_count/total_seconds window, derived on the agent from TAR's
/// `usage_daily` fold via the read-only `app_usage` plugin.
///
/// HASH-SKIP OVER RAW BYTES (mirrors `SoftwareLicensingStore`, ADR-0024
/// Decision 3 / roadmap D-2): `content_hash` is the SHA-256 of the RAW
/// received blob bytes, recomputed by the ingest seam
/// (`app_usage_ingestion.cpp`) — never re-derived from parsed rows and never
/// trusted from the agent's claim. The store has no canonical_hash of its
/// own: it persists the seam's hash verbatim and offers the trichotomy
/// primitives (`stored_hash` / `touch` / `replace_agent_last_used`) the seam
/// drives — stored (full payload replaced), touched (hash matched, freshness
/// bumped), need-full (no state row or drifted hash).
///
/// Substrate contract (ADR-0008/0012): holds a `pg::PgPool&`, migrates at
/// construction on a pinned lease, schema-qualifies every runtime statement,
/// uses `RETURNING`, bounded leases. Failure posture (ADR-0012 §1):
///   - **Ingest:** fail-soft — a transient PG outage returns false; the seam
///     nacks and the agent re-sends next cycle.
///   - **Reads:** AUTHORITATIVE — a store/pool/query failure returns
///     `std::nullopt`, NEVER a silent empty. An empty *value* = a genuine
///     zero-row result.
///   - `first_seen`/`last_seen`/`updated_at` on the state row are SERVER
///     receipt time (TIMESTAMPTZ, `now()` in SQL — never the agent-supplied
///     collection time; the #1685 lesson / ADR-0016 clock-skew rule). The
///     per-row `first_seen`/`last_seen`/`run_count_30d`/`total_seconds_30d`
///     columns on `agent_last_used` ARE the agent-observed values (they are
///     the payload, not a freshness stamp).
///
/// DECOMMISSION (PLAN-01 ruling (b), Alex 2026-09-06): `delete_agent` erases
/// the agent from BOTH `usage_state` and `agent_last_used` in ONE transaction.
/// This is load-bearing, not tidiness: `usage_state.content_hash` drives the
/// hash-skip trichotomy, so a delete that cleared `agent_last_used` but left
/// `usage_state` would make the still-enrolled agent's next sync `touched`
/// and the projection would NEVER repopulate (rest-api.md:5089 documents that
/// erasure does not unenroll). Pinned by test: after delete_agent,
/// `stored_hash(agent)` is nullopt AND `get_agent_last_used(agent)` is an
/// empty vector (not nullopt).
///
/// Registered in the agent-decommission cascade (agent_decommission.hpp,
/// AgentDecommissionStores::app_usage, the sixth and last store) — the
/// DELETE /api/v1/sle/agents/{id} route erases this store under the scoped
/// `Decommission:Delete` securable (ADR-0024 Decision 9 as amended). This
/// header provides the honest two-table `delete_agent` the cascade calls;
/// see agent_decommission.cpp's registration list for the wiring.

#include <cstdint>
#include <expected>
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

/// One per-executable last-used row (`agent_last_used`). String/numeric
/// fields carry the seam-scrubbed/clamped wire values; the store persists
/// what it is given (projection discipline lives in the ingest seam).
struct AgentLastUsedRow {
    std::string exe_key;
    std::int64_t first_seen{0};        ///< agent-observed all-time first-seen epoch seconds
    std::int64_t last_seen{0};         ///< agent-observed all-time last-seen epoch seconds
    std::int64_t run_count_30d{0};     ///< agent-observed trailing-30-day run count
    std::int64_t total_seconds_30d{0}; ///< agent-observed trailing-30-day total run seconds
    std::int64_t collected_at{0};      ///< agent-supplied collection time (data, not freshness)
};

/// Error type for the authoritative single-row reads: the success type's
/// `std::nullopt` == absent (read succeeded, no row); `std::unexpected(kDegraded)`
/// == store/pool/query failure.
enum class AppUsageReadError { kDegraded };

class AppUsageStore {
public:
    /// Borrows the shared pool and runs the `app_usage_store` schema
    /// migration on a pinned lease. `is_open()` is false if the lease was
    /// empty or the migration failed (the server fails closed before
    /// reaching here).
    explicit AppUsageStore(pg::PgPool& pool);

    AppUsageStore(const AppUsageStore&) = delete;
    AppUsageStore& operator=(const AppUsageStore&) = delete;

    [[nodiscard]] bool is_open() const noexcept { return open_; }

    /// Wire a metrics registry for the read-degrade counter (the shared
    /// `yuzu_inventory_read_degrade_total{reason, source="app_usage"}`
    /// family, #1675). Set ONCE during single-threaded startup; null (the
    /// default) disables emission — every site is null-guarded.
    void set_metrics(yuzu::MetricsRegistry* m) noexcept { metrics_ = m; }

    /// The stored raw-blob content hash for one agent — the seam's hash-skip
    /// comparison input (trichotomy leg 1). `std::unexpected(kDegraded)` on a
    /// store/pool/query failure; a value holding `std::nullopt` when no state
    /// row exists (cold cache → the seam answers need_full); a value holding
    /// the hash otherwise. Returned VERBATIM as stored — the store never
    /// recomputes or normalises it.
    [[nodiscard]] std::expected<std::optional<std::string>, AppUsageReadError>
    stored_hash(std::string_view agent_id);

    /// Bump the state row's `last_seen`/`updated_at` to the server receipt
    /// time after a matching hash-only report (trichotomy leg 2 — "touched":
    /// nothing changed, the agent is alive). Returns false when the row is
    /// missing or on a store/pool/query failure. Child rows are untouched —
    /// the state row is the freshness authority.
    [[nodiscard]] bool touch(std::string_view agent_id);

    /// Full replace for one agent (trichotomy leg 3 — "stored"), in ONE
    /// transaction: upsert the `usage_state` parent (persisting the
    /// seam-recomputed raw-blob `content_hash` VERBATIM; `first_seen`
    /// preserved on conflict, `last_seen`/`updated_at` = server receipt
    /// time), delete the agent's old `agent_last_used` rows, batch-insert the
    /// new ones. An empty `rows` is a legitimate replace-to-empty. Fail-soft:
    /// false on any failure (the txn rolls back whole — old rows survive
    /// untouched; the seam nacks and the agent re-sends).
    [[nodiscard]] bool replace_agent_last_used(std::string_view agent_id,
                                               const std::vector<AgentLastUsedRow>& rows,
                                               std::string_view content_hash);

    /// All per-executable last-used rows for one agent, exe_key-sorted,
    /// capped. AUTHORITATIVE read: `std::nullopt` on a store/pool/query
    /// degrade (NEVER a silent empty); an empty value = the agent genuinely
    /// reported no rows (or a real, committed delete_agent — see the file
    /// header's decommission pin). An empty `agent_id` is a precondition miss
    /// → empty value.
    [[nodiscard]] std::optional<std::vector<AgentLastUsedRow>>
    get_agent_last_used(std::string_view agent_id);

    /// Drop an agent's `agent_last_used` rows AND its `usage_state` row in
    /// ONE transaction (see the file header — the two-table delete is
    /// load-bearing, not tidiness). Empty `agent_id` → warn + return false
    /// without touching PG. Returns true iff the transaction committed;
    /// false on a closed store, a lock/lease timeout, or a SQL failure — a
    /// rolled-back erasure is never reported as a completed delete.
    [[nodiscard]] bool delete_agent(std::string_view agent_id);

    /// Count agents whose usage state has not been refreshed since
    /// `stale_before_secs` (epoch seconds), i.e. `last_seen < to_timestamp(
    /// stale_before_secs)` on `usage_state`. Mirrors the sibling's bounded
    /// posture: a SHORT lease acquire AND a per-statement `SET LOCAL
    /// statement_timeout` so a metrics-sweep caller can never stall behind a
    /// bloated-table scan. `std::nullopt` on a degrade (incl. the execution
    /// timeout) — callers hold the previous value, never publish a false
    /// zero.
    [[nodiscard]] std::optional<std::int64_t> count_stale_agents(std::int64_t stale_before_secs);

private:
    pg::PgPool& pool_;
    bool open_{false};
    yuzu::MetricsRegistry* metrics_{nullptr};
};

} // namespace yuzu::server
