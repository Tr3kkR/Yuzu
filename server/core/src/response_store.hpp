#pragma once

/// @file response_store.hpp
/// Agentic command/instruction response store — born on SQLite, migrated to
/// PostgreSQL (ADR-0006/0008/0009/0039, schema `response_store`). Two tables:
/// `responses` (per-agent result rows) + `response_facets` (denormalised
/// column values powering the dashboard's facet filters). High-write (every
/// command result from every agent), TTL'd (default 90-day retention via
/// `reap_expired()`, called from the server's maintenance tick), a `/tar`-
/// and executions-drawer read source.
///
/// Substrate contract (ADR-0008/0012): holds a `pg::PgPool&`, migrates at
/// construction on a pinned lease, schema-qualifies every runtime statement
/// (`response_store.responses`). No `sqlite3_changes()` (#1033) — mutators
/// check the `PgResult` status / use `RETURNING` directly.
///
/// Failure posture (ADR-0012 §1 / ADR-0039), split by operation class:
///  - **Ingest (`store`)**: FAIL-SOFT (ADR-0037 shape). A dropped result row
///    is re-derivable operational telemetry (the executions ladder tracks the
///    command; the agent's result is best-effort persisted for the
///    drawer/TAR). Never blocks the gRPC thread. Drops counted
///    (`yuzu_server_response_ingest_dropped_total{reason}`).
///  - **Reads** (`query`/`query_by_execution`/`get_by_instruction`/
///    `query_by_ids`/`aggregate`/`distinct_agent_ids`/`facet_values`/
///    `facet_agent_ids`/`facet_response_ids`): degrade-distinguishable at the
///    seam (`std::optional<std::vector<...>>`, nullopt = degrade) +
///    `yuzu_server_response_read_degrade_total{reason,source}` + a sampled
///    log. NOT the catastrophic-read class — these feed the executions
///    drawer / TAR dashboard, not an enforce/target/authz decision, so
///    consumers may render degraded (503 on the REST twin, empty +
///    degrade-banner on the dashboard) — but the seam MUST distinguish empty
///    from degraded. The #1634 group-scoped-read seam (`ResponseQuery{
///    .agent_id}`) is preserved exactly.
///  - **`finalize_terminal_status` / a future `delete_by_instruction`**:
///    fail-hard — the existing tri-state `FinalizeResult` already
///    distinguishes "updated" / "no matching row" / "SQL error"; ported via
///    `RETURNING` (no `sqlite3_changes()`).
///  - **Backfill**: SKIPPABLE (ADR-0009's skippable class) — responses are
///    TTL'd operational data, not authoritative config or compliance
///    evidence. No `migrate_from_sqlite`; the legacy `response.db` is never
///    read. See ADR-0039.

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace yuzu {
class MetricsRegistry;
}

namespace yuzu::server::pg {
class PgPool;
}

namespace yuzu::server {

struct StoredResponse {
    int64_t id{0};
    std::string instruction_id;
    std::string agent_id;
    int64_t timestamp{0}; // epoch seconds
    /// Server-side ingest wall-clock in epoch milliseconds (UAT
    /// 2026-05-06 #10). Stamped by ResponseStore::store at insert time
    /// so the executions drawer's per-agent row can render the actual
    /// arrival time instead of the agent-claimed timestamp. Legacy
    /// rows (pre-v3) read 0; renderers fall back to `timestamp * 1000`.
    int64_t received_at_ms{0};
    int status{0}; // CommandResponse::Status enum value
    std::string output;
    std::string error_detail;
    int64_t ttl_expires_at{0}; // 0 = use default retention
    std::string plugin;        // plugin name (for schema lookup + facets)
    /// Execution row id (from `executions.id`) that produced this response.
    /// Empty for legacy rows (pre-PR-2) and for out-of-band dispatch paths
    /// (CLI / direct gRPC) that don't go through the workflow routes.
    /// Populated by the in-memory command_id→execution_id mapping in
    /// AgentServiceImpl when a response arrives. Indexed via
    /// idx_resp_execution_ts for the `query_by_execution` exact-correlation
    /// path; legacy callers continue to use `query()` keyed by
    /// instruction_id+timestamp window.
    std::string execution_id;
};

/// A facet value from the response_facets index.
struct FacetValue {
    std::string value;
    int64_t line_count{0}; // total lines across responses with this value
};

/// Filter criteria for faceted queries.
struct FacetFilter {
    int col_idx{-1};   // column index (0-based, excl. Agent column)
    std::string value; // exact match
};

struct ResponseQuery {
    std::string agent_id;
    int status{-1};   // -1 = any
    int64_t since{0}; // epoch seconds, 0 = no lower bound
    int64_t until{0}; // epoch seconds, 0 = no upper bound
    int limit{100};
    int offset{0};
};

/// Management-group scope filter for `aggregate()` (#1634) — a DEDICATED
/// parameter, deliberately NOT a field on `ResponseQuery`. A folded aggregate
/// cannot be post-filtered, so the caller's in-scope agent set is pushed into
/// the WHERE clause; the row-returning readers (`query`/`query_by_execution`)
/// post-filter instead and never consult this, so keeping it off the shared
/// query struct removes the trap of a `query()` caller silently getting no
/// scoping from a field the row path ignores (governance #1634 architect review).
///   * `nullopt`           = no scoping (legacy-open / RBAC-disabled / global
///                           operator — totals over all agents, any scale).
///   * engaged + NON-empty = restrict to `agent_id IN (the set)`.
///   * engaged + EMPTY     = the operator can see none → ZERO rows (`AND 1=0`),
///                           never a silent unfiltered read (also the fail-closed
///                           sink for a corrupt RBAC store / a store-read error).
using AggregateScope = std::optional<std::vector<std::string>>;

enum class AggregateOp { Count, Sum, Avg, Min, Max };

struct AggregationQuery {
    std::string group_by; // "status" or "agent_id"
    AggregateOp op{AggregateOp::Count};
    std::string op_column; // column for sum/avg/min/max
};

struct AggregationResult {
    std::string group_value;
    int64_t count{0};
    double aggregate_value{0.0};
};

/// Default retention (days) — matches the pre-migration SQLite default.
inline constexpr int kDefaultResponseRetentionDays = 90;

class ResponseStore {
public:
    /// Borrows the shared pool and runs the `response_store` schema
    /// migration on a pinned lease. `is_open()` is false if the lease was
    /// empty or the migration failed.
    explicit ResponseStore(pg::PgPool& pool, int retention_days = kDefaultResponseRetentionDays);

    ResponseStore(const ResponseStore&) = delete;
    ResponseStore& operator=(const ResponseStore&) = delete;

    [[nodiscard]] bool is_open() const noexcept { return open_; }

    /// Wire a metrics registry for `yuzu_server_response_read_degrade_total{reason,source}`
    /// (degrade-distinguishable reads), `yuzu_server_response_ingest_dropped_total{reason}`
    /// (fail-soft ingest) and `yuzu_server_response_reap_passes_total{result}` (the
    /// retention sweep). Set ONCE during single-threaded startup, before serving
    /// — the pointer is read without synchronisation on serving threads. A null
    /// registry (default, e.g. unit tests) disables emission; every emit site is
    /// null-guarded.
    void set_metrics(yuzu::MetricsRegistry* m) noexcept { metrics_ = m; }

    /// Fail-soft ingest: a response row + its derived facet rows (from the
    /// plugin output schema). A lease/transaction/insert failure is logged +
    /// counted (`yuzu_server_response_ingest_dropped_total{reason}`), never
    /// throws, never blocks the gRPC thread. The response INSERT and every
    /// per-facet INSERT run in ONE transaction; each facet INSERT is wrapped
    /// in its OWN SAVEPOINT so a single malformed facet value cannot abort
    /// the whole transaction and lose the response row too (Postgres aborts
    /// the WHOLE transaction on any failed statement, unlike SQLite — the
    /// ADR-0038 lesson). A facet failure is logged and the pass continues;
    /// only the response INSERT failing aborts the whole call.
    void store(const StoredResponse& resp);

    /// Tri-state outcome of `finalize_terminal_status` so callers can
    /// distinguish "we updated rows in place" from "no matching RUNNING
    /// row exists" from "the SQL itself errored". Conflating the latter
    /// two (bool return) caused UP-3 / chaos CH-1 — under a transient
    /// failure the caller fell through to insert and re-created the
    /// empty-output sentinel that the original UAT-#11 fix removed.
    enum class FinalizeResult {
        Updated, ///< 1+ rows had their status changed; do NOT also insert.
        NoRow,   ///< 0 rows matched; caller should insert the terminal frame.
        Error,   ///< SQL/lease failed; caller should log, NOT insert.
    };

    /// Update existing RUNNING `responses` rows' status when a terminal
    /// CommandResponse frame (SUCCESS / FAILURE / TIMEOUT / REJECTED)
    /// arrives carrying no output — the data already lives in the prior
    /// RUNNING row(s). Fail-hard (RETURNING, no `sqlite3_changes()`).
    /// Scope is (instruction_id, agent_id, execution_id, status=0). The
    /// execution_id match preserves the PR-2 invariant that re-mapped
    /// command_ids (retry under a new execution row) don't fold a
    /// terminal frame back onto rows tagged with the old execution_id.
    /// Empty execution_id matches empty (legacy / out-of-band callers).
    FinalizeResult finalize_terminal_status(const std::string& instruction_id,
                                            const std::string& agent_id, int terminal_status,
                                            const std::string& error_detail,
                                            const std::string& execution_id);

    /// Degrade-distinguishable read: `std::nullopt` on a store/pool/query
    /// failure (see the file header's posture note); an engaged EMPTY vector
    /// is a genuine "no rows" result.
    [[nodiscard]] std::optional<std::vector<StoredResponse>>
    query(const std::string& instruction_id, const ResponseQuery& q = {}) const;
    /// Exact-correlation lookup keyed on `execution_id` (PR 2). Empty
    /// `execution_id` is rejected (returns an engaged empty vector, NOT
    /// nullopt) — that sentinel is the legacy path; callers must fall back
    /// to `query()` if they support pre-PR-2 data.
    [[nodiscard]] std::optional<std::vector<StoredResponse>>
    query_by_execution(const std::string& execution_id, const ResponseQuery& q = {}) const;
    [[nodiscard]] std::optional<std::vector<StoredResponse>>
    get_by_instruction(const std::string& instruction_id) const;
    [[nodiscard]] std::optional<std::vector<AggregationResult>>
    aggregate(const std::string& instruction_id, const AggregationQuery& aq,
             const ResponseQuery& filter = {}, const AggregateScope& scope = std::nullopt) const;
    /// Distinct agent_ids that have a response row for this instruction,
    /// ordered by agent_id (deterministic). Used to resolve a management-group
    /// scoped aggregate (#1634): enumerate the candidates, keep only those the
    /// per-agent scope predicate admits, then pass the survivors back as the
    /// `aggregate()` `scope` argument so the WHERE clause excludes out-of-scope
    /// rows from the totals. Bounded by one instruction's fan-out.
    ///
    /// Returns `nullopt` on a store-read error — DISTINCT from an empty
    /// vector (the instruction genuinely has no rows). The caller MUST fail
    /// closed on `nullopt` (scope to the empty set → zero rows), never treat
    /// an errored read as "no agents to drop" → unrestricted (governance
    /// #1634 unhappy-path UP-2).
    [[nodiscard]] std::optional<std::vector<std::string>>
    distinct_agent_ids(const std::string& instruction_id) const;
    /// Total response count. Degrades to 0 (matches the pre-migration
    /// contract; not in the ADR-0039 optional-wrapped set — this is an
    /// operator-facing gauge, not a fan-out/authz decision input).
    [[nodiscard]] std::size_t total_count() const;

    // -- Faceted queries (for dashboard filtering at scale) --------------------

    /// Distinct facet values for a column within an instruction's results.
    [[nodiscard]] std::optional<std::vector<FacetValue>>
    facet_values(const std::string& instruction_id, int col_idx) const;

    /// Distinct agent IDs that have a matching facet value.
    [[nodiscard]] std::optional<std::vector<std::string>>
    facet_agent_ids(const std::string& instruction_id,
                    const std::vector<FacetFilter>& filters) const;

    /// Count of distinct agents matching facet filters. Degrades to 0 (scalar
    /// convenience read, not in the ADR-0039 optional-wrapped vector set).
    [[nodiscard]] int64_t facet_agent_count(const std::string& instruction_id,
                                            const std::vector<FacetFilter>& filters) const;

    /// Total result line count matching facet filters. Degrades to 0 (same
    /// convenience-scalar posture as facet_agent_count).
    [[nodiscard]] int64_t facet_line_count(const std::string& instruction_id,
                                           const std::vector<FacetFilter>& filters) const;

    /// Load specific responses by their IDs (for two-phase filtered display).
    [[nodiscard]] std::optional<std::vector<StoredResponse>>
    query_by_ids(const std::vector<int64_t>& response_ids) const;

    /// Response IDs that match all given facet filters.
    [[nodiscard]] std::optional<std::vector<int64_t>>
    facet_response_ids(const std::string& instruction_id, const std::vector<FacetFilter>& filters,
                       int limit = 200, int offset = 0) const;

    /// Clock-guarded retention sweep (#2496 `gc_sweep` shape — ADR-0038's
    /// port to this store, ADR-0039). Called from the server's maintenance
    /// tick (~60-minute cadence, matching the old background thread's
    /// default `cleanup_interval_min`). One sweeping replica at a time via
    /// `pg_try_advisory_xact_lock`; a durable `gc_meta` reading + anomaly-
    /// fact-set guards against a skewed wall clock mass-expiring live rows.
    /// `response_facets` rows are removed via `ON DELETE CASCADE` from
    /// `responses` — a single DELETE on `responses` reaps both tables.
    /// Emits `yuzu_server_response_reap_passes_total{result=swept|noop|
    /// declined|failed|skipped_lock}`.
    void reap_expired();

    /// Cumulative responses reaped (lock-free counter for Prometheus scraping
    /// / test observability) — the disposal-evidence twin of the reap-pass
    /// metric, mirrors GuaranteedStateStore's `events_reaped_total()`.
    [[nodiscard]] uint64_t responses_reaped_total() const noexcept {
        return responses_reaped_.load();
    }

private:
    pg::PgPool& pool_;
    bool open_{false};
    int retention_days_;
    yuzu::MetricsRegistry* metrics_{nullptr};
    std::atomic<uint64_t> responses_reaped_{0};

    int64_t compute_ttl_epoch() const;
};

} // namespace yuzu::server
