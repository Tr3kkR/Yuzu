#pragma once

#include <sqlite3.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <shared_mutex>
#include <string>
#include <thread>
#include <vector>

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

class ResponseStore {
public:
    explicit ResponseStore(const std::filesystem::path& db_path, int retention_days = 90,
                           int cleanup_interval_min = 60);
    ~ResponseStore();

    ResponseStore(const ResponseStore&) = delete;
    ResponseStore& operator=(const ResponseStore&) = delete;

    bool is_open() const;

    void store(const StoredResponse& resp);

    /// Tri-state outcome of `finalize_terminal_status` so callers can
    /// distinguish "we updated rows in place" from "no matching RUNNING
    /// row exists" from "the SQL itself errored". Conflating the latter
    /// two (bool return) caused UP-3 / chaos CH-1 — under SQLITE_BUSY the
    /// caller fell through to insert and re-created the empty-output
    /// sentinel that the original UAT-#11 fix removed.
    enum class FinalizeResult {
        Updated, ///< 1+ rows had their status changed; do NOT also insert.
        NoRow,   ///< 0 rows matched; caller should insert the terminal frame.
        Error,   ///< SQL prepare/step failed; caller should log, NOT insert.
    };

    /// Update existing RUNNING `responses` rows' status when a terminal
    /// CommandResponse frame (SUCCESS / FAILURE / TIMEOUT / REJECTED)
    /// arrives carrying no output — the data already lives in the prior
    /// RUNNING row(s). Without this, the agent_service Subscribe stream
    /// inserts an empty-output row whose non-zero `status` enum value
    /// (1=SUCCESS, 2=FAILURE, …) reads to operators as a failure exit
    /// code that "happened before" the real result row (UAT 2026-05-06).
    ///
    /// Scope is (instruction_id, agent_id, execution_id, status=0). The
    /// execution_id match preserves the PR-2 invariant that re-mapped
    /// command_ids (retry under a new execution row) don't fold a
    /// terminal frame back onto rows tagged with the old execution_id.
    /// Empty execution_id matches empty (legacy / out-of-band callers).
    FinalizeResult finalize_terminal_status(const std::string& instruction_id,
                                            const std::string& agent_id, int terminal_status,
                                            const std::string& error_detail,
                                            const std::string& execution_id);
    std::vector<StoredResponse> query(const std::string& instruction_id,
                                      const ResponseQuery& q = {}) const;
    /// Exact-correlation lookup keyed on the new `execution_id` column
    /// (PR 2). Returns rows whose `execution_id` matches; honours the same
    /// agent_id / status / since / until / limit filters as `query()`.
    /// Empty `execution_id` is rejected (returns no rows) — that sentinel
    /// is the legacy path; callers must fall back to `query()` if they
    /// support pre-PR-2 data. Backed by `idx_resp_execution_ts`.
    std::vector<StoredResponse> query_by_execution(const std::string& execution_id,
                                                   const ResponseQuery& q = {}) const;
    std::vector<StoredResponse> get_by_instruction(const std::string& instruction_id) const;
    std::vector<AggregationResult> aggregate(const std::string& instruction_id,
                                             const AggregationQuery& aq,
                                             const ResponseQuery& filter = {},
                                             const AggregateScope& scope = std::nullopt) const;
    /// Distinct agent_ids that have a response row for this instruction,
    /// ordered by agent_id (deterministic). Used to resolve a management-group
    /// scoped aggregate (#1634): enumerate the candidates, keep only those the
    /// per-agent scope predicate admits, then pass the survivors back as the
    /// `aggregate()` `scope` argument so the WHERE clause excludes out-of-scope
    /// rows from the totals. Bounded by one instruction's fan-out.
    ///
    /// Returns `nullopt` on a store-read error (failed prepare/step) — DISTINCT
    /// from an empty vector (the instruction genuinely has no rows). The caller
    /// MUST fail closed on `nullopt` (scope to the empty set → zero rows), never
    /// treat an errored read as "no agents to drop" → unrestricted (governance
    /// #1634 unhappy-path UP-2: an errored read that looked empty re-opened the
    /// aggregate to all agents).
    std::optional<std::vector<std::string>>
    distinct_agent_ids(const std::string& instruction_id) const;
    std::size_t total_count() const;
    std::uintmax_t db_size_bytes() const;

    // -- Faceted queries (for dashboard filtering at scale) --------------------

    /// Distinct facet values for a column within an instruction's results.
    std::vector<FacetValue> facet_values(const std::string& instruction_id, int col_idx) const;

    /// Distinct agent IDs that have a matching facet value.
    std::vector<std::string> facet_agent_ids(const std::string& instruction_id,
                                             const std::vector<FacetFilter>& filters) const;

    /// Count of distinct agents matching facet filters.
    int64_t facet_agent_count(const std::string& instruction_id,
                              const std::vector<FacetFilter>& filters) const;

    /// Total result line count matching facet filters.
    int64_t facet_line_count(const std::string& instruction_id,
                             const std::vector<FacetFilter>& filters) const;

    /// Load specific responses by their IDs (for two-phase filtered display).
    std::vector<StoredResponse> query_by_ids(const std::vector<int64_t>& response_ids) const;

    /// Response IDs that match all given facet filters.
    std::vector<int64_t> facet_response_ids(const std::string& instruction_id,
                                            const std::vector<FacetFilter>& filters,
                                            int limit = 200, int offset = 0) const;

    void start_cleanup();
    void stop_cleanup();

private:
    sqlite3* db_{nullptr};
    std::filesystem::path db_path_;
    int retention_days_;
    int cleanup_interval_min_;
    mutable std::shared_mutex mtx_;
    sqlite3_stmt* insert_stmt_{nullptr};       // Cached prepared INSERT for responses
    sqlite3_stmt* facet_insert_stmt_{nullptr}; // Cached prepared INSERT for facets
#ifdef __cpp_lib_jthread
    std::jthread cleanup_thread_;
#else
    std::thread cleanup_thread_;
    std::atomic<bool> stop_requested_{false};
#endif

    void create_tables();
    void prepare_insert_stmt();
#ifdef __cpp_lib_jthread
    void run_cleanup(std::stop_token stop);
#else
    void run_cleanup();
#endif
};

} // namespace yuzu::server
