#pragma once

#include <sqlite3.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <filesystem>
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
    int status{0};        // CommandResponse::Status enum value
    std::string output;
    std::string error_detail;
    int64_t ttl_expires_at{0}; // 0 = use default retention
    std::string plugin;        // plugin name (for schema lookup + facets)
};

/// A facet value from the response_facets index.
struct FacetValue {
    std::string value;
    int64_t line_count{0}; // total lines across responses with this value
};

/// Filter criteria for faceted queries.
struct FacetFilter {
    int col_idx{-1};        // column index (0-based, excl. Agent column)
    std::string value;      // exact match
};

struct ResponseQuery {
    std::string agent_id;
    int status{-1};   // -1 = any
    int64_t since{0}; // epoch seconds, 0 = no lower bound
    int64_t until{0}; // epoch seconds, 0 = no upper bound
    int limit{100};
    int offset{0};
};

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
    std::vector<StoredResponse> query(const std::string& instruction_id,
                                      const ResponseQuery& q = {}) const;
    std::vector<StoredResponse> get_by_instruction(const std::string& instruction_id) const;
    std::vector<AggregationResult> aggregate(const std::string& instruction_id,
                                             const AggregationQuery& aq,
                                             const ResponseQuery& filter = {}) const;
    std::size_t total_count() const;
    std::uintmax_t db_size_bytes() const;

    // -- Faceted queries (for dashboard filtering at scale) --------------------

    /// Distinct facet values for a column within an instruction's results.
    std::vector<FacetValue> facet_values(const std::string& instruction_id,
                                         int col_idx) const;

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
    sqlite3_stmt* facet_insert_stmt_{nullptr};  // Cached prepared INSERT for facets
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
