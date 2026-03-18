#pragma once

#include <sqlite3.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <filesystem>
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

    void start_cleanup();
    void stop_cleanup();

private:
    sqlite3* db_{nullptr};
    std::filesystem::path db_path_;
    int retention_days_;
    int cleanup_interval_min_;
#ifdef __cpp_lib_jthread
    std::jthread cleanup_thread_;
#else
    std::thread cleanup_thread_;
    std::atomic<bool> stop_requested_{false};
#endif

    void create_tables();
#ifdef __cpp_lib_jthread
    void run_cleanup(std::stop_token stop);
#else
    void run_cleanup();
#endif
};

} // namespace yuzu::server
