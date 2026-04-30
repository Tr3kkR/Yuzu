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

struct AuditEvent {
    int64_t id{0};
    int64_t timestamp{0}; // epoch seconds
    std::string principal;
    std::string principal_role;
    std::string action;
    std::string target_type;
    std::string target_id;
    std::string detail;
    std::string source_ip;
    std::string user_agent;
    std::string session_id;
    std::string result;    // "success", "failure", "denied"
    std::string mcp_tool;  // MCP tool name if action was MCP-initiated (empty otherwise)
};

struct AuditQuery {
    std::string principal;
    std::string action;
    std::string target_type;
    std::string target_id;
    int64_t since{0};
    int64_t until{0};
    int limit{100};
    int offset{0};
};

class AuditStore {
public:
    explicit AuditStore(const std::filesystem::path& db_path, int retention_days = 365,
                        int cleanup_interval_min = 60);
    ~AuditStore();

    AuditStore(const AuditStore&) = delete;
    AuditStore& operator=(const AuditStore&) = delete;

    bool is_open() const;

    void log(const AuditEvent& event);
    std::vector<AuditEvent> query(const AuditQuery& q = {}) const;
    std::size_t total_count() const;

    /// Cumulative audit-event write counts grouped by `result` value. Exposed for
    /// Prometheus scraping; reset at process start. Lock-free reads.
    uint64_t events_written(const std::string& result) const noexcept;

    /// Cumulative count of audit events that failed to persist (sqlite3_step
    /// did not return SQLITE_DONE). Audit pipeline degradation is a SOC 2
    /// CC7.2 evidence-chain risk; surface it on /metrics so operators can
    /// page on a non-zero rate.
    uint64_t emit_failed_count() const noexcept {
        return emit_failed_.load(std::memory_order_relaxed);
    }

    void start_cleanup();
    void stop_cleanup();

private:
    sqlite3* db_{nullptr};
    int retention_days_;
    int cleanup_interval_min_;
    mutable std::shared_mutex mtx_;

    // Cumulative event write counters bucketed by `result` field. Lock-free.
    std::atomic<uint64_t> events_success_{0};
    std::atomic<uint64_t> events_failure_{0};
    std::atomic<uint64_t> events_denied_{0};
    std::atomic<uint64_t> events_other_{0};
    // Persistence-failure counter: rows where the INSERT step returned
    // anything other than SQLITE_DONE.
    std::atomic<uint64_t> emit_failed_{0};
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
