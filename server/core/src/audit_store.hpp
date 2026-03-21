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
    std::string result; // "success", "failure", "denied"
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

    void start_cleanup();
    void stop_cleanup();

private:
    sqlite3* db_{nullptr};
    int retention_days_;
    int cleanup_interval_min_;
    mutable std::shared_mutex mtx_;
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
