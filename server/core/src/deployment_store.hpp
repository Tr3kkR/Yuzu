#pragma once

#include <sqlite3.h>

#include <cstdint>
#include <expected>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::server {

struct DeploymentJob {
    std::string id;
    std::string target_host;
    std::string os;          // "windows", "linux", "darwin"
    std::string method;      // "ssh", "group_policy", "manual"
    std::string status;      // "pending", "running", "completed", "failed", "cancelled"
    int64_t created_at{0};   // epoch seconds
    int64_t started_at{0};   // epoch seconds, 0 = not started
    int64_t completed_at{0}; // epoch seconds, 0 = not completed
    std::string error;       // error message if failed
};

class DeploymentStore {
public:
    explicit DeploymentStore(const std::filesystem::path& db_path);
    ~DeploymentStore();

    DeploymentStore(const DeploymentStore&) = delete;
    DeploymentStore& operator=(const DeploymentStore&) = delete;

    bool is_open() const;

    // ── Job management ────────────────────────────────────────────────────
    std::expected<std::string, std::string> create_job(const std::string& target_host,
                                                        const std::string& os,
                                                        const std::string& method);
    std::vector<DeploymentJob> list_jobs() const;
    std::optional<DeploymentJob> get_job(const std::string& id) const;
    std::expected<void, std::string> update_status(const std::string& id,
                                                    const std::string& status,
                                                    const std::string& error = {});
    std::expected<void, std::string> cancel_job(const std::string& id);

private:
    sqlite3* db_{nullptr};
    void create_tables();
    static std::string generate_id();
};

} // namespace yuzu::server
