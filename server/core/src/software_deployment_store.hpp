#pragma once

#include <sqlite3.h>

#include <cstdint>
#include <expected>
#include <filesystem>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <vector>

namespace yuzu::server {

struct SoftwarePackage {
    std::string id;
    std::string name;
    std::string version;
    std::string platform;         // "windows", "linux", "darwin"
    std::string installer_type;   // "msi", "deb", "rpm", "pkg", "script"
    std::string content_hash;     // SHA-256 of installer
    std::string content_url;      // content_dist URL or local path
    std::string silent_args;      // e.g. "/qn /norestart"
    std::string verify_command;   // post-install verification command
    std::string rollback_command; // rollback command
    int64_t size_bytes{0};
    int64_t created_at{0};
    std::string created_by;
};

struct SoftwareDeployment {
    std::string id;
    std::string package_id;
    std::string scope_expression;
    std::string status; // "staged","deploying","verifying","completed","rolled_back","failed","cancelled"
    std::string created_by;
    int64_t created_at{0};
    int64_t started_at{0};
    int64_t completed_at{0};
    int agents_targeted{0};
    int agents_success{0};
    int agents_failure{0};
};

struct AgentDeploymentStatus {
    std::string deployment_id;
    std::string agent_id;
    std::string status; // "pending","downloading","installing","verifying","success","failed","rolled_back"
    int64_t started_at{0};
    int64_t completed_at{0};
    std::string error;
};

class SoftwareDeploymentStore {
public:
    explicit SoftwareDeploymentStore(const std::filesystem::path& db_path);
    ~SoftwareDeploymentStore();

    SoftwareDeploymentStore(const SoftwareDeploymentStore&) = delete;
    SoftwareDeploymentStore& operator=(const SoftwareDeploymentStore&) = delete;

    bool is_open() const;

    // Packages
    std::expected<std::string, std::string> create_package(const SoftwarePackage& pkg);
    std::vector<SoftwarePackage> list_packages() const;
    std::optional<SoftwarePackage> get_package(const std::string& id) const;
    bool delete_package(const std::string& id);

    // Deployments
    std::expected<std::string, std::string> create_deployment(const SoftwareDeployment& dep);
    std::vector<SoftwareDeployment> list_deployments(const std::string& status = {}) const;
    std::optional<SoftwareDeployment> get_deployment(const std::string& id) const;
    bool start_deployment(const std::string& id);
    bool cancel_deployment(const std::string& id);
    bool rollback_deployment(const std::string& id);
    void update_agent_status(const std::string& deployment_id, const AgentDeploymentStatus& status);
    void refresh_counts(const std::string& deployment_id);
    std::vector<AgentDeploymentStatus> get_agent_statuses(const std::string& deployment_id) const;
    int active_count() const;

private:
    sqlite3* db_{nullptr};
    mutable std::shared_mutex mtx_;
    void create_tables();
};

} // namespace yuzu::server
