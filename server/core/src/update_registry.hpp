#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

#include <sqlite3.h>

namespace yuzu::server {

struct UpdatePackage {
    std::string platform;           // "windows", "linux", "darwin"
    std::string arch;               // "x86_64", "aarch64"
    std::string version;            // "0.2.0+87"
    std::string sha256;             // hex-encoded SHA-256
    std::string filename;           // "yuzu-agent-0.2.0-x64-windows.exe"
    bool        mandatory{false};
    int         rollout_pct{100};   // 0-100
    std::string uploaded_at;        // ISO 8601
    int64_t     file_size{0};
};

class UpdateRegistry {
public:
    explicit UpdateRegistry(const std::filesystem::path& db_path,
                            const std::filesystem::path& update_dir);
    ~UpdateRegistry();

    UpdateRegistry(const UpdateRegistry&) = delete;
    UpdateRegistry& operator=(const UpdateRegistry&) = delete;

    bool is_open() const;

    void upsert_package(const UpdatePackage& pkg);
    void remove_package(const std::string& platform, const std::string& arch,
                        const std::string& version);
    std::vector<UpdatePackage> list_packages() const;
    std::optional<UpdatePackage> latest_for(const std::string& platform,
                                            const std::string& arch) const;

    /// Deterministic rollout: hash(agent_id) % 100 < rollout_pct
    static bool is_eligible(const std::string& agent_id, int rollout_pct);

    std::filesystem::path binary_path(const UpdatePackage& pkg) const;

private:
    sqlite3* db_{nullptr};
    std::filesystem::path update_dir_;
    void create_tables();
};

}  // namespace yuzu::server
