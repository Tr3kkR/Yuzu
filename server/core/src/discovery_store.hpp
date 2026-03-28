#pragma once

#include <sqlite3.h>

#include <cstdint>
#include <expected>
#include <filesystem>
#include <optional>
#include <string>
#include <shared_mutex>
#include <vector>

namespace yuzu::server {

struct DiscoveredDevice {
    int64_t id{0};
    std::string ip_address;
    std::string mac_address;
    std::string hostname;
    bool managed{false};      // true if IP matches a known enrolled agent
    std::string agent_id;     // agent_id if managed
    std::string discovered_by; // agent_id of the agent that discovered this device
    int64_t discovered_at{0}; // epoch seconds
    int64_t last_seen{0};     // epoch seconds
    std::string subnet;       // the subnet that was scanned
};

class DiscoveryStore {
public:
    explicit DiscoveryStore(const std::filesystem::path& db_path);
    ~DiscoveryStore();

    DiscoveryStore(const DiscoveryStore&) = delete;
    DiscoveryStore& operator=(const DiscoveryStore&) = delete;

    bool is_open() const;

    // ── Device operations ────────────────────────────────────────────────
    std::expected<void, std::string> upsert_device(const DiscoveredDevice& device);
    std::vector<DiscoveredDevice> list_devices(const std::string& subnet_filter = {}) const;
    std::optional<DiscoveredDevice> get_device(const std::string& ip_address) const;
    std::expected<void, std::string> mark_managed(const std::string& ip_address,
                                                   const std::string& agent_id);
    std::expected<void, std::string> clear_results(const std::string& subnet = {});

private:
    sqlite3* db_{nullptr};
    mutable std::shared_mutex mtx_; // protects db_ access (G3-ARCH-003)
    void create_tables();
};

} // namespace yuzu::server
