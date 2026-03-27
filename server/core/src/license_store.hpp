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

struct License {
    std::string id;
    std::string organization;
    int64_t seat_count{0};
    int64_t seats_used{0};  // computed at runtime
    int64_t issued_at{0};
    int64_t expires_at{0};  // 0 = perpetual
    std::string edition;    // "community", "professional", "enterprise"
    std::string features_json; // JSON array of feature flags
    std::string status;     // "active", "expired", "exceeded", "invalid"
};

struct LicenseAlert {
    int64_t id{0};
    std::string license_id;
    std::string alert_type;  // "expiry_warning", "seat_limit_warning", "expired", "exceeded"
    std::string message;
    int64_t triggered_at{0};
    bool acknowledged{false};
};

class LicenseStore {
public:
    explicit LicenseStore(const std::filesystem::path& db_path);
    ~LicenseStore();

    LicenseStore(const LicenseStore&) = delete;
    LicenseStore& operator=(const LicenseStore&) = delete;

    bool is_open() const;

    // License CRUD
    std::expected<std::string, std::string> activate_license(const License& license,
                                                              const std::string& license_key);
    std::vector<License> list_licenses() const;
    std::optional<License> get_active_license() const;
    bool remove_license(const std::string& id);

    // Validation
    void validate(int64_t current_agent_count);
    std::string get_status() const;

    // Alerts
    std::vector<LicenseAlert> list_alerts(bool unacknowledged_only = false) const;
    bool acknowledge_alert(int64_t alert_id);

    // Feature check
    bool has_feature(const std::string& feature) const;
    int64_t seat_count() const;
    int64_t days_remaining() const;

private:
    sqlite3* db_{nullptr};
    mutable std::shared_mutex mtx_;
    void create_tables();
    void add_alert(const std::string& license_id, const std::string& type, const std::string& message);
    std::string hash_key(const std::string& raw) const;
};

} // namespace yuzu::server
