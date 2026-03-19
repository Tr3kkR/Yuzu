#pragma once

#include <sqlite3.h>

#include <cstdint>
#include <expected>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::server {

struct QuarantineRecord {
    std::string agent_id;
    std::string status; // "active" or "released"
    std::string quarantined_by;
    int64_t quarantined_at{0};
    int64_t released_at{0};
    std::string whitelist; // comma-separated IPs
    std::string reason;
};

class QuarantineStore {
public:
    explicit QuarantineStore(const std::filesystem::path& db_path);
    ~QuarantineStore();

    QuarantineStore(const QuarantineStore&) = delete;
    QuarantineStore& operator=(const QuarantineStore&) = delete;

    bool is_open() const;

    // ── Quarantine operations ────────────────────────────────────────────
    std::expected<void, std::string> quarantine_device(const std::string& agent_id,
                                                       const std::string& by,
                                                       const std::string& reason,
                                                       const std::string& whitelist);
    std::expected<void, std::string> release_device(const std::string& agent_id);
    std::optional<QuarantineRecord> get_status(const std::string& agent_id) const;
    std::vector<QuarantineRecord> list_quarantined() const;
    std::vector<QuarantineRecord> get_history(const std::string& agent_id) const;

private:
    sqlite3* db_{nullptr};
    void create_tables();
};

} // namespace yuzu::server
