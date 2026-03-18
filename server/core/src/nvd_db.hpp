#pragma once

#include <sqlite3.h>

#include <cstddef>
#include <filesystem>
#include <string>
#include <vector>

namespace yuzu::server {

struct CveRecord {
    std::string cve_id;
    std::string product; // normalized lowercase product name
    std::string vendor;
    std::string affected_below; // versions below this are vulnerable
    std::string fixed_in;
    std::string severity; // CRITICAL, HIGH, MEDIUM, LOW
    std::string description;
    std::string published;     // ISO 8601
    std::string last_modified; // ISO 8601
    std::string source;        // "nvd" or "builtin"
};

struct SoftwareItem {
    std::string name;
    std::string version;
};

struct CveMatch {
    std::string cve_id;
    std::string severity;
    std::string description;
    std::string product;
    std::string installed_version;
    std::string fixed_in;
    std::string source; // "nvd" or "builtin"
};

class NvdDatabase {
public:
    explicit NvdDatabase(const std::filesystem::path& db_path);
    ~NvdDatabase();

    NvdDatabase(const NvdDatabase&) = delete;
    NvdDatabase& operator=(const NvdDatabase&) = delete;

    bool is_open() const;
    void upsert_cve(const CveRecord& record);
    void upsert_cves(const std::vector<CveRecord>& records); // batch in transaction
    std::vector<CveMatch> match_inventory(const std::vector<SoftwareItem>& inventory) const;

    // Sync metadata
    std::string get_meta(const std::string& key) const;
    void set_meta(const std::string& key, const std::string& value);

    // Seed with built-in rules
    void seed_builtin_rules();

    std::size_t total_cve_count() const;

private:
    sqlite3* db_ = nullptr;
    void create_tables();
};

/// Compare two version strings numerically (e.g. "1.10.0" > "1.9.0").
/// Returns <0 if a < b, 0 if equal, >0 if a > b.
int compare_versions(std::string_view a, std::string_view b);

} // namespace yuzu::server
