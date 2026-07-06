#pragma once

#include <sqlite3.h>

#include <cstddef>
#include <filesystem>
#include <shared_mutex>
#include <string>
#include <vector>

namespace yuzu::server {

// One CPE `cpeMatch` node: a product identity plus its vulnerable version
// range. All fields may be empty; an empty/`*`/`-` cpe_version with no bounds
// means "all versions of this product". Mirrors NVD's cpeMatch shape.
struct CpeMatch {
    std::string cpe_vendor;  // normalized lowercase
    std::string cpe_product; // normalized lowercase
    std::string cpe_version; // exact CPE version field ('*'/'-'/'' = any)
    std::string version_start_including;
    std::string version_start_excluding;
    std::string version_end_including;
    std::string version_end_excluding;
    bool is_vulnerable = true;
};

// One CVE: header metadata plus the set of affected product/version matches.
// `matches` is empty for a CVE with no CPE configuration (header-only).
struct CveRecord {
    std::string cve_id;
    std::string severity; // CRITICAL, HIGH, MEDIUM, LOW
    std::string description;
    std::string published;     // ISO 8601
    std::string last_modified; // ISO 8601
    std::string source;        // "nvd" or "builtin"
    std::vector<CpeMatch> matches;
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
    // Batch upsert in one transaction. Returns false if the batch was NOT fully
    // persisted — BEGIN/COMMIT failed, or any record rolled back to its prior state.
    // Callers that advance a resume cursor MUST check this and hold the cursor on
    // false, or they skip past fetched-but-unpersisted CVEs (#1889 review r4).
    [[nodiscard]] bool upsert_cves(const std::vector<CveRecord>& records);
    std::vector<CveMatch> match_inventory(const std::vector<SoftwareItem>& inventory) const;

    // Sync metadata
    std::string get_meta(const std::string& key) const;
    void set_meta(const std::string& key, const std::string& value);

    // Seed with built-in rules
    void seed_builtin_rules();

    std::size_t total_cve_count() const;
    // Count of real NVD-sourced CVEs only (source='nvd'), excluding the built-in
    // fallback rules seeded at startup. Completion/recovery checks must use THIS, not
    // total_cve_count(), or seeded builtins masquerade as a populated mirror
    // (#1889 review r4).
    std::size_t nvd_cve_count() const;

private:
    sqlite3* db_ = nullptr;
    mutable std::shared_mutex mtx_; // protects db_ access
    void create_tables();

    // Internal variants called under existing lock (no re-lock).
    // upsert_cve_impl is atomic per CVE (savepoint) and returns false if the
    // CVE was rolled back, leaving its prior match set intact (governance UP-1).
    bool upsert_cve_impl(const CveRecord& record);
    // Returns false if the batch was not fully persisted (see upsert_cves).
    bool upsert_cves_impl(const std::vector<CveRecord>& records);
};

/// Compare two version strings numerically (e.g. "1.10.0" > "1.9.0").
/// Returns <0 if a < b, 0 if equal, >0 if a > b.
int compare_versions(std::string_view a, std::string_view b);

} // namespace yuzu::server
