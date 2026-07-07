#pragma once

#include <sqlite3.h>

#include <cstddef>
#include <filesystem>
#include <shared_mutex>
#include <string>
#include <utility>
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

// A typed CPE identity to assess against the local NVD mirror (ADR-0018). Unlike
// SoftwareItem (name-only, used by match_inventory), this carries an optional
// vendor so a product name shared across vendors can be disambiguated.
struct CpeQuery {
    std::string vendor;              // may be empty; lowercased inside assess()
    std::string product;             // required; lowercased + LIKE-escaped inside assess()
    std::string version;             // installed version; '' => no hit passes the range check
    bool exact_product = true;       // true: cpe_product = ?  |  false: LIKE 'x%'
};

// One in-range CVE hit for a CpeQuery. `description` is carried because the
// cve JOIN was already paid; `fixed_in` is best-effort (the exclusive upper
// bound of the matched range) and may be empty.
struct CveHit {
    std::string cve_id;
    std::string severity;    // cve.severity
    std::string description; // cve.description
    std::string published;   // cve.published
    std::string fixed_in;    // version_end_excluding; best-effort, may be empty
};

// The result of assess(): whether the product identity is known to the mirror
// (>=1 is_vulnerable=1 row) and the deduped subset of CVEs whose range contains
// the installed version. product_known=true with an empty hits vector is the
// "assessed clean" shape; product_known=false means the mirror has no vulnerable
// data for this identity (do NOT read as clean).
struct AssessResult {
    bool product_known = false;
    std::vector<CveHit> hits;
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
    // changed_ids is the freshness/feed delta ONLY. Backfill MUST pass nullptr and MUST
    // NOT drive the feed trigger (it has its own trigger, ADR-0023 Decision 6d). When
    // non-null it is filled with the deduped set of cve_ids successfully persisted this
    // batch (in-loop from the per-CVE success bool — never sqlite3_changes(), #1033).
    // CAUTION for a future feed-trigger consumer (ADR-0023 Decision 6d): changed_ids is
    // cleared on an outer-commit failure; it may still be non-empty when the bool is
    // false ONLY in the per-record SAVEPOINT-rollback-within-a-committed-batch case
    // (those ids DID commit). A per-CVE SAVEPOINT rollback fails one record while the
    // surrounding batch still commits the rest — the ids already in changed_ids DID
    // commit. So a consumer must decide its own policy for that false case (e.g. still
    // emit the committed delta, or discard and re-derive next pass); it must NOT assume
    // false ⇒ changed_ids is meaningless. do_freshness discards on false today, so this
    // is latent, not a live bug.
    [[nodiscard]] bool upsert_cves(const std::vector<CveRecord>& records,
                                   std::vector<std::string>* changed_ids = nullptr);
    std::vector<CveMatch> match_inventory(const std::vector<SoftwareItem>& inventory) const;

    // Assess a single typed CPE identity against the mirror. Read-only (shared lock).
    // See CpeQuery/AssessResult. The is_vulnerable=1 filter is load-bearing: a plain
    // "any row" would count is_vulnerable=0 platform operands and fabricate an
    // assessed-clean verdict for a product that is only ever a running-on node.
    //
    // Throws std::runtime_error on a SQLite prepare/step error so the caller can
    // distinguish a DB fault from a genuine no-rows/absent result — a caller MUST NOT
    // treat a DB fault as assessed-clean/not-assessed. (The future PR-4 correlation
    // engine wraps each agent's assess() calls in try/catch and ABORTS that agent on a
    // throw, never recording a clean verdict for a DB fault.)
    AssessResult assess(const CpeQuery& q) const;

    // The DISTINCT (vendor, product) identities carried by is_vulnerable=1 match rows
    // for the given cve_ids. Empty input → empty result. Chunked (<=500 ids/query) with
    // cross-chunk dedup (SQL DISTINCT is per-chunk only).
    std::vector<std::pair<std::string, std::string>>
    products_for_cves(const std::vector<std::string>& cve_ids) const;

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
    bool upsert_cves_impl(const std::vector<CveRecord>& records,
                          std::vector<std::string>* changed_ids = nullptr);
};

/// Compare two version strings numerically (e.g. "1.10.0" > "1.9.0").
/// Returns <0 if a < b, 0 if equal, >0 if a > b.
int compare_versions(std::string_view a, std::string_view b);

} // namespace yuzu::server
