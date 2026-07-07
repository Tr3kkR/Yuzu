#include "nvd_db.hpp"
#include "migration_runner.hpp"
#include "nvd_version.hpp"
#include "sqlite_raii.hpp"

#include <spdlog/spdlog.h>
#include <sqlite3.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <mutex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace yuzu::server {

// ── Version comparison ───────────────────────────────────────────────────────
// Returns <0 if a<b, 0 if a==b, >0 if a>b.
// Splits on '.' and '-', compares each segment numerically where possible.
// Same algorithm as agents/plugins/vuln_scan/src/cve_rules.hpp.

int compare_versions(std::string_view a, std::string_view b) {
    auto next_segment = [](std::string_view& s) -> std::string_view {
        if (s.empty())
            return {};
        auto pos = s.find_first_of(".-");
        std::string_view seg;
        if (pos == std::string_view::npos) {
            seg = s;
            s = {};
        } else {
            seg = s.substr(0, pos);
            s = s.substr(pos + 1);
        }
        return seg;
    };

    auto to_num = [](std::string_view seg) -> std::pair<bool, long long> {
        if (seg.empty())
            return {true, 0};
        long long val = 0;
        for (char c : seg) {
            if (c < '0' || c > '9')
                return {false, 0};
            val = val * 10 + (c - '0');
        }
        return {true, val};
    };

    std::string_view ra = a, rb = b;
    while (!ra.empty() || !rb.empty()) {
        auto sa = next_segment(ra);
        auto sb = next_segment(rb);

        auto [a_num, a_val] = to_num(sa);
        auto [b_num, b_val] = to_num(sb);

        if (a_num && b_num) {
            if (a_val != b_val)
                return (a_val < b_val) ? -1 : 1;
        } else {
            int cmp = sa.compare(sb);
            if (cmp != 0)
                return cmp;
        }
    }
    return 0;
}

// ── Helper: lowercase a string ───────────────────────────────────────────────

static std::string to_lower(std::string_view sv) {
    std::string result;
    result.reserve(sv.size());
    for (char c : sv) {
        result.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }
    return result;
}

// ── Built-in CVE rules ───────────────────────────────────────────────────────
// Duplicated from agents/plugins/vuln_scan/src/cve_rules.hpp to avoid
// cross-module dependencies. These are constant data that rarely changes.

struct BuiltinRule {
    std::string_view cve_id;
    std::string_view product;
    std::string_view affected_below;
    std::string_view fixed_in;
    std::string_view severity;
    std::string_view description;
};

static constexpr auto kBuiltinRules = std::to_array<BuiltinRule>({
    // OpenSSL
    {"CVE-2014-0160", "openssl", "1.0.1g", "1.0.1g", "CRITICAL",
     "Heartbleed: TLS heartbeat read overrun allows memory disclosure"},
    {"CVE-2022-3602", "openssl", "3.0.7", "3.0.7", "HIGH",
     "X.509 certificate verification buffer overrun"},
    {"CVE-2023-0286", "openssl", "3.0.8", "3.0.8", "HIGH",
     "X.400 address type confusion in X.509 GeneralName"},
    {"CVE-2024-5535", "openssl", "3.3.2", "3.3.2", "MEDIUM",
     "SSL_select_next_proto buffer overread"},

    // curl
    {"CVE-2023-38545", "curl", "8.4.0", "8.4.0", "CRITICAL", "SOCKS5 heap buffer overflow"},
    {"CVE-2023-38546", "curl", "8.4.0", "8.4.0", "LOW", "Cookie injection with none file"},
    {"CVE-2024-2398", "curl", "8.7.1", "8.7.1", "MEDIUM", "HTTP/2 push headers memory leak"},

    // sudo
    {"CVE-2021-3156", "sudo", "1.9.5p2", "1.9.5p2", "CRITICAL",
     "Baron Samedit: heap buffer overflow in sudoedit"},
    {"CVE-2023-22809", "sudo", "1.9.12p2", "1.9.12p2", "HIGH",
     "sudoedit arbitrary file write via user-provided path"},

    // polkit
    {"CVE-2021-4034", "polkit", "0.120", "0.120", "CRITICAL",
     "PwnKit: local privilege escalation via pkexec"},

    // Log4j (Java)
    {"CVE-2021-44228", "log4j", "2.17.0", "2.17.0", "CRITICAL",
     "Log4Shell: remote code execution via JNDI lookup"},
    {"CVE-2021-45046", "log4j", "2.17.0", "2.17.0", "CRITICAL",
     "Log4Shell bypass: incomplete fix in 2.15.0"},

    // Apache HTTP Server
    {"CVE-2021-41773", "apache", "2.4.50", "2.4.50", "CRITICAL",
     "Path traversal and file disclosure"},
    {"CVE-2023-25690", "apache", "2.4.56", "2.4.56", "CRITICAL",
     "HTTP request smuggling via mod_proxy"},

    // OpenSSH
    {"CVE-2024-6387", "openssh", "9.8", "9.8p1", "CRITICAL",
     "regreSSHion: unauthenticated remote code execution"},
    {"CVE-2023-38408", "openssh", "9.3p2", "9.3p2", "HIGH",
     "PKCS#11 provider remote code execution via ssh-agent"},

    // Python
    {"CVE-2023-24329", "python", "3.11.4", "3.11.4", "HIGH",
     "urllib.parse URL parsing bypass via leading whitespace"},
    {"CVE-2024-0450", "python", "3.12.2", "3.12.2", "MEDIUM",
     "zipfile quoted-overlap zipbomb protection bypass"},

    // Node.js
    {"CVE-2023-44487", "node", "20.8.1", "20.8.1", "HIGH", "HTTP/2 Rapid Reset denial of service"},
    {"CVE-2024-22019", "node", "20.11.1", "20.11.1", "HIGH",
     "Reading unprocessed HTTP request with unbounded chunk extension"},

    // Google Chrome
    {"CVE-2024-0519", "chrome", "120.0.6099.225", "120.0.6099.225", "HIGH",
     "V8 out-of-bounds memory access"},
    {"CVE-2024-4671", "chrome", "124.0.6367.202", "124.0.6367.202", "HIGH",
     "Visuals use-after-free"},

    // Mozilla Firefox
    {"CVE-2024-29944", "firefox", "124.0.1", "124.0.1", "CRITICAL",
     "Privileged JavaScript execution via event handler"},
    {"CVE-2024-9680", "firefox", "131.0.2", "131.0.2", "CRITICAL",
     "Animation timeline use-after-free"},

    // .NET Runtime
    {"CVE-2024-21319", "dotnet", "8.0.1", "8.0.1", "HIGH",
     "Denial of service via SignedCms degenerate certificates"},
    {"CVE-2024-38168", "dotnet", "8.0.8", "8.0.8", "HIGH", "ASP.NET Core denial of service"},

    // Java / OpenJDK
    {"CVE-2024-20918", "openjdk", "21.0.2", "21.0.2", "HIGH",
     "Hotspot array access bounds check bypass"},
    {"CVE-2024-20952", "openjdk", "21.0.2", "21.0.2", "HIGH",
     "Security manager bypass via Object serialization"},

    // Windows Print Spooler
    {"CVE-2021-34527", "windows", "10.0.19041.1083", "KB5004945", "CRITICAL",
     "PrintNightmare: RCE via Windows Print Spooler"},
    {"CVE-2021-1675", "windows", "10.0.19041.1052", "KB5003637", "CRITICAL",
     "Print Spooler privilege escalation"},

    // nginx
    {"CVE-2022-41741", "nginx", "1.23.2", "1.23.2", "HIGH", "mp4 module memory corruption"},
    {"CVE-2024-7347", "nginx", "1.27.1", "1.27.1", "MEDIUM", "Worker process crash in mp4 module"},

    // PostgreSQL
    {"CVE-2023-5868", "postgresql", "16.1", "16.1", "MEDIUM",
     "Memory disclosure in aggregate function calls"},
    {"CVE-2024-0985", "postgresql", "16.2", "16.2", "HIGH",
     "Non-owner REFRESH MATERIALIZED VIEW CONCURRENTLY executes as owner"},

    // Git
    {"CVE-2024-32002", "git", "2.45.1", "2.45.1", "CRITICAL",
     "RCE via crafted repositories with submodules"},
    {"CVE-2023-25652", "git", "2.40.1", "2.40.1", "HIGH",
     "git apply --reject writes outside worktree"},

    // 7-Zip
    {"CVE-2024-11477", "7-zip", "24.07", "24.07", "HIGH",
     "Zstandard decompression integer underflow RCE"},

    // WinRAR
    {"CVE-2023-38831", "winrar", "6.23", "6.23", "HIGH",
     "Code execution when opening crafted archive"},

    // PuTTY
    {"CVE-2024-31497", "putty", "0.81", "0.81", "CRITICAL",
     "NIST P-521 private key recovery from ECDSA signatures"},

    // PHP
    {"CVE-2024-4577", "php", "8.3.8", "8.3.8", "CRITICAL", "CGI argument injection on Windows"},
    {"CVE-2024-2756", "php", "8.3.4", "8.3.4", "MEDIUM", "Cookie __Host-/__Secure- prefix bypass"},
});

// ── NvdDatabase implementation ───────────────────────────────────────────────

NvdDatabase::NvdDatabase(const std::filesystem::path& db_path) {
    int rc = sqlite3_open_v2(db_path.string().c_str(), &db_,
                             SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                             nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("NvdDatabase: failed to open {}: {}", db_path.string(), sqlite3_errmsg(db_));
        if (db_) {
            sqlite3_close(db_);
            db_ = nullptr;
        }
        return;
    }

    // Enable WAL mode for better concurrent read performance
    char* err_msg = nullptr;
    rc = sqlite3_exec(db_, "PRAGMA journal_mode=WAL;", nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        spdlog::warn("NvdDatabase: WAL mode failed: {}", err_msg ? err_msg : "unknown");
        sqlite3_free(err_msg);
    }
    sqlite3_exec(db_, "PRAGMA busy_timeout=5000;", nullptr, nullptr, nullptr);

    create_tables();
    if (db_)
        spdlog::info("NvdDatabase: opened {}", db_path.string());
}

NvdDatabase::~NvdDatabase() {
    if (db_) {
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

bool NvdDatabase::is_open() const {
    return db_ != nullptr;
}

void NvdDatabase::create_tables() {
    if (!db_)
        return;

    static const std::vector<Migration> kMigrations = {
        {1, R"(
            CREATE TABLE IF NOT EXISTS cve (
                cve_id        TEXT PRIMARY KEY,
                product       TEXT NOT NULL,
                vendor        TEXT,
                affected_below TEXT NOT NULL,
                fixed_in      TEXT,
                severity      TEXT NOT NULL,
                description   TEXT NOT NULL,
                published     TEXT,
                last_modified TEXT,
                source        TEXT DEFAULT 'nvd'
            );

            CREATE INDEX IF NOT EXISTS idx_cve_product ON cve(product);

            CREATE TABLE IF NOT EXISTS sync_meta (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
        )"},
        // v2: normalize CVE + per-cpeMatch version ranges. The v1 flat `cve`
        // table (single `affected_below` upper bound) can't represent NVD's
        // versionStart/End include/exclude ranges, and its cve_id PRIMARY KEY
        // dropped all but the last product row for multi-product CVEs. We drop
        // it and rebuild: `cve` becomes a header (one row per CVE), `cve_match`
        // holds one row per cpeMatch. Existing rows are discarded rather than
        // upconverted — they lack range data and are fully reconstructable from
        // the builtin reseed + the sync that both run on startup. Expect
        // total_cve_count() to read low until the first post-migration sync.
        {2, R"(
            DROP INDEX IF EXISTS idx_cve_product;
            DROP TABLE IF EXISTS cve;

            -- The catalog reset must also reset the sync cursor: a preserved
            -- last_sync_time would send the next sync down the incremental path
            -- (do_incremental_sync -> fetch_modified_since), and the dropped,
            -- since-unmodified CVEs would never be re-fetched — silently gone
            -- from /api/nvd/match forever. Clearing it forces the full initial
            -- sync the "fully reconstructable / self-healing" contract promises.
            DELETE FROM sync_meta WHERE key = 'last_sync_time';

            CREATE TABLE IF NOT EXISTS cve (
                cve_id        TEXT PRIMARY KEY,
                severity      TEXT NOT NULL,
                description   TEXT NOT NULL,
                published     TEXT,
                last_modified TEXT,
                source        TEXT DEFAULT 'nvd'
            );

            CREATE TABLE IF NOT EXISTS cve_match (
                id                      INTEGER PRIMARY KEY,
                cve_id                  TEXT NOT NULL,
                cpe_vendor              TEXT,
                cpe_product             TEXT NOT NULL,
                cpe_version             TEXT,
                version_start_including TEXT,
                version_start_excluding TEXT,
                version_end_including   TEXT,
                version_end_excluding   TEXT,
                is_vulnerable           INTEGER DEFAULT 1
            );

            CREATE INDEX IF NOT EXISTS idx_cve_match_product ON cve_match(cpe_product);
            CREATE INDEX IF NOT EXISTS idx_cve_match_cveid   ON cve_match(cve_id);
        )"},
        // v2's idx_cve_match_product is BINARY-collated, but match_inventory
        // filters with a case-insensitive `LIKE 'name%'`. SQLite only uses an
        // index for a LIKE prefix when the index collation matches the LIKE's
        // case-mode — a BINARY index does NOT qualify for the default
        // (case-insensitive) LIKE, so the "prefix-anchor" query still full-scans
        // cve_match. Rebuild the index NOCASE so the prefix seek actually engages
        // at full-catalog scale (governance perf-P1). NOCASE is safe here: the
        // values are already stored lowercased.
        {3, R"(
            DROP INDEX IF EXISTS idx_cve_match_product;
            CREATE INDEX idx_cve_match_product ON cve_match(cpe_product COLLATE NOCASE);
        )"},
        // v4: composite (vendor, product) index for assess()'s vendor-scoped identity
        // lookups (ADR-0018 typed-identity path). cpe_vendor stays BINARY (default —
        // both stored data and the query are lowercased, so an equality seek engages),
        // while cpe_product is COLLATE NOCASE so a vendor+prefix `LIKE 'x%'` still uses
        // the index. The v3 single-column idx_cve_match_product is KEPT: match_inventory
        // and vendor-less prefix assess() queries still seek on it (no regression).
        {4, R"(CREATE INDEX IF NOT EXISTS idx_cve_match_vendor_product
                ON cve_match(cpe_vendor, cpe_product COLLATE NOCASE);)"},
    };
    const int before = MigrationRunner::current_version(db_, "nvd_database");
    if (!MigrationRunner::run(db_, "nvd_database", kMigrations)) {
        spdlog::error("NvdDatabase: schema migration failed, closing database");
        sqlite3_close(db_);
        db_ = nullptr;
    } else if (before == 1) {
        // Only an EXISTING v1 deployment loses data here (a fresh DB starts at
        // 0). Make the expected coverage dip visible in the log so an operator
        // watching /api/nvd/status total_cves after upgrade isn't puzzled.
        spdlog::warn("NvdDatabase: upgraded schema v1->v2 — the local CVE catalog was reset and "
                     "rebuilds from the next NVD sync; matching coverage is reduced and "
                     "/api/nvd/status total_cves reads low until the sync completes");
    }
}

void NvdDatabase::upsert_cve(const CveRecord& record) {
    std::unique_lock lock(mtx_);
    upsert_cve_impl(record);
}

namespace {

// Prepare the three upsert statements ONCE (hoisted out of the per-CVE loop for
// the batch path — #1881; the old code re-prepared+finalized all three per CVE,
// ~3× hundreds of thousands of prepare/finalize on a full backfill). Caller
// finalizes all three. Returns false on any prepare error.
bool prepare_upsert_stmts(sqlite3* db, sqlite3_stmt*& hdr, sqlite3_stmt*& del, sqlite3_stmt*& ins) {
    hdr = del = ins = nullptr;
    const char* hdr_sql = R"(
        INSERT OR REPLACE INTO cve
            (cve_id, severity, description, published, last_modified, source)
        VALUES (?, ?, ?, ?, ?, ?)
    )";
    const char* del_sql = "DELETE FROM cve_match WHERE cve_id = ?";
    const char* ins_sql = R"(
        INSERT INTO cve_match
            (cve_id, cpe_vendor, cpe_product, cpe_version,
             version_start_including, version_start_excluding,
             version_end_including, version_end_excluding, is_vulnerable)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    )";
    if (sqlite3_prepare_v2(db, hdr_sql, -1, &hdr, nullptr) != SQLITE_OK ||
        sqlite3_prepare_v2(db, del_sql, -1, &del, nullptr) != SQLITE_OK ||
        sqlite3_prepare_v2(db, ins_sql, -1, &ins, nullptr) != SQLITE_OK) {
        spdlog::error("NvdDatabase: upsert statement prepare failed: {}", sqlite3_errmsg(db));
        sqlite3_finalize(hdr);
        sqlite3_finalize(del);
        sqlite3_finalize(ins);
        hdr = del = ins = nullptr;
        return false;
    }
    return true;
}

// Bind + step the three ALREADY-PREPARED statements for one CVE, atomic per CVE
// via a SAVEPOINT (governance UP-1). Without this, a mid-sequence failure could
// commit a CVE whose old match rows were deleted but new ones never inserted — a
// PERMANENTLY missed CVE. On any failure we ROLLBACK TO the savepoint, leaving
// the CVE's prior (complete) match set intact. Savepoints nest safely inside the
// batch transaction and also work standalone.
bool upsert_cve_one(sqlite3* db, const CveRecord& record, sqlite3_stmt* hdr, sqlite3_stmt* del,
                    sqlite3_stmt* ins) {
    char* serr = nullptr;
    if (sqlite3_exec(db, "SAVEPOINT cve_upsert;", nullptr, nullptr, &serr) != SQLITE_OK) {
        spdlog::error("NvdDatabase: SAVEPOINT failed for {}: {}", record.cve_id,
                      serr ? serr : "unknown");
        sqlite3_free(serr);
        return false;
    }

    bool ok = true;

    // 1. Upsert the CVE header (keyed on cve_id — idempotent).
    sqlite3_reset(hdr);
    sqlite3_bind_text(hdr, 1, record.cve_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(hdr, 2, record.severity.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(hdr, 3, record.description.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(hdr, 4, record.published.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(hdr, 5, record.last_modified.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(hdr, 6, record.source.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(hdr) != SQLITE_DONE) {
        spdlog::error("NvdDatabase: upsert_cve header step failed for {}: {}", record.cve_id,
                      sqlite3_errmsg(db));
        ok = false;
    }

    // 2. Replace this CVE's match set (delete-then-insert) so re-syncing a CVE
    //    replaces its rows and a multi-product CVE keeps ALL its product rows.
    if (ok) {
        sqlite3_reset(del);
        sqlite3_bind_text(del, 1, record.cve_id.c_str(), -1, SQLITE_TRANSIENT);
        if (sqlite3_step(del) != SQLITE_DONE) {
            spdlog::error("NvdDatabase: cve_match delete step failed for {}: {}", record.cve_id,
                          sqlite3_errmsg(db));
            ok = false;
        }
    }

    // 3. Insert the new match rows.
    if (ok) {
        for (const auto& m : record.matches) {
            sqlite3_reset(ins);
            sqlite3_bind_text(ins, 1, record.cve_id.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(ins, 2, m.cpe_vendor.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(ins, 3, m.cpe_product.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(ins, 4, m.cpe_version.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(ins, 5, m.version_start_including.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(ins, 6, m.version_start_excluding.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(ins, 7, m.version_end_including.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(ins, 8, m.version_end_excluding.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int(ins, 9, m.is_vulnerable ? 1 : 0);
            if (sqlite3_step(ins) != SQLITE_DONE) {
                spdlog::error("NvdDatabase: cve_match insert step failed for {}: {}", record.cve_id,
                              sqlite3_errmsg(db));
                ok = false;
                break;
            }
        }
    }

    if (ok) {
        sqlite3_exec(db, "RELEASE cve_upsert;", nullptr, nullptr, nullptr);
    } else {
        spdlog::error("NvdDatabase: rolling back partial upsert of {} (match set left unchanged)",
                      record.cve_id);
        sqlite3_exec(db, "ROLLBACK TO cve_upsert;", nullptr, nullptr, nullptr);
        sqlite3_exec(db, "RELEASE cve_upsert;", nullptr, nullptr, nullptr);
    }
    return ok;
}

} // namespace

bool NvdDatabase::upsert_cve_impl(const CveRecord& record) {
    if (!db_)
        return false;
    // Standalone single-CVE path: prepare/finalize around the shared helper.
    sqlite3_stmt* hdr = nullptr;
    sqlite3_stmt* del = nullptr;
    sqlite3_stmt* ins = nullptr;
    if (!prepare_upsert_stmts(db_, hdr, del, ins))
        return false;
    const bool ok = upsert_cve_one(db_, record, hdr, del, ins);
    sqlite3_finalize(hdr);
    sqlite3_finalize(del);
    sqlite3_finalize(ins);
    return ok;
}

bool NvdDatabase::upsert_cves(const std::vector<CveRecord>& records,
                             std::vector<std::string>* changed_ids) {
    std::unique_lock lock(mtx_);
    return upsert_cves_impl(records, changed_ids);
}

bool NvdDatabase::upsert_cves_impl(const std::vector<CveRecord>& records,
                                  std::vector<std::string>* changed_ids) {
    if (!db_)
        return false; // no connection — nothing was persisted
    if (records.empty())
        return true; // nothing to persist is not a failure

    char* err_msg = nullptr;
    if (sqlite3_exec(db_, "BEGIN TRANSACTION;", nullptr, nullptr, &err_msg) != SQLITE_OK) {
        spdlog::error("NvdDatabase: BEGIN failed: {}", err_msg ? err_msg : "unknown");
        sqlite3_free(err_msg);
        return false;
    }
    // RAII: any early return OR throw past here rolls the transaction back and finalizes the
    // prepared statements. The dedupe below allocates (unordered_set/map + a merged vector), so
    // a std::bad_alloc would otherwise leave the connection wedged in an open transaction AND
    // leak the three statements (PR #1912 review; docs/cpp-conventions.md §Resource ownership,
    // owners from sqlite_raii.hpp). Declared BEFORE the SqliteStmts so the statements finalize
    // before this rolls back — SQLite wants live statements gone first.
    SqliteTxn txn{db_};

    // ENFORCE (not just document) "at most one CveRecord per cve_id per batch":
    // upsert_cve_one does a delete-then-insert of the whole match set keyed on
    // cve_id, so two records sharing a cve_id would have the second wipe the
    // first's matches. Fast path (the common case, and the invariant today —
    // parse_response folds all cpeMatch nodes into ONE record): no duplicate
    // cve_id, so upsert `records` directly with zero copy. Slow path: merge the
    // duplicates (append matches) into owned records so no rows are lost. FIRST-HEADER-WINS:
    // the earliest record's header fields (severity/description/published/last_modified) are
    // kept; later duplicates contribute ONLY their matches. This only matters for a
    // hypothetical future multi-record batch — parse_response folds each cve_id into one
    // record today, so the merge path is unreached in practice (PR #1912 review, documented).
    std::vector<CveRecord> merged;
    const std::vector<CveRecord>* to_upsert = &records;
    {
        std::unordered_set<std::string_view> seen;
        seen.reserve(records.size());
        bool has_dup = false;
        for (const auto& r : records) {
            if (!seen.insert(r.cve_id).second) {
                has_dup = true;
                break;
            }
        }
        if (has_dup) {
            std::unordered_map<std::string, std::size_t> idx;
            for (const auto& r : records) {
                auto it = idx.find(r.cve_id);
                if (it == idx.end()) {
                    idx.emplace(r.cve_id, merged.size());
                    merged.push_back(r);
                } else {
                    auto& dst = merged[it->second].matches;
                    dst.insert(dst.end(), r.matches.begin(), r.matches.end());
                }
            }
            spdlog::warn("NvdDatabase: merged {} duplicate-cve_id record(s) in a batch of {}",
                         records.size() - merged.size(), records.size());
            to_upsert = &merged;
        }
    }

    // Prepare the three upsert statements ONCE for the whole batch (#1881), RAII-owned so
    // any throw/early-return between here and COMMIT finalizes them (PR #1912 review).
    sqlite3_stmt* hdr_raw = nullptr;
    sqlite3_stmt* del_raw = nullptr;
    sqlite3_stmt* ins_raw = nullptr;
    if (!prepare_upsert_stmts(db_, hdr_raw, del_raw, ins_raw))
        return false; // nothing persisted — txn rolls back; caller holds its cursor (#1889 r4)
    SqliteStmt hdr{hdr_raw};
    SqliteStmt del{del_raw};
    SqliteStmt ins{ins_raw};

    std::size_t failed = 0;
    for (const auto& record : *to_upsert) {
        if (!upsert_cve_one(db_, record, hdr.get(), del.get(), ins.get())) {
            ++failed; // this CVE rolled back to its prior state; batch continues
        } else if (changed_ids) {
            // Record the successfully-persisted cve_id from the per-CVE success bool
            // (NOT sqlite3_changes(), #1033). `*to_upsert` is already deduped by cve_id
            // (the merge path folds duplicates), so this delta is deduped within the
            // batch without a second dedup set.
            changed_ids->push_back(record.cve_id);
        }
    }

    if (failed > 0) {
        spdlog::warn("NvdDatabase: {}/{} CVE upserts rolled back (prior data retained)", failed,
                     to_upsert->size());
    }

    // Finalize the statements before COMMIT — SQLite requires no live statements at commit
    // time (the SqliteStmt dtors would also do this, but do it explicitly pre-commit).
    hdr.reset();
    del.reset();
    ins.reset();

    if (txn.commit() != SQLITE_OK) {
        spdlog::error("NvdDatabase: COMMIT failed");
        // The whole batch rolled back — none of the per-record successes actually
        // committed, so changed_ids (populated in the loop above) would otherwise be
        // returned non-empty with ids that did NOT commit. Clear it so the only
        // non-empty-on-false case left is the genuine per-SAVEPOINT partial-rollback
        // one, whose ids DID commit (FIX 3).
        if (changed_ids)
            changed_ids->clear();
        return false; // commit failed → txn stays armed, its dtor rolls back
    }
    // Return false if the batch was not FULLY persisted — BEGIN/COMMIT failed (handled
    // above) or ANY record rolled back to its prior state (failed > 0). The caller HOLDS
    // its resume cursor on false and retries, so it never advances past unpersisted CVEs
    // (#1889 review r4). It deliberately does not advance-and-drop after N retries: for a
    // vuln mirror a dropped window is a permanent false-negative, so a persistent failure
    // fails safe (the mirror stays incomplete + the error is surfaced) rather than silently
    // losing CVEs. In practice this schema (all-TEXT, no CHECK/UNIQUE) can't produce a
    // data-dependent per-record failure, so a persistent hold only happens on catastrophic
    // I/O/corruption where the whole server is already degraded.
    return failed == 0;
}

std::vector<CveMatch>
NvdDatabase::match_inventory(const std::vector<SoftwareItem>& inventory) const {
    std::shared_lock lock(mtx_);
    std::vector<CveMatch> matches;
    if (!db_ || inventory.empty())
        return matches;

    // Join each cpeMatch row to its CVE header. Identity is still product-name
    // based (SoftwareItem carries no vendor, so cpe_vendor is stored but not
    // used to disambiguate — that waits for the agent typed-identity collector,
    // ADR-0018); version matching now honours the full cpeMatch range.
    const char* sql = R"(
        SELECT m.cve_id, m.cpe_product, m.cpe_version,
               m.version_start_including, m.version_start_excluding,
               m.version_end_including, m.version_end_excluding,
               c.severity, c.description, c.source
        FROM cve_match m JOIN cve c ON c.cve_id = m.cve_id
        WHERE m.cpe_product LIKE ? ESCAPE '\' AND m.is_vulnerable = 1
    )";

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("NvdDatabase: match_inventory prepare failed: {}", sqlite3_errmsg(db_));
        return matches;
    }

    auto col = [](sqlite3_stmt* s, int i) -> std::string {
        const char* t = reinterpret_cast<const char*>(sqlite3_column_text(s, i));
        return t ? t : "";
    };

    // Escape LIKE metacharacters in the (possibly agent-supplied) product name
    // so a name containing '%'/'_' can't broaden its own device's match set
    // (governance security-LOW / UP-5). Pairs with ESCAPE '\' in the query.
    auto like_escape = [](std::string_view s) {
        std::string out;
        out.reserve(s.size());
        for (char c : s) {
            if (c == '\\' || c == '%' || c == '_')
                out.push_back('\\');
            out.push_back(c);
        }
        return out;
    };

    for (const auto& item : inventory) {
        if (item.name.empty() || item.version.empty())
            continue;

        // PREFIX-anchored, not substring: `name%` (no leading `%`) so
        // idx_cve_match_product turns this into an index seek instead of a full
        // cve_match scan per item — required at full-catalog scale (perf-P1 hard
        // gate). Narrower than substring: the inventory name must be a PREFIX of
        // the CPE product (canonical tokens, so acceptable; vendor-precise
        // identity waits for ADR-0018).
        std::string pattern = like_escape(to_lower(item.name)) + "%";

        sqlite3_reset(stmt);
        sqlite3_bind_text(stmt, 1, pattern.c_str(), -1, SQLITE_TRANSIENT);

        // A CVE can have several matching rows for one product; report it once.
        std::unordered_set<std::string> seen;

        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const std::string cve_id = col(stmt, 0);
            const std::string product = col(stmt, 1);
            const std::string cpe_version = col(stmt, 2);
            const std::string vsi = col(stmt, 3);
            const std::string vse = col(stmt, 4);
            const std::string vei = col(stmt, 5);
            const std::string vee = col(stmt, 6);

            VersionRange range{cpe_version, vsi, vse, vei, vee};
            if (!nvd_version_in_range(item.version, range))
                continue;
            if (!seen.insert(cve_id).second)
                continue;

            CveMatch match;
            match.cve_id = cve_id;
            match.product = product;
            match.installed_version = item.version;
            match.severity = col(stmt, 7);
            match.description = col(stmt, 8);
            match.fixed_in = vee; // the exclusive upper bound is the fix boundary
            const std::string src = col(stmt, 9);
            match.source = src.empty() ? "nvd" : src;

            matches.push_back(std::move(match));
        }
    }

    sqlite3_finalize(stmt);
    return matches;
}

AssessResult NvdDatabase::assess(const CpeQuery& q) const {
    std::shared_lock lock(mtx_);
    AssessResult out;

    // Guard 1 (before any vendor branch): no connection or no product → nothing to assess.
    if (!db_ || q.product.empty())
        return out;
    // Guard 2: a bare unqualified prefix must be long enough to seek meaningfully — a
    // <3-char prefix with no vendor scope would sweep half the catalog. Exact-product or
    // vendor-scoped queries are exempt (they seek on an equality column).
    if (!q.exact_product && q.vendor.empty() && q.product.size() < 3)
        return out;

    // ALWAYS lowercase internally — never trust the caller to have done it (the stored
    // cpe_vendor/cpe_product are lowercased at ingest; cpe_vendor uses a BINARY equality
    // seek so both sides must match case).
    const std::string prod = to_lower(q.product);
    const std::string vend = to_lower(q.vendor);

    // Escape LIKE metacharacters so a '_'/'%' in the product name can't broaden the
    // prefix match (same guard as match_inventory). Pairs with ESCAPE '\' below.
    auto like_escape = [](std::string_view s) {
        std::string res;
        res.reserve(s.size());
        for (char c : s) {
            if (c == '\\' || c == '%' || c == '_')
                res.push_back('\\');
            res.push_back(c);
        }
        return res;
    };

    // ONE query. The is_vulnerable=1 filter is both the correctness fix (never count an
    // is_vulnerable=0 platform operand as a vulnerable identity) and the perf fix.
    std::string sql =
        "SELECT m.cve_id, m.cpe_version, "
        "       m.version_start_including, m.version_start_excluding, "
        "       m.version_end_including,  m.version_end_excluding, "
        "       c.severity, c.description, c.published "
        "FROM   cve_match m JOIN cve c ON c.cve_id = m.cve_id "
        "WHERE  m.is_vulnerable = 1 AND ";
    sql += q.exact_product ? "m.cpe_product = ? COLLATE NOCASE"
                           : "m.cpe_product LIKE ? ESCAPE '\\'";
    // INVARIANT (load-bearing): cpe_vendor is compared BINARY (no COLLATE NOCASE),
    // deliberately. Vendors are stored lowercased at ingest (nvd_client.cpp) and
    // assess() lowercases `vend` above, so a BINARY equality seek engages the
    // (cpe_vendor, cpe_product) composite index. Do NOT add COLLATE NOCASE here —
    // it would defeat the vendor seek (the exact reason the schema kept vendor
    // BINARY while product is NOCASE). A future non-lowercasing CveRecord producer
    // is the only way this misses; the fix for that is to lowercase on ingest, not
    // to relax the query.
    if (!vend.empty())
        sql += " AND m.cpe_vendor = ?";

    // RAII-owned statement: a throw below (FIX 1) or a bad_alloc between prepare and the
    // step loop must finalize it on unwind, never leak it (FIX 2, sqlite_raii.hpp).
    SqliteStmt stmt;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, stmt.addr(), nullptr) != SQLITE_OK) {
        // THROW, never return {} on a DB fault: an empty AssessResult is
        // indistinguishable from a genuine no-rows/absent identity, so a swallowed
        // prepare error would fabricate a false product_known=false (the exact
        // ADR-0019 lie the is_vulnerable=1 filter guards). The caller distinguishes a
        // DB fault from assessed-clean by catching this.
        throw std::runtime_error(std::string("NvdDatabase: assess prepare failed: ") +
                                 sqlite3_errmsg(db_));
    }

    const std::string product_bind = q.exact_product ? prod : (like_escape(prod) + "%");
    int bind_idx = 1;
    sqlite3_bind_text(stmt.get(), bind_idx++, product_bind.c_str(), -1, SQLITE_TRANSIENT);
    if (!vend.empty())
        sqlite3_bind_text(stmt.get(), bind_idx++, vend.c_str(), -1, SQLITE_TRANSIENT);

    auto col = [](sqlite3_stmt* s, int i) -> std::string {
        const char* t = reinterpret_cast<const char*>(sqlite3_column_text(s, i));
        return t ? t : "";
    };

    std::unordered_map<std::string, std::size_t> idx; // cve_id -> position in out.hits

    int rc;
    while ((rc = sqlite3_step(stmt.get())) == SQLITE_ROW) {
        // Every stepped row is is_vulnerable=1 for this identity → the product is known.
        out.product_known = true;

        // Empty installed version: the product is known but no hit passes the range
        // check (do NOT fabricate a clean-or-vulnerable verdict without a version).
        if (q.version.empty())
            continue;

        const std::string cve_id = col(stmt.get(), 0);
        const std::string cpe_version = col(stmt.get(), 1);
        const std::string vsi = col(stmt.get(), 2);
        const std::string vse = col(stmt.get(), 3);
        const std::string vei = col(stmt.get(), 4);
        const std::string vee = col(stmt.get(), 5);

        VersionRange range{cpe_version, vsi, vse, vei, vee};
        if (!nvd_version_in_range(q.version, range))
            continue;

        auto it = idx.find(cve_id);
        if (it == idx.end()) {
            idx.emplace(cve_id, out.hits.size());
            out.hits.push_back(CveHit{cve_id, col(stmt.get(), 6), col(stmt.get(), 7),
                                      col(stmt.get(), 8),
                                      /*fixed_in=*/vee});
        } else if (!vee.empty()) {
            // Reconcile fixed_in across multiple in-range vulnerable rows for the same
            // cve_id (real NVD data has several `configurations` branches per CVE+
            // product). The correct answer is the MINIMUM versionEndExcluding across the
            // in-range rows — the smallest version that lifts the installed version out
            // of range. An empty vee carries no fix boundary, so a non-empty candidate
            // always wins over empty; among non-empty candidates take the numeric min
            // via the NVD comparator (NOT string compare — "8.0" < "10.0" lexically is
            // wrong). Deterministic regardless of row order.
            std::string& cur = out.hits[it->second].fixed_in;
            if (cur.empty() || nvd_version_compare(vee, cur) < 0)
                cur = vee;
        }
    }
    // A loop exit on anything but SQLITE_DONE (SQLITE_BUSY/LOCKED/IOERR/CORRUPT) means the
    // scan aborted mid-flight: `out` is a partial/empty result that MUST NOT be read as
    // assessed-clean/not-assessed. Throw so the caller aborts this identity (FIX 1).
    if (rc != SQLITE_DONE) {
        throw std::runtime_error(std::string("NvdDatabase: assess step failed: ") +
                                 sqlite3_errmsg(db_));
    }

    return out;
}

std::vector<std::pair<std::string, std::string>>
NvdDatabase::products_for_cves(const std::vector<std::string>& cve_ids) const {
    std::shared_lock lock(mtx_);
    std::vector<std::pair<std::string, std::string>> result;
    if (!db_ || cve_ids.empty())
        return result;

    // Accumulate DISTINCT (vendor, product) ACROSS chunks — SQL DISTINCT only
    // dedupes within a single IN(...) query, so a product appearing in two chunks
    // would otherwise be emitted twice.
    std::unordered_set<std::string> seen; // "vendor\x1fproduct" key
    auto col = [](sqlite3_stmt* s, int i) -> std::string {
        const char* t = reinterpret_cast<const char*>(sqlite3_column_text(s, i));
        return t ? t : "";
    };

    constexpr std::size_t kChunk = 500;
    for (std::size_t base = 0; base < cve_ids.size(); base += kChunk) {
        const std::size_t n = std::min(kChunk, cve_ids.size() - base);

        std::string sql = "SELECT DISTINCT cpe_vendor, cpe_product FROM cve_match "
                          "WHERE is_vulnerable = 1 AND cve_id IN (";
        for (std::size_t i = 0; i < n; ++i)
            sql += (i == 0) ? "?" : ",?";
        sql += ")";

        // RAII per-chunk statement, finalized before the next chunk's SqliteStmt (FIX 2).
        SqliteStmt stmt;
        if (sqlite3_prepare_v2(db_, sql.c_str(), -1, stmt.addr(), nullptr) != SQLITE_OK) {
            // THROW on ANY chunk's prepare failure — never a silent partial list. An empty
            // or truncated result would be read as "these CVEs affect no products", a false
            // inversion the caller cannot distinguish from a DB fault (FIX 1).
            throw std::runtime_error(std::string("NvdDatabase: products_for_cves prepare failed: ") +
                                     sqlite3_errmsg(db_));
        }
        for (std::size_t i = 0; i < n; ++i)
            sqlite3_bind_text(stmt.get(), static_cast<int>(i + 1), cve_ids[base + i].c_str(), -1,
                              SQLITE_TRANSIENT);

        int rc;
        while ((rc = sqlite3_step(stmt.get())) == SQLITE_ROW) {
            std::string vendor = col(stmt.get(), 0);
            std::string product = col(stmt.get(), 1);
            std::string key = vendor;
            key.push_back('\x1f');
            key += product;
            if (seen.insert(std::move(key)).second)
                result.emplace_back(std::move(vendor), std::move(product));
        }
        // A mid-chunk abort (not SQLITE_DONE) would truncate the inversion silently (FIX 1).
        if (rc != SQLITE_DONE) {
            throw std::runtime_error(std::string("NvdDatabase: products_for_cves step failed: ") +
                                     sqlite3_errmsg(db_));
        }
    }
    return result;
}

std::string NvdDatabase::get_meta(const std::string& key) const {
    std::shared_lock lock(mtx_);
    if (!db_)
        return {};

    const char* sql = "SELECT value FROM sync_meta WHERE key = ?";
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("NvdDatabase: get_meta prepare failed: {}", sqlite3_errmsg(db_));
        return {};
    }

    sqlite3_bind_text(stmt, 1, key.c_str(), -1, SQLITE_TRANSIENT);

    std::string result;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const char* val = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        if (val)
            result = val;
    }

    sqlite3_finalize(stmt);
    return result;
}

void NvdDatabase::set_meta(const std::string& key, const std::string& value) {
    std::unique_lock lock(mtx_);
    if (!db_)
        return;

    const char* sql = "INSERT OR REPLACE INTO sync_meta (key, value) VALUES (?, ?)";
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("NvdDatabase: set_meta prepare failed: {}", sqlite3_errmsg(db_));
        return;
    }

    sqlite3_bind_text(stmt, 1, key.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, value.c_str(), -1, SQLITE_TRANSIENT);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        spdlog::error("NvdDatabase: set_meta step failed: {}", sqlite3_errmsg(db_));
    }

    sqlite3_finalize(stmt);
}

void NvdDatabase::seed_builtin_rules() {
    std::unique_lock lock(mtx_);
    if (!db_)
        return;

    // Only seed if no builtin records exist yet
    const char* check_sql = "SELECT COUNT(*) FROM cve WHERE source = 'builtin'";
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, check_sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("NvdDatabase: seed check prepare failed: {}", sqlite3_errmsg(db_));
        return;
    }

    std::size_t existing_count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        existing_count = static_cast<std::size_t>(sqlite3_column_int64(stmt, 0));
    }
    sqlite3_finalize(stmt);

    if (existing_count > 0) {
        spdlog::debug("NvdDatabase: {} builtin rules already present, skipping seed",
                      existing_count);
        return;
    }

    // Convert builtin rules to CveRecords (one CpeMatch each, the flat rule's
    // affected_below maps to versionEndExcluding) and batch-insert.
    std::vector<CveRecord> records;
    records.reserve(kBuiltinRules.size());
    for (const auto& rule : kBuiltinRules) {
        CveRecord rec;
        rec.cve_id = std::string(rule.cve_id);
        rec.severity = std::string(rule.severity);
        rec.description = std::string(rule.description);
        rec.published = "";
        rec.last_modified = "";
        rec.source = "builtin";

        CpeMatch cm;
        cm.cpe_product = std::string(rule.product);
        cm.version_end_excluding = std::string(rule.affected_below);
        rec.matches.push_back(std::move(cm));

        records.push_back(std::move(rec));
    }

    if (upsert_cves_impl(records))
        spdlog::info("NvdDatabase: seeded {} builtin CVE rules", records.size());
    else
        spdlog::warn("NvdDatabase: some builtin CVE rules failed to seed");
}

std::size_t NvdDatabase::total_cve_count() const {
    std::shared_lock lock(mtx_);
    if (!db_)
        return 0;

    const char* sql = "SELECT COUNT(*) FROM cve";
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("NvdDatabase: total_cve_count prepare failed: {}", sqlite3_errmsg(db_));
        return 0;
    }

    std::size_t count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        count = static_cast<std::size_t>(sqlite3_column_int64(stmt, 0));
    }

    sqlite3_finalize(stmt);
    return count;
}

std::size_t NvdDatabase::nvd_cve_count() const {
    std::shared_lock lock(mtx_);
    if (!db_)
        return 0;

    // Only real NVD rows — NOT the source='builtin' fallback rules seeded at startup —
    // so a mirror holding only builtins is never mistaken for a populated NVD catalog
    // (#1889 review r4).
    const char* sql = "SELECT COUNT(*) FROM cve WHERE source = 'nvd'";
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("NvdDatabase: nvd_cve_count prepare failed: {}", sqlite3_errmsg(db_));
        return 0;
    }

    std::size_t count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        count = static_cast<std::size_t>(sqlite3_column_int64(stmt, 0));
    }

    sqlite3_finalize(stmt);
    return count;
}

} // namespace yuzu::server
