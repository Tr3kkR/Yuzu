#include "nvd_db.hpp"
#include "migration_runner.hpp"
#include "nvd_version.hpp"

#include <spdlog/spdlog.h>
#include <sqlite3.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>

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

bool NvdDatabase::upsert_cve_impl(const CveRecord& record) {
    if (!db_)
        return false;

    // Make header-upsert + match delete-then-insert ATOMIC per CVE (governance
    // c1735cd3 UP-1). Without this, a mid-sequence failure could commit a CVE
    // whose old match rows were deleted but new ones never inserted — a
    // PERMANENTLY missed CVE, because incremental sync never re-sends an
    // unmodified entry. On any failure we ROLLBACK TO the savepoint, leaving the
    // CVE's prior (complete) match set intact. Savepoints nest safely inside the
    // batch transaction (upsert_cves_impl) and also work standalone.
    char* serr = nullptr;
    if (sqlite3_exec(db_, "SAVEPOINT cve_upsert;", nullptr, nullptr, &serr) != SQLITE_OK) {
        spdlog::error("NvdDatabase: SAVEPOINT failed for {}: {}", record.cve_id,
                      serr ? serr : "unknown");
        sqlite3_free(serr);
        return false;
    }

    bool ok = true;

    // 1. Upsert the CVE header (keyed on cve_id — idempotent).
    {
        const char* sql = R"(
            INSERT OR REPLACE INTO cve
                (cve_id, severity, description, published, last_modified, source)
            VALUES (?, ?, ?, ?, ?, ?)
        )";
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
            spdlog::error("NvdDatabase: upsert_cve header prepare failed: {}",
                          sqlite3_errmsg(db_));
            ok = false;
        } else {
            sqlite3_bind_text(stmt, 1, record.cve_id.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 2, record.severity.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 3, record.description.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 4, record.published.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 5, record.last_modified.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 6, record.source.c_str(), -1, SQLITE_TRANSIENT);
            if (sqlite3_step(stmt) != SQLITE_DONE) {
                spdlog::error("NvdDatabase: upsert_cve header step failed for {}: {}",
                              record.cve_id, sqlite3_errmsg(db_));
                ok = false;
            }
            sqlite3_finalize(stmt);
        }
    }

    // 2. Replace this CVE's match set (delete-then-insert) so re-syncing a CVE
    //    replaces its rows and a multi-product CVE keeps ALL its product rows.
    if (ok) {
        const char* del = "DELETE FROM cve_match WHERE cve_id = ?";
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, del, -1, &stmt, nullptr) != SQLITE_OK) {
            spdlog::error("NvdDatabase: cve_match delete prepare failed: {}", sqlite3_errmsg(db_));
            ok = false;
        } else {
            sqlite3_bind_text(stmt, 1, record.cve_id.c_str(), -1, SQLITE_TRANSIENT);
            if (sqlite3_step(stmt) != SQLITE_DONE) {
                spdlog::error("NvdDatabase: cve_match delete step failed for {}: {}", record.cve_id,
                              sqlite3_errmsg(db_));
                ok = false;
            }
            sqlite3_finalize(stmt);
        }
    }

    // 3. Insert the new match rows.
    if (ok && !record.matches.empty()) {
        const char* ins = R"(
            INSERT INTO cve_match
                (cve_id, cpe_vendor, cpe_product, cpe_version,
                 version_start_including, version_start_excluding,
                 version_end_including, version_end_excluding, is_vulnerable)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        )";
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, ins, -1, &stmt, nullptr) != SQLITE_OK) {
            spdlog::error("NvdDatabase: cve_match insert prepare failed: {}", sqlite3_errmsg(db_));
            ok = false;
        } else {
            for (const auto& m : record.matches) {
                sqlite3_reset(stmt);
                sqlite3_bind_text(stmt, 1, record.cve_id.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(stmt, 2, m.cpe_vendor.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(stmt, 3, m.cpe_product.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(stmt, 4, m.cpe_version.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(stmt, 5, m.version_start_including.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(stmt, 6, m.version_start_excluding.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(stmt, 7, m.version_end_including.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(stmt, 8, m.version_end_excluding.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_int(stmt, 9, m.is_vulnerable ? 1 : 0);
                if (sqlite3_step(stmt) != SQLITE_DONE) {
                    spdlog::error("NvdDatabase: cve_match insert step failed for {}: {}",
                                  record.cve_id, sqlite3_errmsg(db_));
                    ok = false;
                    break;
                }
            }
            sqlite3_finalize(stmt);
        }
    }

    if (ok) {
        sqlite3_exec(db_, "RELEASE cve_upsert;", nullptr, nullptr, nullptr);
    } else {
        spdlog::error("NvdDatabase: rolling back partial upsert of {} (match set left unchanged)",
                      record.cve_id);
        sqlite3_exec(db_, "ROLLBACK TO cve_upsert;", nullptr, nullptr, nullptr);
        sqlite3_exec(db_, "RELEASE cve_upsert;", nullptr, nullptr, nullptr);
    }
    return ok;
}

void NvdDatabase::upsert_cves(const std::vector<CveRecord>& records) {
    std::unique_lock lock(mtx_);
    upsert_cves_impl(records);
}

void NvdDatabase::upsert_cves_impl(const std::vector<CveRecord>& records) {
    if (!db_ || records.empty())
        return;

    char* err_msg = nullptr;
    int rc = sqlite3_exec(db_, "BEGIN TRANSACTION;", nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        spdlog::error("NvdDatabase: BEGIN failed: {}", err_msg ? err_msg : "unknown");
        sqlite3_free(err_msg);
        return;
    }

    // INVARIANT: at most one CveRecord per cve_id per batch. upsert_cve_impl
    // does a delete-then-insert of the whole match set keyed on cve_id, so two
    // records sharing a cve_id would have the second wipe the first's matches —
    // reintroducing the very multi-product row-loss this reshape fixed. The
    // reshaped parse_response folds all cpeMatch nodes of a CVE into ONE record,
    // and builtin cve_ids are unique, so this holds today (governance N1).
    std::size_t failed = 0;
    for (const auto& record : records) {
        if (!upsert_cve_impl(record))
            ++failed; // this CVE was rolled back to its prior state; batch continues
    }
    if (failed > 0) {
        spdlog::warn("NvdDatabase: {}/{} CVE upserts rolled back (prior data retained)", failed,
                     records.size());
    }

    rc = sqlite3_exec(db_, "COMMIT;", nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        spdlog::error("NvdDatabase: COMMIT failed: {}", err_msg ? err_msg : "unknown");
        sqlite3_free(err_msg);
        // Attempt rollback
        sqlite3_exec(db_, "ROLLBACK;", nullptr, nullptr, nullptr);
    }
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

        std::string pattern = "%" + like_escape(to_lower(item.name)) + "%";

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

    upsert_cves_impl(records);
    spdlog::info("NvdDatabase: seeded {} builtin CVE rules", records.size());
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

} // namespace yuzu::server
