#include "nvd_db.hpp"
#include "migration_runner.hpp"

#include <spdlog/spdlog.h>
#include <sqlite3.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <mutex>
#include <string_view>
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
    };
    if (!MigrationRunner::run(db_, "nvd_database", kMigrations)) {
        spdlog::error("NvdDatabase: schema migration failed, closing database");
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

void NvdDatabase::upsert_cve(const CveRecord& record) {
    std::unique_lock lock(mtx_);
    upsert_cve_impl(record);
}

void NvdDatabase::upsert_cve_impl(const CveRecord& record) {
    if (!db_)
        return;

    const char* sql = R"(
        INSERT OR REPLACE INTO cve
            (cve_id, product, vendor, affected_below, fixed_in, severity,
             description, published, last_modified, source)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    )";

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("NvdDatabase: upsert_cve prepare failed: {}", sqlite3_errmsg(db_));
        return;
    }

    sqlite3_bind_text(stmt, 1, record.cve_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, record.product.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, record.vendor.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, record.affected_below.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, record.fixed_in.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 6, record.severity.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 7, record.description.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 8, record.published.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 9, record.last_modified.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 10, record.source.c_str(), -1, SQLITE_TRANSIENT);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        spdlog::error("NvdDatabase: upsert_cve step failed for {}: {}", record.cve_id,
                      sqlite3_errmsg(db_));
    }

    sqlite3_finalize(stmt);
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

    for (const auto& record : records) {
        upsert_cve_impl(record);
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

    const char* sql = "SELECT cve_id, product, affected_below, fixed_in, severity, "
                      "description, source FROM cve WHERE product LIKE ?";

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("NvdDatabase: match_inventory prepare failed: {}", sqlite3_errmsg(db_));
        return matches;
    }

    for (const auto& item : inventory) {
        if (item.name.empty() || item.version.empty())
            continue;

        std::string name_lower = to_lower(item.name);
        std::string pattern = "%" + name_lower + "%";

        sqlite3_reset(stmt);
        sqlite3_bind_text(stmt, 1, pattern.c_str(), -1, SQLITE_TRANSIENT);

        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const char* affected_below =
                reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
            if (!affected_below)
                continue;

            // Version is vulnerable if installed_version < affected_below
            if (compare_versions(item.version, affected_below) < 0) {
                CveMatch match;
                match.cve_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
                match.product = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
                match.installed_version = item.version;
                match.severity = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
                match.description = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));

                const char* fixed = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
                match.fixed_in = fixed ? fixed : "";

                const char* src = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
                match.source = src ? src : "nvd";

                matches.push_back(std::move(match));
            }
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

    // Convert builtin rules to CveRecords and batch-insert
    std::vector<CveRecord> records;
    records.reserve(kBuiltinRules.size());
    for (const auto& rule : kBuiltinRules) {
        CveRecord rec;
        rec.cve_id = std::string(rule.cve_id);
        rec.product = std::string(rule.product);
        rec.vendor = "";
        rec.affected_below = std::string(rule.affected_below);
        rec.fixed_in = std::string(rule.fixed_in);
        rec.severity = std::string(rule.severity);
        rec.description = std::string(rule.description);
        rec.published = "";
        rec.last_modified = "";
        rec.source = "builtin";
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
