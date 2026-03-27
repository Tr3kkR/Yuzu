#include "license_store.hpp"

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <chrono>
#include <random>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
// clang-format off
#include <windows.h>  // must precede bcrypt.h (defines NTSTATUS)
// clang-format on
#include <bcrypt.h>
#else
#include <openssl/sha.h>
#endif

namespace yuzu::server {

// -- Helpers ------------------------------------------------------------------

static int64_t now_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

static const char* safe(const char* p) {
    return p ? p : "";
}

static std::string generate_id() {
    static thread_local std::mt19937_64 rng{std::random_device{}()};
    static constexpr char hex_chars[] = "0123456789abcdef";
    std::string id;
    id.reserve(32); // 16 bytes = 32 hex chars
    std::uniform_int_distribution<int> dist(0, 15);
    for (int i = 0; i < 32; ++i)
        id += hex_chars[dist(rng)];
    return id;
}

// -- Construction / teardown --------------------------------------------------

LicenseStore::LicenseStore(const std::filesystem::path& db_path) {
    auto canonical_path = db_path;
    {
        std::error_code ec;
        auto parent = db_path.parent_path();
        if (!parent.empty() && std::filesystem::exists(parent, ec)) {
            auto canon_parent = std::filesystem::canonical(parent, ec);
            if (!ec)
                canonical_path = canon_parent / db_path.filename();
        }
    }
    int rc = sqlite3_open(canonical_path.string().c_str(), &db_);
    if (rc != SQLITE_OK) {
        spdlog::error("LicenseStore: failed to open {}: {}", canonical_path.string(),
                      sqlite3_errmsg(db_));
        if (db_) {
            sqlite3_close(db_);
            db_ = nullptr;
        }
        return;
    }
    sqlite3_exec(db_, "PRAGMA journal_mode=WAL;", nullptr, nullptr, nullptr);
    sqlite3_exec(db_, "PRAGMA busy_timeout=5000;", nullptr, nullptr, nullptr);
    create_tables();
    spdlog::info("LicenseStore: opened {}", canonical_path.string());
}

LicenseStore::~LicenseStore() {
    if (db_)
        sqlite3_close(db_);
}

bool LicenseStore::is_open() const {
    return db_ != nullptr;
}

// -- DDL ----------------------------------------------------------------------

void LicenseStore::create_tables() {
    const char* sql = R"(
        CREATE TABLE IF NOT EXISTS licenses (
            id              TEXT PRIMARY KEY,
            license_key_hash TEXT NOT NULL UNIQUE,
            organization    TEXT NOT NULL DEFAULT '',
            seat_count      INTEGER NOT NULL DEFAULT 0,
            issued_at       INTEGER NOT NULL DEFAULT 0,
            expires_at      INTEGER NOT NULL DEFAULT 0,
            edition         TEXT NOT NULL DEFAULT 'community',
            features_json   TEXT NOT NULL DEFAULT '[]',
            status          TEXT NOT NULL DEFAULT 'active',
            activated_at    INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_license_status ON licenses(status);

        CREATE TABLE IF NOT EXISTS license_alerts (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            license_id      TEXT NOT NULL,
            alert_type      TEXT NOT NULL,
            message         TEXT NOT NULL DEFAULT '',
            triggered_at    INTEGER NOT NULL DEFAULT 0,
            acknowledged    INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_license_alert_lic ON license_alerts(license_id);
        CREATE INDEX IF NOT EXISTS idx_license_alert_ack ON license_alerts(acknowledged, triggered_at);
    )";
    char* err = nullptr;
    if (sqlite3_exec(db_, sql, nullptr, nullptr, &err) != SQLITE_OK) {
        spdlog::error("LicenseStore: create_tables failed: {}", err ? err : "unknown");
        sqlite3_free(err);
    }
}

// -- Hashing ------------------------------------------------------------------

std::string LicenseStore::hash_key(const std::string& raw) const {
    unsigned char hash[32]{};

#ifdef _WIN32
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (alg) {
        BCRYPT_HASH_HANDLE h = nullptr;
        BCryptCreateHash(alg, &h, nullptr, 0, nullptr, 0, 0);
        if (h) {
            BCryptHashData(h, reinterpret_cast<PUCHAR>(const_cast<char*>(raw.data())),
                           static_cast<ULONG>(raw.size()), 0);
            BCryptFinishHash(h, hash, 32, 0);
            BCryptDestroyHash(h);
        }
        BCryptCloseAlgorithmProvider(alg, 0);
    }
#else
    SHA256(reinterpret_cast<const unsigned char*>(raw.data()), raw.size(), hash);
#endif

    static constexpr char hex[] = "0123456789abcdef";
    std::string result;
    result.reserve(64);
    for (unsigned char c : hash) {
        result += hex[c >> 4];
        result += hex[c & 0x0f];
    }
    return result;
}

// -- License CRUD -------------------------------------------------------------

std::expected<std::string, std::string>
LicenseStore::activate_license(const License& license, const std::string& license_key) {
    if (!db_)
        return std::unexpected("database not open");
    if (license_key.empty())
        return std::unexpected("license key cannot be empty");
    if (license.organization.empty())
        return std::unexpected("organization cannot be empty");

    std::unique_lock lock(mtx_);

    auto key_hash = hash_key(license_key);
    auto id = license.id.empty() ? generate_id() : license.id;
    auto now = now_epoch();

    // Check for duplicate key
    {
        sqlite3_stmt* chk = nullptr;
        if (sqlite3_prepare_v2(db_,
                               "SELECT id FROM licenses WHERE license_key_hash = ?;",
                               -1, &chk, nullptr) == SQLITE_OK) {
            sqlite3_bind_text(chk, 1, key_hash.c_str(), -1, SQLITE_TRANSIENT);
            if (sqlite3_step(chk) == SQLITE_ROW) {
                sqlite3_finalize(chk);
                return std::unexpected("license key already activated");
            }
            sqlite3_finalize(chk);
        }
    }

    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "INSERT INTO licenses "
                           "(id, license_key_hash, organization, seat_count, issued_at, "
                           "expires_at, edition, features_json, status, activated_at) "
                           "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', ?);",
                           -1, &s, nullptr) != SQLITE_OK)
        return std::unexpected(std::string("prepare failed: ") + sqlite3_errmsg(db_));

    sqlite3_bind_text(s, 1, id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 2, key_hash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 3, license.organization.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(s, 4, license.seat_count);
    sqlite3_bind_int64(s, 5, license.issued_at > 0 ? license.issued_at : now);
    sqlite3_bind_int64(s, 6, license.expires_at);
    sqlite3_bind_text(s, 7, license.edition.empty() ? "community" : license.edition.c_str(),
                      -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 8, license.features_json.empty() ? "[]" : license.features_json.c_str(),
                      -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(s, 9, now);

    int rc = sqlite3_step(s);
    sqlite3_finalize(s);
    if (rc != SQLITE_DONE)
        return std::unexpected(std::string("failed to activate license: ") + sqlite3_errmsg(db_));

    spdlog::info("LicenseStore: activated license '{}' for org '{}' (edition={}, seats={})",
                 id, license.organization, license.edition, license.seat_count);
    return id;
}

std::vector<License> LicenseStore::list_licenses() const {
    std::vector<License> result;
    if (!db_)
        return result;

    std::shared_lock lock(mtx_);

    const char* sql =
        "SELECT id, organization, seat_count, issued_at, expires_at, "
        "edition, features_json, status "
        "FROM licenses ORDER BY activated_at DESC;";

    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &s, nullptr) != SQLITE_OK)
        return result;

    while (sqlite3_step(s) == SQLITE_ROW) {
        License lic;
        lic.id = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 0)));
        lic.organization = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 1)));
        lic.seat_count = sqlite3_column_int64(s, 2);
        lic.issued_at = sqlite3_column_int64(s, 3);
        lic.expires_at = sqlite3_column_int64(s, 4);
        lic.edition = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 5)));
        lic.features_json = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 6)));
        lic.status = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 7)));
        result.push_back(std::move(lic));
    }
    sqlite3_finalize(s);
    return result;
}

std::optional<License> LicenseStore::get_active_license() const {
    if (!db_)
        return std::nullopt;

    std::shared_lock lock(mtx_);

    const char* sql =
        "SELECT id, organization, seat_count, issued_at, expires_at, "
        "edition, features_json, status "
        "FROM licenses WHERE status = 'active' "
        "ORDER BY activated_at DESC LIMIT 1;";

    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &s, nullptr) != SQLITE_OK)
        return std::nullopt;

    std::optional<License> result;
    if (sqlite3_step(s) == SQLITE_ROW) {
        License lic;
        lic.id = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 0)));
        lic.organization = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 1)));
        lic.seat_count = sqlite3_column_int64(s, 2);
        lic.issued_at = sqlite3_column_int64(s, 3);
        lic.expires_at = sqlite3_column_int64(s, 4);
        lic.edition = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 5)));
        lic.features_json = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 6)));
        lic.status = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 7)));
        result = std::move(lic);
    }
    sqlite3_finalize(s);
    return result;
}

bool LicenseStore::remove_license(const std::string& id) {
    if (!db_ || id.empty())
        return false;

    std::unique_lock lock(mtx_);

    // Remove associated alerts first
    {
        sqlite3_stmt* da = nullptr;
        if (sqlite3_prepare_v2(db_,
                               "DELETE FROM license_alerts WHERE license_id = ?;",
                               -1, &da, nullptr) == SQLITE_OK) {
            sqlite3_bind_text(da, 1, id.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_step(da);
            sqlite3_finalize(da);
        }
    }

    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_, "DELETE FROM licenses WHERE id = ?;",
                           -1, &s, nullptr) != SQLITE_OK)
        return false;
    sqlite3_bind_text(s, 1, id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(s);
    sqlite3_finalize(s);
    bool removed = sqlite3_changes(db_) > 0;
    if (removed)
        spdlog::info("LicenseStore: removed license '{}'", id);
    return removed;
}

// -- Validation ---------------------------------------------------------------

void LicenseStore::validate(int64_t current_agent_count) {
    if (!db_)
        return;

    std::unique_lock lock(mtx_);

    auto now = now_epoch();

    // Fetch all active licenses
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "SELECT id, seat_count, expires_at, status "
                           "FROM licenses WHERE status = 'active';",
                           -1, &s, nullptr) != SQLITE_OK)
        return;

    struct LicenseRow {
        std::string id;
        int64_t seat_count{0};
        int64_t expires_at{0};
        std::string status;
    };
    std::vector<LicenseRow> active;

    while (sqlite3_step(s) == SQLITE_ROW) {
        LicenseRow row;
        row.id = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 0)));
        row.seat_count = sqlite3_column_int64(s, 1);
        row.expires_at = sqlite3_column_int64(s, 2);
        row.status = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 3)));
        active.push_back(std::move(row));
    }
    sqlite3_finalize(s);

    for (const auto& lic : active) {
        std::string new_status = "active";

        // Check expiry
        if (lic.expires_at > 0 && now > lic.expires_at) {
            new_status = "expired";
            add_alert(lic.id, "expired",
                      std::string("License '") + lic.id + "' has expired");
        } else if (lic.expires_at > 0) {
            int64_t days = (lic.expires_at - now) / 86400;
            if (days <= 30) {
                add_alert(lic.id, "expiry_warning",
                          std::string("License '") + lic.id + "' expires in " +
                              std::to_string(days) + " days");
            }
        }

        // Check seat usage
        if (lic.seat_count > 0 && current_agent_count > lic.seat_count) {
            new_status = "exceeded";
            add_alert(lic.id, "exceeded",
                      std::string("License '") + lic.id + "' seat limit exceeded (" +
                          std::to_string(current_agent_count) + "/" +
                          std::to_string(lic.seat_count) + ")");
        } else if (lic.seat_count > 0) {
            double usage = static_cast<double>(current_agent_count) /
                           static_cast<double>(lic.seat_count);
            if (usage >= 0.9) {
                add_alert(lic.id, "seat_limit_warning",
                          std::string("License '") + lic.id + "' at " +
                              std::to_string(static_cast<int>(usage * 100)) + "% seat capacity (" +
                              std::to_string(current_agent_count) + "/" +
                              std::to_string(lic.seat_count) + ")");
            }
        }

        // Update status if changed
        if (new_status != lic.status) {
            sqlite3_stmt* upd = nullptr;
            if (sqlite3_prepare_v2(db_,
                                   "UPDATE licenses SET status = ? WHERE id = ?;",
                                   -1, &upd, nullptr) == SQLITE_OK) {
                sqlite3_bind_text(upd, 1, new_status.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(upd, 2, lic.id.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_step(upd);
                sqlite3_finalize(upd);
                spdlog::warn("LicenseStore: license '{}' status changed to '{}'",
                             lic.id, new_status);
            }
        }
    }
}

std::string LicenseStore::get_status() const {
    if (!db_)
        return "no_database";

    std::shared_lock lock(mtx_);

    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "SELECT status FROM licenses "
                           "ORDER BY activated_at DESC LIMIT 1;",
                           -1, &s, nullptr) != SQLITE_OK)
        return "unknown";

    std::string status = "unlicensed";
    if (sqlite3_step(s) == SQLITE_ROW) {
        auto val = sqlite3_column_text(s, 0);
        if (val)
            status = reinterpret_cast<const char*>(val);
    }
    sqlite3_finalize(s);
    return status;
}

// -- Alerts -------------------------------------------------------------------

void LicenseStore::add_alert(const std::string& license_id, const std::string& type,
                              const std::string& message) {
    // Caller must hold the write lock (unique_lock on mtx_).
    auto now = now_epoch();

    // Deduplicate: do not create another alert of the same type for the same
    // license within the last 24 hours.
    {
        sqlite3_stmt* chk = nullptr;
        if (sqlite3_prepare_v2(db_,
                               "SELECT id FROM license_alerts "
                               "WHERE license_id = ? AND alert_type = ? AND triggered_at > ?;",
                               -1, &chk, nullptr) == SQLITE_OK) {
            sqlite3_bind_text(chk, 1, license_id.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(chk, 2, type.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(chk, 3, now - 86400);
            bool exists = (sqlite3_step(chk) == SQLITE_ROW);
            sqlite3_finalize(chk);
            if (exists)
                return; // already alerted recently
        }
    }

    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "INSERT INTO license_alerts "
                           "(license_id, alert_type, message, triggered_at) "
                           "VALUES (?, ?, ?, ?);",
                           -1, &s, nullptr) != SQLITE_OK)
        return;

    sqlite3_bind_text(s, 1, license_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 2, type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 3, message.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(s, 4, now);
    sqlite3_step(s);
    sqlite3_finalize(s);

    spdlog::info("LicenseStore: alert [{}] for license '{}': {}", type, license_id, message);
}

std::vector<LicenseAlert> LicenseStore::list_alerts(bool unacknowledged_only) const {
    std::vector<LicenseAlert> result;
    if (!db_)
        return result;

    std::shared_lock lock(mtx_);

    std::string sql =
        "SELECT id, license_id, alert_type, message, triggered_at, acknowledged "
        "FROM license_alerts";
    if (unacknowledged_only)
        sql += " WHERE acknowledged = 0";
    sql += " ORDER BY triggered_at DESC;";

    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &s, nullptr) != SQLITE_OK)
        return result;

    while (sqlite3_step(s) == SQLITE_ROW) {
        LicenseAlert alert;
        alert.id = sqlite3_column_int64(s, 0);
        alert.license_id = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 1)));
        alert.alert_type = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 2)));
        alert.message = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 3)));
        alert.triggered_at = sqlite3_column_int64(s, 4);
        alert.acknowledged = sqlite3_column_int(s, 5) != 0;
        result.push_back(std::move(alert));
    }
    sqlite3_finalize(s);
    return result;
}

bool LicenseStore::acknowledge_alert(int64_t alert_id) {
    if (!db_)
        return false;

    std::unique_lock lock(mtx_);

    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "UPDATE license_alerts SET acknowledged = 1 WHERE id = ?;",
                           -1, &s, nullptr) != SQLITE_OK)
        return false;
    sqlite3_bind_int64(s, 1, alert_id);
    sqlite3_step(s);
    sqlite3_finalize(s);
    return sqlite3_changes(db_) > 0;
}

// -- Feature checks -----------------------------------------------------------

bool LicenseStore::has_feature(const std::string& feature) const {
    if (!db_ || feature.empty())
        return false;

    std::shared_lock lock(mtx_);

    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "SELECT features_json FROM licenses "
                           "WHERE status = 'active' "
                           "ORDER BY activated_at DESC LIMIT 1;",
                           -1, &s, nullptr) != SQLITE_OK)
        return false;

    bool found = false;
    if (sqlite3_step(s) == SQLITE_ROW) {
        auto json_str = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 0)));
        // Simple substring search in the JSON array for the feature string.
        // Parse features_json as a JSON array and check for exact match
        auto parsed = nlohmann::json::parse(json_str, nullptr, false);
        if (parsed.is_array()) {
            for (const auto& elem : parsed) {
                if (elem.is_string() && elem.get<std::string>() == feature) {
                    found = true;
                    break;
                }
            }
        }
    }
    sqlite3_finalize(s);
    return found;
}

int64_t LicenseStore::seat_count() const {
    if (!db_)
        return 0;

    std::shared_lock lock(mtx_);

    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "SELECT seat_count FROM licenses "
                           "WHERE status = 'active' "
                           "ORDER BY activated_at DESC LIMIT 1;",
                           -1, &s, nullptr) != SQLITE_OK)
        return 0;

    int64_t count = 0;
    if (sqlite3_step(s) == SQLITE_ROW)
        count = sqlite3_column_int64(s, 0);
    sqlite3_finalize(s);
    return count;
}

int64_t LicenseStore::days_remaining() const {
    if (!db_)
        return 0;

    std::shared_lock lock(mtx_);

    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "SELECT expires_at FROM licenses "
                           "WHERE status = 'active' "
                           "ORDER BY activated_at DESC LIMIT 1;",
                           -1, &s, nullptr) != SQLITE_OK)
        return 0;

    int64_t days = 0;
    if (sqlite3_step(s) == SQLITE_ROW) {
        int64_t expires = sqlite3_column_int64(s, 0);
        if (expires == 0) {
            // Perpetual license — return 0 to signal "no expiry"
            days = 0;
        } else {
            int64_t remaining = expires - now_epoch();
            days = remaining > 0 ? remaining / 86400 : 0;
        }
    }
    sqlite3_finalize(s);
    return days;
}

} // namespace yuzu::server
