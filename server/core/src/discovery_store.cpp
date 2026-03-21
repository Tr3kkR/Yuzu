#include "discovery_store.hpp"

#include <spdlog/spdlog.h>

#include <chrono>

namespace yuzu::server {

static int64_t now_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

static const char* safe(const char* p) {
    return p ? p : "";
}

// ── Construction / teardown ──────────────────────────────────────────────────

DiscoveryStore::DiscoveryStore(const std::filesystem::path& db_path) {
    int rc = sqlite3_open(db_path.string().c_str(), &db_);
    if (rc != SQLITE_OK) {
        spdlog::error("DiscoveryStore: failed to open {}: {}", db_path.string(),
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
    spdlog::info("DiscoveryStore: opened {}", db_path.string());
}

DiscoveryStore::~DiscoveryStore() {
    if (db_)
        sqlite3_close(db_);
}

bool DiscoveryStore::is_open() const {
    return db_ != nullptr;
}

void DiscoveryStore::create_tables() {
    const char* sql = R"(
        CREATE TABLE IF NOT EXISTS discovered_devices (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address      TEXT NOT NULL UNIQUE,
            mac_address     TEXT NOT NULL DEFAULT '',
            hostname        TEXT NOT NULL DEFAULT '',
            managed         INTEGER NOT NULL DEFAULT 0,
            agent_id        TEXT NOT NULL DEFAULT '',
            discovered_by   TEXT NOT NULL DEFAULT '',
            discovered_at   INTEGER NOT NULL DEFAULT 0,
            last_seen       INTEGER NOT NULL DEFAULT 0,
            subnet          TEXT NOT NULL DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_discovery_ip ON discovered_devices(ip_address);
        CREATE INDEX IF NOT EXISTS idx_discovery_managed ON discovered_devices(managed);
        CREATE INDEX IF NOT EXISTS idx_discovery_subnet ON discovered_devices(subnet);
    )";
    char* err = nullptr;
    if (sqlite3_exec(db_, sql, nullptr, nullptr, &err) != SQLITE_OK) {
        spdlog::error("DiscoveryStore: create_tables failed: {}", err ? err : "unknown");
        sqlite3_free(err);
    }
}

// ── Operations ───────────────────────────────────────────────────────────────

std::expected<void, std::string>
DiscoveryStore::upsert_device(const DiscoveredDevice& device) {
    if (!db_)
        return std::unexpected("database not open");

    auto now = now_epoch();

    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(
            db_,
            "INSERT INTO discovered_devices "
            "(ip_address, mac_address, hostname, managed, agent_id, discovered_by, "
            "discovered_at, last_seen, subnet) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(ip_address) DO UPDATE SET "
            "mac_address = excluded.mac_address, "
            "hostname = CASE WHEN excluded.hostname != '' THEN excluded.hostname "
            "               ELSE discovered_devices.hostname END, "
            "last_seen = excluded.last_seen, "
            "subnet = excluded.subnet;",
            -1, &s, nullptr) != SQLITE_OK)
        return std::unexpected(sqlite3_errmsg(db_));

    sqlite3_bind_text(s, 1, device.ip_address.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 2, device.mac_address.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 3, device.hostname.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(s, 4, device.managed ? 1 : 0);
    sqlite3_bind_text(s, 5, device.agent_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 6, device.discovered_by.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(s, 7, device.discovered_at > 0 ? device.discovered_at : now);
    sqlite3_bind_int64(s, 8, now);
    sqlite3_bind_text(s, 9, device.subnet.c_str(), -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(s);
    sqlite3_finalize(s);
    if (rc != SQLITE_DONE)
        return std::unexpected(sqlite3_errmsg(db_));

    return {};
}

std::vector<DiscoveredDevice> DiscoveryStore::list_devices(const std::string& subnet_filter) const {
    std::vector<DiscoveredDevice> result;
    if (!db_)
        return result;

    sqlite3_stmt* s = nullptr;
    if (subnet_filter.empty()) {
        if (sqlite3_prepare_v2(
                db_,
                "SELECT id, ip_address, mac_address, hostname, managed, agent_id, "
                "discovered_by, discovered_at, last_seen, subnet "
                "FROM discovered_devices ORDER BY last_seen DESC;",
                -1, &s, nullptr) != SQLITE_OK)
            return result;
    } else {
        if (sqlite3_prepare_v2(
                db_,
                "SELECT id, ip_address, mac_address, hostname, managed, agent_id, "
                "discovered_by, discovered_at, last_seen, subnet "
                "FROM discovered_devices WHERE subnet = ? ORDER BY last_seen DESC;",
                -1, &s, nullptr) != SQLITE_OK)
            return result;
        sqlite3_bind_text(s, 1, subnet_filter.c_str(), -1, SQLITE_TRANSIENT);
    }

    while (sqlite3_step(s) == SQLITE_ROW) {
        DiscoveredDevice d;
        d.id = sqlite3_column_int64(s, 0);
        d.ip_address = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 1)));
        d.mac_address = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 2)));
        d.hostname = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 3)));
        d.managed = sqlite3_column_int(s, 4) != 0;
        d.agent_id = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 5)));
        d.discovered_by = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 6)));
        d.discovered_at = sqlite3_column_int64(s, 7);
        d.last_seen = sqlite3_column_int64(s, 8);
        d.subnet = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 9)));
        result.push_back(std::move(d));
    }
    sqlite3_finalize(s);
    return result;
}

std::optional<DiscoveredDevice>
DiscoveryStore::get_device(const std::string& ip_address) const {
    if (!db_)
        return std::nullopt;

    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(
            db_,
            "SELECT id, ip_address, mac_address, hostname, managed, agent_id, "
            "discovered_by, discovered_at, last_seen, subnet "
            "FROM discovered_devices WHERE ip_address = ? LIMIT 1;",
            -1, &s, nullptr) != SQLITE_OK)
        return std::nullopt;

    sqlite3_bind_text(s, 1, ip_address.c_str(), -1, SQLITE_TRANSIENT);

    std::optional<DiscoveredDevice> result;
    if (sqlite3_step(s) == SQLITE_ROW) {
        DiscoveredDevice d;
        d.id = sqlite3_column_int64(s, 0);
        d.ip_address = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 1)));
        d.mac_address = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 2)));
        d.hostname = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 3)));
        d.managed = sqlite3_column_int(s, 4) != 0;
        d.agent_id = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 5)));
        d.discovered_by = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 6)));
        d.discovered_at = sqlite3_column_int64(s, 7);
        d.last_seen = sqlite3_column_int64(s, 8);
        d.subnet = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 9)));
        result = std::move(d);
    }
    sqlite3_finalize(s);
    return result;
}

std::expected<void, std::string>
DiscoveryStore::mark_managed(const std::string& ip_address, const std::string& agent_id) {
    if (!db_)
        return std::unexpected("database not open");

    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(
            db_,
            "UPDATE discovered_devices SET managed = 1, agent_id = ? WHERE ip_address = ?;",
            -1, &s, nullptr) != SQLITE_OK)
        return std::unexpected(sqlite3_errmsg(db_));

    sqlite3_bind_text(s, 1, agent_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 2, ip_address.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(s);
    sqlite3_finalize(s);

    if (sqlite3_changes(db_) == 0)
        return std::unexpected("device not found");

    return {};
}

std::expected<void, std::string>
DiscoveryStore::clear_results(const std::string& subnet) {
    if (!db_)
        return std::unexpected("database not open");

    sqlite3_stmt* s = nullptr;
    if (subnet.empty()) {
        if (sqlite3_prepare_v2(db_, "DELETE FROM discovered_devices;",
                               -1, &s, nullptr) != SQLITE_OK)
            return std::unexpected(sqlite3_errmsg(db_));
    } else {
        if (sqlite3_prepare_v2(db_, "DELETE FROM discovered_devices WHERE subnet = ?;",
                               -1, &s, nullptr) != SQLITE_OK)
            return std::unexpected(sqlite3_errmsg(db_));
        sqlite3_bind_text(s, 1, subnet.c_str(), -1, SQLITE_TRANSIENT);
    }

    int rc = sqlite3_step(s);
    sqlite3_finalize(s);
    if (rc != SQLITE_DONE)
        return std::unexpected(sqlite3_errmsg(db_));

    return {};
}

} // namespace yuzu::server
