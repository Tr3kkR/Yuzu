#include "webhook_store.hpp"
#include "migration_runner.hpp"

#include <httplib.h>
#include <spdlog/spdlog.h>
#include <sqlite3.h>

#include <chrono>
#include <iomanip>
#include <semaphore>
#include <shared_mutex>
#include <sstream>
#include <thread>

#ifdef _WIN32
// clang-format off
#include <windows.h>
#include <bcrypt.h>
// clang-format on
#pragma comment(lib, "bcrypt.lib")
#else
#include <openssl/evp.h>
#include <openssl/hmac.h>
#endif

namespace yuzu::server {

// ── Helpers ─────────────────────────────────────────────────────────────────

static std::string bytes_to_hex(const uint8_t* data, std::size_t len) {
    std::ostringstream oss;
    for (std::size_t i = 0; i < len; ++i) {
        oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(data[i]);
    }
    return oss.str();
}

static int64_t epoch_seconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

/// Check if a comma-separated list of event types contains a specific event.
/// Supports wildcard "*" to match all events.
static bool event_matches(const std::string& event_types, const std::string& event_type) {
    if (event_types == "*")
        return true;

    std::istringstream stream(event_types);
    std::string token;
    while (std::getline(stream, token, ',')) {
        // Trim whitespace
        auto start = token.find_first_not_of(' ');
        auto end = token.find_last_not_of(' ');
        if (start != std::string::npos) {
            auto trimmed = token.substr(start, end - start + 1);
            if (trimmed == event_type || trimmed == "*")
                return true;
        }
    }
    return false;
}

// ── HMAC-SHA256 ─────────────────────────────────────────────────────────────

std::string WebhookStore::hmac_sha256(const std::string& secret, const std::string& data) {
    uint8_t hash[32] = {};

#ifdef _WIN32
    BCRYPT_ALG_HANDLE alg = nullptr;
    auto status = BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr,
                                              BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!BCRYPT_SUCCESS(status))
        return {};

    BCRYPT_HASH_HANDLE hHash = nullptr;
    status = BCryptCreateHash(alg, &hHash, nullptr, 0,
                              reinterpret_cast<PUCHAR>(const_cast<char*>(secret.data())),
                              static_cast<ULONG>(secret.size()), 0);
    if (BCRYPT_SUCCESS(status)) {
        BCryptHashData(hHash, reinterpret_cast<PUCHAR>(const_cast<char*>(data.data())),
                       static_cast<ULONG>(data.size()), 0);
        BCryptFinishHash(hHash, hash, 32, 0);
        BCryptDestroyHash(hHash);
    }
    BCryptCloseAlgorithmProvider(alg, 0);
#else
    unsigned int len = 32;
    HMAC(EVP_sha256(), secret.data(), static_cast<int>(secret.size()),
         reinterpret_cast<const unsigned char*>(data.data()), data.size(), hash, &len);
#endif

    return bytes_to_hex(hash, 32);
}

// ── Constructor / Destructor ────────────────────────────────────────────────

WebhookStore::WebhookStore(const std::filesystem::path& db_path) {
    int rc = sqlite3_open_v2(db_path.string().c_str(), &db_,
                             SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                             nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("WebhookStore: failed to open {}: {}", db_path.string(),
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
    spdlog::info("WebhookStore: opened {}", db_path.string());
}

WebhookStore::~WebhookStore() {
    if (db_)
        sqlite3_close(db_);
}

bool WebhookStore::is_open() const {
    return db_ != nullptr;
}

void WebhookStore::create_tables() {
    static const std::vector<Migration> kMigrations = {
        {1, R"(
            CREATE TABLE IF NOT EXISTS webhooks (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                url         TEXT    NOT NULL,
                event_types TEXT    NOT NULL DEFAULT '*',
                secret      TEXT    NOT NULL DEFAULT '',
                enabled     INTEGER NOT NULL DEFAULT 1,
                created_at  INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS webhook_deliveries (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                webhook_id  INTEGER NOT NULL,
                event_type  TEXT    NOT NULL,
                payload     TEXT    NOT NULL,
                status_code INTEGER NOT NULL DEFAULT 0,
                delivered_at INTEGER NOT NULL,
                error       TEXT    NOT NULL DEFAULT '',
                FOREIGN KEY (webhook_id) REFERENCES webhooks(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_delivery_webhook_ts
                ON webhook_deliveries(webhook_id, delivered_at);
        )"},
    };
    if (!MigrationRunner::run(db_, "webhook_store", kMigrations)) {
        spdlog::error("WebhookStore: schema migration failed, closing database");
        sqlite3_close(db_);
        db_ = nullptr;
        return;
    }
    // Enable foreign keys
    sqlite3_exec(db_, "PRAGMA foreign_keys = ON;", nullptr, nullptr, nullptr);
}

// ── CRUD ────────────────────────────────────────────────────────────────────

int64_t WebhookStore::create_webhook(const std::string& url, const std::string& event_types,
                                     const std::string& secret, bool enabled) {
    // Validate URL scheme — only http:// and https:// are allowed
    if (!url.starts_with("http://") && !url.starts_with("https://")) {
        spdlog::warn("WebhookStore: rejected webhook with invalid URL scheme: {}", url);
        return -1;
    }

    std::unique_lock lock(mtx_);
    if (!db_)
        return -1;

    const char* sql =
        "INSERT INTO webhooks (url, event_types, secret, enabled, created_at) VALUES (?, ?, ?, ?, ?)";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return -1;

    auto now = epoch_seconds();
    sqlite3_bind_text(stmt, 1, url.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, event_types.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, secret.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 4, enabled ? 1 : 0);
    sqlite3_bind_int64(stmt, 5, now);

    int64_t result = -1;
    if (sqlite3_step(stmt) == SQLITE_DONE) {
        result = sqlite3_last_insert_rowid(db_);
    }
    sqlite3_finalize(stmt);
    return result;
}

std::vector<Webhook> WebhookStore::list(int limit, int offset) const {
    std::shared_lock lock(mtx_);
    std::vector<Webhook> results;
    if (!db_)
        return results;

    // Do not SELECT secret — list() must never expose webhook secrets
    const char* sql = "SELECT id, url, event_types, enabled, created_at "
                      "FROM webhooks ORDER BY created_at DESC LIMIT ? OFFSET ?";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return results;

    sqlite3_bind_int(stmt, 1, limit);
    sqlite3_bind_int(stmt, 2, offset);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        Webhook w;
        w.id = sqlite3_column_int64(stmt, 0);
        auto u = sqlite3_column_text(stmt, 1);
        if (u)
            w.url = reinterpret_cast<const char*>(u);
        auto et = sqlite3_column_text(stmt, 2);
        if (et)
            w.event_types = reinterpret_cast<const char*>(et);
        // Secret intentionally not queried — never exposed in list results
        w.secret = "";
        w.enabled = sqlite3_column_int(stmt, 3) != 0;
        w.created_at = sqlite3_column_int64(stmt, 4);
        results.push_back(std::move(w));
    }
    sqlite3_finalize(stmt);
    return results;
}

bool WebhookStore::delete_webhook(int64_t id) {
    std::unique_lock lock(mtx_);
    if (!db_)
        return false;

    // Delete deliveries first (or rely on ON DELETE CASCADE)
    const char* del_deliveries = "DELETE FROM webhook_deliveries WHERE webhook_id = ?";
    sqlite3_stmt* d_stmt = nullptr;
    if (sqlite3_prepare_v2(db_, del_deliveries, -1, &d_stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_int64(d_stmt, 1, id);
        sqlite3_step(d_stmt);
        sqlite3_finalize(d_stmt);
    }

    const char* sql = "DELETE FROM webhooks WHERE id = ?";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return false;

    sqlite3_bind_int64(stmt, 1, id);
    sqlite3_step(stmt);
    bool deleted = sqlite3_changes(db_) > 0;
    sqlite3_finalize(stmt);
    return deleted;
}

std::vector<WebhookDelivery> WebhookStore::get_deliveries(int64_t webhook_id, int limit) const {
    std::shared_lock lock(mtx_);
    std::vector<WebhookDelivery> results;
    if (!db_)
        return results;

    const char* sql = "SELECT id, webhook_id, event_type, payload, status_code, delivered_at, error "
                      "FROM webhook_deliveries WHERE webhook_id = ? "
                      "ORDER BY delivered_at DESC LIMIT ?";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return results;

    sqlite3_bind_int64(stmt, 1, webhook_id);
    sqlite3_bind_int(stmt, 2, limit);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        WebhookDelivery d;
        d.id = sqlite3_column_int64(stmt, 0);
        d.webhook_id = sqlite3_column_int64(stmt, 1);
        auto et = sqlite3_column_text(stmt, 2);
        if (et)
            d.event_type = reinterpret_cast<const char*>(et);
        auto pl = sqlite3_column_text(stmt, 3);
        if (pl)
            d.payload = reinterpret_cast<const char*>(pl);
        d.status_code = sqlite3_column_int(stmt, 4);
        d.delivered_at = sqlite3_column_int64(stmt, 5);
        auto err = sqlite3_column_text(stmt, 6);
        if (err)
            d.error = reinterpret_cast<const char*>(err);
        results.push_back(std::move(d));
    }
    sqlite3_finalize(stmt);
    return results;
}

// ── Delivery recording ──────────────────────────────────────────────────────

void WebhookStore::record_delivery(int64_t webhook_id, const std::string& event_type,
                                   const std::string& payload, int status_code,
                                   const std::string& error) {
    // Caller must hold unique_lock on mtx_
    if (!db_)
        return;

    const char* sql =
        "INSERT INTO webhook_deliveries (webhook_id, event_type, payload, status_code, delivered_at, error) "
        "VALUES (?, ?, ?, ?, ?, ?)";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return;

    auto now = epoch_seconds();
    sqlite3_bind_int64(stmt, 1, webhook_id);
    sqlite3_bind_text(stmt, 2, event_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, payload.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 4, status_code);
    sqlite3_bind_int64(stmt, 5, now);
    sqlite3_bind_text(stmt, 6, error.c_str(), -1, SQLITE_TRANSIENT);

    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

// ── Concurrency limiter for async delivery ──────────────────────────────────

/// Counting semaphore limiting concurrent webhook deliveries to 10 threads.
static std::counting_semaphore<10> delivery_semaphore{10};

// ── Single webhook delivery (runs on a worker thread) ───────────────────────

void WebhookStore::deliver_single(const Webhook& wh, const std::string& event_type,
                                  const std::string& payload_json) {
    // Acquire semaphore slot — blocks if 10 deliveries already in flight
    delivery_semaphore.acquire();

    int status_code = 0;
    std::string error;

    try {
        // Parse the URL to extract scheme, host, port, path
        std::string url = wh.url;
        std::string scheme = "http";
        std::string host_port;
        std::string path = "/";

        if (url.starts_with("https://")) {
            scheme = "https";
            url = url.substr(8);
        } else if (url.starts_with("http://")) {
            url = url.substr(7);
        }

        auto path_pos = url.find('/');
        if (path_pos != std::string::npos) {
            host_port = url.substr(0, path_pos);
            path = url.substr(path_pos);
        } else {
            host_port = url;
        }

        httplib::Client cli(scheme + "://" + host_port);
        cli.set_connection_timeout(5);
        cli.set_read_timeout(10);

        httplib::Headers headers;
        headers.emplace("Content-Type", "application/json");
        headers.emplace("X-Yuzu-Event", event_type);

        // Sign with HMAC-SHA256 if secret is configured
        if (!wh.secret.empty()) {
            auto sig = hmac_sha256(wh.secret, payload_json);
            headers.emplace("X-Yuzu-Signature", "sha256=" + sig);
        }

        auto result = cli.Post(path, headers, payload_json, "application/json");
        if (result) {
            status_code = result->status;
        } else {
            error = "connection_failed";
            spdlog::warn("WebhookStore: delivery to {} failed: connection error", wh.url);
        }
    } catch (const std::exception& ex) {
        error = ex.what();
        spdlog::warn("WebhookStore: delivery to {} failed: {}", wh.url, error);
    }

    // Record delivery under unique lock
    {
        std::unique_lock lock(mtx_);
        record_delivery(wh.id, event_type, payload_json, status_code, error);
    }

    delivery_semaphore.release();
}

// ── Event firing (async — returns immediately) ──────────────────────────────

void WebhookStore::fire_event(const std::string& event_type, const std::string& payload_json) {
    // Gather matching webhooks under shared lock
    std::vector<Webhook> matching;
    {
        std::shared_lock lock(mtx_);
        if (!db_)
            return;

        const char* sql = "SELECT id, url, event_types, secret, enabled, created_at "
                          "FROM webhooks WHERE enabled = 1";
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
            return;

        while (sqlite3_step(stmt) == SQLITE_ROW) {
            Webhook w;
            w.id = sqlite3_column_int64(stmt, 0);
            auto u = sqlite3_column_text(stmt, 1);
            if (u)
                w.url = reinterpret_cast<const char*>(u);
            auto et = sqlite3_column_text(stmt, 2);
            if (et)
                w.event_types = reinterpret_cast<const char*>(et);
            auto sec = sqlite3_column_text(stmt, 3);
            if (sec)
                w.secret = reinterpret_cast<const char*>(sec);
            w.enabled = true;
            w.created_at = sqlite3_column_int64(stmt, 5);

            if (event_matches(w.event_types, event_type)) {
                matching.push_back(std::move(w));
            }
        }
        sqlite3_finalize(stmt);
    }

    // Deliver to each matching webhook asynchronously on detached threads.
    // The counting semaphore limits concurrent deliveries to 10.
    for (const auto& wh : matching) {
        std::thread([this, wh, event_type, payload_json]() {
            deliver_single(wh, event_type, payload_json);
        }).detach();
    }
}

} // namespace yuzu::server
