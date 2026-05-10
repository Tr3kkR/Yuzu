#include "offload_target_store.hpp"
#include "migration_runner.hpp"

#include <httplib.h>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>
#include <sqlite3.h>

#include <algorithm>
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

static bool event_matches(const std::string& event_types, const std::string& event_type) {
    if (event_types == "*")
        return true;
    std::istringstream stream(event_types);
    std::string token;
    while (std::getline(stream, token, ',')) {
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

// ── Auth-type enum bridge ───────────────────────────────────────────────────

std::string offload_auth_type_to_string(OffloadAuthType t) {
    switch (t) {
    case OffloadAuthType::Bearer: return "bearer";
    case OffloadAuthType::Basic:  return "basic";
    case OffloadAuthType::Hmac:   return "hmac";
    case OffloadAuthType::None:   break;
    }
    return "none";
}

OffloadAuthType offload_auth_type_from_string(const std::string& s) {
    if (s == "bearer") return OffloadAuthType::Bearer;
    if (s == "basic")  return OffloadAuthType::Basic;
    if (s == "hmac")   return OffloadAuthType::Hmac;
    return OffloadAuthType::None;
}

// ── HMAC-SHA256 ─────────────────────────────────────────────────────────────

std::string OffloadTargetStore::hmac_sha256(const std::string& secret, const std::string& data) {
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

// ── Base64 (RFC 4648, standard alphabet, padded) ────────────────────────────

std::string OffloadTargetStore::base64_encode(const std::string& data) {
    static constexpr char kAlphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((data.size() + 2) / 3) * 4);
    std::size_t i = 0;
    while (i + 3 <= data.size()) {
        uint32_t triplet = (static_cast<uint8_t>(data[i]) << 16) |
                           (static_cast<uint8_t>(data[i + 1]) << 8) |
                           static_cast<uint8_t>(data[i + 2]);
        out.push_back(kAlphabet[(triplet >> 18) & 0x3F]);
        out.push_back(kAlphabet[(triplet >> 12) & 0x3F]);
        out.push_back(kAlphabet[(triplet >> 6) & 0x3F]);
        out.push_back(kAlphabet[triplet & 0x3F]);
        i += 3;
    }
    if (i < data.size()) {
        uint32_t triplet = static_cast<uint8_t>(data[i]) << 16;
        if (i + 1 < data.size())
            triplet |= static_cast<uint8_t>(data[i + 1]) << 8;
        out.push_back(kAlphabet[(triplet >> 18) & 0x3F]);
        out.push_back(kAlphabet[(triplet >> 12) & 0x3F]);
        out.push_back(i + 1 < data.size() ? kAlphabet[(triplet >> 6) & 0x3F] : '=');
        out.push_back('=');
    }
    return out;
}

// ── Constructor / Destructor ────────────────────────────────────────────────

OffloadTargetStore::OffloadTargetStore(const std::filesystem::path& db_path) {
    int rc = sqlite3_open_v2(db_path.string().c_str(), &db_,
                             SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                             nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("OffloadTargetStore: failed to open {}: {}", db_path.string(),
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
    spdlog::info("OffloadTargetStore: opened {}", db_path.string());
}

OffloadTargetStore::~OffloadTargetStore() {
    // Intentionally NOT calling flush_all() here. flush_all() spawns
    // detached worker threads that capture `this` and reach back into
    // `mtx_` / `db_` via record_delivery — those references would dangle
    // once the destructor returns. WebhookStore (the sibling) follows the
    // same pattern: pending fire-and-forget deliveries are lost on
    // shutdown. Operators that need at-least-once semantics should set
    // batch_size=1 (immediate dispatch, no buffer) or build a queue
    // upstream of the offload receiver.
    if (db_)
        sqlite3_close(db_);
}

bool OffloadTargetStore::is_open() const {
    return db_ != nullptr;
}

void OffloadTargetStore::create_tables() {
    static const std::vector<Migration> kMigrations = {
        {1, R"(
            CREATE TABLE IF NOT EXISTS offload_targets (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                name            TEXT    NOT NULL UNIQUE,
                url             TEXT    NOT NULL,
                auth_type       TEXT    NOT NULL DEFAULT 'none',
                auth_credential TEXT    NOT NULL DEFAULT '',
                event_types     TEXT    NOT NULL DEFAULT '*',
                batch_size      INTEGER NOT NULL DEFAULT 1,
                enabled         INTEGER NOT NULL DEFAULT 1,
                created_at      INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS offload_deliveries (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id    INTEGER NOT NULL,
                event_type   TEXT    NOT NULL,
                event_count  INTEGER NOT NULL DEFAULT 1,
                payload      TEXT    NOT NULL,
                status_code  INTEGER NOT NULL DEFAULT 0,
                delivered_at INTEGER NOT NULL,
                error        TEXT    NOT NULL DEFAULT '',
                FOREIGN KEY (target_id) REFERENCES offload_targets(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_offload_delivery_target_ts
                ON offload_deliveries(target_id, delivered_at);
            -- Partial index on enabled targets: fire_event scans this on
            -- every dispatched event, and at N>~50 targets a full scan
            -- shows up in profiles. The partial form (WHERE enabled = 1)
            -- keeps the index small because disabled rows never need to
            -- be scanned (perf-S2).
            CREATE INDEX IF NOT EXISTS idx_offload_targets_enabled
                ON offload_targets(enabled) WHERE enabled = 1;
        )"},
    };
    if (!MigrationRunner::run(db_, "offload_target_store", kMigrations)) {
        spdlog::error("OffloadTargetStore: schema migration failed, closing database");
        sqlite3_close(db_);
        db_ = nullptr;
        return;
    }
    sqlite3_exec(db_, "PRAGMA foreign_keys = ON;", nullptr, nullptr, nullptr);
}

// ── CRUD ────────────────────────────────────────────────────────────────────

int64_t OffloadTargetStore::create_target(const std::string& name, const std::string& url,
                                          OffloadAuthType auth_type,
                                          const std::string& auth_credential,
                                          const std::string& event_types, int batch_size,
                                          bool enabled) {
    if (name.empty()) {
        spdlog::warn("OffloadTargetStore: rejected target with empty name");
        return -1;
    }
    if (!url.starts_with("http://") && !url.starts_with("https://")) {
        spdlog::warn("OffloadTargetStore: rejected target with invalid URL scheme: {}", url);
        return -1;
    }
    if (batch_size < 1) {
        spdlog::warn("OffloadTargetStore: batch_size must be >= 1, got {}", batch_size);
        return -1;
    }
    // Reject control characters in operator-supplied free-text fields.
    // - auth_credential: Bearer tokens flow into the
    //   `Authorization: Bearer <credential>` header verbatim — CR/LF
    //   would inject a second header and smuggle a request through any
    //   HTTP-aware proxy. Basic is base64'd, HMAC is hex; the guard
    //   fires for all auth_types as defence-in-depth.
    // - name, url: both are emitted verbatim into the DELETE audit-row
    //   `detail` field as `name=<n> url=<u>`. A control byte (CR/LF/NUL)
    //   in either field would line-split the audit row and forge a
    //   downstream event in any SIEM that parses log lines individually
    //   (round-3 re-review residual finding).
    auto has_control_byte = [](const std::string& s) {
        for (char c : s) {
            if (static_cast<unsigned char>(c) < 0x20)
                return true;
        }
        return false;
    };
    if (has_control_byte(auth_credential)) {
        spdlog::warn(
            "OffloadTargetStore: rejected target with control bytes in auth_credential: {}",
            name);
        return -1;
    }
    if (has_control_byte(name)) {
        spdlog::warn("OffloadTargetStore: rejected target with control bytes in name");
        return -1;
    }
    if (has_control_byte(url)) {
        spdlog::warn(
            "OffloadTargetStore: rejected target with control bytes in url (target name: {})",
            name);
        return -1;
    }

    std::unique_lock lock(mtx_);
    if (!db_)
        return -1;

    const char* sql = "INSERT INTO offload_targets "
                      "(name, url, auth_type, auth_credential, event_types, batch_size, enabled, "
                      " created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return -1;

    auto now = epoch_seconds();
    auto auth_str = offload_auth_type_to_string(auth_type);
    sqlite3_bind_text(stmt, 1, name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, url.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, auth_str.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, auth_credential.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, event_types.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 6, batch_size);
    sqlite3_bind_int(stmt, 7, enabled ? 1 : 0);
    sqlite3_bind_int64(stmt, 8, now);

    int64_t result = -1;
    if (sqlite3_step(stmt) == SQLITE_DONE) {
        result = sqlite3_last_insert_rowid(db_);
    }
    sqlite3_finalize(stmt);
    return result;
}

static OffloadTarget row_to_target_no_secret(sqlite3_stmt* stmt) {
    OffloadTarget t;
    t.id = sqlite3_column_int64(stmt, 0);
    if (auto v = sqlite3_column_text(stmt, 1))
        t.name = reinterpret_cast<const char*>(v);
    if (auto v = sqlite3_column_text(stmt, 2))
        t.url = reinterpret_cast<const char*>(v);
    if (auto v = sqlite3_column_text(stmt, 3))
        t.auth_type = offload_auth_type_from_string(reinterpret_cast<const char*>(v));
    // auth_credential intentionally not selected
    if (auto v = sqlite3_column_text(stmt, 4))
        t.event_types = reinterpret_cast<const char*>(v);
    t.batch_size = sqlite3_column_int(stmt, 5);
    t.enabled = sqlite3_column_int(stmt, 6) != 0;
    t.created_at = sqlite3_column_int64(stmt, 7);
    return t;
}

std::vector<OffloadTarget> OffloadTargetStore::list(int limit, int offset) const {
    std::shared_lock lock(mtx_);
    std::vector<OffloadTarget> results;
    if (!db_)
        return results;

    const char* sql =
        "SELECT id, name, url, auth_type, event_types, batch_size, enabled, created_at "
        "FROM offload_targets ORDER BY created_at DESC LIMIT ? OFFSET ?";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return results;

    sqlite3_bind_int(stmt, 1, limit);
    sqlite3_bind_int(stmt, 2, offset);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        results.push_back(row_to_target_no_secret(stmt));
    }
    sqlite3_finalize(stmt);
    return results;
}

std::optional<OffloadTarget> OffloadTargetStore::get(int64_t id) const {
    std::shared_lock lock(mtx_);
    if (!db_)
        return std::nullopt;

    const char* sql =
        "SELECT id, name, url, auth_type, event_types, batch_size, enabled, created_at "
        "FROM offload_targets WHERE id = ?";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return std::nullopt;

    sqlite3_bind_int64(stmt, 1, id);
    std::optional<OffloadTarget> out;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        out = row_to_target_no_secret(stmt);
    }
    sqlite3_finalize(stmt);
    return out;
}

std::optional<OffloadTarget> OffloadTargetStore::get_by_name(const std::string& name) const {
    std::shared_lock lock(mtx_);
    if (!db_)
        return std::nullopt;

    const char* sql =
        "SELECT id, name, url, auth_type, event_types, batch_size, enabled, created_at "
        "FROM offload_targets WHERE name = ?";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return std::nullopt;

    sqlite3_bind_text(stmt, 1, name.c_str(), -1, SQLITE_TRANSIENT);
    std::optional<OffloadTarget> out;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        out = row_to_target_no_secret(stmt);
    }
    sqlite3_finalize(stmt);
    return out;
}

bool OffloadTargetStore::delete_target(int64_t id) {
    std::unique_lock lock(mtx_);
    if (!db_)
        return false;

    {
        const char* del_d = "DELETE FROM offload_deliveries WHERE target_id = ?";
        sqlite3_stmt* d_stmt = nullptr;
        if (sqlite3_prepare_v2(db_, del_d, -1, &d_stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_int64(d_stmt, 1, id);
            sqlite3_step(d_stmt);
            sqlite3_finalize(d_stmt);
        }
    }

    const char* sql = "DELETE FROM offload_targets WHERE id = ?";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return false;

    sqlite3_bind_int64(stmt, 1, id);
    sqlite3_step(stmt);
    bool deleted = sqlite3_changes(db_) > 0;
    sqlite3_finalize(stmt);

    // Drop any in-memory buffer for this target (no flush — the operator
    // asked to delete it; pending events go away with it).
    if (deleted) {
        std::lock_guard buf_lock(buf_mu_);
        buffers_.erase(id);
    }
    return deleted;
}

std::vector<OffloadDelivery> OffloadTargetStore::get_deliveries(int64_t target_id,
                                                                int limit) const {
    std::shared_lock lock(mtx_);
    std::vector<OffloadDelivery> results;
    if (!db_)
        return results;

    const char* sql =
        "SELECT id, target_id, event_type, event_count, payload, status_code, delivered_at, error "
        "FROM offload_deliveries WHERE target_id = ? "
        "ORDER BY delivered_at DESC LIMIT ?";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return results;

    sqlite3_bind_int64(stmt, 1, target_id);
    sqlite3_bind_int(stmt, 2, limit);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        OffloadDelivery d;
        d.id = sqlite3_column_int64(stmt, 0);
        d.target_id = sqlite3_column_int64(stmt, 1);
        if (auto v = sqlite3_column_text(stmt, 2))
            d.event_type = reinterpret_cast<const char*>(v);
        d.event_count = sqlite3_column_int(stmt, 3);
        if (auto v = sqlite3_column_text(stmt, 4))
            d.payload = reinterpret_cast<const char*>(v);
        d.status_code = sqlite3_column_int(stmt, 5);
        d.delivered_at = sqlite3_column_int64(stmt, 6);
        if (auto v = sqlite3_column_text(stmt, 7))
            d.error = reinterpret_cast<const char*>(v);
        results.push_back(std::move(d));
    }
    sqlite3_finalize(stmt);
    return results;
}

// ── Delivery recording ──────────────────────────────────────────────────────

void OffloadTargetStore::record_delivery(int64_t target_id, const std::string& event_type,
                                         int event_count, const std::string& payload,
                                         int status_code, const std::string& error) {
    std::unique_lock lock(mtx_);
    if (!db_)
        return;

    const char* sql = "INSERT INTO offload_deliveries "
                      "(target_id, event_type, event_count, payload, status_code, "
                      " delivered_at, error) "
                      "VALUES (?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return;

    auto now = epoch_seconds();
    sqlite3_bind_int64(stmt, 1, target_id);
    sqlite3_bind_text(stmt, 2, event_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 3, event_count);
    sqlite3_bind_text(stmt, 4, payload.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 5, status_code);
    sqlite3_bind_int64(stmt, 6, now);
    sqlite3_bind_text(stmt, 7, error.c_str(), -1, SQLITE_TRANSIENT);

    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

// ── Concurrency limiter for async delivery ──────────────────────────────────

/// Counting semaphore limiting concurrent offload deliveries to 10 threads.
/// Mirrors WebhookStore — both stores share the dispatch shape but each
/// maintains its own quota (operator can run a ten-target SIEM fleet
/// without it crowding webhook delivery slots).
static std::counting_semaphore<10> offload_semaphore{10};

namespace {
/// RAII guard for the delivery semaphore — ensures release on every exit
/// path including throw / unhandled exception. The hand-paired
/// acquire/release was a slot-leak risk (sec-L7) if any delivery step
/// threw between acquire and release.
struct SemaGuard {
    SemaGuard() { offload_semaphore.acquire(); }
    ~SemaGuard() { offload_semaphore.release(); }
    SemaGuard(const SemaGuard&) = delete;
    SemaGuard& operator=(const SemaGuard&) = delete;
};
} // namespace

// ── Single delivery (runs on a worker thread) ───────────────────────────────

std::string OffloadTargetStore::build_batch_body(const std::vector<BufferedEvent>& events) {
    nlohmann::json arr = nlohmann::json::array();
    for (const auto& e : events) {
        try {
            arr.push_back(nlohmann::json::parse(e.payload_json));
        } catch (...) {
            // Fallback: treat the unparseable event as a raw string so we
            // never silently drop it. The receiver gets a clear-text
            // record that they can investigate.
            arr.push_back(e.payload_json);
        }
    }
    return nlohmann::json({{"events", arr}}).dump();
}

void OffloadTargetStore::deliver_single(const OffloadTarget& tgt, const std::string& event_type,
                                        int event_count, const std::string& payload_body) {
    // Defence-in-depth scheme re-check: the create-time guard rejects
    // non-http(s) URLs, but a tampered row (manual SQLite write, future
    // update path, or any other write surface that bypasses
    // create_target) would otherwise be dispatched here verbatim. Record
    // the rejection so the operator sees it in /deliveries.
    if (!tgt.url.starts_with("http://") && !tgt.url.starts_with("https://")) {
        record_delivery(tgt.id, event_type, event_count, payload_body, 0, "invalid_scheme");
        spdlog::warn("OffloadTargetStore: refused dispatch with non-http(s) URL: {}", tgt.url);
        return;
    }

    SemaGuard guard;

    int status_code = 0;
    std::string error;

    try {
        std::string url = tgt.url;
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
        headers.emplace("X-Yuzu-Event-Count", std::to_string(event_count));

        switch (tgt.auth_type) {
        case OffloadAuthType::Bearer:
            if (!tgt.auth_credential.empty())
                headers.emplace("Authorization", "Bearer " + tgt.auth_credential);
            break;
        case OffloadAuthType::Basic:
            if (!tgt.auth_credential.empty())
                headers.emplace("Authorization", "Basic " + base64_encode(tgt.auth_credential));
            break;
        case OffloadAuthType::Hmac:
            if (!tgt.auth_credential.empty()) {
                auto sig = hmac_sha256(tgt.auth_credential, payload_body);
                headers.emplace("X-Yuzu-Signature", "sha256=" + sig);
            }
            break;
        case OffloadAuthType::None:
            break;
        }

        auto result = cli.Post(path, headers, payload_body, "application/json");
        if (result) {
            status_code = result->status;
        } else {
            error = "connection_failed";
            spdlog::warn("OffloadTargetStore: delivery to {} failed: connection error", tgt.url);
        }
    } catch (const std::exception& ex) {
        error = ex.what();
        spdlog::warn("OffloadTargetStore: delivery to {} failed: {}", tgt.url, error);
    }

    record_delivery(tgt.id, event_type, event_count, payload_body, status_code, error);
    // SemaGuard releases on scope exit.
}

// ── Event firing (async — returns immediately) ──────────────────────────────

void OffloadTargetStore::fire_event(const std::string& event_type,
                                    const std::string& payload_json,
                                    const std::vector<std::string>& target_filter) {
    // Gather matching, enabled targets under shared lock.
    std::vector<OffloadTarget> matching;
    {
        std::shared_lock lock(mtx_);
        if (!db_)
            return;

        const char* sql =
            "SELECT id, name, url, auth_type, auth_credential, event_types, batch_size, "
            "       enabled, created_at "
            "FROM offload_targets WHERE enabled = 1";
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
            return;

        while (sqlite3_step(stmt) == SQLITE_ROW) {
            OffloadTarget t;
            t.id = sqlite3_column_int64(stmt, 0);
            if (auto v = sqlite3_column_text(stmt, 1))
                t.name = reinterpret_cast<const char*>(v);
            if (auto v = sqlite3_column_text(stmt, 2))
                t.url = reinterpret_cast<const char*>(v);
            if (auto v = sqlite3_column_text(stmt, 3))
                t.auth_type = offload_auth_type_from_string(reinterpret_cast<const char*>(v));
            if (auto v = sqlite3_column_text(stmt, 4))
                t.auth_credential = reinterpret_cast<const char*>(v);
            if (auto v = sqlite3_column_text(stmt, 5))
                t.event_types = reinterpret_cast<const char*>(v);
            t.batch_size = sqlite3_column_int(stmt, 6);
            t.enabled = true;
            t.created_at = sqlite3_column_int64(stmt, 8);

            if (!event_matches(t.event_types, event_type))
                continue;

            if (!target_filter.empty()) {
                auto it = std::find(target_filter.begin(), target_filter.end(), t.name);
                if (it == target_filter.end())
                    continue;
            }

            matching.push_back(std::move(t));
        }
        sqlite3_finalize(stmt);
    }

    // Per-target dispatch: batch_size==1 → fire immediately; otherwise
    // append to buffer and flush on threshold.
    for (auto& tgt : matching) {
        if (tgt.batch_size <= 1) {
            std::thread([this, tgt, event_type, payload_json]() {
                deliver_single(tgt, event_type, /*event_count=*/1, payload_json);
            }).detach();
            continue;
        }

        std::vector<BufferedEvent> to_flush;
        {
            std::lock_guard buf_lock(buf_mu_);
            auto& buf = buffers_[tgt.id];
            buf.push_back({event_type, payload_json});
            if (static_cast<int>(buf.size()) >= tgt.batch_size) {
                to_flush = std::move(buf);
                buf.clear();
            }
        }

        if (!to_flush.empty()) {
            auto body = build_batch_body(to_flush);
            int count = static_cast<int>(to_flush.size());
            std::thread([this, tgt, event_type, count, body]() {
                deliver_single(tgt, event_type, count, body);
            }).detach();
        }
    }
}

void OffloadTargetStore::flush_all() {
    // Snapshot non-empty buffers under buf_mu_, then read fresh target
    // configs under mtx_, then fire deliveries with neither lock held.
    std::unordered_map<int64_t, std::vector<BufferedEvent>> snapshot;
    {
        std::lock_guard buf_lock(buf_mu_);
        for (auto& [id, evs] : buffers_) {
            if (!evs.empty()) {
                snapshot.emplace(id, std::move(evs));
                evs.clear();
            }
        }
    }
    if (snapshot.empty())
        return;

    for (auto& [target_id, events] : snapshot) {
        if (events.empty())
            continue;
        auto tgt_opt = get(target_id);
        if (!tgt_opt)
            continue;
        // Refresh credential too (get() redacts), so re-read directly.
        OffloadTarget tgt = *tgt_opt;
        {
            std::shared_lock lock(mtx_);
            if (db_) {
                const char* sql = "SELECT auth_credential FROM offload_targets WHERE id = ?";
                sqlite3_stmt* stmt = nullptr;
                if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) == SQLITE_OK) {
                    sqlite3_bind_int64(stmt, 1, target_id);
                    if (sqlite3_step(stmt) == SQLITE_ROW) {
                        if (auto v = sqlite3_column_text(stmt, 0))
                            tgt.auth_credential = reinterpret_cast<const char*>(v);
                    }
                    sqlite3_finalize(stmt);
                }
            }
        }

        auto event_type = events.front().event_type; // representative
        auto body = build_batch_body(events);
        int count = static_cast<int>(events.size());
        std::thread([this, tgt, event_type, count, body]() {
            deliver_single(tgt, event_type, count, body);
        }).detach();
    }
}

} // namespace yuzu::server
