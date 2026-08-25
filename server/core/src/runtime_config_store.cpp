#include "runtime_config_store.hpp"
#include "config_secret_keys.hpp"

#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "pg/secret_codec.hpp"
#include "secure_buffer.hpp"
#include "sqlite_raii.hpp"
#include "utf8_sanitize.hpp"

#include <yuzu/metrics.hpp>

#include <libpq-fe.h>
#include <openssl/evp.h>
#include <spdlog/spdlog.h>
#include <sqlite3.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <map>
#include <span>
#include <system_error>

namespace yuzu::server {

// ── Allowed keys (safe for runtime modification) ─────────────────────────────

static const std::vector<std::string> kAllowedKeys = {
    "heartbeat_timeout",             // seconds before marking agent offline
    "response_retention_days",       // days to keep instruction responses
    "audit_retention_days",          // days to keep audit events
    "guardian_event_retention_days", // days to keep guaranteed-state events
    "auto_approve_enabled",          // "true" or "false"
    "log_level",                     // trace|debug|info|warn|error
    "oidc_issuer",                   // OIDC issuer URL
    "oidc_client_id",                // OIDC client ID
    "oidc_client_secret",            // OIDC client secret — SecretCodec-envelope
                                     // encrypted; see runtime_config_secrets (ADR-0060)
    "oidc_redirect_uri",             // OIDC redirect URI
    "oidc_admin_group",              // OIDC admin group ID
    "oidc_skip_tls_verify",          // "true" or "false"
    "plugin_signing_required",       // see plugin_signing::kPluginSigningRequiredKey — must match
    // F1 DEX alerting (Settings → DEX alerts; applied live, no restart)
    "dex_alert_routing",             // JSON array of routed obs_types
    "dex_blast_min_devices",         // blast-radius alert shape (clamped on apply)
    "dex_blast_window_seconds",      //
    "dex_blast_cooldown_seconds",    //
    // F2a PR3 cohort metrics export (Settings → DEX alerts; next gauge sweep)
    "dex_cohort_export_key",         // tag key; "" = export disabled (validated on apply)
};

const std::vector<std::string>& RuntimeConfigStore::allowed_keys() {
    return kAllowedKeys;
}

bool RuntimeConfigStore::is_allowed_key(const std::string& key) {
    return std::find(kAllowedKeys.begin(), kAllowedKeys.end(), key) != kAllowedKeys.end();
}

bool RuntimeConfigStore::is_secret_key(const std::string& key) {
    return is_secret_config_key(key); // the shared leaf; see config_secret_keys.hpp
}

namespace {

constexpr const char* kStoreName = "runtime_config_store";

// Bounded acquires (ADR-0012 §2(a)). Reads/writes here are boot-time and
// admin-Settings-driven — low volume, but never unbounded. Construction and
// the one-shot backfill are the only unbounded acquires.
constexpr std::chrono::milliseconds kAcquireTimeout{2000};
constexpr std::chrono::milliseconds kWriteTimeout{2000};
constexpr std::chrono::milliseconds kBackfillTxnTimeout{60000};

const std::vector<pg::PgMigration>& migrations() {
    // Unqualified DDL: the runner sets search_path to the store schema for
    // the migration txn. Runtime statements below schema-qualify explicitly.
    //
    // Three tables (ADR-0060): `runtime_config` holds every non-secret value
    // PLUS a secret key's value when it is EMPTY (see the header's "empty
    // secret" note); `runtime_config_secrets` holds a secret key's value
    // ONLY when it is non-empty, envelope-encrypted (ADR-0010) —
    // `sealed_value` is NOT NULL because a row's mere presence there is the
    // "has a real secret" signal, so an empty ciphertext is never written
    // (the store deletes the row instead); `runtime_config_meta` carries the
    // ADR-0009 backfill completion marker + source fingerprint, mirroring
    // `TagStore::tag_store_meta`.
    static const std::vector<pg::PgMigration> kMigrations = {
        {1, R"(
            CREATE TABLE runtime_config (
                key         TEXT PRIMARY KEY,
                value       TEXT NOT NULL DEFAULT '',
                updated_by  TEXT NOT NULL DEFAULT '',
                updated_at  BIGINT NOT NULL
            );

            CREATE TABLE runtime_config_secrets (
                key          TEXT PRIMARY KEY,
                sealed_value BYTEA NOT NULL,
                updated_by   TEXT NOT NULL DEFAULT '',
                updated_at   BIGINT NOT NULL
            );

            CREATE TABLE runtime_config_meta (
                key    TEXT PRIMARY KEY,
                value  TEXT NOT NULL
            );
        )"},
    };
    return kMigrations;
}

// ── PG result helpers (file-local — no shared header across stores; mirrors
//    auth_db.cpp / plugin_config_store.cpp / offline_endpoint_store.cpp's own
//    file-local copies) ───────────────────────────────────────────────────

const char* col(PGresult* res, int row, int c) {
    return PQgetisnull(res, row, c) ? "" : PQgetvalue(res, row, c);
}
std::string col_str(PGresult* res, int row, int c) { return std::string(col(res, row, c)); }
std::int64_t to_i64(const char* s) {
    if (s == nullptr || s[0] == '\0')
        return 0;
    return static_cast<std::int64_t>(std::strtoll(s, nullptr, 10));
}
std::int64_t now_secs() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::string bytes_to_hex(std::span<const std::uint8_t> bytes) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (std::uint8_t b : bytes) {
        out.push_back(kHex[(b >> 4) & 0xF]);
        out.push_back(kHex[b & 0xF]);
    }
    return out;
}

std::vector<std::uint8_t> hex_to_bytes(std::string_view hex) {
    std::vector<std::uint8_t> out;
    out.reserve(hex.size() / 2);
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (std::size_t i = 0; i + 1 < hex.size(); i += 2) {
        const int hi = nibble(hex[i]);
        const int lo = nibble(hex[i + 1]);
        if (hi < 0 || lo < 0)
            break;
        out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
    }
    return out;
}

// Same treatment as TagStore/CustomPropertiesStore/RbacStore (ADR-0041/0045):
// scrub invalid UTF-8 to U+FFFD, then replace any embedded NUL the scrub
// leaves behind — PostgreSQL TEXT can't store NUL and libpq's text-format
// bind C-string-truncates at the first one. Applied to every free-text
// value INCLUDING the backfill path.
std::string sanitize_pg_text(std::string_view s) {
    std::string out = sanitize_utf8_strict(s);
    std::size_t pos = 0;
    while ((pos = out.find('\0', pos)) != std::string::npos) {
        out.replace(pos, 1, "\xEF\xBF\xBD");
        pos += 3;
    }
    return out;
}

RuntimeConfigEntry plain_row(PGresult* r, int i) {
    RuntimeConfigEntry e;
    e.key = col_str(r, i, 0);
    e.value = col_str(r, i, 1);
    e.updated_by = col_str(r, i, 2);
    e.updated_at = to_i64(col(r, i, 3));
    return e;
}

// ── Read-degrade observability (#1675 convention, mirrors ProductPackStore) ──
constexpr const char* kReasonStoreNotOpen = "store_not_open";
constexpr const char* kReasonPoolTimeout = "pool_acquire_timeout";
constexpr const char* kReasonQueryError = "query_error";
constexpr const char* kReasonCryptoError = "crypto_error";
constexpr std::uint64_t kReadDegradeLogSample = 100;
constexpr std::int64_t kDegradeEpisodeGapSecs = 60;

struct DegradeSampler {
    std::atomic<std::uint64_t> count{0};
    std::atomic<std::int64_t> last_ts{0};
};

bool note_read_degrade(yuzu::MetricsRegistry* metrics, const char* reason, DegradeSampler& s) {
    if (metrics)
        metrics->counter("yuzu_server_runtime_config_read_degrade_total", {{"reason", reason}})
            .increment();
    const std::int64_t now = now_secs();
    const std::int64_t prev = s.last_ts.exchange(now, std::memory_order_relaxed);
    const std::uint64_t n = s.count.fetch_add(1, std::memory_order_relaxed) + 1;
    const bool new_episode = prev == 0 || (now - prev) > kDegradeEpisodeGapSecs;
    return new_episode || (n % kReadDegradeLogSample) == 0;
}

// One sampler per distinct read call site (a shared sampler would let a hot get_all_with_secrets()
// degrade mask a cold get_with_secrets() one from ever logging).
DegradeSampler g_get_all_sampler;
DegradeSampler g_get_sampler;

} // namespace

// ── Constructor ───────────────────────────────────────────────────────────

RuntimeConfigStore::RuntimeConfigStore(pg::PgPool& pool, pg::SecretCodec& secret_codec)
    : pool_(pool), secret_codec_(secret_codec) {
    // Construction-only unbounded acquire (ADR-0012 §2) — every runtime
    // acquire elsewhere in this file is bounded. The playbook names this
    // sequence "the open_with_migrations helper", but no such helper exists
    // anywhere in the tree — every store (offline_endpoint_store.cpp,
    // auth_db.cpp, plugin_config_store.cpp, tag_store.cpp) hand-rolls this
    // exact acquire/run/release sequence; this mirrors that precedent.
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error("RuntimeConfigStore: no database connection at construction ({}) — "
                      "runtime config disabled",
                      pool_.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error("RuntimeConfigStore: schema migration failed — runtime config disabled");
        return;
    }
    lease.reset(); // release before touching the codec (never hold a lease across other work)

    // ADR-0010 register-before-init sequencing (playbook §3 / AuthDB /
    // PluginConfigStore precedent): this ctor registers the column; the
    // CALLER runs secret_codec.init() immediately after this ctor returns.
    if (!secret_codec_.register_secret_column(
            {kStoreName, "runtime_config_secrets", "sealed_value", "key"})) {
        spdlog::error("RuntimeConfigStore: failed to register runtime_config_secrets.sealed_value "
                      "as a secret column — runtime config disabled");
        return;
    }

    open_ = true;
    spdlog::info("RuntimeConfigStore: opened (schema {})", kStoreName);
}

// ── Queries ──────────────────────────────────────────────────────────────────

namespace {

std::expected<std::string, std::string>
decrypt_sealed_value(pg::SecretCodec& codec, const std::string& key, const char* hex) {
    const auto bytes = hex_to_bytes(hex);
    auto dec = codec.decrypt(pg::SecretCodec::SecretId{kStoreName, "runtime_config_secrets",
                                                        "sealed_value", key},
                             std::span<const std::uint8_t>{bytes.data(), bytes.size()});
    if (!dec.has_value()) {
        spdlog::error("RuntimeConfigStore: decrypt failed for key '{}' ({})", key,
                      pg::SecretCodec::to_string(dec.error().cls));
        return std::unexpected(std::string(kRuntimeConfigDbErrorPrefix) +
                               "secret decrypt failed for key '" + key + "'");
    }
    return std::string(reinterpret_cast<const char*>(dec->data()), dec->size());
}

} // namespace

std::expected<std::vector<RuntimeConfigEntry>, std::string>
RuntimeConfigStore::get_all_with_secrets() const {
    if (!open_) {
        if (note_read_degrade(metrics_, kReasonStoreNotOpen, g_get_all_sampler))
            spdlog::warn("RuntimeConfigStore: get_all_with_secrets degraded - store not open");
        return std::unexpected(std::string(kRuntimeConfigDbErrorPrefix) + "store not open");
    }

    auto lease = pool_.try_acquire_for(kAcquireTimeout);
    if (!lease) {
        if (note_read_degrade(metrics_, kReasonPoolTimeout, g_get_all_sampler))
            spdlog::warn("RuntimeConfigStore: get_all_with_secrets degraded - pool acquire timeout");
        return std::unexpected(std::string(kRuntimeConfigDbErrorPrefix) +
                               "no database connection in time");
    }

    std::map<std::string, RuntimeConfigEntry> merged;

    pg::PgResult plain = pg::exec_params(
        lease.get(),
        "SELECT key, value, updated_by, updated_at FROM runtime_config_store.runtime_config "
        "ORDER BY key",
        std::vector<std::string>{});
    if (plain.status() != PGRES_TUPLES_OK) {
        if (note_read_degrade(metrics_, kReasonQueryError, g_get_all_sampler))
            spdlog::warn("RuntimeConfigStore: get_all_with_secrets degraded - plain query error");
        return std::unexpected(std::string(kRuntimeConfigDbErrorPrefix) + "database read failed");
    }
    for (int i = 0; i < PQntuples(plain.get()); ++i) {
        auto e = plain_row(plain.get(), i);
        const std::string k = e.key;
        merged[k] = std::move(e);
    }

    pg::PgResult secrets = pg::exec_params(
        lease.get(),
        "SELECT key, encode(sealed_value, 'hex'), updated_by, updated_at "
        "FROM runtime_config_store.runtime_config_secrets ORDER BY key",
        std::vector<std::string>{});
    if (secrets.status() != PGRES_TUPLES_OK) {
        if (note_read_degrade(metrics_, kReasonQueryError, g_get_all_sampler))
            spdlog::warn("RuntimeConfigStore: get_all_with_secrets degraded - secrets query error");
        return std::unexpected(std::string(kRuntimeConfigDbErrorPrefix) + "database read failed");
    }
    for (int i = 0; i < PQntuples(secrets.get()); ++i) {
        const std::string key = col_str(secrets.get(), i, 0);
        auto real = decrypt_sealed_value(secret_codec_, key, col(secrets.get(), i, 1));
        if (!real.has_value()) {
            if (note_read_degrade(metrics_, kReasonCryptoError, g_get_all_sampler))
                spdlog::warn("RuntimeConfigStore: get_all_with_secrets degraded - decrypt failed");
            return std::unexpected(real.error());
        }
        RuntimeConfigEntry e;
        e.key = key;
        e.value = *real;
        e.updated_by = col_str(secrets.get(), i, 2);
        e.updated_at = to_i64(col(secrets.get(), i, 3));
        merged[key] = std::move(e); // secrets-table presence always wins (see header)
    }

    std::vector<RuntimeConfigEntry> out;
    out.reserve(merged.size());
    for (auto& kv : merged)
        out.push_back(std::move(kv.second));
    return out;
}

std::expected<std::vector<RuntimeConfigEntry>, std::string> RuntimeConfigStore::get_all() const {
    auto entries = get_all_with_secrets();
    if (!entries.has_value())
        return entries;
    for (auto& e : *entries) {
        // An EMPTY secret stays empty. There is nothing to protect, and replacing it
        // with the non-empty placeholder destroys the only signal a caller has for
        // set-vs-unset: GET /api/config derives `is_set` from !value.empty(), so
        // blanket replacement made `is_set` unconditionally true and no stored
        // secret could ever report false.
        if (is_secret_key(e.key) && !e.value.empty())
            e.value = redacted_placeholder();
    }
    return entries;
}

std::expected<std::optional<RuntimeConfigEntry>, std::string>
RuntimeConfigStore::get_with_secrets(const std::string& key) const {
    if (!open_) {
        if (note_read_degrade(metrics_, kReasonStoreNotOpen, g_get_sampler))
            spdlog::warn("RuntimeConfigStore: get_with_secrets degraded - store not open");
        return std::unexpected(std::string(kRuntimeConfigDbErrorPrefix) + "store not open");
    }

    auto lease = pool_.try_acquire_for(kAcquireTimeout);
    if (!lease) {
        if (note_read_degrade(metrics_, kReasonPoolTimeout, g_get_sampler))
            spdlog::warn("RuntimeConfigStore: get_with_secrets degraded - pool acquire timeout");
        return std::unexpected(std::string(kRuntimeConfigDbErrorPrefix) +
                               "no database connection in time");
    }

    pg::PgResult secret = pg::exec_params(
        lease.get(),
        "SELECT encode(sealed_value, 'hex'), updated_by, updated_at "
        "FROM runtime_config_store.runtime_config_secrets WHERE key = $1",
        std::vector<std::string>{key});
    if (secret.status() != PGRES_TUPLES_OK) {
        if (note_read_degrade(metrics_, kReasonQueryError, g_get_sampler))
            spdlog::warn("RuntimeConfigStore: get_with_secrets degraded - secret query error");
        return std::unexpected(std::string(kRuntimeConfigDbErrorPrefix) + "database read failed");
    }
    if (PQntuples(secret.get()) > 0) {
        auto real = decrypt_sealed_value(secret_codec_, key, col(secret.get(), 0, 0));
        if (!real.has_value()) {
            if (note_read_degrade(metrics_, kReasonCryptoError, g_get_sampler))
                spdlog::warn("RuntimeConfigStore: get_with_secrets degraded - decrypt failed");
            return std::unexpected(real.error());
        }
        RuntimeConfigEntry e;
        e.key = key;
        e.value = *real;
        e.updated_by = col_str(secret.get(), 0, 1);
        e.updated_at = to_i64(col(secret.get(), 0, 2));
        return std::optional<RuntimeConfigEntry>(std::move(e));
    }

    pg::PgResult plain = pg::exec_params(
        lease.get(),
        "SELECT key, value, updated_by, updated_at FROM runtime_config_store.runtime_config "
        "WHERE key = $1",
        std::vector<std::string>{key});
    if (plain.status() != PGRES_TUPLES_OK) {
        if (note_read_degrade(metrics_, kReasonQueryError, g_get_sampler))
            spdlog::warn("RuntimeConfigStore: get_with_secrets degraded - plain query error");
        return std::unexpected(std::string(kRuntimeConfigDbErrorPrefix) + "database read failed");
    }
    if (PQntuples(plain.get()) == 0)
        return std::optional<RuntimeConfigEntry>(std::nullopt);
    return std::optional<RuntimeConfigEntry>(plain_row(plain.get(), 0));
}

std::expected<std::optional<RuntimeConfigEntry>, std::string>
RuntimeConfigStore::get(const std::string& key) const {
    auto entry = get_with_secrets(key);
    if (!entry.has_value())
        return entry;
    if (*entry && is_secret_key((*entry)->key) && !(*entry)->value.empty())
        (*entry)->value = redacted_placeholder();
    return entry;
}

std::string RuntimeConfigStore::get_value(const std::string& key) const {
    auto entry = get(key);
    if (!entry.has_value() || !*entry)
        return {};
    return (*entry)->value;
}

std::string RuntimeConfigStore::get_value_with_secrets(const std::string& key) const {
    auto entry = get_with_secrets(key);
    if (!entry.has_value() || !*entry)
        return {};
    return (*entry)->value;
}

// ── Mutations ────────────────────────────────────────────────────────────────

std::expected<void, std::string> RuntimeConfigStore::set(const std::string& key,
                                                         const std::string& value,
                                                         const std::string& updated_by) {
    if (!open_)
        return std::unexpected(std::string(kRuntimeConfigDbErrorPrefix) + "store not open");

    if (!is_allowed_key(key))
        return std::unexpected("key '" + key + "' is not a configurable runtime setting");

    // The redaction placeholder is not a credential. GET /api/config omits a secret's
    // value precisely so a round-tripping client cannot write this back -- but the
    // startup log prints it, and a human copying that line reaches the same place.
    // Storing it would break SSO and destroy the real secret, so refuse at the sink
    // rather than relying on every caller to notice.
    if (is_secret_key(key) && is_redaction_placeholder(value))
        return std::unexpected("value is the redaction placeholder, not a credential; send the "
                               "real secret, or omit the key to leave it unchanged");

    // Basic validation per key
    if (key == "heartbeat_timeout" || key == "response_retention_days" ||
        key == "audit_retention_days") {
        try {
            int val = std::stoi(value);
            if (val <= 0)
                return std::unexpected("value must be a positive integer");
        } catch (...) {
            return std::unexpected("value must be a valid integer");
        }
    }

    if (key == "auto_approve_enabled" || key == "plugin_signing_required") {
        if (value != "true" && value != "false")
            return std::unexpected("value must be 'true' or 'false'");
    }

    if (key == "log_level") {
        static const std::vector<std::string> valid_levels = {"trace", "debug", "info", "warn",
                                                              "error"};
        if (std::find(valid_levels.begin(), valid_levels.end(), value) == valid_levels.end())
            return std::unexpected("value must be one of: trace, debug, info, warn, error");
    }

    const std::string sanitized_value = sanitize_pg_text(value);
    const std::string sanitized_by = sanitize_pg_text(updated_by);
    const auto now = now_secs();

    if (is_secret_key(key)) {
        if (sanitized_value.empty()) {
            // Empty-stays-empty (see header): no ciphertext, ever. Clear any
            // stale ciphertext row and record the clear in the plain table so
            // updated_by/updated_at survive.
            const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) -> bool {
                pg::PgResult del = pg::exec_params(
                    c, "DELETE FROM runtime_config_store.runtime_config_secrets WHERE key = $1",
                    std::vector<std::string>{key});
                if (del.status() != PGRES_COMMAND_OK)
                    return false;
                pg::PgResult up = pg::exec_params(
                    c,
                    "INSERT INTO runtime_config_store.runtime_config (key, value, updated_by, "
                    "updated_at) VALUES ($1, '', $2, $3::bigint) ON CONFLICT (key) DO UPDATE SET "
                    "value = '', updated_by = EXCLUDED.updated_by, updated_at = EXCLUDED.updated_at",
                    std::vector<std::string>{key, sanitized_by, std::to_string(now)});
                return up.status() == PGRES_COMMAND_OK;
            });
            if (!ok)
                return std::unexpected(std::string(kRuntimeConfigDbErrorPrefix) +
                                       "database write failed");
        } else {
            // ADR-0010 encrypt-failure semantics: encrypt OUTSIDE any lease,
            // BEFORE any write. A failed encrypt touches nothing.
            const auto* bytes = reinterpret_cast<const std::uint8_t*>(sanitized_value.data());
            auto enc = secret_codec_.encrypt(
                pg::SecretCodec::SecretId{kStoreName, "runtime_config_secrets", "sealed_value", key},
                std::span<const std::uint8_t>{bytes, sanitized_value.size()});
            if (!enc.has_value()) {
                spdlog::error("RuntimeConfigStore::set: encrypt failed for key '{}'", key);
                return std::unexpected(std::string(kRuntimeConfigDbErrorPrefix) +
                                       "secret encrypt failed");
            }
            const std::string hex = bytes_to_hex(*enc);
            const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) -> bool {
                pg::PgResult del = pg::exec_params(
                    c, "DELETE FROM runtime_config_store.runtime_config WHERE key = $1",
                    std::vector<std::string>{key});
                if (del.status() != PGRES_COMMAND_OK)
                    return false;
                pg::PgResult up = pg::exec_params(
                    c,
                    "INSERT INTO runtime_config_store.runtime_config_secrets (key, sealed_value, "
                    "updated_by, updated_at) VALUES ($1, decode($2, 'hex'), $3, $4::bigint) "
                    "ON CONFLICT (key) DO UPDATE SET sealed_value = EXCLUDED.sealed_value, "
                    "updated_by = EXCLUDED.updated_by, updated_at = EXCLUDED.updated_at",
                    std::vector<std::string>{key, hex, sanitized_by, std::to_string(now)});
                return up.status() == PGRES_COMMAND_OK;
            });
            if (!ok)
                return std::unexpected(std::string(kRuntimeConfigDbErrorPrefix) +
                                       "database write failed");
        }
    } else {
        auto lease = pool_.try_acquire_for(kWriteTimeout);
        if (!lease)
            return std::unexpected(std::string(kRuntimeConfigDbErrorPrefix) +
                                   "no database connection in time");
        pg::PgResult res = pg::exec_params(
            lease.get(),
            "INSERT INTO runtime_config_store.runtime_config (key, value, updated_by, updated_at) "
            "VALUES ($1, $2, $3, $4::bigint) ON CONFLICT (key) DO UPDATE SET "
            "value = EXCLUDED.value, updated_by = EXCLUDED.updated_by, "
            "updated_at = EXCLUDED.updated_at",
            std::vector<std::string>{key, sanitized_value, sanitized_by, std::to_string(now)});
        if (res.status() != PGRES_COMMAND_OK)
            return std::unexpected(std::string(kRuntimeConfigDbErrorPrefix) +
                                   "database write failed");
    }

    // Apply the change immediately
    if (key == "log_level") {
        spdlog::set_level(spdlog::level::from_str(value));
        spdlog::info("Runtime config: log_level changed to '{}'", value);
    }

    return {};
}

bool RuntimeConfigStore::remove(const std::string& key) {
    if (!open_)
        return false;

    bool removed = false;
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) -> bool {
        pg::PgResult r1 = pg::exec_params(
            c, "DELETE FROM runtime_config_store.runtime_config WHERE key = $1 RETURNING key",
            std::vector<std::string>{key});
        if (r1.status() != PGRES_TUPLES_OK)
            return false;
        if (PQntuples(r1.get()) > 0)
            removed = true;

        pg::PgResult r2 = pg::exec_params(
            c,
            "DELETE FROM runtime_config_store.runtime_config_secrets WHERE key = $1 "
            "RETURNING key",
            std::vector<std::string>{key});
        if (r2.status() != PGRES_TUPLES_OK)
            return false;
        if (PQntuples(r2.get()) > 0)
            removed = true;
        return true;
    });
    return ok && removed;
}

// ── Backfill (ADR-0009) ──────────────────────────────────────────────────────

namespace {

constexpr const char* kSourcelessFingerprint = "sourceless";

std::optional<bool> legacy_has_table(sqlite3* db, const char* table) {
    SqliteStmt s;
    if (sqlite3_prepare_v2(db, "SELECT 1 FROM sqlite_master WHERE type='table' AND name = ?", -1,
                           s.addr(), nullptr) != SQLITE_OK)
        return std::nullopt;
    sqlite3_bind_text(s.get(), 1, table, -1, SQLITE_STATIC);
    const int rc = sqlite3_step(s.get());
    if (rc == SQLITE_ROW)
        return true;
    if (rc == SQLITE_DONE)
        return false;
    return std::nullopt;
}

std::optional<std::string> sha256_hex(std::string_view in) {
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    if (EVP_Digest(in.data(), in.size(), md, &len, EVP_sha256(), nullptr) != 1)
        return std::nullopt;
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (unsigned int i = 0; i < len; ++i) {
        out.push_back(kHex[md[i] >> 4]);
        out.push_back(kHex[md[i] & 0x0F]);
    }
    return out;
}

std::string legacy_text(sqlite3_stmt* s, int c) {
    const auto* v = sqlite3_column_text(s, c);
    return v ? std::string(reinterpret_cast<const char*>(v),
                           static_cast<std::size_t>(sqlite3_column_bytes(s, c)))
             : std::string{};
}

struct LRow {
    std::string key, value, updated_by;
    std::int64_t updated_at{0};
};
struct LegacySnapshot {
    std::vector<LRow> rows;
};

void append_field(std::string& out, std::string_view v) {
    out += std::to_string(v.size());
    out += ':';
    out += v;
}
void append_field(std::string& out, std::int64_t v) { append_field(out, std::to_string(v)); }

std::string canonicalize_legacy_snapshot(const LegacySnapshot& snap) {
    std::vector<std::string> rows;
    rows.reserve(snap.rows.size());
    for (const auto& r : snap.rows) {
        std::string s;
        append_field(s, "row");
        append_field(s, r.key);
        append_field(s, r.value);
        append_field(s, r.updated_by);
        append_field(s, r.updated_at);
        rows.push_back(std::move(s));
    }
    std::sort(rows.begin(), rows.end());
    std::string canon = "runtime-config-legacy-fingerprint-v1\n";
    for (const auto& r : rows)
        canon += r;
    return canon;
}

std::optional<std::string> fingerprint_legacy_snapshot(const LegacySnapshot& snap) {
    const auto hash = sha256_hex(canonicalize_legacy_snapshot(snap));
    if (!hash)
        return std::nullopt;
    return "v1:" + *hash;
}

// nullopt == a genuine read error (fail-closed). Single deferred transaction
// (RAII SqliteTxn) so a legacy file a stale pre-migration binary is still
// writing yields one consistent snapshot (TagStore/CustomPropertiesStore
// precedent).
std::optional<LegacySnapshot> read_legacy_snapshot(sqlite3* db) {
    if (sqlite3_exec(db, "BEGIN", nullptr, nullptr, nullptr) != SQLITE_OK)
        return std::nullopt;
    SqliteTxn txn(db);
    LegacySnapshot snap;
    bool ok = true;
    {
        SqliteStmt s;
        if (sqlite3_prepare_v2(db, "SELECT key, value, updated_by, updated_at FROM runtime_config",
                               -1, s.addr(), nullptr) != SQLITE_OK) {
            ok = false;
        } else {
            int rc;
            while ((rc = sqlite3_step(s.get())) == SQLITE_ROW) {
                // A structurally-wrong-but-openable legacy file (updated_at
                // stored as TEXT/NULL) would coerce to 0, silently making
                // every migrated row "oldest" and skewing the direction-aware
                // conflict compare — refuse the read instead.
                if (sqlite3_column_type(s.get(), 3) != SQLITE_INTEGER)
                    break; // rc stays SQLITE_ROW -> the != SQLITE_DONE check below fails the read
                LRow r;
                r.key = legacy_text(s.get(), 0);
                r.value = legacy_text(s.get(), 1);
                r.updated_by = legacy_text(s.get(), 2);
                r.updated_at = sqlite3_column_int64(s.get(), 3);
                snap.rows.push_back(std::move(r));
            }
            if (rc != SQLITE_DONE)
                ok = false;
        }
    }
    if (ok && txn.commit() != SQLITE_OK)
        spdlog::warn("RuntimeConfigStore: read_legacy_snapshot: COMMIT failed: {}",
                    sqlite3_errmsg(db));
    if (!ok)
        return std::nullopt;
    return snap;
}

// Path-based convenience for holder-side verification. nullopt ONLY on a
// corrupt/unreadable file or a snapshot read failure — the caller MUST fail
// closed on that, never treat it as sourceless-equivalent.
std::optional<std::string> legacy_fingerprint(const std::filesystem::path& legacy_db_path) {
    SqliteDb legacy;
    if (sqlite3_open_v2(legacy_db_path.string().c_str(), legacy.addr(), SQLITE_OPEN_READONLY,
                        nullptr) != SQLITE_OK)
        return std::nullopt;
    sqlite3_exec(legacy.get(), "PRAGMA busy_timeout=5000;", nullptr, nullptr, nullptr);
    {
        SqliteStmt probe;
        if (sqlite3_prepare_v2(legacy.get(), "SELECT count(*) FROM sqlite_master", -1, probe.addr(),
                               nullptr) != SQLITE_OK ||
            sqlite3_step(probe.get()) != SQLITE_ROW)
            return std::nullopt;
    }
    const auto has_table = legacy_has_table(legacy.get(), "runtime_config");
    if (!has_table)
        return std::nullopt;
    if (!*has_table)
        return std::string(kSourcelessFingerprint);
    const auto snap = read_legacy_snapshot(legacy.get());
    if (!snap)
        return std::nullopt;
    return fingerprint_legacy_snapshot(*snap);
}

} // namespace

bool RuntimeConfigStore::migrate_from_sqlite(const std::filesystem::path& legacy_db_path) {
    if (!open_)
        return false;

    const auto backfill_metric = [this](const char* result) {
        if (metrics_)
            metrics_->counter("yuzu_server_runtime_config_backfill_total", {{"result", result}})
                .increment();
    };

    // Marker + source fingerprint stamped together, in the SAME transaction,
    // via a monotonic-promotion upsert — ported unmodified from
    // TagStore/RbacStore/CustomPropertiesStore: "sourceless" carries no
    // evidence worth protecting, so a real fingerprint may promote a stored
    // "sourceless" value; a stored REAL value is never overwritten; a writer
    // whose value already equals what's stored counts as success.
    const auto stamp_complete = [&](std::string_view source_fingerprint) -> bool {
        return pool_.with_txn_for(kBackfillTxnTimeout, [source_fingerprint](PGconn* c) -> bool {
            pg::PgResult mk = pg::exec_params(
                c,
                "INSERT INTO runtime_config_store.runtime_config_meta (key, value) VALUES "
                "('backfill_complete', $1) ON CONFLICT (key) DO NOTHING",
                std::vector<std::string>{std::to_string(now_secs())});
            if (mk.status() != PGRES_COMMAND_OK) {
                spdlog::error("RuntimeConfigStore: migrate_from_sqlite: marker stamp failed: {}",
                              PQerrorMessage(c));
                return false;
            }
            pg::PgResult fp = pg::exec_params(
                c,
                "INSERT INTO runtime_config_store.runtime_config_meta (key, value) VALUES "
                "('backfill_source_fingerprint', $1) ON CONFLICT (key) DO UPDATE SET "
                "value = EXCLUDED.value WHERE "
                "runtime_config_store.runtime_config_meta.value = 'sourceless' OR "
                "runtime_config_store.runtime_config_meta.value = EXCLUDED.value RETURNING value",
                std::vector<std::string>{std::string(source_fingerprint)});
            if (fp.status() != PGRES_TUPLES_OK) {
                spdlog::error(
                    "RuntimeConfigStore: migrate_from_sqlite: source-fingerprint stamp failed: {}",
                    PQerrorMessage(c));
                return false;
            }
            if (PQntuples(fp.get()) == 0 && source_fingerprint != kSourcelessFingerprint) {
                spdlog::error(
                    "RuntimeConfigStore: migrate_from_sqlite: lost the race to record this "
                    "backfill's own source fingerprint — a DIFFERENT real fingerprint already "
                    "stamped backfill_source_fingerprint between this pass's marker-absent check "
                    "and this commit.");
                return false;
            }
            return true;
        });
    };

    const auto move_legacy_aside = [](const std::filesystem::path& path) {
        std::filesystem::path aside;
        for (int suffix = 0;; ++suffix) {
            aside = path;
            aside += ".migrated-" + std::to_string(now_secs());
            if (suffix > 0)
                aside += "-" + std::to_string(suffix);
            std::error_code exists_ec;
            if (!std::filesystem::exists(aside, exists_ec))
                break;
        }
        std::error_code mv_ec;
        std::filesystem::rename(path, aside, mv_ec);
        if (mv_ec)
            spdlog::warn("RuntimeConfigStore: migrate_from_sqlite: could not move legacy {} aside "
                        "({}); it is safe to archive/remove manually",
                        path.string(), mv_ec.message());
        else
            spdlog::info("RuntimeConfigStore: migrate_from_sqlite: moved legacy db to {}",
                        aside.string());
    };

    std::error_code ec;
    const bool legacy_exists = std::filesystem::exists(legacy_db_path, ec);
    if (ec) {
        spdlog::error("RuntimeConfigStore: migrate_from_sqlite: cannot stat legacy path {}: {}",
                      legacy_db_path.string(), ec.message());
        backfill_metric("failed");
        return false;
    }

    bool marker_present = false;
    std::optional<std::string> stored_fingerprint;
    {
        auto lease = pool_.acquire();
        if (!lease) {
            spdlog::error("RuntimeConfigStore: migrate_from_sqlite: no database connection ({})",
                          pool_.last_error());
            backfill_metric("failed");
            return false;
        }
        pg::PgResult mk = pg::exec_params(
            lease.get(),
            "SELECT key, value FROM runtime_config_store.runtime_config_meta WHERE key IN "
            "('backfill_complete', 'backfill_source_fingerprint')",
            std::vector<std::string>{});
        if (mk.status() != PGRES_TUPLES_OK) {
            spdlog::error("RuntimeConfigStore: migrate_from_sqlite: marker lookup failed: {}",
                          PQerrorMessage(lease.get()));
            backfill_metric("failed");
            return false;
        }
        for (int i = 0; i < PQntuples(mk.get()); ++i) {
            const std::string k = col_str(mk.get(), i, 0);
            if (k == "backfill_complete")
                marker_present = true;
            else if (k == "backfill_source_fingerprint")
                stored_fingerprint = col_str(mk.get(), i, 1);
        }
    }

    if (marker_present) {
        if (!legacy_exists) {
            spdlog::debug("RuntimeConfigStore: migrate_from_sqlite already completed, skipping");
            return true;
        }
        const auto verify_fp = legacy_fingerprint(legacy_db_path);
        if (!verify_fp) {
            spdlog::error(
                "RuntimeConfigStore: migrate_from_sqlite: backfill_complete is already set, and "
                "this replica's own legacy db {} exists but is unreadable/corrupt while being "
                "fingerprint-verified — refusing (fail-closed)",
                legacy_db_path.string());
            backfill_metric("failed");
            return false;
        }
        if (*verify_fp == kSourcelessFingerprint) {
            spdlog::debug("RuntimeConfigStore: migrate_from_sqlite already completed; this "
                         "replica's own legacy db has no runtime_config table, skipping");
            return true;
        }
        if (!stored_fingerprint || *stored_fingerprint != *verify_fp) {
            spdlog::error(
                "RuntimeConfigStore: migrate_from_sqlite: HOLDER-SIDE VERIFICATION FAILED — "
                "backfill_complete is already set with fingerprint '{}' but this replica's own "
                "legacy db {} fingerprints as '{}' — some other replica's legacy data was "
                "migrated, not this one's. Refusing to silently accept a completion this "
                "replica's config was never part of.",
                stored_fingerprint.value_or("<none recorded>"), legacy_db_path.string(),
                *verify_fp);
            backfill_metric("failed");
            return false;
        }
        spdlog::debug(
            "RuntimeConfigStore: migrate_from_sqlite already completed (fingerprint verified), "
            "skipping");
        move_legacy_aside(legacy_db_path);
        return true;
    }

    if (!legacy_exists) {
        if (!stamp_complete(kSourcelessFingerprint)) {
            backfill_metric("failed");
            return false;
        }
        spdlog::info(
            "RuntimeConfigStore: migrate_from_sqlite: no legacy db at {}; marking backfill "
            "complete (fresh install)",
            legacy_db_path.string());
        backfill_metric("fresh");
        return true;
    }

    SqliteDb legacy;
    if (sqlite3_open_v2(legacy_db_path.string().c_str(), legacy.addr(), SQLITE_OPEN_READONLY,
                        nullptr) != SQLITE_OK) {
        spdlog::error("RuntimeConfigStore: migrate_from_sqlite: failed to open legacy db {}: {}",
                      legacy_db_path.string(), legacy ? sqlite3_errmsg(legacy.get()) : "open failed");
        backfill_metric("failed");
        return false;
    }
    sqlite3_exec(legacy.get(), "PRAGMA busy_timeout=5000;", nullptr, nullptr, nullptr);
    {
        SqliteStmt probe;
        if (sqlite3_prepare_v2(legacy.get(), "SELECT count(*) FROM sqlite_master", -1, probe.addr(),
                               nullptr) != SQLITE_OK ||
            sqlite3_step(probe.get()) != SQLITE_ROW) {
            spdlog::error(
                "RuntimeConfigStore: migrate_from_sqlite: legacy db {} is unreadable/corrupt ({}); "
                "refusing backfill (fail-closed)",
                legacy_db_path.string(), sqlite3_errmsg(legacy.get()));
            backfill_metric("failed");
            return false;
        }
    }
    const auto has_table = legacy_has_table(legacy.get(), "runtime_config");
    if (!has_table) {
        spdlog::error(
            "RuntimeConfigStore: migrate_from_sqlite: legacy db {} could not be probed for a "
            "runtime_config table ({}); refusing backfill (fail-closed)",
            legacy_db_path.string(), sqlite3_errmsg(legacy.get()));
        backfill_metric("failed");
        return false;
    }
    if (!*has_table) {
        if (!stamp_complete(kSourcelessFingerprint)) {
            backfill_metric("failed");
            return false;
        }
        spdlog::warn(
            "RuntimeConfigStore: migrate_from_sqlite: legacy db {} has no runtime_config table; "
            "marking backfill complete",
            legacy_db_path.string());
        backfill_metric("fresh");
        return true;
    }

    const auto snap_opt = read_legacy_snapshot(legacy.get());
    if (!snap_opt) {
        spdlog::error("RuntimeConfigStore: migrate_from_sqlite: legacy read failed: {}",
                      sqlite3_errmsg(legacy.get()));
        backfill_metric("failed");
        return false;
    }
    const LegacySnapshot& snap = *snap_opt;
    const auto fingerprint = fingerprint_legacy_snapshot(snap);
    if (!fingerprint) {
        spdlog::error("RuntimeConfigStore: migrate_from_sqlite: failed to fingerprint legacy "
                     "content (SHA-256 digest failure) — refusing backfill (fail-closed)");
        backfill_metric("failed");
        return false;
    }

    // Row conflicts: `key` is IDENTITY; value/updated_by/updated_at are
    // LIFECYCLE. Secret keys use a SIMPLER rule than the non-secret
    // direction-aware compare below: an envelope blob does not byte-compare
    // against legacy plaintext, so ANY existing Postgres content for a
    // secret key (a runtime_config_secrets row, OR a non-empty
    // runtime_config row) wins unconditionally — see the header.
    const bool ok = pool_.with_txn_for(kBackfillTxnTimeout, [&](PGconn* c) -> bool {
        for (const auto& r : snap.rows) {
            const std::string s_key = sanitize_pg_text(r.key);
            const std::string s_value = sanitize_pg_text(r.value);
            const std::string s_by = sanitize_pg_text(r.updated_by);

            if (is_secret_config_key(s_key)) {
                pg::PgResult has_secret = pg::exec_params(
                    c, "SELECT 1 FROM runtime_config_store.runtime_config_secrets WHERE key = $1",
                    std::vector<std::string>{s_key});
                if (has_secret.status() != PGRES_TUPLES_OK) {
                    spdlog::error("RuntimeConfigStore: migrate_from_sqlite: secret-row lookup "
                                 "failed for '{}': {}",
                                 r.key, PQerrorMessage(c));
                    return false;
                }
                pg::PgResult plain_existing = pg::exec_params(
                    c, "SELECT value FROM runtime_config_store.runtime_config WHERE key = $1",
                    std::vector<std::string>{s_key});
                if (plain_existing.status() != PGRES_TUPLES_OK) {
                    spdlog::error("RuntimeConfigStore: migrate_from_sqlite: plain-row lookup "
                                 "failed for '{}': {}",
                                 r.key, PQerrorMessage(c));
                    return false;
                }
                const bool pg_has_content =
                    PQntuples(has_secret.get()) > 0 ||
                    (PQntuples(plain_existing.get()) > 0 &&
                     !std::string(col(plain_existing.get(), 0, 0)).empty());
                if (pg_has_content) {
                    spdlog::warn(
                        "RuntimeConfigStore: migrate_from_sqlite: Postgres already holds content "
                        "for secret key '{}' — keeping it (envelopes don't byte-compare against "
                        "legacy plaintext; PG-present always wins for secret keys)",
                        r.key);
                    continue;
                }
                if (s_value.empty()) {
                    pg::PgResult ins = pg::exec_params(
                        c,
                        "INSERT INTO runtime_config_store.runtime_config (key, value, updated_by, "
                        "updated_at) VALUES ($1, '', $2, $3::bigint) ON CONFLICT (key) DO NOTHING",
                        std::vector<std::string>{s_key, s_by, std::to_string(r.updated_at)});
                    if (ins.status() != PGRES_COMMAND_OK) {
                        spdlog::error("RuntimeConfigStore: migrate_from_sqlite: insert failed for "
                                     "'{}': {}",
                                     r.key, PQerrorMessage(c));
                        return false;
                    }
                    continue;
                }
                const auto* bytes = reinterpret_cast<const std::uint8_t*>(s_value.data());
                auto enc = secret_codec_.encrypt(
                    pg::SecretCodec::SecretId{kStoreName, "runtime_config_secrets", "sealed_value",
                                              s_key},
                    std::span<const std::uint8_t>{bytes, s_value.size()});
                if (!enc.has_value()) {
                    spdlog::error("RuntimeConfigStore: migrate_from_sqlite: encrypt failed for "
                                 "secret key '{}' — refusing backfill (fail-closed)",
                                 r.key);
                    return false;
                }
                pg::PgResult ins = pg::exec_params(
                    c,
                    "INSERT INTO runtime_config_store.runtime_config_secrets (key, sealed_value, "
                    "updated_by, updated_at) VALUES ($1, decode($2, 'hex'), $3, $4::bigint) "
                    "ON CONFLICT (key) DO NOTHING RETURNING key",
                    std::vector<std::string>{s_key, bytes_to_hex(*enc), s_by,
                                             std::to_string(r.updated_at)});
                if (ins.status() != PGRES_TUPLES_OK) {
                    spdlog::error("RuntimeConfigStore: migrate_from_sqlite: insert failed for "
                                 "secret key '{}': {}",
                                 r.key, PQerrorMessage(c));
                    return false;
                }
                if (PQntuples(ins.get()) == 0) {
                    spdlog::error("RuntimeConfigStore: migrate_from_sqlite: concurrent writer "
                                 "inserted secret key '{}' mid-backfill — refusing",
                                 r.key);
                    return false;
                }
                continue;
            }

            pg::PgResult stored = pg::exec_params(
                c, "SELECT value, updated_by, updated_at FROM runtime_config_store.runtime_config "
                   "WHERE key = $1",
                std::vector<std::string>{s_key});
            if (stored.status() != PGRES_TUPLES_OK) {
                spdlog::error(
                    "RuntimeConfigStore: migrate_from_sqlite: stored-row lookup failed for '{}': {}",
                    r.key, PQerrorMessage(c));
                return false;
            }
            if (PQntuples(stored.get()) == 0) {
                pg::PgResult ins = pg::exec_params(
                    c,
                    "INSERT INTO runtime_config_store.runtime_config (key, value, updated_by, "
                    "updated_at) VALUES ($1, $2, $3, $4::bigint) ON CONFLICT (key) DO NOTHING",
                    std::vector<std::string>{s_key, s_value, s_by, std::to_string(r.updated_at)});
                if (ins.status() != PGRES_COMMAND_OK) {
                    spdlog::error(
                        "RuntimeConfigStore: migrate_from_sqlite: insert failed for '{}': {}",
                        r.key, PQerrorMessage(c));
                    return false;
                }
                if (std::string_view(PQcmdTuples(ins.get())) == "0") {
                    spdlog::error(
                        "RuntimeConfigStore: migrate_from_sqlite: concurrent writer inserted '{}' "
                        "mid-backfill — refusing (re-run will compare directions cleanly)",
                        r.key);
                    return false;
                }
                continue;
            }
            const std::string st_value = col_str(stored.get(), 0, 0);
            const std::string st_by = col_str(stored.get(), 0, 1);
            const std::int64_t st_updated = to_i64(col(stored.get(), 0, 2));
            const bool identical = st_value == s_value && st_by == s_by && st_updated == r.updated_at;
            if (identical)
                continue;
            if (st_updated > r.updated_at) {
                spdlog::warn(
                    "RuntimeConfigStore: migrate_from_sqlite: Postgres row '{}' is strictly ahead "
                    "of the legacy row (stored updated_at={} > legacy {}) — keeping Postgres's "
                    "value",
                    r.key, st_updated, r.updated_at);
                continue;
            }
            spdlog::error(
                "RuntimeConfigStore: migrate_from_sqlite: legacy row '{}' {} Postgres's current "
                "value (stored: value='{}' updated_by='{}' updated_at={}; legacy: value='{}' "
                "updated_by='{}' updated_at={}) — refusing to silently discard that evidence. "
                "Reconcile which side is authoritative before restarting.",
                r.key,
                r.updated_at > st_updated ? "shows MORE progress than"
                                          : "contradicts (tied updated_at, differing content)",
                st_value, st_by, st_updated, s_value, s_by, r.updated_at);
            return false;
        }
        return true;
    });
    if (!ok) {
        backfill_metric("failed");
        return false;
    }

    if (!stamp_complete(*fingerprint)) {
        backfill_metric("failed");
        return false;
    }
    spdlog::info("RuntimeConfigStore: migrate_from_sqlite: backfilled {} row(s) from {}",
                snap.rows.size(), legacy_db_path.string());
    // Close the legacy read-only handle FIRST — Windows refuses to rename a
    // file with an open handle (ERROR_SHARING_VIOLATION); POSIX allows it.
    legacy.close();
    move_legacy_aside(legacy_db_path);
    backfill_metric("success");
    return true;
}

} // namespace yuzu::server
