#include "webhook_store.hpp"

#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "pg/secret_codec.hpp"
#include "secure_buffer.hpp"
#include "sqlite_raii.hpp"
#include "utf8_sanitize.hpp"

#include <httplib.h>
#include <libpq-fe.h>
#include <spdlog/spdlog.h>
#include <sqlite3.h>
#include <yuzu/metrics.hpp>

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

#include <chrono>
#include <cstdlib>
#include <optional>
#include <set>
#include <sstream>
#include <string_view>

namespace yuzu::server {

namespace {

constexpr const char* kStoreName = "webhook_store";

// Authoritative store (ADR-0012 §1) — operator-authored integration config,
// not a hot path (CRUD is operator-driven). fire_event's own scan is
// deliberately fail-soft with a SHORT bound instead — see its own comment.
constexpr std::chrono::milliseconds kReadTimeout{2000};
constexpr std::chrono::milliseconds kWriteTimeout{4000};
// fire_event can be called from a gRPC handler thread (Register/execution-
// completion) — it must never block meaningfully on a saturated pool.
constexpr std::chrono::milliseconds kFireEventAcquireTimeout{300};
// gov UP-5 precedent: bounded materialization regardless of table growth.
constexpr int kListRowCap = 10000;

// Sentinel fingerprint for "this replica's legacy file is absent, or
// present but holds no `webhooks` table/rows worth migrating" — see
// migrate_from_sqlite_impl's doc comment. Mirrors DeploymentStore's
// kSourcelessFingerprint (deployment_store.cpp).
constexpr const char* kSourcelessFingerprint = "sourceless";

// ── Small local helpers (each PG store keeps its own copy — not yet
//    promoted to a shared header, docs/postgres-store-playbook.md /
//    ADR-0040 Follow-ups) ──────────────────────────────────────────────────

std::int64_t now_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::int64_t to_i64(const char* s) {
    if (s == nullptr || s[0] == '\0')
        return 0;
    return static_cast<std::int64_t>(std::strtoll(s, nullptr, 10));
}

std::string text_col(PGresult* res, int row, int col) {
    if (PQgetisnull(res, row, col))
        return {};
    return std::string(PQgetvalue(res, row, col),
                       static_cast<std::size_t>(PQgetlength(res, row, col)));
}

// Only used against legacy SQLite text columns (may be nullptr).
const char* safe(const char* p) {
    return p ? p : "";
}

std::string bytes_to_hex(std::span<const std::uint8_t> b) {
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string out;
    out.reserve(b.size() * 2);
    for (std::uint8_t byte : b) {
        out.push_back(kDigits[byte >> 4]);
        out.push_back(kDigits[byte & 0x0F]);
    }
    return out;
}

std::vector<std::uint8_t> hex_to_bytes(const std::string& hex) {
    std::vector<std::uint8_t> out;
    out.reserve(hex.size() / 2);
    const auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9')
            return c - '0';
        if (c >= 'a' && c <= 'f')
            return c - 'a' + 10;
        if (c >= 'A' && c <= 'F')
            return c - 'A' + 10;
        return -1;
    };
    for (std::size_t i = 0; i + 1 < hex.size(); i += 2) {
        const int hi = nibble(hex[i]);
        const int lo = nibble(hex[i + 1]);
        if (hi < 0 || lo < 0)
            break; // malformed — server-authored hex only, defensive stop
        out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
    }
    return out;
}

// sanitize_utf8_strict scrubs invalid UTF-8 to U+FFFD but keeps embedded
// NUL. PostgreSQL TEXT cannot store a NUL and libpq's text-format bind
// C-string-truncates at the first one, so replace every NUL with U+FFFD
// too. Ported from rbac_store.cpp/management_group_store.cpp (ADR-0041/
// 0042); applied on BOTH the live-write path (url/event_types/payload/
// error, client-supplied) and the backfill path (#1593 class — AuditStore's
// migration corrected an earlier version of this idiom that sanitized only
// the backfill copy, ADR-0040).
std::string sanitize_pg_text(std::string_view s) {
    std::string out = sanitize_utf8_strict(s);
    std::size_t pos = 0;
    while ((pos = out.find('\0', pos)) != std::string::npos) {
        out.replace(pos, 1, "\xEF\xBF\xBD");
        pos += 3;
    }
    return out;
}

// Length-prefixed ("<byte-length>:<bytes>") canonicalization — two
// different field sequences can never encode to the same preimage
// regardless of content (RbacStore/DeploymentStore/NotificationStore
// precedent; RbacStore's original unescaped-delimiter version collided on
// crafted input, PR #2703).
void append_field(std::string& out, std::string_view f) {
    out += std::to_string(f.size());
    out += ':';
    out.append(f.data(), f.size());
}

std::string sha256_hex(std::string_view in) {
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    if (EVP_Digest(in.data(), in.size(), md, &len, EVP_sha256(), nullptr) != 1)
        return {};
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.reserve(static_cast<std::size_t>(len) * 2);
    for (unsigned int i = 0; i < len; ++i) {
        out.push_back(kHex[md[i] >> 4]);
        out.push_back(kHex[md[i] & 0x0f]);
    }
    return out;
}

/// Check if a comma-separated list of event types contains a specific event.
/// Supports wildcard "*" to match all events.
bool event_matches(const std::string& event_types, const std::string& event_type) {
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

// Unqualified DDL: the runner sets search_path to `webhook_store` for the
// migration transaction. Runtime statements below schema-qualify
// explicitly. `secret` is BYTEA (SecretCodec envelope, ADR-0010 — follows
// AuthDB's `mfa_totp_secret` precedent for type); `has_secret` is the
// INDEPENDENT flag ADR-0010 §Decision-1 requires so "no secret configured"
// is never represented by column emptiness. `sqlite_backfill_source`
// mirrors DeploymentStore's per-legacy-content-fingerprint idempotency
// table (ADR-0057: content fingerprint set, not a single-marker
// holder-side-reverify — see migrate_from_sqlite_impl's doc comment for why).
const std::vector<pg::PgMigration>& migrations() {
    static const std::vector<pg::PgMigration> kMigrations = {
        {1, R"(
            CREATE TABLE webhooks (
                id          BIGINT  GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                url         TEXT    NOT NULL,
                event_types TEXT    NOT NULL DEFAULT '*',
                secret      BYTEA,
                has_secret  BOOLEAN NOT NULL DEFAULT FALSE,
                enabled     BOOLEAN NOT NULL DEFAULT TRUE,
                created_at  BIGINT  NOT NULL,
                CHECK ((has_secret AND secret IS NOT NULL) OR (NOT has_secret AND secret IS NULL))
            );
            CREATE TABLE webhook_deliveries (
                id           BIGINT  GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                webhook_id   BIGINT  NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
                event_type   TEXT    NOT NULL,
                payload      TEXT    NOT NULL,
                status_code  INTEGER NOT NULL DEFAULT 0,
                delivered_at BIGINT  NOT NULL,
                error        TEXT    NOT NULL DEFAULT ''
            );
            CREATE INDEX idx_delivery_webhook_ts ON webhook_deliveries(webhook_id, delivered_at);
            CREATE TABLE sqlite_backfill_source (
                fingerprint  TEXT PRIMARY KEY,
                completed_at BIGINT NOT NULL
            );
        )"},
    };
    return kMigrations;
}

// ── Legacy (SQLite) read-side types — migrate_from_sqlite_impl only ────────

struct LegacyWebhook {
    std::int64_t id{0};
    std::string url;
    std::string event_types;
    std::string secret; // plaintext — lives ONLY in this transient struct
    bool enabled{true};
    std::int64_t created_at{0};
};

struct LegacyDelivery {
    std::int64_t id{0};
    std::int64_t webhook_id{0};
    std::string event_type;
    std::string payload;
    int status_code{0};
    std::int64_t delivered_at{0};
    std::string error;
};

// Fingerprint over IDENTITY fields ONLY — deliberately EXCLUDES the
// plaintext secret bytes (ADR-0057, gov secrets-lens finding): the
// fingerprint is itself stored in a Postgres column
// (sqlite_backfill_source.fingerprint), readable by anyone with
// Infrastructure:Read-class access, alongside every OTHER webhooks column
// in cleartext (url/event_types/created_at). Hashing the plaintext secret
// into it would let a SQL-insider brute-force a low-entropy legacy secret
// offline against the stored hash — exactly the adversary ADR-0010 exists
// to defend against. Only a boolean has-secret bit is included; this is
// sound BECAUSE of the backfill's own conflict rule below (a legacy file
// that differs from an already-migrated one ONLY in its secret VALUE, with
// has-secret unchanged, verifies as identical — and post-marker, `secret`
// is never re-imported by backfill regardless, so there is nothing for a
// finer-grained fingerprint to protect). Count-prefixed per table
// (LicenseStore lesson, docs/postgres-migration-ladder.md): a per-field
// length prefix alone is not injective over a TWO-section sequence without
// also fixing each section's row count up front.
std::string canonicalize_legacy(const std::vector<LegacyWebhook>& hooks,
                                const std::vector<LegacyDelivery>& deliveries) {
    std::string canon = "webhook-legacy-fingerprint-v1\n";
    append_field(canon, std::to_string(hooks.size()));
    for (const auto& h : hooks) {
        append_field(canon, std::to_string(h.id));
        append_field(canon, h.url);
        append_field(canon, h.event_types);
        append_field(canon, h.secret.empty() ? "0" : "1"); // has-secret bit ONLY, never the bytes
        append_field(canon, h.enabled ? "1" : "0");
        append_field(canon, std::to_string(h.created_at));
    }
    append_field(canon, std::to_string(deliveries.size()));
    for (const auto& d : deliveries) {
        append_field(canon, std::to_string(d.id));
        append_field(canon, std::to_string(d.webhook_id));
        append_field(canon, d.event_type);
        append_field(canon, d.payload);
        append_field(canon, std::to_string(d.status_code));
        append_field(canon, std::to_string(d.delivered_at));
        append_field(canon, d.error);
    }
    return canon;
}

// Move a verified-backfilled legacy file aside (never delete — ADR-0009
// rollback net). Non-fatal on failure: the trail's presence in PG has
// already been established by the time this runs. Carries the WAL/SHM
// sidecars across with the main file (ADR-0040/AuditStore precedent): a
// clean shutdown checkpoints them away, but after an unclean stop the
// committed tail lives in `-wal`, and the retained copy — which still
// holds the pre-cutover PLAINTEXT signing secret(s), ADR-0009/0010 forbid
// scrubbing it — is unopenable standalone without it.
void move_legacy_aside(const std::filesystem::path& legacy_db_path) {
    std::error_code mv_ec;
    auto aside = legacy_db_path;
    aside += ".migrated-" + std::to_string(now_epoch());
    std::filesystem::rename(legacy_db_path, aside, mv_ec);
    if (mv_ec) {
        spdlog::warn("WebhookStore::migrate_from_sqlite: could not move legacy {} aside ({}); it "
                     "is safe to archive/remove manually, or a later boot retries",
                     legacy_db_path.string(), mv_ec.message());
        return;
    }
    for (const char* suffix : {"-wal", "-shm"}) {
        auto side = legacy_db_path;
        side += suffix;
        std::error_code side_ec;
        if (!std::filesystem::exists(side, side_ec) || side_ec)
            continue;
        auto side_aside = aside;
        side_aside += suffix;
        std::filesystem::rename(side, side_aside, side_ec);
        if (side_ec)
            spdlog::warn("WebhookStore::migrate_from_sqlite: moved the legacy webhook db but not "
                         "its {} sidecar ({}); the retained copy at {} may not open standalone "
                         "until the sidecar is moved beside it",
                         suffix, side_ec.message(), aside.string());
    }
    // The main file was already forced to 0600 before it was opened for
    // reading (ADR-0010 §Consequences (a)); re-apply to the moved copy too
    // — rename preserves mode, so this is normally a no-op, defence in
    // depth if the move landed on semantics where it wasn't.
    std::error_code perm_ec;
    std::filesystem::permissions(aside,
                                 std::filesystem::perms::owner_read |
                                     std::filesystem::perms::owner_write,
                                 std::filesystem::perm_options::replace, perm_ec);
    spdlog::info("WebhookStore::migrate_from_sqlite: moved legacy webhook db to {} (0600, "
                 "retained one release per ADR-0009 — still holds the pre-cutover PLAINTEXT "
                 "signing secret(s); see ADR-0057 for the operator purge/rotate guidance)",
                 aside.string());
}

} // namespace

// ── HMAC-SHA256 ─────────────────────────────────────────────────────────────

std::string WebhookStore::hmac_sha256(std::string_view secret, std::string_view data) {
    std::uint8_t hash[32] = {};

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

    return bytes_to_hex(std::span<const std::uint8_t>(hash, 32));
}

// ── Constructor / Destructor ────────────────────────────────────────────────

WebhookStore::WebhookStore(pg::PgPool& pool, pg::SecretCodec& secret_codec)
    : pool_(pool), secret_codec_(secret_codec) {
    // Construction-only unbounded acquire (ADR-0012 §2(a)).
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error("WebhookStore: no database connection at construction ({}) — webhook "
                      "store disabled",
                      pool_.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error("WebhookStore: schema migration failed — webhook store disabled");
        return;
    }
    lease.reset(); // release before touching the codec (never hold a lease across other work)

    // ADR-0010: register the sole secret-bearing column. This ctor never
    // calls secret_codec_.init() — the caller (server.cpp) constructs the
    // codec, then this store (which registers the column), THEN calls
    // init() — mirrors AuthDB's construction contract exactly
    // (docs/postgres-store-playbook.md step 3).
    if (!secret_codec_.register_secret_column({"webhook_store", "webhooks", "secret", "id"})) {
        spdlog::error(
            "WebhookStore: failed to register 'secret' as a secret column — webhook store "
            "disabled");
        return;
    }

    open_ = true;
    spdlog::info("WebhookStore: opened (schema {})", kStoreName);
}

WebhookStore::~WebhookStore() {
    // Ported verbatim from the SQLite era (#3261 governance hardening) — the
    // reasoning is storage-backend-agnostic: a destructor's BODY runs BEFORE
    // its members' destructors, so declaring delivery_pool_ last does not by
    // itself stop a still-running worker from touching pool_/secret_codec_
    // while this body executes. In the intended production flow
    // (ServerImpl::stop() -> quiesce(60s) -> success -> .reset()) this is
    // always instant — the pool is already empty by the time this
    // destructor runs. Bounded generously (24h) rather than literally
    // forever; if still not drained, LEAK rather than let a worker's
    // decrypt-and-sign call touch pool_/secret_codec_ (and, transitively,
    // the KeyProvider its codec borrows) after this store is gone.
    if (!delivery_pool_.quiesce(std::chrono::hours(24))) {
        try {
            spdlog::critical("WebhookStore::~WebhookStore: delivery pool did not quiesce within "
                             "24h - leaking rather than risking a use-after-free against an "
                             "in-flight delivery");
        } catch (...) {
        }
    }
}

void WebhookStore::set_metrics(yuzu::MetricsRegistry* metrics) { metrics_ = metrics; }

bool WebhookStore::quiesce(std::chrono::milliseconds timeout) {
    return delivery_pool_.quiesce(timeout);
}

// ── CRUD ────────────────────────────────────────────────────────────────────

std::expected<int64_t, WebhookWriteError>
WebhookStore::create_webhook(const std::string& url, const std::string& event_types,
                             const std::string& secret, bool enabled) {
    // Validate URL scheme — only http:// and https:// are allowed.
    if (!url.starts_with("http://") && !url.starts_with("https://")) {
        spdlog::warn("WebhookStore: rejected webhook with invalid URL scheme: {}", url);
        return std::unexpected(WebhookWriteError::invalid_url);
    }
    if (!open_)
        return std::unexpected(WebhookWriteError::store_unavailable);

    // ADR-0010 Amendment: a GENERATED-ALWAYS (serial-PK) secret-bearing
    // table must allocate its row id BEFORE encrypting (the AAD binds the
    // row PK) — nextval() first, then INSERT the encrypted blob with that
    // id explicit (OVERRIDING SYSTEM VALUE). Never INSERT-then-UPDATE,
    // which would transiently write a non-blob value to `secret`.
    std::int64_t id = 0;
    {
        auto lease = pool_.try_acquire_for(kWriteTimeout);
        if (!lease)
            return std::unexpected(WebhookWriteError::store_unavailable);
        pg::PgResult seq = pg::exec_params(
            lease.get(), "SELECT nextval(pg_get_serial_sequence('webhook_store.webhooks','id'))",
            std::vector<std::string>{});
        if (seq.status() != PGRES_TUPLES_OK || PQntuples(seq.get()) != 1) {
            spdlog::error("WebhookStore::create_webhook: id allocation failed: {}",
                          PQerrorMessage(lease.get()));
            return std::unexpected(WebhookWriteError::db_error);
        }
        id = to_i64(PQgetvalue(seq.get(), 0, 0));
    } // lease released — never hold one across encryption (ADR-0012 §2(b))

    const bool has_secret = !secret.empty();
    std::vector<std::uint8_t> encrypted;
    if (has_secret) {
        auto pk = pg::SecretCodec::encode_bigint_pk(id);
        auto enc = secret_codec_.encrypt(
            pg::SecretCodec::SecretId{"webhook_store", "webhooks", "secret", pk},
            std::span<const std::uint8_t>{reinterpret_cast<const std::uint8_t*>(secret.data()),
                                          secret.size()});
        if (!enc.has_value()) {
            // Encrypt failure aborts here — never write plaintext, never
            // write anything at all (ADR-0010 encrypt-failure semantics).
            spdlog::error("WebhookStore::create_webhook: secret encrypt failed for {}", url);
            return std::unexpected(WebhookWriteError::db_error);
        }
        encrypted = std::move(*enc);
    }

    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected(WebhookWriteError::store_unavailable);
    std::vector<std::optional<std::string>> params = {
        std::to_string(id),
        sanitize_pg_text(url),
        sanitize_pg_text(event_types),
        has_secret ? std::optional<std::string>(bytes_to_hex(encrypted)) : std::nullopt,
        has_secret ? "true" : "false",
        enabled ? "true" : "false",
        std::to_string(now_epoch()),
    };
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "INSERT INTO webhook_store.webhooks "
        "(id, url, event_types, secret, has_secret, enabled, created_at) "
        "OVERRIDING SYSTEM VALUE VALUES "
        "($1::bigint, $2, $3, decode($4,'hex'), $5::boolean, $6::boolean, $7::bigint) "
        "RETURNING id",
        params);
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) == 0) {
        spdlog::error("WebhookStore::create_webhook: insert failed for {}: {}", url,
                      PQerrorMessage(lease.get()));
        return std::unexpected(WebhookWriteError::db_error);
    }
    return id;
}

std::optional<std::vector<Webhook>> WebhookStore::list(int limit, int offset) const {
    if (!open_)
        return std::nullopt;
    if (limit <= 0)
        limit = 100;
    limit = std::min(limit, kListRowCap);
    if (offset < 0)
        offset = 0;

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        spdlog::debug("WebhookStore::list: no connection in time ({})", pool_.last_error());
        return std::nullopt;
    }
    // Never selects `secret` — list() must never expose webhook secrets,
    // encrypted or otherwise; `has_secret` is the non-sensitive signal.
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT id, url, event_types, has_secret, enabled, created_at "
        "FROM webhook_store.webhooks ORDER BY created_at DESC, id DESC LIMIT $1::bigint OFFSET "
        "$2::bigint",
        std::vector<std::string>{std::to_string(limit), std::to_string(offset)});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::debug("WebhookStore::list: query failed: {}", PQerrorMessage(lease.get()));
        return std::nullopt;
    }

    std::vector<Webhook> out;
    const int rows = PQntuples(res.get());
    out.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i) {
        Webhook w;
        w.id = to_i64(PQgetvalue(res.get(), i, 0));
        w.url = text_col(res.get(), i, 1);
        w.event_types = text_col(res.get(), i, 2);
        w.has_secret = text_col(res.get(), i, 3) == "t";
        w.enabled = text_col(res.get(), i, 4) == "t";
        w.created_at = to_i64(PQgetvalue(res.get(), i, 5));
        out.push_back(std::move(w));
    }
    return out;
}

std::expected<bool, WebhookWriteError> WebhookStore::delete_webhook(int64_t id) {
    if (!open_)
        return std::unexpected(WebhookWriteError::store_unavailable);
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected(WebhookWriteError::store_unavailable);
    // ON DELETE CASCADE removes webhook_deliveries rows. RETURNING proves
    // whether THIS call's row existed — never sqlite3_changes()-style
    // mutate-then-count (#1033).
    pg::PgResult res = pg::exec_params(
        lease.get(), "DELETE FROM webhook_store.webhooks WHERE id = $1::bigint RETURNING id",
        std::vector<std::string>{std::to_string(id)});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::error("WebhookStore::delete_webhook: query failed for id={}: {}", id,
                      PQerrorMessage(lease.get()));
        return std::unexpected(WebhookWriteError::db_error);
    }
    return PQntuples(res.get()) > 0;
}

std::vector<WebhookDelivery> WebhookStore::get_deliveries(int64_t webhook_id, int limit) const {
    std::vector<WebhookDelivery> results;
    if (!open_)
        return results;
    if (limit <= 0)
        limit = 50;
    limit = std::min(limit, kListRowCap);

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        spdlog::debug("WebhookStore::get_deliveries: no connection in time ({})",
                      pool_.last_error());
        return results;
    }
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT id, webhook_id, event_type, payload, status_code, delivered_at, error "
        "FROM webhook_store.webhook_deliveries WHERE webhook_id = $1::bigint "
        "ORDER BY delivered_at DESC, id DESC LIMIT $2::bigint",
        std::vector<std::string>{std::to_string(webhook_id), std::to_string(limit)});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::debug("WebhookStore::get_deliveries: query failed: {}", PQerrorMessage(lease.get()));
        return results;
    }

    const int rows = PQntuples(res.get());
    results.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i) {
        WebhookDelivery d;
        d.id = to_i64(PQgetvalue(res.get(), i, 0));
        d.webhook_id = to_i64(PQgetvalue(res.get(), i, 1));
        d.event_type = text_col(res.get(), i, 2);
        d.payload = text_col(res.get(), i, 3);
        d.status_code = static_cast<int>(to_i64(PQgetvalue(res.get(), i, 4)));
        d.delivered_at = to_i64(PQgetvalue(res.get(), i, 5));
        d.error = text_col(res.get(), i, 6);
        results.push_back(std::move(d));
    }
    return results;
}

// ── Delivery recording ──────────────────────────────────────────────────────

bool WebhookStore::record_delivery(int64_t webhook_id, const std::string& event_type,
                                   const std::string& payload, int status_code,
                                   const std::string& error) {
    if (!open_)
        return false;
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease) {
        spdlog::warn("WebhookStore::record_delivery: no connection in time for webhook_id={} "
                     "({})",
                     webhook_id, pool_.last_error());
        if (metrics_)
            metrics_->counter("yuzu_server_webhook_delivery_log_failed_total").increment();
        return false;
    }
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "INSERT INTO webhook_store.webhook_deliveries "
        "(webhook_id, event_type, payload, status_code, delivered_at, error) "
        "VALUES ($1::bigint, $2, $3, $4::integer, $5::bigint, $6) RETURNING id",
        std::vector<std::string>{std::to_string(webhook_id), sanitize_pg_text(event_type),
                                 sanitize_pg_text(payload), std::to_string(status_code),
                                 std::to_string(now_epoch()), sanitize_pg_text(error)});
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) == 0) {
        spdlog::warn("WebhookStore::record_delivery: insert failed for webhook_id={}: {}",
                     webhook_id, PQerrorMessage(lease.get()));
        if (metrics_)
            metrics_->counter("yuzu_server_webhook_delivery_log_failed_total").increment();
        return false;
    }
    return true;
}

// ── Single webhook delivery (runs on a worker pool thread) ─────────────────

void WebhookStore::deliver_single(const WebhookDeliveryTarget& wh, const std::string& event_type,
                                  const std::string& payload_json) {
    int status_code = 0;
    std::string error;

    // Decrypt-on-use, right here, before ANY network work — the raw secret
    // exists in memory only around the HMAC call below (file header;
    // ADR-0010 §Consequences' per-delivery-batch cache allowance is
    // deliberately declined here, ADR-0057). A decrypt failure skips the
    // delivery ENTIRELY: it must never fire unsigned and must never fire
    // with an empty secret.
    std::optional<SecureBuffer> secret;
    if (wh.has_secret) {
        auto pk = pg::SecretCodec::encode_bigint_pk(wh.id);
        auto dec = secret_codec_.decrypt(
            pg::SecretCodec::SecretId{"webhook_store", "webhooks", "secret", pk}, wh.secret_blob);
        if (!dec.has_value()) {
            spdlog::warn("WebhookStore: delivery to {} skipped - signing secret unavailable "
                         "({})",
                         wh.url, pg::SecretCodec::to_external_error());
            if (metrics_)
                metrics_->counter("yuzu_server_webhook_delivery_secret_unavailable_total")
                    .increment();
            record_delivery(wh.id, event_type, payload_json, 0, "secret_unavailable");
            return;
        }
        secret = std::move(*dec);
    }

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
        cli.set_write_timeout(10);

        httplib::Headers headers;
        headers.emplace("Content-Type", "application/json");
        headers.emplace("X-Yuzu-Event", event_type);

        if (secret) {
            auto view =
                std::string_view(reinterpret_cast<const char*>(secret->data()), secret->size());
            auto sig = hmac_sha256(view, payload_json);
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
    // `secret` (if any) goes out of scope here and is wiped by
    // SecureBuffer's destructor on every exit path, including the catch
    // above — matches "the raw secret exists in memory only around the
    // HMAC call".

    const bool ok = error.empty() && status_code >= 200 && status_code < 300;
    if (metrics_) {
        metrics_->counter(ok ? "yuzu_server_webhook_delivery_success_total"
                              : "yuzu_server_webhook_delivery_failed_total")
            .increment();
    }
    record_delivery(wh.id, event_type, payload_json, status_code, error);
}

// ── Event firing (async — returns immediately) ──────────────────────────────

void WebhookStore::fire_event(const std::string& event_type, const std::string& payload_json) {
    if (!open_)
        return;

    std::vector<WebhookDeliveryTarget> matching;
    {
        // Short bound (fire_event can run on a gRPC handler thread) and
        // deliberately fail-soft: this is a "skip this tick's firing"
        // degrade, never an error the caller (Register/execution-completion
        // handlers) has any way to act on. See the file header's posture
        // note.
        auto lease = pool_.try_acquire_for(kFireEventAcquireTimeout);
        if (!lease) {
            spdlog::debug("WebhookStore::fire_event: no connection in time, skipping this "
                         "tick's matching scan ({})",
                         pool_.last_error());
            if (metrics_)
                metrics_->counter("yuzu_server_webhook_fire_event_degraded_total").increment();
            return;
        }
        pg::PgResult res = pg::exec_params(
            lease.get(),
            "SELECT id, url, event_types, encode(secret,'hex'), has_secret "
            "FROM webhook_store.webhooks WHERE enabled = TRUE",
            std::vector<std::string>{});
        if (res.status() != PGRES_TUPLES_OK) {
            spdlog::debug("WebhookStore::fire_event: query failed: {}", PQerrorMessage(lease.get()));
            if (metrics_)
                metrics_->counter("yuzu_server_webhook_fire_event_degraded_total").increment();
            return;
        }

        const int rows = PQntuples(res.get());
        for (int i = 0; i < rows; ++i) {
            std::string event_types = text_col(res.get(), i, 2);
            if (!event_matches(event_types, event_type))
                continue;

            WebhookDeliveryTarget wh;
            wh.id = to_i64(PQgetvalue(res.get(), i, 0));
            wh.url = text_col(res.get(), i, 1);
            wh.event_types = std::move(event_types);
            wh.has_secret = text_col(res.get(), i, 4) == "t";
            if (wh.has_secret)
                wh.secret_blob = hex_to_bytes(text_col(res.get(), i, 3));
            matching.push_back(std::move(wh));
        }
    }

    // Deliver to each matching webhook on the bounded pool (#3261 governance
    // hardening) - `wh` carries only the ENCRYPTED blob + has_secret, never
    // plaintext, so this closure never holds a decrypted secret while
    // queued.
    for (const auto& wh : matching) {
        const bool queued = delivery_pool_.submit(
            [this, wh, event_type, payload_json]() { deliver_single(wh, event_type, payload_json); });
        if (!queued) {
            spdlog::warn("WebhookStore: dropped delivery to {} - worker pool queue full or "
                         "server shutting down",
                         wh.url);
            if (metrics_)
                metrics_->counter("yuzu_server_webhook_delivery_dropped_total").increment();
        }
    }
}

// ── Legacy SQLite backfill (ADR-0009 mandatory, ADR-0010 transform) ────────

bool WebhookStore::migrate_from_sqlite(const std::filesystem::path& legacy_db_path) {
    const bool ok = migrate_from_sqlite_impl(legacy_db_path);
    if (metrics_)
        metrics_->counter("yuzu_server_webhook_backfill_total",
                          {{"result", ok ? "success" : "failed"}})
            .increment();
    return ok;
}

/// Idempotency model: a per-legacy-CONTENT fingerprint SET
/// (`sqlite_backfill_source`, DeploymentStore's shape), not
/// NotificationStore's single-marker-with-holder-side-reverify. Chosen
/// because `webhooks` rows have a real (if currently unbuilt) post-
/// migration LIFECYCLE for `secret` — a future rotation surface must never
/// have its write clobbered by a re-run backfill — and the per-row
/// ON-CONFLICT-then-IDENTITY-compare loop below is what actually enforces
/// that, unconditionally, for every replica and every retry. The
/// fingerprint set exists only to make an unmodified legacy file a cheap
/// no-op on a later boot; it is not the safety mechanism.
bool WebhookStore::migrate_from_sqlite_impl(const std::filesystem::path& legacy_db_path) {
    if (!open_)
        return false;

    std::error_code ec;
    const bool legacy_exists = std::filesystem::exists(legacy_db_path, ec);
    if (ec) {
        spdlog::error("WebhookStore::migrate_from_sqlite: cannot stat legacy path {}: {}",
                      legacy_db_path.string(), ec.message());
        return false;
    }

    if (legacy_exists) {
        // ADR-0010 §Consequences (a): a legacy file we are about to read
        // holds a PLAINTEXT webhook signing secret column — force 0600
        // defence-in-depth before touching it (ca_store.cpp idiom).
        std::filesystem::permissions(legacy_db_path,
                                     std::filesystem::perms::owner_read |
                                         std::filesystem::perms::owner_write,
                                     std::filesystem::perm_options::replace, ec);
        if (ec)
            spdlog::warn("WebhookStore::migrate_from_sqlite: could not set 0600 on legacy {}: {}",
                         legacy_db_path.string(), ec.message());
    }

    std::string fingerprint;
    std::vector<LegacyWebhook> legacy_hooks;
    std::vector<LegacyDelivery> legacy_deliveries;
    if (!legacy_exists) {
        fingerprint = kSourcelessFingerprint;
    } else {
        // Read the legacy SQLite file READ-ONLY. It is retained (never
        // deleted/moved here) until a verified backfill succeeds below.
        // SqliteDb/SqliteStmt: close/finalize on every path, including an
        // exception thrown mid read-loop.
        SqliteDb legacy;
        if (sqlite3_open_v2(legacy_db_path.string().c_str(), legacy.addr(), SQLITE_OPEN_READONLY,
                            nullptr) != SQLITE_OK) {
            spdlog::error("WebhookStore::migrate_from_sqlite: failed to open legacy {}: {}",
                          legacy_db_path.string(),
                          legacy ? sqlite3_errmsg(legacy.get()) : "open failed");
            return false;
        }

        bool has_table = false;
        {
            SqliteStmt probe;
            if (sqlite3_prepare_v2(legacy.get(),
                                   "SELECT count(*) FROM sqlite_master WHERE type='table' AND "
                                   "name='webhooks'",
                                   -1, probe.addr(), nullptr) != SQLITE_OK) {
                spdlog::error(
                    "WebhookStore::migrate_from_sqlite: schema probe failed on legacy {}: {}",
                    legacy_db_path.string(), sqlite3_errmsg(legacy.get()));
                return false;
            }
            if (sqlite3_step(probe.get()) != SQLITE_ROW) {
                spdlog::error(
                    "WebhookStore::migrate_from_sqlite: schema probe step failed on legacy {}: "
                    "{}",
                    legacy_db_path.string(), sqlite3_errmsg(legacy.get()));
                return false;
            }
            has_table = sqlite3_column_int64(probe.get(), 0) > 0;
        }

        if (!has_table) {
            // A present-but-schema-less file has nothing to protect — same
            // "nothing to lose" class as no file at all.
            fingerprint = kSourcelessFingerprint;
        } else {
            // Webhooks (parent) first.
            {
                SqliteStmt s;
                const char* sql = "SELECT id, url, event_types, secret, enabled, created_at "
                                  "FROM webhooks ORDER BY id ASC;";
                if (sqlite3_prepare_v2(legacy.get(), sql, -1, s.addr(), nullptr) != SQLITE_OK) {
                    spdlog::error(
                        "WebhookStore::migrate_from_sqlite: legacy webhooks query failed: {}",
                        sqlite3_errmsg(legacy.get()));
                    return false;
                }
                int step_rc = SQLITE_OK;
                while ((step_rc = sqlite3_step(s.get())) == SQLITE_ROW) {
                    LegacyWebhook h;
                    h.id = sqlite3_column_int64(s.get(), 0);
                    h.url = safe(reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 1)));
                    h.event_types =
                        safe(reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 2)));
                    h.secret =
                        safe(reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 3)));
                    h.enabled = sqlite3_column_int(s.get(), 4) != 0;
                    h.created_at = sqlite3_column_int64(s.get(), 5);
                    legacy_hooks.push_back(std::move(h));
                }
                // H2-class guard (governance): require the terminal code to
                // be SQLITE_DONE — a corrupt page or I/O error mid-scan
                // otherwise truncates the legacy set silently, and a
                // fingerprint computed over a partial read would stamp
                // completion over a partial copy, permanently.
                if (step_rc != SQLITE_DONE) {
                    spdlog::error(
                        "WebhookStore::migrate_from_sqlite: legacy webhooks scan aborted "
                        "mid-read (rc={} {}): refusing to stamp a partial backfill",
                        step_rc, sqlite3_errmsg(legacy.get()));
                    return false;
                }
            }
            // Deliveries (child) — orphan-checked against the parent ids
            // just read.
            {
                std::set<std::int64_t> hook_ids;
                for (const auto& h : legacy_hooks)
                    hook_ids.insert(h.id);

                SqliteStmt s;
                const char* sql =
                    "SELECT id, webhook_id, event_type, payload, status_code, delivered_at, "
                    "error FROM webhook_deliveries ORDER BY id ASC;";
                if (sqlite3_prepare_v2(legacy.get(), sql, -1, s.addr(), nullptr) != SQLITE_OK) {
                    spdlog::error("WebhookStore::migrate_from_sqlite: legacy "
                                  "webhook_deliveries query failed: {}",
                                  sqlite3_errmsg(legacy.get()));
                    return false;
                }
                int step_rc = SQLITE_OK;
                while ((step_rc = sqlite3_step(s.get())) == SQLITE_ROW) {
                    LegacyDelivery d;
                    d.id = sqlite3_column_int64(s.get(), 0);
                    d.webhook_id = sqlite3_column_int64(s.get(), 1);
                    d.event_type =
                        safe(reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 2)));
                    d.payload =
                        safe(reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 3)));
                    d.status_code = sqlite3_column_int(s.get(), 4);
                    d.delivered_at = sqlite3_column_int64(s.get(), 5);
                    d.error =
                        safe(reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 6)));
                    if (!hook_ids.contains(d.webhook_id)) {
                        // Both the legacy AND the migrated schema enforce
                        // webhook_id via FK CASCADE, so an orphaned
                        // delivery row is corruption, not a real upgrade
                        // artifact (SoftwareDeploymentStore's referential-
                        // closure reasoning, docs/postgres-migration-
                        // ladder.md) — fail closed naming the row.
                        spdlog::error(
                            "WebhookStore::migrate_from_sqlite: legacy webhook_deliveries row "
                            "{} references webhook_id={} which is not a legacy webhooks row — "
                            "refusing (fail-closed; an orphaned delivery is corruption, not a "
                            "real upgrade artifact)",
                            d.id, d.webhook_id);
                        return false;
                    }
                    legacy_deliveries.push_back(std::move(d));
                }
                if (step_rc != SQLITE_DONE) {
                    spdlog::error(
                        "WebhookStore::migrate_from_sqlite: legacy webhook_deliveries scan "
                        "aborted mid-read (rc={} {}): refusing to stamp a partial backfill",
                        step_rc, sqlite3_errmsg(legacy.get()));
                    return false;
                }
            }

            if (legacy_hooks.empty()) {
                fingerprint = kSourcelessFingerprint;
            } else {
                fingerprint = sha256_hex(canonicalize_legacy(legacy_hooks, legacy_deliveries));
                if (fingerprint.empty()) {
                    spdlog::error(
                        "WebhookStore::migrate_from_sqlite: SHA-256 hashing failed for legacy "
                        "content at {} — refusing (fail-closed)",
                        legacy_db_path.string());
                    return false;
                }
            }
        }
    }
    // `legacy` (if opened) is closed here via SqliteDb's destructor —
    // Windows refuses to rename a file with an open handle, and every read
    // above is already materialised into legacy_hooks/legacy_deliveries.

    // Has this exact content already been processed — by this replica's own
    // prior boot, or any other replica that shares this legacy file?
    {
        auto lease = pool_.acquire();
        if (!lease) {
            spdlog::error("WebhookStore::migrate_from_sqlite: no database connection");
            return false;
        }
        pg::PgResult chk = pg::exec_params(
            lease.get(),
            "SELECT 1 FROM webhook_store.sqlite_backfill_source WHERE fingerprint=$1",
            std::vector<std::string>{fingerprint});
        if (chk.status() != PGRES_TUPLES_OK) {
            spdlog::error("WebhookStore::migrate_from_sqlite: backfill-marker check failed: {}",
                          PQerrorMessage(lease.get()));
            return false;
        }
        if (PQntuples(chk.get()) > 0) {
            lease.reset();
            spdlog::debug(
                "WebhookStore::migrate_from_sqlite: fingerprint already processed, skipping");
            if (legacy_exists)
                move_legacy_aside(legacy_db_path);
            return true;
        }
    }

    if (fingerprint == kSourcelessFingerprint) {
        auto lease = pool_.acquire();
        if (!lease) {
            spdlog::error("WebhookStore::migrate_from_sqlite: no connection to stamp marker");
            return false;
        }
        pg::PgResult mk = pg::exec_params(
            lease.get(),
            "INSERT INTO webhook_store.sqlite_backfill_source (fingerprint, completed_at) "
            "VALUES ($1, $2::bigint) ON CONFLICT (fingerprint) DO NOTHING",
            std::vector<std::string>{fingerprint, std::to_string(now_epoch())});
        if (mk.status() != PGRES_COMMAND_OK) {
            spdlog::error("WebhookStore::migrate_from_sqlite: failed to stamp marker: {}",
                          PQerrorMessage(lease.get()));
            return false;
        }
        lease.reset();
        spdlog::info(
            "WebhookStore::migrate_from_sqlite: no legacy webhooks at {} — nothing to backfill",
            legacy_db_path.string());
        if (legacy_exists)
            move_legacy_aside(legacy_db_path);
        return true;
    }

    spdlog::info("WebhookStore::migrate_from_sqlite: backfilling {} webhook(s), {} delivery "
                 "record(s) from {}",
                 legacy_hooks.size(), legacy_deliveries.size(), legacy_db_path.string());

    // Encrypt every non-empty legacy secret BEFORE the transaction — never
    // hold a lease across crypto (ADR-0012 §2(b)). The row id is already
    // fixed (the legacy id, preserved via OVERRIDING SYSTEM VALUE below),
    // so the AAD row-PK is known upfront and no INSERT-then-UPDATE dance is
    // needed. An encrypt failure aborts the WHOLE backfill closed — never
    // writes plaintext, never writes a partial set (ADR-0010).
    std::vector<std::vector<std::uint8_t>> encrypted_secrets(legacy_hooks.size());
    for (std::size_t i = 0; i < legacy_hooks.size(); ++i) {
        const auto& h = legacy_hooks[i];
        if (h.secret.empty())
            continue;
        auto pk = pg::SecretCodec::encode_bigint_pk(h.id);
        auto enc = secret_codec_.encrypt(
            pg::SecretCodec::SecretId{"webhook_store", "webhooks", "secret", pk},
            std::span<const std::uint8_t>{reinterpret_cast<const std::uint8_t*>(h.secret.data()),
                                          h.secret.size()});
        if (!enc.has_value()) {
            spdlog::error(
                "WebhookStore::migrate_from_sqlite: secret encrypt failed for legacy webhook "
                "id={} — refusing (fail-closed; never writes plaintext or a partial backfill)",
                h.id);
            return false;
        }
        encrypted_secrets[i] = std::move(*enc);
    }

    std::string failure_detail;
    // ONE transaction: fail closed on any error, nothing partially
    // committed (ADR-0009). Unbounded with_txn: startup is serial, same
    // discipline as the ctor's unbounded acquire() (ADR-0012 §2(a)).
    const bool ok = pool_.with_txn([&](PGconn* conn) -> bool {
        for (std::size_t i = 0; i < legacy_hooks.size(); ++i) {
            const auto& h = legacy_hooks[i];
            const bool has_secret = !h.secret.empty();
            std::vector<std::optional<std::string>> params = {
                std::to_string(h.id),
                sanitize_pg_text(h.url),
                sanitize_pg_text(h.event_types),
                has_secret ? std::optional<std::string>(bytes_to_hex(encrypted_secrets[i]))
                          : std::nullopt,
                has_secret ? "true" : "false",
                h.enabled ? "true" : "false",
                std::to_string(h.created_at),
            };
            // RETURNING id + PQntuples() (never a bare PGRES_COMMAND_OK
            // check on ON CONFLICT DO NOTHING, docs/postgres-store-
            // playbook.md's Anti-patterns list): the status alone cannot
            // distinguish "inserted" from "silently no-opped".
            pg::PgResult res = pg::exec_params(
                conn,
                "INSERT INTO webhook_store.webhooks "
                "(id, url, event_types, secret, has_secret, enabled, created_at) "
                "OVERRIDING SYSTEM VALUE VALUES "
                "($1::bigint, $2, $3, decode($4,'hex'), $5::boolean, $6::boolean, $7::bigint) "
                "ON CONFLICT (id) DO NOTHING RETURNING id",
                params);
            if (res.status() != PGRES_TUPLES_OK) {
                failure_detail = std::string("legacy webhooks row id=") + std::to_string(h.id) +
                                 ": " + PQerrorMessage(conn);
                spdlog::error(
                    "WebhookStore::migrate_from_sqlite: insert of webhook {} failed: {}", h.id,
                    PQerrorMessage(conn));
                return false;
            }
            if (PQntuples(res.get()) > 0)
                continue; // inserted cleanly — no conflict

            // Conflict: a row with this id already exists (a peer
            // replica's backfill, or a retry of this same backfill after a
            // partial prior failure — impossible under the fingerprint-set
            // gate above for THIS content, but a differently-fingerprinted
            // legacy file sharing an id is still possible). Every
            // `webhooks` column except `secret` is write-once today — no
            // update/enable-disable/rotate-secret REST surface exists
            // (ADR-0057 scope guard) — so IDENTITY here is every OTHER
            // column, and `secret`/`has_secret` are never compared or
            // re-written on conflict: whatever Postgres already holds
            // wins, unconditionally (kickoff lesson 1 — once a rotation
            // surface exists, a secret rotated post-cutover must never be
            // clobbered by a re-run backfill).
            pg::PgResult existing = pg::exec_params(
                conn,
                "SELECT url, event_types, has_secret, enabled, created_at "
                "FROM webhook_store.webhooks WHERE id=$1::bigint",
                std::vector<std::string>{std::to_string(h.id)});
            if (existing.status() != PGRES_TUPLES_OK || PQntuples(existing.get()) == 0) {
                failure_detail = std::string("legacy webhooks row id=") + std::to_string(h.id) +
                                 ": conflicted on insert but the existing row could not be read "
                                 "back for comparison: " +
                                 PQerrorMessage(conn);
                spdlog::error(
                    "WebhookStore::migrate_from_sqlite: webhook {} conflicted but the existing "
                    "row read-back failed: {}",
                    h.id, PQerrorMessage(conn));
                return false;
            }
            const std::string stored_url = text_col(existing.get(), 0, 0);
            const std::string stored_event_types = text_col(existing.get(), 0, 1);
            const bool stored_has_secret = text_col(existing.get(), 0, 2) == "t";
            const bool stored_enabled = text_col(existing.get(), 0, 3) == "t";
            const std::int64_t stored_created_at = to_i64(PQgetvalue(existing.get(), 0, 4));
            const bool identity_matches =
                stored_url == h.url && stored_event_types == h.event_types &&
                stored_enabled == h.enabled && stored_created_at == h.created_at;
            if (!identity_matches) {
                failure_detail =
                    std::string("legacy webhooks row id=") + std::to_string(h.id) +
                    " already exists with DIFFERENT identity — refusing to silently discard it";
                spdlog::error(
                    "WebhookStore::migrate_from_sqlite: webhook {} conflicts with different "
                    "IDENTITY — refusing to stamp a backfill that would silently discard it",
                    h.id);
                return false;
            }
            if (stored_has_secret != has_secret) {
                spdlog::warn(
                    "WebhookStore::migrate_from_sqlite: webhook {} already present with "
                    "has_secret={} vs this legacy snapshot's has_secret={} — keeping the "
                    "current Postgres value (secret state is never reconciled by backfill, "
                    "ADR-0057)",
                    h.id, stored_has_secret, has_secret);
            } else {
                spdlog::debug(
                    "WebhookStore::migrate_from_sqlite: webhook {} already present with "
                    "matching identity, skipping (benign no-op)",
                    h.id);
            }
        }

        for (const auto& d : legacy_deliveries) {
            pg::PgResult res = pg::exec_params(
                conn,
                "INSERT INTO webhook_store.webhook_deliveries "
                "(id, webhook_id, event_type, payload, status_code, delivered_at, error) "
                "OVERRIDING SYSTEM VALUE VALUES "
                "($1::bigint, $2::bigint, $3, $4, $5::integer, $6::bigint, $7) "
                "ON CONFLICT (id) DO NOTHING RETURNING id",
                std::vector<std::string>{
                    std::to_string(d.id), std::to_string(d.webhook_id),
                    sanitize_pg_text(d.event_type), sanitize_pg_text(d.payload),
                    std::to_string(d.status_code), std::to_string(d.delivered_at),
                    sanitize_pg_text(d.error)});
            if (res.status() != PGRES_TUPLES_OK) {
                failure_detail = std::string("legacy webhook_deliveries row id=") +
                                 std::to_string(d.id) + ": " + PQerrorMessage(conn);
                spdlog::error(
                    "WebhookStore::migrate_from_sqlite: insert of delivery {} failed: {}", d.id,
                    PQerrorMessage(conn));
                return false;
            }
            if (PQntuples(res.get()) > 0)
                continue;

            // Deliveries are append-only telemetry with NO lifecycle at
            // all — a conflicting id must match byte-for-byte or it is
            // corruption, never a benign progress difference.
            pg::PgResult existing = pg::exec_params(
                conn,
                "SELECT webhook_id, event_type, payload, status_code, delivered_at, error "
                "FROM webhook_store.webhook_deliveries WHERE id=$1::bigint",
                std::vector<std::string>{std::to_string(d.id)});
            if (existing.status() != PGRES_TUPLES_OK || PQntuples(existing.get()) == 0) {
                failure_detail = std::string("legacy webhook_deliveries row id=") +
                                 std::to_string(d.id) +
                                 ": conflicted on insert but the existing row could not be read "
                                 "back for comparison: " +
                                 PQerrorMessage(conn);
                spdlog::error(
                    "WebhookStore::migrate_from_sqlite: delivery {} conflicted but the "
                    "existing row read-back failed: {}",
                    d.id, PQerrorMessage(conn));
                return false;
            }
            const bool matches = to_i64(PQgetvalue(existing.get(), 0, 0)) == d.webhook_id &&
                                text_col(existing.get(), 0, 1) == d.event_type &&
                                text_col(existing.get(), 0, 2) == d.payload &&
                                to_i64(PQgetvalue(existing.get(), 0, 3)) == d.status_code &&
                                to_i64(PQgetvalue(existing.get(), 0, 4)) == d.delivered_at &&
                                text_col(existing.get(), 0, 5) == d.error;
            if (!matches) {
                failure_detail = std::string("legacy webhook_deliveries row id=") +
                                 std::to_string(d.id) +
                                 " already exists with DIFFERENT content — refusing to "
                                 "silently discard it";
                spdlog::error(
                    "WebhookStore::migrate_from_sqlite: delivery {} conflicts with different "
                    "content — refusing to stamp a backfill that would silently discard it",
                    d.id);
                return false;
            }
            spdlog::debug(
                "WebhookStore::migrate_from_sqlite: delivery {} already present with identical "
                "content, skipping (benign no-op)",
                d.id);
        }

        // Advance BOTH identity sequences past the migrated ids — load-
        // bearing: without this the sequences still start at 1 and the
        // first live create_webhook()/record_delivery() after backfill
        // collides with a backfilled id (NotificationStore precedent).
        pg::PgResult sv1 = pg::exec_params(
            conn,
            "SELECT setval(pg_get_serial_sequence('webhook_store.webhooks','id'), "
            "GREATEST((SELECT COALESCE(MAX(id),0) FROM webhook_store.webhooks), 1), "
            "(SELECT COUNT(*) FROM webhook_store.webhooks) > 0)",
            std::vector<std::string>{});
        if (sv1.status() != PGRES_TUPLES_OK) {
            failure_detail = std::string("webhooks sequence advance: ") + PQerrorMessage(conn);
            spdlog::error(
                "WebhookStore::migrate_from_sqlite: webhooks sequence advance failed: {}",
                PQerrorMessage(conn));
            return false;
        }
        pg::PgResult sv2 = pg::exec_params(
            conn,
            "SELECT setval(pg_get_serial_sequence('webhook_store.webhook_deliveries','id'), "
            "GREATEST((SELECT COALESCE(MAX(id),0) FROM webhook_store.webhook_deliveries), 1), "
            "(SELECT COUNT(*) FROM webhook_store.webhook_deliveries) > 0)",
            std::vector<std::string>{});
        if (sv2.status() != PGRES_TUPLES_OK) {
            failure_detail =
                std::string("webhook_deliveries sequence advance: ") + PQerrorMessage(conn);
            spdlog::error(
                "WebhookStore::migrate_from_sqlite: webhook_deliveries sequence advance "
                "failed: {}",
                PQerrorMessage(conn));
            return false;
        }

        pg::PgResult marker = pg::exec_params(
            conn,
            "INSERT INTO webhook_store.sqlite_backfill_source (fingerprint, completed_at) "
            "VALUES ($1, $2::bigint) ON CONFLICT (fingerprint) DO NOTHING",
            std::vector<std::string>{fingerprint, std::to_string(now_epoch())});
        if (marker.status() != PGRES_COMMAND_OK) {
            failure_detail = std::string("backfill marker stamp: ") + PQerrorMessage(conn);
            spdlog::error(
                "WebhookStore::migrate_from_sqlite: failed to stamp backfill marker: {}",
                PQerrorMessage(conn));
            return false;
        }
        return true;
    });

    if (!ok) {
        spdlog::error(
            "WebhookStore::migrate_from_sqlite: backfill transaction failed and was rolled "
            "back ({}); legacy db {} left untouched — will retry on next boot",
            failure_detail, legacy_db_path.string());
        return false;
    }

    spdlog::info("WebhookStore::migrate_from_sqlite: backfilled {} webhook(s), {} delivery "
                 "record(s)",
                 legacy_hooks.size(), legacy_deliveries.size());
    move_legacy_aside(legacy_db_path);
    return true;
}

} // namespace yuzu::server
