#include "device_token_store.hpp"

#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "secure_random.hpp"
#include "sqlite_raii.hpp"
#include "utf8_sanitize.hpp"

#include <libpq-fe.h>
#include <openssl/evp.h> // sha256_hex's EVP_Digest — needed unconditionally (backfill fingerprinting runs on every platform), never gated behind _WIN32 like the SHA256-vs-BCrypt hash_token() split below
#include <spdlog/spdlog.h>
#include <sqlite3.h>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
// clang-format off
#include <windows.h>  // must precede bcrypt.h (defines NTSTATUS)
// clang-format on
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#else
#include <openssl/sha.h>
#endif

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <string_view>

namespace yuzu::server {

namespace {

constexpr const char* kStoreName = "device_token_store";

// validate_token is a genuine request/response path once wired (a bearer credential presented
// on every scoped API call) — shorter than LicenseStore::validate()'s 10s (a periodic
// background pass). create_token/revoke_token/revoke_by_principal are operator-driven, same
// budget class as list_tokens.
constexpr std::chrono::milliseconds kReadTimeout{2000};
constexpr std::chrono::milliseconds kWriteTimeout{4000};
constexpr std::chrono::milliseconds kValidateTimeout{2000};

// gov UP-5 precedent (every migrated store on this ladder): bounded materialization regardless
// of table growth — an operator convenience list, not a paged feed.
constexpr int kListRowCap = 10000;

// Sentinel fingerprint for "this replica's legacy file is absent, or present but holds no
// device_auth_tokens table/rows worth migrating" — mirrors DeploymentStore's
// kSourcelessFingerprint (deployment_store.cpp).
constexpr const char* kSourcelessFingerprint = "sourceless";

// ── Small helpers ────────────────────────────────────────────────────────────

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

bool to_bool(const char* s) {
    return s != nullptr && (s[0] == 't' || s[0] == 'T' || s[0] == '1');
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

// Applied to every free-text column reaching Postgres (name/principal_id/device_id/
// definition_id), mirroring license_store.cpp's sanitize_pg_text — a bad byte at-rest in a
// legacy device-tokens.db must not brick the mandatory backfill, and an operator-supplied
// name/device_id/definition_id over REST is equally untrusted (already length-clamped at the
// route, but not UTF-8-validated there).
std::string sanitize_pg_text(std::string_view s) {
    std::string out = sanitize_utf8_strict(s);
    std::size_t pos = 0;
    while ((pos = out.find('\0', pos)) != std::string::npos) {
        out.replace(pos, 1, "\xEF\xBF\xBD");
        pos += 3;
    }
    return out;
}

// token_id (generate_token_id(), 32 lowercase hex chars) and token_hash (hash_token(), 64
// lowercase hex chars) are both deterministically hex-formatted by every write path this store
// owns. Validated here, before either can reach Postgres via backfill, for the same reason
// LicenseStore validates id/license_key_hash (gov security-guardian MEDIUM precedent, ADR-0048):
// an invalid-UTF-8 or non-hex byte in a hand-edited/corrupted legacy value would otherwise reach
// Postgres raw (sanitize_pg_text is applied to the OTHER free-text columns but not these two, to
// keep the format check exact) and fail the INSERT with an opaque server-side encoding/
// constraint error that retries identically on every future boot against the same corrupt file.
bool is_valid_lowercase_hex(std::string_view s, std::size_t expected_len) {
    if (s.size() != expected_len)
        return false;
    return std::all_of(s.begin(), s.end(), [](char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    });
}

// ── Backfill fingerprinting ──────────────────────────────────────────────────

// Internal-only row shape carrying every column relevant to backfill.
struct LegacyDeviceTokenRow {
    std::string token_id;
    std::string token_hash;
    std::string name;
    std::string principal_id;
    std::string device_id;
    std::string definition_id;
    std::int64_t created_at{0};
    std::int64_t expires_at{0};
    std::int64_t last_used_at{0};
    bool revoked{false};
};

std::string sha256_hex(const std::string& in) {
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

// Length-prefixed (`<byte-length>:<bytes>`, the netstring/bencode technique — see
// DeploymentStore's canonicalize_legacy_jobs for the injectivity rationale): a raw delimiter
// byte embedded in a field can't be confused with a real field boundary.
void append_field(std::string& out, std::string_view field) {
    out += std::to_string(field.size());
    out += ':';
    out += field;
}

std::string canonicalize_legacy_tokens(const std::vector<LegacyDeviceTokenRow>& rows) {
    std::vector<std::string> encoded;
    encoded.reserve(rows.size());
    for (const auto& r : rows) {
        std::string e;
        append_field(e, r.token_id);
        append_field(e, r.token_hash);
        append_field(e, r.name);
        append_field(e, r.principal_id);
        append_field(e, r.device_id);
        append_field(e, r.definition_id);
        append_field(e, std::to_string(r.created_at));
        append_field(e, std::to_string(r.expires_at));
        append_field(e, std::to_string(r.last_used_at));
        append_field(e, r.revoked ? "1" : "0");
        encoded.push_back(std::move(e));
    }
    std::sort(encoded.begin(), encoded.end());
    std::string canon = "device-token-legacy-fingerprint-v1\n";
    for (const auto& e : encoded)
        canon += e;
    return canon;
}

// ── Migration DDL ────────────────────────────────────────────────────────────

const std::vector<pg::PgMigration>& migrations() {
    // Unqualified DDL: the runner sets search_path to the store schema for the migration txn.
    // Runtime statements below schema-qualify explicitly.
    static const std::vector<pg::PgMigration> kMigrations = {
        {1,
         "CREATE TABLE device_auth_tokens ("
         "  token_id      TEXT PRIMARY KEY,"
         "  token_hash    TEXT NOT NULL UNIQUE,"
         "  name          TEXT NOT NULL DEFAULT '',"
         "  principal_id  TEXT NOT NULL,"
         "  device_id     TEXT NOT NULL DEFAULT '',"
         "  definition_id TEXT NOT NULL DEFAULT '',"
         "  created_at    BIGINT NOT NULL DEFAULT 0,"
         "  expires_at    BIGINT NOT NULL DEFAULT 0,"
         "  last_used_at  BIGINT NOT NULL DEFAULT 0,"
         "  revoked       BOOLEAN NOT NULL DEFAULT FALSE);"
         // token_hash already carries a UNIQUE constraint, which Postgres backs with its own
         // index — no separate idx_device_token_hash (the pre-migration SQLite schema had one,
         // but it was always redundant with the UNIQUE index; not reproduced here).
         "CREATE INDEX idx_device_token_device ON device_auth_tokens(device_id);"
         // ADR-0009 backfill idempotency — content-fingerprinted, not a single fleet-wide
         // completion flag (see migrate_from_sqlite's doc comment).
         "CREATE TABLE sqlite_backfill_source ("
         "  fingerprint  TEXT PRIMARY KEY,"
         "  completed_at BIGINT NOT NULL);"},
    };
    return kMigrations;
}

// ── Token hashing (kept cross-platform-identical to the pre-migration store) ───────────────

std::string hash_token(const std::string& raw) {
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

// Cryptographic PRNG required — mt19937 is predictable from its outputs (#801).
// random_hex routes through OpenSSL RAND_bytes (POSIX) / BCryptGenRandom (Win).
std::expected<std::string, std::string> generate_raw_device_token() {
    auto bytes = random_hex(32); // 32 bytes -> 64 hex chars
    if (!bytes.has_value())
        return std::unexpected(std::string{"CSPRNG unavailable (entropy exhausted)"});
    return std::string{"ydt_"} + *bytes; // yuzu device token prefix
}

std::expected<std::string, std::string> generate_token_id() {
    auto bytes = random_hex(16); // 16 bytes -> 32 hex chars
    if (!bytes.has_value())
        return std::unexpected(std::string{"CSPRNG unavailable (entropy exhausted)"});
    return std::move(*bytes);
}

// Whether sqlite_master lists a table named `table_name`; `nullopt` on a schema-probe DB error
// (never conflated with "table absent").
std::optional<bool> sqlite_table_exists(sqlite3* db, const char* table_name) {
    SqliteStmt probe;
    if (sqlite3_prepare_v2(db, "SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?;",
                           -1, probe.addr(), nullptr) != SQLITE_OK)
        return std::nullopt;
    sqlite3_bind_text(probe.get(), 1, table_name, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(probe.get()) != SQLITE_ROW)
        return std::nullopt;
    return sqlite3_column_int64(probe.get(), 0) > 0;
}

} // namespace

// ── Construction ─────────────────────────────────────────────────────────────

DeviceTokenStore::DeviceTokenStore(pg::PgPool& pool) : pool_(pool) {
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error("DeviceTokenStore: no database connection at construction ({}) — device "
                      "token persistence disabled",
                      pool_.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error("DeviceTokenStore: schema migration failed — device token persistence "
                      "disabled");
        return;
    }
    open_ = true;
}

// ── Backfill (ADR-0009/0052) ─────────────────────────────────────────────────
//
// Content-fingerprinted, not a single fleet-wide completion flag — mirrors DeploymentStore's
// (docs/adr/0043-...md) single-table shape most closely among the already-migrated stores: a
// client-generated surrogate `token_id`, no small-human-chosen-identifier collision risk
// RbacStore has to guard against.
//
// Per-row conflict handling on `token_id` (`ON CONFLICT (token_id) DO NOTHING`) partitions the
// compared columns into IDENTITY (token_hash, name, principal_id, device_id, definition_id,
// created_at, expires_at — write-once at INSERT, no other method mutates them) and LIFECYCLE
// (last_used_at, revoked — both monotone: last_used_at only grows via GREATEST(), revoked only
// ever moves 0->1, never back). An identity mismatch fails the boot closed — the same class as
// every other migrated store's IDENTITY conflict.
//
// The LIFECYCLE direction check applies the SAME fail-closed-on-legacy-ahead rule
// DeploymentStore/LicenseStore's rank-based template already uses (gov architect, corrected —
// both siblings also fail closed when the legacy side is strictly ahead; verify against
// deployment_store.cpp's/license_store.cpp's own conflict-handling blocks, not this comment).
// This store's field just doesn't need a rank computed: `revoked` is a two-value monotone flag
// with no terminal-tie case a multi-value status enum has to resolve, so "which side is ahead"
// reduces to a single boolean check. `revoked` is also the auth-bypass-relevant field here — if
// the legacy row shows revoked=true but Postgres currently holds revoked=false, that is exactly
// the shape ADR-0009's rollback-then-roll-forward note warns about — an operator revoked this
// token while running the pre-migration binary, and silently keeping Postgres's stale "still
// active" value would resurrect a credential the operator explicitly killed. That case FAILS THE
// BACKFILL CLOSED, naming both sides, exactly like an IDENTITY mismatch — never a WARNING-logged
// benign no-op. The reverse (Postgres already revoked, legacy still shows active) is safe:
// revoked is monotone, so Postgres being ahead is the ordinary shape of post-migration progress
// and is a benign no-op. A `last_used_at`-only divergence (both sides agree on `revoked`) carries
// no auth-bypass risk either direction — it is bookkeeping, not authorization state — so it is
// always a benign no-op regardless of which side is numerically ahead; the backfill never
// updates an existing row either way.
//
// Legacy files are read READ-ONLY and never deleted/moved — retained for the ADR-0009
// one-release rollback window.

bool DeviceTokenStore::migrate_from_sqlite(const std::filesystem::path& legacy_db_path) {
    if (!open_)
        return false;

    std::error_code ec;
    const bool legacy_exists = std::filesystem::exists(legacy_db_path, ec);
    if (ec) {
        spdlog::error("DeviceTokenStore::migrate_from_sqlite: cannot stat legacy path {}: {}",
                      legacy_db_path.string(), ec.message());
        return false;
    }

    std::string fingerprint;
    std::vector<LegacyDeviceTokenRow> legacy_rows;

    if (!legacy_exists) {
        fingerprint = kSourcelessFingerprint;
    } else {
        // SqliteDb/SqliteStmt (gov cpp-safety): close/finalize on every path, including an
        // exception thrown mid read-loop.
        SqliteDb legacy;
        if (sqlite3_open_v2(legacy_db_path.string().c_str(), legacy.addr(), SQLITE_OPEN_READONLY,
                            nullptr) != SQLITE_OK) {
            spdlog::error("DeviceTokenStore::migrate_from_sqlite: failed to open legacy {}: {}",
                          legacy_db_path.string(),
                          legacy ? sqlite3_errmsg(legacy.get()) : "open failed");
            return false;
        }

        auto has_table_probe = sqlite_table_exists(legacy.get(), "device_auth_tokens");
        if (!has_table_probe) {
            spdlog::error(
                "DeviceTokenStore::migrate_from_sqlite: schema probe failed on legacy {}: {}",
                legacy_db_path.string(), sqlite3_errmsg(legacy.get()));
            return false;
        }

        if (!*has_table_probe) {
            // Present-but-schema-less file — same "nothing to protect" class as no file at all.
            fingerprint = kSourcelessFingerprint;
        } else {
            SqliteStmt s;
            const char* sql =
                "SELECT token_id, token_hash, name, principal_id, device_id, definition_id, "
                "created_at, expires_at, last_used_at, revoked FROM device_auth_tokens "
                // gov Gate 8 architect precedent (LicenseStore/DeploymentStore, PK order): two
                // replicas whose legacy files order the same row set differently otherwise
                // acquire Postgres row locks in opposite order during backfill INSERT — PK order
                // makes every overlapping pass agree, closing that deadlock class up front.
                "ORDER BY token_id ASC;";
            if (sqlite3_prepare_v2(legacy.get(), sql, -1, s.addr(), nullptr) != SQLITE_OK) {
                spdlog::error(
                    "DeviceTokenStore::migrate_from_sqlite: legacy device_auth_tokens query "
                    "failed: {}",
                    sqlite3_errmsg(legacy.get()));
                return false;
            }
            int step_rc = SQLITE_OK;
            while ((step_rc = sqlite3_step(s.get())) == SQLITE_ROW) {
                LegacyDeviceTokenRow r;
                r.token_id = safe(reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 0)));
                r.token_hash =
                    safe(reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 1)));
                r.name = safe(reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 2)));
                r.principal_id =
                    safe(reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 3)));
                r.device_id = safe(reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 4)));
                r.definition_id =
                    safe(reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 5)));
                r.created_at = sqlite3_column_int64(s.get(), 6);
                r.expires_at = sqlite3_column_int64(s.get(), 7);
                r.last_used_at = sqlite3_column_int64(s.get(), 8);
                r.revoked = sqlite3_column_int64(s.get(), 9) != 0;

                // gov security-guardian MEDIUM precedent (LicenseStore, ADR-0048): token_id/
                // token_hash are read raw and skipped by sanitize_pg_text (unlike the other
                // free-text columns) — validate their hex format before either can reach
                // Postgres, so a corrupt/hand-edited legacy value fails loudly here rather than
                // as an opaque constraint error that retries identically on every future boot.
                if (!is_valid_lowercase_hex(r.token_id, 32)) {
                    spdlog::error(
                        "DeviceTokenStore::migrate_from_sqlite: legacy device_auth_tokens row "
                        "has an invalid token_id '{}' (expected 32 lowercase hex chars) — "
                        "refusing to stamp a backfill containing it",
                        r.token_id);
                    return false;
                }
                if (!is_valid_lowercase_hex(r.token_hash, 64)) {
                    spdlog::error(
                        "DeviceTokenStore::migrate_from_sqlite: legacy device_auth_tokens row "
                        "{} has an invalid token_hash (expected 64 lowercase hex chars) — "
                        "refusing to stamp a backfill containing it",
                        r.token_id);
                    return false;
                }
                legacy_rows.push_back(std::move(r));
            }
            // Mid-scan-corruption guard (gov docs-writer/cpp-expert precedent, DeploymentStore/
            // LicenseStore): the terminal step code must be SQLITE_DONE, never merely "loop
            // exited" — a corrupt page is never silently treated as an empty/complete table.
            if (step_rc != SQLITE_DONE) {
                spdlog::error(
                    "DeviceTokenStore::migrate_from_sqlite: legacy device_auth_tokens scan "
                    "aborted mid-read (rc={} {}): refusing to stamp a partial backfill",
                    step_rc, sqlite3_errmsg(legacy.get()));
                return false;
            }

            if (legacy_rows.empty()) {
                fingerprint = kSourcelessFingerprint;
            } else {
                fingerprint = sha256_hex(canonicalize_legacy_tokens(legacy_rows));
                if (fingerprint.empty()) {
                    spdlog::error(
                        "DeviceTokenStore::migrate_from_sqlite: SHA-256 hashing failed for "
                        "legacy content at {} — refusing (fail-closed)",
                        legacy_db_path.string());
                    return false;
                }
            }
        }
    }
    // `legacy` (if opened) closed here via SqliteDb's destructor.

    // Has THIS specific fingerprint already been processed? Unbounded acquire() here is
    // construction-time discipline (ADR-0012 §2(a)) — this runs once at boot, before serving.
    {
        auto lease = pool_.acquire();
        if (!lease) {
            spdlog::error("DeviceTokenStore::migrate_from_sqlite: no database connection");
            return false;
        }
        pg::PgResult marker = pg::exec_params(
            lease.get(),
            "SELECT 1 FROM device_token_store.sqlite_backfill_source WHERE fingerprint=$1",
            std::vector<std::string>{fingerprint});
        if (marker.status() != PGRES_TUPLES_OK) {
            spdlog::error("DeviceTokenStore::migrate_from_sqlite: backfill-marker check failed: "
                          "{}",
                          PQerrorMessage(lease.get()));
            return false;
        }
        if (PQntuples(marker.get()) > 0) {
            spdlog::debug(
                "DeviceTokenStore::migrate_from_sqlite: fingerprint already processed, skipping");
            return true;
        }
    }

    if (fingerprint == kSourcelessFingerprint) {
        auto lease = pool_.acquire();
        if (!lease) {
            spdlog::error("DeviceTokenStore::migrate_from_sqlite: no connection to stamp marker");
            return false;
        }
        pg::PgResult r = pg::exec_params(
            lease.get(),
            "INSERT INTO device_token_store.sqlite_backfill_source (fingerprint, completed_at) "
            "VALUES ($1, $2::bigint) ON CONFLICT (fingerprint) DO NOTHING",
            std::vector<std::string>{fingerprint, std::to_string(now_epoch())});
        if (r.status() != PGRES_COMMAND_OK) {
            spdlog::error("DeviceTokenStore::migrate_from_sqlite: failed to stamp marker: {}",
                          PQerrorMessage(lease.get()));
            return false;
        }
        spdlog::info("DeviceTokenStore::migrate_from_sqlite: no legacy device tokens at {} — "
                     "nothing to backfill",
                     legacy_db_path.string());
        return true;
    }

    spdlog::info("DeviceTokenStore::migrate_from_sqlite: backfilling {} device token(s) from {}",
                 legacy_rows.size(), legacy_db_path.string());

    std::string failure_detail;
    bool row_conflict_guidance = false;
    bool ok = pool_.with_txn([&](PGconn* conn) -> bool {
        for (const auto& r : legacy_rows) {
            pg::PgResult res = pg::exec_params(
                conn,
                "INSERT INTO device_token_store.device_auth_tokens "
                "(token_id, token_hash, name, principal_id, device_id, definition_id, "
                " created_at, expires_at, last_used_at, revoked) "
                "VALUES ($1,$2,$3,$4,$5,$6,$7::bigint,$8::bigint,$9::bigint,$10) "
                "ON CONFLICT (token_id) DO NOTHING RETURNING token_id",
                std::vector<std::string>{
                    r.token_id, r.token_hash, sanitize_pg_text(r.name),
                    sanitize_pg_text(r.principal_id), sanitize_pg_text(r.device_id),
                    sanitize_pg_text(r.definition_id), std::to_string(r.created_at),
                    std::to_string(r.expires_at), std::to_string(r.last_used_at),
                    r.revoked ? "true" : "false"});
            if (res.status() != PGRES_TUPLES_OK) {
                failure_detail = std::string("legacy device_auth_tokens row token_id='") +
                                 r.token_id + "': " + PQerrorMessage(conn);
                spdlog::error("DeviceTokenStore::migrate_from_sqlite: insert of {} failed: {}",
                              r.token_id, PQerrorMessage(conn));
                return false;
            }
            if (PQntuples(res.get()) > 0)
                continue; // inserted cleanly — no conflict

            // Conflict: a row with this token_id already exists. `ON CONFLICT` matches on
            // token_id ALONE — read the existing row back and compare in two classes (file
            // header).
            //
            // gov unhappy-path UP-1: this read-back is NOT row-locked (no `FOR UPDATE`) and runs
            // as a second statement in the same transaction, so it can observe a state a
            // concurrent writer produced after the INSERT's conflict was detected. Safe ONLY
            // because IDENTITY columns are write-once (no code path ever UPDATEs them) and
            // `revoked` is monotone false->true (a race can only make `stored.revoked` MORE
            // true, which is always this function's benign branch — see the LIFECYCLE direction
            // comment above `migrate_from_sqlite`). A future change that makes any IDENTITY
            // column mutable, or that lets `revoked` move true->false, reopens a real race here
            // and would need this read-back to become `FOR UPDATE` (inside a transaction that
            // also holds the lock across the eventual write, which today's design never issues).
            pg::PgResult existing = pg::exec_params(
                conn,
                "SELECT token_id, token_hash, name, principal_id, device_id, definition_id, "
                "created_at, expires_at, last_used_at, revoked "
                "FROM device_token_store.device_auth_tokens WHERE token_id=$1",
                std::vector<std::string>{r.token_id});
            if (existing.status() != PGRES_TUPLES_OK || PQntuples(existing.get()) == 0) {
                failure_detail = std::string("legacy device_auth_tokens row token_id='") +
                                 r.token_id +
                                 "': conflicted on insert but the existing row could not be read "
                                 "back for comparison: " +
                                 PQerrorMessage(conn);
                spdlog::error(
                    "DeviceTokenStore::migrate_from_sqlite: row {} conflicted but the existing "
                    "row read-back failed: {}",
                    r.token_id, PQerrorMessage(conn));
                return false;
            }
            LegacyDeviceTokenRow stored;
            stored.token_id = text_col(existing.get(), 0, 0);
            stored.token_hash = text_col(existing.get(), 0, 1);
            stored.name = text_col(existing.get(), 0, 2);
            stored.principal_id = text_col(existing.get(), 0, 3);
            stored.device_id = text_col(existing.get(), 0, 4);
            stored.definition_id = text_col(existing.get(), 0, 5);
            stored.created_at = to_i64(PQgetvalue(existing.get(), 0, 6));
            stored.expires_at = to_i64(PQgetvalue(existing.get(), 0, 7));
            stored.last_used_at = to_i64(PQgetvalue(existing.get(), 0, 8));
            stored.revoked = to_bool(PQgetvalue(existing.get(), 0, 9));

            const bool identity_matches =
                stored.token_hash == r.token_hash && stored.name == sanitize_pg_text(r.name) &&
                stored.principal_id == sanitize_pg_text(r.principal_id) &&
                stored.device_id == sanitize_pg_text(r.device_id) &&
                stored.definition_id == sanitize_pg_text(r.definition_id) &&
                stored.created_at == r.created_at && stored.expires_at == r.expires_at;
            if (!identity_matches) {
                row_conflict_guidance = true;
                failure_detail =
                    std::string("legacy device_auth_tokens row token_id='") + r.token_id +
                    "' already exists with DIFFERENT identity (stored: name='" + stored.name +
                    "' principal_id='" + stored.principal_id + "' device_id='" +
                    stored.device_id + "' definition_id='" + stored.definition_id +
                    "' created_at=" + std::to_string(stored.created_at) +
                    " expires_at=" + std::to_string(stored.expires_at) + "; legacy: name='" +
                    r.name + "' principal_id='" + r.principal_id + "' device_id='" +
                    r.device_id + "' definition_id='" + r.definition_id +
                    "' created_at=" + std::to_string(r.created_at) +
                    " expires_at=" + std::to_string(r.expires_at) +
                    ") — refusing to silently discard it";
                spdlog::error(
                    "DeviceTokenStore::migrate_from_sqlite: row {} conflicts with different "
                    "IDENTITY — refusing to stamp a backfill that would silently discard it",
                    r.token_id);
                return false;
            }

            const bool lifecycle_matches =
                stored.last_used_at == r.last_used_at && stored.revoked == r.revoked;
            if (lifecycle_matches) {
                spdlog::debug(
                    "DeviceTokenStore::migrate_from_sqlite: row {} already present with "
                    "identical content, skipping (benign no-op)",
                    r.token_id);
                continue;
            }

            // Security-relevant asymmetry (file header, ADR-0052): the legacy row shows this
            // token revoked but Postgres does not yet reflect that — silently keeping
            // Postgres's stale "still active" value would resurrect a credential the operator
            // explicitly killed. `revoked` only ever moves false->true, so this is the one
            // LIFECYCLE direction that must fail closed rather than warn-and-keep.
            if (r.revoked && !stored.revoked) {
                row_conflict_guidance = true;
                failure_detail =
                    std::string("legacy device_auth_tokens row token_id='") + r.token_id +
                    "' was REVOKED in the legacy snapshot but Postgres's current row is still "
                    "active (stored: revoked=false last_used_at=" +
                    std::to_string(stored.last_used_at) +
                    "; legacy: revoked=true last_used_at=" + std::to_string(r.last_used_at) +
                    ") — refusing to silently discard evidence of a revocation the operator "
                    "issued while running the pre-migration binary (ADR-0009 "
                    "rollback-then-roll-forward). Reconcile Postgres to revoked=true or, to "
                    "explicitly accept the loss, move the whole legacy file aside so this "
                    "backfill is never retried against it, then restart";
                spdlog::error(
                    "DeviceTokenStore::migrate_from_sqlite: row {} legacy snapshot shows a "
                    "revocation Postgres does not have — refusing to stamp a backfill that "
                    "would silently discard it",
                    r.token_id);
                return false;
            }

            // Otherwise benign: either Postgres already has revoked=true (monotone — the
            // ordinary shape of post-migration progress) or both sides agree on `revoked` and
            // only `last_used_at` (bookkeeping, no auth-bypass risk either direction) differs.
            // The backfill never updates an existing row — Postgres's current value is kept.
            spdlog::warn(
                "DeviceTokenStore::migrate_from_sqlite: row {} already migrated with lifecycle "
                "drift since this legacy snapshot was taken (legacy revoked={} last_used_at={} "
                "vs current revoked={} last_used_at={}) — keeping the current Postgres value; "
                "this is expected on a replica whose legacy file predates that progress, not a "
                "conflict",
                r.token_id, r.revoked, r.last_used_at, stored.revoked, stored.last_used_at);
            continue;
        }

        pg::PgResult marker = pg::exec_params(
            conn,
            "INSERT INTO device_token_store.sqlite_backfill_source (fingerprint, completed_at) "
            "VALUES ($1, $2::bigint) ON CONFLICT (fingerprint) DO NOTHING",
            std::vector<std::string>{fingerprint, std::to_string(now_epoch())});
        if (marker.status() != PGRES_COMMAND_OK) {
            failure_detail = std::string("backfill marker stamp: ") + PQerrorMessage(conn);
            spdlog::error(
                "DeviceTokenStore::migrate_from_sqlite: failed to stamp backfill marker: {}",
                PQerrorMessage(conn));
            return false;
        }
        return true;
    });
    if (!ok) {
        const std::string offending =
            failure_detail.empty() ? std::string("unknown (see the specific-row error above)")
                                   : failure_detail;
        if (row_conflict_guidance) {
            spdlog::error(
                "DeviceTokenStore::migrate_from_sqlite: backfill transaction failed and was "
                "rolled back — device token data NOT migrated. Offending: {}. See the guidance "
                "above for which side to reconcile. The retained read-only legacy file is at "
                "{} (e.g. `sqlite3 {} \"SELECT * FROM device_auth_tokens WHERE "
                "token_id='<id>'\"` to inspect it) — compare it against Postgres's current row "
                "for the same id, then restart the server once resolved; the backfill marker "
                "was NOT stamped, so the next boot retries the whole backfill.",
                offending, legacy_db_path.string(), legacy_db_path.string());
        } else {
            spdlog::error(
                "DeviceTokenStore::migrate_from_sqlite: backfill transaction failed and was "
                "rolled back — device token data NOT migrated. Offending: {}. This is a "
                "database or legacy-file-read failure, not a row-content disagreement — "
                "resolve the underlying error above and restart the server; the backfill "
                "marker was NOT stamped, so the next boot retries the whole backfill.",
                offending);
        }
        return false;
    }
    spdlog::info("DeviceTokenStore::migrate_from_sqlite: backfill complete");
    return true;
}

// ── Operations ───────────────────────────────────────────────────────────────

std::expected<std::string, std::string>
DeviceTokenStore::create_token(const std::string& name, const std::string& principal_id,
                               const std::string& device_id, const std::string& definition_id,
                               int64_t expires_at) {
    if (!open_)
        return std::unexpected(std::string(kDeviceTokenDbErrorPrefix) + "database not open");
    if (principal_id.empty())
        return std::unexpected("principal_id cannot be empty");

    auto raw_result = generate_raw_device_token();
    if (!raw_result.has_value())
        return std::unexpected(raw_result.error());
    auto token_id_result = generate_token_id();
    if (!token_id_result.has_value())
        return std::unexpected(token_id_result.error());

    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected(std::string(kDeviceTokenDbErrorPrefix) +
                               "database unavailable — try again");

    auto raw = std::move(*raw_result);
    auto hashed = hash_token(raw);
    auto token_id = std::move(*token_id_result);
    auto now = now_epoch();

    // ON CONFLICT (token_id) DO NOTHING RETURNING: token_id is 128 bits of CSPRNG entropy, so a
    // collision here is not a realistic retry path, but the atomic-upsert shape is the
    // playbook-endorsed default (docs/postgres-store-playbook.md anti-patterns) over a bare
    // INSERT whose constraint-violation error text would otherwise be the only signal. A
    // token_hash collision (equally implausible) surfaces as a genuine UNIQUE-violation error
    // via the `res.status() != PGRES_TUPLES_OK` branch below.
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "INSERT INTO device_token_store.device_auth_tokens "
        "(token_id, token_hash, name, principal_id, device_id, definition_id, created_at, "
        " expires_at) "
        "VALUES ($1,$2,$3,$4,$5,$6,$7::bigint,$8::bigint) "
        "ON CONFLICT (token_id) DO NOTHING RETURNING token_id",
        std::vector<std::string>{token_id, hashed, sanitize_pg_text(name),
                                 sanitize_pg_text(principal_id), sanitize_pg_text(device_id),
                                 sanitize_pg_text(definition_id), std::to_string(now),
                                 std::to_string(expires_at)});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kDeviceTokenDbErrorPrefix) +
                               "create_token failed: " + PQerrorMessage(lease.get()));
    if (PQntuples(res.get()) == 0)
        return std::unexpected(std::string(kDeviceTokenDbErrorPrefix) +
                               "create_token: token_id collision — retry");

    spdlog::info("DeviceTokenStore: created token '{}' for principal '{}' (device='{}', "
                 "def='{}')",
                 name, principal_id, device_id, definition_id);
    return raw; // Return raw token (shown once to user)
}

std::expected<DeviceAuthToken, RejectedToken>
DeviceTokenStore::validate_token(const std::string& raw_token,
                                 const std::string& presenting_agent_id) {
    auto reject_input = []() {
        RejectedToken r;
        r.error = DeviceTokenValidateError::invalid_input;
        return r;
    };
    if (!open_ || raw_token.empty())
        return std::unexpected(reject_input());

    auto hashed = hash_token(raw_token);

    DeviceAuthToken t;
    RejectedToken rejected;
    bool accepted = false;
    bool internal_fault = false;

    // One transaction for the whole read+update, `SELECT ... FOR UPDATE`: the PG equivalent of
    // the pre-migration store's single-unique_lock discipline — a concurrent revoke_token on
    // this row blocks until this transaction commits, closing the TOCTOU window a
    // read-then-separately-write pair would leave open.
    bool ok = pool_.with_txn_for(kValidateTimeout, [&](PGconn* conn) -> bool {
        pg::PgResult res = pg::exec_params(
            conn,
            "SELECT token_id, name, principal_id, device_id, definition_id, created_at, "
            "expires_at, last_used_at, revoked FROM device_token_store.device_auth_tokens "
            "WHERE token_hash = $1 FOR UPDATE",
            std::vector<std::string>{hashed});
        if (res.status() != PGRES_TUPLES_OK) {
            // #1056: a lookup failure is a store-internal fault, not a clean miss. Labelling it
            // not_found would pollute the not-found signal and mislead forensics.
            internal_fault = true;
            spdlog::error("DeviceTokenStore::validate_token: lookup failed: {}",
                          PQerrorMessage(conn));
            return false;
        }
        if (PQntuples(res.get()) == 0) {
            rejected.error = DeviceTokenValidateError::not_found;
            return true;
        }

        t.token_id = text_col(res.get(), 0, 0);
        t.name = text_col(res.get(), 0, 1);
        t.principal_id = text_col(res.get(), 0, 2);
        t.device_id = text_col(res.get(), 0, 3);
        t.definition_id = text_col(res.get(), 0, 4);
        t.created_at = to_i64(PQgetvalue(res.get(), 0, 5));
        t.expires_at = to_i64(PQgetvalue(res.get(), 0, 6));
        t.last_used_at = to_i64(PQgetvalue(res.get(), 0, 7));
        t.revoked = to_bool(PQgetvalue(res.get(), 0, 8));

        // #1053: every rejection from this point on has row context that the W1.3 handler needs
        // to emit a complete audit row WITHOUT a second SELECT.
        auto reject_with_context = [&](DeviceTokenValidateError err, bool include_bound_device) {
            RejectedToken r;
            r.error = err;
            r.token_id = t.token_id;
            r.bound_principal_id = t.principal_id;
            if (include_bound_device)
                r.bound_device_id = t.device_id;
            return r;
        };

        if (t.revoked) {
            rejected = reject_with_context(DeviceTokenValidateError::revoked,
                                           /*include_bound_device=*/true);
            return true;
        }

        const auto now = now_epoch();
        if (t.expires_at > 0 && now > t.expires_at) {
            rejected = reject_with_context(DeviceTokenValidateError::expired,
                                           /*include_bound_device=*/true);
            return true;
        }

        // HIGH-1/HIGH-2 (PR #824 round 2): tokens stored with empty device_id are a back-door —
        // any presenter would pass the empty-comparison short-circuit. Refuse to validate them.
        if (t.device_id.empty()) {
            rejected = reject_with_context(DeviceTokenValidateError::unbound_legacy,
                                           /*include_bound_device=*/false);
            return true;
        }

        // Binding enforcement (#824): an empty presenting_agent_id is also a mismatch — the
        // stored device_id is guaranteed non-empty by the unbound_legacy check above.
        if (presenting_agent_id != t.device_id) {
            rejected = reject_with_context(DeviceTokenValidateError::binding_mismatch,
                                           /*include_bound_device=*/true);
            return true;
        }

        // Accepted. Bump last_used_at monotonically (GREATEST — mirrors touch semantics; never
        // regresses even under an out-of-order concurrent update) inside this same row-locked
        // transaction.
        pg::PgResult upd = pg::exec_params(
            conn,
            "UPDATE device_token_store.device_auth_tokens "
            "SET last_used_at = GREATEST(last_used_at, $1::bigint) WHERE token_hash = $2",
            std::vector<std::string>{std::to_string(now), hashed});
        if (upd.status() != PGRES_COMMAND_OK) {
            internal_fault = true;
            spdlog::error("DeviceTokenStore::validate_token: last_used_at update failed: {}",
                          PQerrorMessage(conn));
            return false;
        }
        t.last_used_at = std::max(t.last_used_at, now);
        accepted = true;
        return true;
    });

    if (!ok || internal_fault) {
        RejectedToken r;
        r.error = DeviceTokenValidateError::internal_error;
        return std::unexpected(r);
    }
    if (accepted)
        return t;
    return std::unexpected(rejected);
}

std::expected<std::vector<DeviceAuthToken>, std::string>
DeviceTokenStore::list_tokens(const std::string& principal_id) {
    if (!open_)
        return std::unexpected(std::string(kDeviceTokenDbErrorPrefix) + "database not open");

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected(std::string(kDeviceTokenDbErrorPrefix) +
                               "database unavailable — try again");

    std::string sql = "SELECT token_id, name, principal_id, device_id, definition_id, "
                      "created_at, expires_at, last_used_at, revoked "
                      "FROM device_token_store.device_auth_tokens";
    std::vector<std::string> params;
    if (!principal_id.empty()) {
        sql += " WHERE principal_id = $1";
        params.push_back(principal_id);
    }
    sql += " ORDER BY created_at DESC LIMIT $" + std::to_string(params.size() + 1);
    params.push_back(std::to_string(kListRowCap));

    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), params);
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kDeviceTokenDbErrorPrefix) +
                               "list_tokens failed: " + PQerrorMessage(lease.get()));

    const int rows = PQntuples(res.get());
    std::vector<DeviceAuthToken> out;
    out.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i) {
        DeviceAuthToken t;
        t.token_id = text_col(res.get(), i, 0);
        t.name = text_col(res.get(), i, 1);
        t.principal_id = text_col(res.get(), i, 2);
        t.device_id = text_col(res.get(), i, 3);
        t.definition_id = text_col(res.get(), i, 4);
        t.created_at = to_i64(PQgetvalue(res.get(), i, 5));
        t.expires_at = to_i64(PQgetvalue(res.get(), i, 6));
        t.last_used_at = to_i64(PQgetvalue(res.get(), i, 7));
        t.revoked = to_bool(PQgetvalue(res.get(), i, 8));
        out.push_back(std::move(t));
    }
    return out;
}

std::expected<void, std::string> DeviceTokenStore::revoke_token(const std::string& token_id) {
    if (!open_)
        return std::unexpected(std::string(kDeviceTokenDbErrorPrefix) + "database not open");

    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected(std::string(kDeviceTokenDbErrorPrefix) +
                               "database unavailable — try again");

    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE device_token_store.device_auth_tokens SET revoked = true "
        "WHERE token_id = $1 RETURNING token_id",
        std::vector<std::string>{token_id});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kDeviceTokenDbErrorPrefix) +
                               "revoke_token failed: " + PQerrorMessage(lease.get()));
    if (PQntuples(res.get()) == 0)
        return std::unexpected("not_found: device token '" + token_id + "'");

    spdlog::info("DeviceTokenStore: revoked token '{}'", token_id);
    return {};
}

std::expected<std::int64_t, std::string>
DeviceTokenStore::revoke_by_principal(const std::string& principal_id) {
    // Empty principal_id is a no-op: a buggy caller passing the empty default must not be able
    // to revoke the entire table or match historical rows that lack a principal binding. See
    // header doc.
    if (!open_)
        return std::unexpected(std::string(kDeviceTokenDbErrorPrefix) + "database not open");
    if (principal_id.empty())
        return std::int64_t{0};

    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected(std::string(kDeviceTokenDbErrorPrefix) +
                               "database unavailable — try again");

    // RETURNING avoids the FULLMUTEX sqlite3_changes() race (#1033) — moot on Postgres, but
    // RETURNING + PQntuples() is the shared idiom every migrated store's mutate-and-return path
    // uses (docs/postgres-store-playbook.md).
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE device_token_store.device_auth_tokens SET revoked = true "
        "WHERE principal_id = $1 AND revoked = false RETURNING token_id",
        std::vector<std::string>{principal_id});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kDeviceTokenDbErrorPrefix) +
                               "revoke_by_principal failed: " + PQerrorMessage(lease.get()));

    const std::int64_t revoked = PQntuples(res.get());
    if (revoked > 0)
        spdlog::info("DeviceTokenStore: revoked {} device token(s) for principal '{}'", revoked,
                     principal_id);
    return revoked;
}

} // namespace yuzu::server
