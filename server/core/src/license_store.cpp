#include "license_store.hpp"

#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "sqlite_raii.hpp"
#include "utf8_sanitize.hpp"

#include <nlohmann/json.hpp>

#include <libpq-fe.h>
#include <openssl/evp.h>
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
#include <random>
#include <string_view>

namespace yuzu::server {

namespace {

constexpr const char* kStoreName = "license_store";

// Not a hot path — operator-driven (activate/remove/acknowledge) or periodic-background
// (validate), same budget class as DeploymentStore (docs/adr/0043-...md).
constexpr std::chrono::milliseconds kReadTimeout{2000};
constexpr std::chrono::milliseconds kWriteTimeout{4000};
// validate()'s pool-ACQUIRE-wait budget only (with_txn_for, per pg_pool.hpp) — NOT a bound on
// the transaction body's own execution time, which is governed solely by the pool's
// per-connection statement_timeout GUC (playbook: "Pool connection setup†" quick fact). Set
// generously since validate() is a periodic background pass, not a request/response path.
constexpr std::chrono::milliseconds kValidateTimeout{10000};

// gov UP-5 precedent (every migrated store on this ladder): bounded materialization regardless
// of table growth — an operator convenience list, not a paged feed.
constexpr int kListRowCap = 10000;

// Sentinel fingerprint for "this replica's legacy file is absent, or present but holds neither
// the licenses nor license_alerts table" — mirrors DeploymentStore's kSourcelessFingerprint.
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

// Applied to every free-text column reaching Postgres (organization/edition/features_json),
// mirroring discovery_store.cpp's sanitize_pg_text — a bad byte at-rest in a legacy license.db
// must not brick the mandatory backfill, and an operator-supplied organization/edition string
// over REST is equally untrusted.
std::string sanitize_pg_text(std::string_view s) {
    std::string out = sanitize_utf8_strict(s);
    std::size_t pos = 0;
    while ((pos = out.find('\0', pos)) != std::string::npos) {
        out.replace(pos, 1, "\xEF\xBF\xBD");
        pos += 3;
    }
    return out;
}

// active=0 (initial); {expired, exceeded, invalid}=1 (terminal tier — validate() never revisits
// a license once it leaves 'active', a pre-existing behavior preserved unchanged by this
// migration); unrecognised=2 (maximal — used both as the legacy-status validation gate and as
// the direction check's "always ahead" sentinel, matching DeploymentStore's lifecycle_rank
// shape). See ADR-0048 "licenses conflict handling" for how this feeds migrate_from_sqlite.
int license_status_rank(std::string_view status) {
    if (status == "active")
        return 0;
    if (status == "expired" || status == "exceeded" || status == "invalid")
        return 1;
    return 2;
}

bool is_valid_alert_type(std::string_view t) {
    return t == "expiry_warning" || t == "seat_limit_warning" || t == "expired" ||
           t == "exceeded";
}

// `id` (generate_id(), 32 lowercase hex chars) and `license_key_hash` (hash_key(), 64
// lowercase hex chars) are both deterministically hex-formatted by every write path this store
// owns. Validated here, before either can reach Postgres, for the same reason status/alert_type
// are (gov security-guardian MEDIUM): an invalid-UTF-8 byte in a hand-edited/corrupted legacy
// value would otherwise reach Postgres raw (sanitize_pg_text is applied to the OTHER free-text
// columns but not these two) and fail the INSERT with an opaque server-side encoding error —
// which, unlike a clear "unrecognised value" rejection here, retries identically on every future
// boot against the same corrupt file, permanently bricking the mandatory backfill.
bool is_valid_lowercase_hex(std::string_view s, std::size_t expected_len) {
    if (s.size() != expected_len)
        return false;
    return std::all_of(s.begin(), s.end(), [](char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    });
}

// ── Backfill fingerprinting ──────────────────────────────────────────────────

// Internal-only row shapes carrying every column relevant to backfill — including
// license_key_hash and activated_at, which the public License struct deliberately omits (the
// hash is never re-exposed; activated_at is ORDER-BY-only in every public read).
struct LegacyLicenseRow {
    std::string id;
    std::string license_key_hash;
    std::string organization;
    std::int64_t seat_count{0};
    std::int64_t issued_at{0};
    std::int64_t expires_at{0};
    std::string edition;
    std::string features_json;
    std::string status;
    std::int64_t activated_at{0};
};

struct LegacyAlertRow {
    std::string license_id;
    std::string alert_type;
    std::string message;
    std::int64_t triggered_at{0};
    bool acknowledged{false};
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

// Canonicalizes BOTH legacy tables into one stable, order-independent, injective fingerprint
// input. Two extensions beyond DeploymentStore's single-table version (ADR-0048): each row is
// still length-prefixed field-by-field, but each TABLE'S SECTION is additionally prefixed with
// its own row count — without that, a 10-field license row's encoding could be byte-identical
// to two consecutive 5-field alert rows' concatenated encoding, making the two-section sequence
// itself non-injective even though each row within a section is.
std::string canonicalize_legacy(const std::vector<LegacyLicenseRow>& licenses,
                                const std::vector<LegacyAlertRow>& alerts) {
    std::vector<std::string> lic_rows;
    lic_rows.reserve(licenses.size());
    for (const auto& l : licenses) {
        std::string r;
        append_field(r, l.id);
        append_field(r, l.license_key_hash);
        append_field(r, l.organization);
        append_field(r, std::to_string(l.seat_count));
        append_field(r, std::to_string(l.issued_at));
        append_field(r, std::to_string(l.expires_at));
        append_field(r, l.edition);
        append_field(r, l.features_json);
        append_field(r, l.status);
        append_field(r, std::to_string(l.activated_at));
        lic_rows.push_back(std::move(r));
    }
    std::sort(lic_rows.begin(), lic_rows.end());

    std::vector<std::string> alert_rows;
    alert_rows.reserve(alerts.size());
    for (const auto& a : alerts) {
        std::string r;
        append_field(r, a.license_id);
        append_field(r, a.alert_type);
        append_field(r, a.message);
        append_field(r, std::to_string(a.triggered_at));
        append_field(r, a.acknowledged ? "1" : "0");
        alert_rows.push_back(std::move(r));
    }
    std::sort(alert_rows.begin(), alert_rows.end());

    std::string canon = "license-legacy-fingerprint-v1\n";
    append_field(canon, std::to_string(lic_rows.size()));
    for (const auto& r : lic_rows)
        canon += r;
    append_field(canon, std::to_string(alert_rows.size()));
    for (const auto& r : alert_rows)
        canon += r;
    return canon;
}

// ── Migration DDL ────────────────────────────────────────────────────────────

const std::vector<pg::PgMigration>& migrations() {
    // Unqualified DDL: the runner sets search_path to the store schema for the migration txn.
    // Runtime statements below schema-qualify explicitly.
    static const std::vector<pg::PgMigration> kMigrations = {
        {1,
         "CREATE TABLE licenses ("
         "  id                TEXT PRIMARY KEY,"
         "  license_key_hash  TEXT NOT NULL UNIQUE,"
         "  organization      TEXT NOT NULL DEFAULT '',"
         "  seat_count        BIGINT NOT NULL DEFAULT 0,"
         "  issued_at         BIGINT NOT NULL DEFAULT 0,"
         "  expires_at        BIGINT NOT NULL DEFAULT 0,"
         "  edition           TEXT NOT NULL DEFAULT 'community',"
         "  features_json     TEXT NOT NULL DEFAULT '[]',"
         "  status            TEXT NOT NULL DEFAULT 'active',"
         "  activated_at      BIGINT NOT NULL DEFAULT 0);"
         "CREATE INDEX idx_license_status ON licenses(status);"
         "CREATE TABLE license_alerts ("
         "  id              BIGSERIAL PRIMARY KEY,"
         "  license_id      TEXT NOT NULL,"
         "  alert_type      TEXT NOT NULL,"
         "  message         TEXT NOT NULL DEFAULT '',"
         "  triggered_at    BIGINT NOT NULL DEFAULT 0,"
         "  acknowledged    BOOLEAN NOT NULL DEFAULT FALSE,"
         // ADR-0048: dedups a backfill re-encountering an overlapping-but-differently-
         // fingerprinted legacy snapshot (license_alerts.id is always freshly minted by
         // Postgres, so it can never be the ON CONFLICT target the way licenses.id is).
         "  UNIQUE (license_id, alert_type, triggered_at));"
         "CREATE INDEX idx_license_alert_lic ON license_alerts(license_id);"
         "CREATE INDEX idx_license_alert_ack ON license_alerts(acknowledged, triggered_at);"
         // ADR-0009 backfill idempotency — content-fingerprinted, not a single fleet-wide
         // completion flag (see migrate_from_sqlite's doc comment).
         "CREATE TABLE sqlite_backfill_source ("
         "  fingerprint  TEXT PRIMARY KEY,"
         "  completed_at BIGINT NOT NULL);"},
    };
    return kMigrations;
}

// ── Row readers ──────────────────────────────────────────────────────────────

constexpr const char* kLicensePublicCols =
    "id, organization, seat_count, issued_at, expires_at, edition, features_json, status";
constexpr const char* kLicenseBackfillCols =
    "id, license_key_hash, organization, seat_count, issued_at, expires_at, edition, "
    "features_json, status, activated_at";

License read_license_public(PGresult* res, int row) {
    License lic;
    int c = 0;
    lic.id = text_col(res, row, c++);
    lic.organization = text_col(res, row, c++);
    lic.seat_count = to_i64(PQgetvalue(res, row, c++));
    lic.issued_at = to_i64(PQgetvalue(res, row, c++));
    lic.expires_at = to_i64(PQgetvalue(res, row, c++));
    lic.edition = text_col(res, row, c++);
    lic.features_json = text_col(res, row, c++);
    lic.status = text_col(res, row, c++);
    return lic;
}

LegacyLicenseRow read_backfill_row(PGresult* res, int row) {
    LegacyLicenseRow l;
    int c = 0;
    l.id = text_col(res, row, c++);
    l.license_key_hash = text_col(res, row, c++);
    l.organization = text_col(res, row, c++);
    l.seat_count = to_i64(PQgetvalue(res, row, c++));
    l.issued_at = to_i64(PQgetvalue(res, row, c++));
    l.expires_at = to_i64(PQgetvalue(res, row, c++));
    l.edition = text_col(res, row, c++);
    l.features_json = text_col(res, row, c++);
    l.status = text_col(res, row, c++);
    l.activated_at = to_i64(PQgetvalue(res, row, c++));
    return l;
}

// ── Alerts (shared by validate() and the legacy read path) ─────────────────

// Caller must already be inside an active transaction (`conn` is a transaction-pinned
// connection — never a plain pool lease; nesting a second acquire here inside validate()'s
// with_txn would deadlock a size-1 pool). Returns false only on a genuine DB error; a skip due
// to the 24h dedup window is success (true), matching the pre-migration store's silent-skip
// semantics exactly.
bool add_alert(PGconn* conn, const std::string& license_id, const std::string& alert_type,
               const std::string& message) {
    const std::int64_t now = now_epoch();

    pg::PgResult chk = pg::exec_params(
        conn,
        "SELECT id FROM license_store.license_alerts "
        "WHERE license_id = $1 AND alert_type = $2 AND triggered_at > $3::bigint LIMIT 1",
        std::vector<std::string>{license_id, alert_type, std::to_string(now - 86400)});
    if (chk.status() != PGRES_TUPLES_OK) {
        spdlog::error("LicenseStore::add_alert: dedup check failed for '{}'/{}: {}", license_id,
                      alert_type, PQerrorMessage(conn));
        return false;
    }
    if (PQntuples(chk.get()) > 0)
        return true; // already alerted recently — same silent-skip as the original

    // ON CONFLICT DO NOTHING: the UNIQUE(license_id, alert_type, triggered_at) constraint
    // exists for backfill dedup (ADR-0048), but a same-second race between two concurrent
    // validate() calls could in principle hit it too — treated as a benign no-op either way.
    pg::PgResult res = pg::exec_params(
        conn,
        "INSERT INTO license_store.license_alerts "
        "(license_id, alert_type, message, triggered_at) VALUES ($1,$2,$3,$4::bigint) "
        "ON CONFLICT (license_id, alert_type, triggered_at) DO NOTHING",
        std::vector<std::string>{license_id, alert_type, sanitize_pg_text(message),
                                 std::to_string(now)});
    if (res.status() != PGRES_COMMAND_OK) {
        spdlog::error("LicenseStore::add_alert: insert failed for '{}'/{}: {}", license_id,
                      alert_type, PQerrorMessage(conn));
        return false;
    }
    spdlog::info("LicenseStore: alert [{}] for license '{}': {}", alert_type, license_id,
                 message);
    return true;
}

// ── License-key hashing (kept cross-platform-identical to the pre-migration store) ─────────

std::string hash_key(const std::string& raw) {
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

// 32 lowercase-hex-char id (16 random bytes via mt19937_64) — the ORIGINAL pre-migration
// format, deliberately kept (not DeploymentStore's 16-hex/8-byte format): ADR-0048 "pre-
// migration ID contracts are kept exactly", which is about preserving THIS store's existing
// format, not converging every migrated store onto the same one.
std::string generate_id() {
    static thread_local std::mt19937_64 rng{std::random_device{}()};
    static constexpr char hex_chars[] = "0123456789abcdef";
    std::string id;
    id.reserve(32);
    std::uniform_int_distribution<int> dist(0, 15);
    for (int i = 0; i < 32; ++i)
        id += hex_chars[dist(rng)];
    return id;
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

LicenseStore::LicenseStore(pg::PgPool& pool) : pool_(pool) {
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error("LicenseStore: no database connection at construction ({}) — license "
                      "persistence disabled",
                      pool_.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error("LicenseStore: schema migration failed — license persistence disabled");
        return;
    }
    open_ = true;
}

// ── Backfill (ADR-0009/0048) ─────────────────────────────────────────────────
//
// Content-fingerprinted, not a single fleet-wide completion flag — mirrors DeploymentStore
// (docs/adr/0043-...md) most closely among the already-migrated Wave 2 stores: a client-
// generated surrogate `licenses.id`, no small-human-chosen-identifier collision risk RbacStore
// has to guard against. Two extensions beyond that single-table reference, both driven by this
// store having TWO legacy tables (ADR-0048 documents the reasoning in full):
//
//   1. Half-schema detection: the shipped pre-migration binary always creates `licenses` and
//      `license_alerts` together in one migration step, so a legacy file holding exactly one of
//      the two is never a real fresh-install/upgrade artifact — it fails the whole backfill
//      closed, the same bias as an unrecognised enum value.
//   2. The fingerprint canonicalizes BOTH tables' rows with an explicit row-count prefix ahead
//      of each table's section (see canonicalize_legacy above) — a per-field length prefix
//      alone makes one row injective but not the SEQUENCE of two variable-length sections.
//
// Per-row conflict handling on `licenses.id` (`ON CONFLICT (id) DO NOTHING`) partitions the
// compared columns into IDENTITY (license_key_hash, organization, seat_count, issued_at,
// expires_at, edition, features_json — write-once at INSERT, no other method mutates them) and
// LIFECYCLE
// (status, activated_at — see ADR-0048 for why activated_at is classified LIFECYCLE despite
// being write-once in the CURRENT code). An identity mismatch fails the boot closed. A
// lifecycle-only difference is resolved by status-rank direction, exactly mirroring
// DeploymentStore's lifecycle_rank shape: Postgres strictly ahead, or a same-status tie, is a
// benign no-op (WARNING-logged); the legacy row strictly ahead, or a same-rank pair disagreeing
// on WHICH terminal status, fails the boot closed (the ADR-0009 rollback-then-roll-forward
// shape).
//
// `license_alerts` gets a deliberately SIMPLER treatment (ADR-0048): it has no legacy-preserved
// identity column to conflict on (id is always freshly minted by Postgres), so a plain per-row
// INSERT would duplicate an alert already migrated by an overlapping-but-differently-
// fingerprinted legacy snapshot. The UNIQUE(license_id, alert_type, triggered_at) constraint
// plus ON CONFLICT DO NOTHING on the insert closes this without needing licenses' full
// IDENTITY/LIFECYCLE machinery — alerts are derived/notification records regenerable by
// validate(), not independent operator-authored entitlement state.
//
// Legacy files are read READ-ONLY and never deleted/moved — retained for the ADR-0009
// one-release rollback window.

bool LicenseStore::migrate_from_sqlite(const std::filesystem::path& legacy_db_path) {
    if (!open_)
        return false;

    std::error_code ec;
    const bool legacy_exists = std::filesystem::exists(legacy_db_path, ec);
    if (ec) {
        spdlog::error("LicenseStore::migrate_from_sqlite: cannot stat legacy path {}: {}",
                      legacy_db_path.string(), ec.message());
        return false;
    }

    std::string fingerprint;
    std::vector<LegacyLicenseRow> legacy_licenses;
    std::vector<LegacyAlertRow> legacy_alerts;

    if (!legacy_exists) {
        fingerprint = kSourcelessFingerprint;
    } else {
        // SqliteDb/SqliteStmt (gov cpp-safety): close/finalize on every path, including an
        // exception thrown mid read-loop.
        SqliteDb legacy;
        if (sqlite3_open_v2(legacy_db_path.string().c_str(), legacy.addr(), SQLITE_OPEN_READONLY,
                            nullptr) != SQLITE_OK) {
            spdlog::error("LicenseStore::migrate_from_sqlite: failed to open legacy {}: {}",
                          legacy_db_path.string(),
                          legacy ? sqlite3_errmsg(legacy.get()) : "open failed");
            return false;
        }

        auto licenses_probe = sqlite_table_exists(legacy.get(), "licenses");
        auto alerts_probe = sqlite_table_exists(legacy.get(), "license_alerts");
        if (!licenses_probe || !alerts_probe) {
            spdlog::error("LicenseStore::migrate_from_sqlite: schema probe failed on legacy {}: "
                          "{}",
                          legacy_db_path.string(), sqlite3_errmsg(legacy.get()));
            return false;
        }
        const bool has_licenses = *licenses_probe;
        const bool has_alerts = *alerts_probe;

        if (!has_licenses && !has_alerts) {
            // Present-but-schema-less file — same "nothing to protect" class as no file at all.
            fingerprint = kSourcelessFingerprint;
        } else if (has_licenses != has_alerts) {
            // ADR-0048: no version of the shipped binary can produce this shape (both tables
            // are always created together) — treat as corrupt/hand-edited, fail closed.
            spdlog::error(
                "LicenseStore::migrate_from_sqlite: legacy {} has exactly one of "
                "{{licenses, license_alerts}} present (licenses={}, license_alerts={}) — "
                "refusing (fail-closed): the shipped binary always creates both together, this "
                "looks like a corrupt or hand-edited file",
                legacy_db_path.string(), has_licenses, has_alerts);
            return false;
        } else {
            {
                SqliteStmt s;
                const char* sql =
                    "SELECT id, license_key_hash, organization, seat_count, issued_at, "
                    "expires_at, edition, features_json, status, activated_at FROM licenses "
                    // gov Gate 8 architect (SHOULD): PK order, not a content-dependent column —
                    // canonicalize_legacy() re-sorts before fingerprinting regardless (verified
                    // std::sort call sites), so this can't change any fingerprint, and PK order
                    // means two replicas scanning the same id set always acquire Postgres row
                    // locks in the SAME order during backfill INSERT, closing the deadlock class
                    // this store's own gov Gate 4 unhappy-path UP-3 flagged.
                    "ORDER BY id ASC;";
                if (sqlite3_prepare_v2(legacy.get(), sql, -1, s.addr(), nullptr) != SQLITE_OK) {
                    spdlog::error(
                        "LicenseStore::migrate_from_sqlite: legacy licenses query failed: {}",
                        sqlite3_errmsg(legacy.get()));
                    return false;
                }
                int step_rc = SQLITE_OK;
                while ((step_rc = sqlite3_step(s.get())) == SQLITE_ROW) {
                    LegacyLicenseRow l;
                    l.id = safe(reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 0)));
                    l.license_key_hash =
                        safe(reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 1)));
                    l.organization =
                        safe(reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 2)));
                    l.seat_count = sqlite3_column_int64(s.get(), 3);
                    l.issued_at = sqlite3_column_int64(s.get(), 4);
                    l.expires_at = sqlite3_column_int64(s.get(), 5);
                    l.edition =
                        safe(reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 6)));
                    l.features_json =
                        safe(reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 7)));
                    l.status =
                        safe(reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 8)));
                    l.activated_at = sqlite3_column_int64(s.get(), 9);
                    // gov docs-writer precedent (DeploymentStore hardening round 5): a legacy
                    // file's status column is read raw from untrusted SQLite with no
                    // validation elsewhere — validate it here, before it can ever reach
                    // Postgres, using the same maximal-fallback rank sentinel as the direction
                    // check below.
                    if (license_status_rank(l.status) == 2) {
                        spdlog::error(
                            "LicenseStore::migrate_from_sqlite: legacy licenses row {} has an "
                            "unrecognised status '{}' — refusing to stamp a backfill "
                            "containing it",
                            l.id, l.status);
                        return false;
                    }
                    // gov security-guardian MEDIUM: id/license_key_hash are read raw and
                    // skipped sanitize_pg_text (unlike organization/edition/features_json) —
                    // validate their hex format before either can reach Postgres.
                    if (!is_valid_lowercase_hex(l.id, 32)) {
                        spdlog::error(
                            "LicenseStore::migrate_from_sqlite: legacy licenses row has an "
                            "invalid id '{}' (expected 32 lowercase hex chars) — refusing to "
                            "stamp a backfill containing it",
                            l.id);
                        return false;
                    }
                    if (!is_valid_lowercase_hex(l.license_key_hash, 64)) {
                        spdlog::error(
                            "LicenseStore::migrate_from_sqlite: legacy licenses row {} has an "
                            "invalid license_key_hash (expected 64 lowercase hex chars) — "
                            "refusing to stamp a backfill containing it",
                            l.id);
                        return false;
                    }
                    legacy_licenses.push_back(std::move(l));
                }
                if (step_rc != SQLITE_DONE) {
                    spdlog::error(
                        "LicenseStore::migrate_from_sqlite: legacy licenses scan aborted "
                        "mid-read (rc={} {}): refusing to stamp a partial backfill",
                        step_rc, sqlite3_errmsg(legacy.get()));
                    return false;
                }
            }
            {
                SqliteStmt s;
                const char* sql =
                    "SELECT license_id, alert_type, message, triggered_at, acknowledged FROM "
                    // gov Gate 8 architect (SHOULD): PK order — same rationale as the licenses
                    // scan above. `id` need not be in the SELECT list to ORDER BY it.
                    "license_alerts ORDER BY id ASC;";
                if (sqlite3_prepare_v2(legacy.get(), sql, -1, s.addr(), nullptr) != SQLITE_OK) {
                    spdlog::error(
                        "LicenseStore::migrate_from_sqlite: legacy license_alerts query "
                        "failed: {}",
                        sqlite3_errmsg(legacy.get()));
                    return false;
                }
                int step_rc = SQLITE_OK;
                while ((step_rc = sqlite3_step(s.get())) == SQLITE_ROW) {
                    LegacyAlertRow a;
                    a.license_id =
                        safe(reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 0)));
                    a.alert_type =
                        safe(reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 1)));
                    a.message =
                        safe(reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 2)));
                    a.triggered_at = sqlite3_column_int64(s.get(), 3);
                    a.acknowledged = sqlite3_column_int64(s.get(), 4) != 0;
                    if (!is_valid_alert_type(a.alert_type)) {
                        spdlog::error(
                            "LicenseStore::migrate_from_sqlite: legacy license_alerts row for "
                            "license '{}' has an unrecognised alert_type '{}' — refusing to "
                            "stamp a backfill containing it",
                            a.license_id, a.alert_type);
                        return false;
                    }
                    legacy_alerts.push_back(std::move(a));
                }
                if (step_rc != SQLITE_DONE) {
                    spdlog::error(
                        "LicenseStore::migrate_from_sqlite: legacy license_alerts scan "
                        "aborted mid-read (rc={} {}): refusing to stamp a partial backfill",
                        step_rc, sqlite3_errmsg(legacy.get()));
                    return false;
                }
            }

            if (legacy_licenses.empty() && legacy_alerts.empty()) {
                fingerprint = kSourcelessFingerprint;
            } else {
                fingerprint = sha256_hex(canonicalize_legacy(legacy_licenses, legacy_alerts));
                if (fingerprint.empty()) {
                    spdlog::error(
                        "LicenseStore::migrate_from_sqlite: SHA-256 hashing failed for legacy "
                        "content at {} — refusing (fail-closed)",
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
            spdlog::error("LicenseStore::migrate_from_sqlite: no database connection");
            return false;
        }
        pg::PgResult marker = pg::exec_params(
            lease.get(),
            "SELECT 1 FROM license_store.sqlite_backfill_source WHERE fingerprint=$1",
            std::vector<std::string>{fingerprint});
        if (marker.status() != PGRES_TUPLES_OK) {
            spdlog::error("LicenseStore::migrate_from_sqlite: backfill-marker check failed: {}",
                          PQerrorMessage(lease.get()));
            return false;
        }
        if (PQntuples(marker.get()) > 0) {
            spdlog::debug(
                "LicenseStore::migrate_from_sqlite: fingerprint already processed, skipping");
            return true;
        }
    }

    if (fingerprint == kSourcelessFingerprint) {
        auto lease = pool_.acquire();
        if (!lease) {
            spdlog::error("LicenseStore::migrate_from_sqlite: no connection to stamp marker");
            return false;
        }
        pg::PgResult r = pg::exec_params(
            lease.get(),
            "INSERT INTO license_store.sqlite_backfill_source (fingerprint, completed_at) "
            "VALUES ($1, $2::bigint) ON CONFLICT (fingerprint) DO NOTHING",
            std::vector<std::string>{fingerprint, std::to_string(now_epoch())});
        if (r.status() != PGRES_COMMAND_OK) {
            spdlog::error("LicenseStore::migrate_from_sqlite: failed to stamp marker: {}",
                          PQerrorMessage(lease.get()));
            return false;
        }
        spdlog::info("LicenseStore::migrate_from_sqlite: no legacy license data at {} — "
                     "nothing to backfill",
                     legacy_db_path.string());
        return true;
    }

    spdlog::info(
        "LicenseStore::migrate_from_sqlite: backfilling {} license(s) and {} alert(s) from {}",
        legacy_licenses.size(), legacy_alerts.size(), legacy_db_path.string());

    std::string failure_detail;
    bool row_conflict_guidance = false;
    bool ok = pool_.with_txn([&](PGconn* conn) -> bool {
        for (const auto& l : legacy_licenses) {
            pg::PgResult res = pg::exec_params(
                conn,
                "INSERT INTO license_store.licenses "
                "(id, license_key_hash, organization, seat_count, issued_at, expires_at, "
                " edition, features_json, status, activated_at) "
                "VALUES ($1,$2,$3,$4::bigint,$5::bigint,$6::bigint,$7,$8,$9,$10::bigint) "
                "ON CONFLICT (id) DO NOTHING RETURNING id",
                std::vector<std::string>{
                    l.id, l.license_key_hash, sanitize_pg_text(l.organization),
                    std::to_string(l.seat_count), std::to_string(l.issued_at),
                    std::to_string(l.expires_at), sanitize_pg_text(l.edition),
                    sanitize_pg_text(l.features_json), l.status,
                    std::to_string(l.activated_at)});
            if (res.status() != PGRES_TUPLES_OK) {
                failure_detail =
                    std::string("legacy licenses row id='") + l.id + "': " + PQerrorMessage(conn);
                spdlog::error("LicenseStore::migrate_from_sqlite: insert of {} failed: {}", l.id,
                              PQerrorMessage(conn));
                return false;
            }
            if (PQntuples(res.get()) > 0)
                continue; // inserted cleanly — no conflict

            // Conflict: a row with this id already exists. `ON CONFLICT` matches on id ALONE —
            // read the existing row back and compare in two classes (see the file header).
            std::string existing_sql = std::string("SELECT ") + kLicenseBackfillCols +
                                       " FROM license_store.licenses WHERE id=$1";
            pg::PgResult existing =
                pg::exec_params(conn, existing_sql.c_str(), std::vector<std::string>{l.id});
            if (existing.status() != PGRES_TUPLES_OK || PQntuples(existing.get()) == 0) {
                failure_detail = std::string("legacy licenses row id='") + l.id +
                                 "': conflicted on insert but the existing row could not be "
                                 "read back for comparison: " +
                                 PQerrorMessage(conn);
                spdlog::error(
                    "LicenseStore::migrate_from_sqlite: row {} conflicted but the existing "
                    "row read-back failed: {}",
                    l.id, PQerrorMessage(conn));
                return false;
            }
            const LegacyLicenseRow stored = read_backfill_row(existing.get(), 0);
            // seat_count is IDENTITY, not LIFECYCLE: activate_license sets it once at INSERT
            // and no other method (remove_license/validate/acknowledge_alert) ever mutates it
            // — same write-once criterion as organization/edition/features_json. Omitting it
            // here would let a legacy row differing ONLY in seat_count be misclassified as
            // "identical content" by lifecycle_matches below and silently discarded (gov
            // security-guardian HIGH finding).
            const bool identity_matches =
                stored.license_key_hash == l.license_key_hash &&
                stored.organization == sanitize_pg_text(l.organization) &&
                stored.seat_count == l.seat_count && stored.issued_at == l.issued_at &&
                stored.expires_at == l.expires_at &&
                stored.edition == sanitize_pg_text(l.edition) &&
                stored.features_json == sanitize_pg_text(l.features_json);
            if (!identity_matches) {
                row_conflict_guidance = true;
                failure_detail =
                    std::string("legacy licenses row id='") + l.id +
                    "' already exists with DIFFERENT identity (stored: organization='" +
                    stored.organization + "' edition='" + stored.edition +
                    "' seat_count=" + std::to_string(stored.seat_count) + " expires_at=" +
                    std::to_string(stored.expires_at) + "; legacy: organization='" +
                    l.organization + "' edition='" + l.edition +
                    "' seat_count=" + std::to_string(l.seat_count) +
                    " expires_at=" + std::to_string(l.expires_at) +
                    ") — refusing to silently discard it";
                spdlog::error(
                    "LicenseStore::migrate_from_sqlite: row {} conflicts with different "
                    "IDENTITY — refusing to stamp a backfill that would silently discard it",
                    l.id);
                return false;
            }
            const bool lifecycle_matches =
                stored.status == l.status && stored.activated_at == l.activated_at;
            if (lifecycle_matches) {
                spdlog::debug(
                    "LicenseStore::migrate_from_sqlite: row {} already present with identical "
                    "content, skipping (benign no-op)",
                    l.id);
                continue;
            }
            const int legacy_rank = license_status_rank(l.status);
            const int stored_rank = license_status_rank(stored.status);
            const bool legacy_ahead = legacy_rank > stored_rank;
            const bool terminal_disagreement =
                legacy_rank == stored_rank && legacy_rank == 1 && l.status != stored.status;
            if (legacy_ahead || terminal_disagreement) {
                row_conflict_guidance = true;
                failure_detail =
                    std::string("legacy licenses row id='") + l.id + "' lifecycle " +
                    (legacy_ahead ? "shows MORE progress than"
                                  : "reports a DIFFERENT terminal outcome than") +
                    " Postgres's current value (stored: status='" + stored.status +
                    "' activated_at=" + std::to_string(stored.activated_at) +
                    "; legacy: status='" + l.status +
                    "' activated_at=" + std::to_string(l.activated_at) +
                    ") — likely a rollback-then-roll-forward cycle (ADR-0009) progressed this "
                    "license while running the pre-migration binary; refusing to silently "
                    "discard that evidence. Postgres's value is the STALE or CONTRADICTED "
                    "side here — do NOT edit the retained legacy file to make it match "
                    "Postgres, that would destroy the only record of what the pre-migration "
                    "binary actually did. Reconcile Postgres to the correct outcome or, to "
                    "explicitly accept the loss, move the whole legacy file aside so this "
                    "backfill is never retried against it, then restart";
                spdlog::error(
                    "LicenseStore::migrate_from_sqlite: row {} legacy snapshot conflicts with "
                    "the current Postgres value ({}) — refusing to stamp a backfill that "
                    "would silently discard it",
                    l.id, legacy_ahead ? "more progress" : "different terminal outcome");
                return false;
            }
            spdlog::warn(
                "LicenseStore::migrate_from_sqlite: row {} already migrated with lifecycle "
                "progress since this legacy snapshot was taken (legacy status='{}' "
                "activated_at={} vs current status='{}' activated_at={}) — keeping the "
                "current Postgres value; this is expected on a replica whose legacy file "
                "predates that progress, not a conflict",
                l.id, l.status, l.activated_at, stored.status, stored.activated_at);
            continue;
        }

        for (const auto& a : legacy_alerts) {
            // gov happy-path (Gate 4): license_id is read raw from the untrusted legacy file,
            // same brick-the-backfill exposure sanitize_pg_text closes elsewhere — but it is a
            // documented SOFT reference (no FK, an orphaned alert is legitimate), so it is
            // sanitized here rather than hex-validated like licenses.id/license_key_hash: a
            // format check would incorrectly reject a legitimately-diverged reference.
            //
            // ON CONFLICT ... DO UPDATE (gov Gate 4 unhappy-path UP-2, HIGH): a plain DO NOTHING
            // left `acknowledged` untouched on conflict, so a second replica backfilling from a
            // legacy file that differs only in `acknowledged` would silently discard an
            // operator's real dismissal if it lost the race to be first. `acknowledged` is
            // write-once monotonic (acknowledge_alert() only ever sets it true, never back to
            // false — see that method), so OR-ing the two sides is a safe, order-independent
            // merge: the row ends up acknowledged iff either side ever recorded that.
            pg::PgResult res = pg::exec_params(
                conn,
                "INSERT INTO license_store.license_alerts "
                "(license_id, alert_type, message, triggered_at, acknowledged) "
                "VALUES ($1,$2,$3,$4::bigint,$5) "
                "ON CONFLICT (license_id, alert_type, triggered_at) DO UPDATE SET "
                "acknowledged = license_store.license_alerts.acknowledged OR EXCLUDED.acknowledged",
                std::vector<std::string>{sanitize_pg_text(a.license_id), a.alert_type,
                                         sanitize_pg_text(a.message),
                                         std::to_string(a.triggered_at),
                                         a.acknowledged ? "true" : "false"});
            if (res.status() != PGRES_COMMAND_OK) {
                failure_detail = std::string("legacy license_alerts row for license_id='") +
                                 a.license_id + "' alert_type='" + a.alert_type +
                                 "': " + PQerrorMessage(conn);
                spdlog::error(
                    "LicenseStore::migrate_from_sqlite: insert of alert for {}/{} failed: {}",
                    a.license_id, a.alert_type, PQerrorMessage(conn));
                return false;
            }
        }

        pg::PgResult marker = pg::exec_params(
            conn,
            "INSERT INTO license_store.sqlite_backfill_source (fingerprint, completed_at) "
            "VALUES ($1, $2::bigint) ON CONFLICT (fingerprint) DO NOTHING",
            std::vector<std::string>{fingerprint, std::to_string(now_epoch())});
        if (marker.status() != PGRES_COMMAND_OK) {
            failure_detail = std::string("backfill marker stamp: ") + PQerrorMessage(conn);
            spdlog::error(
                "LicenseStore::migrate_from_sqlite: failed to stamp backfill marker: {}",
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
                "LicenseStore::migrate_from_sqlite: backfill transaction failed and was "
                "rolled back — license data NOT migrated. Offending: {}. See the guidance "
                "above for which side to reconcile. The retained read-only legacy file is at "
                "{} (e.g. `sqlite3 {} \"SELECT * FROM licenses WHERE id='<id>'\"` to inspect "
                "it) — compare it against Postgres's current row for the same id, then "
                "restart the server once resolved; the backfill marker was NOT stamped, so "
                "the next boot retries the whole backfill.",
                offending, legacy_db_path.string(), legacy_db_path.string());
        } else {
            spdlog::error(
                "LicenseStore::migrate_from_sqlite: backfill transaction failed and was "
                "rolled back — license data NOT migrated. Offending: {}. This is a database "
                "or legacy-file-read failure, not a row-content disagreement — resolve the "
                "underlying error above and restart the server; the backfill marker was NOT "
                "stamped, so the next boot retries the whole backfill.",
                offending);
        }
        return false;
    }
    spdlog::info("LicenseStore::migrate_from_sqlite: backfill complete");
    return true;
}

// ── Operations ───────────────────────────────────────────────────────────────

std::expected<std::string, std::string>
LicenseStore::activate_license(const License& license, const std::string& license_key) {
    if (!open_)
        return std::unexpected(std::string(kLicenseDbErrorPrefix) + "database not open");
    if (license_key.empty())
        return std::unexpected("license key cannot be empty");
    if (license.organization.empty())
        return std::unexpected("organization cannot be empty");

    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected(std::string(kLicenseDbErrorPrefix) +
                               "database unavailable — try again");

    const std::string key_hash = hash_key(license_key);
    const std::string id = license.id.empty() ? generate_id() : license.id;
    const std::int64_t now = now_epoch();
    const std::int64_t issued_at = license.issued_at > 0 ? license.issued_at : now;
    const std::string edition = license.edition.empty() ? "community" : license.edition;
    const std::string features = license.features_json.empty() ? "[]" : license.features_json;

    // Atomic upsert (ADR-0048 hardening over the pre-migration check-then-insert): the conflict
    // itself, not a separate SELECT, detects a duplicate key — closes the TOCTOU window a
    // check-then-act pair leaves open.
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "INSERT INTO license_store.licenses "
        "(id, license_key_hash, organization, seat_count, issued_at, expires_at, edition, "
        " features_json, status, activated_at) "
        "VALUES ($1,$2,$3,$4::bigint,$5::bigint,$6::bigint,$7,$8,'active',$9::bigint) "
        "ON CONFLICT (license_key_hash) DO NOTHING RETURNING id",
        std::vector<std::string>{id, key_hash, sanitize_pg_text(license.organization),
                                 std::to_string(license.seat_count), std::to_string(issued_at),
                                 std::to_string(license.expires_at), sanitize_pg_text(edition),
                                 sanitize_pg_text(features), std::to_string(now)});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kLicenseDbErrorPrefix) + "activate_license failed: " +
                               PQerrorMessage(lease.get()));
    if (PQntuples(res.get()) == 0)
        return std::unexpected("license key already activated");

    spdlog::info("LicenseStore: activated license '{}' for org '{}' (edition={}, seats={})", id,
                 license.organization, edition, license.seat_count);
    return id;
}

std::expected<std::vector<License>, std::string> LicenseStore::list_licenses() {
    if (!open_)
        return std::unexpected(std::string(kLicenseDbErrorPrefix) + "database not open");

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected(std::string(kLicenseDbErrorPrefix) +
                               "database unavailable — try again");

    std::string sql = std::string("SELECT ") + kLicensePublicCols +
                      " FROM license_store.licenses ORDER BY activated_at DESC LIMIT $1";
    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(),
                                       std::vector<std::string>{std::to_string(kListRowCap)});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kLicenseDbErrorPrefix) + "list_licenses failed: " +
                               PQerrorMessage(lease.get()));

    const int rows = PQntuples(res.get());
    std::vector<License> out;
    out.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i)
        out.push_back(read_license_public(res.get(), i));
    return out;
}

std::expected<std::optional<License>, std::string> LicenseStore::get_active_license() {
    if (!open_)
        return std::unexpected(std::string(kLicenseDbErrorPrefix) + "database not open");

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected(std::string(kLicenseDbErrorPrefix) +
                               "database unavailable — try again");

    std::string sql = std::string("SELECT ") + kLicensePublicCols +
                      " FROM license_store.licenses WHERE status = 'active' "
                      "ORDER BY activated_at DESC LIMIT 1";
    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kLicenseDbErrorPrefix) +
                               "get_active_license failed: " + PQerrorMessage(lease.get()));

    if (PQntuples(res.get()) == 0)
        return std::optional<License>{std::nullopt};
    return std::optional<License>{read_license_public(res.get(), 0)};
}

std::expected<void, std::string> LicenseStore::remove_license(const std::string& id) {
    if (!open_)
        return std::unexpected(std::string(kLicenseDbErrorPrefix) + "database not open");
    if (id.empty())
        return std::unexpected("id cannot be empty");

    bool deleted = false;
    std::string db_err;
    // One transaction: delete the license's alerts, then the license itself — never a partial
    // delete (the pre-migration version ran these as two independent best-effort statements).
    bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* conn) -> bool {
        pg::PgResult da = pg::exec_params(
            conn, "DELETE FROM license_store.license_alerts WHERE license_id = $1",
            std::vector<std::string>{id});
        if (da.status() != PGRES_COMMAND_OK) {
            db_err = PQerrorMessage(conn);
            return false;
        }
        pg::PgResult dl = pg::exec_params(
            conn, "DELETE FROM license_store.licenses WHERE id = $1 RETURNING id",
            std::vector<std::string>{id});
        if (dl.status() != PGRES_TUPLES_OK) {
            db_err = PQerrorMessage(conn);
            return false;
        }
        deleted = PQntuples(dl.get()) > 0;
        return true;
    });
    if (!ok) {
        // db_err stays empty when with_txn_for fails before the lambda ever runs (lease
        // acquire timeout) or after it returns true (a failed COMMIT) — never leave the
        // message with a dangling "failed: " tail in either case.
        if (db_err.empty())
            db_err = "transaction failed (lease timeout or begin/commit failure)";
        return std::unexpected(std::string(kLicenseDbErrorPrefix) +
                               "remove_license failed: " + db_err);
    }
    if (!deleted)
        return std::unexpected("not_found: license '" + id + "'");

    spdlog::info("LicenseStore: removed license '{}'", id);
    return {};
}

std::expected<void, std::string> LicenseStore::validate(std::int64_t current_agent_count) {
    if (!open_)
        return std::unexpected(std::string(kLicenseDbErrorPrefix) + "database not open");

    std::string db_err;
    // One transaction for the whole pass (ADR-0048 hardening over the pre-migration version,
    // which processed each license independently and ignored write failures): every status
    // transition and the alerts it produces commit atomically, or none do.
    //
    // FOR UPDATE (gov Gate 4 unhappy-path UP-1, HIGH): without a row lock, two overlapping
    // validate() transactions (e.g. two server replicas sharing this Postgres) each read the
    // same pre-transition status under their own snapshot, independently compute a new status,
    // and the later COMMIT silently clobbers the earlier one's write with no error — the
    // UPDATE below has no re-check against what was read. FOR UPDATE makes the second
    // transaction's SELECT block until the first commits, so it re-reads the already-updated
    // row instead of racing against it.
    bool ok = pool_.with_txn_for(kValidateTimeout, [&](PGconn* conn) -> bool {
        pg::PgResult res = pg::exec_params(
            conn,
            "SELECT id, seat_count, expires_at, status FROM license_store.licenses "
            // gov Gate 8 architect (SHOULD): PK order — two overlapping validate() passes
            // locking more than one row now acquire Postgres row locks in the same order,
            // closing the same deadlock class as the backfill loops' ORDER BY above.
            "WHERE status = 'active' ORDER BY id ASC FOR UPDATE",
            std::vector<std::string>{});
        if (res.status() != PGRES_TUPLES_OK) {
            db_err = PQerrorMessage(conn);
            return false;
        }

        const int rows = PQntuples(res.get());
        const std::int64_t now = now_epoch();
        for (int i = 0; i < rows; ++i) {
            const std::string id = text_col(res.get(), i, 0);
            const std::int64_t seats = to_i64(PQgetvalue(res.get(), i, 1));
            const std::int64_t expires_at = to_i64(PQgetvalue(res.get(), i, 2));
            const std::string status = text_col(res.get(), i, 3);

            std::string new_status = "active";

            if (expires_at > 0 && now > expires_at) {
                new_status = "expired";
                if (!add_alert(conn, id, "expired", "License '" + id + "' has expired")) {
                    db_err = "failed to record expiry alert for '" + id + "'";
                    return false;
                }
            } else if (expires_at > 0) {
                const std::int64_t days = (expires_at - now) / 86400;
                if (days <= 30) {
                    if (!add_alert(conn, id, "expiry_warning",
                                   "License '" + id + "' expires in " + std::to_string(days) +
                                       " days")) {
                        db_err = "failed to record expiry warning for '" + id + "'";
                        return false;
                    }
                }
            }

            if (seats > 0 && current_agent_count > seats) {
                new_status = "exceeded";
                if (!add_alert(conn, id, "exceeded",
                               "License '" + id + "' seat limit exceeded (" +
                                   std::to_string(current_agent_count) + "/" +
                                   std::to_string(seats) + ")")) {
                    db_err = "failed to record seat-exceeded alert for '" + id + "'";
                    return false;
                }
            } else if (seats > 0) {
                const double usage =
                    static_cast<double>(current_agent_count) / static_cast<double>(seats);
                if (usage >= 0.9) {
                    if (!add_alert(conn, id, "seat_limit_warning",
                                   "License '" + id + "' at " +
                                       std::to_string(static_cast<int>(usage * 100)) +
                                       "% seat capacity (" +
                                       std::to_string(current_agent_count) + "/" +
                                       std::to_string(seats) + ")")) {
                        db_err = "failed to record seat-warning alert for '" + id + "'";
                        return false;
                    }
                }
            }

            if (new_status != status) {
                pg::PgResult upd = pg::exec_params(
                    conn, "UPDATE license_store.licenses SET status = $1 WHERE id = $2",
                    std::vector<std::string>{new_status, id});
                if (upd.status() != PGRES_COMMAND_OK) {
                    db_err = PQerrorMessage(conn);
                    return false;
                }
                spdlog::warn("LicenseStore: license '{}' status changed to '{}'", id, new_status);
            }
        }
        return true;
    });
    if (!ok) {
        // Same empty-db_err gap as remove_license: with_txn_for can fail before the lambda runs
        // (lease timeout) or after it returns true (a failed COMMIT).
        if (db_err.empty())
            db_err = "transaction failed (lease timeout or begin/commit failure)";
        return std::unexpected(std::string(kLicenseDbErrorPrefix) + "validate failed: " + db_err);
    }
    return {};
}

std::expected<std::string, std::string> LicenseStore::get_status() {
    if (!open_)
        return std::unexpected(std::string(kLicenseDbErrorPrefix) + "database not open");

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected(std::string(kLicenseDbErrorPrefix) +
                               "database unavailable — try again");

    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT status FROM license_store.licenses ORDER BY activated_at DESC LIMIT 1",
        std::vector<std::string>{});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kLicenseDbErrorPrefix) +
                               "get_status failed: " + PQerrorMessage(lease.get()));

    if (PQntuples(res.get()) == 0)
        return std::string("unlicensed");
    return text_col(res.get(), 0, 0);
}

std::expected<std::vector<LicenseAlert>, std::string>
LicenseStore::list_alerts(bool unacknowledged_only) {
    if (!open_)
        return std::unexpected(std::string(kLicenseDbErrorPrefix) + "database not open");

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected(std::string(kLicenseDbErrorPrefix) +
                               "database unavailable — try again");

    std::string sql = "SELECT id, license_id, alert_type, message, triggered_at, acknowledged "
                      "FROM license_store.license_alerts";
    if (unacknowledged_only)
        sql += " WHERE acknowledged = false";
    sql += " ORDER BY triggered_at DESC LIMIT $1";
    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(),
                                       std::vector<std::string>{std::to_string(kListRowCap)});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kLicenseDbErrorPrefix) +
                               "list_alerts failed: " + PQerrorMessage(lease.get()));

    const int rows = PQntuples(res.get());
    std::vector<LicenseAlert> out;
    out.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i) {
        LicenseAlert a;
        int c = 0;
        a.id = to_i64(PQgetvalue(res.get(), i, c++));
        a.license_id = text_col(res.get(), i, c++);
        a.alert_type = text_col(res.get(), i, c++);
        a.message = text_col(res.get(), i, c++);
        a.triggered_at = to_i64(PQgetvalue(res.get(), i, c++));
        a.acknowledged = to_bool(PQgetvalue(res.get(), i, c++));
        out.push_back(std::move(a));
    }
    return out;
}

std::expected<void, std::string> LicenseStore::acknowledge_alert(std::int64_t alert_id) {
    if (!open_)
        return std::unexpected(std::string(kLicenseDbErrorPrefix) + "database not open");

    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected(std::string(kLicenseDbErrorPrefix) +
                               "database unavailable — try again");

    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE license_store.license_alerts SET acknowledged = true WHERE id = $1 RETURNING id",
        std::vector<std::string>{std::to_string(alert_id)});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kLicenseDbErrorPrefix) +
                               "acknowledge_alert failed: " + PQerrorMessage(lease.get()));
    if (PQntuples(res.get()) == 0)
        return std::unexpected("not_found: alert " + std::to_string(alert_id));
    return {};
}

std::expected<bool, std::string> LicenseStore::has_feature(const std::string& feature) {
    if (!open_)
        return std::unexpected(std::string(kLicenseDbErrorPrefix) + "database not open");
    if (feature.empty())
        return false;

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected(std::string(kLicenseDbErrorPrefix) +
                               "database unavailable — try again");

    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT features_json FROM license_store.licenses WHERE status = 'active' "
        "ORDER BY activated_at DESC LIMIT 1",
        std::vector<std::string>{});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kLicenseDbErrorPrefix) +
                               "has_feature failed: " + PQerrorMessage(lease.get()));
    if (PQntuples(res.get()) == 0)
        return false;

    auto parsed = nlohmann::json::parse(PQgetvalue(res.get(), 0, 0), nullptr, false);
    if (!parsed.is_array())
        return false;
    for (const auto& elem : parsed) {
        if (elem.is_string() && elem.get<std::string>() == feature)
            return true;
    }
    return false;
}

std::expected<std::int64_t, std::string> LicenseStore::seat_count() {
    if (!open_)
        return std::unexpected(std::string(kLicenseDbErrorPrefix) + "database not open");

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected(std::string(kLicenseDbErrorPrefix) +
                               "database unavailable — try again");

    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT seat_count FROM license_store.licenses WHERE status = 'active' "
        "ORDER BY activated_at DESC LIMIT 1",
        std::vector<std::string>{});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kLicenseDbErrorPrefix) +
                               "seat_count failed: " + PQerrorMessage(lease.get()));
    if (PQntuples(res.get()) == 0)
        return std::int64_t{0};
    return to_i64(PQgetvalue(res.get(), 0, 0));
}

std::expected<std::int64_t, std::string> LicenseStore::days_remaining() {
    if (!open_)
        return std::unexpected(std::string(kLicenseDbErrorPrefix) + "database not open");

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected(std::string(kLicenseDbErrorPrefix) +
                               "database unavailable — try again");

    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT expires_at FROM license_store.licenses WHERE status = 'active' "
        "ORDER BY activated_at DESC LIMIT 1",
        std::vector<std::string>{});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kLicenseDbErrorPrefix) +
                               "days_remaining failed: " + PQerrorMessage(lease.get()));
    if (PQntuples(res.get()) == 0)
        return std::int64_t{0};

    const std::int64_t expires = to_i64(PQgetvalue(res.get(), 0, 0));
    if (expires == 0)
        return std::int64_t{0}; // perpetual
    const std::int64_t remaining = expires - now_epoch();
    return remaining > 0 ? remaining / 86400 : std::int64_t{0};
}

} // namespace yuzu::server
