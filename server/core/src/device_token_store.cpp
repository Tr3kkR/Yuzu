#include "device_token_store.hpp"

#include "evp_raii.hpp"
#include "pg/pg_array.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "secure_random.hpp"
#include "sqlite_raii.hpp"
#include "utf8_sanitize.hpp"

#include <libpq-fe.h>
// #3351: EVP_Digest is the SOLE hashing path now (Sha256Stream's backfill fingerprinting AND
// sha256_hex/hash_token below) — the prior _WIN32/BCrypt split is gone, so this include is simply
// unconditional rather than the split-with-a-comment it used to need. `spdlog/spdlog.h` below
// pulls no transitive `<windows.h>` in this build (this project sets `SPDLOG_COMPILED_LIB`
// project-wide, which dead-codes spdlog's header-only Windows.h-including paths) — cpp-expert and
// cross-platform confirmed by source inspection, so this file carries zero `#ifdef _WIN32`
// branches and needs none.
#include <openssl/evp.h>
#include <spdlog/spdlog.h>
#include <sqlite3.h>

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <optional>
#include <span>
#include <string_view>
#include <unordered_set>

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

// #3399: the legacy-copy pass batches Postgres inserts via `unnest(...)` instead of one INSERT
// per row (see flush_batch). 10 array params per statement REGARDLESS of batch size (the libpq
// 65535-parameter ceiling is not a factor at any realistic legacy table size), so this bounds
// resident memory (one batch of rows, not the whole table) and per-statement duration, not param
// count. 500 keeps even a pessimistic large-value batch's array-literal size and round-trip time
// far under the pool's 30s statement_timeout (pg_pool.hpp) — no cap on the number of BATCHES a
// legacy table produces, unlike QuarantineStore's post-materialization row cap (ADR-0047), which
// this design deliberately avoids inheriting (see ADR-0052's Backfill section).
constexpr std::size_t kBackfillBatchRows = 500;

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
//
// #3351: single reserve-and-append pass (#2691 precedent, response_store.cpp — Doomgoose finding
// #8), not the naive find+replace loop copied into every OTHER store's sanitize_pg_text (still
// quadratic there; out of scope here — see #3351's follow-up). The prior loop shifted every
// trailing byte on each NUL hit (1 byte -> 3), an O(k*n) rebuild in NUL count x length for a
// NUL-dense string. Count once, reserve the final size, then copy the segments between NULs
// directly — no in-place shifting.
std::string sanitize_pg_text(std::string_view s) {
    std::string scrubbed = sanitize_utf8_strict(s);
    const std::size_t nul_count =
        static_cast<std::size_t>(std::count(scrubbed.begin(), scrubbed.end(), '\0'));
    if (nul_count == 0)
        return scrubbed;
    std::string out;
    out.reserve(scrubbed.size() + nul_count * 2); // each NUL grows 1 byte -> 3
    std::size_t start = 0;
    for (std::size_t i = 0; i < scrubbed.size(); ++i) {
        if (scrubbed[i] == '\0') {
            out.append(scrubbed, start, i - start);
            out.append("\xEF\xBF\xBD");
            start = i + 1;
        }
    }
    out.append(scrubbed, start, scrubbed.size() - start);
    return out;
}

// #3351: store-level bound on every free-text field, matching the REST route's own 256-char
// clamp (rest_api_v1.cpp) for name/device_id/definition_id — principal_id has NO route-level
// clamp (it comes from session->username, itself bounded to 64 by auth_db.cpp) so this is the
// only bound it gets. Applied on RAW byte length, BEFORE sanitize_pg_text (which can only grow a
// string, never shrink it — utf8_sanitize.hpp's ordering contract), so this is the first, not
// last, gate a caller's input passes through. Defence-in-depth for any future non-REST caller
// (e.g. an MCP twin) — unreachable via the REST route today given its own clamp.
constexpr std::size_t kMaxTextFieldLength = 256;

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

// Length-prefixed (`<byte-length>:<bytes>`, the netstring/bencode technique — see
// DeploymentStore's canonicalize_legacy_jobs for the injectivity rationale): a raw delimiter
// byte embedded in a field can't be confused with a real field boundary.
void append_field(std::string& out, std::string_view field) {
    out += std::to_string(field.size());
    out += ':';
    out += field;
}

// #3399: the per-row body of what was canonicalize_legacy_tokens's loop, extracted so the
// fingerprint can be computed by an incremental digest fed one row at a time (streaming, below)
// instead of materializing every row's encoding before hashing. Encodes the RAW legacy values —
// NOT sanitize_pg_text'd — exactly as the original v1 algorithm did; sanitizing here would change
// every already-stamped fingerprint in the field.
std::string encode_legacy_row(const LegacyDeviceTokenRow& r) {
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
    return e;
}

// Shared by Sha256Stream::final_hex() and sha256_hex() below — both feed EVP's raw digest bytes
// through the identical lowercase-hex encoding, so the encoding step lives once rather than
// twice; the two functions differ only in how they GET those bytes (incremental vs one-shot).
std::string hex_encode(const unsigned char* md, unsigned int len) {
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.reserve(static_cast<std::size_t>(len) * 2);
    for (unsigned int i = 0; i < len; ++i) {
        out.push_back(kHex[md[i] >> 4]);
        out.push_back(kHex[md[i] & 0x0f]);
    }
    return out;
}

// Incremental SHA-256 over EvpMdCtxPtr (evp_raii.hpp) — file_retrieval_routes.cpp's
// compute_file_sha256_hex is the streaming-digest precedent this mirrors.
//
// #3399: replaces materializing every row's encode_legacy_row() output into a vector, sorting it,
// and hashing the concatenation (the original v1 canonicalize_legacy_tokens/sha256_hex pair) with
// an incremental digest fed one row at a time during the SQLite scan. This is NOT merely
// "similar" to v1 — it is BYTE-IDENTICAL, because every encoded row starts "32:<token_id>" (every
// token_id is validated as exactly 32 lowercase hex chars before it can reach here, and is the
// legacy table's PRIMARY KEY), so std::sort(encoded) — comparing byte-for-byte, and hitting its
// first difference inside the token_id substring since the "32:" prefix is identical on every
// element — produces EXACTLY the same order as SQLite's `ORDER BY token_id ASC` (default BINARY
// collation on a TEXT PK). Feeding rows to this digest in scan order therefore reproduces the v1
// sorted-canonical-form hash without ever materializing the sorted vector — pinned by the
// "v1 fingerprint is stable and independent of legacy row order" golden test.
class Sha256Stream {
public:
    [[nodiscard]] bool init() {
        ctx_.reset(EVP_MD_CTX_new());
        return ctx_ && EVP_DigestInit_ex(ctx_.get(), EVP_sha256(), nullptr) == 1;
    }
    [[nodiscard]] bool update(std::string_view bytes) {
        // Defence in depth: the one caller always checks init()'s return before calling this, so
        // ctx_ is never null on any current path — but EVP_DigestUpdate(nullptr, ...) is not
        // documented OpenSSL-safe, so guard here too rather than rely solely on the caller.
        return ctx_ && EVP_DigestUpdate(ctx_.get(), bytes.data(), bytes.size()) == 1;
    }
    // Empty string on failure — callers fail closed on an empty return, matching the pre-#3399
    // sha256_hex() contract.
    [[nodiscard]] std::string final_hex() {
        if (!ctx_)
            return {};
        unsigned char md[EVP_MAX_MD_SIZE];
        unsigned int len = 0;
        if (EVP_DigestFinal_ex(ctx_.get(), md, &len) != 1)
            return {};
        return hex_encode(md, len);
    }

private:
    EvpMdCtxPtr ctx_;
};

constexpr std::string_view kLegacyFingerprintPrefix = "device-token-legacy-fingerprint-v1\n";

// #3351: one-shot counterpart to Sha256Stream above, for hash_token below (a single raw token,
// never a multi-row incremental digest — Sha256Stream's init/update/final_hex sequencing would be
// pure overhead here). Byte-for-byte the same digest (both EVP_sha256, both lowercase-hex-encode
// EVP_MAX_MD_SIZE bytes via the identical table) — restated standalone rather than routed through
// Sha256Stream so a single call site is a single EVP_Digest(), not an init/update/final triple.
std::string sha256_hex(std::string_view in) {
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    if (EVP_Digest(in.data(), in.size(), md, &len, EVP_sha256(), nullptr) != 1)
        return {};
    return hex_encode(md, len);
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

// #3351: was a hand-rolled _WIN32-BCrypt-vs-OpenSSL-SHA256 split with FOUR unchecked BCrypt
// calls on the Windows branch — a failure anywhere in that chain (alg/hash handle never
// allocated, BCryptHashData/BCryptFinishHash erroring) fell through the zero-initialized
// `hash[32]` and silently returned the hex of 32 zero bytes: a constant hash for every input,
// which is an auth-bypass shape on a bearer-credential path (create_token would persist it,
// validate_token would recompute the same constant for ANY raw token). Now a single checked path
// on every platform via a single checked EVP_Digest call (sha256_hex above) — OpenSSL is
// required on Windows regardless of linkage (CLAUDE.md vcpkg section), so there is no
// cross-platform reason left for a BCrypt branch. Output bytes are identical to the old BCrypt
// branch (both are SHA-256), so no legacy hash is invalidated.
std::expected<std::string, std::string> hash_token(const std::string& raw) {
    auto h = sha256_hex(raw);
    if (h.empty())
        return std::unexpected("internal_error: token hash computation failed");
    return h;
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

// ── #3399: shared row reader for both backfill passes ───────────────────────

enum class LegacyStep { row, done, error, invalid };

// One sqlite3_step + column extraction + hex-format validation for a single legacy
// device_auth_tokens row. Shared by both backfill passes (fingerprint below, copy inside
// migrate_from_sqlite's Postgres transaction) so validation and its error text can never diverge
// between them. `step_rc` is always set to the raw sqlite3_step() return, for the caller's own
// "scan aborted mid-read (rc={} {})" mid-scan-corruption log — kept as an out-param rather than
// folded into LegacyStep so ONE log call at each call site can name the raw code.
LegacyStep read_legacy_row(sqlite3_stmt* s, LegacyDeviceTokenRow& out, int& step_rc) {
    step_rc = sqlite3_step(s);
    if (step_rc == SQLITE_DONE)
        return LegacyStep::done;
    if (step_rc != SQLITE_ROW)
        return LegacyStep::error;

    // #3351: length-aware, not C-string — std::string(const char*) stops at the first embedded
    // NUL, which would drop the remainder BEFORE sanitize_pg_text can turn that NUL into U+FFFD,
    // truncating rather than defanging (ADR-0040 requires the latter). Yuzu's own legacy writer
    // always bound with -1, so no row it wrote can carry bytes past a NUL; this is robustness
    // against anything else that wrote the file. audit_store.cpp uses the same
    // sqlite3_column_bytes pattern. token_id/token_hash below deliberately keep the plain
    // safe()/sqlite3_column_text read: a NUL-truncated hex string is already shorter than the
    // required 32/64 chars, so the hex-format check below catches it without the length-aware
    // read too.
    // Named sqlite_text_col, not text_col — that similarly-spelled name is a different, file-scope
    // helper (text_col(PGresult*, int, int), reading a Postgres result) — see flush_batch's
    // identical text_col/text_cols confusability note for why this file is deliberate about it.
    const auto sqlite_text_col = [&](int i) {
        const auto* v = sqlite3_column_text(s, i);
        const int n = sqlite3_column_bytes(s, i);
        return v ? std::string(reinterpret_cast<const char*>(v), static_cast<std::size_t>(n))
                 : std::string{};
    };

    LegacyDeviceTokenRow r;
    r.token_id = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 0)));
    r.token_hash = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 1)));
    r.name = sqlite_text_col(2);
    r.principal_id = sqlite_text_col(3);
    r.device_id = sqlite_text_col(4);
    r.definition_id = sqlite_text_col(5);
    r.created_at = sqlite3_column_int64(s, 6);
    r.expires_at = sqlite3_column_int64(s, 7);
    r.last_used_at = sqlite3_column_int64(s, 8);
    r.revoked = sqlite3_column_int64(s, 9) != 0;

    // gov security-guardian MEDIUM precedent (LicenseStore, ADR-0048): token_id/token_hash are
    // read raw and skipped by sanitize_pg_text (unlike the other free-text columns) — validate
    // their hex format before either can reach Postgres, so a corrupt/hand-edited legacy value
    // fails loudly here rather than as an opaque constraint error that retries identically on
    // every future boot.
    if (!is_valid_lowercase_hex(r.token_id, 32)) {
        spdlog::error("DeviceTokenStore::migrate_from_sqlite: legacy device_auth_tokens row has "
                      "an invalid token_id '{}' (expected 32 lowercase hex chars) — refusing to "
                      "stamp a backfill containing it",
                      r.token_id);
        return LegacyStep::invalid;
    }
    if (!is_valid_lowercase_hex(r.token_hash, 64)) {
        spdlog::error("DeviceTokenStore::migrate_from_sqlite: legacy device_auth_tokens row {} "
                      "has an invalid token_hash (expected 64 lowercase hex chars) — refusing to "
                      "stamp a backfill containing it",
                      r.token_id);
        return LegacyStep::invalid;
    }
    // #3351: reject (never clamp) an oversized legacy free-text field, on the raw read, before
    // sanitize_pg_text/fingerprinting see it. Rejecting — not clamping — keeps the raw-row
    // fingerprint (encode_legacy_row, above) and the sanitize-both-sides IDENTITY comparison
    // (check_conflict, below) symmetric: a clamp applied on one side but not the other would turn
    // a benign re-run into a spurious "refusing to stamp a backfill" abort. Sharing this check
    // inside read_legacy_row (rather than duplicating it in both backfill passes) is exactly the
    // #3399 rationale that motivated extracting this function in the first place — validation and
    // its error text can never diverge between the fingerprint and copy passes.
    if (r.name.size() > kMaxTextFieldLength || r.principal_id.size() > kMaxTextFieldLength ||
        r.device_id.size() > kMaxTextFieldLength || r.definition_id.size() > kMaxTextFieldLength) {
        spdlog::error(
            "DeviceTokenStore::migrate_from_sqlite: legacy device_auth_tokens row {} has a "
            "free-text field exceeding {} bytes — refusing to stamp a backfill containing it",
            r.token_id, kMaxTextFieldLength);
        return LegacyStep::invalid;
    }
    out = std::move(r);
    return LegacyStep::row;
}

// ── #3399: batched-insert helpers for the copy pass ──────────────────────────

// A row conflicted on INSERT (ON CONFLICT (token_id) DO NOTHING matched an existing row) — read
// the existing row back and classify it, exactly as the pre-#3399 per-row with_txn loop did
// (extracted verbatim so log text and classification stay byte-identical). Returns false only for
// the two fail-closed classes (IDENTITY mismatch, legacy-revoked-but-Postgres-active); every other
// outcome (identical content, benign lifecycle drift) is a no-op and returns true — the caller
// does not `continue` a loop here, it just moves on to the next conflicting row.
bool check_conflict(PGconn* conn, const LegacyDeviceTokenRow& r, std::string& failure_detail,
                    bool& row_conflict_guidance) {
    // gov unhappy-path UP-1: this read-back is NOT row-locked (no `FOR UPDATE`) and runs as a
    // second statement in the same transaction, so it can observe a state a concurrent writer
    // produced after the INSERT's conflict was detected. Safe ONLY because IDENTITY columns are
    // write-once (no code path ever UPDATEs them) and `revoked` is monotone false->true (a race
    // can only make `stored.revoked` MORE true, which is always this function's benign branch —
    // see the LIFECYCLE direction comment above migrate_from_sqlite). A future change that makes
    // any IDENTITY column mutable, or that lets `revoked` move true->false, reopens a real race
    // here and would need this read-back to become `FOR UPDATE` (inside a transaction that also
    // holds the lock across the eventual write, which today's design never issues).
    pg::PgResult existing = pg::exec_params(
        conn,
        "SELECT token_id, token_hash, name, principal_id, device_id, definition_id, "
        "created_at, expires_at, last_used_at, revoked "
        "FROM device_token_store.device_auth_tokens WHERE token_id=$1",
        std::vector<std::string>{r.token_id});
    if (existing.status() != PGRES_TUPLES_OK || PQntuples(existing.get()) == 0) {
        failure_detail = std::string("legacy device_auth_tokens row token_id='") + r.token_id +
                         "': conflicted on insert but the existing row could not be read back "
                         "for comparison: " +
                         PQerrorMessage(conn);
        spdlog::error("DeviceTokenStore::migrate_from_sqlite: row {} conflicted but the existing "
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
        failure_detail = std::string("legacy device_auth_tokens row token_id='") + r.token_id +
                         "' already exists with DIFFERENT identity (stored: name='" +
                         stored.name + "' principal_id='" + stored.principal_id +
                         "' device_id='" + stored.device_id + "' definition_id='" +
                         stored.definition_id +
                         "' created_at=" + std::to_string(stored.created_at) +
                         " expires_at=" + std::to_string(stored.expires_at) + "; legacy: name='" +
                         r.name + "' principal_id='" + r.principal_id + "' device_id='" +
                         r.device_id + "' definition_id='" + r.definition_id +
                         "' created_at=" + std::to_string(r.created_at) +
                         " expires_at=" + std::to_string(r.expires_at) +
                         ") — refusing to silently discard it";
        spdlog::error("DeviceTokenStore::migrate_from_sqlite: row {} conflicts with different "
                      "IDENTITY — refusing to stamp a backfill that would silently discard it",
                      r.token_id);
        return false;
    }

    const bool lifecycle_matches =
        stored.last_used_at == r.last_used_at && stored.revoked == r.revoked;
    if (lifecycle_matches) {
        spdlog::debug("DeviceTokenStore::migrate_from_sqlite: row {} already present with "
                      "identical content, skipping (benign no-op)",
                      r.token_id);
        return true;
    }

    // Security-relevant asymmetry (file header, ADR-0052): the legacy row shows this token
    // revoked but Postgres does not yet reflect that — silently keeping Postgres's stale "still
    // active" value would resurrect a credential the operator explicitly killed. `revoked` only
    // ever moves false->true, so this is the one LIFECYCLE direction that must fail closed
    // rather than warn-and-keep.
    if (r.revoked && !stored.revoked) {
        row_conflict_guidance = true;
        failure_detail = std::string("legacy device_auth_tokens row token_id='") + r.token_id +
                         "' was REVOKED in the legacy snapshot but Postgres's current row is "
                         "still active (stored: revoked=false last_used_at=" +
                         std::to_string(stored.last_used_at) +
                         "; legacy: revoked=true last_used_at=" + std::to_string(r.last_used_at) +
                         ") — refusing to silently discard evidence of a revocation the operator "
                         "issued while running the pre-migration binary (ADR-0009 "
                         "rollback-then-roll-forward). Reconcile Postgres to revoked=true or, to "
                         "explicitly accept the loss, move the whole legacy file aside so this "
                         "backfill is never retried against it, then restart";
        spdlog::error("DeviceTokenStore::migrate_from_sqlite: row {} legacy snapshot shows a "
                      "revocation Postgres does not have — refusing to stamp a backfill that "
                      "would silently discard it",
                      r.token_id);
        return false;
    }

    // Otherwise benign: either Postgres already has revoked=true (monotone — the ordinary shape
    // of post-migration progress) or both sides agree on `revoked` and only `last_used_at`
    // (bookkeeping, no auth-bypass risk either direction) differs. The backfill never updates an
    // existing row — Postgres's current value is kept.
    spdlog::warn("DeviceTokenStore::migrate_from_sqlite: row {} already migrated with lifecycle "
                "drift since this legacy snapshot was taken (legacy revoked={} last_used_at={} "
                "vs current revoked={} last_used_at={}) — keeping the current Postgres value; "
                "this is expected on a replica whose legacy file predates that progress, not a "
                "conflict",
                r.token_id, r.revoked, r.last_used_at, stored.revoked, stored.last_used_at);
    return true;
}

// One batch INSERT via `unnest(...)` (software_inventory_store.cpp's ADR-0016/#1664 precedent for
// the shape) instead of one round-trip per row — bounds the copy pass's statement count and
// connection-hold duration to O(table size / kBackfillBatchRows) rather than O(table size).
// Preserves the token_id-ASC lock order ADR-0052 §Backfill promises: `unnest()`'s SELECT emits
// rows in array order, and `batch` arrives here in the SQLite scan's `ORDER BY token_id ASC`
// order, so the array literals built below are too. Rows NOT returned by
// `ON CONFLICT (token_id) DO NOTHING RETURNING token_id` are conflicts — each goes through
// check_conflict, the same per-row classification the pre-#3399 loop used inline.
bool flush_batch(PGconn* conn, std::span<const LegacyDeviceTokenRow> batch,
                 std::string& failure_detail, bool& row_conflict_guidance, std::size_t& inserted,
                 std::size_t& conflicted) {
    if (batch.empty())
        return true;

    // token_id/token_hash are raw fields on `batch`'s own elements (hex-validated, never
    // sanitized) — views into them are valid for `batch`'s lifetime, no owned copy needed.
    // `revoked` is one of two static literals, also no owned copy needed. The other 4 free-text
    // columns are sanitize_pg_text'd and the 3 numeric columns are stringified — BOTH need owned
    // per-batch storage (`text_owned`/`num_owned` below) that the views point into, since neither
    // transform's result lives anywhere else.
    std::vector<std::string_view> id_col, hash_col, revoked_col;
    id_col.reserve(batch.size());
    hash_col.reserve(batch.size());
    revoked_col.reserve(batch.size());

    // [name, principal_id, device_id, definition_id]. Named text_cols (plural), not text_col —
    // that singular name is a different, file-scope helper function (text_col(PGresult*, int,
    // int), used by check_conflict above) this array must not shadow.
    std::vector<std::string> text_owned[4];
    std::vector<std::string_view> text_cols[4];
    for (auto& v : text_owned)
        v.reserve(batch.size());
    for (auto& v : text_cols)
        v.reserve(batch.size());

    // [created_at, expires_at, last_used_at]
    std::vector<std::string> num_owned[3];
    std::vector<std::string_view> num_col[3];
    for (auto& v : num_owned)
        v.reserve(batch.size());
    for (auto& v : num_col)
        v.reserve(batch.size());

    for (const auto& r : batch) {
        id_col.emplace_back(r.token_id);
        hash_col.emplace_back(r.token_hash);
        revoked_col.emplace_back(r.revoked ? "true" : "false");

        // reserve()'d above, so no reallocation invalidates a prior element's address mid-loop —
        // .back() after push_back is safe to view immediately.
        text_owned[0].push_back(sanitize_pg_text(r.name));
        text_owned[1].push_back(sanitize_pg_text(r.principal_id));
        text_owned[2].push_back(sanitize_pg_text(r.device_id));
        text_owned[3].push_back(sanitize_pg_text(r.definition_id));
        for (int i = 0; i < 4; ++i)
            text_cols[i].emplace_back(text_owned[i].back());

        num_owned[0].push_back(std::to_string(r.created_at));
        num_owned[1].push_back(std::to_string(r.expires_at));
        num_owned[2].push_back(std::to_string(r.last_used_at));
        for (int i = 0; i < 3; ++i)
            num_col[i].emplace_back(num_owned[i].back());
    }

    std::vector<std::string> params;
    params.reserve(10);
    params.push_back(pg::to_text_array(id_col));
    params.push_back(pg::to_text_array(hash_col));
    params.push_back(pg::to_text_array(text_cols[0])); // name
    params.push_back(pg::to_text_array(text_cols[1])); // principal_id
    params.push_back(pg::to_text_array(text_cols[2])); // device_id
    params.push_back(pg::to_text_array(text_cols[3])); // definition_id
    params.push_back(pg::to_text_array(num_col[0]));  // created_at
    params.push_back(pg::to_text_array(num_col[1]));  // expires_at
    params.push_back(pg::to_text_array(num_col[2]));  // last_used_at
    params.push_back(pg::to_text_array(revoked_col));

    pg::PgResult res = pg::exec_params(
        conn,
        "INSERT INTO device_token_store.device_auth_tokens "
        "(token_id, token_hash, name, principal_id, device_id, definition_id, "
        " created_at, expires_at, last_used_at, revoked) "
        "SELECT t.id, t.h, t.n, t.p, t.d, t.def, t.c, t.e, t.l, t.r "
        "FROM unnest($1::text[], $2::text[], $3::text[], $4::text[], $5::text[], $6::text[], "
        "$7::bigint[], $8::bigint[], $9::bigint[], $10::boolean[]) "
        "AS t(id, h, n, p, d, def, c, e, l, r) "
        "ON CONFLICT (token_id) DO NOTHING RETURNING token_id",
        params);
    if (res.status() != PGRES_TUPLES_OK) {
        failure_detail = std::string("legacy device_auth_tokens batch (token_id '") +
                         batch.front().token_id + "'..'" + batch.back().token_id + "', " +
                         std::to_string(batch.size()) + " row(s)): " + PQerrorMessage(conn);
        spdlog::error("DeviceTokenStore::migrate_from_sqlite: batch insert of {} row(s) "
                      "(token_id '{}'..'{}') failed: {}",
                      batch.size(), batch.front().token_id, batch.back().token_id,
                      PQerrorMessage(conn));
        return false;
    }

    // An all-conflict batch legitimately returns 0 tuples with PGRES_TUPLES_OK — not an error.
    std::unordered_set<std::string_view> returned;
    const int n = PQntuples(res.get());
    returned.reserve(static_cast<std::size_t>(n));
    for (int i = 0; i < n; ++i)
        returned.emplace(PQgetvalue(res.get(), i, 0),
                         static_cast<std::size_t>(PQgetlength(res.get(), i, 0)));
    inserted += returned.size();

    for (const auto& r : batch) {
        if (returned.contains(std::string_view(r.token_id)))
            continue;
        ++conflicted;
        if (!check_conflict(conn, r, failure_detail, row_conflict_guidance))
            return false;
    }
    return true;
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

    // #3399: holds the legacy SQLite connection, its snapshot transaction, and the prepared scan
    // statement ALIVE across BOTH backfill passes — fingerprint (pass 1, below) and copy (pass 2,
    // inside the Postgres transaction further down) — so both read the exact same snapshot
    // without ever materializing the legacy table into memory. Member declaration order gives
    // reverse-destruction stmt-finalize -> txn-ROLLBACK -> db-close (sqlite_raii.hpp's ordering
    // contract) on every early return; `txn` is populated only once `BEGIN` has succeeded.
    struct LegacyScan {
        SqliteDb db;
        std::optional<SqliteTxn> txn;
        SqliteStmt stmt;
        std::size_t pass1_rows{0};
    };
    std::optional<LegacyScan> scan;

    if (!legacy_exists) {
        fingerprint = kSourcelessFingerprint;
    } else {
        scan.emplace();
        if (sqlite3_open_v2(legacy_db_path.string().c_str(), scan->db.addr(),
                            SQLITE_OPEN_READONLY, nullptr) != SQLITE_OK) {
            spdlog::error("DeviceTokenStore::migrate_from_sqlite: failed to open legacy {}: {}",
                          legacy_db_path.string(),
                          scan->db ? sqlite3_errmsg(scan->db.get()) : "open failed");
            return false;
        }

        // #3398: the pre-migration store set this (dbe176ed:63) and the rewrite dropped it —
        // without it, a legacy file held by a concurrent writer (even just a RESERVED lock, not
        // necessarily EXCLUSIVE) makes this connection's very first read fail SQLITE_BUSY
        // immediately instead of waiting briefly, which the mid-scan-corruption guard below then
        // reports as a corruption-flavoured "scan aborted mid-read" — misattributing transient
        // contention as a corrupt file. Matches software_deployment_store.cpp's measured
        // justification (taskset-pinned A/B, 30 runs each): 2/30 SQLITE_BUSY failures without
        // this pragma, 0/30 with it, against a WAL-mode legacy file — WAL does not exempt this
        // path.
        if (sqlite3_exec(scan->db.get(), "PRAGMA busy_timeout=5000;", nullptr, nullptr, nullptr) !=
            SQLITE_OK) {
            // Non-fatal: a failed PRAGMA leaves this connection at SQLite's compiled-in default
            // (0), silently reintroducing the exact misattributed-contention failure mode #3398
            // fixes — surfaced here so it's diagnosable rather than invisible, without making the
            // backfill fail closed over a pragma the pre-#3398 code never had at all.
            spdlog::warn("DeviceTokenStore::migrate_from_sqlite: failed to set busy_timeout on "
                        "legacy {}: {} — a contended legacy file may now fail immediately "
                        "instead of waiting",
                        legacy_db_path.string(), sqlite3_errmsg(scan->db.get()));
        }

        // A deferred transaction fixes ONE consistent snapshot for the table probe and BOTH
        // backfill passes below (software_deployment_store.cpp's precedent, extended here to
        // span the copy pass too — #3399): without it, this connection's default autocommit mode
        // makes each probe/read its own independent transaction, so a legacy file still being
        // written by another process mid-backfill can interleave a write between them, or the
        // fingerprint pass and the copy pass could see two DIFFERENT row sets. `BEGIN` (not
        // `BEGIN IMMEDIATE`) is sufficient: this connection is SQLITE_OPEN_READONLY, so there is
        // nothing for it to write that a reserved lock would need to protect.
        if (sqlite3_exec(scan->db.get(), "BEGIN", nullptr, nullptr, nullptr) != SQLITE_OK) {
            spdlog::error("DeviceTokenStore::migrate_from_sqlite: failed to start a snapshot "
                          "transaction on legacy {}: {}",
                          legacy_db_path.string(), sqlite3_errmsg(scan->db.get()));
            return false;
        }
        scan->txn.emplace(scan->db.get());

        auto has_table_probe = sqlite_table_exists(scan->db.get(), "device_auth_tokens");
        if (!has_table_probe) {
            spdlog::error(
                "DeviceTokenStore::migrate_from_sqlite: schema probe failed on legacy {}: {}",
                legacy_db_path.string(), sqlite3_errmsg(scan->db.get()));
            return false;
        }

        if (!*has_table_probe) {
            // Present-but-schema-less file — same "nothing to protect" class as no file at all.
            // `scan`'s uncommitted txn rolls back harmlessly at function exit (READONLY, nothing
            // written) — no explicit commit needed for a pass that never ran.
            fingerprint = kSourcelessFingerprint;
        } else {
            const char* sql =
                "SELECT token_id, token_hash, name, principal_id, device_id, definition_id, "
                "created_at, expires_at, last_used_at, revoked FROM device_auth_tokens "
                // gov Gate 8 architect precedent (LicenseStore/DeploymentStore, PK order): two
                // replicas whose legacy files order the same row set differently otherwise
                // acquire Postgres row locks in opposite order during backfill INSERT — PK order
                // makes every overlapping pass agree, closing that deadlock class up front.
                "ORDER BY token_id ASC;";
            if (sqlite3_prepare_v2(scan->db.get(), sql, -1, scan->stmt.addr(), nullptr) !=
                SQLITE_OK) {
                spdlog::error(
                    "DeviceTokenStore::migrate_from_sqlite: legacy device_auth_tokens query "
                    "failed: {}",
                    sqlite3_errmsg(scan->db.get()));
                return false;
            }

            // ── Pass 1: fingerprint, O(1) resident memory (#3399) ──
            Sha256Stream hasher;
            if (!hasher.init() || !hasher.update(kLegacyFingerprintPrefix)) {
                spdlog::error("DeviceTokenStore::migrate_from_sqlite: SHA-256 hashing failed "
                              "for legacy content at {} — refusing (fail-closed)",
                              legacy_db_path.string());
                return false;
            }
            int step_rc = SQLITE_OK;
            for (;;) {
                LegacyDeviceTokenRow r;
                const LegacyStep st = read_legacy_row(scan->stmt.get(), r, step_rc);
                if (st == LegacyStep::done)
                    break;
                if (st == LegacyStep::invalid)
                    return false; // already logged by read_legacy_row
                if (st == LegacyStep::error) {
                    // Mid-scan-corruption guard (gov docs-writer/cpp-expert precedent,
                    // DeploymentStore/LicenseStore): the terminal step code must be SQLITE_DONE,
                    // never merely "loop exited" — a corrupt page is never silently treated as
                    // an empty/complete table.
                    spdlog::error(
                        "DeviceTokenStore::migrate_from_sqlite: legacy device_auth_tokens scan "
                        "aborted mid-read (rc={} {}): refusing to stamp a partial backfill",
                        step_rc, sqlite3_errmsg(scan->db.get()));
                    return false;
                }
                if (!hasher.update(encode_legacy_row(r))) {
                    spdlog::error("DeviceTokenStore::migrate_from_sqlite: SHA-256 hashing "
                                  "failed for legacy content at {} — refusing (fail-closed)",
                                  legacy_db_path.string());
                    return false;
                }
                ++scan->pass1_rows;
            }

            if (scan->pass1_rows == 0) {
                fingerprint = kSourcelessFingerprint;
            } else {
                fingerprint = hasher.final_hex();
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

    // Has THIS specific fingerprint already been processed? Unbounded acquire() here is
    // construction-time discipline (ADR-0012 §2(a)) — this runs once at boot, before serving.
    // `scan`'s uncommitted snapshot txn (if any) rolls back harmlessly when this function returns
    // — nothing was ever written through a READONLY connection.
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

    // A real (non-sourceless) fingerprint is only ever produced by the populated-table branch
    // above, which requires `scan` to hold a value with a successfully-prepared `stmt` — so
    // `scan` is guaranteed populated at this point; the marker-skip and sourceless returns above
    // already handled every path where it might not be.
    spdlog::info("DeviceTokenStore::migrate_from_sqlite: backfilling {} device token(s) from {}",
                 scan->pass1_rows, legacy_db_path.string());

    std::string failure_detail;
    bool row_conflict_guidance = false;
    std::size_t inserted = 0;
    std::size_t conflicted = 0;
    bool ok = pool_.with_txn([&](PGconn* conn) -> bool {
        // ── Pass 2: re-scan the SAME SQLite snapshot, batched copy (#3399) ──
        // sqlite3_reset() is the raw C API call — restarts this prepared statement for
        // re-stepping, does NOT finalize it. NOT scan->stmt.reset() (the SqliteStmt member
        // function below, which DOES finalize) — the two share a name but are opposite
        // operations; do not swap one for the other.
        sqlite3_reset(scan->stmt.get());
        std::vector<LegacyDeviceTokenRow> batch;
        batch.reserve(kBackfillBatchRows);
        std::size_t pass2_rows = 0;
        int step_rc = SQLITE_OK;
        for (;;) {
            LegacyDeviceTokenRow r;
            const LegacyStep st = read_legacy_row(scan->stmt.get(), r, step_rc);
            if (st == LegacyStep::done)
                break;
            if (st == LegacyStep::invalid) {
                // Already logged by read_legacy_row. Structurally unreachable — pass 1 already
                // validated every row in this same snapshot — but fail closed rather than assume.
                failure_detail = "legacy row failed hex-format validation on the copy pass (see "
                                 "the error above)";
                return false;
            }
            if (st == LegacyStep::error) {
                failure_detail = std::string("legacy device_auth_tokens re-scan on the copy "
                                             "pass aborted mid-read (rc=") +
                                 std::to_string(step_rc) + " " + sqlite3_errmsg(scan->db.get()) +
                                 ")";
                spdlog::error(
                    "DeviceTokenStore::migrate_from_sqlite: legacy device_auth_tokens re-scan "
                    "on the copy pass aborted mid-read (rc={} {}): refusing to stamp a partial "
                    "backfill",
                    step_rc, sqlite3_errmsg(scan->db.get()));
                return false;
            }
            ++pass2_rows;
            batch.push_back(std::move(r));
            if (batch.size() == kBackfillBatchRows) {
                if (!flush_batch(conn, batch, failure_detail, row_conflict_guidance, inserted,
                                 conflicted))
                    return false;
                batch.clear();
            }
        }
        if (!flush_batch(conn, batch, failure_detail, row_conflict_guidance, inserted, conflicted))
            return false;

        // Defence in depth: impossible under the one SQLite snapshot BEGIN'd above (both passes
        // read identical bytes), but a torn read here would silently back a fingerprint computed
        // over one row set with a copy of a DIFFERENT one — fail closed rather than assume.
        if (pass2_rows != scan->pass1_rows) {
            failure_detail = "legacy row set changed between the fingerprint pass (" +
                             std::to_string(scan->pass1_rows) + " rows) and the copy pass (" +
                             std::to_string(pass2_rows) + " rows)";
            spdlog::error("DeviceTokenStore::migrate_from_sqlite: {}", failure_detail);
            return false;
        }

        // Finalize the scan statement before COMMIT (sqlite_raii.hpp's ordering note: SQLite
        // wants live statements finalized before a transaction ends) and close the read snapshot
        // BEFORE the marker stamp below. Both passes' work is already reflected in `conn`'s
        // (uncommitted) Postgres transaction at this point — if the SQLite commit fails, `return
        // false` here rolls that transaction back too via PgPool::run_in_txn's PgTxn guard, so no
        // rows and no marker persist and the next boot retries the whole backfill. This is safe
        // specifically because the SQLite commit runs BEFORE the marker INSERT below, inside the
        // SAME Postgres transaction those inserts are still part of — unlike a design where the
        // SQLite snapshot closes only after the Postgres transaction has already committed, there
        // is no "Postgres committed but the SQLite snapshot failed to close" ambiguity to resolve.
        scan->stmt.reset();
        if (scan->txn->commit() != SQLITE_OK) {
            failure_detail = std::string("failed to close the legacy snapshot transaction: ") +
                             sqlite3_errmsg(scan->db.get());
            spdlog::error("DeviceTokenStore::migrate_from_sqlite: failed to close the legacy "
                          "snapshot transaction on {}: {}",
                          legacy_db_path.string(), sqlite3_errmsg(scan->db.get()));
            return false;
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
    spdlog::info(
        "DeviceTokenStore::migrate_from_sqlite: backfill complete: {} inserted, {} already "
        "present",
        inserted, conflicted);
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
    // #3351: reject (not clamp) on RAW byte length, before sanitize_pg_text can grow the field —
    // see kMaxTextFieldLength's doc comment.
    if (name.size() > kMaxTextFieldLength)
        return std::unexpected("invalid_input_length: name exceeds 256 chars");
    if (principal_id.size() > kMaxTextFieldLength)
        return std::unexpected("invalid_input_length: principal_id exceeds 256 chars");
    if (device_id.size() > kMaxTextFieldLength)
        return std::unexpected("invalid_input_length: device_id exceeds 256 chars");
    if (definition_id.size() > kMaxTextFieldLength)
        return std::unexpected("invalid_input_length: definition_id exceeds 256 chars");

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
    auto hashed_result = hash_token(raw);
    if (!hashed_result)
        return std::unexpected(hashed_result.error());
    auto hashed = std::move(*hashed_result);
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

    auto hashed_result = hash_token(raw_token);
    if (!hashed_result) {
        // #3351: a hash-computation fault is a store-internal failure, never a benign rejection
        // reason — same posture as the #1056 lookup-failure handling below (internal_fault),
        // which this mirrors before the transaction even starts.
        spdlog::error("DeviceTokenStore::validate_token: {}", hashed_result.error());
        RejectedToken r;
        r.error = DeviceTokenValidateError::internal_error;
        return std::unexpected(r);
    }
    auto hashed = std::move(*hashed_result);

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

std::expected<std::int64_t, std::string>
DeviceTokenStore::revoke_by_device(const std::string& device_id) {
    // Empty device_id is a no-op: create_token permits an empty device_id (an intentionally
    // unbound token), and a buggy caller passing the empty default must not sweep that
    // population. See header doc.
    if (!open_)
        return std::unexpected(std::string(kDeviceTokenDbErrorPrefix) + "database not open");
    if (device_id.empty())
        return std::int64_t{0};

    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected(std::string(kDeviceTokenDbErrorPrefix) +
                               "database unavailable — try again");

    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE device_token_store.device_auth_tokens SET revoked = true "
        "WHERE device_id = $1 AND revoked = false RETURNING token_id",
        std::vector<std::string>{device_id});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kDeviceTokenDbErrorPrefix) +
                               "revoke_by_device failed: " + PQerrorMessage(lease.get()));

    const std::int64_t revoked = PQntuples(res.get());
    if (revoked > 0)
        spdlog::info("DeviceTokenStore: revoked {} device token(s) for device '{}'", revoked,
                     device_id);
    return revoked;
}

} // namespace yuzu::server
