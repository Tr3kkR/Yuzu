#include "ca_store.hpp"
#include "migration_runner.hpp"

#include <spdlog/spdlog.h>
#include <sqlite3.h>

#include <filesystem>
#include <system_error>

namespace yuzu::server {

namespace {

int64_t epoch_seconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// Bind a std::string as TRANSIENT so SQLite copies it (the source string may go
// out of scope before step()).
void bind_text(sqlite3_stmt* st, int idx, const std::string& v) {
    sqlite3_bind_text(st, idx, v.c_str(), static_cast<int>(v.size()), SQLITE_TRANSIENT);
}

std::string col_text(sqlite3_stmt* st, int idx) {
    const auto* p = sqlite3_column_text(st, idx);
    if (!p)
        return {};
    return std::string(reinterpret_cast<const char*>(p),
                       static_cast<std::size_t>(sqlite3_column_bytes(st, idx)));
}

CertStatus status_from_string(const std::string& s) {
    return s == "revoked" ? CertStatus::Revoked : CertStatus::Active;
}

IssuedCertRecord read_issued_row(sqlite3_stmt* st) {
    IssuedCertRecord r;
    r.serial_hex = col_text(st, 0);
    r.subject = col_text(st, 1);
    r.san = col_text(st, 2);
    r.purpose = col_text(st, 3);
    r.not_after = sqlite3_column_int64(st, 4);
    r.status = status_from_string(col_text(st, 5));
    r.revocation_reason = col_text(st, 6);
    r.revoked_at = sqlite3_column_int64(st, 7);
    r.issued_at = sqlite3_column_int64(st, 8);
    r.issued_by = col_text(st, 9);
    r.enrollment_request_id = col_text(st, 10);
    r.cert_pem = col_text(st, 11);
    r.issuer_fingerprint = col_text(st, 12);
    return r;
}

constexpr const char* kIssuedCols =
    "serial_hex, subject, san, purpose, not_after, status, revocation_reason, revoked_at, "
    "issued_at, issued_by, enrollment_request_id, cert_pem, issuer_fingerprint";

} // namespace

std::optional<std::string> normalize_serial_hex(std::string_view serial) {
    // RFC 5280 serials are <= 20 octets (40 hex chars); cap generously so a
    // pathological multi-megabyte "serial" can't drive an unbounded allocation.
    if (serial.size() > 256)
        return std::nullopt;
    std::string out;
    out.reserve(serial.size());
    for (char c : serial) {
        // Strip the common decorations OpenSSL/operators add (colons, whitespace).
        if (c == ':' || c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f' || c == '\v')
            continue;
        if (c >= '0' && c <= '9')
            out += c;
        else if (c >= 'A' && c <= 'F')
            out += c;
        else if (c >= 'a' && c <= 'f')
            out += static_cast<char>(c - 'a' + 'A'); // canonical uppercase
        else
            return std::nullopt; // any non-hex byte → fail closed
    }
    if (out.empty())
        return std::nullopt;
    // Strip leading zeros so the canonical form matches BN_bn2hex's value
    // semantics (a BIGNUM carries no leading zeros). This makes the form
    // mathematically unique, so an operator-supplied zero-padded serial still
    // matches the stored one. Keep a single digit for the (invalid-but-canonical)
    // zero value rather than collapsing to empty.
    const auto first = out.find_first_not_of('0');
    if (first == std::string::npos)
        out = "0";
    else if (first > 0)
        out.erase(0, first);
    return out;
}

// ── Enum bridges ──────────────────────────────────────────────────────────────

std::string ca_mode_to_string(CaMode m) {
    return m == CaMode::Subordinate ? "subordinate" : "builtin";
}
CaMode ca_mode_from_string(const std::string& s) {
    return s == "subordinate" ? CaMode::Subordinate : CaMode::Builtin;
}
std::string cert_status_to_string(CertStatus s) {
    return s == CertStatus::Revoked ? "revoked" : "active";
}

// ── Lifecycle ─────────────────────────────────────────────────────────────────

CaStore::CaStore(const std::filesystem::path& db_path) {
    if (sqlite3_open_v2(db_path.string().c_str(), &db_,
                        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                        nullptr) != SQLITE_OK) {
        spdlog::error("CaStore: cannot open {}: {}", db_path.string(),
                      db_ ? sqlite3_errmsg(db_) : "(null)");
        if (db_) {
            sqlite3_close(db_);
            db_ = nullptr;
        }
        return;
    }
    // ca.db holds the public root cert, the issued-cert inventory, and CRLs —
    // plus the root key's opaque key_ref, but NOT the key itself (that lives in a
    // separate 0600 file via KeyProvider). 0600 here is defence-in-depth, so a
    // chmod failure on an exotic filesystem warns rather than refusing to start.
    std::error_code ec;
    std::filesystem::permissions(db_path,
                                 std::filesystem::perms::owner_read |
                                     std::filesystem::perms::owner_write,
                                 std::filesystem::perm_options::replace, ec);
    if (ec)
        spdlog::warn("CaStore: could not set 0600 on {}: {}", db_path.string(), ec.message());

    // Match sibling stores (offload_target_store, api_token_store): WAL + a busy
    // timeout so a concurrent reader during a write doesn't hit an instant
    // SQLITE_BUSY once CaStore is wired into the running server (PR2).
    sqlite3_exec(db_, "PRAGMA journal_mode=WAL;", nullptr, nullptr, nullptr);
    sqlite3_exec(db_, "PRAGMA busy_timeout=5000;", nullptr, nullptr, nullptr);

    run_migrations();
}

CaStore::~CaStore() {
    if (db_)
        sqlite3_close(db_);
}

bool CaStore::is_open() const {
    return db_ != nullptr;
}

void CaStore::run_migrations() {
    static const std::vector<Migration> kMigrations = {
        {1, R"(
            CREATE TABLE IF NOT EXISTS ca_root (
                id                 INTEGER PRIMARY KEY CHECK (id = 1),
                cert_pem           TEXT    NOT NULL,
                key_ref            TEXT    NOT NULL,
                algo               TEXT    NOT NULL,
                not_before         INTEGER NOT NULL,
                not_after          INTEGER NOT NULL,
                fingerprint_sha256 TEXT    NOT NULL,
                mode               TEXT    NOT NULL DEFAULT 'builtin',
                created_at         INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS ca_issued (
                serial_hex            TEXT    PRIMARY KEY,
                subject               TEXT    NOT NULL,
                san                   TEXT    NOT NULL DEFAULT '',
                purpose               TEXT    NOT NULL DEFAULT '',
                not_after             INTEGER NOT NULL,
                status                TEXT    NOT NULL DEFAULT 'active',
                revocation_reason     TEXT    NOT NULL DEFAULT '',
                revoked_at            INTEGER NOT NULL DEFAULT 0,
                issued_at             INTEGER NOT NULL,
                -- Provenance: populated by the PR4 issue/revoke REST layer (empty
                -- until then). Added in PR1 so the schema is stable BEFORE ca.db
                -- ships — retrofitting after deployment leaves historical rows
                -- blank (compliance CC6.1 "who issued/revoked"; enterprise
                -- forensic "produce the exact cert").
                issued_by             TEXT    NOT NULL DEFAULT '',
                enrollment_request_id TEXT    NOT NULL DEFAULT '',
                cert_pem              TEXT    NOT NULL DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_ca_issued_status
                ON ca_issued(status) WHERE status = 'revoked';
            CREATE TABLE IF NOT EXISTS ca_crl_versions (
                version      INTEGER PRIMARY KEY,
                der          BLOB    NOT NULL,
                this_update  INTEGER NOT NULL,
                next_update  INTEGER NOT NULL,
                published_at INTEGER NOT NULL
            );
        )"},
        // v2: provenance link to the signing root (its SHA-256 fingerprint) on
        // both the issued inventory and the CRL history. A subordinate-CA re-key
        // (PR6) replaces ca_root id=1; without this an issued cert / stored CRL
        // has no link to the root that signed it (a re-key would orphan the
        // inventory and could serve an old-root CRL against the new root). Done
        // as a v2 ALTER — NOT an in-place edit of the v1 CREATE TABLE — so an
        // already-migrated (v1) ca.db gains the column too, rather than the
        // IF NOT EXISTS path silently skipping it. NOT NULL DEFAULT '' keeps it
        // backward-compatible for code that does not set it yet.
        {2, R"(
            ALTER TABLE ca_issued       ADD COLUMN issuer_fingerprint TEXT NOT NULL DEFAULT '';
            ALTER TABLE ca_crl_versions ADD COLUMN issuer_fingerprint TEXT NOT NULL DEFAULT '';
        )"},
        // v3: index the inventory's default sort key. GET /api/v1/ca/issued and the
        // list_issued_certs MCP tool ORDER BY issued_at DESC; without this every
        // call full-scans + sorts ca_issued (#1240 performance). Additive index.
        {3, R"(
            CREATE INDEX IF NOT EXISTS idx_ca_issued_issued_at ON ca_issued(issued_at);
        )"},
    };
    if (!MigrationRunner::run(db_, "ca_store", kMigrations)) {
        spdlog::error("CaStore: schema migration failed, closing database");
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

// ── Root ──────────────────────────────────────────────────────────────────────

bool CaStore::has_root() {
    std::lock_guard lk(mu_);
    if (!db_)
        return false;
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db_, "SELECT 1 FROM ca_root WHERE id = 1;", -1, &st, nullptr) !=
        SQLITE_OK)
        return false;
    const bool found = sqlite3_step(st) == SQLITE_ROW;
    sqlite3_finalize(st);
    return found;
}

std::optional<CaRoot> CaStore::get_root() {
    std::lock_guard lk(mu_);
    if (!db_)
        return std::nullopt;
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "SELECT cert_pem, key_ref, algo, not_before, not_after, "
                           "fingerprint_sha256, mode, created_at FROM ca_root WHERE id = 1;",
                           -1, &st, nullptr) != SQLITE_OK)
        return std::nullopt;
    std::optional<CaRoot> out;
    if (sqlite3_step(st) == SQLITE_ROW) {
        CaRoot r;
        r.cert_pem = col_text(st, 0);
        r.key_ref = col_text(st, 1);
        r.algo = col_text(st, 2);
        r.not_before = sqlite3_column_int64(st, 3);
        r.not_after = sqlite3_column_int64(st, 4);
        r.fingerprint_sha256 = col_text(st, 5);
        r.mode = ca_mode_from_string(col_text(st, 6));
        r.created_at = sqlite3_column_int64(st, 7);
        out = std::move(r);
    }
    sqlite3_finalize(st);
    return out;
}

bool CaStore::set_root(const CaRoot& root) {
    std::lock_guard lk(mu_);
    if (!db_)
        return false;
    if (root.cert_pem.empty() || root.key_ref.empty()) {
        spdlog::error("CaStore: refusing to set root with empty cert/key_ref");
        return false;
    }
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "INSERT OR REPLACE INTO ca_root (id, cert_pem, key_ref, algo, "
                           "not_before, not_after, fingerprint_sha256, mode, created_at) "
                           "VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?);",
                           -1, &st, nullptr) != SQLITE_OK) {
        spdlog::error("CaStore: prepare set_root failed: {}", sqlite3_errmsg(db_));
        return false;
    }
    bind_text(st, 1, root.cert_pem);
    bind_text(st, 2, root.key_ref);
    bind_text(st, 3, root.algo);
    sqlite3_bind_int64(st, 4, root.not_before);
    sqlite3_bind_int64(st, 5, root.not_after);
    bind_text(st, 6, root.fingerprint_sha256);
    bind_text(st, 7, ca_mode_to_string(root.mode));
    sqlite3_bind_int64(st, 8, root.created_at ? root.created_at : epoch_seconds());
    const bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    if (!ok)
        spdlog::error("CaStore: set_root step failed: {}", sqlite3_errmsg(db_));
    return ok;
}

// ── Issued inventory ────────────────────────────────────────────────────────────

bool CaStore::record_issued(const IssuedCertRecord& rec) {
    std::lock_guard lk(mu_);
    if (!db_)
        return false;
    // Canonicalise the serial at the write boundary so a later revoke()/
    // is_revoked() lookup matches regardless of case/colon decoration. Fail
    // closed on a non-hex serial — never store a cert we couldn't later revoke.
    const auto serial = normalize_serial_hex(rec.serial_hex);
    if (!serial) {
        // Don't echo the raw serial — it may be untrusted (PR4 operator/REST
        // input) and could carry CRLF/control bytes to forge log lines.
        spdlog::error("CaStore: refusing to record issued cert with empty/non-hex serial (len {})",
                      rec.serial_hex.size());
        return false;
    }
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "INSERT INTO ca_issued (serial_hex, subject, san, purpose, not_after, "
                           "status, revocation_reason, revoked_at, issued_at, issued_by, "
                           "enrollment_request_id, cert_pem, issuer_fingerprint) "
                           "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
                           -1, &st, nullptr) != SQLITE_OK) {
        spdlog::error("CaStore: prepare record_issued failed: {}", sqlite3_errmsg(db_));
        return false;
    }
    bind_text(st, 1, *serial);
    bind_text(st, 2, rec.subject);
    bind_text(st, 3, rec.san);
    bind_text(st, 4, rec.purpose);
    sqlite3_bind_int64(st, 5, rec.not_after);
    bind_text(st, 6, cert_status_to_string(rec.status));
    bind_text(st, 7, rec.revocation_reason);
    sqlite3_bind_int64(st, 8, rec.revoked_at);
    sqlite3_bind_int64(st, 9, rec.issued_at ? rec.issued_at : epoch_seconds());
    bind_text(st, 10, rec.issued_by);
    bind_text(st, 11, rec.enrollment_request_id);
    bind_text(st, 12, rec.cert_pem);
    bind_text(st, 13, rec.issuer_fingerprint);
    const bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    if (!ok)
        spdlog::error("CaStore: record_issued step failed: {}", sqlite3_errmsg(db_));
    return ok;
}

std::optional<IssuedCertRecord> CaStore::get_issued(const std::string& serial_hex) {
    std::lock_guard lk(mu_);
    if (!db_)
        return std::nullopt;
    const auto serial = normalize_serial_hex(serial_hex);
    if (!serial)
        return std::nullopt; // non-hex → no such cert
    sqlite3_stmt* st = nullptr;
    const std::string sql =
        std::string("SELECT ") + kIssuedCols + " FROM ca_issued WHERE serial_hex = ?;";
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &st, nullptr) != SQLITE_OK)
        return std::nullopt;
    bind_text(st, 1, *serial);
    std::optional<IssuedCertRecord> out;
    if (sqlite3_step(st) == SQLITE_ROW)
        out = read_issued_row(st);
    sqlite3_finalize(st);
    return out;
}

std::vector<IssuedCertRecord> CaStore::list_issued(int limit, int offset) {
    std::lock_guard lk(mu_);
    std::vector<IssuedCertRecord> out;
    if (!db_)
        return out;
    // SQLite treats a negative LIMIT as "unbounded"; clamp so a caller passing a
    // negative value can't trigger an unbounded result-set memory DoS.
    if (limit < 0 || limit > 10000)
        limit = 10000;
    if (offset < 0)
        offset = 0;
    sqlite3_stmt* st = nullptr;
    const std::string sql = std::string("SELECT ") + kIssuedCols +
                            " FROM ca_issued ORDER BY issued_at DESC LIMIT ? OFFSET ?;";
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &st, nullptr) != SQLITE_OK)
        return out;
    sqlite3_bind_int(st, 1, limit);
    sqlite3_bind_int(st, 2, offset);
    while (sqlite3_step(st) == SQLITE_ROW)
        out.push_back(read_issued_row(st));
    sqlite3_finalize(st);
    return out;
}

bool CaStore::revoke(const std::string& serial_hex, const std::string& reason) {
    std::lock_guard lk(mu_);
    if (!db_)
        return false;
    // Canonicalise so an operator/REST-supplied serial (lowercase / colons)
    // matches the stored form; fail closed on non-hex (no such cert to revoke).
    const auto serial = normalize_serial_hex(serial_hex);
    if (!serial)
        return false;
    // RETURNING carries the change in the step result — never sqlite3_changes()
    // on a shared connection (#1033). A no-op (already revoked / unknown serial)
    // returns no row.
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "UPDATE ca_issued SET status = 'revoked', revocation_reason = ?, "
                           "revoked_at = ? WHERE serial_hex = ? AND status != 'revoked' "
                           "RETURNING serial_hex;",
                           -1, &st, nullptr) != SQLITE_OK) {
        spdlog::error("CaStore: prepare revoke failed: {}", sqlite3_errmsg(db_));
        return false;
    }
    bind_text(st, 1, reason);
    sqlite3_bind_int64(st, 2, epoch_seconds());
    bind_text(st, 3, *serial);
    const bool changed = sqlite3_step(st) == SQLITE_ROW;
    sqlite3_finalize(st);
    return changed;
}

bool CaStore::is_revoked(const std::string& serial_hex) {
    // Direct single-statement check under the lock (not via get_issued) so the
    // answer is a clean point-in-time read for the PR3 mTLS-accept gate.
    std::lock_guard lk(mu_);
    if (!db_)
        return false;
    // Canonicalise so the lookup matches the stored form. This is a SECURITY
    // gate ("reject if revoked"); a serial that won't normalise to hex cannot be
    // one of our issued certs, so fail closed — treat it as revoked (reject)
    // rather than silently returning "not revoked". In practice every real caller
    // passes a BN_bn2hex-form serial from a chain-verified leaf, so this branch
    // is unreachable on the happy path.
    const auto serial = normalize_serial_hex(serial_hex);
    if (!serial) {
        // Don't echo the raw serial (untrusted → CRLF/log-forging risk).
        spdlog::warn("CaStore: is_revoked got a non-hex serial (len {}) — failing closed (revoked)",
                     serial_hex.size());
        return true;
    }
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "SELECT 1 FROM ca_issued WHERE serial_hex = ? AND status = 'revoked';",
                           -1, &st, nullptr) != SQLITE_OK)
        return false;
    bind_text(st, 1, *serial);
    const bool revoked = sqlite3_step(st) == SQLITE_ROW;
    sqlite3_finalize(st);
    return revoked;
}

std::vector<IssuedCertRecord> CaStore::list_revoked() {
    std::lock_guard lk(mu_);
    std::vector<IssuedCertRecord> out;
    if (!db_)
        return out;
    sqlite3_stmt* st = nullptr;
    const std::string sql = std::string("SELECT ") + kIssuedCols +
                            " FROM ca_issued WHERE status = 'revoked' ORDER BY revoked_at;";
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &st, nullptr) != SQLITE_OK)
        return out;
    while (sqlite3_step(st) == SQLITE_ROW)
        out.push_back(read_issued_row(st));
    sqlite3_finalize(st);
    return out;
}

bool CaStore::delete_issued_by(const std::string& issued_by) {
    std::lock_guard lk(mu_);
    if (!db_)
        return false;
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db_, "DELETE FROM ca_issued WHERE issued_by = ?;", -1, &st, nullptr) !=
        SQLITE_OK) {
        spdlog::error("CaStore: prepare delete_issued_by failed: {}", sqlite3_errmsg(db_));
        return false;
    }
    bind_text(st, 1, issued_by);
    const bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

// ── CRL versions ────────────────────────────────────────────────────────────────

uint64_t CaStore::next_crl_number() {
    std::lock_guard lk(mu_);
    if (!db_)
        return 1;
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db_, "SELECT COALESCE(MAX(version), 0) + 1 FROM ca_crl_versions;", -1,
                           &st, nullptr) != SQLITE_OK)
        return 1;
    uint64_t n = 1;
    if (sqlite3_step(st) == SQLITE_ROW)
        n = static_cast<uint64_t>(sqlite3_column_int64(st, 0));
    sqlite3_finalize(st);
    return n;
}

bool CaStore::record_crl(const CrlVersionRecord& rec) {
    std::lock_guard lk(mu_);
    if (!db_)
        return false;
    if (rec.der.empty()) {
        spdlog::error("CaStore: refusing to record empty CRL");
        return false;
    }
    if (rec.version < 1) {
        // crlNumber is a positive monotonic sequence (RFC 5280 §5.2.3); version 0
        // would collide with COALESCE(MAX,0) sentinels and is never legitimate.
        spdlog::error("CaStore: refusing to record CRL with version {} (< 1)", rec.version);
        return false;
    }
    // Plain INSERT (NOT "OR REPLACE"): a duplicate version is a real conflict
    // (two publishers raced a number) — fail it so the caller re-allocates,
    // rather than silently clobbering an existing generation. The race-free path
    // is publish_next_crl(); this manual path stays safe by refusing collisions.
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "INSERT INTO ca_crl_versions (version, der, this_update, "
                           "next_update, published_at, issuer_fingerprint) VALUES (?, ?, ?, ?, ?, ?);",
                           -1, &st, nullptr) != SQLITE_OK) {
        spdlog::error("CaStore: prepare record_crl failed: {}", sqlite3_errmsg(db_));
        return false;
    }
    sqlite3_bind_int64(st, 1, rec.version);
    sqlite3_bind_blob(st, 2, rec.der.data(), static_cast<int>(rec.der.size()), SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, rec.this_update);
    sqlite3_bind_int64(st, 4, rec.next_update);
    sqlite3_bind_int64(st, 5, rec.published_at ? rec.published_at : epoch_seconds());
    bind_text(st, 6, rec.issuer_fingerprint);
    const bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    if (!ok)
        spdlog::error("CaStore: record_crl step failed: {}", sqlite3_errmsg(db_));
    return ok;
}

std::optional<CrlVersionRecord>
CaStore::publish_next_crl(const CrlBuilder& build, int64_t this_update, int64_t next_update,
                          const std::string& issuer_fingerprint) {
    if (!build)
        return std::nullopt;
    // Serialise publishes against each other so the number allocated by
    // next_crl_number() is still free when record_crl() inserts it — WITHOUT
    // holding the connection lock (mu_) across the signing callback. Each DB step
    // below takes mu_ only briefly via the public methods; `build` (CA-key load +
    // sign) runs with no DB lock held, so concurrent issuance is not blocked and
    // `build` cannot deadlock the store.
    std::lock_guard pub(crl_publish_mu_);
    if (!is_open())
        return std::nullopt;
    const uint64_t version = next_crl_number();                  // MAX(version)+1
    const std::vector<IssuedCertRecord> revoked = list_revoked(); // current revoked set
    std::vector<uint8_t> der = build(version, revoked);
    if (der.empty()) {
        spdlog::error("CaStore: publish_next_crl build produced no DER (version {})", version);
        return std::nullopt; // nothing inserted → the number is not consumed
    }
    CrlVersionRecord rec;
    rec.version = static_cast<int64_t>(version);
    rec.der = std::move(der);
    rec.this_update = this_update;
    rec.next_update = next_update;
    rec.published_at = epoch_seconds();
    rec.issuer_fingerprint = issuer_fingerprint;
    // Plain INSERT (in record_crl): a duplicate version — only reachable via a
    // cross-process publisher, not the single-server M1 model — is refused, never
    // clobbered. crl_publish_mu_ makes the same-process path collision-free.
    if (!record_crl(rec))
        return std::nullopt;
    return rec;
}

std::optional<CrlVersionRecord> CaStore::latest_crl() {
    std::lock_guard lk(mu_);
    if (!db_)
        return std::nullopt;
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "SELECT version, der, this_update, next_update, published_at, "
                           "issuer_fingerprint FROM ca_crl_versions ORDER BY version DESC LIMIT 1;",
                           -1, &st, nullptr) != SQLITE_OK)
        return std::nullopt;
    std::optional<CrlVersionRecord> out;
    if (sqlite3_step(st) == SQLITE_ROW) {
        CrlVersionRecord r;
        r.version = sqlite3_column_int64(st, 0);
        const void* blob = sqlite3_column_blob(st, 1);
        const int n = sqlite3_column_bytes(st, 1);
        if (blob && n > 0) {
            const auto* p = static_cast<const uint8_t*>(blob);
            r.der.assign(p, p + n);
        }
        r.this_update = sqlite3_column_int64(st, 2);
        r.next_update = sqlite3_column_int64(st, 3);
        r.published_at = sqlite3_column_int64(st, 4);
        r.issuer_fingerprint = col_text(st, 5);
        out = std::move(r);
    }
    sqlite3_finalize(st);
    return out;
}

} // namespace yuzu::server
