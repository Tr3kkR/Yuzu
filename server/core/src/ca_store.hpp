#pragma once

/// @file ca_store.hpp
/// Migrated Postgres store (ADR-0006/0009/0053, schema `ca_store`) for Yuzu's internal CA
/// inventory + lifecycle (`ca_root`, `ca_issued`, `ca_crl_versions`).
///
/// Holds METADATA ONLY: the root certificate, the issued-cert inventory, and the CRL version
/// history. The root PRIVATE KEY is NEVER stored here — it lives behind a `KeyProvider` (a 0600
/// file in Milestone 1) and only its opaque `key_ref` is persisted in `ca_root`. This keeps the
/// crown-jewel key out of the database blast radius and lets a future HSM swap leave this store
/// untouched. `key_ref` is the ONLY thing this migration resolves the Wave 3 "secret-gated"
/// listing over — there is no envelope-encrypted column here, so `SecretCodec` is not involved
/// (ADR-0053).
///
/// Posture (ADR-0012 §1): AUTHORITATIVE / fail-hard, both construction and runtime. The database
/// is the source of truth for the revoked-certificate set — a silently-empty/-false read on
/// `is_revoked`/`list_revoked` would silently accept a certificate that should have been
/// rejected, or publish a CRL that omits a real revocation. Every reader/mutator whose false/empty
/// result could feed that class of decision returns `std::expected<..., std::string>` (ADR-0036
/// type-distinguishability), prefixed `kCaDbErrorPrefix` on a genuine DB/lease failure — EXCEPT
/// `is_revoked()`, which stays a plain `bool` and is documented below to degrade to `true` (fail
/// CLOSED: treat "couldn't tell" as "revoked") rather than exposing a three-state channel on the
/// mTLS-accept hot path.
///
/// Substrate contract (ADR-0008): the store holds a `pg::PgPool&` (not a `sqlite3*`), runs its
/// schema migration at construction on a pinned lease, and schema-qualifies every runtime
/// statement (`ca_store.ca_root` / `ca_store.ca_issued` / `ca_store.ca_crl_versions`) — pooled
/// connections carry no per-store search_path. Mutate-and-return uses `RETURNING`, never
/// `sqlite3_changes()`.
///
/// **First-boot CA-root race (ADR-0053 "Root-singleton first-boot race").** Under per-instance
/// SQLite this race never existed — each server instance held its own local `ca.db`. A shared
/// Postgres substrate makes it possible for two instances to independently generate root material
/// and race to establish it. `try_insert_root()` is the dedicated, race-safe entry point for
/// FIRST-BOOT generation (`default_certs.cpp`): `ON CONFLICT (id) DO NOTHING` means at most one
/// caller's row is ever inserted, and every caller — winner or loser — reads back the SAME row
/// that is now canonical. `set_root()` keeps its pre-migration unconditional-REPLACE contract for
/// the two callers that legitimately intend a replace: PR6 subordinate-CA import (an explicit,
/// single-writer, operator-triggered re-root) and test seeding. Never call `set_root()` from
/// first-boot generation — see `try_insert_root()`'s doc comment for why.
///
/// `migrate_from_sqlite()` retired (#3623, ADR-0053 Update): no production fleet ever ran a
/// pre-Postgres build of this store, so the mandatory three-table fingerprinted backfill it
/// implemented never had real legacy data to protect. `server.cpp` now runs
/// `legacy_sqlite_probe::warn_if_legacy_rows` over `ca_root`/`ca_issued`/`ca_crl_versions`
/// instead — silent unless real rows are found, never blocks boot.

#include <chrono>
#include <cstdint>
#include <expected>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server::pg {
class PgPool;
}

namespace yuzu::server {

/// Machine-checkable prefix on every `CaStore` `unexpected()` that represents a genuine DB/lease
/// failure rather than a business-rule answer (mirrors `LicenseStore`'s `kLicenseDbErrorPrefix` —
/// deliberately a separate constant per-store, not shared; see the playbook / ADR-0048).
inline constexpr const char* kCaDbErrorPrefix = "db_error: ";

/// Machine-checkable prefix on `record_issued`'s `unexpected()` when the failure is specifically
/// a `serial_hex` unique-violation (PG SQLSTATE 23505) rather than a genuine DB/lease failure —
/// see `record_issued`'s doc comment and the `.cpp` file header for #1276. Distinct from
/// `kCaDbErrorPrefix` because this ONE case is retryable-with-a-fresh-serial, not an outage —
/// infrastructure for a FUTURE caller to act on; `sign_agent_csr` (the sole production caller
/// today) does not yet inspect this prefix and retry, it logs and returns nullopt on any
/// `record_issued` failure regardless of classification (governance Gate 3 cpp-expert,
/// 2026-08-21 — this comment previously read as though the retry were already wired).
inline constexpr const char* kCaDuplicateSerialPrefix = "duplicate_serial: ";

/// Trust-source mode of the issuing CA. Builtin = self-signed install root (M1). Subordinate =
/// intermediate signed by an enterprise root (PR6).
enum class CaMode {
    Builtin,
    Subordinate,
};
std::string ca_mode_to_string(CaMode m);
CaMode ca_mode_from_string(const std::string& s);

struct CaRoot {
    std::string cert_pem; ///< The ISSUING cert: self-signed root (Builtin) or our
                          ///< enterprise-signed intermediate (Subordinate).
    std::string key_ref;  ///< Opaque KeyProvider reference — never the key itself.
    std::string algo;     ///< "EcP384" / "EcP256".
    int64_t not_before{0};
    int64_t not_after{0};
    std::string fingerprint_sha256;
    CaMode mode{CaMode::Builtin};
    int64_t created_at{0};
    /// Parent CA chain ABOVE the issuing cert — the enterprise root [+ any
    /// intermediates], PEM-concatenated. Empty in Builtin mode. Set on
    /// subordinate-CA import (PR6) so issued leaves can present a full path to the
    /// corporate trust anchor. The issuing key (`key_ref`) is unchanged across the
    /// builtin→subordinate transition — the enterprise signs our existing public
    /// key — so previously-issued leaves keep validating.
    std::string chain_pem;
};

enum class CertStatus {
    Active,
    Revoked,
};
std::string cert_status_to_string(CertStatus s);

struct IssuedCertRecord {
    std::string serial_hex;
    std::string subject;
    std::string san;     ///< Human-readable SAN summary (for the inventory UI).
    std::string purpose; ///< "https" | "server" | "gateway" | "agent" | "code-signing".
    int64_t not_after{0};
    CertStatus status{CertStatus::Active};
    std::string revocation_reason;
    int64_t revoked_at{0};
    int64_t issued_at{0};
    /// Provenance — populated by the PR4 issue/revoke REST layer; empty until
    /// then. Present from PR1 so the ca.db schema is stable before first deploy.
    std::string issued_by;             ///< Yuzu principal that triggered issuance.
    std::string enrollment_request_id; ///< Correlation handle to the enrollment.
    std::string cert_pem;              ///< Full issued leaf PEM (forensic/audit).
    /// SHA-256 fingerprint of the issuer CERTIFICATE **at issuance time**. Forensic
    /// metadata only — it records which issuer cert minted this leaf.
    ///
    /// CONTRACT (PR6 Hermes H1): this is NOT a stable CA identity and MUST NEVER be
    /// used as an admission / revocation / filter key. A subordinate-CA import
    /// (`CaMode::Subordinate`) keeps the issuing KEY but swaps the issuer cert, so
    /// the *current* root fingerprint changes while leaves minted before the switch
    /// retain their original (builtin-root) fingerprint — two distinct fingerprints
    /// over the SAME signing key. Those leaves stay fully valid: admission verifies
    /// by the key+DN (`is_yuzu_issued`→`verify_chain`), and revocation matches by
    /// serial — neither consults this column. A future "issued by THIS CA" query
    /// must therefore key on the stable identity (`issuer_key_id` below), never on
    /// a single fingerprint value. Empty until a caller populates it.
    std::string issuer_fingerprint;
    /// STABLE key-based CA identity (#1296): SHA-256 of the issuer's subjectPublicKey
    /// (`pki::issuer_key_id`). Unlike issuer_fingerprint this is invariant across a
    /// subordinate-CA re-key (same key, new issuer cert), so it — NOT the
    /// fingerprint — is the correct key for an "issued by THIS CA" inventory query
    /// (`CaStore::list_issued_by_key_id`). Empty on pre-v5 / unpopulated rows.
    std::string issuer_key_id;
};

struct CrlVersionRecord {
    int64_t version{0};
    std::vector<uint8_t> der;
    int64_t this_update{0};
    int64_t next_update{0};
    int64_t published_at{0};
    /// SHA-256 fingerprint of the root that signed this CRL (see IssuedCertRecord).
    /// Empty until populated; prevents serving an old-root CRL after a re-key.
    std::string issuer_fingerprint;
    /// STABLE key-based identity of the signing CA (#1296, see IssuedCertRecord).
    /// Invariant across a subordinate re-key; empty on pre-v5 rows.
    std::string issuer_key_id;
};

/// Canonicalise a certificate serial to the engine's stored form — uppercase
/// hex with no colons or whitespace (BN_bn2hex form). The engine emits serials
/// in this form; an operator/REST-supplied serial (PR4) may arrive lowercase or
/// colon-decorated, which would otherwise silently miss revoke()/is_revoked()
/// (a revoked cert that keeps validating). Returns nullopt on an empty or
/// non-hex input so callers fail closed (mirrors x509_ca::build_crl's bad-serial
/// precedent). Pure string transform — this store deliberately links no crypto.
[[nodiscard]] std::optional<std::string> normalize_serial_hex(std::string_view serial);

class CaStore {
public:
    /// Borrows the shared pool and runs the `ca_store` schema migration on a pinned lease.
    /// `is_open()` is false if the lease was empty or the migration failed.
    explicit CaStore(pg::PgPool& pool);
    ~CaStore();

    CaStore(const CaStore&) = delete;
    CaStore& operator=(const CaStore&) = delete;

    [[nodiscard]] bool is_open() const noexcept { return open_; }

    /// The shared pool this store borrows. Exposed so a caller that already
    /// holds a `CaStore*` can take an INDEPENDENT lease for its own purpose —
    /// e.g. `default_certs.cpp`'s bootstrap advisory lock (ADR-0053 UP-2 Gate 8
    /// fix, 2026-08-21), which needs a connection to hold a session advisory
    /// lock across a multi-call critical section, separate from this store's
    /// own per-call leasing.
    [[nodiscard]] pg::PgPool& pool() const noexcept { return pool_; }

    // ── Root ──────────────────────────────────────────────────────────────────

    /// The current root (id=1), if any. `nullopt` = a successful read finding none (a genuine,
    /// successful answer — e.g. operator-supplied certs, or before first-boot generation has
    /// run). `unexpected(msg)` (prefixed `kCaDbErrorPrefix`) is a genuine read failure — ADR-0036:
    /// a caller deciding whether to (re)generate/re-root MUST treat that as fail-closed (refuse),
    /// never fold it into the "no root" case. See `has_root()` for the narrower convenience that
    /// is safe to use ONLY where a degraded answer collapsing to "no root" is an acceptable,
    /// non-security-relevant default (documented per call site in the `.cpp` of callers).
    [[nodiscard]] std::expected<std::optional<CaRoot>, std::string> get_root();

    /// Convenience wrapper over `get_root()` for callers where a degraded read collapsing to
    /// "false" is an acceptable, conservative default (a background CRL-freshness sweep skipping
    /// a tick; the `/readyz` `ca_root` signal, where "can't prove a root exists" SHOULD read as
    /// unhealthy anyway). **Never use this to gate a decision to (re)generate or replace the root**
    /// — `default_certs.cpp`'s B-2 re-root guard calls `get_root()` directly for exactly this
    /// reason: a DB blip collapsing to "no root" there would let a fresh CA generation proceed and
    /// silently re-root a fleet that already has one.
    [[nodiscard]] bool has_root();

    /// Unconditionally REPLACES the root row (id=1) — the pre-migration `INSERT OR REPLACE`
    /// contract, kept verbatim for the two callers that legitimately intend an unconditional
    /// replace: PR6 subordinate-CA import (`ServerImpl::import_subordinate_chain`, an explicit,
    /// single-writer, operator-triggered re-root of an ALREADY-established root) and test seeding.
    /// **Never call this from first-boot root generation** — two instances racing this call over a
    /// shared Postgres would have the later writer silently clobber the earlier one's root
    /// (orphaning every agent enrolled under it in the instant between). Use `try_insert_root()`
    /// there. `unexpected("empty cert/key_ref")` on an invalid root; `unexpected(msg)` (prefixed
    /// `kCaDbErrorPrefix`) is a genuine write failure.
    [[nodiscard]] std::expected<void, std::string> set_root(const CaRoot& root);

    /// Race-safe first-boot root establishment (ADR-0053). `ON CONFLICT (id) DO NOTHING` — at
    /// most one caller's row is ever inserted. Returns the root now on file: the caller's own
    /// `root` echoed back if it won the race, or the ALREADY-ESTABLISHED root (some other writer's)
    /// if it lost. **The caller MUST compare the returned fingerprint against what it generated to
    /// learn which happened — never locally infer "I won" from anything but this return value.**
    /// A losing caller's own already-generated key material is NOT retroactively usable (nobody
    /// else holds its private key) — the caller's job on a loss is to discard its attempt and
    /// refuse to proceed as authoritative, not to keep operating under material nobody else
    /// recognises. `unexpected(msg)` (prefixed `kCaDbErrorPrefix`) is a genuine DB failure — the
    /// caller must NOT treat that as "I won" or "lost", only as "undetermined, retry/abort".
    [[nodiscard]] std::expected<CaRoot, std::string> try_insert_root(const CaRoot& root);

    // ── Issued inventory ────────────────────────────────────────────────────────

    /// Records a newly issued certificate. `unexpected("duplicate_serial: ...")` on a serial
    /// collision (PG unique-violation SQLSTATE 23505 on `ca_issued.serial_hex`) — the caller
    /// (server.cpp) treats ANY failure here as fail-closed (does not hand out an unrecorded cert),
    /// but a duplicate-serial collision is specifically retryable (mint a fresh serial and retry
    /// issuance) rather than a genuine outage; see the `.cpp` file header for #1276. Any other
    /// `unexpected(msg)` (prefixed `kCaDbErrorPrefix`) is a genuine write failure.
    [[nodiscard]] std::expected<void, std::string> record_issued(const IssuedCertRecord& rec);

    /// `nullopt` = a successful read finding no such serial (or a non-hex serial — there is no
    /// such cert). `unexpected(msg)` (prefixed `kCaDbErrorPrefix`) is a genuine read failure.
    [[nodiscard]] std::expected<std::optional<IssuedCertRecord>, std::string>
    get_issued(const std::string& serial_hex);

    /// Newest-issued-first, `limit` clamped to [1, 10000] (bounded materialisation, matches the
    /// ladder's UP-5 precedent). `unexpected(msg)` (prefixed `kCaDbErrorPrefix`) is a genuine read
    /// failure; an empty inventory still returns success with an empty vector.
    [[nodiscard]] std::expected<std::vector<IssuedCertRecord>, std::string>
    list_issued(int limit = 200, int offset = 0);

    /// "Certificates issued by THIS CA", keyed on the STABLE pki::issuer_key_id (#1296) — NOT
    /// issuer_fingerprint, which a subordinate re-key would split into two values over one key and
    /// silently orphan the older population. An empty `issuer_key_id` returns an empty vector (the
    /// unpopulated-row sentinel is not a CA identity — see IssuedCertRecord::issuer_key_id).
    [[nodiscard]] std::expected<std::vector<IssuedCertRecord>, std::string>
    list_issued_by_key_id(const std::string& issuer_key_id, int limit = 200, int offset = 0);

    /// Revoke a cert. `Ok(true)` = a row transitioned Active → Revoked. `Ok(false)` = a genuine,
    /// successful business answer — the serial is unknown or already revoked (idempotent
    /// reject-without-state-change; callers audit this as `result=denied`, per
    /// `docs/pki-architecture.md`). `unexpected(msg)` (prefixed `kCaDbErrorPrefix`) is a genuine
    /// write failure — callers MUST NOT fold this into the `Ok(false)` case: doing so would
    /// falsely audit a database outage as "serial not found" (a false compliance record).
    [[nodiscard]] std::expected<bool, std::string> revoke(const std::string& serial_hex,
                                                           const std::string& reason);

    /// True iff the presented serial is one of ours and currently revoked. **Deliberately stays a
    /// plain `bool`, not `std::expected`** — this is the mTLS-accept security gate
    /// (`is_peer_cert_revoked`), and the fail-closed contract IS the type: every degradation mode
    /// (a non-hex serial, a lease timeout, a query error) returns `true` ("treat as revoked,
    /// refuse") rather than exposing a third state a caller could accidentally fold into "not
    /// revoked" (mirrors `ApiTokenStore::validate_token`'s hot-path-degrades-to-the-safe-answer
    /// precedent). **Operational note:** during a sustained Postgres outage this means EVERY
    /// heartbeat/Subscribe/Register-reauth is rejected fleet-wide, not just genuinely-revoked
    /// agents — an operator must be able to tell "mass rejection because the DB is down" from
    /// "mass rejection because of a real revocation sweep" from logs/metrics alone, since the
    /// return value itself cannot distinguish them; see the `.cpp` for the distinct log line this
    /// degradation emits.
    [[nodiscard]] bool is_revoked(const std::string& serial_hex);

    /// The full currently-revoked set — feeds CRL construction directly. `unexpected(msg)`
    /// (prefixed `kCaDbErrorPrefix`) is a genuine read failure; **callers MUST treat this as an
    /// abort-the-publish signal, never as "empty = nobody is revoked"** — publishing a CRL built
    /// from a silently-empty read would un-revoke every real revocation in every cache that trusts
    /// it (ADR-0036; ADR-0053 "CRL version continuity").
    [[nodiscard]] std::expected<std::vector<IssuedCertRecord>, std::string> list_revoked();

    /// Serials-only revoked set — same WHERE clause as `list_revoked()` but no `cert_pem`
    /// (unbounded blob, grows forever — nothing prunes `ca_issued`) and no `ORDER BY` (CRL
    /// construction needs a stable, complete row set; the revocation-SWEEP caller below only
    /// needs set membership). Gate 8 fix (unhappy-path, 2026-08-21): the ~15s revocation-sweep
    /// tick used to share `list_revoked()` with CRL publishing, and that heavier query failing
    /// under load/lock contention while the cheaper point-lookup `is_revoked()` kept succeeding
    /// was a real, nameable corridor where the sweep silently stopped tearing down live streams
    /// for already-revoked agents while new connections were still correctly gated — a security
    /// control quietly not holding, not merely an availability blip. Same abort-never-empty
    /// contract as `list_revoked()`: `unexpected(msg)` is a genuine read failure, never "nobody
    /// is revoked".
    [[nodiscard]] std::expected<std::vector<std::string>, std::string> list_revoked_serials();

    /// Delete all issued-cert rows with the given issued_by — used to purge stale default-cert
    /// inventory on regeneration so the store reflects only the live set. Best-effort / non-fatal
    /// by design (the caller already logs+continues on failure — a purge miss leaves stale rows,
    /// not a security or correctness defect); stays a plain `bool`.
    [[nodiscard]] bool delete_issued_by(const std::string& issued_by);

    // ── CRL versions ────────────────────────────────────────────────────────────

    /// Next CRL sequence number = MAX(version)+1, as a plain read. NOT an allocator: the number
    /// can be taken by another publisher (on this or any other replica) before a caller inserts
    /// it. Production publishing goes through `publish_next_crl`, which allocates under a table
    /// lock inside its own transaction. `unexpected(msg)` (prefixed `kCaDbErrorPrefix`) is a
    /// genuine read failure — never substitute a default number (ADR-0053 "CRL version
    /// continuity").
    [[nodiscard]] std::expected<std::uint64_t, std::string> next_crl_number();

    /// Persist a CRL version with a caller-chosen number (test seeding / import). Plain INSERT
    /// (never "ON CONFLICT ... DO UPDATE"): a duplicate version is refused, never a silent
    /// clobber of an existing generation. Takes the ROW EXCLUSIVE lock, so it also queues behind
    /// an in-flight `publish_next_crl`.
    [[nodiscard]] bool record_crl(const CrlVersionRecord& rec);

    /// The most recently published CRL, if any. Both "genuinely none published yet" and "a
    /// genuine read failure" already degrade safely to the SAME caller behaviour (the public
    /// `GET /api/v1/ca/crl` route serves 503 either way rather than ever synthesizing/serving a
    /// wrong CRL) — verified against every call site before choosing to keep this a plain
    /// `std::optional` rather than `std::expected` (ADR-0053).
    [[nodiscard]] std::optional<CrlVersionRecord> latest_crl();

    /// What a `CrlBuilder` returns: the signed DER plus the validity window it signed.
    struct BuiltCrl {
        std::vector<uint8_t> der;
        int64_t this_update{0};
        int64_t next_update{0};
    };

    /// Builds and signs the CRL for an allocated `crl_number` over the supplied `revoked`
    /// inventory. Runs INSIDE `publish_next_crl`'s transaction while the CRL table lock is held,
    /// so it must be pure CPU work — load the CA key BEFORE calling `publish_next_crl`, never in
    /// here. Returning `nullopt` or empty DER aborts the publish (e.g. a bad serial — fail closed)
    /// and consumes no number. It must not call back into this store.
    using CrlBuilder = std::function<std::optional<BuiltCrl>(
        uint64_t crl_number, const std::vector<IssuedCertRecord>& revoked)>;

    /// The one production CRL publish path (HA WS-6 slice 6.1, closes #4126). One transaction:
    /// take `LOCK TABLE ca_store.ca_crl_versions IN SHARE ROW EXCLUSIVE MODE`, read MAX+1, read
    /// the revoked set, build, INSERT, COMMIT. The table lock serialises every publisher on every
    /// replica sharing the database, so crlNumbers are strictly increasing with no duplicates
    /// and no gaps, and each new CRL contains every revocation the previous one did. Not
    /// epoch-fenced: operator revocation publishes through here synchronously (two-dispatch-
    /// planes rule), and the lock alone is what makes concurrent publishers safe. `nullopt` on
    /// any failure (lock timeout, read failure, build abort, insert failure, lost COMMIT ack) —
    /// nothing is reported as published unless the transaction committed.
    [[nodiscard]] std::optional<CrlVersionRecord>
    publish_next_crl(const CrlBuilder& build, const std::string& issuer_fingerprint = {},
                     const std::string& issuer_key_id = {});

private:
    pg::PgPool& pool_;
    bool open_{false};
};

} // namespace yuzu::server
