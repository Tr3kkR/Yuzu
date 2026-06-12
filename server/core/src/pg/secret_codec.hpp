#pragma once

/// @file secret_codec.hpp
/// App-side envelope encryption for secret columns in the Postgres substrate
/// — the implementation of ADR-0010 (conformance spec; do not re-derive its
/// rules here). Each secret value is AES-256-GCM-encrypted under a fresh
/// per-value DEK; the DEK is wrapped by the install's KEK, which lives behind
/// the `KeyProvider` wrap/unwrap seam and never enters Postgres.
///
/// Blob v1 layout (all widths pinned by ADR-0010 §1; every field but
/// `ciphertext` fixed-width, so `ciphertext` is the remainder):
///
///   ver(1) || kek_version(4 BE) || wrap_nonce(12) || wrapped_dek(32) ||
///   wrap_tag(16) || data_nonce(12) || data_tag(16) || ciphertext
///
/// AAD binding (anti-swap): the payload AAD is the canonical serialization of
/// `(ver, store, table, column, row_pk)` — deliberately WITHOUT kek_version,
/// so re-wrap-only rotation never touches the payload tag (the #1333
/// fjarvis HIGH-1 bug class). The wrap AAD is the same tuple PLUS the
/// kek_version bytes, byte-identical to the blob field — a tampered blob
/// kek_version fails the wrap-layer tag check. Fields are u32-BE
/// length-prefixed (naive concatenation is exactly the swap class AAD exists
/// to defeat); BIGINT row PKs use the fixed 8-byte-BE canonical encoding.
///
/// Decrypt-failure semantics: fail closed at every caller — a failure is
/// surfaced, audited (identifiers only), and counted; it never degrades to
/// an empty secret. Encrypt failure means the surrounding store transaction
/// must abort — a failed encrypt never writes anything to the column.

#include "../key_provider.hpp"
#include "../secure_buffer.hpp"

#include <libpq-fe.h>

#include <cstdint>
#include <expected>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server::pg {

class SecretCodec {
public:
    // ── Blob v1 constants (public: tests + a future denormalized
    //    kek_version column both read the fixed header offsets) ────────────
    static constexpr std::uint8_t kBlobVersion = 1;
    static constexpr std::size_t kKekVersionOffset = 1; ///< 4 bytes, u32-BE
    static constexpr std::size_t kWrapNonceOffset = 5;
    static constexpr std::size_t kWrappedDekOffset = 17;
    static constexpr std::size_t kWrapTagOffset = 49;
    static constexpr std::size_t kDataNonceOffset = 65;
    static constexpr std::size_t kDataTagOffset = 77;
    static constexpr std::size_t kCiphertextOffset = 93;
    static constexpr std::size_t kMinBlobSize = kCiphertextOffset;
    // INVARIANT: the rotation/retirement header scans read kek_version at
    // its fixed offset WITHOUT checking the version byte — any future blob
    // v2 must keep kek_version at offset 1 or update those scans in the
    // same change (sec-I1).

    /// Failure-class taxonomy (ADR-0010 §1/§3). Appears in the server-side
    /// audit event and metric ONLY — external surfaces get one generic
    /// "unavailable" so no caller can distinguish decrypt-failure from
    /// not-found (existence/tamper oracle).
    enum class FailureClass {
        tag_mismatch,     ///< GCM auth failed — the tamper signal
        kek_unresolvable, ///< blob references a KEK version the provider can't supply
        malformed_blob,   ///< parse failure (short blob, unknown ver byte)
        crypto_failure,   ///< CSPRNG/EVP failure (encrypt side; never plaintext-writes)
    };
    [[nodiscard]] static std::string_view to_string(FailureClass cls);

    /// Codec error. `message` carries identifiers and class only — never
    /// ciphertext, plaintext, DEK, or key bytes (ADR zeroization/audit rule).
    struct Error {
        FailureClass cls;
        std::string message;
    };

    /// Boot-verification failure taxonomy (typed so callers and tests gate
    /// on the discriminant, never on message wording — governance qe-B1).
    /// The kind name is also the stable startup-log token operators alert
    /// on; `message` is the human-readable detail.
    /// The canonical fatal startup line is
    /// `to_string(kind) + ": " + message` — `message` does NOT repeat the
    /// token, so wiring code composes exactly one prefix (CON-S2).
    struct InitError {
        enum class Kind {
            kek_unresolvable, ///< registered version has no key material (backup skew / wrong dir / second server)
            kek_corrupt,      ///< key material present but fingerprint mismatch (torn/corrupt/foreign file)
            provider_failure, ///< generation/check-value failure (CSPRNG, storage)
            db_error,         ///< migration/query/commit failure
        } kind;
        std::string message;
    };
    [[nodiscard]] static std::string_view to_string(InitError::Kind kind);

    /// The identity tuple AAD binds to. Encrypted values are non-relocatable
    /// across any of these coordinates. Secret-bearing tables must use stable
    /// PKs; identity-changing migrations decrypt-and-re-encrypt, never copy
    /// blobs (ADR §1 stable-identity constraint).
    struct SecretId {
        std::string store; ///< Postgres schema / store namespace
        std::string table;
        std::string column;
        /// Canonical pk bytes: BIGINT via encode_bigint_pk; TEXT pks pass
        /// the raw string bytes directly (byte-identical to what the
        /// binary-format libpq rotation scan reads back). Never decimal-
        /// format a BIGINT pk.
        std::string row_pk;
    };
    /// Canonical 8-byte-BE encoding for BIGINT primary keys.
    [[nodiscard]] static std::string encode_bigint_pk(std::int64_t pk);

    /// A registered secret-bearing column — the rotation scan,
    /// oldest_kek_version_in_use() and retirement refusal all walk this
    /// registry. Identifiers are validated (lowercase SQL identifier rule)
    /// at registration. No pk-type discriminator is needed: scans use
    /// binary libpq results, whose bytes ARE the canonical AAD encoding for
    /// every supported pk type (BIGINT → 8-byte BE, TEXT → raw bytes).
    struct SecretColumn {
        std::string store; ///< Postgres schema
        std::string table;
        std::string column;
        std::string pk_column;
    };

    explicit SecretCodec(KekProvider& provider);

    SecretCodec(const SecretCodec&) = delete;
    SecretCodec& operator=(const SecretCodec&) = delete;

    /// Substrate-level boot init — call BEFORE stores open (ADR §2):
    /// runs the `secrets` schema migration (kek_meta fingerprint table),
    /// first-boot KEK generation (`secrets-kek-v1`), and verifies every
    /// registered, non-retired kek_version resolves through the provider to
    /// material matching its fingerprint. Distinct error tokens —
    /// `kek_unresolvable` (backup skew, wrong keys dir, second server
    /// against a shared database) vs `kek_corrupt` (torn/corrupt file) — so
    /// operators triage separately from "DB down". Any failure is the
    /// startup_failed() class: a loudly-down server over one silently
    /// serving with unreadable secrets.
    ///
    /// WIRING OBLIGATION (governance Pattern E): an init() error must abort
    /// the server (startup_failed). If the codec is ever constructed with
    /// init() deferred, `active_kek_version() > 0` must join the /readyz and
    /// /healthz stores_ok conjunctions — a constructed-but-uninitialized
    /// codec fails every encrypt.
    [[nodiscard]] std::expected<void, InitError> init(PGconn* conn);

    /// Newest non-retired KEK version (encrypts use this). 0 before init.
    [[nodiscard]] std::uint32_t active_kek_version() const;

    /// Register a secret-bearing column. Returns false (and registers
    /// nothing) if any identifier fails the SQL-identifier rule.
    [[nodiscard]] bool register_secret_column(SecretColumn col);

    // ── Per-value operations ────────────────────────────────────────────────

    /// Encrypt one value: fresh DEK + fresh nonces per call (a DEK encrypts
    /// exactly one value exactly once — updating a secret mints a fresh DEK,
    /// never DEK reuse under a new nonce). On error the caller MUST abort
    /// the surrounding store write/transaction.
    [[nodiscard]] std::expected<std::vector<std::uint8_t>, Error>
    encrypt(const SecretId& id, std::span<const std::uint8_t> plaintext);

    /// Decrypt one blob. Failures are audited (identifiers only) + counted
    /// before returning. NULL/absent-column handling is the STORE's duty
    /// (hard error, never "no auth" — ADR §1 anti-downgrade); the codec only
    /// sees bytes that exist.
    [[nodiscard]] std::expected<SecureBuffer, Error> decrypt(const SecretId& id,
                                                             std::span<const std::uint8_t> blob);

    /// Re-wrap a blob's DEK under `to_version` WITHOUT touching the payload
    /// (data_nonce/data_tag/ciphertext are copied verbatim — the rotation
    /// invariant fjarvis's #1333 reproduction pinned).
    [[nodiscard]] std::expected<std::vector<std::uint8_t>, Error>
    rewrap(const SecretId& id, std::span<const std::uint8_t> blob, std::uint32_t to_version);

    // ── KEK lifecycle (ADR §3) ──────────────────────────────────────────────

    /// Mint `secrets-kek-v<N+1>`, register its fingerprint (mint+register
    /// is serialized under the substrate advisory lock and one transaction),
    /// then re-wrap every registered row (rewrap_all). Returns the new
    /// version. Rotation is incremental and interruptible — a crash
    /// mid-rotation is resumed by calling rewrap_all(); re-runs detect
    /// already-rotated rows by the blob header version, never by value.
    /// NOTE: if an error is returned AFTER the new version registered (a
    /// rewrap_all failure), active_version_ has already advanced — new
    /// encrypts use the new KEK; call rewrap_all() to finish, never
    /// rotate_kek again.
    [[nodiscard]] std::expected<std::uint32_t, std::string> rotate_kek(PGconn* conn);

    /// Re-wrap every registered row not already on the active version.
    /// Compare-and-swap per row (`WHERE <col> = <bytes read>`): a plain
    /// write would silently revert an operator's mid-rotation secret update
    /// to the old value under the new KEK. CAS losers are skipped (the
    /// concurrent writer encrypted under the active version anyway) and
    /// counted in the return. Returns rows re-wrapped.
    [[nodiscard]] std::expected<std::size_t, std::string> rewrap_all(PGconn* conn);

    /// Smallest kek_version any stored blob still references (header scan of
    /// every registered column — scan-trivial at our volumes, ADR §3), or
    /// nullopt when no secret rows exist. The operator's rotation-complete /
    /// safe-retirement signal.
    [[nodiscard]] std::expected<std::optional<std::uint32_t>, std::string>
    oldest_kek_version_in_use(PGconn* conn);

    /// Retire an old KEK version: refused while it is the active version or
    /// while ANY stored blob still references it (premature retirement is
    /// permanent loss of every un-rewrapped row). Marks `retired_at` in
    /// kek_meta (destruction evidence — the row is never deleted) and
    /// deletes the key from provider storage. The backup-honoring condition
    /// (ADR §3 (b)) is the operator's call via the runbook — it cannot be
    /// checked here.
    [[nodiscard]] std::expected<void, std::string> retire_kek(PGconn* conn, std::uint32_t version);

    // ── Observability seams ─────────────────────────────────────────────────

    /// Audit hook for the ADR §3 taxonomy verbs: `kek.generated`,
    /// `kek.rotated`, `kek.retired`, `secret.decrypt_failure`. `detail_json`
    /// carries identifiers only (AAD tuple coordinates, kek_version, failure
    /// class). Wiring to the AuditStore happens where the codec is
    /// constructed (the per-store migration PRs); unset = no-op.
    ///
    /// Lifetime: whatever the hook captures must outlive the codec, or the
    /// wiring must `set_audit_hook({})` before destroying the target.
    /// Attribution: codec-level events are system-attributed — operator
    /// attribution for rotate/retire rides the ROUTE-level audit event of
    /// the surface that invoked them (decided at design review, arch-7).
    using AuditHook = std::function<void(std::string_view verb, const std::string& detail_json)>;
    void set_audit_hook(AuditHook hook);

    /// Cumulative decrypt-failure counts keyed by (store, failure class) —
    /// the backing data for
    /// `yuzu_server_secret_decrypt_failures_total{store, failure_class}`
    /// (named per the docs/observability-conventions.md rules; register it
    /// there when the wiring PR exposes it); the metrics endpoint reads
    /// this when the codec is wired into ServerImpl.
    [[nodiscard]] std::vector<std::pair<std::pair<std::string, FailureClass>, std::uint64_t>>
    decrypt_failure_counts() const;

private:
    KekProvider& provider_;

    mutable std::mutex mu_;
    std::uint32_t active_version_{0};
    std::map<std::uint32_t, std::string> key_refs_; ///< non-retired version → opaque key_ref
    std::vector<SecretColumn> columns_;
    AuditHook audit_hook_;
    std::map<std::pair<std::string, FailureClass>, std::uint64_t> failure_counts_;

    /// Record + audit a DECRYPT-side failure (`secret.decrypt_failure`
    /// verb + metric counter), then build the Error.
    [[nodiscard]] Error fail(const SecretId& id, FailureClass cls, std::uint32_t kek_version,
                             std::string_view what);

    /// Encrypt-side failure: logged and returned, but NOT audited/counted
    /// under the decrypt-failure taxonomy (the metric is
    /// secret_decrypt_failures; an encrypt failure aborts the caller's
    /// transaction instead — ADR §1 encrypt-failure semantics).
    [[nodiscard]] static Error fail_encrypt(const SecretId& id, FailureClass cls,
                                            std::string_view what);

    void emit_audit(std::string_view verb, const std::string& detail_json);
};

} // namespace yuzu::server::pg
