#pragma once

/// @file ca_store.hpp
/// SQLite-backed inventory + lifecycle store for Yuzu's internal CA (`ca.db`).
///
/// Holds METADATA ONLY: the root certificate, the issued-cert inventory, and
/// the CRL version history. The root PRIVATE KEY is NOT stored here — it lives
/// behind a `KeyProvider` (a 0600 file in Milestone 1) and only its opaque
/// `key_ref` is persisted in `ca_root`. This keeps the crown-jewel key out of
/// the database blast radius and lets a future HSM swap leave `ca.db` untouched.
///
/// Threading: a single connection guarded by one std::mutex. The CA store is
/// low-traffic (issuance at enrollment, revocation by an operator), so coarse
/// serialisation is the right trade — and it sidesteps the FULLMUTEX
/// `sqlite3_changes()` data race (#1033) entirely. The one place a change-count
/// matters (revoke) uses `RETURNING`, never `sqlite3_changes()`.

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

struct sqlite3;

namespace yuzu::server {

/// Trust-source mode of the issuing CA. Builtin = self-signed install root
/// (M1). Subordinate = intermediate signed by an enterprise root (PR6).
enum class CaMode {
    Builtin,
    Subordinate,
};
std::string ca_mode_to_string(CaMode m);
CaMode ca_mode_from_string(const std::string& s);

struct CaRoot {
    std::string cert_pem;
    std::string key_ref; ///< Opaque KeyProvider reference — never the key itself.
    std::string algo;    ///< "EcP384" / "EcP256".
    int64_t not_before{0};
    int64_t not_after{0};
    std::string fingerprint_sha256;
    CaMode mode{CaMode::Builtin};
    int64_t created_at{0};
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
};

struct CrlVersionRecord {
    int64_t version{0};
    std::vector<uint8_t> der;
    int64_t this_update{0};
    int64_t next_update{0};
    int64_t published_at{0};
};

class CaStore {
public:
    explicit CaStore(const std::filesystem::path& db_path);
    ~CaStore();
    CaStore(const CaStore&) = delete;
    CaStore& operator=(const CaStore&) = delete;

    [[nodiscard]] bool is_open() const;

    // ── Root ──────────────────────────────────────────────────────────────────
    [[nodiscard]] bool has_root();
    [[nodiscard]] std::optional<CaRoot> get_root();
    /// Persist the single root row (id = 1). Replaces any existing root — used
    /// once at first-boot generation and again on subordinate-CA import (PR6).
    [[nodiscard]] bool set_root(const CaRoot& root);

    // ── Issued inventory ────────────────────────────────────────────────────────
    [[nodiscard]] bool record_issued(const IssuedCertRecord& rec);
    [[nodiscard]] std::optional<IssuedCertRecord> get_issued(const std::string& serial_hex);
    [[nodiscard]] std::vector<IssuedCertRecord> list_issued(int limit = 200, int offset = 0);
    /// Revoke a cert. Returns true iff a row transitioned Active → Revoked; an
    /// already-revoked or unknown serial returns false (idempotent).
    [[nodiscard]] bool revoke(const std::string& serial_hex, const std::string& reason);
    [[nodiscard]] bool is_revoked(const std::string& serial_hex);
    [[nodiscard]] std::vector<IssuedCertRecord> list_revoked();

    // ── CRL versions ────────────────────────────────────────────────────────────
    [[nodiscard]] uint64_t next_crl_number();
    [[nodiscard]] bool record_crl(const CrlVersionRecord& rec);
    [[nodiscard]] std::optional<CrlVersionRecord> latest_crl();

private:
    sqlite3* db_{nullptr};
    std::mutex mu_;

    void run_migrations();
};

} // namespace yuzu::server
