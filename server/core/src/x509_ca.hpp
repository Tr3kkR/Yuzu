#pragma once

/// @file x509_ca.hpp
/// Pure-OpenSSL PKI engine for Yuzu's internal Certificate Authority.
///
/// This module is the single crypto primitive layer shared by the default-cert
/// bootstrap (`default_certs.*`), the issuance subsystem (`ca_store.*`), and the
/// per-agent enrollment signer (`agent_service_impl.cpp`). It has NO dependency
/// on SQLite, the server config, or any Yuzu store — it deals only in PEM/DER
/// strings and value types so it can be unit-tested in isolation and, later,
/// extracted into a lib shared with the agent (PR3) without dragging server
/// state along.
///
/// Algorithm policy (locked): ECDSA P-256 leaves, P-384 root. ECDSA is the
/// roadmap-aligned choice for the planned gRPC→QUIC move (#376): QUIC mandates
/// TLS 1.3, which treats ecdsa_secp256r1_sha256 / ecdsa_secp384r1_sha384 as
/// first-class, and the smaller certs cost fewer bytes under QUIC's
/// anti-amplification limit. The signature digest is chosen from the *issuer*
/// key strength (P-384 CA → SHA-384, P-256 → SHA-256).
///
/// Every function returns std::nullopt on failure and logs the OpenSSL error
/// stack via spdlog. The implementation is compiled only when OpenSSL is
/// available (`CPPHTTPLIB_OPENSSL_SUPPORT`, the project-wide signal that
/// libssl/libcrypto are linked — see `cert_reloader.cpp`); without it every
/// entry point returns std::nullopt so the build stays green on a
/// TLS-less configuration (which cannot serve HTTPS anyway).

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server::pki {

/// Elliptic-curve key strength. No RSA in Milestone 1 (documented add-on).
enum class KeyAlgo {
    EcP256, ///< prime256v1 / secp256r1 — leaves.
    EcP384, ///< secp384r1 — the install root / issuing CA.
};

/// Minimal distinguished name. Yuzu only ever sets CN (+ a fixed O); a richer
/// DN is unnecessary for an internal PKI and only widens the parse surface.
struct DistinguishedName {
    std::string common_name;
    std::string organization; ///< Defaults to "Yuzu" when empty at call sites.
};

/// Subject Alternative Names. IPs are textual ("127.0.0.1", "::1"); URIs carry
/// the agent identity ("yuzu://<install-id>/agent/<agent_id>").
struct SubjectAltNames {
    std::vector<std::string> dns;
    std::vector<std::string> ips;
    std::vector<std::string> uris;

    [[nodiscard]] bool empty() const {
        return dns.empty() && ips.empty() && uris.empty();
    }
};

/// Validity window. Callers build explicit time points; helpers below cover the
/// common "N years/days from now" cases so the call sites read cleanly.
struct Validity {
    std::chrono::system_clock::time_point not_before;
    std::chrono::system_clock::time_point not_after;
};

// Validity-window helpers. NOTE (SRE): leaf/CA expiry must be alerted on before
// it bites the fleet — root warn @365d / crit @90d; server leaf warn @30d /
// crit @7d. A follow-up PR wires the `yuzu_server_ca_*_expiry_seconds` gauges + alert
// rules. Assumes a 64-bit time_t (true for every current build target).
[[nodiscard]] Validity validity_years_from_now(int years);
[[nodiscard]] Validity validity_days_from_now(int days);

/// Extended-key-usage selection for a leaf. A leaf may be both server- and
/// client-auth (the default server leaves are server-auth only; agent leaves
/// are client-auth only).
struct LeafUsage {
    bool server_auth{false};
    bool client_auth{false};
    bool code_signing{false};
};

// ── Key generation ───────────────────────────────────────────────────────────

/// Generate an EC private key. Returns PKCS#8 PEM (unencrypted — storage-layer
/// encryption / file mode is the `key_provider`'s job, not ours).
[[nodiscard]] std::optional<std::string> generate_private_key(KeyAlgo algo);

// ── CA root ──────────────────────────────────────────────────────────────────

struct CaParams {
    DistinguishedName subject;
    Validity validity;
    /// basicConstraints pathlen. 0 = this CA may issue end-entity certs only
    /// (no sub-CAs beneath it) — correct for the single-tier install CA.
    int path_len{0};
};

/// Self-sign a CA root certificate over `ca_key_pem`. Sets
/// basicConstraints=critical,CA:TRUE,pathlen:N; keyUsage=critical,keyCertSign,
/// cRLSign; subjectKeyIdentifier; authorityKeyIdentifier=keyid,issuer.
[[nodiscard]] std::optional<std::string> self_sign_ca(std::string_view ca_key_pem,
                                                      const CaParams& params);

// ── CSR ──────────────────────────────────────────────────────────────────────

struct CsrParams {
    DistinguishedName subject;
    SubjectAltNames san;
};

/// Build a PKCS#10 CSR over `key_pem`, self-signed for proof-of-possession.
/// Used (a) agent-side for the per-agent client cert and (b) server-side to
/// export the install CA's CSR for an enterprise root to sign (subordinate-CA,
/// PR6).
[[nodiscard]] std::optional<std::string> make_csr(std::string_view key_pem,
                                                  const CsrParams& params);

// ── Leaf issuance ────────────────────────────────────────────────────────────

struct LeafParams {
    DistinguishedName subject; ///< Server-chosen subject (CN). See sign_csr note.
    SubjectAltNames san;       ///< Server-chosen SAN. See sign_csr note.
    Validity validity;
    LeafUsage usage;
    /// Caller-assigned serial as uppercase colon-free hex (e.g. from
    /// `ca_store`). Empty → the engine generates a random 128-bit serial and
    /// returns it in `IssuedCert::serial_hex`.
    std::string serial_hex;
};

struct IssuedCert {
    std::string cert_pem;
    std::string serial_hex; ///< The serial actually embedded (uppercase hex).
};

/// Sign an end-entity certificate from a CSR.
///
/// SECURITY: the CSR is used ONLY for its public key, and ONLY after its
/// self-signature is verified (proof the requester holds the matching private
/// key). The issued cert's subject, SAN, EKU, and validity come entirely from
/// `params` — the CSR's own subject/SAN are deliberately IGNORED. This is what
/// stops an enrolling agent from requesting another agent's identity: the
/// server sets CN=<agent_id> and the URI SAN itself from the authenticated
/// enrollment, never from attacker-controlled CSR fields.
[[nodiscard]] std::optional<IssuedCert> sign_csr(std::string_view csr_pem,
                                                 std::string_view ca_cert_pem,
                                                 std::string_view ca_key_pem,
                                                 const LeafParams& params);

struct KeyAndCert {
    std::string private_key_pem;
    std::string cert_pem;
    std::string serial_hex;
};

/// Generate a fresh leaf key and sign a leaf for it in one step. For the
/// server-side default leaves (HTTPS / agent-listener / gateway) where the
/// server legitimately holds the private key. Never used for agent client
/// certs — the agent generates its own key and only sends a CSR (so the server
/// never sees an agent private key).
[[nodiscard]] std::optional<KeyAndCert> issue_leaf(std::string_view ca_cert_pem,
                                                   std::string_view ca_key_pem, KeyAlgo leaf_algo,
                                                   const LeafParams& params);

// ── CRL ──────────────────────────────────────────────────────────────────────

struct CrlRevocation {
    std::string serial_hex; ///< Uppercase hex, matching IssuedCert::serial_hex.
    std::chrono::system_clock::time_point revoked_at;
};

/// Build a DER-encoded X.509 CRL signed by the CA. `crl_number` is the
/// monotonic CRL sequence (from `ca_store.ca_crl_versions`). Returns the DER
/// bytes for `GET /api/v1/ca/crl` and on-disk publication.
[[nodiscard]] std::optional<std::vector<uint8_t>> build_crl(
    std::string_view ca_cert_pem, std::string_view ca_key_pem,
    const std::vector<CrlRevocation>& revoked, const Validity& crl_validity, uint64_t crl_number);

// ── Inspection / verification ────────────────────────────────────────────────

/// SHA-256 fingerprint of the DER form of a PEM certificate, formatted as
/// uppercase colon-separated hex ("AB:CD:…"). This is the canonical
/// "which CA / cert is this" identifier surfaced in banners, /health, and audit.
[[nodiscard]] std::optional<std::string> fingerprint_sha256(std::string_view cert_pem);

struct CertDetails {
    DistinguishedName subject;
    DistinguishedName issuer;
    std::string serial_hex;
    std::chrono::system_clock::time_point not_before;
    std::chrono::system_clock::time_point not_after;
    SubjectAltNames san;
    bool is_ca{false};
};

[[nodiscard]] std::optional<CertDetails> parse_certificate(std::string_view cert_pem);

/// True iff `leaf_pem` verifies up to `ca_pem` as a trust anchor (signature +
/// validity period + basic-constraints path). Used by tests and by the
/// subordinate-CA import path (PR6) to confirm an uploaded chain actually signs
/// our CA public key.
///
/// NOTE: this does NOT consult the CRL / revocation status — a revoked cert
/// still returns true. Revocation is enforced separately (`CaStore::is_revoked`
/// at the mTLS-accept gate, PR3). Never use verify_chain alone as an admission
/// decision.
[[nodiscard]] bool verify_chain(std::string_view leaf_pem, std::string_view ca_pem);

} // namespace yuzu::server::pki
