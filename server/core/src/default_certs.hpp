#pragma once

/// @file default_certs.hpp
/// First-boot, zero-config certificate bootstrap (PKI PR2).
///
/// A fresh Yuzu install has no operator-provided certs. Rather than refuse to
/// start (the old behaviour, papered over everywhere with --no-tls --no-https),
/// the server generates a per-install internal CA + the server-side leaves on
/// first boot so every transport is encrypted with no operator action — while
/// making it impossible to miss that defaults are in use (see the six
/// notification surfaces wired in server.cpp / main.cpp).
///
/// Built on the PR1 engine: x509_ca (key/cert/CRL), key_provider (0600 key
/// custody), ca_store (inventory). No bundled/shared private keys — every
/// install generates its own root.

#include "ca_store.hpp"

#include <chrono>
#include <filesystem>
#include <string>

namespace yuzu::server {

/// Resolved on-disk locations + identity of the generated default cert set.
struct DefaultCertSet {
    std::filesystem::path ca_cert;     ///< default-ca.pem  (public root; also the mTLS CA bundle)
    std::filesystem::path https_cert;  ///< default-https.pem
    std::filesystem::path https_key;   ///< default-https.key (0600)
    std::filesystem::path server_cert; ///< default-server.pem (agent + mgmt gRPC listener)
    std::filesystem::path server_key;  ///< default-server.key (0600)
    std::filesystem::path gateway_cert; ///< default-gateway.pem (consumed by PR5)
    std::filesystem::path gateway_key;  ///< default-gateway.key (0600)
    std::string ca_fingerprint_sha256;  ///< colon-hex; surfaced in banner/health/audit
    std::chrono::system_clock::time_point ca_expires_at{};
    bool freshly_generated{false}; ///< true only on the boot that created the set
};

/// Ensure a complete default cert set exists under `dir`.
///
/// On first boot generates a per-install ECDSA P-384 root CA (10-year) and
/// P-256 leaves for the HTTPS, agent/management-gRPC, and gateway listeners.
/// Each leaf's SAN carries DNS:localhost, IP:127.0.0.1, IP:::1, DNS:<hostname>;
/// each leaf is sized to the CA's notAfter so it can never outlive the issuer.
/// A `default-marker.json` records {version, generated_at, ca_fingerprint,
/// expires_at, hostname}.
///
/// Idempotent: if the marker + every cert/key file exist and the CA cert's
/// fingerprint matches the marker, returns the existing set unchanged
/// (freshly_generated = false). If the marker is missing or anything is
/// corrupt/mismatched, regenerates the WHOLE set atomically (never a partial
/// state). When `ca_store` is non-null, records the root + each issued leaf in
/// the inventory (best-effort; a record failure is logged, not fatal).
///
/// Returns false only on an unrecoverable failure (e.g. keygen / signing /
/// filesystem error, or — when ca_store is non-null — a failed inventory write,
/// which is fatal so the inventory stays consistent for revocation/rotation) —
/// the caller should refuse to start rather than serve without the certs it
/// expected.
///
/// NOTES: default-marker.json is crash-recovery idempotency, NOT tamper evidence
/// (an attacker who can write the 0700 cert dir is already past the boundary; the
/// fast path still chain-verifies the leaves as a corruption check). Leaf SANs
/// cover localhost / loopback IPs / the detected hostname only — access by a LAN
/// IP or a non-hostname FQDN needs operator-provided certs or DNS. Leaves are
/// sized to the CA notAfter (10y) by design: there is no server-leaf
/// auto-renewal, so a short life would be a guaranteed future outage, and the
/// operator is loudly told to replace defaults.
[[nodiscard]] bool ensure_default_certs(const std::filesystem::path& dir,
                                        const std::string& hostname, CaStore* ca_store,
                                        DefaultCertSet& out);

} // namespace yuzu::server
