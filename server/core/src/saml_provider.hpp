#pragma once

/**
 * saml_provider.hpp — SAML 2.0 SP core verifier library
 *
 * Thread-safe. On Windows, all methods are stubs that return disabled/error
 * (Non-Negotiable #4 — never return success-without-verify on any platform).
 *
 * Security invariants enforced by this library (all 4 non-negotiables):
 *   N1: Signature verified against PINNED IdP cert only. In-document KeyInfo
 *       is IGNORED entirely (dsigCtx->signKey set directly before verify —
 *       bypasses key discovery from the document).
 *   N2: XSW (signature-wrapping) binding: document must contain exactly one
 *       <saml:Assertion>; the verified Reference URI must be "#<that assertion's
 *       ID>"; NameID/Conditions are read ONLY from the verified assertion node.
 *   N3: Full condition validation: Status/Success, NotBefore/NotOnOrAfter,
 *       AudienceRestriction, SubjectConfirmationData Recipient + NotOnOrAfter +
 *       InResponseTo (tracked, consumed on use, replay-protected).
 *   N4: Windows compile-time stubs — is_enabled()→false,
 *       validate_response()→std::unexpected, build_authn_request()→"".
 */

#include <chrono>
#include <expected>
#include <mutex>
#include <string>
#include <unordered_map>

namespace yuzu::server::saml {

/// Configuration for the SAML 2.0 SP. All string fields are UTF-8.
struct SamlConfig {
    std::string idp_entity_id;  ///< IdP entityID — must match Issuer in assertions
    std::string idp_sso_url;    ///< IdP SSO endpoint for HTTP-Redirect binding
    std::string sp_entity_id;   ///< SP entityID — used as Audience in assertions
    std::string sp_acs_url;     ///< SP Assertion Consumer Service URL
    std::string idp_cert_pem;   ///< PEM-encoded IdP signing certificate (PINNED KEY — N1)
    bool        enabled{false};
};

/// Claims extracted from a verified SAML assertion.
/// attributes map is empty in this thin slice (follow-up: populate from AttributeStatement).
struct SamlAssertion {
    std::string name_id;
    // std::map<std::string, std::string> attributes; // follow-up
};

/// SAML 2.0 SP verifier — pure library, no HTTP routes, no session minting.
///
/// Construct at startup (before request threads spin up) — the underlying
/// xmlsec1 global init is not thread-safe; after first construction it is
/// idempotent.
class SamlProvider {
public:
    explicit SamlProvider(SamlConfig config);
    ~SamlProvider();

    // Non-copyable, non-movable (mutex + xmlsec state)
    SamlProvider(const SamlProvider&) = delete;
    SamlProvider& operator=(const SamlProvider&) = delete;

    /// Returns true only when enabled flag is set AND idp_cert_pem is non-empty.
    bool is_enabled() const;

    /// Result of build_authn_request.
    /// Both fields are empty strings when the provider is not enabled.
    struct AuthnRequestResult {
        std::string url;            ///< Full IdP redirect URL
        std::string cookie_secret;  ///< 32-byte CSPRNG secret (hex) for the binding cookie
    };

    /// Build an AuthnRequest redirect URL (HTTP-Redirect binding).
    /// Generates a random request ID and a CSPRNG binding secret, stores
    /// SHA-256(secret) alongside the expiry for InResponseTo validation,
    /// raw-DEFLATEs the XML, base64-encodes, URL-encodes, and appends relay_state.
    /// Note: AuthnRequest signing is a follow-up (not required for basic interop).
    /// @returns AuthnRequestResult with url + cookie_secret; both empty if not enabled.
    AuthnRequestResult build_authn_request(const std::string& relay_state);

    /// Validate a base64-encoded SAMLResponse (POST binding).
    /// Performs all four non-negotiable security checks plus browser-binding
    /// verification: SHA-256(cookie_secret) must match the hash stored when
    /// the corresponding AuthnRequest was issued.
    /// @param saml_response_b64  Base64-encoded SAMLResponse POST parameter.
    /// @param cookie_secret      Raw binding secret from the __Host-yuzu_saml_bind cookie.
    std::expected<SamlAssertion, std::string> validate_response(
        const std::string& saml_response_b64,
        const std::string& cookie_secret);

    /// Purge expired pending AuthnRequest IDs (call periodically).
    void cleanup_expired_states();

private:
    void cleanup_expired_states_locked(); ///< Must be called with mu_ held.

    SamlConfig config_;
    mutable std::mutex mu_;

    /// Tracks issued AuthnRequest IDs → (expiry, binding_hash).
    /// binding_hash = SHA-256(cookie_secret) stored at request-issue time.
    /// Consumed on use (replay prevention).  Atomic under mu_ with validate_response.
    struct PendingRequest {
        std::chrono::steady_clock::time_point expiry;
        std::string binding_hash; ///< hex-encoded SHA-256 of the binding cookie secret
    };
    std::unordered_map<std::string, PendingRequest> pending_requests_;

    static constexpr auto kRequestTtl          = std::chrono::minutes(10);
    static constexpr std::size_t kMaxPendingRequests = 1000;
};

} // namespace yuzu::server::saml
