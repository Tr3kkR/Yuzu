#pragma once

#include <chrono>
#include <expected>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace yuzu::server::oidc {

struct OidcConfig {
    std::string issuer;
    std::string client_id;
    std::string client_secret; // Required for web platform (Entra confidential client)
    std::string redirect_uri;
    std::string authorization_endpoint;
    std::string token_endpoint;
    std::string exchange_script; // Path to oidc_token_exchange.py
    std::string admin_group_id;  // Entra group ID that maps to admin role

    bool is_enabled() const { return !issuer.empty() && !client_id.empty(); }
};

struct PkceChallenge {
    std::string code_verifier;
    std::string code_challenge;
    std::string state;
    std::string nonce;
    std::string redirect_uri; // The exact redirect_uri used for this flow
    std::chrono::steady_clock::time_point expires_at;
};

struct IdTokenClaims {
    std::string sub;
    std::string email;
    std::string preferred_username;
    std::string name;
    std::string iss;
    std::string aud;
    std::string nonce;
    int64_t exp{0};
    int64_t iat{0};
    std::vector<std::string> groups; // Entra security group object IDs
};

class OidcProvider {
public:
    explicit OidcProvider(OidcConfig config);

    bool is_enabled() const;

    /// Generate PKCE params, store them, return authorization URL for redirect.
    /// @param request_redirect_uri If non-empty, overrides the configured redirect_uri
    ///        (derived from the request Host header for multi-origin support).
    std::string start_auth_flow(const std::string& request_redirect_uri = {});

    /// Exchange authorization code for tokens, validate ID token, return claims.
    std::expected<IdTokenClaims, std::string> handle_callback(const std::string& code,
                                                              const std::string& state);

    /// Remove expired PKCE states.
    void cleanup_expired_states();

    // ── Exposed for unit testing ──────────────────────────────────────────
    static std::string base64url_encode(const std::vector<uint8_t>& data);
    static std::string base64url_decode(const std::string& input);
    static std::string generate_code_verifier();
    static std::string compute_code_challenge(const std::string& verifier);
    static std::expected<IdTokenClaims, std::string> parse_id_token(const std::string& jwt);

    std::expected<void, std::string> validate_claims(const IdTokenClaims& claims,
                                                     const std::string& expected_nonce) const;

private:
    static std::string url_encode(const std::string& value);

    std::expected<std::string, std::string> exchange_code(const std::string& code,
                                                          const std::string& code_verifier,
                                                          const std::string& redirect_uri);

    OidcConfig config_;
    std::string exchange_script_path_;
    mutable std::mutex mu_;
    std::unordered_map<std::string, PkceChallenge> pending_challenges_;

    static constexpr auto kChallengeTtl = std::chrono::minutes(10);
};

} // namespace yuzu::server::oidc
