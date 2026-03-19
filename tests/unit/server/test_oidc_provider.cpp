/**
 * test_oidc_provider.cpp — Unit tests for OidcProvider
 *
 * Covers: base64url encode/decode, PKCE code_verifier/code_challenge,
 * JWT parsing, claim validation, auth flow URL generation, state lifecycle.
 */

#include "oidc_provider.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <string>

using namespace yuzu::server::oidc;

// ── Base64URL ────────────────────────────────────────────────────────────────

TEST_CASE("OIDC: base64url encode/decode roundtrip", "[oidc]") {
    std::vector<uint8_t> data = {0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD, 0x80, 0x7F};
    auto encoded = OidcProvider::base64url_encode(data);

    // Must not contain +, /, or =
    CHECK(encoded.find('+') == std::string::npos);
    CHECK(encoded.find('/') == std::string::npos);
    CHECK(encoded.find('=') == std::string::npos);

    auto decoded = OidcProvider::base64url_decode(encoded);
    REQUIRE(decoded.size() == data.size());
    for (size_t i = 0; i < data.size(); ++i)
        CHECK(static_cast<uint8_t>(decoded[i]) == data[i]);
}

TEST_CASE("OIDC: base64url decode without padding", "[oidc]") {
    // "Hello" in base64url is "SGVsbG8" (no padding)
    auto decoded = OidcProvider::base64url_decode("SGVsbG8");
    CHECK(decoded == "Hello");
}

TEST_CASE("OIDC: base64url encode empty input", "[oidc]") {
    auto encoded = OidcProvider::base64url_encode({});
    CHECK(encoded.empty());
    auto decoded = OidcProvider::base64url_decode("");
    CHECK(decoded.empty());
}

// ── PKCE ─────────────────────────────────────────────────────────────────────

TEST_CASE("OIDC: code_verifier length", "[oidc]") {
    auto verifier = OidcProvider::generate_code_verifier();
    // 32 bytes -> 43 base64url characters (no padding)
    CHECK(verifier.size() == 43);
    // Must only contain unreserved characters
    for (char c : verifier) {
        CHECK((std::isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_'));
    }
}

TEST_CASE("OIDC: code_challenge is deterministic for same verifier", "[oidc]") {
    auto verifier = OidcProvider::generate_code_verifier();
    auto c1 = OidcProvider::compute_code_challenge(verifier);
    auto c2 = OidcProvider::compute_code_challenge(verifier);
    CHECK(c1 == c2);
}

TEST_CASE("OIDC: code_challenge differs for different verifiers", "[oidc]") {
    auto v1 = OidcProvider::generate_code_verifier();
    auto v2 = OidcProvider::generate_code_verifier();
    // Two random verifiers should produce different challenges
    CHECK(v1 != v2);
    CHECK(OidcProvider::compute_code_challenge(v1) != OidcProvider::compute_code_challenge(v2));
}

TEST_CASE("OIDC: code_challenge against RFC 7636 Appendix B", "[oidc]") {
    // RFC 7636 test vector:
    //   code_verifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    //   code_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    auto challenge =
        OidcProvider::compute_code_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
    CHECK(challenge == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
}

// ── JWT parsing ──────────────────────────────────────────────────────────────

static std::string make_test_jwt(const std::string& payload_json) {
    // Encode a minimal JWT: header.payload.signature (fake signature)
    auto encode_part = [](const std::string& s) {
        std::vector<uint8_t> bytes(s.begin(), s.end());
        return OidcProvider::base64url_encode(bytes);
    };
    auto header = R"({"alg":"RS256","typ":"JWT"})";
    return encode_part(header) + "." + encode_part(payload_json) + ".fakesignature";
}

TEST_CASE("OIDC: parse valid ID token", "[oidc]") {
    auto jwt = make_test_jwt(R"({
        "sub": "user123",
        "email": "alice@example.com",
        "preferred_username": "alice",
        "name": "Alice Operator",
        "iss": "https://login.microsoftonline.com/tenant/v2.0",
        "aud": "my-client-id",
        "nonce": "abc123",
        "exp": 9999999999,
        "iat": 1700000000
    })");

    auto result = OidcProvider::parse_id_token(jwt);
    REQUIRE(result.has_value());
    CHECK(result->sub == "user123");
    CHECK(result->email == "alice@example.com");
    CHECK(result->preferred_username == "alice");
    CHECK(result->name == "Alice Operator");
    CHECK(result->iss == "https://login.microsoftonline.com/tenant/v2.0");
    CHECK(result->aud == "my-client-id");
    CHECK(result->nonce == "abc123");
    CHECK(result->exp == 9999999999);
    CHECK(result->iat == 1700000000);
}

TEST_CASE("OIDC: parse ID token with aud as array", "[oidc]") {
    auto jwt = make_test_jwt(R"({
        "sub": "user123",
        "aud": ["client-a", "client-b"],
        "iss": "https://issuer",
        "nonce": "n",
        "exp": 9999999999
    })");
    auto result = OidcProvider::parse_id_token(jwt);
    REQUIRE(result.has_value());
    CHECK(result->aud == "client-a");
}

TEST_CASE("OIDC: parse malformed JWT — no dots", "[oidc]") {
    auto result = OidcProvider::parse_id_token("nodots");
    CHECK_FALSE(result.has_value());
    CHECK(result.error().find("no dots") != std::string::npos);
}

TEST_CASE("OIDC: parse malformed JWT — one dot", "[oidc]") {
    auto result = OidcProvider::parse_id_token("one.dot");
    CHECK_FALSE(result.has_value());
    CHECK(result.error().find("only one dot") != std::string::npos);
}

TEST_CASE("OIDC: parse malformed JWT — invalid base64url payload", "[oidc]") {
    auto result = OidcProvider::parse_id_token("header.!!!invalid!!!.sig");
    CHECK_FALSE(result.has_value());
    CHECK(result.error().find("parse error") != std::string::npos);
}

// ── Claim validation ─────────────────────────────────────────────────────────

TEST_CASE("OIDC: validate_claims — valid", "[oidc]") {
    OidcConfig cfg;
    cfg.issuer = "https://issuer";
    cfg.client_id = "my-client";
    OidcProvider provider(std::move(cfg));

    IdTokenClaims claims;
    claims.iss = "https://issuer";
    claims.aud = "my-client";
    claims.nonce = "test-nonce";
    claims.exp = std::chrono::duration_cast<std::chrono::seconds>(
                     std::chrono::system_clock::now().time_since_epoch())
                     .count() +
                 3600;

    auto result = provider.validate_claims(claims, "test-nonce");
    CHECK(result.has_value());
}

TEST_CASE("OIDC: validate_claims — wrong issuer", "[oidc]") {
    OidcConfig cfg;
    cfg.issuer = "https://expected";
    cfg.client_id = "c";
    OidcProvider provider(std::move(cfg));

    IdTokenClaims claims;
    claims.iss = "https://wrong";
    claims.aud = "c";
    claims.nonce = "n";
    claims.exp = 9999999999;

    auto result = provider.validate_claims(claims, "n");
    CHECK_FALSE(result.has_value());
    CHECK(result.error().find("iss mismatch") != std::string::npos);
}

TEST_CASE("OIDC: validate_claims — wrong audience", "[oidc]") {
    OidcConfig cfg;
    cfg.issuer = "https://iss";
    cfg.client_id = "expected";
    OidcProvider provider(std::move(cfg));

    IdTokenClaims claims;
    claims.iss = "https://iss";
    claims.aud = "wrong";
    claims.nonce = "n";
    claims.exp = 9999999999;

    auto result = provider.validate_claims(claims, "n");
    CHECK_FALSE(result.has_value());
    CHECK(result.error().find("aud mismatch") != std::string::npos);
}

TEST_CASE("OIDC: validate_claims — expired token", "[oidc]") {
    OidcConfig cfg;
    cfg.issuer = "https://iss";
    cfg.client_id = "c";
    OidcProvider provider(std::move(cfg));

    IdTokenClaims claims;
    claims.iss = "https://iss";
    claims.aud = "c";
    claims.nonce = "n";
    claims.exp = 1000000000; // long expired

    auto result = provider.validate_claims(claims, "n");
    CHECK_FALSE(result.has_value());
    CHECK(result.error().find("expired") != std::string::npos);
}

TEST_CASE("OIDC: validate_claims — wrong nonce", "[oidc]") {
    OidcConfig cfg;
    cfg.issuer = "https://iss";
    cfg.client_id = "c";
    OidcProvider provider(std::move(cfg));

    IdTokenClaims claims;
    claims.iss = "https://iss";
    claims.aud = "c";
    claims.nonce = "actual";
    claims.exp = 9999999999;

    auto result = provider.validate_claims(claims, "expected");
    CHECK_FALSE(result.has_value());
    CHECK(result.error().find("nonce mismatch") != std::string::npos);
}

// ── Auth flow ────────────────────────────────────────────────────────────────

TEST_CASE("OIDC: start_auth_flow generates valid URL", "[oidc]") {
    OidcConfig cfg;
    cfg.issuer = "https://login.example.com/tenant/v2.0";
    cfg.client_id = "test-client-id";
    cfg.redirect_uri = "http://localhost:8443/auth/callback";
    cfg.authorization_endpoint = cfg.issuer + "/authorize";
    cfg.token_endpoint = cfg.issuer + "/token";
    OidcProvider provider(std::move(cfg));

    auto url = provider.start_auth_flow();

    CHECK(url.starts_with("https://login.example.com/tenant/v2.0/authorize?"));
    CHECK(url.find("client_id=test-client-id") != std::string::npos);
    CHECK(url.find("response_type=code") != std::string::npos);
    CHECK(url.find("code_challenge=") != std::string::npos);
    CHECK(url.find("code_challenge_method=S256") != std::string::npos);
    CHECK(url.find("state=") != std::string::npos);
    CHECK(url.find("nonce=") != std::string::npos);
    CHECK(url.find("redirect_uri=") != std::string::npos);
}

TEST_CASE("OIDC: cleanup_expired_states removes old entries", "[oidc]") {
    OidcConfig cfg;
    cfg.issuer = "https://iss";
    cfg.client_id = "c";
    cfg.redirect_uri = "http://localhost/cb";
    cfg.authorization_endpoint = cfg.issuer + "/authorize";
    cfg.token_endpoint = cfg.issuer + "/token";
    OidcProvider provider(std::move(cfg));

    // Start a flow to create a pending challenge
    auto url = provider.start_auth_flow();
    (void)url;

    // Cleanup should not remove it (not yet expired)
    provider.cleanup_expired_states();

    // Try handle_callback with a bogus state — should fail with "unknown"
    auto result = provider.handle_callback("fakecode", "bogus-state");
    CHECK_FALSE(result.has_value());
    CHECK(result.error().find("unknown") != std::string::npos);
}

TEST_CASE("OIDC: handle_callback with unknown state fails", "[oidc]") {
    OidcConfig cfg;
    cfg.issuer = "https://iss";
    cfg.client_id = "c";
    cfg.redirect_uri = "http://localhost/cb";
    cfg.authorization_endpoint = cfg.issuer + "/authorize";
    cfg.token_endpoint = cfg.issuer + "/token";
    OidcProvider provider(std::move(cfg));

    auto result = provider.handle_callback("code", "nonexistent-state");
    CHECK_FALSE(result.has_value());
    CHECK(result.error().find("unknown") != std::string::npos);
}
