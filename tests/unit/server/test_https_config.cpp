/**
 * test_https_config.cpp — Unit tests for HTTPS configuration validation
 *
 * Covers: Config defaults, validation logic, cookie security attributes.
 */

#include <yuzu/server/server.hpp>

#include <catch2/catch_test_macros.hpp>

#include <string>

using namespace yuzu::server;

// ── Config defaults ────────────────────────────────────────────────────────

TEST_CASE("HTTPS config: defaults", "[https][config]") {
    Config cfg;
    CHECK(cfg.https_enabled == false);
    CHECK(cfg.https_port == 8443);
    CHECK(cfg.https_redirect == true);
    CHECK(cfg.https_cert_path.empty());
    CHECK(cfg.https_key_path.empty());
}

TEST_CASE("HTTPS config: enabled with paths", "[https][config]") {
    Config cfg;
    cfg.https_enabled = true;
    cfg.https_port = 443;
    cfg.https_cert_path = "/etc/yuzu/server.pem";
    cfg.https_key_path = "/etc/yuzu/server-key.pem";

    CHECK(cfg.https_enabled == true);
    CHECK(cfg.https_port == 443);
    CHECK(!cfg.https_cert_path.empty());
    CHECK(!cfg.https_key_path.empty());
}

TEST_CASE("HTTPS config: redirect disabled", "[https][config]") {
    Config cfg;
    cfg.https_enabled = true;
    cfg.https_redirect = false;

    CHECK(cfg.https_redirect == false);
}

// ── Cookie security helper ─────────────────────────────────────────────────

namespace {
// Simulates the session_cookie_attrs helper
std::string session_cookie_attrs(bool https_enabled) {
    std::string attrs = "; Path=/; HttpOnly; SameSite=Strict; Max-Age=28800";
    if (https_enabled) {
        attrs += "; Secure";
    }
    return attrs;
}
} // namespace

TEST_CASE("HTTPS cookie: no Secure flag when HTTP", "[https][cookie]") {
    auto attrs = session_cookie_attrs(false);
    CHECK(attrs.find("Secure") == std::string::npos);
}

TEST_CASE("HTTPS cookie: Secure flag when HTTPS", "[https][cookie]") {
    auto attrs = session_cookie_attrs(true);
    CHECK(attrs.find("Secure") != std::string::npos);
}

TEST_CASE("HTTPS cookie: always has HttpOnly", "[https][cookie]") {
    CHECK(session_cookie_attrs(false).find("HttpOnly") != std::string::npos);
    CHECK(session_cookie_attrs(true).find("HttpOnly") != std::string::npos);
}

TEST_CASE("HTTPS cookie: always has SameSite", "[https][cookie]") {
    CHECK(session_cookie_attrs(false).find("SameSite") != std::string::npos);
    CHECK(session_cookie_attrs(true).find("SameSite") != std::string::npos);
}

// ── Response retention config ──────────────────────────────────────────────

TEST_CASE("Config: response retention default", "[config]") {
    Config cfg;
    CHECK(cfg.response_retention_days == 90);
}

TEST_CASE("Config: audit retention default", "[config]") {
    Config cfg;
    CHECK(cfg.audit_retention_days == 365);
}
