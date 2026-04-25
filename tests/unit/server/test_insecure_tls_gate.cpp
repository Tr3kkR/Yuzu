// test_insecure_tls_gate.cpp — Pin the #79 second-confirmation gate.
//
// `--insecure-skip-client-verify` (formerly `--allow-one-way-tls`) requires
// `YUZU_ALLOW_INSECURE_TLS=1` in the environment as a second confirmation
// before the server is allowed to start with client cert verification
// disabled. The exact-match comparison is intentional: any "boolean-ish"
// permissiveness (`"true"`, `"yes"`, `"TRUE"`, `"0"`) creates a class of
// silent-misconfiguration bugs we want to make impossible.
//
// These tests pin the constants and the comparison logic so the gate can
// only be loosened by an explicit, reviewed change to the header.

#include "insecure_tls_gate.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string_view>

using yuzu::server::security::insecure_tls_env_authorized;
using yuzu::server::security::kInsecureTlsEnvAuthorizedValue;
using yuzu::server::security::kInsecureTlsEnvVar;

TEST_CASE("Insecure TLS gate: env var name is the documented constant",
          "[security][insecure_tls][issue79]") {
    // The CHANGELOG, SECURITY_REVIEW, Certificate Instructions, and the
    // dashboard all reference this exact env-var name. If a future refactor
    // renames it, those docs must be updated together with this constant.
    CHECK(kInsecureTlsEnvVar == std::string_view{"YUZU_ALLOW_INSECURE_TLS"});
}

TEST_CASE("Insecure TLS gate: authorized value is the literal '1'",
          "[security][insecure_tls][issue79]") {
    CHECK(kInsecureTlsEnvAuthorizedValue == std::string_view{"1"});
}

TEST_CASE("Insecure TLS gate: rejects nullptr", "[security][insecure_tls][issue79]") {
    CHECK_FALSE(insecure_tls_env_authorized(nullptr));
}

TEST_CASE("Insecure TLS gate: rejects empty string", "[security][insecure_tls][issue79]") {
    CHECK_FALSE(insecure_tls_env_authorized(""));
}

TEST_CASE("Insecure TLS gate: rejects '0'", "[security][insecure_tls][issue79]") {
    CHECK_FALSE(insecure_tls_env_authorized("0"));
}

TEST_CASE("Insecure TLS gate: rejects 'true' (any case)",
          "[security][insecure_tls][issue79]") {
    CHECK_FALSE(insecure_tls_env_authorized("true"));
    CHECK_FALSE(insecure_tls_env_authorized("True"));
    CHECK_FALSE(insecure_tls_env_authorized("TRUE"));
}

TEST_CASE("Insecure TLS gate: rejects 'yes', 'on', 'enabled'",
          "[security][insecure_tls][issue79]") {
    // Common boolean-ish values operators might paste in expecting them to
    // work. None of these authorize.
    CHECK_FALSE(insecure_tls_env_authorized("yes"));
    CHECK_FALSE(insecure_tls_env_authorized("on"));
    CHECK_FALSE(insecure_tls_env_authorized("enabled"));
}

TEST_CASE("Insecure TLS gate: rejects whitespace-padded '1'",
          "[security][insecure_tls][issue79]") {
    // Exact-match: leading or trailing whitespace must not authorize.
    CHECK_FALSE(insecure_tls_env_authorized(" 1"));
    CHECK_FALSE(insecure_tls_env_authorized("1 "));
    CHECK_FALSE(insecure_tls_env_authorized("\t1"));
}

TEST_CASE("Insecure TLS gate: rejects '1' with trailing junk",
          "[security][insecure_tls][issue79]") {
    CHECK_FALSE(insecure_tls_env_authorized("10"));
    CHECK_FALSE(insecure_tls_env_authorized("1abc"));
    CHECK_FALSE(insecure_tls_env_authorized("11"));
}

TEST_CASE("Insecure TLS gate: accepts only the literal '1'",
          "[security][insecure_tls][issue79]") {
    CHECK(insecure_tls_env_authorized("1"));
}
