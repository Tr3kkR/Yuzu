// test_tls_policy.cpp -- pure tests of common/include/yuzu/tls_policy.hpp.
//
// Registered in the AGENT test executable, not the server one: server
// shards are the bottleneck (CLAUDE.md test-efficiency discipline) and
// this header touches no server/agent state at all — precedent for a
// common/ header tested here is unit/test_shutdown_pipe.cpp.

#include <yuzu/tls_policy.hpp>

#include "scoped_env.hpp"

#include <catch2/catch_test_macros.hpp>

#include <openssl/ssl.h>

#include <cstdlib>
#include <string>

TEST_CASE("tls_policy: kTls12CipherList text is exactly the six-suite allow-list",
          "[tls][tls_policy]") {
    CHECK(yuzu::tls::kTls12CipherList ==
          "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-"
          "POLY1305:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-CHACHA20-"
          "POLY1305");

    std::string joined;
    for (size_t i = 0; i < yuzu::tls::kTls12CipherNames.size(); ++i) {
        if (i)
            joined += ':';
        joined += yuzu::tls::kTls12CipherNames[i];
    }
    CHECK(joined == yuzu::tls::kTls12CipherList);
}

TEST_CASE("tls_policy: every allow-list entry is ECDHE + AEAD, both ECDSA and RSA present",
          "[tls][tls_policy]") {
    bool saw_ecdsa = false, saw_rsa = false;
    for (auto name : yuzu::tls::kTls12CipherNames) {
        CAPTURE(name);
        CHECK(name.starts_with("ECDHE-"));
        CHECK((name.find("-GCM-") != std::string_view::npos ||
              name.find("CHACHA20") != std::string_view::npos));
        if (name.find("ECDHE-ECDSA-") != std::string_view::npos)
            saw_ecdsa = true;
        if (name.find("ECDHE-RSA-") != std::string_view::npos)
            saw_rsa = true;
    }
    CHECK(saw_ecdsa);
    CHECK(saw_rsa);
}

TEST_CASE("tls_policy: resolve_cipher_policy resolves the default list in order",
          "[tls][tls_policy]") {
    auto r = yuzu::tls::resolve_cipher_policy();
    REQUIRE(r.has_value());

    // OpenSSL drops unknown names silently as long as at least one resolves;
    // pinning this equality is what makes a typo in the constant visible.
    REQUIRE(r->tls12.size() == yuzu::tls::kTls12CipherNames.size());
    for (size_t i = 0; i < r->tls12.size(); ++i) {
        CHECK(r->tls12[i] == yuzu::tls::kTls12CipherNames[i]);
    }

    CHECK_FALSE(r->tls13.empty());
    for (const auto& name : r->tls13) {
        CAPTURE(name);
        CHECK(name.starts_with("TLS_"));
    }
}

TEST_CASE("tls_policy: resolve_cipher_policy rejects an unresolvable or empty list",
          "[tls][tls_policy]") {
    CHECK_FALSE(yuzu::tls::resolve_cipher_policy("NO-SUCH-CIPHER").has_value());
    CHECK_FALSE(yuzu::tls::resolve_cipher_policy("").has_value());
    // A TLS-1.3-only name has no TLS 1.2 match, so tls12 comes back empty.
    CHECK_FALSE(yuzu::tls::resolve_cipher_policy("TLS_AES_128_GCM_SHA256").has_value());
}

TEST_CASE("tls_policy: tls_policy_report_lines names both protocol versions",
          "[tls][tls_policy]") {
    auto r = yuzu::tls::resolve_cipher_policy();
    REQUIRE(r.has_value());
    auto lines = yuzu::tls::tls_policy_report_lines(*r);

    CHECK(lines[0].find("TLS 1.2") != std::string::npos);
    for (const auto& name : r->tls12) {
        CAPTURE(name);
        CHECK(lines[0].find(name) != std::string::npos);
    }

    CHECK(lines[1].find("TLS 1.3") != std::string::npos);
    CHECK(lines[1].find("OpenSSL") != std::string::npos);
    CHECK(lines[1].find("SSL_CTX_set_ciphersuites") != std::string::npos);
}

TEST_CASE("tls_policy: pin_grpc_cipher_env unconditionally overwrites an inherited value",
          "[tls][tls_policy]") {
    yuzu::test::ScopedEnv guard(std::string(yuzu::tls::kGrpcCipherSuitesEnvVar), "JUNK");
    CHECK(std::getenv(yuzu::tls::kGrpcCipherSuitesEnvVar.data()) == std::string("JUNK"));

    CHECK(yuzu::tls::pin_grpc_cipher_env());

    const char* after = std::getenv(yuzu::tls::kGrpcCipherSuitesEnvVar.data());
    REQUIRE(after != nullptr);
    CHECK(std::string(after) == yuzu::tls::kTls12CipherList);
}
