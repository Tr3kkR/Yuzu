/**
 * test_cert_store_fallback.cpp -- the Security-absent build path of
 * agents/core/src/cert_store.cpp's __APPLE__ branch (A-1.20, P8).
 *
 * yuzu_agent_core_lib compiles cert_store.cpp with -DYUZU_HAVE_SECURITY on
 * THIS build host (Security.framework is found -- see
 * agents/core/meson.build), so agent_test_exe alone can never reach the
 * honest-error stub a real "Security.framework not found at configure time"
 * build would ship. This binary (tests/meson.build's
 * cert_store_fallback_test_exe) recompiles the SAME untouched
 * cert_store.cpp source into a dedicated executable with
 * YUZU_HAVE_SECURITY deliberately left undefined, forcing the __APPLE__ /
 * !YUZU_HAVE_SECURITY branch, so the fallback's "no fabricated success"
 * contract is covered on every host regardless of what the current build's
 * SDK happens to have.
 */

#include <catch2/catch_test_macros.hpp>

#include <yuzu/agent/cert_store.hpp>

using yuzu::agent::CertStoreResult;
using yuzu::agent::read_cert_from_store;

TEST_CASE("Security-absent build returns an honest error, never a fabricated success",
          "[cert_store][macos]") {
    const CertStoreResult result = read_cert_from_store(/*store_name=*/"", "yuzu-agent",
                                                          /*thumbprint=*/"");

    CHECK_FALSE(result.ok());
    CHECK_FALSE(result.error.empty());
    // No PEM material fabricated alongside the error.
    CHECK(result.pem_cert_chain.empty());
    CHECK(result.pem_private_key.empty());
}

TEST_CASE("Security-absent build errors identically regardless of which selector is given",
          "[cert_store][macos]") {
    // The stub ignores its arguments entirely -- it always reports the
    // build-time limitation, not an argument-validation error, whether
    // called by subject, by thumbprint, or with neither.
    const CertStoreResult by_subject = read_cert_from_store("", "some-subject", "");
    const CertStoreResult by_thumbprint = read_cert_from_store("", "", "AABBCCDDEEFF00112233445566778899AABBCCDD");
    const CertStoreResult neither = read_cert_from_store("", "", "");

    CHECK_FALSE(by_subject.ok());
    CHECK_FALSE(by_thumbprint.ok());
    CHECK_FALSE(neither.ok());
    CHECK(by_subject.error == neither.error);
    CHECK(by_thumbprint.error == neither.error);
}
