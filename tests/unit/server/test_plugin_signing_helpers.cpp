#include "plugin_signing_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

// pem.h before bio.h — declaration-order convention.
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

#include <memory>
#include <random>
#include <string>

namespace ps = yuzu::server::plugin_signing;

namespace {

struct SslFreer {
    void operator()(BIO* p) const noexcept { BIO_free_all(p); }
    void operator()(EVP_PKEY* p) const noexcept { EVP_PKEY_free(p); }
    void operator()(EVP_PKEY_CTX* p) const noexcept { EVP_PKEY_CTX_free(p); }
    void operator()(X509* p) const noexcept { X509_free(p); }
};
template <typename T>
using ssl_ptr = std::unique_ptr<T, SslFreer>;

ssl_ptr<EVP_PKEY> generate_ec_key() {
    ssl_ptr<EVP_PKEY_CTX> ctx{EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr)};
    REQUIRE(ctx);
    REQUIRE(EVP_PKEY_keygen_init(ctx.get()) == 1);
    REQUIRE(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx.get(),
                                                    NID_X9_62_prime256v1) == 1);
    EVP_PKEY* raw = nullptr;
    REQUIRE(EVP_PKEY_keygen(ctx.get(), &raw) == 1);
    return ssl_ptr<EVP_PKEY>{raw};
}

// Mint a self-signed cert with the given CN. Used to build PEMs for the
// validate_trust_bundle_pem() tests; we don't care about validity dates
// or extensions because the helper does not chain-verify.
ssl_ptr<X509> mint_self_signed(EVP_PKEY* key, const std::string& cn) {
    ssl_ptr<X509> cert{X509_new()};
    REQUIRE(cert);
    REQUIRE(X509_set_version(cert.get(), 2) == 1);
    ASN1_INTEGER_set(X509_get_serialNumber(cert.get()),
                     static_cast<long>(std::random_device{}()));
    X509_gmtime_adj(X509_getm_notBefore(cert.get()), 0);
    X509_gmtime_adj(X509_getm_notAfter(cert.get()), 60 * 60 * 24);
    X509_NAME* name = X509_get_subject_name(cert.get());
    X509_NAME_add_entry_by_txt(
        name, "CN", MBSTRING_ASC,
        reinterpret_cast<const unsigned char*>(cn.c_str()), -1, -1, 0);
    REQUIRE(X509_set_issuer_name(cert.get(), name) == 1);
    REQUIRE(X509_set_pubkey(cert.get(), key) == 1);
    REQUIRE(X509_sign(cert.get(), key, EVP_sha256()) > 0);
    return cert;
}

std::string cert_to_pem(X509* cert) {
    ssl_ptr<BIO> bio{BIO_new(BIO_s_mem())};
    REQUIRE(bio);
    REQUIRE(PEM_write_bio_X509(bio.get(), cert) == 1);
    BUF_MEM* mem = nullptr;
    BIO_get_mem_ptr(bio.get(), &mem);
    REQUIRE(mem);
    return std::string(mem->data, mem->length);
}

std::string make_pem_bundle(int n_certs) {
    std::string out;
    for (int i = 0; i < n_certs; ++i) {
        auto k = generate_ec_key();
        auto c = mint_self_signed(k.get(), "Test Cert " + std::to_string(i));
        out += cert_to_pem(c.get());
    }
    return out;
}

} // namespace

TEST_CASE("validate_trust_bundle_pem rejects empty input",
          "[plugin_signing][validation]") {
    auto r = ps::validate_trust_bundle_pem("");
    REQUIRE_FALSE(r.has_value());
    REQUIRE(r.error().find("empty") != std::string::npos);
}

TEST_CASE("validate_trust_bundle_pem rejects input without PEM markers",
          "[plugin_signing][validation]") {
    auto r = ps::validate_trust_bundle_pem("not a pem at all");
    REQUIRE_FALSE(r.has_value());
    // Error message must reference the missing markers so the operator
    // sees a useful diagnostic in the UI.
    REQUIRE(r.error().find("marker") != std::string::npos);
}

TEST_CASE("validate_trust_bundle_pem rejects PEM with markers but no certs",
          "[plugin_signing][validation]") {
    // Markers present but no actual cert body — exercises the "OpenSSL
    // accepted nothing" path that returns the no-certs error.
    auto r = ps::validate_trust_bundle_pem(
        "-----BEGIN CERTIFICATE-----\n"
        "garbagegarbagegarbage\n"
        "-----END CERTIFICATE-----\n");
    REQUIRE_FALSE(r.has_value());
}

TEST_CASE("validate_trust_bundle_pem accepts a single cert PEM",
          "[plugin_signing][validation]") {
    auto pem = make_pem_bundle(1);
    auto r = ps::validate_trust_bundle_pem(pem);
    REQUIRE(r.has_value());
    REQUIRE(r->cert_count == 1);
    REQUIRE(r->sha256_hex.size() == 64);
    REQUIRE(r->subjects.size() == 1);
    REQUIRE(r->subjects.front().find("Test Cert 0") != std::string::npos);
}

TEST_CASE("validate_trust_bundle_pem accepts multi-cert PEM and counts each",
          "[plugin_signing][validation]") {
    auto pem = make_pem_bundle(3);
    auto r = ps::validate_trust_bundle_pem(pem);
    REQUIRE(r.has_value());
    REQUIRE(r->cert_count == 3);
    REQUIRE(r->subjects.size() == 3);
}

TEST_CASE("validate_trust_bundle_pem caps subjects displayed at 16",
          "[plugin_signing][validation]") {
    // Counts every cert but only retains the first 16 subjects so the
    // UI never bloats indefinitely on a giant bundle.
    auto pem = make_pem_bundle(20);
    auto r = ps::validate_trust_bundle_pem(pem);
    REQUIRE(r.has_value());
    REQUIRE(r->cert_count == 20);
    REQUIRE(r->subjects.size() == 16);
}

TEST_CASE("validate_trust_bundle_pem produces a stable SHA-256 over the PEM bytes",
          "[plugin_signing][validation]") {
    auto pem = make_pem_bundle(2);
    auto a = ps::validate_trust_bundle_pem(pem);
    auto b = ps::validate_trust_bundle_pem(pem);
    REQUIRE(a.has_value());
    REQUIRE(b.has_value());
    REQUIRE(a->sha256_hex == b->sha256_hex);

    // Different inputs → different hashes (no collision risk in test).
    auto pem2 = make_pem_bundle(2);
    auto c = ps::validate_trust_bundle_pem(pem2);
    REQUIRE(c.has_value());
    REQUIRE(c->sha256_hex != a->sha256_hex);
}

TEST_CASE("trust_bundle_path resolves under default_cert_dir",
          "[plugin_signing][path]") {
    auto p = ps::trust_bundle_path();
    REQUIRE_FALSE(p.empty());
    REQUIRE(p.filename().string() == ps::kPluginTrustBundleFilename);
}
