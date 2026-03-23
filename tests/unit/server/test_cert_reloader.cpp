/**
 * test_cert_reloader.cpp — Unit tests for certificate hot-reload (H4)
 *
 * Covers: Config defaults, PEM validation, file change detection, permission checks,
 * try_reload failure paths, start/stop lifecycle.
 */

#include <yuzu/server/server.hpp>

#include "cert_reloader.hpp"
#include "file_utils.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <string>
#include <thread>

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#endif

using namespace yuzu::server;

// ── Config defaults ────────────────────────────────────────────────────────

TEST_CASE("Cert reload config: defaults", "[cert-reload][config]") {
    Config cfg;
    CHECK(cfg.cert_reload_enabled == true);
    CHECK(cfg.cert_reload_interval_seconds == 60);
}

TEST_CASE("Cert reload config: disabled", "[cert-reload][config]") {
    Config cfg;
    cfg.cert_reload_enabled = false;
    cfg.cert_reload_interval_seconds = 120;
    CHECK(cfg.cert_reload_enabled == false);
    CHECK(cfg.cert_reload_interval_seconds == 120);
}

TEST_CASE("Cert reload: max PEM file size constant", "[cert-reload][config]") {
    CHECK(CertReloader::kMaxPemFileSize == 1024 * 1024);
}

// ── PEM validation (requires OpenSSL) ──────────────────────────────────────

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT

namespace {

struct PemPair {
    std::string cert;
    std::string key;
};

PemPair generate_self_signed() {
    PemPair result;

    auto* pkey = EVP_PKEY_new();
    auto* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);
    EVP_PKEY_keygen(ctx, &pkey);
    EVP_PKEY_CTX_free(ctx);

    auto* x509 = X509_new();
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    X509_gmtime_adj(X509_getm_notBefore(x509), 0);
    X509_gmtime_adj(X509_getm_notAfter(x509), 365 * 24 * 3600);
    X509_set_pubkey(x509, pkey);

    auto* name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                reinterpret_cast<const unsigned char*>("test"), -1, -1, 0);
    X509_set_issuer_name(x509, name);
    X509_sign(x509, pkey, EVP_sha256());

    auto* cert_bio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(cert_bio, x509);
    char* cert_data = nullptr;
    long cert_len = BIO_get_mem_data(cert_bio, &cert_data);
    result.cert.assign(cert_data, static_cast<size_t>(cert_len));
    BIO_free(cert_bio);

    auto* key_bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(key_bio, pkey, nullptr, nullptr, 0, nullptr, nullptr);
    char* key_data = nullptr;
    long key_len = BIO_get_mem_data(key_bio, &key_data);
    result.key.assign(key_data, static_cast<size_t>(key_len));
    BIO_free(key_bio);

    X509_free(x509);
    EVP_PKEY_free(pkey);

    return result;
}

// Write a PEM pair to disk with secure permissions
void write_pem_files(const std::filesystem::path& cert_path,
                     const std::filesystem::path& key_path,
                     const PemPair& pair) {
    {
        std::ofstream f(cert_path, std::ios::binary | std::ios::trunc);
        f << pair.cert;
    }
    {
        std::ofstream f(key_path, std::ios::binary | std::ios::trunc);
        f << pair.key;
    }
#ifndef _WIN32
    std::filesystem::permissions(key_path, std::filesystem::perms::owner_read |
                                                std::filesystem::perms::owner_write);
#endif
}

} // namespace

TEST_CASE("validate_pem_pair: valid cert+key", "[cert-reload][pem]") {
    auto pair = generate_self_signed();
    CHECK(CertReloader::validate_pem_pair(pair.cert, pair.key));
}

TEST_CASE("validate_pem_pair: mismatched cert+key", "[cert-reload][pem]") {
    auto pair1 = generate_self_signed();
    auto pair2 = generate_self_signed();
    CHECK_FALSE(CertReloader::validate_pem_pair(pair1.cert, pair2.key));
}

TEST_CASE("validate_pem_pair: garbage input", "[cert-reload][pem]") {
    CHECK_FALSE(CertReloader::validate_pem_pair("not-a-cert", "not-a-key"));
}

TEST_CASE("validate_pem_pair: empty strings", "[cert-reload][pem]") {
    CHECK_FALSE(CertReloader::validate_pem_pair("", ""));
}

TEST_CASE("validate_pem_pair: binary garbage", "[cert-reload][pem]") {
    std::string binary(256, '\0');
    for (int i = 0; i < 256; ++i)
        binary[static_cast<size_t>(i)] = static_cast<char>(i);
    CHECK_FALSE(CertReloader::validate_pem_pair(binary, binary));
}

#endif // CPPHTTPLIB_OPENSSL_SUPPORT

// ── File change detection ──────────────────────────────────────────────────

TEST_CASE("CertReloader: construction records mtimes", "[cert-reload][mtime]") {
    auto tmp = std::filesystem::temp_directory_path() / "yuzu_cert_reload_test_mtime";
    std::filesystem::create_directories(tmp);
    auto cert_path = tmp / "test.pem";
    auto key_path = tmp / "test-key.pem";

    {
        std::ofstream(cert_path) << "initial-cert";
        std::ofstream(key_path) << "initial-key";
    }
#ifndef _WIN32
    std::filesystem::permissions(key_path, std::filesystem::perms::owner_read |
                                                std::filesystem::perms::owner_write);
#endif

    CertReloader::Params params;
    params.cert_path = cert_path;
    params.key_path = key_path;
    params.interval = std::chrono::seconds{60};
    params.web_server = nullptr;

    CertReloader reloader(params);
    CHECK(reloader.reload_count() == 0);
    CHECK(reloader.failure_count() == 0);

    std::filesystem::remove_all(tmp);
}

// ── try_reload failure paths ────────────────────────────────────────────────

TEST_CASE("CertReloader: try_reload fails with null web_server", "[cert-reload][reload]") {
    auto tmp = std::filesystem::temp_directory_path() / "yuzu_cert_reload_test_null";
    std::filesystem::create_directories(tmp);
    auto cert_path = tmp / "test.pem";
    auto key_path = tmp / "test-key.pem";

    // Write valid-looking PEM (just needs to not be empty for the early checks)
    {
        std::ofstream(cert_path) << "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n";
        std::ofstream(key_path) << "-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----\n";
    }
#ifndef _WIN32
    std::filesystem::permissions(key_path, std::filesystem::perms::owner_read |
                                                std::filesystem::perms::owner_write);
#endif

    CertReloader::Params params;
    params.cert_path = cert_path;
    params.key_path = key_path;
    params.interval = std::chrono::seconds{60};
    params.web_server = nullptr; // <-- null

    CertReloader reloader(params);
    // PEM validation will fail on the fake content (OpenSSL can't parse it)
    // or the null server check will catch it. Either way it should fail safely.
    bool result = reloader.try_reload();
    CHECK_FALSE(result);
    CHECK(reloader.failure_count() > 0);
    CHECK(reloader.reload_count() == 0);

    std::filesystem::remove_all(tmp);
}

TEST_CASE("CertReloader: try_reload fails with empty files", "[cert-reload][reload]") {
    auto tmp = std::filesystem::temp_directory_path() / "yuzu_cert_reload_test_empty";
    std::filesystem::create_directories(tmp);
    auto cert_path = tmp / "test.pem";
    auto key_path = tmp / "test-key.pem";

    // Write empty files (must touch them so they exist with 0 bytes)
    { std::ofstream f(cert_path, std::ios::trunc); f.flush(); }
    { std::ofstream f(key_path, std::ios::trunc); f.flush(); }
#ifndef _WIN32
    // Only set permissions if files exist
    if (std::filesystem::exists(key_path)) {
        std::filesystem::permissions(key_path, std::filesystem::perms::owner_read |
                                                    std::filesystem::perms::owner_write);
    }
#endif

    CertReloader::Params params;
    params.cert_path = cert_path;
    params.key_path = key_path;
    params.interval = std::chrono::seconds{60};
    params.web_server = nullptr;

    CertReloader reloader(params);
    bool result = reloader.try_reload();
    CHECK_FALSE(result);
    CHECK(reloader.failure_count() > 0);

    std::filesystem::remove_all(tmp);
}

// ── Start / stop lifecycle ──────────────────────────────────────────────────

TEST_CASE("CertReloader: start and stop without crash", "[cert-reload][lifecycle]") {
    auto tmp = std::filesystem::temp_directory_path() / "yuzu_cert_reload_test_lifecycle";
    std::filesystem::create_directories(tmp);
    auto cert_path = tmp / "test.pem";
    auto key_path = tmp / "test-key.pem";

    {
        std::ofstream(cert_path) << "cert-content";
        std::ofstream(key_path) << "key-content";
    }
#ifndef _WIN32
    std::filesystem::permissions(key_path, std::filesystem::perms::owner_read |
                                                std::filesystem::perms::owner_write);
#endif

    CertReloader::Params params;
    params.cert_path = cert_path;
    params.key_path = key_path;
    params.interval = std::chrono::seconds{10};
    params.web_server = nullptr;

    CertReloader reloader(params);
    reloader.start();
    // Let it run briefly
    std::this_thread::sleep_for(std::chrono::milliseconds{100});
    reloader.stop();
    // No crash, no hang
    CHECK(true);

    std::filesystem::remove_all(tmp);
}

TEST_CASE("CertReloader: destructor stops cleanly", "[cert-reload][lifecycle]") {
    auto tmp = std::filesystem::temp_directory_path() / "yuzu_cert_reload_test_dtor";
    std::filesystem::create_directories(tmp);
    auto cert_path = tmp / "test.pem";
    auto key_path = tmp / "test-key.pem";

    {
        std::ofstream(cert_path) << "cert-content";
        std::ofstream(key_path) << "key-content";
    }
#ifndef _WIN32
    std::filesystem::permissions(key_path, std::filesystem::perms::owner_read |
                                                std::filesystem::perms::owner_write);
#endif

    {
        CertReloader::Params params;
        params.cert_path = cert_path;
        params.key_path = key_path;
        params.interval = std::chrono::seconds{10};
        params.web_server = nullptr;

        CertReloader reloader(params);
        reloader.start();
        std::this_thread::sleep_for(std::chrono::milliseconds{100});
        // Destructor should call stop() and join the thread
    }
    CHECK(true);

    std::filesystem::remove_all(tmp);
}

// ── Permission validation (Unix only) ──────────────────────────────────────

#ifndef _WIN32
TEST_CASE("validate_key_file_permissions: rejects group-readable", "[cert-reload][perms]") {
    auto tmp = std::filesystem::temp_directory_path() / "yuzu_perm_test_grp";
    std::filesystem::create_directories(tmp);
    auto key_path = tmp / "test-key.pem";

    { std::ofstream(key_path) << "test-key-content"; }

    std::filesystem::permissions(key_path, std::filesystem::perms::owner_read |
                                                std::filesystem::perms::owner_write |
                                                std::filesystem::perms::group_read);
    CHECK_FALSE(detail::validate_key_file_permissions(key_path, "test"));

    std::filesystem::permissions(key_path, std::filesystem::perms::owner_read |
                                                std::filesystem::perms::owner_write);
    CHECK(detail::validate_key_file_permissions(key_path, "test"));

    std::filesystem::remove_all(tmp);
}

TEST_CASE("validate_key_file_permissions: rejects others-readable", "[cert-reload][perms]") {
    auto tmp = std::filesystem::temp_directory_path() / "yuzu_perm_test_oth";
    std::filesystem::create_directories(tmp);
    auto key_path = tmp / "test-key.pem";

    { std::ofstream(key_path) << "test-key-content"; }

    std::filesystem::permissions(key_path, std::filesystem::perms::owner_read |
                                                std::filesystem::perms::owner_write |
                                                std::filesystem::perms::others_read);
    CHECK_FALSE(detail::validate_key_file_permissions(key_path, "test"));

    std::filesystem::remove_all(tmp);
}
#endif
