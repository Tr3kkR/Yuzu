#include "plugin_signing_helpers.hpp"

#include <yuzu/server/auth.hpp>

// pem.h before bio.h — keeps PEM_*_X509 macros declared.
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

namespace yuzu::server::plugin_signing {

std::filesystem::path trust_bundle_path() {
    return auth::default_cert_dir() / kPluginTrustBundleFilename;
}

std::expected<TrustBundleStats, std::string>
validate_trust_bundle_pem(std::string_view pem) {
    if (pem.empty()) {
        return std::unexpected("trust bundle is empty");
    }
    if (pem.find("-----BEGIN") == std::string_view::npos ||
        pem.find("-----END") == std::string_view::npos) {
        return std::unexpected("missing PEM begin/end markers");
    }

    BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
    if (!bio) {
        return std::unexpected("BIO_new_mem_buf failed");
    }

    TrustBundleStats stats;
    while (X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr)) {
        ++stats.cert_count;
        if (stats.cert_count <= 16) { // cap subjects shown to operator
            char* name =
                X509_NAME_oneline(X509_get_subject_name(cert), nullptr, 0);
            if (name) {
                stats.subjects.emplace_back(name);
                OPENSSL_free(name);
            }
        }
        X509_free(cert);
    }
    BIO_free(bio);
    // PEM_read_bio_X509 pushes a benign PEM_R_NO_START_LINE entry onto
    // the thread-local error queue when it hits end-of-stream. Drain it
    // so a later TLS handshake on the same httplib worker thread does
    // not surface stale errors (governance hardening round 1, sec-LOW-6).
    ERR_clear_error();

    if (stats.cert_count == 0) {
        return std::unexpected("no X.509 certificates found in PEM");
    }

    unsigned char digest[SHA256_DIGEST_LENGTH];
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        return std::unexpected("EVP_MD_CTX_new failed");
    }
    bool ok = EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) == 1 &&
              EVP_DigestUpdate(ctx, pem.data(), pem.size()) == 1;
    unsigned int out_len = 0;
    ok = ok && EVP_DigestFinal_ex(ctx, digest, &out_len) == 1 &&
         out_len == SHA256_DIGEST_LENGTH;
    EVP_MD_CTX_free(ctx);
    if (!ok) {
        return std::unexpected("SHA-256 hashing failed");
    }
    static constexpr char kHex[] = "0123456789abcdef";
    stats.sha256_hex.reserve(SHA256_DIGEST_LENGTH * 2);
    for (unsigned i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        stats.sha256_hex.push_back(kHex[digest[i] >> 4]);
        stats.sha256_hex.push_back(kHex[digest[i] & 0x0F]);
    }
    return stats;
}

} // namespace yuzu::server::plugin_signing
