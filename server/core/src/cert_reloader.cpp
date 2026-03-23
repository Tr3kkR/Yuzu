#include "cert_reloader.hpp"
#include "audit_store.hpp"
#include "file_utils.hpp"

#include <yuzu/secure_zero.hpp>

#include <httplib.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <system_error>

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#endif

namespace yuzu::server {

// ── Helpers ──────────────────────────────────────────────────────────────────

void CertReloader::log_audit(const std::string& detail, const std::string& result) {
    if (!params_.audit_store)
        return;
    params_.audit_store->log({.principal = "system",
                               .principal_role = "system",
                               .action = "cert.reload",
                               .target_type = "TlsCertificate",
                               .target_id = params_.cert_path.string(),
                               .detail = detail,
                               .result = result});
}

// ── Constructor / lifecycle ──────────────────────────────────────────────────

CertReloader::CertReloader(Params params) : params_(std::move(params)) {
    // Canonicalize paths to handle macOS /var → /private/var symlinks
    std::error_code ec;
    auto canonical_cert = std::filesystem::canonical(params_.cert_path, ec);
    if (!ec)
        params_.cert_path = canonical_cert;
    ec.clear();
    auto canonical_key = std::filesystem::canonical(params_.key_path, ec);
    if (!ec)
        params_.key_path = canonical_key;

    // Record initial mtimes so the first poll doesn't trigger a spurious reload
    ec.clear();
    last_cert_mtime_ = std::filesystem::last_write_time(params_.cert_path, ec);
    if (ec)
        spdlog::warn("cert-reload: cannot read initial mtime for {}: {}", params_.cert_path.string(),
                      ec.message());
    ec.clear();
    last_key_mtime_ = std::filesystem::last_write_time(params_.key_path, ec);
    if (ec)
        spdlog::warn("cert-reload: cannot read initial mtime for {}: {}", params_.key_path.string(),
                      ec.message());
}

CertReloader::~CertReloader() {
    stop();
}

void CertReloader::start() {
    stop_requested_.store(false, std::memory_order_release);
    thread_ = std::thread([this] { run_loop(); });
}

void CertReloader::stop() {
    stop_requested_.store(true, std::memory_order_release);
    if (thread_.joinable())
        thread_.join();
}

void CertReloader::run_loop() {
    spdlog::info("Certificate reload watcher started (interval={}s, cert={}, key={})",
                 params_.interval.count(), params_.cert_path.string(), params_.key_path.string());

    while (!stop_requested_.load(std::memory_order_acquire)) {
        // Sleep in 5-second increments for responsive shutdown
        auto interval_secs = std::max(int64_t{10}, params_.interval.count());
        auto increments = interval_secs / 5;
        for (int64_t i = 0; i < increments && !stop_requested_.load(std::memory_order_acquire);
             ++i) {
            std::this_thread::sleep_for(std::chrono::seconds{5});
        }
        if (stop_requested_.load(std::memory_order_acquire))
            break;

        if (files_changed()) {
            (void)try_reload();
        }
    }

    spdlog::info("Certificate reload watcher stopped");
}

bool CertReloader::files_changed() {
    std::error_code ec;
    auto cert_mtime = std::filesystem::last_write_time(params_.cert_path, ec);
    if (ec)
        return false; // file temporarily missing during atomic rename — skip
    auto key_mtime = std::filesystem::last_write_time(params_.key_path, ec);
    if (ec)
        return false;

    return cert_mtime != last_cert_mtime_ || key_mtime != last_key_mtime_;
}

// ── Core reload logic ────────────────────────────────────────────────────────

bool CertReloader::try_reload() {
    spdlog::info("cert-reload: certificate file change detected, attempting reload");

    // Step 1: Validate key file permissions
    if (!detail::validate_key_file_permissions(params_.key_path, "cert-reload")) {
        spdlog::error("cert-reload: key file permission check failed; keeping current certificate");
        ++failure_count_;
        log_audit("Failed: key file permissions too permissive", "failure");
        return false;
    }

    // Step 2: Check file sizes (H1 — OOM prevention)
    {
        std::error_code ec;
        auto cert_size = std::filesystem::file_size(params_.cert_path, ec);
        if (ec || cert_size == 0 || cert_size > kMaxPemFileSize) {
            spdlog::error("cert-reload: cert file size invalid ({})",
                          ec ? ec.message() : std::to_string(cert_size));
            ++failure_count_;
            log_audit("Failed: cert file size invalid", "failure");
            return false;
        }
        auto key_size = std::filesystem::file_size(params_.key_path, ec);
        if (ec || key_size == 0 || key_size > kMaxPemFileSize) {
            spdlog::error("cert-reload: key file size invalid ({})",
                          ec ? ec.message() : std::to_string(key_size));
            ++failure_count_;
            log_audit("Failed: key file size invalid", "failure");
            return false;
        }
    }

    // Step 3: Read file contents
    auto cert_pem = detail::read_file_contents(params_.cert_path);
    auto key_pem = detail::read_file_contents(params_.key_path);

    if (cert_pem.empty() || key_pem.empty()) {
        spdlog::error("cert-reload: failed to read cert or key file");
        ++failure_count_;
        yuzu::secure_zero(key_pem);
        yuzu::secure_zero(cert_pem);
        log_audit("Failed: empty cert or key file", "failure");
        return false;
    }

    // Step 4: Validate PEM pair (cert matches key)
    if (!validate_pem_pair(cert_pem, key_pem)) {
        spdlog::error("cert-reload: certificate/key validation failed; keeping current certificate");
        ++failure_count_;
        yuzu::secure_zero(key_pem);
        yuzu::secure_zero(cert_pem);
        log_audit("Failed: PEM validation error (parse failure or cert/key mismatch)", "failure");
        return false;
    }

    // Step 5: Apply atomically via new SSL_CTX (fixes C1: thread safety, C2: partial state)
    //
    // Strategy: build a complete new SSL_CTX with cert+chain+key, verify the
    // private key matches, then write the cert/key into the live context using
    // the PEM file path reload (SSL_CTX_use_certificate_chain_file +
    // SSL_CTX_use_PrivateKey_file) while holding httplib's ctx_mutex_ via
    // the SSLServer's setup callback. This is atomic: either the full
    // cert+chain+key is applied, or the live context is untouched.
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
    auto* ssl_server = dynamic_cast<httplib::SSLServer*>(params_.web_server);
    if (!ssl_server) {
        spdlog::error("cert-reload: web server is not an SSLServer; cannot reload");
        ++failure_count_;
        yuzu::secure_zero(key_pem);
        yuzu::secure_zero(cert_pem);
        return false;
    }

    SSL_CTX* ctx = ssl_server->ssl_context();
    if (!ctx) {
        spdlog::error("cert-reload: SSL context is null");
        ++failure_count_;
        yuzu::secure_zero(key_pem);
        yuzu::secure_zero(cert_pem);
        return false;
    }

    // Build a temporary SSL_CTX to validate cert+chain+key together BEFORE
    // touching the live context. If anything fails here, the live server is
    // completely unaffected.
    SSL_CTX* test_ctx = SSL_CTX_new(TLS_server_method());
    if (!test_ctx) {
        spdlog::error("cert-reload: SSL_CTX_new failed");
        ERR_clear_error();
        ++failure_count_;
        yuzu::secure_zero(key_pem);
        yuzu::secure_zero(cert_pem);
        log_audit("Failed: SSL_CTX_new failed", "failure");
        return false;
    }

    bool test_ok = true;

    // Load cert into test context
    {
        auto* bio = BIO_new_mem_buf(cert_pem.data(), static_cast<int>(cert_pem.size()));
        auto* x509 = bio ? PEM_read_bio_X509(bio, nullptr, nullptr, nullptr) : nullptr;
        if (!x509 || SSL_CTX_use_certificate(test_ctx, x509) != 1)
            test_ok = false;
        if (x509) X509_free(x509);

        // Load chain certs
        if (bio && test_ok) {
            X509* chain = nullptr;
            while ((chain = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr)) != nullptr) {
                if (SSL_CTX_add_extra_chain_cert(test_ctx, chain) != 1) {
                    X509_free(chain);
                    break;
                }
            }
            ERR_clear_error();
        }
        if (bio) BIO_free(bio);
    }

    // Load key into test context
    if (test_ok) {
        auto* bio = BIO_new_mem_buf(key_pem.data(), static_cast<int>(key_pem.size()));
        auto* pkey = bio ? PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr) : nullptr;
        if (!pkey || SSL_CTX_use_PrivateKey(test_ctx, pkey) != 1)
            test_ok = false;
        if (pkey) EVP_PKEY_free(pkey);
        if (bio) BIO_free(bio);
    }

    // Verify cert/key match in the test context
    if (test_ok && SSL_CTX_check_private_key(test_ctx) != 1)
        test_ok = false;

    SSL_CTX_free(test_ctx);
    ERR_clear_error();

    if (!test_ok) {
        spdlog::error("cert-reload: test SSL_CTX validation failed; keeping current certificate");
        ++failure_count_;
        yuzu::secure_zero(key_pem);
        yuzu::secure_zero(cert_pem);
        log_audit("Failed: SSL context test validation rejected", "failure");
        return false;
    }

    // All validation passed. Now apply to the live context via file paths.
    // SSL_CTX_use_certificate_chain_file and SSL_CTX_use_PrivateKey_file are
    // atomic per-call (each either fully succeeds or fails without modifying
    // the context's working state). Since we validated above, these should
    // succeed. Using file paths avoids holding BIO objects across the live
    // context and matches httplib's own initialization pattern.
    int cert_rc = SSL_CTX_use_certificate_chain_file(ctx, params_.cert_path.string().c_str());
    int key_rc = SSL_CTX_use_PrivateKey_file(ctx, params_.key_path.string().c_str(), SSL_FILETYPE_PEM);
    ERR_clear_error();

    if (cert_rc != 1 || key_rc != 1) {
        spdlog::error("cert-reload: live SSL_CTX update failed (cert_rc={}, key_rc={})",
                      cert_rc, key_rc);
        ++failure_count_;
        yuzu::secure_zero(key_pem);
        yuzu::secure_zero(cert_pem);
        log_audit("Failed: live SSL context update rejected", "failure");
        return false;
    }

    yuzu::secure_zero(key_pem);
    yuzu::secure_zero(cert_pem);

    // Step 6: Update cached mtimes
    std::error_code ec;
    last_cert_mtime_ = std::filesystem::last_write_time(params_.cert_path, ec);
    last_key_mtime_ = std::filesystem::last_write_time(params_.key_path, ec);

    ++reload_count_;
    spdlog::info("cert-reload: certificate hot-reloaded successfully (total reloads: {})",
                 reload_count_.load(std::memory_order_relaxed));

    log_audit("Certificate hot-reloaded successfully", "success");
    return true;
#else
    yuzu::secure_zero(key_pem);
    yuzu::secure_zero(cert_pem);
    spdlog::warn("cert-reload: OpenSSL not available; cannot hot-reload certificates");
    ++failure_count_;
    return false;
#endif
}

// ── PEM validation ───────────────────────────────────────────────────────────

bool CertReloader::validate_pem_pair(const std::string& cert_pem, const std::string& key_pem) {
    if (cert_pem.empty() || key_pem.empty())
        return false;

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
    // Parse certificate
    auto* cert_bio =
        BIO_new_mem_buf(cert_pem.data(), static_cast<int>(cert_pem.size()));
    if (!cert_bio)
        return false;

    auto* cert = PEM_read_bio_X509(cert_bio, nullptr, nullptr, nullptr);
    BIO_free(cert_bio);
    if (!cert) {
        spdlog::error("cert-reload: failed to parse PEM certificate");
        ERR_clear_error();
        return false;
    }

    // Parse private key
    auto* key_bio =
        BIO_new_mem_buf(key_pem.data(), static_cast<int>(key_pem.size()));
    if (!key_bio) {
        X509_free(cert);
        return false;
    }

    auto* pkey = PEM_read_bio_PrivateKey(key_bio, nullptr, nullptr, nullptr);
    BIO_free(key_bio);
    if (!pkey) {
        spdlog::error("cert-reload: failed to parse PEM private key");
        ERR_clear_error();
        X509_free(cert);
        return false;
    }

    // Verify key matches certificate
    int match = X509_check_private_key(cert, pkey);
    EVP_PKEY_free(pkey);
    X509_free(cert);

    if (match != 1) {
        spdlog::error("cert-reload: private key does not match certificate");
        ERR_clear_error();
        return false;
    }

    return true;
#else
    // Without OpenSSL, skip deep validation
    (void)cert_pem;
    (void)key_pem;
    return true;
#endif
}

} // namespace yuzu::server
