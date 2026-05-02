#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <mutex>
#include <string>
#include <thread>

namespace httplib {
class Server;
} // namespace httplib

namespace yuzu::server {

class AuditStore;

/// Polls HTTPS cert/key PEM files for changes and hot-reloads the SSL context
/// without requiring a server restart. Uses std::filesystem::last_write_time for
/// cross-platform file change detection.
///
/// Thread safety: the reload path builds a complete new SSL_CTX, validates it,
/// then atomically swaps it into the httplib SSLServer. Counters are atomic.
class CertReloader {
public:
    static constexpr size_t kMaxPemFileSize = 1024 * 1024; // 1 MB sanity cap

    struct Params {
        std::filesystem::path cert_path;
        std::filesystem::path key_path;
        std::chrono::seconds interval{60};
        httplib::Server* web_server{nullptr}; // must be SSLServer at runtime
        AuditStore* audit_store{nullptr};
    };

    explicit CertReloader(Params params);
    ~CertReloader();

    CertReloader(const CertReloader&) = delete;
    CertReloader& operator=(const CertReloader&) = delete;

    void start();
    void stop();

    /// Attempt a reload now. Returns true if certs were successfully refreshed.
    /// Exposed for testing.
    [[nodiscard]] bool try_reload();

    /// Validate that a PEM cert+key pair is parseable and the key matches the cert.
    /// Exposed for testing.
    [[nodiscard]] static bool validate_pem_pair(const std::string& cert_pem,
                                                 const std::string& key_pem);

    uint64_t reload_count() const { return reload_count_.load(std::memory_order_relaxed); }
    uint64_t failure_count() const { return failure_count_.load(std::memory_order_relaxed); }

private:
    void run_loop();
    [[nodiscard]] bool files_changed();
    void log_audit(const std::string& detail, const std::string& result);

    Params params_;
    std::filesystem::file_time_type last_cert_mtime_{};
    std::filesystem::file_time_type last_key_mtime_{};
    std::thread thread_;
    std::atomic<bool> stop_requested_{false};
    // stop_cv_ + stop_mu_ make stop() wake the worker immediately rather than
    // forcing it to wait out a 5-second sleep increment. The 5-second poll
    // version pushed the server-tests suite over its 120s budget on contended
    // runners (#flake from PR 734); CV-based wait keeps shutdown < 1ms.
    std::mutex stop_mu_;
    std::condition_variable stop_cv_;
    std::atomic<uint64_t> reload_count_{0};
    std::atomic<uint64_t> failure_count_{0};
};

} // namespace yuzu::server
