#pragma once

#include "nvd_db.hpp"

#include <chrono>
#include <optional>
#include <string>
#include <vector>

namespace httplib {
class Client;
}

namespace yuzu::server {

struct NvdFetchResult {
    std::vector<CveRecord> records;
    int total_results = 0;
    std::string last_modified_timestamp; // latest lastModified in results
};

class NvdClient {
public:
    explicit NvdClient(std::string api_key = {}, std::string proxy_url = {});

    // Fetch CVEs modified since the given ISO 8601 timestamp.
    // Returns empty vector on error (logs via spdlog).
    NvdFetchResult fetch_modified_since(const std::string& iso_timestamp);

    // Fetch CVEs matching a keyword search (for initial targeted sync).
    NvdFetchResult fetch_by_keyword(const std::string& keyword, int start_index = 0);

    /// Parse a raw NVD API JSON response into CveRecords.
    NvdFetchResult parse_response(const std::string& json_body);

private:
    std::string api_key_;
    std::string proxy_host_;
    int proxy_port_ = 0;
    // std::nullopt until the first request — a sentinel time_point overflowed
    // the rate-limit subtraction and slept ~forever on the first call (#1867).
    std::optional<std::chrono::steady_clock::time_point> last_request_time_;

    void rate_limit();
    void apply_proxy(httplib::Client& client) const;
    // Apply the shared per-request client config (timeouts, proxy).
    void configure_client(httplib::Client& client) const;
};

/// How long to sleep to honour `interval` since the `last` request — zero when
/// there was no prior request (nullopt) or `interval` has already elapsed.
/// Overflow-safe: a regression guard for the `time_point::min()` sentinel that
/// overflowed `now - last` and slept ~292 years on the first NVD request (#1867).
std::chrono::steady_clock::duration
nvd_rate_limit_wait(std::optional<std::chrono::steady_clock::time_point> last,
                    std::chrono::steady_clock::time_point now,
                    std::chrono::steady_clock::duration interval);

} // namespace yuzu::server
