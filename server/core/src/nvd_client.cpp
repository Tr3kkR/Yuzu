#include <algorithm>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <httplib.h>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include "nvd_client.hpp"

namespace yuzu::server {

namespace {

constexpr const char* kNvdHost = "services.nvd.nist.gov";
constexpr const char* kNvdPath = "/rest/json/cves/2.0";
constexpr int kResultsPerPage = 2000;

// Rate limit intervals
constexpr auto kPublicInterval = std::chrono::milliseconds(6000);   // 5 req / 30s
constexpr auto kApiKeyInterval = std::chrono::milliseconds(600);    // 50 req / 30s

std::string current_iso_timestamp() {
    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                  now.time_since_epoch()) %
              1000;

    std::tm utc_tm{};
#ifdef _WIN32
    gmtime_s(&utc_tm, &time_t_now);
#else
    gmtime_r(&time_t_now, &utc_tm);
#endif

    std::ostringstream oss;
    oss << std::put_time(&utc_tm, "%Y-%m-%dT%H:%M:%S")
        << '.' << std::setfill('0') << std::setw(3) << ms.count();
    return oss.str();
}

std::string url_encode(const std::string& value) {
    std::ostringstream escaped;
    escaped.fill('0');
    escaped << std::hex;
    for (char c : value) {
        if (std::isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_' ||
            c == '.' || c == '~') {
            escaped << c;
        } else {
            escaped << '%' << std::setw(2)
                    << static_cast<int>(static_cast<unsigned char>(c));
        }
    }
    return escaped.str();
}

}  // namespace

NvdClient::NvdClient(std::string api_key, std::string proxy_url)
    : api_key_(std::move(api_key)),
      last_request_time_(std::chrono::steady_clock::time_point::min()) {
    // Parse proxy URL: "http://host:port" or "host:port"
    if (!proxy_url.empty()) {
        auto url = proxy_url;
        // Strip scheme
        if (url.starts_with("http://"))  url = url.substr(7);
        if (url.starts_with("https://")) url = url.substr(8);
        // Strip trailing slash
        if (!url.empty() && url.back() == '/') url.pop_back();

        auto colon = url.rfind(':');
        if (colon != std::string::npos) {
            proxy_host_ = url.substr(0, colon);
            try {
                proxy_port_ = std::stoi(url.substr(colon + 1));
            } catch (...) {
                proxy_port_ = 8080;
            }
        } else {
            proxy_host_ = url;
            proxy_port_ = 8080;
        }
        spdlog::info("NVD client using proxy {}:{}", proxy_host_, proxy_port_);
    }
}

void NvdClient::apply_proxy(httplib::Client& client) const {
    if (!proxy_host_.empty()) {
        client.set_proxy(proxy_host_, proxy_port_);
    }
}

void NvdClient::rate_limit() {
    auto interval = api_key_.empty() ? kPublicInterval : kApiKeyInterval;
    auto now = std::chrono::steady_clock::now();
    auto elapsed = now - last_request_time_;

    if (elapsed < interval) {
        auto wait = interval - elapsed;
        spdlog::debug("NVD rate limit: sleeping {}ms",
                      std::chrono::duration_cast<std::chrono::milliseconds>(wait).count());
        std::this_thread::sleep_for(wait);
    }

    last_request_time_ = std::chrono::steady_clock::now();
}

NvdFetchResult NvdClient::fetch_modified_since(const std::string& iso_timestamp) {
    NvdFetchResult combined;
    int start_index = 0;

    std::string end_date = current_iso_timestamp();

    while (true) {
        rate_limit();

        httplib::Client client(std::string("https://") + kNvdHost);
        client.set_connection_timeout(30);
        client.set_read_timeout(60);
        apply_proxy(client);

        std::string query = std::string(kNvdPath) + "?" +
                            "lastModStartDate=" + url_encode(iso_timestamp) +
                            "&lastModEndDate=" + url_encode(end_date) +
                            "&resultsPerPage=" + std::to_string(kResultsPerPage) +
                            "&startIndex=" + std::to_string(start_index);

        httplib::Headers headers;
        headers.emplace("Accept", "application/json");
        if (!api_key_.empty()) {
            headers.emplace("apiKey", api_key_);
        }

        spdlog::info("NVD API request: startIndex={}", start_index);
        auto res = client.Get(query, headers);

        if (!res) {
            spdlog::error("NVD API request failed: connection error");
            return combined;
        }

        if (res->status != 200) {
            spdlog::error("NVD API returned HTTP {}: {}", res->status, res->body.substr(0, 200));
            return combined;
        }

        auto page = parse_response(res->body);
        if (page.records.empty() && page.total_results == 0) {
            // Parse error or no results
            return combined;
        }

        combined.total_results = page.total_results;
        if (!page.last_modified_timestamp.empty()) {
            if (combined.last_modified_timestamp.empty() ||
                page.last_modified_timestamp > combined.last_modified_timestamp) {
                combined.last_modified_timestamp = page.last_modified_timestamp;
            }
        }
        combined.records.insert(combined.records.end(),
                                std::make_move_iterator(page.records.begin()),
                                std::make_move_iterator(page.records.end()));

        spdlog::info("NVD fetch progress: {}/{} total results",
                     combined.records.size(), combined.total_results);

        start_index += kResultsPerPage;
        if (start_index >= combined.total_results) {
            break;
        }
    }

    return combined;
}

NvdFetchResult NvdClient::fetch_by_keyword(const std::string& keyword, int start_index) {
    rate_limit();

    httplib::Client client(std::string("https://") + kNvdHost);
    client.set_connection_timeout(30);
    client.set_read_timeout(60);
    apply_proxy(client);

    std::string query = std::string(kNvdPath) + "?" +
                        "keywordSearch=" + url_encode(keyword) +
                        "&resultsPerPage=" + std::to_string(kResultsPerPage) +
                        "&startIndex=" + std::to_string(start_index);

    httplib::Headers headers;
    headers.emplace("Accept", "application/json");
    if (!api_key_.empty()) {
        headers.emplace("apiKey", api_key_);
    }

    spdlog::info("NVD keyword search: '{}' startIndex={}", keyword, start_index);
    auto res = client.Get(query, headers);

    if (!res) {
        spdlog::error("NVD API keyword request failed: connection error");
        return {};
    }

    if (res->status != 200) {
        spdlog::error("NVD API returned HTTP {}: {}", res->status, res->body.substr(0, 200));
        return {};
    }

    return parse_response(res->body);
}

NvdFetchResult NvdClient::parse_response(const std::string& json_body) {
    NvdFetchResult result;

    nlohmann::json doc;
    try {
        doc = nlohmann::json::parse(json_body);
    } catch (const nlohmann::json::parse_error& e) {
        spdlog::error("NVD JSON parse error: {}", e.what());
        return result;
    }

    result.total_results = doc.value("totalResults", 0);

    if (!doc.contains("vulnerabilities") || !doc["vulnerabilities"].is_array()) {
        return result;
    }

    for (const auto& vuln_entry : doc["vulnerabilities"]) {
        if (!vuln_entry.contains("cve") || !vuln_entry["cve"].is_object()) {
            continue;
        }

        const auto& cve = vuln_entry["cve"];
        std::string cve_id = cve.value("id", "");
        if (cve_id.empty()) {
            continue;
        }

        // Extract English description
        std::string description;
        if (cve.contains("descriptions") && cve["descriptions"].is_array()) {
            for (const auto& desc : cve["descriptions"]) {
                if (desc.value("lang", "") == "en") {
                    description = desc.value("value", "");
                    break;
                }
            }
        }

        // Extract severity from CVSS metrics (v3.1 > v3.0 > v2)
        std::string severity = "MEDIUM";
        if (cve.contains("metrics") && cve["metrics"].is_object()) {
            const auto& metrics = cve["metrics"];
            bool found = false;

            for (const char* metric_key : {"cvssMetricV31", "cvssMetricV30"}) {
                if (found) break;
                if (metrics.contains(metric_key) && metrics[metric_key].is_array() &&
                    !metrics[metric_key].empty()) {
                    const auto& first = metrics[metric_key][0];
                    if (first.contains("cvssData") && first["cvssData"].is_object()) {
                        auto sev = first["cvssData"].value("baseSeverity", "");
                        if (!sev.empty()) {
                            severity = sev;
                            found = true;
                        }
                    }
                }
            }

            if (!found && metrics.contains("cvssMetricV2") && metrics["cvssMetricV2"].is_array() &&
                !metrics["cvssMetricV2"].empty()) {
                const auto& first = metrics["cvssMetricV2"][0];
                auto sev = first.value("baseSeverity", "");
                if (!sev.empty()) {
                    severity = sev;
                }
            }
        }

        // Normalize severity to uppercase
        std::transform(severity.begin(), severity.end(), severity.begin(),
                       [](unsigned char c) { return static_cast<char>(std::toupper(c)); });

        std::string published = cve.value("published", "");
        std::string last_modified = cve.value("lastModified", "");

        // Track latest lastModified
        if (!last_modified.empty()) {
            if (result.last_modified_timestamp.empty() ||
                last_modified > result.last_modified_timestamp) {
                result.last_modified_timestamp = last_modified;
            }
        }

        // Extract CPE matches from configurations
        bool has_cpe = false;
        if (cve.contains("configurations") && cve["configurations"].is_array()) {
            for (const auto& config : cve["configurations"]) {
                if (!config.contains("nodes") || !config["nodes"].is_array()) {
                    continue;
                }
                for (const auto& node : config["nodes"]) {
                    if (!node.contains("cpeMatch") || !node["cpeMatch"].is_array()) {
                        continue;
                    }
                    for (const auto& match : node["cpeMatch"]) {
                        std::string criteria = match.value("criteria", "");
                        if (criteria.empty()) {
                            continue;
                        }

                        // Parse CPE 2.3 URI: cpe:2.3:part:vendor:product:version:...
                        // Fields: 0=cpe, 1=2.3, 2=part, 3=vendor, 4=product, 5=version, ...
                        std::vector<std::string> parts;
                        std::istringstream cpe_stream(criteria);
                        std::string part;
                        while (std::getline(cpe_stream, part, ':')) {
                            parts.push_back(part);
                        }

                        if (parts.size() < 5) {
                            continue;
                        }

                        std::string vendor = parts[3];
                        std::string product = parts[4];

                        // Normalize to lowercase
                        std::transform(product.begin(), product.end(), product.begin(),
                                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
                        std::transform(vendor.begin(), vendor.end(), vendor.begin(),
                                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

                        // Extract version constraint
                        std::string affected_below;
                        if (match.contains("versionEndExcluding")) {
                            affected_below = match.value("versionEndExcluding", "");
                        } else if (match.contains("versionEndIncluding")) {
                            affected_below = match.value("versionEndIncluding", "");
                        }

                        CveRecord record;
                        record.cve_id = cve_id;
                        record.product = product;
                        record.vendor = vendor;
                        record.affected_below = affected_below;
                        record.severity = severity;
                        record.description = description;
                        record.published = published;
                        record.last_modified = last_modified;
                        record.source = "nvd";

                        result.records.push_back(std::move(record));
                        has_cpe = true;
                    }
                }
            }
        }

        // If no CPE configurations, still create a record with empty product/vendor
        // so the CVE data isn't lost
        if (!has_cpe) {
            CveRecord record;
            record.cve_id = cve_id;
            record.severity = severity;
            record.description = description;
            record.published = published;
            record.last_modified = last_modified;
            record.source = "nvd";

            result.records.push_back(std::move(record));
        }
    }

    spdlog::debug("NVD parsed {} records from {} vulnerabilities",
                  result.records.size(), doc["vulnerabilities"].size());

    return result;
}

}  // namespace yuzu::server
