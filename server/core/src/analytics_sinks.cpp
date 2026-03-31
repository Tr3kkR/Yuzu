#include "analytics_event_store.hpp"

#include <httplib.h>
#include <spdlog/spdlog.h>

#include <fstream>
#include <string>

namespace yuzu::server {

// ── JsonLinesSink ──────────────────────────────────────────────────────────

class JsonLinesSink : public AnalyticsEventSink {
public:
    explicit JsonLinesSink(std::filesystem::path path) : path_(std::move(path)) {}

    bool send(std::span<const AnalyticsEvent> batch) override {
        std::ofstream out(path_, std::ios::app);
        if (!out) {
            spdlog::error("JsonLinesSink: failed to open {}", path_.string());
            return false;
        }
        for (const auto& event : batch) {
            nlohmann::json j = event;
            out << j.dump() << '\n';
        }
        return out.good();
    }

    std::string name() const override { return "jsonlines:" + path_.string(); }

private:
    std::filesystem::path path_;
};

// ── ClickHouseSink ─────────────────────────────────────────────────────────

class ClickHouseSink : public AnalyticsEventSink {
public:
    ClickHouseSink(std::string url, std::string database, std::string table, std::string username,
                   std::string password)
        : url_(std::move(url)), database_(std::move(database)), table_(std::move(table)),
          username_(std::move(username)), password_(std::move(password)) {}

    bool send(std::span<const AnalyticsEvent> batch) override {
        // Build JSONEachRow body
        std::string body;
        for (const auto& event : batch) {
            nlohmann::json j = event;
            body += j.dump();
            body += '\n';
        }

        // Parse host:port from URL
        // Expect format: "http://host:port" or "https://host:port"
        std::string scheme, host;
        int port = 8123;
        parse_url(url_, scheme, host, port);

        // Simple percent-encode for the INSERT query (spaces → %20)
        auto insert_sql = "INSERT INTO " + table_ + " FORMAT JSONEachRow";
        std::string encoded;
        for (char c : insert_sql) {
            if (c == ' ')
                encoded += "%20";
            else
                encoded += c;
        }
        auto query = "/?database=" + database_ + "&query=" + encoded;

        httplib::Client cli(scheme + "://" + host + ":" + std::to_string(port));
        cli.set_connection_timeout(5);
        cli.set_read_timeout(10);

        httplib::Headers headers;
        if (!username_.empty()) {
            headers.emplace("X-ClickHouse-User", username_);
            headers.emplace("X-ClickHouse-Key", password_);
        }

        auto result = cli.Post(query, headers, body, "application/json");
        if (!result) {
            spdlog::warn("ClickHouseSink: connection failed to {}", url_);
            return false;
        }
        if (result->status != 200) {
            spdlog::warn("ClickHouseSink: HTTP {} — {}", result->status, result->body);
            return false;
        }
        return true;
    }

    std::string name() const override { return "clickhouse:" + url_; }

private:
    std::string url_;
    std::string database_;
    std::string table_;
    std::string username_;
    std::string password_;

    static void parse_url(const std::string& url, std::string& scheme, std::string& host,
                          int& port) {
        // Simple parser for "http://host:port"
        auto scheme_end = url.find("://");
        if (scheme_end == std::string::npos) {
            scheme = "http";
            host = url;
        } else {
            scheme = url.substr(0, scheme_end);
            host = url.substr(scheme_end + 3);
        }
        auto colon = host.rfind(':');
        if (colon != std::string::npos) {
            try {
                port = std::stoi(host.substr(colon + 1));
                host = host.substr(0, colon);
            } catch (...) {}
        }
    }
};

// ── Factory functions ──────────────────────────────────────────────────────

std::unique_ptr<AnalyticsEventSink> make_jsonlines_sink(const std::filesystem::path& path) {
    return std::make_unique<JsonLinesSink>(path);
}

std::unique_ptr<AnalyticsEventSink>
make_clickhouse_sink(const std::string& url, const std::string& database, const std::string& table,
                     const std::string& username, const std::string& password) {
    return std::make_unique<ClickHouseSink>(url, database, table, username, password);
}

} // namespace yuzu::server
