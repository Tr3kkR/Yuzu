#pragma once

#include <sqlite3.h>

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <shared_mutex>
#include <string>
#include <vector>

namespace yuzu::server {

struct Webhook {
    int64_t id{0};
    std::string url;
    std::string event_types; // comma-separated: "agent.registered,execution.completed"
    std::string secret;      // HMAC-SHA256 signing secret
    bool enabled{true};
    int64_t created_at{0};
};

struct WebhookDelivery {
    int64_t id{0};
    int64_t webhook_id{0};
    std::string event_type;
    std::string payload; // JSON
    int status_code{0};
    int64_t delivered_at{0};
    std::string error;
};

class WebhookStore {
public:
    explicit WebhookStore(const std::filesystem::path& db_path);
    ~WebhookStore();

    WebhookStore(const WebhookStore&) = delete;
    WebhookStore& operator=(const WebhookStore&) = delete;

    bool is_open() const;

    /// Create a new webhook. Returns the assigned id.
    int64_t create_webhook(const std::string& url, const std::string& event_types,
                           const std::string& secret, bool enabled = true);

    /// List all webhooks.
    std::vector<Webhook> list(int limit = 100, int offset = 0) const;

    /// Delete a webhook by id.
    bool delete_webhook(int64_t id);

    /// Get recent deliveries for a webhook.
    std::vector<WebhookDelivery> get_deliveries(int64_t webhook_id, int limit = 50) const;

    /// Fire an event to all matching webhooks asynchronously.
    /// Each delivery runs on a detached thread; a counting semaphore limits
    /// concurrent deliveries to 10 to prevent thread explosion.
    void fire_event(const std::string& event_type, const std::string& payload_json);

    /// Compute HMAC-SHA256 signature for webhook payload verification.
    static std::string hmac_sha256(const std::string& secret, const std::string& data);

private:
    sqlite3* db_{nullptr};
    mutable std::shared_mutex mtx_;

    void create_tables();
    void deliver_single(const Webhook& wh, const std::string& event_type,
                        const std::string& payload_json);
    void record_delivery(int64_t webhook_id, const std::string& event_type,
                         const std::string& payload, int status_code, const std::string& error);
};

} // namespace yuzu::server
