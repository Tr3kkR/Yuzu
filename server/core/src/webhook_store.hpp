#pragma once

#include "store_worker_pool.hpp"

#include <sqlite3.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <shared_mutex>
#include <string>
#include <vector>

namespace yuzu {
class MetricsRegistry;
}

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

    /// Wire a metrics sink for delivery outcome counters. Set-before-traffic
    /// contract, same as DexAlertRouter::set_metrics - call once, before
    /// the store is wired into agent_service_.
    void set_metrics(yuzu::MetricsRegistry* metrics);

    /// Stop accepting new deliveries and wait up to `timeout` for every
    /// queued/in-flight delivery to finish. Returns true if fully drained.
    /// The caller (ServerImpl::stop()) MUST NOT destroy this store if this
    /// returns false - see store_worker_pool.hpp's header comment.
    bool quiesce(std::chrono::milliseconds timeout);

    /// Create a new webhook. Returns the assigned id.
    int64_t create_webhook(const std::string& url, const std::string& event_types,
                           const std::string& secret, bool enabled = true);

    /// List all webhooks.
    std::vector<Webhook> list(int limit = 100, int offset = 0) const;

    /// Delete a webhook by id.
    bool delete_webhook(int64_t id);

    /// Get recent deliveries for a webhook.
    std::vector<WebhookDelivery> get_deliveries(int64_t webhook_id, int limit = 50) const;

    /// Fire an event to all matching webhooks asynchronously. Each delivery
    /// runs on the bounded worker pool (see `pool_` below) - never a raw
    /// thread - so concurrency and thread creation are both capped.
    void fire_event(const std::string& event_type, const std::string& payload_json);

    /// Compute HMAC-SHA256 signature for webhook payload verification.
    static std::string hmac_sha256(const std::string& secret, const std::string& data);

private:
    sqlite3* db_{nullptr};
    mutable std::shared_mutex mtx_;
    yuzu::MetricsRegistry* metrics_{nullptr};

    void create_tables();
    void deliver_single(const Webhook& wh, const std::string& event_type,
                        const std::string& payload_json);
    void record_delivery(int64_t webhook_id, const std::string& event_type,
                         const std::string& payload, int status_code, const std::string& error);

    // LAST-DECLARED MEMBER (#3261 governance hardening) - see the identical
    // comment on OffloadTargetStore::pool_ in offload_target_store.hpp. The
    // destructor still drains this explicitly before touching db_/mtx_ (a
    // destructor's body runs before its members' destructors), so this
    // ordering is defense in depth, not the sole guarantee - an earlier
    // version of this comment claimed declaration order alone was
    // sufficient, which is false and was corrected in review (Gate 8
    // consistency-auditor): it contradicted this file's own .cpp, where
    // ~WebhookStore's comment already states the real mechanism.
    StoreWorkerPool pool_{/*num_threads=*/4, /*max_queue=*/256};
};

} // namespace yuzu::server
