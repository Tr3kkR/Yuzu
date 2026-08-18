#pragma once

/// @file offload_target_store.hpp
/// Phase 8.3 (#255) — Response Offloading. Configurable external HTTP
/// endpoints that receive response data in real time.
///
/// Reuses the WebhookStore delivery pattern (bounded-worker-pool dispatch
/// per delivery, async record - see store_worker_pool.hpp), and adds:
///   - typed auth (none / bearer / basic / hmac)
///   - server-side batching (`batch_size > 1` accumulates events into a
///     per-target buffer and flushes on threshold or on `flush_all()`)
///   - per-target name → callers can name a target and reference it from
///     `spec.offload.targets` in InstructionDefinition YAML
///
/// Secrets (auth_credential) are persisted but NEVER returned by `list()`.
/// The `fire_event` call path is fire-and-forget and dispatches onto the
/// bounded worker pool so a slow endpoint can't drown the server.

#include "store_worker_pool.hpp"

#include <sqlite3.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace yuzu {
class MetricsRegistry;
}

namespace yuzu::server {

enum class OffloadAuthType {
    None,
    Bearer,
    Basic,
    Hmac,
};

/// Convert auth-type enum ↔ wire string. Wire strings are lowercase.
std::string offload_auth_type_to_string(OffloadAuthType t);
OffloadAuthType offload_auth_type_from_string(const std::string& s);

struct OffloadTarget {
    int64_t id{0};
    std::string name;
    std::string url;
    OffloadAuthType auth_type{OffloadAuthType::None};
    /// Bearer: token. Basic: "user:pass". Hmac: shared secret. Never
    /// returned from `list()`.
    std::string auth_credential;
    /// Comma-separated event types or "*". Same semantics as WebhookStore.
    std::string event_types;
    /// 1 = no batching (deliver each event immediately).
    /// >1 = accumulate up to N events before POST.
    int batch_size{1};
    bool enabled{true};
    int64_t created_at{0};
};

struct OffloadDelivery {
    int64_t id{0};
    int64_t target_id{0};
    std::string event_type;
    /// Number of events in this delivery (>=1 when batching).
    int event_count{1};
    /// JSON payload. For batches this is a JSON array.
    std::string payload;
    int status_code{0};
    int64_t delivered_at{0};
    std::string error;
};

class OffloadTargetStore {
public:
    explicit OffloadTargetStore(const std::filesystem::path& db_path);

    /// Destruction does NOT flush pending batched events - call
    /// `flush_all()` on a graceful-shutdown path first if at-least-once
    /// delivery for batched (`batch_size > 1`) targets matters; anything
    /// still buffered when this destructs is dropped.
    ///
    /// #3261 governance hardening: deliveries used to run on raw detached
    /// `std::thread`s with no join, so this comment used to say a delivery
    /// still in flight at destruction time would race the SQLite handle
    /// close and "silently no-op" - that was optimistic; it was actually a
    /// use-after-free (`record_delivery` locks `mtx_`, a member, as its
    /// first statement). Deliveries now run on `pool_`, a bounded worker
    /// pool this destructor drains BEFORE closing `db_` (see the .cpp), so
    /// a delivery in flight at destruction time now blocks the destructor
    /// until it finishes rather than racing it. `flush_all()` before
    /// destruction is still the right call for at-least-once semantics on
    /// batched targets - it is about not LOSING buffered events, not about
    /// safety, which the pool now guarantees unconditionally.
    ~OffloadTargetStore();

    OffloadTargetStore(const OffloadTargetStore&) = delete;
    OffloadTargetStore& operator=(const OffloadTargetStore&) = delete;

    bool is_open() const;

    /// Wire a metrics sink for delivery outcome counters. Set-before-traffic
    /// contract, same as DexAlertRouter::set_metrics.
    void set_metrics(yuzu::MetricsRegistry* metrics);

    /// Stop accepting new deliveries and wait up to `timeout` for every
    /// queued/in-flight delivery to finish. Returns true if fully drained.
    /// The caller (ServerImpl::stop()) MUST NOT destroy this store if this
    /// returns false - see store_worker_pool.hpp's header comment.
    bool quiesce(std::chrono::milliseconds timeout);

    /// Create a new offload target. Returns the assigned id, or -1 on
    /// validation failure (invalid URL scheme, empty name, duplicate
    /// name, batch_size < 1).
    int64_t create_target(const std::string& name, const std::string& url,
                          OffloadAuthType auth_type, const std::string& auth_credential,
                          const std::string& event_types, int batch_size = 1,
                          bool enabled = true);

    /// List all targets (auth_credential redacted). Newest first.
    std::vector<OffloadTarget> list(int limit = 100, int offset = 0) const;

    /// Get a single target by id (auth_credential redacted).
    std::optional<OffloadTarget> get(int64_t id) const;

    /// Look up a target by name (auth_credential redacted).
    std::optional<OffloadTarget> get_by_name(const std::string& name) const;

    /// Delete a target. Cascades on offload_deliveries.
    bool delete_target(int64_t id);

    /// Recent deliveries for a target.
    std::vector<OffloadDelivery> get_deliveries(int64_t target_id, int limit = 50) const;

    /// Fire an event to all enabled, matching targets. Honours batching:
    /// when a target has `batch_size > 1`, the event is appended to an
    /// in-memory buffer keyed on `target_id`. When the buffer reaches
    /// `batch_size`, it is flushed asynchronously. `target_filter`
    /// (optional non-empty) limits dispatch to targets named in the
    /// vector — `spec.offload.targets` in InstructionDefinition YAML.
    ///
    /// Per the Phase 8.3 doc, `fire_event` returns immediately;
    /// deliveries run on detached worker threads.
    void fire_event(const std::string& event_type, const std::string& payload_json,
                    const std::vector<std::string>& target_filter = {});

    /// Flush any non-empty per-target buffers regardless of batch_size.
    /// Useful for graceful shutdown and tests.
    void flush_all();

    /// Compute HMAC-SHA256 signature for HMAC auth. Same primitive as
    /// WebhookStore::hmac_sha256.
    static std::string hmac_sha256(const std::string& secret, const std::string& data);

    /// Base64-encode bytes for the Basic auth header.
    static std::string base64_encode(const std::string& data);

private:
    sqlite3* db_{nullptr};
    mutable std::shared_mutex mtx_;
    yuzu::MetricsRegistry* metrics_{nullptr};

    /// Per-target accumulator for `batch_size > 1`. Guarded by buf_mu_;
    /// kept separate from mtx_ so a flush in flight does not block the
    /// REST list/get paths.
    struct BufferedEvent {
        std::string event_type;
        std::string payload_json;
    };
    mutable std::mutex buf_mu_;
    std::unordered_map<int64_t, std::vector<BufferedEvent>> buffers_;

    void create_tables();
    void deliver_single(const OffloadTarget& tgt, const std::string& event_type,
                        int event_count, const std::string& payload_body);
    void record_delivery(int64_t target_id, const std::string& event_type, int event_count,
                         const std::string& payload, int status_code, const std::string& error);

    /// Log + count a delivery dropped because pool_.submit() returned
    /// false (queue full or the store is quiescing/shutting down).
    void log_dropped_delivery(const std::string& target_url);

    /// Build the JSON body to POST. For a single event this is the raw
    /// payload_json. For a batched flush, the events are wrapped in a
    /// JSON array under `{"events":[…]}`.
    static std::string build_batch_body(const std::vector<BufferedEvent>& events);

    // LAST-DECLARED MEMBER (#3261 governance hardening) - see the identical
    // comment on WebhookStore::pool_ in webhook_store.hpp. The destructor
    // still drains this explicitly before touching db_/mtx_ (a
    // destructor's body runs before its members' destructors), so this
    // ordering is defense in depth, not the sole guarantee.
    StoreWorkerPool pool_{/*num_threads=*/4, /*max_queue=*/256};
};

} // namespace yuzu::server
