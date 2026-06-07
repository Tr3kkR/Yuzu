#pragma once

/// @file offload_target_store.hpp
/// Phase 8.3 (#255) — Response Offloading. Configurable external HTTP
/// endpoints that receive response data in real time.
///
/// Reuses the WebhookStore delivery pattern (counting-semaphore-bounded
/// detached thread per delivery, async record), and adds:
///   - typed auth (none / bearer / basic / hmac)
///   - server-side batching (`batch_size > 1` accumulates events into a
///     per-target buffer and flushes on threshold or on `flush_all()`)
///   - per-target name → callers can name a target and reference it from
///     `spec.offload.targets` in InstructionDefinition YAML
///
/// Secrets (auth_credential) are persisted but NEVER returned by `list()`.
/// The `fire_event` call path is fire-and-forget and acquires a 10-slot
/// semaphore so a slow endpoint can't drown the server.

#include <sqlite3.h>

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

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

    /// Destruction does NOT flush pending batched events. Detached worker
    /// threads spawned by `fire_event` / `flush_all` capture the store
    /// pointer; flushing in the destructor would race the SQLite handle
    /// close. Operators that need at-least-once delivery semantics should
    /// (a) use `batch_size = 1` (immediate dispatch) or (b) call
    /// `flush_all()` on a graceful-shutdown path before the store is
    /// destroyed. Detached deliveries already in flight when the store
    /// is destroyed are best-effort: each captured an `OffloadTarget`
    /// by value so it can finish independently of the store, but the
    /// `record_delivery` step that writes to `offload_deliveries.db`
    /// will silently no-op once the underlying SQLite handle is closed.
    /// Mirrors the WebhookStore precedent.
    ~OffloadTargetStore();

    OffloadTargetStore(const OffloadTargetStore&) = delete;
    OffloadTargetStore& operator=(const OffloadTargetStore&) = delete;

    bool is_open() const;

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

    /// Build the JSON body to POST. For a single event this is the raw
    /// payload_json. For a batched flush, the events are wrapped in a
    /// JSON array under `{"events":[…]}`.
    static std::string build_batch_body(const std::vector<BufferedEvent>& events);
};

} // namespace yuzu::server
