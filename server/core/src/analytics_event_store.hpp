#pragma once

/// @file analytics_event_store.hpp
/// PostgreSQL-backed outbox/spool for analytics events (ADR-0049, schema
/// `analytics_event_store`). `emit()` inserts into `analytics_buffer`; a
/// background thread drains undrained rows to registered `AnalyticsEventSink`s
/// in batches. Not operator state — expendable, best-effort telemetry.
///
/// Posture (ADR-0012 §1 / ADR-0049): CONSTRUCTION is fail-closed like every
/// other Postgres-backed store (a reachable database whose schema can't be
/// migrated is a deploy error) — but only when the feature is enabled
/// (`--analytics-drain-interval`'s sibling `cfg_.analytics_enabled`); the
/// store is simply not constructed when the feature is off. RUNTIME ingest is
/// fail-SOFT (`emit()` never blocks or throws into the calling request path —
/// writers include the auth/SCIM routes) and reads (`query_recent`,
/// `pending_count`) are degrade-distinguishable at the seam
/// (`std::optional`, `nullopt` on a DB error, never a false-empty). Backfill
/// is SKIPPABLE (ADR-0009 exception, recorded in ADR-0049): the spool is
/// transient by design and a drained row is already delivered.
///
/// The drain pass is single-sweeper fleet-wide via a
/// `pg_try_advisory_xact_lock` lease (the AuditStore/ResultSetStore pattern),
/// but — unlike a pure-DB reap — the actual sink delivery is network I/O, so
/// the claim (advisory lock + `UPDATE ... RETURNING` inside one transaction)
/// and the send (no lease held) are two separate steps; a batch whose sinks
/// don't all succeed is reverted (`drained = false`) in a third, separate
/// statement. See analytics_event_store.cpp's `drain_batch()` for the exact
/// three-phase shape and its at-most-once-on-crash / at-least-once-on-partial-
/// sink-failure delivery semantics.
///
/// Substrate contract (ADR-0008): the store holds a `PgPool&` (not a
/// `sqlite3*`), runs its schema migration at construction on a pinned lease,
/// and schema-qualifies every runtime statement
/// (`analytics_event_store.analytics_buffer`) — pooled connections carry no
/// per-store search_path. Mutate-and-return uses `RETURNING`, never
/// `sqlite3_changes()`.

#include "analytics_event.hpp"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <thread>
#include <vector>

namespace yuzu::server::pg {
class PgPool;
}

namespace yuzu {
class MetricsRegistry;
}

namespace yuzu::server {

/// Abstract sink interface — receives batches of analytics events.
class AnalyticsEventSink {
public:
    virtual ~AnalyticsEventSink() = default;
    virtual bool send(std::span<const AnalyticsEvent> batch) = 0;
    virtual std::string name() const = 0;
};

/// PostgreSQL-backed outbox for analytics events with pluggable sinks.
class AnalyticsEventStore {
public:
    /// Borrows the shared pool and runs the `analytics_event_store` schema
    /// migration on a pinned lease. `is_open()` is false if the lease was
    /// empty or the migration failed.
    explicit AnalyticsEventStore(pg::PgPool& pool, int drain_interval_seconds = 10,
                                 int batch_size = 100);
    ~AnalyticsEventStore();

    AnalyticsEventStore(const AnalyticsEventStore&) = delete;
    AnalyticsEventStore& operator=(const AnalyticsEventStore&) = delete;

    [[nodiscard]] bool is_open() const noexcept { return open_; }

    /// Wires the Prometheus counters (`yuzu_server_analytics_emit_dropped_total`,
    /// `yuzu_server_analytics_read_degrade_total`). Optional — a null registry
    /// (never set) just skips the increment, matching ResponseStore.
    void set_metrics(yuzu::MetricsRegistry* metrics) noexcept { metrics_ = metrics; }

    /// Insert an event into the buffer. Stamps ingest_time. Thread-safe,
    /// fail-soft: a store-not-open / pool-acquire-timeout / query error never
    /// throws or blocks the caller — the drop is counted
    /// (`yuzu_server_analytics_emit_dropped_total{reason}`) and logged at
    /// debug, never silently swallowed.
    void emit(AnalyticsEvent event);

    /// Query recent events (for diagnostics / API), newest first.
    /// `nullopt` on a degraded read (store not open, pool timeout, query
    /// error) — distinct from a genuinely empty buffer.
    [[nodiscard]] std::optional<std::vector<AnalyticsEvent>> query_recent(int limit = 50) const;

    /// Number of events waiting to be drained to sinks. `nullopt` on a
    /// degraded read.
    [[nodiscard]] std::optional<std::size_t> pending_count() const;

    /// Total events successfully emitted since this store was constructed
    /// (in-process counter, matches the SQLite predecessor's documented
    /// "since store was opened" contract — never a full-table scan of the
    /// ever-growing buffer).
    [[nodiscard]] std::size_t total_emitted() const noexcept;

    /// Register a sink. Must be called before start_drain().
    void add_sink(std::unique_ptr<AnalyticsEventSink> sink);

    /// Start the background drain thread.
    void start_drain();

    /// Stop the background drain thread.
    void stop_drain();

private:
    pg::PgPool& pool_;
    bool open_{false};
    int drain_interval_seconds_;
    int batch_size_;
#ifdef __cpp_lib_jthread
    std::jthread drain_thread_;
#else
    std::thread drain_thread_;
    std::atomic<bool> stop_requested_{false};
#endif
    std::atomic<std::uint64_t> total_emitted_{0};
    yuzu::MetricsRegistry* metrics_{nullptr};
    std::vector<std::unique_ptr<AnalyticsEventSink>> sinks_;

#ifdef __cpp_lib_jthread
    void run_drain(std::stop_token stop);
#else
    void run_drain();
#endif
    void drain_batch();
};

/// Factory: create a JSONL file sink.
std::unique_ptr<AnalyticsEventSink> make_jsonlines_sink(const std::filesystem::path& path);

/// Factory: create a ClickHouse HTTP sink.
std::unique_ptr<AnalyticsEventSink>
make_clickhouse_sink(const std::string& url, const std::string& database, const std::string& table,
                     const std::string& username, const std::string& password);

} // namespace yuzu::server
