#pragma once

#include "analytics_event.hpp"

#include <sqlite3.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <thread>
#include <vector>

namespace yuzu::server {

/// Abstract sink interface — receives batches of analytics events.
class AnalyticsEventSink {
public:
    virtual ~AnalyticsEventSink() = default;
    virtual bool send(std::span<const AnalyticsEvent> batch) = 0;
    virtual std::string name() const = 0;
};

/// Local SQLite buffer for analytics events with pluggable sinks.
///
/// Pattern matches AuditStore/ResponseStore:
/// - SQLite WAL-mode local buffer (":memory:" in tests)
/// - emit() is thread-safe insert, stamps ingest_time
/// - Background jthread drains buffered events to registered sinks in batches
class AnalyticsEventStore {
public:
    explicit AnalyticsEventStore(const std::filesystem::path& db_path,
                                 int drain_interval_seconds = 10, int batch_size = 100);
    ~AnalyticsEventStore();

    AnalyticsEventStore(const AnalyticsEventStore&) = delete;
    AnalyticsEventStore& operator=(const AnalyticsEventStore&) = delete;

    bool is_open() const;

    /// Insert an event into the buffer. Stamps ingest_time. Thread-safe.
    void emit(AnalyticsEvent event);

    /// Query recent events (for diagnostics / API).
    std::vector<AnalyticsEvent> query_recent(int limit = 50) const;

    /// Number of events waiting to be drained to sinks.
    std::size_t pending_count() const;

    /// Total events emitted since store was opened.
    std::size_t total_emitted() const;

    /// Register a sink. Must be called before start_drain().
    void add_sink(std::unique_ptr<AnalyticsEventSink> sink);

    /// Start the background drain thread.
    void start_drain();

    /// Stop the background drain thread.
    void stop_drain();

private:
    sqlite3* db_{nullptr};
    int drain_interval_seconds_;
    int batch_size_;
#ifdef __cpp_lib_jthread
    std::jthread drain_thread_;
#else
    std::thread drain_thread_;
    std::atomic<bool> stop_requested_{false};
#endif
    mutable std::mutex mu_;
    std::vector<std::unique_ptr<AnalyticsEventSink>> sinks_;

    void create_tables();
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
