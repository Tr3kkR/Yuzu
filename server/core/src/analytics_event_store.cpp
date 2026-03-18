#include "analytics_event_store.hpp"

#include <spdlog/spdlog.h>
#include <sqlite3.h>

#include <chrono>

namespace yuzu::server {

AnalyticsEventStore::AnalyticsEventStore(const std::filesystem::path& db_path,
                                         int drain_interval_seconds, int batch_size)
    : drain_interval_seconds_(drain_interval_seconds), batch_size_(batch_size) {
    int rc = sqlite3_open(db_path.string().c_str(), &db_);
    if (rc != SQLITE_OK) {
        spdlog::error("AnalyticsEventStore: failed to open {}: {}", db_path.string(),
                      sqlite3_errmsg(db_));
        if (db_) {
            sqlite3_close(db_);
            db_ = nullptr;
        }
        return;
    }

    sqlite3_exec(db_, "PRAGMA journal_mode=WAL;", nullptr, nullptr, nullptr);
    sqlite3_exec(db_, "PRAGMA busy_timeout=5000;", nullptr, nullptr, nullptr);
    create_tables();
    spdlog::info("AnalyticsEventStore: opened {}", db_path.string());
}

AnalyticsEventStore::~AnalyticsEventStore() {
    stop_drain();
    if (db_)
        sqlite3_close(db_);
}

bool AnalyticsEventStore::is_open() const {
    return db_ != nullptr;
}

void AnalyticsEventStore::create_tables() {
    const char* sql = R"(
        CREATE TABLE IF NOT EXISTS analytics_buffer (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            event_json TEXT    NOT NULL,
            created_at INTEGER NOT NULL,
            drained    INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_analytics_drained
            ON analytics_buffer(drained, id);
    )";
    char* err = nullptr;
    if (sqlite3_exec(db_, sql, nullptr, nullptr, &err) != SQLITE_OK) {
        spdlog::error("AnalyticsEventStore: create_tables failed: {}", err ? err : "unknown");
        sqlite3_free(err);
    }
}

void AnalyticsEventStore::emit(AnalyticsEvent event) {
    if (!db_)
        return;

    // Stamp ingest_time
    event.ingest_time = now_ms();
    if (event.event_time == 0) {
        event.event_time = event.ingest_time;
    }

    nlohmann::json j = event;
    auto json_str = j.dump();

    const char* sql = "INSERT INTO analytics_buffer (event_json, created_at) VALUES (?, ?)";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return;

    sqlite3_bind_text(stmt, 1, json_str.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 2, event.ingest_time);

    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

std::vector<AnalyticsEvent> AnalyticsEventStore::query_recent(int limit) const {
    std::vector<AnalyticsEvent> results;
    if (!db_)
        return results;

    auto sql =
        "SELECT event_json FROM analytics_buffer ORDER BY id DESC LIMIT " + std::to_string(limit);
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK)
        return results;

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        auto text = sqlite3_column_text(stmt, 0);
        if (!text)
            continue;
        try {
            auto j = nlohmann::json::parse(reinterpret_cast<const char*>(text));
            results.push_back(j.get<AnalyticsEvent>());
        } catch (...) {}
    }
    sqlite3_finalize(stmt);
    return results;
}

std::size_t AnalyticsEventStore::pending_count() const {
    if (!db_)
        return 0;
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, "SELECT COUNT(*) FROM analytics_buffer WHERE drained = 0", -1,
                           &stmt, nullptr) != SQLITE_OK)
        return 0;
    std::size_t count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW)
        count = static_cast<std::size_t>(sqlite3_column_int64(stmt, 0));
    sqlite3_finalize(stmt);
    return count;
}

std::size_t AnalyticsEventStore::total_emitted() const {
    if (!db_)
        return 0;
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, "SELECT COUNT(*) FROM analytics_buffer", -1, &stmt, nullptr) !=
        SQLITE_OK)
        return 0;
    std::size_t count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW)
        count = static_cast<std::size_t>(sqlite3_column_int64(stmt, 0));
    sqlite3_finalize(stmt);
    return count;
}

void AnalyticsEventStore::add_sink(std::unique_ptr<AnalyticsEventSink> sink) {
    std::lock_guard lock(mu_);
    spdlog::info("AnalyticsEventStore: registered sink '{}'", sink->name());
    sinks_.push_back(std::move(sink));
}

void AnalyticsEventStore::start_drain() {
    if (!db_ || drain_interval_seconds_ <= 0)
        return;
    std::lock_guard lock(mu_);
    if (sinks_.empty())
        return;
#ifdef __cpp_lib_jthread
    drain_thread_ = std::jthread([this](std::stop_token stop) { run_drain(stop); });
#else
    stop_requested_ = false;
    drain_thread_ = std::thread([this] { run_drain(); });
#endif
}

void AnalyticsEventStore::stop_drain() {
#ifdef __cpp_lib_jthread
    if (drain_thread_.joinable()) {
        drain_thread_.request_stop();
        drain_thread_.join();
    }
#else
    if (drain_thread_.joinable()) {
        stop_requested_ = true;
        drain_thread_.join();
    }
#endif
}

#ifdef __cpp_lib_jthread
void AnalyticsEventStore::run_drain(std::stop_token stop) {
    while (!stop.stop_requested()) {
        for (int i = 0; i < drain_interval_seconds_ && !stop.stop_requested(); ++i) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        if (stop.stop_requested())
            break;
#else
void AnalyticsEventStore::run_drain() {
    while (!stop_requested_.load()) {
        for (int i = 0; i < drain_interval_seconds_ && !stop_requested_.load(); ++i) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        if (stop_requested_.load())
            break;
#endif
        drain_batch();
    }
}

void AnalyticsEventStore::drain_batch() {
    if (!db_)
        return;

    // Read a batch of undrained events
    auto sql =
        "SELECT id, event_json FROM analytics_buffer WHERE drained = 0 ORDER BY id ASC LIMIT " +
        std::to_string(batch_size_);
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK)
        return;

    std::vector<int64_t> ids;
    std::vector<AnalyticsEvent> events;

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        auto id = sqlite3_column_int64(stmt, 0);
        auto text = sqlite3_column_text(stmt, 1);
        if (!text)
            continue;
        try {
            auto j = nlohmann::json::parse(reinterpret_cast<const char*>(text));
            events.push_back(j.get<AnalyticsEvent>());
            ids.push_back(id);
        } catch (...) {}
    }
    sqlite3_finalize(stmt);

    if (events.empty())
        return;

    // Send to all sinks
    bool all_ok = true;
    {
        std::lock_guard lock(mu_);
        for (auto& sink : sinks_) {
            if (!sink->send(events)) {
                spdlog::warn("AnalyticsEventStore: sink '{}' failed for batch of {}", sink->name(),
                             events.size());
                all_ok = false;
            }
        }
    }

    // Mark as drained only if all sinks succeeded
    if (all_ok && !ids.empty()) {
        std::string id_list;
        for (size_t i = 0; i < ids.size(); ++i) {
            if (i > 0)
                id_list += ',';
            id_list += std::to_string(ids[i]);
        }
        auto update_sql = "UPDATE analytics_buffer SET drained = 1 WHERE id IN (" + id_list + ")";
        sqlite3_exec(db_, update_sql.c_str(), nullptr, nullptr, nullptr);
    }
}

} // namespace yuzu::server
