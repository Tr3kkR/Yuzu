#include "nvd_sync.hpp"

#include <spdlog/spdlog.h>

#include <array>
#include <chrono>
#include <format>

namespace yuzu::server {

namespace {

std::string current_iso_timestamp() {
    const auto now = std::chrono::system_clock::now();
    return std::format("{:%FT%TZ}", std::chrono::floor<std::chrono::seconds>(now));
}

constexpr std::array kInitialSyncKeywords = {
    "openssl", "curl",    "sudo",   "openssh", "apache", "nginx",   "postgresql",
    "python",  "node.js", "chrome", "firefox", "dotnet", "openjdk", "log4j",
    "git",     "php",     "putty",  "7-zip",   "winrar", "windows",
};

} // namespace

NvdSyncManager::NvdSyncManager(std::shared_ptr<NvdDatabase> db, std::string api_key,
                               std::string proxy_url, std::chrono::seconds sync_interval)
    : db_{std::move(db)}, client_{std::move(api_key), std::move(proxy_url)},
      interval_{sync_interval} {}

NvdSyncManager::~NvdSyncManager() {
    stop();
}

void NvdSyncManager::start() {
    if (sync_thread_.joinable()) {
        return; // already running
    }
#ifdef __cpp_lib_jthread
    sync_thread_ = std::jthread([this](std::stop_token stop) { sync_loop(stop); });
#else
    stop_requested_ = false;
    sync_thread_ = std::thread([this] { sync_loop(); });
#endif
    spdlog::info("NVD sync manager started (interval={}s)", interval_.count());
}

void NvdSyncManager::stop() {
    if (!sync_thread_.joinable()) {
        return;
    }
#ifdef __cpp_lib_jthread
    sync_thread_.request_stop();
    {
        std::lock_guard<std::mutex> lock{mu_};
        cv_.notify_all();
    }
    sync_thread_.join();
#else
    stop_requested_ = true;
    {
        std::lock_guard<std::mutex> lock{mu_};
        cv_.notify_all();
    }
    sync_thread_.join();
#endif
    spdlog::info("NVD sync manager stopped");
}

void NvdSyncManager::sync_now() {
    do_sync();
}

NvdSyncManager::SyncStatus NvdSyncManager::status() const {
    std::lock_guard<std::mutex> lock{mu_};
    return status_;
}

#ifdef __cpp_lib_jthread
void NvdSyncManager::sync_loop(std::stop_token stop) {
#else
void NvdSyncManager::sync_loop() {
#endif
    // Seed built-in rules on first run
    try {
        db_->seed_builtin_rules();
        spdlog::info("NVD built-in rules seeded");
    } catch (const std::exception& e) {
        spdlog::error("Failed to seed built-in rules: {}", e.what());
    }

    // Immediate first sync
    do_sync();

    // Periodic sync loop
#ifdef __cpp_lib_jthread
    while (!stop.stop_requested()) {
        std::unique_lock<std::mutex> lock{mu_};
        cv_.wait_for(lock, interval_, [&stop] { return stop.stop_requested(); });
        if (stop.stop_requested())
            break;
#else
    while (!stop_requested_.load()) {
        std::unique_lock<std::mutex> lock{mu_};
        cv_.wait_for(lock, interval_, [this] { return stop_requested_.load(); });
        if (stop_requested_.load())
            break;
#endif
        lock.unlock();
        do_sync();
    }
}

void NvdSyncManager::do_sync() {
    {
        std::lock_guard<std::mutex> lock{mu_};
        status_.syncing = true;
        status_.last_error.clear();
    }

    try {
        auto last_sync = db_->get_meta("last_sync_time");
        if (last_sync.empty()) {
            spdlog::info("No previous sync found — starting initial sync");
            do_initial_sync();
        } else {
            spdlog::info("Last sync: {} — starting incremental sync", last_sync);
            do_incremental_sync();
        }

        std::lock_guard<std::mutex> lock{mu_};
        status_.total_cves = db_->total_cve_count();
        status_.last_sync_time = db_->get_meta("last_sync_time");
        status_.syncing = false;
    } catch (const std::exception& e) {
        spdlog::error("NVD sync failed: {}", e.what());
        std::lock_guard<std::mutex> lock{mu_};
        status_.last_error = e.what();
        status_.syncing = false;
    }
}

void NvdSyncManager::do_initial_sync() {
    std::size_t total_upserted = 0;

    for (const auto* keyword : kInitialSyncKeywords) {
        spdlog::info("Initial sync: fetching CVEs for '{}'", keyword);

        int start_index = 0;
        int fetched_this_keyword = 0;

        while (true) {
            auto result = client_.fetch_by_keyword(keyword, start_index);

            if (result.records.empty()) {
                break;
            }

            db_->upsert_cves(result.records);
            fetched_this_keyword += static_cast<int>(result.records.size());
            total_upserted += result.records.size();

            // If we got fewer than total_results, advance pagination
            start_index += static_cast<int>(result.records.size());
            if (start_index >= result.total_results) {
                break;
            }
        }

        spdlog::info("Initial sync: '{}' — {} CVEs fetched", keyword, fetched_this_keyword);
    }

    db_->set_meta("last_sync_time", current_iso_timestamp());
    spdlog::info("Initial sync complete: {} total CVEs upserted", total_upserted);
}

void NvdSyncManager::do_incremental_sync() {
    auto last_sync = db_->get_meta("last_sync_time");
    std::size_t total_upserted = 0;
    std::string latest_modified;

    auto result = client_.fetch_modified_since(last_sync);

    if (!result.records.empty()) {
        db_->upsert_cves(result.records);
        total_upserted += result.records.size();
        latest_modified = result.last_modified_timestamp;
    }

    // Update sync timestamp to the latest lastModified from results,
    // or current time if there were no results
    auto new_sync_time = latest_modified.empty() ? current_iso_timestamp() : latest_modified;
    db_->set_meta("last_sync_time", new_sync_time);

    spdlog::info("Incremental sync complete: {} CVEs updated, new sync time: {}", total_upserted,
                 new_sync_time);
}

} // namespace yuzu::server
