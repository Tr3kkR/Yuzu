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
    // If stop() returns false here it detached a wedged thread, which means the
    // owner did NOT honour the leak contract (ServerImpl::stop() releases the
    // unique_ptr on false, so the dtor normally never runs on that path). By the
    // time the dtor runs on a false result the members are already being torn
    // down under a live thread — unavoidable at that point; the fix lives at the
    // owner (see ServerImpl::stop()). Discard the result here.
    (void)stop();
}

void NvdSyncManager::start() {
    if (sync_thread_.joinable()) {
        return; // already running
    }
    finished_.store(false);
#ifdef __cpp_lib_jthread
    sync_thread_ = std::jthread([this](std::stop_token stop) { sync_loop(stop); });
#else
    stop_requested_ = false;
    sync_thread_ = std::thread([this] { sync_loop(); });
#endif
    spdlog::info("NVD sync manager started (interval={}s)", interval_.count());
}

bool NvdSyncManager::stop() {
    if (!sync_thread_.joinable()) {
        return true; // never started or already cleanly stopped — safe to destroy
    }
#ifdef __cpp_lib_jthread
    sync_thread_.request_stop();
#else
    stop_requested_ = true;
#endif
    {
        std::lock_guard<std::mutex> lock{mu_};
        cv_.notify_all();
    }

    // #1867: bounded join. The sync thread may be wedged in an NVD fetch that
    // ignores its per-request timeouts; an unconditional join() would hang the
    // whole process on shutdown and defeat any restart policy. Wait a short
    // grace period for the loop to exit cleanly, then detach + warn so the
    // process can still terminate. Detach is the lesser evil (the process is
    // going down anyway) versus a permanent hang.
    constexpr auto kGrace = std::chrono::seconds(5);
    const auto deadline = std::chrono::steady_clock::now() + kGrace;
    while (!finished_.load() && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    if (finished_.load()) {
        sync_thread_.join();
        spdlog::info("NVD sync manager stopped");
        return true;
    }
    // Detached: the abandoned thread still references this manager's members
    // (client_, mu_, cv_, status_, and the NvdDatabase). Signal the owner to
    // LEAK this manager instead of destroying it — otherwise the thread wakes
    // (once #1872 lets it make real requests) and writes freed memory. Returning
    // false is the contract for "do not destroy me".
    spdlog::warn("NVD sync thread did not exit within {}s (stuck in a fetch?); detaching + leaking "
                 "the manager to avoid wedging shutdown / a teardown UAF (see #1867)",
                 kGrace.count());
    sync_thread_.detach();
    return false;
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

    // Signal a clean exit so stop() can join() instead of detaching (#1867).
    finished_.store(true);
}

void NvdSyncManager::do_sync() {
    // Reject a concurrent sync (periodic loop vs. detached "Sync now"): running
    // two on the same client_ races last_request_time_ and doubles NVD load.
    bool expected = false;
    if (!sync_active_.compare_exchange_strong(expected, true)) {
        spdlog::info("NVD sync already in progress — skipping this trigger");
        return;
    }
    struct ActiveGuard {
        std::atomic<bool>& flag;
        ~ActiveGuard() { flag.store(false); }
    } active_guard{sync_active_};

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
