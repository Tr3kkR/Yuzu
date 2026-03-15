#pragma once

#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

#include "nvd_client.hpp"
#include "nvd_db.hpp"

namespace yuzu::server {

class NvdSyncManager {
public:
    NvdSyncManager(std::shared_ptr<NvdDatabase> db,
                   std::string api_key,
                   std::string proxy_url,
                   std::chrono::seconds sync_interval);
    ~NvdSyncManager();

    NvdSyncManager(const NvdSyncManager&) = delete;
    NvdSyncManager& operator=(const NvdSyncManager&) = delete;

    void start();  // Start background sync thread
    void stop();   // Signal stop and join thread

    // Manual sync (blocks until complete)
    void sync_now();

    // Status info for UI
    struct SyncStatus {
        bool syncing = false;
        std::string last_sync_time;  // ISO 8601 or empty
        std::size_t total_cves = 0;
        std::string last_error;
    };
    SyncStatus status() const;

private:
    std::shared_ptr<NvdDatabase> db_;
    NvdClient client_;
    std::chrono::seconds interval_;

    std::jthread sync_thread_;
    mutable std::mutex mu_;
    std::condition_variable cv_;
    SyncStatus status_;

    void sync_loop(std::stop_token token);
    void do_sync();
    void do_initial_sync();
    void do_incremental_sync();
};

}  // namespace yuzu::server
