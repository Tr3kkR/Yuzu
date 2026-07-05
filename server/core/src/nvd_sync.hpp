#pragma once

#include "nvd_client.hpp"
#include "nvd_db.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

namespace yuzu::server {

class NvdSyncManager {
public:
    NvdSyncManager(std::shared_ptr<NvdDatabase> db, std::string api_key, std::string proxy_url,
                   std::chrono::seconds sync_interval);
    ~NvdSyncManager();

    NvdSyncManager(const NvdSyncManager&) = delete;
    NvdSyncManager& operator=(const NvdSyncManager&) = delete;

    void start(); // Start background sync thread
    // Signal stop and join the sync thread. Returns true when the manager is safe
    // to destroy (thread joined cleanly, or never started). Returns FALSE when a
    // wedged thread had to be detached and still references this manager — the
    // owner MUST then leak the manager (not destroy it) to avoid a teardown UAF
    // (see ServerImpl::stop(), #1867).
    [[nodiscard]] bool stop();

    // Manual sync (blocks until complete)
    void sync_now();

    // Status info for UI
    struct SyncStatus {
        bool syncing = false;
        std::string last_sync_time; // ISO 8601 or empty
        std::size_t total_cves = 0;
        std::string last_error;
    };
    SyncStatus status() const;

private:
    std::shared_ptr<NvdDatabase> db_;
    NvdClient client_;
    std::chrono::seconds interval_;

#ifdef __cpp_lib_jthread
    std::jthread sync_thread_;
#else
    std::thread sync_thread_;
    std::atomic<bool> stop_requested_{false};
#endif
    mutable std::mutex mu_;
    std::condition_variable cv_;
    SyncStatus status_;
    // Serialises do_sync(): the periodic loop and the detached POST /api/nvd/sync
    // thread both call it on the same NvdClient; running two concurrently races
    // the client's rate-limit state and doubles NVD load (#1867 governance).
    std::atomic<bool> sync_active_{false};
    // Set true when sync_loop() actually returns. stop() waits on this so a
    // thread wedged in an uncancellable fetch (#1867) is detached rather than
    // joined-forever, letting the process exit instead of hanging shutdown.
    std::atomic<bool> finished_{false};

#ifdef __cpp_lib_jthread
    void sync_loop(std::stop_token stop);
#else
    void sync_loop();
#endif
    void do_sync();
    void do_initial_sync();
    void do_incremental_sync();
};

} // namespace yuzu::server
