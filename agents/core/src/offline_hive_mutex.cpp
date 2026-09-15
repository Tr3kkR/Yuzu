#include <yuzu/agent/offline_hive_mutex.hpp>

#include <spdlog/spdlog.h>

namespace yuzu::agent {

std::mutex& offline_hive_mutex() {
    static std::mutex m;
    return m;
}

namespace {
// A hold past this length is unusual enough (the offline arm is file-I/O
// bound, not compute-bound) to warrant a warn rather than a debug log --
// see offline_hive_mutex.hpp's INSTRUMENTATION note.
constexpr auto kSlowHoldWarnThreshold = std::chrono::milliseconds(500);
} // namespace

ScopedOfflineHiveLock::ScopedOfflineHiveLock(const char* caller)
    : caller_(caller), lock_(offline_hive_mutex(), std::defer_lock) {
    const auto wait_start = std::chrono::steady_clock::now();
    lock_.lock();
    acquired_at_ = std::chrono::steady_clock::now();
    waited_ = std::chrono::duration_cast<std::chrono::milliseconds>(acquired_at_ - wait_start);
    // No I/O here deliberately -- the wait-time log fires from the
    // destructor instead, alongside the hold-time log, so both happen
    // after unlock() below and logging itself never extends another
    // caller's wait. See the destructor for why that placement matters and
    // why it's the only try/catch this class needs.
}

ScopedOfflineHiveLock::~ScopedOfflineHiveLock() {
    const auto held = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - acquired_at_);
    lock_.unlock();
    // Diagnostics must never throw out of a destructor -- it's implicitly
    // noexcept, so an escaping exception here would call std::terminate()
    // rather than merely fail to log (this repo's established idiom for
    // lifetime-boundary logging; see e.g. mcp_stream_bridge.cpp's
    // best-effort spdlog::info, similarly caught-and-discarded). Both log
    // calls sit here, after unlock() above, rather than the wait-time one
    // living in the constructor next to lock_.lock() -- logging before
    // releasing would hold the process-wide mutex for the duration of a
    // spdlog call (format + sink I/O), directly extending the wait for
    // whichever of the other four plugins is queued behind it.
    try {
        if (waited_ > std::chrono::milliseconds::zero())
            spdlog::debug("offline_hive_mutex: {} waited {}ms to acquire", caller_,
                          waited_.count());
        if (held >= kSlowHoldWarnThreshold)
            spdlog::warn("offline_hive_mutex: {} held lock for {}ms", caller_, held.count());
        else
            spdlog::debug("offline_hive_mutex: {} held lock for {}ms", caller_, held.count());
    } catch (...) {
    }
}

} // namespace yuzu::agent
