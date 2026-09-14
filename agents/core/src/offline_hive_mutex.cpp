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

ScopedOfflineHiveLock::ScopedOfflineHiveLock(const char* caller) : caller_(caller) {
    const auto wait_start = std::chrono::steady_clock::now();
    offline_hive_mutex().lock();
    acquired_at_ = std::chrono::steady_clock::now();
    const auto waited = std::chrono::duration_cast<std::chrono::milliseconds>(acquired_at_ -
                                                                               wait_start);
    if (waited > std::chrono::milliseconds::zero())
        spdlog::debug("offline_hive_mutex: {} waited {}ms to acquire", caller_, waited.count());
}

ScopedOfflineHiveLock::~ScopedOfflineHiveLock() {
    const auto held = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - acquired_at_);
    offline_hive_mutex().unlock();
    if (held >= kSlowHoldWarnThreshold)
        spdlog::warn("offline_hive_mutex: {} held lock for {}ms", caller_, held.count());
    else
        spdlog::debug("offline_hive_mutex: {} held lock for {}ms", caller_, held.count());
}

} // namespace yuzu::agent
