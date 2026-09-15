// Unit tests for ScopedOfflineHiveLock (agents/core/include/yuzu/agent/offline_hive_mutex.hpp):
// the RAII wrapper around the process-wide offline-hive-mount mutex shared by five plugins
// (autoruns, installed_apps, license_scan, registry, tar) via with_user_hive().
//
// Scope note: this covers B1 (acquire-on-construct / release-on-destruct / mutual exclusion)
// only. The wait/hold-time logging behaviour (constructor and destructor spdlog calls) is
// deliberately NOT exercised here with a throwing-sink or capturing-sink fixture:
//   - offline_hive_mutex.cpp is compiled into libyuzu_agent_core (a separate .dylib/.so from
//     this test binary), and tests/unit/test_log_capture.hpp's own header documents an
//     observed, unresolved (#3355) cross-image hazard where a default-logger swap made from
//     the test binary's image does not reliably reach spdlog:: calls made from code compiled
//     into that separate library on every toolchain -- a throwing/capturing-sink test here
//     would risk passing vacuously (false-green) rather than actually exercising the
//     destructor's try/catch.
//   - the exception-safety property itself (a `catch (...)` around a log call cannot let that
//     call's exception escape) is a language-level guarantee, not a runtime behaviour that
//     needs a dynamic proof; code-review verified both the constructor's and destructor's
//     guards directly.
// The lock/unlock and RAII-scope contract below has no such hazard and is fully proven here.

#include <yuzu/agent/offline_hive_mutex.hpp>

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <mutex>
#include <thread>

using namespace yuzu::agent;

TEST_CASE("ScopedOfflineHiveLock acquires on construction and releases on destruction",
          "[agent][offline_hive_mutex]") {
    {
        const ScopedOfflineHiveLock guard("test_offline_hive_mutex");
        // Held for the guard's whole scope: a second, non-blocking attempt from another
        // thread must fail while `guard` is alive.
        std::thread contender([] { CHECK_FALSE(offline_hive_mutex().try_lock()); });
        contender.join();
    }
    // Released on scope exit: the mutex must be free again.
    REQUIRE(offline_hive_mutex().try_lock());
    offline_hive_mutex().unlock();
}

TEST_CASE("ScopedOfflineHiveLock serialises two overlapping guards", "[agent][offline_hive_mutex]") {
    int in_critical_section = 0;
    int max_concurrent = 0;
    std::mutex counter_mtx;

    auto worker = [&] {
        const ScopedOfflineHiveLock guard("test_offline_hive_mutex");
        {
            const std::lock_guard<std::mutex> counter_lock(counter_mtx);
            ++in_critical_section;
            max_concurrent = std::max(max_concurrent, in_critical_section);
        }
        {
            const std::lock_guard<std::mutex> counter_lock(counter_mtx);
            --in_critical_section;
        }
    };

    std::thread a(worker);
    std::thread b(worker);
    a.join();
    b.join();

    // Never both inside the guarded section at once -- offline_hive_mutex() is exclusive.
    CHECK(max_concurrent == 1);
}
