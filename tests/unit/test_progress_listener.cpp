// Per-test-case progress logging for yuzu_agent_tests, gated on YUZU_TEST_PROGRESS
// (#4018). Silent by default so every leg's output stays byte-identical; when set,
// prints one flushed stderr line per test start/end (and the run's Catch2 seed), so
// a stalled CI job's log shows the last TEST_CASE that started rather than nothing.
// Flushed stderr survives meson's taskkill /F /T on a Windows timeout kill
// (test_runner_main.cpp documents the same partial-output-survives-cancel fact for
// its own diagnostic line) - Catch2's own buffered reporter output may not.
//
// One dedicated TU, same reasoning as test_pg_template_cleanup.cpp's listener: a
// CATCH_REGISTER_LISTENER in a header would register once per including TU.

#include <catch2/catch_get_random_seed.hpp>
#include <catch2/catch_test_case_info.hpp>
#include <catch2/catch_test_run_info.hpp>
#include <catch2/interfaces/catch_interfaces_reporter.hpp>
#include <catch2/reporters/catch_reporter_event_listener.hpp>
#include <catch2/reporters/catch_reporter_registrars.hpp>

#include <chrono>
#include <cstdio>
#include <cstdlib>

namespace {

class ProgressListener : public Catch::EventListenerBase {
public:
    explicit ProgressListener(Catch::IConfig const* config)
        : Catch::EventListenerBase(config), enabled_(read_enabled()) {}

    void testRunStarting(Catch::TestRunInfo const& info) override {
        if (!enabled_)
            return;
        emit("[progress] RUN %.*s seed=%u\n", static_cast<int>(info.name.size()), info.name.data(),
             Catch::getSeed());
    }

    void testCaseStarting(Catch::TestCaseInfo const& info) override {
        if (!enabled_)
            return;
        start_ = clock::now();
        emit("[progress] START %s\n", info.name.c_str());
    }

    void testCaseEnded(Catch::TestCaseStats const& stats) override {
        if (!enabled_)
            return;
        const auto ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(clock::now() - start_).count();
        emit("[progress] END %s %lld ms\n", stats.testInfo->name.c_str(), static_cast<long long>(ms));
    }

private:
    using clock = std::chrono::steady_clock;

    // Read once at construction, not per-event: env can't change mid-run and a syscall
    // per TEST_CASE would be needless overhead on the exact suite this is measuring.
    static bool read_enabled() {
        const char* v = std::getenv("YUZU_TEST_PROGRESS");
        return v != nullptr && std::atoi(v) != 0; // atoi(nullptr) is UB - guarded above
    }

    template <class... Args>
    void emit(const char* fmt, Args... args) {
        std::fprintf(stderr, fmt, args...);
        std::fflush(stderr);
        // Mirrored to a file when set (e.g. so a live-tailing diagnostic doesn't have to
        // share the runner's stderr pipe); opened/closed per line, not held open, so a
        // hard kill never leaves a line half-written or a handle leaked.
        if (const char* path = std::getenv("YUZU_TEST_PROGRESS_FILE")) {
            if (FILE* f = std::fopen(path, "a")) {
                std::fprintf(f, fmt, args...);
                std::fclose(f);
            }
        }
    }

    bool enabled_;
    clock::time_point start_{};
};

} // namespace

CATCH_REGISTER_LISTENER(ProgressListener)
