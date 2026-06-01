/**
 * test_guard_file.cpp — FileGuard file-exists watch (Change B / B1).
 *
 * Exercises the real ReadDirectoryChangesW watch against a real scratch
 * directory + file: arm the guard, mutate the filesystem, assert the drift
 * report. Windows-only (the guard is a no-op elsewhere — covered by the
 * non-Windows case). Detection-only: no write-back is asserted.
 */

#include <yuzu/agent/guard_file.hpp>

#include <catch2/catch_test_macros.hpp>

#include "test_helpers.hpp" // yuzu::test::unique_temp_path

#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using namespace yuzu::agent;
namespace fs = std::filesystem;

namespace {

// Collects every drift the guard reports; wait_for_detected blocks until a drift
// carrying `val` arrives (robust to the sink debounce and the async watch thread).
struct FileDriftCollector {
    std::mutex m;
    std::condition_variable cv;
    std::vector<GuardDrift> events;

    void push(const GuardDrift& d) {
        std::lock_guard lk(m);
        events.push_back(d);
        cv.notify_all();
    }
    bool wait_for_detected(const std::string& val, std::chrono::milliseconds to) {
        std::unique_lock lk(m);
        return cv.wait_for(lk, to, [&] {
            for (const auto& e : events)
                if (e.detected_value == val)
                    return true;
            return false;
        });
    }
    std::size_t size() {
        std::lock_guard lk(m);
        return events.size();
    }
};

void write_file(const fs::path& p, const std::string& s = "x") {
    std::ofstream(p, std::ios::binary) << s;
}

} // namespace

#ifdef _WIN32

TEST_CASE("FileGuard file-exists: detects deletion in realtime", "[guardian][guard][file]") {
    const auto dir = yuzu::test::unique_temp_path("fileguard-del");
    fs::create_directories(dir);
    const auto target = dir / "watched.txt";
    write_file(target);

    auto col = std::make_shared<FileDriftCollector>();
    FileGuard::Config cfg;
    cfg.rule_id = "fg-del";
    cfg.rule_name = "delete watch";
    cfg.path = target.string();
    cfg.expect_present = true; // drift when the file goes missing
    cfg.event_debounce_ms = 50;
    FileGuard g(cfg, [col](const GuardDrift& d) { col->push(d); });

    REQUIRE(g.start());
    std::this_thread::sleep_for(std::chrono::milliseconds(300)); // let the watch arm
    fs::remove(target);
    CHECK(col->wait_for_detected("<absent>", std::chrono::seconds(5)));
    g.stop();

    // The reported drift carries the file guard_type + expected state.
    REQUIRE(col->size() >= 1);
    {
        std::lock_guard lk(col->m);
        const auto& last = col->events.back();
        CHECK(last.guard_type == "file");
        CHECK(last.expected_value == "<present>");
        CHECK_FALSE(last.remediation_attempted); // detection-only
    }
    fs::remove_all(dir);
}

TEST_CASE("FileGuard file-exists: absent at arm reports initial drift", "[guardian][guard][file]") {
    const auto dir = yuzu::test::unique_temp_path("fileguard-absent");
    fs::create_directories(dir);
    const auto target = dir / "never-created.txt";

    auto col = std::make_shared<FileDriftCollector>();
    FileGuard::Config cfg;
    cfg.rule_id = "fg-absent";
    cfg.path = target.string();
    cfg.expect_present = true;
    cfg.event_debounce_ms = 50;
    FileGuard g(cfg, [col](const GuardDrift& d) { col->push(d); });

    REQUIRE(g.start());
    // No race: the initial compare runs synchronously inside the first reconcile.
    CHECK(col->wait_for_detected("<absent>", std::chrono::seconds(5)));
    g.stop();
    fs::remove_all(dir);
}

TEST_CASE("FileGuard file-exists: expect-absent detects creation", "[guardian][guard][file]") {
    const auto dir = yuzu::test::unique_temp_path("fileguard-create");
    fs::create_directories(dir);
    const auto target = dir / "should-not-exist.txt";

    auto col = std::make_shared<FileDriftCollector>();
    FileGuard::Config cfg;
    cfg.rule_id = "fg-create";
    cfg.path = target.string();
    cfg.expect_present = false; // tripwire: drift when the file APPEARS
    cfg.event_debounce_ms = 50;
    FileGuard g(cfg, [col](const GuardDrift& d) { col->push(d); });

    REQUIRE(g.start());
    std::this_thread::sleep_for(std::chrono::milliseconds(300)); // arm (compliant: absent==expected)
    write_file(target);
    CHECK(col->wait_for_detected("<present>", std::chrono::seconds(5)));
    g.stop();
    fs::remove_all(dir);
}

TEST_CASE("FileGuard file-exists: compliant present state is quiet", "[guardian][guard][file]") {
    const auto dir = yuzu::test::unique_temp_path("fileguard-quiet");
    fs::create_directories(dir);
    const auto target = dir / "present.txt";
    write_file(target);

    auto col = std::make_shared<FileDriftCollector>();
    FileGuard::Config cfg;
    cfg.rule_id = "fg-quiet";
    cfg.path = target.string();
    cfg.expect_present = true; // present == expected → no drift
    cfg.event_debounce_ms = 50;
    FileGuard g(cfg, [col](const GuardDrift& d) { col->push(d); });

    REQUIRE(g.start());
    std::this_thread::sleep_for(std::chrono::milliseconds(800)); // a compliant guard must not emit
    g.stop();
    CHECK(col->size() == 0);
    fs::remove_all(dir);
}

#else // !_WIN32

TEST_CASE("FileGuard: no-op off Windows", "[guardian][guard][file]") {
    FileGuard::Config cfg;
    cfg.rule_id = "fg-noop";
    cfg.path = "/tmp/whatever";
    FileGuard g(cfg, [](const GuardDrift&) {});
    CHECK_FALSE(g.start()); // file-change Spark is Windows-only for the MVP
}

#endif // _WIN32
