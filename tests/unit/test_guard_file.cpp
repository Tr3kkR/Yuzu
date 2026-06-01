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

#ifdef _WIN32

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
    bool wait_count(std::size_t min, std::chrono::milliseconds to) {
        std::unique_lock lk(m);
        return cv.wait_for(lk, to, [&] { return events.size() >= min; });
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

// ── file-hash-equals (B2) ────────────────────────────────────────────────────

TEST_CASE("FileGuard file-hash-equals: detects a content change", "[guardian][guard][file][hash]") {
    const auto dir = yuzu::test::unique_temp_path("fileguard-hash");
    fs::create_directories(dir);
    const auto target = dir / "content.txt";
    write_file(target, "version-one");

    auto col = std::make_shared<FileDriftCollector>();
    FileGuard::Config cfg;
    cfg.rule_id = "fg-hash";
    cfg.path = target.string();
    cfg.assertion = FileGuard::Assertion::HashEquals; // empty expected_hash → baseline-on-arm
    cfg.settle_ms = 100;
    cfg.event_debounce_ms = 50;
    FileGuard g(cfg, [col](const GuardDrift& d) { col->push(d); });

    REQUIRE(g.start());
    std::this_thread::sleep_for(std::chrono::milliseconds(300)); // arm + baseline; no drift yet
    CHECK(col->size() == 0);
    write_file(target, "version-two-different"); // content changes
    REQUIRE(col->wait_count(1, std::chrono::seconds(5)));
    g.stop();
    {
        std::lock_guard lk(col->m);
        const auto& last = col->events.back();
        CHECK(last.guard_type == "file");
        CHECK(last.detected_value.size() == 64); // a real SHA-256 hex, not a sentinel
    }
    fs::remove_all(dir);
}

TEST_CASE("FileGuard file-hash-equals: identical-content rewrite stays quiet",
          "[guardian][guard][file][hash]") {
    const auto dir = yuzu::test::unique_temp_path("fileguard-hash-quiet");
    fs::create_directories(dir);
    const auto target = dir / "stable.txt";
    write_file(target, "unchanging");

    auto col = std::make_shared<FileDriftCollector>();
    FileGuard::Config cfg;
    cfg.rule_id = "fg-hash-quiet";
    cfg.path = target.string();
    cfg.assertion = FileGuard::Assertion::HashEquals;
    cfg.settle_ms = 100;
    cfg.event_debounce_ms = 50;
    FileGuard g(cfg, [col](const GuardDrift& d) { col->push(d); });

    REQUIRE(g.start());
    std::this_thread::sleep_for(std::chrono::milliseconds(300)); // baseline
    write_file(target, "unchanging"); // rewrite SAME bytes → notification, but hash unchanged
    std::this_thread::sleep_for(std::chrono::milliseconds(600)); // settle + eval window
    g.stop();
    CHECK(col->size() == 0); // content-change semantics: a no-op rewrite is not drift
    fs::remove_all(dir);
}

TEST_CASE("FileGuard file-hash-equals: oversize is reported, not silently skipped",
          "[guardian][guard][file][hash]") {
    const auto dir = yuzu::test::unique_temp_path("fileguard-hash-big");
    fs::create_directories(dir);
    const auto target = dir / "big.bin";
    write_file(target, std::string(4096, 'A')); // 4 KiB

    auto col = std::make_shared<FileDriftCollector>();
    FileGuard::Config cfg;
    cfg.rule_id = "fg-hash-big";
    cfg.path = target.string();
    cfg.assertion = FileGuard::Assertion::HashEquals;
    cfg.max_hash_bytes = 64; // far below the file size
    cfg.settle_ms = 100;
    cfg.event_debounce_ms = 50;
    FileGuard g(cfg, [col](const GuardDrift& d) { col->push(d); });

    REQUIRE(g.start());
    // Fail-loud at arm: too large to verify within the DoS cap → "<oversize>" drift.
    CHECK(col->wait_for_detected("<oversize>", std::chrono::seconds(5)));
    g.stop();
    fs::remove_all(dir);
}

TEST_CASE("FileGuard file-hash-equals: mismatch against a supplied expected hash drifts",
          "[guardian][guard][file][hash]") {
    const auto dir = yuzu::test::unique_temp_path("fileguard-hash-exp");
    fs::create_directories(dir);
    const auto target = dir / "watched.cfg";
    write_file(target, "actual-content");

    auto col = std::make_shared<FileDriftCollector>();
    FileGuard::Config cfg;
    cfg.rule_id = "fg-hash-exp";
    cfg.path = target.string();
    cfg.assertion = FileGuard::Assertion::HashEquals;
    cfg.expected_hash = std::string(64, '0'); // a hash the real content cannot match
    cfg.settle_ms = 100;
    cfg.event_debounce_ms = 50;
    FileGuard g(cfg, [col](const GuardDrift& d) { col->push(d); });

    REQUIRE(g.start());
    // Operator-supplied baseline: the initial compare already drifts (content != expected).
    REQUIRE(col->wait_count(1, std::chrono::seconds(5)));
    g.stop();
    {
        std::lock_guard lk(col->m);
        CHECK(col->events.back().expected_value == std::string(64, '0'));
        CHECK(col->events.back().detected_value.size() == 64); // the real hash
    }
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
