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
#include <type_traits>
#include <vector>

using namespace yuzu::agent;

// Ownership contract (cpp-safety): FileGuard owns a HANDLE + a std::thread; copy or
// move would double-close / double-join. Must be non-copyable AND non-movable.
static_assert(!std::is_copy_constructible_v<FileGuard>);
static_assert(!std::is_copy_assignable_v<FileGuard>);
static_assert(!std::is_move_constructible_v<FileGuard>);

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
    // Drift = a NON-compliant report. Slice B added the guard.compliant edge (one on
    // arm / baseline, and one on each drift-clear), so "no drift" intent must count
    // drifts, not raw events.
    std::size_t drift_count() {
        std::lock_guard lk(m);
        std::size_t n = 0;
        for (const auto& e : events)
            if (!e.compliant)
                ++n;
        return n;
    }
    bool wait_drift_count(std::size_t min, std::chrono::milliseconds to) {
        std::unique_lock lk(m);
        return cv.wait_for(lk, to, [&] {
            std::size_t n = 0;
            for (const auto& e : events)
                if (!e.compliant)
                    ++n;
            return n >= min;
        });
    }
    GuardDrift last_drift() { // most-recent non-compliant report
        std::lock_guard lk(m);
        for (auto it = events.rbegin(); it != events.rend(); ++it)
            if (!it->compliant)
                return *it;
        return {};
    }
    bool wait_compliant(std::chrono::milliseconds to) {
        std::unique_lock lk(m);
        return cv.wait_for(lk, to, [&] {
            for (const auto& e : events)
                if (e.compliant)
                    return true;
            return false;
        });
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

TEST_CASE("FileGuard file-exists: compliant present state emits one edge then is quiet",
          "[guardian][guard][file]") {
    const auto dir = yuzu::test::unique_temp_path("fileguard-quiet");
    fs::create_directories(dir);
    const auto target = dir / "present.txt";
    write_file(target);

    auto col = std::make_shared<FileDriftCollector>();
    FileGuard::Config cfg;
    cfg.rule_id = "fg-quiet";
    cfg.path = target.string();
    cfg.expect_present = true; // present == expected → compliant
    cfg.event_debounce_ms = 50;
    FileGuard g(cfg, [col](const GuardDrift& d) { col->push(d); });

    REQUIRE(g.start());
    // Slice B: arming compliant emits ONE guard.compliant edge (so the server can
    // see the rule is green), then the guard stays silent — never drift.
    REQUIRE(col->wait_compliant(std::chrono::seconds(5)));
    std::this_thread::sleep_for(std::chrono::milliseconds(800));
    g.stop();
    CHECK(col->drift_count() == 0); // no drift while compliant
    fs::remove_all(dir);
}

TEST_CASE("FileGuard file-exists: drift then clear emits a fresh compliant edge (Slice B)",
          "[guardian][guard][file][compliant]") {
    const auto dir = yuzu::test::unique_temp_path("fileguard-clear");
    fs::create_directories(dir);
    const auto target = dir / "watched.txt";
    write_file(target); // present == expected → compliant on arm

    auto col = std::make_shared<FileDriftCollector>();
    FileGuard::Config cfg;
    cfg.rule_id = "fg-clear";
    cfg.path = target.string();
    cfg.expect_present = true;
    cfg.event_debounce_ms = 50;
    FileGuard g(cfg, [col](const GuardDrift& d) { col->push(d); });

    REQUIRE(g.start());
    REQUIRE(col->wait_compliant(std::chrono::seconds(5))); // arm compliant edge
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    fs::remove(target); // → absent drift
    REQUIRE(col->wait_drift_count(1, std::chrono::seconds(5)));
    const auto after_drift = col->size();

    write_file(target); // restored → a fresh compliant edge (rule went green again)
    REQUIRE(col->wait_count(after_drift + 1, std::chrono::seconds(5)));
    {
        std::lock_guard lk(col->m);
        CHECK(col->events.back().compliant); // the clear is a compliant edge, not a drift
    }
    g.stop();
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
    std::this_thread::sleep_for(std::chrono::milliseconds(300)); // arm + baseline (compliant edge)
    CHECK(col->drift_count() == 0); // baseline-on-arm is compliant, not drift
    write_file(target, "version-two-different"); // content changes
    REQUIRE(col->wait_drift_count(1, std::chrono::seconds(5)));
    g.stop();
    {
        const auto d = col->last_drift();
        CHECK(d.guard_type == "file");
        CHECK(d.detected_value.size() == 64); // a real SHA-256 hex, not a sentinel
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
    std::this_thread::sleep_for(std::chrono::milliseconds(300)); // baseline (compliant edge)
    write_file(target, "unchanging"); // rewrite SAME bytes → notification, but hash unchanged
    std::this_thread::sleep_for(std::chrono::milliseconds(600)); // settle + eval window
    g.stop();
    CHECK(col->drift_count() == 0); // content-change semantics: a no-op rewrite is not drift
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

// ── teardown + resilience (governance Gate-7 hardening) ──────────────────────

TEST_CASE("FileGuard: stop() with a watch armed but no change in-flight returns",
          "[guardian][guard][file][teardown]") {
    const auto dir = yuzu::test::unique_temp_path("fileguard-stopclean");
    fs::create_directories(dir);
    const auto target = dir / "x.txt";
    write_file(target);
    auto col = std::make_shared<FileDriftCollector>();
    FileGuard::Config cfg;
    cfg.rule_id = "fg-stopclean";
    cfg.path = target.string();
    cfg.expect_present = true; // compliant — no drift, watch just armed
    FileGuard g(cfg, [col](const GuardDrift& d) { col->push(d); });
    REQUIRE(g.start());
    g.stop(); // must join promptly with no outstanding-IO crash (test timeout catches a hang)
    fs::remove_all(dir);
    SUCCEED();
}

TEST_CASE("FileGuard: stop() races an in-flight change notification without crashing",
          "[guardian][guard][file][teardown]") {
    // Tight start/change/stop loop exercises CancelIo + CloseHandle + join while a
    // ReadDirectoryChangesW read is outstanding (the teardown UAF window).
    for (int i = 0; i < 25; ++i) {
        const auto dir = yuzu::test::unique_temp_path("fileguard-stoprace");
        fs::create_directories(dir);
        const auto target = dir / "y.txt";
        write_file(target, "a");
        FileGuard::Config cfg;
        cfg.rule_id = "fg-stoprace";
        cfg.path = target.string();
        cfg.expect_present = true;
        FileGuard g(cfg, [](const GuardDrift&) {});
        REQUIRE(g.start());
        write_file(target, "b"); // trigger a notification, then immediately tear down
        fs::remove(target);
        g.stop();
        fs::remove_all(dir);
    }
    SUCCEED();
}

TEST_CASE("FileGuard file-exists: survives parent-dir delete and recreate",
          "[guardian][guard][file][resilience]") {
    const auto base = yuzu::test::unique_temp_path("fileguard-resil");
    const auto parent = base / "sub";
    const auto target = parent / "watched.txt";
    fs::create_directories(parent);
    write_file(target);

    auto col = std::make_shared<FileDriftCollector>();
    FileGuard::Config cfg;
    cfg.rule_id = "fg-resil";
    cfg.path = target.string();
    cfg.expect_present = true;
    cfg.event_debounce_ms = 50;
    FileGuard g(cfg, [col](const GuardDrift& d) { col->push(d); });
    REQUIRE(g.start());
    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    // 1) delete the whole parent directory → file is absent → drift. (Count drifts,
    //    not raw events — arming present emitted a compliant edge first, Slice B.)
    fs::remove_all(parent);
    REQUIRE(col->wait_drift_count(1, std::chrono::seconds(5)));

    // 2) recreate the parent + file (compliant again), then delete once more — the
    //    guard must have re-armed via the nearest-ancestor watch and detect again.
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    fs::create_directories(parent);
    write_file(target);
    std::this_thread::sleep_for(std::chrono::milliseconds(400)); // let it re-arm + re-baseline present
    fs::remove(target);
    CHECK(col->wait_drift_count(2, std::chrono::seconds(5))); // second <absent> drift proves survival
    g.stop();
    fs::remove_all(base);
}

TEST_CASE("FileGuard file-hash-equals: continuous sub-settle writes still get hashed (defer cap)",
          "[guardian][guard][file][hash]") {
    // A writer touching the file faster than settle_ms must not starve the hash
    // forever — max_settle_defer_ms forces an evaluation (UP-1 regression guard).
    const auto dir = yuzu::test::unique_temp_path("fileguard-defercap");
    fs::create_directories(dir);
    const auto target = dir / "churn.txt";
    write_file(target, "v0");

    auto col = std::make_shared<FileDriftCollector>();
    FileGuard::Config cfg;
    cfg.rule_id = "fg-defercap";
    cfg.path = target.string();
    cfg.assertion = FileGuard::Assertion::HashEquals; // baseline-on-arm = "v0"
    cfg.settle_ms = 200;             // never quiesces under the 100ms write cadence below
    cfg.max_settle_defer_ms = 600;   // ...but the cap forces a hash within ~600ms
    cfg.event_debounce_ms = 50;
    FileGuard g(cfg, [col](const GuardDrift& d) { col->push(d); });
    REQUIRE(g.start());
    std::this_thread::sleep_for(std::chrono::milliseconds(250)); // arm + baseline v0

    for (int i = 1; i <= 14; ++i) { // ~1.4s of continuous changing writes < settle_ms apart
        write_file(target, "v" + std::to_string(i));
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    // Without the defer cap this would never fire (settle never quiesces).
    CHECK(col->wait_count(1, std::chrono::seconds(3)));
    g.stop();
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
