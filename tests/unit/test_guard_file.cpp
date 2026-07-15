/**
 * test_guard_file.cpp — FileGuard file-exists watch (Change B / B1).
 *
 * Exercises the real kernel-notified watch (ReadDirectoryChangesW on Windows,
 * FSEvents on macOS) against a real scratch directory + file: arm the guard,
 * mutate the filesystem, assert the drift report. The cases are pure
 * std::filesystem + sink assertions, so Windows and macOS share them verbatim
 * — one behaviour, two watch plumbings. Linux (where the guard is a no-op) is
 * covered by the no-op case. Detection-only: no write-back is asserted.
 *
 * macOS note: unique_temp_path yields /var/folders/... which the guard
 * canonicalises to /private/var/... (darwin-compat pitfall) — every case here
 * exercises that resolution implicitly.
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
#include <optional>
#include <string>
#include <thread>
#include <type_traits>
#include <vector>

using namespace yuzu::agent;

// Ownership contract (cpp-safety): FileGuard owns an OS wake handle (Windows
// event HANDLE / macOS wake state) + a std::thread; copy or move would
// double-close / double-join. Must be non-copyable AND non-movable.
static_assert(!std::is_copy_constructible_v<FileGuard>);
static_assert(!std::is_copy_assignable_v<FileGuard>);
static_assert(!std::is_move_constructible_v<FileGuard>);

#if defined(_WIN32) || defined(__APPLE__)

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
    // Index-anchored variants: wait for a compliant / non-compliant event at
    // index >= from. Raw-count syncs race late in-flight events (a deletion
    // storm can emit two drifts across wake cycles), which lets survival
    // assertions pass vacuously — anchoring on the event KIND at a known index
    // closes that (Gate-8 F4/G8R-1). Returns the matching index, or nullopt.
    std::optional<std::size_t> wait_compliant_from(std::size_t from, std::chrono::milliseconds to) {
        std::unique_lock lk(m);
        std::optional<std::size_t> hit;
        cv.wait_for(lk, to, [&] {
            for (std::size_t i = from; i < events.size(); ++i)
                if (events[i].compliant) {
                    hit = i;
                    return true;
                }
            return false;
        });
        return hit;
    }
    std::optional<std::size_t> wait_drift_from(std::size_t from, std::chrono::milliseconds to) {
        std::unique_lock lk(m);
        std::optional<std::size_t> hit;
        cv.wait_for(lk, to, [&] {
            for (std::size_t i = from; i < events.size(); ++i)
                if (!events[i].compliant) {
                    hit = i;
                    return true;
                }
            return false;
        });
        return hit;
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
    // Arm-edge sync (not a sleep): present == expected emits one compliant edge
    // once the watch is live — mutating before it races stream setup on loaded CI.
    REQUIRE(col->wait_compliant(std::chrono::seconds(5)));
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
    // Arm-edge sync: absent == expected emits the compliant edge once live.
    REQUIRE(col->wait_compliant(std::chrono::seconds(5)));
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
    // Arm-edge sync: baseline-on-arm emits the compliant edge once live.
    REQUIRE(col->wait_compliant(std::chrono::seconds(5)));
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
    // Arm-edge sync: baseline-on-arm emits the compliant edge once live.
    REQUIRE(col->wait_compliant(std::chrono::seconds(5)));
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
    // Tight start/change/stop loop exercises teardown while a change notification
    // is in flight (the teardown UAF window): Windows — CancelIo + CloseHandle +
    // join with a ReadDirectoryChangesW read outstanding; macOS — FSEvents stream
    // invalidate + delivery-queue drain racing a callback.
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
    // This case asserts TWO distinct drifts and (edge-synced) can produce them
    // within one debounce window, where the collapse-with-count design folds the
    // second into a never-sent follow-up. Debounce isn't under test here: 0 =
    // emit every drift.
    cfg.event_debounce_ms = 0;
    FileGuard g(cfg, [col](const GuardDrift& d) { col->push(d); });
    REQUIRE(g.start());
    // Arm-edge sync: present == expected emits the compliant edge once live.
    REQUIRE(col->wait_compliant(std::chrono::seconds(5)));

    // 1) delete the whole parent directory → file is absent → drift. (Count drifts,
    //    not raw events — arming present emitted a compliant edge first, Slice B.
    //    A deletion storm may emit MORE than one drift across wake cycles, so
    //    step 2 anchors on the compliant EDGE, never on raw counts.)
    fs::remove_all(parent);
    REQUIRE(col->wait_drift_count(1, std::chrono::seconds(5)));
    const auto after_drift = col->size();

    // 2) recreate the parent + file — the guard must go compliant again (the
    //    edge event doubles as the re-arm/re-baseline sync), then delete once
    //    more and a drift must land AFTER that edge, proving live survival
    //    (Windows: re-armed via the nearest-ancestor watch; macOS: the
    //    path-based FSEvents stream survives the recreation outright).
    fs::create_directories(parent);
    write_file(target);
    const auto clear_edge = col->wait_compliant_from(after_drift, std::chrono::seconds(5));
    REQUIRE(clear_edge.has_value());
    fs::remove(target);
    // A drift strictly after the clear edge cannot be a late step-1 straggler.
    CHECK(col->wait_drift_from(*clear_edge + 1, std::chrono::seconds(5)).has_value());
    g.stop();
    fs::remove_all(base);
}

TEST_CASE("FileGuard file-exists: arms with a never-existed parent and detects its creation",
          "[guardian][guard][file][resilience]") {
    // Parent directory does not exist at arm time: the guard reports the initial
    // <absent> drift, holds the watch via its backstop (Windows: nearest-ancestor
    // notification; macOS: ancestor FSEvents stream / degraded re-arm), and goes
    // compliant once the parent chain + file appear.
    const auto base = yuzu::test::unique_temp_path("yuzu_test_fileguard-noparent");
    fs::create_directories(base);
    const auto parent = base / "missing";
    const auto target = parent / "watched.txt";

    auto col = std::make_shared<FileDriftCollector>();
    FileGuard::Config cfg;
    cfg.rule_id = "fg-noparent";
    cfg.path = target.string();
    cfg.expect_present = true;
    cfg.event_debounce_ms = 50;
    FileGuard g(cfg, [col](const GuardDrift& d) { col->push(d); });
    REQUIRE(g.start());
    REQUIRE(col->wait_for_detected("<absent>", std::chrono::seconds(5))); // initial drift

    fs::create_directories(parent);
    write_file(target);
    // Compliant edge proves the backstop re-armed onto the newly-created parent.
    CHECK(col->wait_compliant(std::chrono::seconds(10)));
    g.stop();
    fs::remove_all(base);
}

TEST_CASE("FileGuard file-exists: non-ASCII filename deletion is detected",
          "[guardian][guard][file][unicode]") {
    // café.txt exercises the non-ASCII paths: Windows matches via wide ordinal
    // compare; macOS bypasses the ASCII prefilter (APFS Unicode folding — a
    // missed wake would be a missed drift).
    const auto dir = yuzu::test::unique_temp_path("yuzu_test_fileguard-uni");
    fs::create_directories(dir);
    const auto target = dir / "caf\xC3\xA9.txt"; // UTF-8 é
    write_file(target);

    auto col = std::make_shared<FileDriftCollector>();
    FileGuard::Config cfg;
    cfg.rule_id = "fg-uni";
    cfg.path = target.string();
    cfg.expect_present = true;
    cfg.event_debounce_ms = 50;
    FileGuard g(cfg, [col](const GuardDrift& d) { col->push(d); });
    REQUIRE(g.start());
    REQUIRE(col->wait_compliant(std::chrono::seconds(5)));
    fs::remove(target);
    CHECK(col->wait_for_detected("<absent>", std::chrono::seconds(5)));
    g.stop();
    fs::remove_all(dir);
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
    // Arm-edge sync: baseline-on-arm emits the compliant edge once live.
    REQUIRE(col->wait_compliant(std::chrono::seconds(5)));

    for (int i = 1; i <= 14; ++i) { // ~1.4s of continuous changing writes < settle_ms apart
        write_file(target, "v" + std::to_string(i));
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    // Without the defer cap this would never fire (settle never quiesces). Count
    // DRIFTS — the arm-time compliant edge already satisfies a raw event count,
    // which made the old wait_count(1) assertion vacuous (QE-M1).
    CHECK(col->wait_drift_count(1, std::chrono::seconds(3)));
    g.stop();
    fs::remove_all(dir);
}

#else // Linux — the guard is a no-op stub

TEST_CASE("FileGuard: no-op on unsupported platforms", "[guardian][guard][file]") {
    FileGuard::Config cfg;
    cfg.rule_id = "fg-noop";
    cfg.path = "/tmp/whatever";
    FileGuard g(cfg, [](const GuardDrift&) {});
    CHECK_FALSE(g.start()); // file-change Spark is Windows/macOS-only today (Linux inotify later)
}

#endif // _WIN32 || __APPLE__
