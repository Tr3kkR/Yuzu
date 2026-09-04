/**
 * test_tar_cursor.cpp -- Unit tests for the TAR cursor-model seam
 * (tar_cursor.hpp): CursorSource lifecycle contract, tar_cursor persistence,
 * pending-queue durability, and the frozen power/removable schema rows.
 *
 * A FakeCursorSource plays the role a wave-2 collector will fill (power /
 * removable): it implements CursorSource directly against a real (ephemeral)
 * TarDatabase, so these tests exercise the actual insert_power_events_and_
 * cursor / get_cursor / generate_warehouse_ddl code paths the seam promises,
 * without depending on tar_plugin.cpp (which owns the driver loop and is
 * translation-unit-local -- see test_tar_capture_status.cpp for the same
 * "fixture collector through the shared contract, not through the plugin"
 * pattern this file follows).
 */

#include "tar_cursor.hpp"
#include "tar_db.hpp"
#include "tar_schema_registry.hpp"
#include "test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using namespace yuzu::tar;

// ── Test DB harness (mirrors test_tar_store.cpp's TestTarDb) ────────────────

namespace {

struct TestTarDb {
    TarDatabase db;
    fs::path path;

    ~TestTarDb() {
        { TarDatabase discard = std::move(db); }
        std::error_code ec;
        fs::remove(path, ec);
        fs::remove(fs::path{path.string() + "-wal"}, ec);
        fs::remove(fs::path{path.string() + "-shm"}, ec);
    }
};

TestTarDb make_test_db() {
    auto tmp = yuzu::test::unique_temp_path("yuzu_test_tar_cursor_");
    auto result = TarDatabase::open(tmp);
    REQUIRE(result.has_value());
    return TestTarDb{std::move(*result), tmp};
}

// A fake CursorSource driving the real contract against a real TarDatabase.
// Every collect() call persists its own events+cursor atomically via
// insert_power_events_and_cursor, exactly as a real wave-2 source must --
// this class supplies only the DECISION of what to do each tick, not a
// second, parallel persistence path.
class FakePowerCursorSource final : public CursorSource {
public:
    std::string name() const override { return "power"; }

    void start(TarDatabase& db) override {
        started_ = true;
        db_at_start_ = &db;
    }

    CursorCollectResult collect(TarDatabase& db,
                                const std::optional<std::string>& cursor_json) override {
        if (throw_incomplete)
            throw IncompleteCaptureError("fake transient read failure");

        if (force_lost) {
            // Rule 2: lost/invalid cursor is NOT an exception -- emit a
            // capture_gap, re-baseline at "now" (never replay-from-zero),
            // persist atomically, return CursorLost.
            PowerEvent gap;
            gap.ts = 100;
            gap.snapshot_id = 1;
            gap.action = "capture_gap";
            gap.detail = "cursor lost (fixture)";
            gap.record_key = next_key();
            const std::string new_cursor = R"({"v":1,"pos":"rebaselined"})";
            const bool ok = db.insert_power_events_and_cursor({gap}, new_cursor);
            return {new_cursor, ok ? std::size_t{1} : std::size_t{0}, CursorOutcome::CursorLost,
                    "lost"};
        }

        PowerEvent ev;
        ev.ts = 200;
        ev.snapshot_id = 1;
        ev.action = "wake";
        ev.record_key = next_key();
        const std::string new_cursor = R"({"v":1,"pos":"advanced"})";
        const bool ok = db.insert_power_events_and_cursor({ev}, new_cursor);
        const auto outcome = cursor_json.has_value() ? CursorOutcome::Advanced
                                                     : CursorOutcome::Baseline;
        return {new_cursor, ok ? std::size_t{1} : std::size_t{0}, outcome, ""};
    }

    void stop() noexcept override {
        stopped_ = true;
        // Lifecycle ordering assertion (P-002): a correct driver calls
        // stop() on every source BEFORE tearing down the database, so the
        // database must still be open right now.
        db_open_at_stop_ = db_at_start_ != nullptr && db_at_start_->is_open();
    }

    void on_enabled_changed(bool enabled) override {
        if (!enabled) {
            // disable: drain-and-DISCARD the paused-window queue.
            pending_.discard_all();
            saw_disable_ = true;
        } else {
            // re-enable: re-baseline forward, never replay the disabled
            // window's own events.
            saw_reenable_ = true;
        }
    }

    bool throw_incomplete{false};
    bool force_lost{false};
    bool started_{false};
    bool stopped_{false};
    bool db_open_at_stop_{false};
    bool saw_disable_{false};
    bool saw_reenable_{false};
    BoundedPendingQueue<PowerEvent> pending_;
    TarDatabase* db_at_start_{nullptr};

private:
    std::string next_key() { return "power-fixture-" + std::to_string(++counter_); }
    int counter_{0};
};

} // namespace

// ── tar_cursor persistence: round trip ───────────────────────────────────────

TEST_CASE("TarDatabase: get_cursor returns nullopt before any cursor is persisted",
          "[tar][cursor]") {
    auto t = make_test_db();
    CHECK_FALSE(t.db.get_cursor("power").has_value());
}

TEST_CASE("TarDatabase: insert_power_events_and_cursor persists the cursor even with zero events",
          "[tar][cursor]") {
    auto t = make_test_db();
    REQUIRE(t.db.insert_power_events_and_cursor({}, R"({"v":1,"pos":10})"));
    auto c = t.db.get_cursor("power");
    REQUIRE(c.has_value());
    CHECK(*c == R"({"v":1,"pos":10})");
}

TEST_CASE("TarDatabase: insert_removable_events_and_cursor round-trips events + cursor together",
          "[tar][cursor]") {
    auto t = make_test_db();
    RemovableEvent ev;
    ev.ts = 1;
    ev.snapshot_id = 1;
    ev.action = "attached";
    ev.device_key = "usb-0001";
    ev.vendor = "Acme";
    ev.product = "Widget";
    ev.serial = "SN1";
    ev.bus = "usb";
    ev.volume = "E:";
    ev.size_bytes = 1024;
    ev.image_path = "";
    ev.pid = 0;
    ev.evidence = "{}";
    ev.record_key = "rm-1";

    REQUIRE(t.db.insert_removable_events_and_cursor({ev}, R"({"v":1})"));
    auto res = t.db.execute_query("SELECT COUNT(*) FROM removable_live");
    REQUIRE(res.has_value());
    CHECK(res->rows[0][0] == "1");
    CHECK(t.db.get_cursor("removable") == std::string(R"({"v":1})"));
}

// ── Replay idempotence via UNIQUE record_key ────────────────────────────────

TEST_CASE("power_live: duplicate record_key is a no-op (row count unchanged), cursor still advances",
          "[tar][cursor]") {
    auto t = make_test_db();
    PowerEvent ev;
    ev.ts = 1;
    ev.snapshot_id = 1;
    ev.action = "wake";
    ev.record_key = "dup-1";

    REQUIRE(t.db.insert_power_events_and_cursor({ev}, R"({"v":1})"));
    // Replay the SAME event (e.g. a cursor re-read from a slightly earlier
    // position) -- record_key's UNIQUE index makes this a silent no-op, not
    // a duplicate row (tar_cursor.hpp rule 3).
    REQUIRE(t.db.insert_power_events_and_cursor({ev}, R"({"v":2})"));

    auto res = t.db.execute_query("SELECT COUNT(*) FROM power_live");
    REQUIRE(res.has_value());
    CHECK(res->rows[0][0] == "1");
    // The cursor itself is NOT gated by record_key idempotence -- it still
    // advances to whatever the (idempotent) tick reports.
    CHECK(t.db.get_cursor("power") == std::string(R"({"v":2})"));
}

// ── Atomic commit/rollback ───────────────────────────────────────────────────

TEST_CASE("insert_power_events_and_cursor rolls back the cursor when the event insert fails",
          "[tar][cursor]") {
    auto t = make_test_db();
    REQUIRE(t.db.insert_power_events_and_cursor({}, R"({"v":1})"));

    // Force the event-insert half of the transaction to fail deterministically.
    REQUIRE(t.db.execute_sql("DROP TABLE power_live"));

    PowerEvent ev;
    ev.ts = 1;
    ev.snapshot_id = 1;
    ev.action = "sleep";
    ev.record_key = "will-not-land";
    CHECK_FALSE(t.db.insert_power_events_and_cursor({ev}, R"({"v":2})"));

    // Neither half landed: the cursor is exactly what it was before this
    // call (rule 6 / tar_db.hpp:458-477 -- events and cursor commit or fail
    // together).
    CHECK(t.db.get_cursor("power") == std::string(R"({"v":1})"));
}

TEST_CASE("insert_removable_events_and_cursor rolls back the cursor when the event insert fails",
          "[tar][cursor]") {
    auto t = make_test_db();
    REQUIRE(t.db.insert_removable_events_and_cursor({}, R"({"v":1})"));
    REQUIRE(t.db.execute_sql("DROP TABLE removable_live"));

    RemovableEvent ev;
    ev.ts = 1;
    ev.snapshot_id = 1;
    ev.action = "detached";
    ev.record_key = "will-not-land";
    CHECK_FALSE(t.db.insert_removable_events_and_cursor({ev}, R"({"v":2})"));
    CHECK(t.db.get_cursor("removable") == std::string(R"({"v":1})"));
}

// ── Generated DDL ─────────────────────────────────────────────────────────────

TEST_CASE("TAR warehouse DDL: power_live and removable_live carry a record_key UNIQUE index",
          "[tar][cursor][warehouse]") {
    auto ddl = generate_warehouse_ddl();
    CHECK(ddl.find("CREATE UNIQUE INDEX IF NOT EXISTS power_live_record_key_uq "
                   "ON power_live(record_key);") != std::string::npos);
    CHECK(ddl.find("CREATE UNIQUE INDEX IF NOT EXISTS removable_live_record_key_uq "
                   "ON removable_live(record_key);") != std::string::npos);
}

// ── Frozen schema-registry rows ─────────────────────────────────────────────

TEST_CASE("TAR schema registry: power and removable default to ENABLED, live-tier-only",
          "[tar][cursor][registry]") {
    bool saw_power = false, saw_removable = false;
    for (const auto& src : capture_sources()) {
        if (src.name != "power" && src.name != "removable")
            continue;
        if (src.name == "power")
            saw_power = true;
        else
            saw_removable = true;

        // ALEX RULING 2026-09-04: the first two default-ON sources.
        CHECK(src.default_enabled);
        CHECK(src.unique_key_column == "record_key");
        REQUIRE(src.granularities.size() == 1);
        CHECK(src.granularities.front().suffix == "live");
    }
    CHECK(saw_power);
    CHECK(saw_removable);
}

// ── Fake CursorSource driver semantics ──────────────────────────────────────

TEST_CASE("CursorSource contract: a successful collect persists events + cursor atomically",
          "[tar][cursor][lifecycle]") {
    auto t = make_test_db();
    FakePowerCursorSource src;
    src.start(t.db);
    CHECK(src.started_);

    auto result = src.collect(t.db, std::nullopt);
    CHECK(result.outcome == CursorOutcome::Baseline);
    CHECK(result.events_emitted == 1);
    CHECK(t.db.get_cursor("power") == result.new_cursor_json);

    // A second tick with a prior cursor present reports Advanced.
    auto result2 = src.collect(t.db, t.db.get_cursor("power"));
    CHECK(result2.outcome == CursorOutcome::Advanced);
}

TEST_CASE("CursorSource contract: IncompleteCaptureError leaves the persisted cursor untouched",
          "[tar][cursor][lifecycle]") {
    auto t = make_test_db();
    FakePowerCursorSource src;
    src.start(t.db);
    auto seed = src.collect(t.db, std::nullopt);
    REQUIRE(t.db.get_cursor("power") == seed.new_cursor_json);

    // Rule 1: a transient failure throws rather than returning a result --
    // the driver (simulated here directly) must not call any persist path
    // on this branch, so the cursor is exactly what it was before.
    src.throw_incomplete = true;
    const auto cursor_before = t.db.get_cursor("power");
    REQUIRE_THROWS_AS(src.collect(t.db, cursor_before), IncompleteCaptureError);
    CHECK(t.db.get_cursor("power") == cursor_before);
}

TEST_CASE("CursorSource contract: CursorLost emits a capture_gap and re-baselines forward",
          "[tar][cursor][lifecycle]") {
    auto t = make_test_db();
    FakePowerCursorSource src;
    src.start(t.db);
    src.force_lost = true;

    auto result = src.collect(t.db, R"({"v":1,"pos":"stale-behind-a-wrapped-log"})");
    CHECK(result.outcome == CursorOutcome::CursorLost);

    auto res = t.db.execute_query("SELECT action FROM power_live WHERE action = 'capture_gap'");
    REQUIRE(res.has_value());
    CHECK(res->rows.size() == 1);
    // Re-baselined at "now", never replay-from-zero -- the new cursor is
    // exactly what this tick persisted, not derived from the stale input.
    CHECK(t.db.get_cursor("power") == result.new_cursor_json);
}

TEST_CASE("CursorSource lifecycle: stop() runs while the database is still open",
          "[tar][cursor][lifecycle]") {
    auto t = make_test_db();
    FakePowerCursorSource src;
    src.start(t.db);
    REQUIRE(t.db.is_open());

    src.stop(); // simulates shutdown()'s ordering: stop() BEFORE db_.reset()
    CHECK(src.stopped_);
    CHECK(src.db_open_at_stop_);
}

TEST_CASE("CursorSource lifecycle: on_enabled_changed(false) discards the paused window",
          "[tar][cursor][lifecycle]") {
    FakePowerCursorSource src;
    PowerEvent buffered;
    buffered.action = "wake";
    buffered.record_key = "buffered-during-pause";
    src.pending_.push(buffered);
    REQUIRE(src.pending_.size() == 1);

    src.on_enabled_changed(false);
    CHECK(src.saw_disable_);
    // Nothing from the paused window survives -- discard, not overflow.
    CHECK(src.pending_.size() == 0);
    CHECK(src.pending_.dropped() == 0);
}

TEST_CASE("CursorSource lifecycle: on_enabled_changed(true) signals a re-baseline, not a replay",
          "[tar][cursor][lifecycle]") {
    FakePowerCursorSource src;
    src.on_enabled_changed(true);
    CHECK(src.saw_reenable_);
}

// ── BoundedPendingQueue (P-003 subscription durability) ─────────────────────

TEST_CASE("BoundedPendingQueue: a failed insert leaves entries unacked; a retry commits them "
          "exactly once",
          "[tar][cursor][queue]") {
    BoundedPendingQueue<int> q;
    q.push(1);
    q.push(2);
    q.push(3);

    auto batch = q.snapshot();
    REQUIRE(batch.size() == 3);

    // Simulated failed insert: do NOT ack -- the batch must still be there
    // for the next tick's retry.
    CHECK(q.snapshot().size() == 3);

    // Simulated successful insert: ack exactly the snapshotted count.
    q.ack(batch.size());
    CHECK(q.snapshot().empty());

    // A second ack (nothing new pushed) is a safe no-op, not a crash/underflow.
    q.ack(5);
    CHECK(q.snapshot().empty());
}

TEST_CASE("BoundedPendingQueue: overflow drops the OLDEST entry and counts it cumulatively",
          "[tar][cursor][queue]") {
    BoundedPendingQueue<int> q;
    constexpr std::size_t kOverBy = 5;
    for (std::size_t i = 0; i < BoundedPendingQueue<int>::kCap + kOverBy; ++i)
        q.push(static_cast<int>(i));

    CHECK(q.size() == BoundedPendingQueue<int>::kCap);
    CHECK(q.dropped() == kOverBy);

    auto batch = q.snapshot();
    REQUIRE_FALSE(batch.empty());
    // The oldest kOverBy entries (0..kOverBy-1) were dropped -- the front of
    // the queue is now entry kOverBy, not 0.
    CHECK(batch.front() == static_cast<int>(kOverBy));
}

TEST_CASE("BoundedPendingQueue: the dropped count surfaces in the next capture_gap event",
          "[tar][cursor][queue]") {
    auto t = make_test_db();
    BoundedPendingQueue<PowerEvent> q;
    constexpr std::size_t kOverBy = 3;
    for (std::size_t i = 0; i < BoundedPendingQueue<PowerEvent>::kCap + kOverBy; ++i) {
        PowerEvent ev;
        ev.record_key = "q-" + std::to_string(i);
        q.push(ev);
    }
    REQUIRE(q.dropped() == kOverBy);

    PowerEvent gap;
    gap.ts = 1;
    gap.snapshot_id = 1;
    gap.action = "capture_gap";
    gap.detail = "dropped=" + std::to_string(q.dropped());
    gap.record_key = "gap-for-overflow";
    REQUIRE(t.db.insert_power_events_and_cursor({gap}, R"({"v":1})"));

    auto res = t.db.execute_query("SELECT detail FROM power_live WHERE action = 'capture_gap'");
    REQUIRE(res.has_value());
    REQUIRE(res->rows.size() == 1);
    CHECK(res->rows[0][0] == "dropped=3");
}
