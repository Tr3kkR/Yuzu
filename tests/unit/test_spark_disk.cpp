/**
 * test_spark_disk.cpp — pure disk-spark decision logic (spark_disk.cpp) plus
 * the spark_key canonical identity (spark_spec.cpp).
 *
 * The latch is the dex_win_poll `latch_should_emit` contract ported to the
 * spark tier and extended with the Recovery edge: Breach exactly on the
 * transition INTO bad, silence while bad persists, Recovery exactly on a VALID
 * healthy reading, and an INVALID reading never moves the latch in either
 * direction (gov UP-5). All pure — no engine, no threads.
 */

#include "spark_types.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

using namespace yuzu::agent;

namespace {

constexpr std::uint64_t kGiB = 1024ULL * 1024 * 1024;

DiskReading reading(std::uint64_t total, std::uint64_t free_bytes) {
    DiskReading r;
    r.valid = true;
    r.total_bytes = total;
    r.free_bytes = free_bytes;
    return r;
}

constexpr std::uint32_t kPct = 90;
constexpr std::uint64_t kMinFree = 5 * kGiB;

} // namespace

TEST_CASE("disk_reading_is_bad: thresholds", "[spark][disk]") {
    // 100 GiB volume: bad at >= 90% used OR < 5 GiB free.
    CHECK_FALSE(disk_reading_is_bad(reading(100 * kGiB, 50 * kGiB), kPct, kMinFree));
    CHECK_FALSE(disk_reading_is_bad(reading(100 * kGiB, 11 * kGiB), kPct, kMinFree));
    CHECK(disk_reading_is_bad(reading(100 * kGiB, 10 * kGiB), kPct, kMinFree)); // exactly 90% used
    CHECK(disk_reading_is_bad(reading(100 * kGiB, 4 * kGiB), kPct, kMinFree));

    // Small volume: 80% used (below the 90% pct threshold) but only 4 GiB free
    // — bad via the absolute floor alone.
    CHECK(disk_reading_is_bad(reading(20 * kGiB, 4 * kGiB), kPct, kMinFree));

    // min_free_bytes == 0 disables the absolute floor: the same reading is
    // healthy once only the pct threshold applies.
    CHECK_FALSE(disk_reading_is_bad(reading(20 * kGiB, 4 * kGiB), kPct, 0));
    CHECK(disk_reading_is_bad(reading(100 * kGiB, 1 * kGiB), kPct, 0)); // 99% used still bad
}

TEST_CASE("disk_reading_is_bad: invalid or zero-size readings are never bad", "[spark][disk]") {
    DiskReading invalid; // valid == false
    CHECK_FALSE(disk_reading_is_bad(invalid, kPct, kMinFree));
    CHECK_FALSE(disk_reading_is_bad(reading(0, 0), kPct, kMinFree)); // zero-size volume
}

TEST_CASE("disk_latch_transition: breach once, silent while bad, recovery once",
          "[spark][disk]") {
    bool latched = false;

    // Healthy → nothing, latch stays off.
    CHECK_FALSE(disk_latch_transition(reading(100 * kGiB, 50 * kGiB), kPct, kMinFree, latched)
                    .has_value());
    CHECK_FALSE(latched);

    // Transition into bad → Breach, exactly once.
    auto e1 = disk_latch_transition(reading(100 * kGiB, 2 * kGiB), kPct, kMinFree, latched);
    REQUIRE(e1.has_value());
    CHECK(*e1 == DiskEdge::Breach);
    CHECK(latched);

    // Still bad → suppressed.
    CHECK_FALSE(
        disk_latch_transition(reading(100 * kGiB, 1 * kGiB), kPct, kMinFree, latched).has_value());
    CHECK(latched);

    // Valid healthy reading → Recovery, exactly once, latch re-armed.
    auto e2 = disk_latch_transition(reading(100 * kGiB, 60 * kGiB), kPct, kMinFree, latched);
    REQUIRE(e2.has_value());
    CHECK(*e2 == DiskEdge::Recovery);
    CHECK_FALSE(latched);

    // Healthy again → nothing.
    CHECK_FALSE(disk_latch_transition(reading(100 * kGiB, 60 * kGiB), kPct, kMinFree, latched)
                    .has_value());

    // A second breach after recovery fires again (re-armed).
    auto e3 = disk_latch_transition(reading(100 * kGiB, 2 * kGiB), kPct, kMinFree, latched);
    REQUIRE(e3.has_value());
    CHECK(*e3 == DiskEdge::Breach);
}

TEST_CASE("disk_latch_transition: an invalid reading never moves the latch (UP-5)",
          "[spark][disk]") {
    DiskReading invalid; // valid == false

    // Latched (breached earlier): a read failure must NOT clear the latch —
    // otherwise the next bad reading would re-fire a duplicate breach.
    bool latched = true;
    CHECK_FALSE(disk_latch_transition(invalid, kPct, kMinFree, latched).has_value());
    CHECK(latched);
    // ...and the still-bad reading after the blip stays suppressed.
    CHECK_FALSE(
        disk_latch_transition(reading(100 * kGiB, 1 * kGiB), kPct, kMinFree, latched).has_value());

    // Unlatched: a read failure must not fabricate a breach either.
    latched = false;
    CHECK_FALSE(disk_latch_transition(invalid, kPct, kMinFree, latched).has_value());
    CHECK_FALSE(latched);
}

TEST_CASE("disk_process_due: emits only on edges, always reschedules", "[spark][disk]") {
    DiskSparkParams params;
    params.path = "/does-not-matter";
    DiskReading next = reading(100 * kGiB, 50 * kGiB);
    const DiskReaderFn reader = [&](const std::string&) { return next; };
    bool latched = false;
    const auto now = std::chrono::steady_clock::now();

    // Healthy: no emission, rescheduled one poll out.
    auto d1 = disk_process_due(params, 1000, latched, reader, now);
    CHECK_FALSE(d1.emit);
    REQUIRE(d1.reschedule.has_value());
    CHECK(*d1.reschedule == now + std::chrono::milliseconds(1000));

    // Breach: emits with the reading + edge attached.
    next = reading(100 * kGiB, 1 * kGiB);
    auto d2 = disk_process_due(params, 1000, latched, reader, now);
    REQUIRE(d2.emit);
    const auto* data = std::get_if<DiskSparkData>(&d2.data);
    REQUIRE(data != nullptr);
    CHECK(data->edge == DiskEdge::Breach);
    CHECK(data->reading == next);
    CHECK(latched);

    // Recovery edge comes through too.
    next = reading(100 * kGiB, 60 * kGiB);
    auto d3 = disk_process_due(params, 1000, latched, reader, now);
    REQUIRE(d3.emit);
    const auto* data3 = std::get_if<DiskSparkData>(&d3.data);
    REQUIRE(data3 != nullptr);
    CHECK(data3->edge == DiskEdge::Recovery);
}

TEST_CASE("read_disk_level: real filesystem read is valid and sane", "[spark][disk]") {
    // Any test runner has a readable cwd; this exercises the platform path.
    const DiskReading r = read_disk_level(".");
    REQUIRE(r.valid);
    CHECK(r.total_bytes > 0);
    CHECK(r.free_bytes <= r.total_bytes);

    // A nonexistent path fails CLOSED: valid == false, never a reading.
    const DiskReading bad = read_disk_level("/definitely/not/a/real/path/yuzu-spark-test");
    CHECK_FALSE(bad.valid);
}

TEST_CASE("spark_key: deterministic, type-tagged, injective on delimiters", "[spark][key]") {
    SparkSpec interval{SparkType::Interval, IntervalSparkParams{60'000}};
    CHECK(spark_key(interval) == spark_key(interval));
    CHECK(spark_key(interval) !=
          spark_key(SparkSpec{SparkType::Interval, IntervalSparkParams{30'000}}));

    // Same-looking params under different types never collide.
    CHECK(spark_key(SparkSpec{SparkType::File, FileSparkParams{"x"}}) !=
          spark_key(SparkSpec{SparkType::Service, ServiceSparkParams{"x"}}));

    // Length-prefixing keeps delimiter-bearing strings injective: ("a|b","c")
    // vs ("a","b|c") must differ.
    CHECK(spark_key(SparkSpec{SparkType::Registry, RegistrySparkParams{"a|b", "c"}}) !=
          spark_key(SparkSpec{SparkType::Registry, RegistrySparkParams{"a", "b|c"}}));

    SparkSpec disk{SparkType::Disk, DiskSparkParams{"C:\\", 90, 5 * kGiB, 600'000}};
    SparkSpec disk2{SparkType::Disk, DiskSparkParams{"C:\\", 85, 5 * kGiB, 600'000}};
    CHECK(spark_key(disk) != spark_key(disk2));
}
