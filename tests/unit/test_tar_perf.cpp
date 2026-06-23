/**
 * test_tar_perf.cpp — perf sampling for the TAR edge warehouse (BRD A1).
 *
 * Two halves:
 *  1. derive_sample (pure): the cumulative-counter → rate/percentage math —
 *     CPU busy %, memory/commit %, disk throughput + per-IO latency, network
 *     rates — including the degradation contract (CPU regression invalidates
 *     the sample; disk/net regression zeroes only its own domain).
 *  2. Schema-registry pins: the perf source's tables exist, translate, are
 *     operator-queryable, roll up hourly, and carry time-based retention.
 *
 * The Win32 counter reads are the impure shell, exercised on a live box; the
 * rest runs on every host.
 */

#include "tar_perf.hpp"
#include "tar_schema_registry.hpp"

#include <catch2/catch_approx.hpp>
#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <string>

using namespace yuzu::tar;
using Catch::Approx;

namespace {

// A baseline reading at t=1000 with all counters at comfortable values.
PerfCounters baseline() {
    PerfCounters c;
    c.valid = true;
    c.disk_valid = true;
    c.ts_epoch = 1000;
    c.cpu_idle = 1'000'000'000;
    c.cpu_kernel = 1'500'000'000; // includes idle
    c.cpu_user = 500'000'000;
    c.mem_total_bytes = 16ULL << 30;
    c.mem_avail_bytes = 4ULL << 30;
    c.commit_total_bytes = 10ULL << 30;
    c.commit_limit_bytes = 20ULL << 30;
    c.disk_read_bytes = 1'000'000;
    c.disk_write_bytes = 2'000'000;
    c.disk_read_time_100ns = 10'000'000;
    c.disk_write_time_100ns = 20'000'000;
    c.disk_reads = 1000;
    c.disk_writes = 2000;
    c.net_rx_bytes = 5'000'000;
    c.net_tx_bytes = 6'000'000;
    return c;
}

} // namespace

TEST_CASE("perf: invalid inputs and zero elapsed never derive", "[tar][perf]") {
    PerfCounters good = baseline();
    CHECK(!derive_sample(PerfCounters{}, good).valid);
    CHECK(!derive_sample(good, PerfCounters{}).valid);
    PerfCounters same_ts = good;
    CHECK(!derive_sample(good, same_ts).valid); // elapsed == 0
}

TEST_CASE("perf: normal 30 s derivation", "[tar][perf]") {
    PerfCounters prev = baseline();
    PerfCounters cur = prev;
    cur.ts_epoch = 1030;
    // 30 s on (say) 2 cores: total delta = 600e6 (100 ns units of CPU-time),
    // idle delta = 300e6 → 50% busy.
    cur.cpu_idle += 300'000'000;
    cur.cpu_kernel += 400'000'000; // kernel includes the idle delta
    cur.cpu_user += 200'000'000;
    // 12 GiB of 16 GiB in use; commit unchanged at 50%.
    cur.mem_avail_bytes = 4ULL << 30;
    // Disk: +30 MB read over 30 s = 1 MB/s; +3000 reads taking +3e6 ×100 ns
    // total → 1000 ×100 ns = 100 µs per read. Writes idle.
    cur.disk_read_bytes += 30'000'000;
    cur.disk_reads += 3000;
    cur.disk_read_time_100ns += 3'000'000;
    // Net: +3 MB rx, +1.5 MB tx over 30 s.
    cur.net_rx_bytes += 3'000'000;
    cur.net_tx_bytes += 1'500'000;

    auto s = derive_sample(prev, cur);
    REQUIRE(s.valid);
    CHECK(s.cpu_pct == Approx(50.0));
    CHECK(s.mem_used_pct == Approx(75.0));
    CHECK(s.commit_pct == Approx(50.0));
    CHECK(s.disk_read_bps == 1'000'000);
    CHECK(s.disk_write_bps == 0);
    CHECK(s.disk_read_lat_us == 100); // 3e6 / 3000 reads / 10 = 100 µs per read
    CHECK(s.disk_write_lat_us == 0);  // no writes → no latency claim
    CHECK(s.net_rx_bps == 100'000);
    CHECK(s.net_tx_bps == 50'000);
}

TEST_CASE("perf: CPU counter regression invalidates the whole sample", "[tar][perf]") {
    PerfCounters prev = baseline();
    PerfCounters cur = prev;
    cur.ts_epoch = 1030;
    cur.cpu_kernel -= 1; // reboot / counter reset
    CHECK(!derive_sample(prev, cur).valid);
}

TEST_CASE("perf: disk regression zeroes the disk domain only", "[tar][perf]") {
    PerfCounters prev = baseline();
    PerfCounters cur = prev;
    cur.ts_epoch = 1030;
    cur.cpu_kernel += 100'000'000;
    cur.cpu_idle += 100'000'000;
    cur.disk_read_bytes = 0; // hotplug — counters reset below the baseline
    cur.disk_reads = 0;
    cur.net_rx_bytes += 300'000;

    auto s = derive_sample(prev, cur);
    REQUIRE(s.valid); // the sample survives
    CHECK(s.disk_read_bps == 0);
    CHECK(s.disk_read_lat_us == 0);
    CHECK(s.net_rx_bps == 10'000); // the other domains stay honest
}

TEST_CASE("perf: missing disk support leaves disk fields zero", "[tar][perf]") {
    PerfCounters prev = baseline();
    PerfCounters cur = prev;
    cur.ts_epoch = 1030;
    prev.disk_valid = false; // IOCTL_DISK_PERFORMANCE unavailable
    cur.disk_read_bytes += 30'000'000;
    auto s = derive_sample(prev, cur);
    REQUIRE(s.valid);
    CHECK(s.disk_read_bps == 0);
}

TEST_CASE("perf: percentages are clamped against garbage readings", "[tar][perf]") {
    PerfCounters prev = baseline();
    PerfCounters cur = prev;
    cur.ts_epoch = 1030;
    cur.cpu_kernel += 100;
    cur.mem_avail_bytes = 32ULL << 30;            // avail > total
    cur.commit_total_bytes = 40ULL << 30;         // commit > limit
    auto s = derive_sample(prev, cur);
    REQUIRE(s.valid);
    CHECK(s.mem_used_pct == 0.0);
    CHECK(s.commit_pct == 100.0);
}

TEST_CASE("perf: live counter read smoke", "[tar][perf]") {
#ifdef _WIN32
    // Real syscalls on a real box: the core reads must succeed everywhere.
    auto c = read_perf_counters();
    REQUIRE(c.valid);
    CHECK(c.mem_total_bytes > 0);
    CHECK(c.cpu_kernel > 0); // cumulative since boot — never zero on a live system
#else
    CHECK(!read_perf_counters().valid); // kPlanned platforms record nothing
#endif
}

// ── Schema registry pins ─────────────────────────────────────────────────────

TEST_CASE("perf: registry tables translate and are operator-queryable", "[tar][perf]") {
    auto live = translate_dollar_name("$Perf_Live");
    REQUIRE(live);
    CHECK(*live == "perf_live");
    auto hourly = translate_dollar_name("$Perf_Hourly");
    REQUIRE(hourly);
    CHECK(*hourly == "perf_hourly");
    CHECK(is_queryable_table("perf_live"));
    CHECK(is_queryable_table("perf_hourly"));

    auto cols = columns_for_table("perf_live");
    CHECK(std::find(cols.begin(), cols.end(), "cpu_pct") != cols.end());
    CHECK(std::find(cols.begin(), cols.end(), "net_tx_bps") != cols.end());
}

TEST_CASE("perf: hourly rollup SQL exists and targets perf_hourly", "[tar][perf]") {
    auto sql = rollup_sql("perf", "hourly");
    REQUIRE(!sql.empty());
    CHECK(sql.find("INSERT INTO perf_hourly") != std::string::npos);
    CHECK(sql.find("MAX(cpu_pct)") != std::string::npos);
}

TEST_CASE("perf: live retention is time-based", "[tar][perf]") {
    auto sql = retention_sql("perf_live", 2'000'000);
    REQUIRE(!sql.empty());
    CHECK(sql.find("DELETE FROM perf_live WHERE ts <") != std::string::npos);
}

TEST_CASE("perf: DDL declares the perf tables with numeric defaults", "[tar][perf]") {
    auto ddl = generate_warehouse_ddl();
    CHECK(ddl.find("CREATE TABLE IF NOT EXISTS perf_live") != std::string::npos);
    CHECK(ddl.find("CREATE TABLE IF NOT EXISTS perf_hourly") != std::string::npos);
    // REAL columns must default 0, not '' (generator fix shipped with A1).
    CHECK(ddl.find("cpu_pct REAL NOT NULL DEFAULT 0") != std::string::npos);
}

TEST_CASE("perf #538: a reset baseline (post-disable) emits no off-period-spanning row",
          "[tar][perf][source-lifecycle]") {
    // When `perf` is disabled, do_collect_perf's disable branch installs a
    // default-constructed PerfCounters as prev_perf_ (valid=false). This models
    // the first tick AFTER a re-enable: even though the live counters advanced a
    // lot during the paused window, deriving against the reset baseline must
    // produce NO sample (it re-baselines), so the first post-re-enable row never
    // covers the off-period. Without the reset, prev_perf_ would still hold the
    // pre-disable reading and this same call would emit a delta spanning the gap.
    PerfCounters after_gap = baseline();
    after_gap.ts_epoch = 100'000;             // long pause elapsed
    after_gap.cpu_idle += 50'000'000'000;     // counters advanced across the gap
    after_gap.cpu_kernel += 80'000'000'000;
    after_gap.cpu_user += 30'000'000'000;
    after_gap.disk_read_bytes += 9'000'000'000;
    after_gap.net_rx_bytes += 9'000'000'000;

    // The disable branch's reset == a default-constructed prev → no row.
    CHECK(!derive_sample(PerfCounters{}, after_gap).valid);
    // Sanity: against the real pre-gap baseline it WOULD have emitted a row —
    // exactly the off-period leak the reset prevents.
    CHECK(derive_sample(baseline(), after_gap).valid);
}
