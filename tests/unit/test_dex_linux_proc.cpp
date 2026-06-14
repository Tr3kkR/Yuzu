/**
 * test_dex_linux_proc.cpp — pure Linux /proc parsers (dex_linux_proc).
 *
 * The sibling of test_dex_perf_breach / test_dex_win_poll: /proc/stat, /proc/meminfo
 * and /proc/mounts parsing is pure text handling, so it runs on EVERY host against
 * captured fixtures. The statvfs read and the poll thread (dex_linux_collector) are
 * exercised on a real Linux box via the live pipeline, not here.
 */

#include "dex_linux_proc.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_floating_point.hpp>

using namespace yuzu::agent::lnx;
using Catch::Matchers::WithinAbs;

TEST_CASE("parse_proc_stat reads the aggregate cpu line", "[guardian][dex][linux][proc]") {
    const std::string s = "cpu  2180059 2396 206543 27474468 18799 0 3876 0 0 0\n"
                          "cpu0 1090000 1200 103000 13700000 9000 0 1900 0 0 0\n"
                          "intr 12345\n";
    const CpuJiffies j = parse_proc_stat(s);
    REQUIRE(j.valid);
    // total = first 8 fields only (guest/guest_nice excluded — folded into user/nice)
    CHECK(j.total == 2180059ULL + 2396 + 206543 + 27474468 + 18799 + 0 + 3876 + 0);
    CHECK(j.idle == 27474468ULL + 18799); // idle + iowait
}

TEST_CASE("parse_proc_stat rejects missing/short/malformed", "[guardian][dex][linux][proc]") {
    CHECK_FALSE(parse_proc_stat("").valid);
    CHECK_FALSE(parse_proc_stat("cpu0 1 2 3 4 5\nintr 9\n").valid); // per-core only, no aggregate
    CHECK_FALSE(parse_proc_stat("cpu 1 2\n").valid);                // fewer than 4 fields
    CHECK_FALSE(parse_proc_stat("cpu 100 200 xx 400 500\n").valid); // non-numeric token, never throws
}

TEST_CASE("parse_proc_stat tolerates a pre-2.6.11 5-field line", "[guardian][dex][linux][proc]") {
    // user nice system idle iowait — no irq/softirq/steal
    const CpuJiffies j = parse_proc_stat("cpu 10 0 5 80 5\n");
    REQUIRE(j.valid);
    CHECK(j.total == 100); // 10+0+5+80+5
    CHECK(j.idle == 85);   // 80 + 5
}

TEST_CASE("cpu_busy_pct derives the busy fraction", "[guardian][dex][linux][proc]") {
    // dt = 1000, di (idle delta) = 400 → 60% busy
    const auto pct = cpu_busy_pct(CpuJiffies{true, 1000, 800}, CpuJiffies{true, 2000, 1200});
    REQUIRE(pct.has_value());
    CHECK_THAT(*pct, WithinAbs(60.0, 1e-9));
}

TEST_CASE("cpu_busy_pct guards invalid/regressed/zero-elapsed", "[guardian][dex][linux][proc]") {
    CHECK_FALSE(cpu_busy_pct(CpuJiffies{false, 0, 0}, CpuJiffies{true, 2000, 1200}).has_value());
    CHECK_FALSE(cpu_busy_pct(CpuJiffies{true, 2000, 1200}, CpuJiffies{true, 1000, 800})
                    .has_value()); // total regression (reboot)
    CHECK_FALSE(
        cpu_busy_pct(CpuJiffies{true, 1000, 800}, CpuJiffies{true, 1000, 800}).has_value()); // dt=0
}

TEST_CASE("parse_commit_pct = Committed_AS / CommitLimit", "[guardian][dex][linux][proc]") {
    const std::string s = "MemTotal:       11034524 kB\n"
                          "MemAvailable:    9141240 kB\n"
                          "CommitLimit:     9711560 kB\n"
                          "Committed_AS:    7532440 kB\n";
    const auto pct = parse_commit_pct(s);
    REQUIRE(pct.has_value());
    CHECK_THAT(*pct, WithinAbs(100.0 * 7532440.0 / 9711560.0, 1e-6)); // ~77.56%
}

TEST_CASE("parse_commit_pct guards missing/zero limit", "[guardian][dex][linux][proc]") {
    CHECK_FALSE(parse_commit_pct("Committed_AS: 100 kB\n").has_value());            // no limit
    CHECK_FALSE(parse_commit_pct("CommitLimit: 0 kB\nCommitted_AS: 5 kB\n").has_value()); // zero
    CHECK_FALSE(parse_commit_pct("CommitLimit: 100 kB\n").has_value());            // no committed
    // exact-key match: "CommitLimit" must not be read as "Committed_AS"
    CHECK_FALSE(parse_commit_pct("CommitLimit: 100 kB\nCommitLimitFoo: 1 kB\n").has_value());
}

TEST_CASE("parse_commit_pct clamps heuristic overcommit to 100", "[guardian][dex][linux][proc]") {
    const auto pct = parse_commit_pct("CommitLimit: 100 kB\nCommitted_AS: 150 kB\n");
    REQUIRE(pct.has_value());
    CHECK_THAT(*pct, WithinAbs(100.0, 1e-9));
}

TEST_CASE("parse_storage_mounts whitelists local fs, skips pseudo/ro/snap",
          "[guardian][dex][linux][proc]") {
    const std::string m = "sysfs /sys sysfs rw,nosuid 0 0\n"
                          "/dev/sda1 / ext4 rw,relatime 0 0\n"
                          "/dev/sdb1 /data xfs rw 0 0\n"
                          "/dev/loop0 /snap/core squashfs ro,nodev 0 0\n"
                          "tmpfs /run tmpfs rw,nosuid 0 0\n"
                          "/dev/sdc1 /mnt/ro ext4 ro,relatime 0 0\n"
                          "server:/export /nfs nfs rw 0 0\n";
    const auto mounts = parse_storage_mounts(m);
    REQUIRE(mounts.size() == 2);
    CHECK(mounts[0].path == "/");
    CHECK(mounts[0].fstype == "ext4");
    CHECK(mounts[1].path == "/data");
    CHECK(mounts[1].fstype == "xfs");
}

TEST_CASE("parse_storage_mounts dedups by backing device", "[guardian][dex][linux][proc]") {
    const std::string m = "/dev/sda1 / ext4 rw 0 0\n"
                          "/dev/sda1 /mnt/bind ext4 rw 0 0\n";
    CHECK(parse_storage_mounts(m).size() == 1);
}
