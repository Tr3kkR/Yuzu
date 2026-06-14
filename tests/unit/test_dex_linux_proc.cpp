/**
 * test_dex_linux_proc.cpp — pure Linux /proc parsers (dex_linux_proc).
 *
 * The sibling of test_dex_perf_breach / test_dex_win_poll: /proc/stat, /proc/meminfo
 * and /proc/mounts parsing is pure text handling, so it runs on EVERY host against
 * captured fixtures. The statvfs read and the poll thread (dex_linux_collector) are
 * exercised on a real Linux box via the live pipeline, not here.
 */

#include "dex_linux_proc.hpp"

#include "dex_event.hpp"         // signal_detail_json — prove no path PII reaches the wire payload
#include "dex_linux_storage.hpp" // storage_low_observation — the exact chokepoint the collector calls
#include "dex_win_poll.hpp"      // DiskLevel

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_floating_point.hpp>

#include <string>
#include <string_view>

using namespace yuzu::agent;
using namespace yuzu::agent::lnx;
using Catch::Matchers::WithinAbs;

namespace {
// A near-full local volume (100 GiB total, 1 GiB free = 99% used) — trips storage.low.
win::DiskLevel near_full() {
    win::DiskLevel d;
    d.valid = true;
    d.total_bytes = 100ULL * 1024 * 1024 * 1024;
    d.free_bytes = 1ULL * 1024 * 1024 * 1024;
    return d;
}
} // namespace

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

TEST_CASE("overcommit_is_always detects mode 1 only", "[guardian][dex][linux][proc]") {
    CHECK(overcommit_is_always("1\n"));
    CHECK(overcommit_is_always("1"));
    CHECK_FALSE(overcommit_is_always("0\n")); // heuristic (default)
    CHECK_FALSE(overcommit_is_always("2\n")); // strict — CommitLimit is hard, keep the signal
    CHECK_FALSE(overcommit_is_always(""));     // unreadable → keep the signal (fail-safe)
    CHECK_FALSE(overcommit_is_always("10\n")); // must be exactly "1", not a prefix
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

TEST_CASE("parse_storage_mounts decodes octal-escaped mount paths",
          "[guardian][dex][linux][proc]") {
    // A mount point containing a space: the kernel writes it as \040 in /proc/mounts.
    // Without decoding, statvfs would be handed the wrong spelling and silently skip it.
    const auto mounts = parse_storage_mounts("/dev/sdb1 /mnt/My\\040Backup ext4 rw 0 0\n");
    REQUIRE(mounts.size() == 1);
    CHECK(mounts[0].path == "/mnt/My Backup");
    // The DEVICE field is decoded too (it is the dedup key + the device_label source).
    const auto dev = parse_storage_mounts("/dev/My\\040Disk / ext4 rw 0 0\n");
    REQUIRE(dev.size() == 1);
    CHECK(dev[0].device == "/dev/My Disk");
    CHECK(device_label(dev[0].device) == "My Disk");
    // A truncated escape at end-of-field is copied verbatim, never read out of bounds.
    const auto trunc = parse_storage_mounts("/dev/sda1 /mnt/x\\04 ext4 rw 0 0\n");
    REQUIRE(trunc.size() == 1);
    CHECK(trunc[0].path == "/mnt/x\\04");
}

TEST_CASE("parse_storage_mounts keeps the rw mount when an ro mount of the same device precedes it",
          "[guardian][dex][linux][proc]") {
    // The reviewer's LOW edge: ro-first, rw-second. The ro filter runs BEFORE the dedup,
    // so the ro mount never occupies the dedup slot and the writable mount is the one kept.
    const auto mounts = parse_storage_mounts("/dev/sda1 /snap/x ext4 ro 0 0\n"
                                             "/dev/sda1 / ext4 rw 0 0\n");
    REQUIRE(mounts.size() == 1);
    CHECK(mounts[0].path == "/"); // the rw mount, not the ro one
}

TEST_CASE("device_label is the backing-device basename, never a path component",
          "[guardian][dex][linux][proc][privacy]") {
    CHECK(device_label("/dev/sda1") == "sda1");
    CHECK(device_label("/dev/nvme0n1p2") == "nvme0n1p2");
    CHECK(device_label("/dev/mapper/vg0-root") == "vg0-root"); // LVM friendly name = infra config
    CHECK(device_label("sda1") == "sda1");                     // already a basename
    CHECK(device_label("") == "disk");                         // empty → safe fallback
    CHECK(device_label("/dev/") == "disk");                    // trailing slash → empty basename
    // ZFS dataset: /proc/mounts source is the dataset PATH, not a /dev node, and the
    // canonical layout puts the user/tenant in the LEAF — so the label must be the POOL
    // (first segment), NEVER the basename (which would leak the leaf). (Gate-2 HIGH.)
    CHECK(device_label("tank/home/alice") == "tank");
    CHECK(device_label("rpool/USERDATA/alice_a1b2c3") == "rpool"); // zsys real-world form
    CHECK(device_label("tank") == "tank");                         // pool root mounted directly
}

TEST_CASE("storage.low carries the device label, NEVER the mount path (edge-privacy)",
          "[guardian][dex][linux][proc][privacy]") {
    // A mount path laden with a username + tenant/project name — the exact content the
    // DEX edge-privacy contract forbids leaving the device.
    const auto mounts = parse_storage_mounts("/dev/sdb1 /home/alice/Acquisition-X ext4 rw 0 0\n");
    REQUIRE(mounts.size() == 1);
    CHECK(mounts[0].path == "/home/alice/Acquisition-X"); // retained ONLY for the local statvfs()

    // Call the SAME chokepoint the collector calls (dex_linux_collector.cpp:
    //   lnx::storage_low_observation(m, level)) — so this is a regression guard on the
    // collector's wiring, not just a re-composition of the expression.
    const auto obs = storage_low_observation(mounts[0], near_full());
    REQUIRE(obs);
    CHECK(obs->subject == "sdb1");

    // No path component may appear in ANY emitted surface: the subject, the sentence
    // (→ detected_value / the event name), or the structured detail_json (→ wire + dashboard).
    const std::string detail = signal_detail_json(*obs);
    for (const std::string_view leak : {"alice", "Acquisition", "/home", "home/"}) {
        CHECK(obs->subject.find(leak) == std::string_view::npos);
        CHECK(obs->sentence.find(leak) == std::string_view::npos);
        CHECK(detail.find(leak) == std::string_view::npos);
    }
}

TEST_CASE("storage.low on a ZFS dataset emits the POOL, never the per-user leaf (edge-privacy)",
          "[guardian][dex][linux][proc][privacy]") {
    // ZFS's /proc/mounts source is the dataset PATH; the canonical layout puts the
    // user/tenant in the LEAF. Both real-world forms must reduce to the pool, with no
    // leaf token reaching subject / sentence / detail_json. (Gate-2 HIGH regression guard.)
    const auto check_pool = [](const char* mounts_line, const char* pool, const char* leak) {
        const auto mounts = parse_storage_mounts(mounts_line);
        REQUIRE(mounts.size() == 1);
        const auto obs = storage_low_observation(mounts[0], near_full());
        REQUIRE(obs);
        CHECK(obs->subject == pool); // the pool (infra config), not the dataset leaf
        const std::string detail = signal_detail_json(*obs);
        CHECK(obs->subject.find(leak) == std::string::npos);
        CHECK(obs->sentence.find(leak) == std::string::npos);
        CHECK(detail.find(leak) == std::string::npos);
    };
    check_pool("tank/home/alice /home/alice zfs rw 0 0\n", "tank", "alice");
    check_pool("rpool/USERDATA/alice_a1b2c3 /home/alice zfs rw 0 0\n", "rpool", "alice");
}
