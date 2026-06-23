/**
 * test_dex_linux_kmsg.cpp — pure kernel-message classification (dex_linux_kmsg).
 *
 * Kernel ring-buffer lines carry no MESSAGE_ID, so they are classified by anchored
 * substring markers on the raw MESSAGE. Parsing them is pure text handling, so this
 * runs on EVERY host incl. MSVC.
 *
 * FIXTURE PROVENANCE (the make-or-break — a guessed marker is a dead signal that
 * still passes a guessed fixture):
 *   - disk.error / fs.corruption / os.dirty_shutdown fixtures are records
 *     LIVE-CAPTURED on a real systemd-259 / kernel-7.0 box via safe error injection
 *     (scsi_debug medium error → "critical medium error, dev sdb, sector …";
 *     debugfs block-pointer corruption → "EXT4-fs error (device loop17): …";
 *     a direct-IO loop snapshot mid-write → "EXT4-fs (loop17): recovery complete").
 *   - os.bugcheck / hw.error / process.hung use the dead-stable documented kernel
 *     format strings (the box can't panic / inject MCE) — fixture-pinned, awaiting
 *     live-fire, the Windows manifest-pinned convention.
 */

#include "dex_linux_kmsg.hpp"

#include "dex_event.hpp" // signal_detail_json — prove no raw kernel detail reaches the wire

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <string_view>

using namespace yuzu::agent::lnx;

// ── disk.error (LIVE-CAPTURED) ───────────────────────────────────────────────────

TEST_CASE("kmsg: SCSI critical medium error → disk.error (device subject)",
          "[guardian][dex][linux][kmsg]") {
    // Real scsi_debug medium-error injection; the "blk_update_request:" prefix is
    // stripped on modern kernels, so the line is the bare "<type> error, dev X, …".
    const auto obs = classify_kernel_message(
        "critical medium error, dev sdb, sector 24 op 0x0:(READ) flags 0x800000 phys_seg 1 prio class 2");
    REQUIRE(obs.has_value());
    CHECK(obs->obs_type == "disk.error");
    CHECK(obs->subject == "sdb"); // the backing device — the storm/dedup key
    CHECK(obs->reason == "medium-error");
    CHECK(obs->platform.empty()); // the collector stamps platform, not the classifier
}

TEST_CASE("kmsg: Buffer I/O error → disk.error", "[guardian][dex][linux][kmsg]") {
    const auto obs =
        classify_kernel_message("Buffer I/O error on dev sdb, logical block 0, async page read");
    REQUIRE(obs.has_value());
    CHECK(obs->obs_type == "disk.error");
    CHECK(obs->subject == "sdb");
    CHECK(obs->reason == "io-error");
}

TEST_CASE("kmsg: dm / generic block I/O error subject is the device-mapper name",
          "[guardian][dex][linux][kmsg]") {
    const auto obs =
        classify_kernel_message("Buffer I/O error on dev dm-0, logical block 0, async page read");
    REQUIRE(obs.has_value());
    CHECK(obs->obs_type == "disk.error");
    CHECK(obs->subject == "dm-0");
}

// ── fs.corruption (LIVE-CAPTURED) ────────────────────────────────────────────────

TEST_CASE("kmsg: EXT4-fs error → fs.corruption (device subject, raw detail dropped)",
          "[guardian][dex][linux][kmsg]") {
    const auto obs = classify_kernel_message(
        "EXT4-fs error (device loop17): __ext4_iget:5393: inode #13: block 9999999: comm cat: invalid block");
    REQUIRE(obs.has_value());
    CHECK(obs->obs_type == "fs.corruption");
    CHECK(obs->subject == "loop17");
    CHECK(obs->reason == "fs-error");
}

TEST_CASE("kmsg: XFS / BTRFS corruption → fs.corruption", "[guardian][dex][linux][kmsg]") {
    const auto xfs =
        classify_kernel_message("XFS (sda1): Metadata corruption detected at xfs_agf_read_verify");
    REQUIRE(xfs.has_value());
    CHECK(xfs->obs_type == "fs.corruption");
    CHECK(xfs->subject == "sda1");

    const auto btrfs =
        classify_kernel_message("BTRFS error (device sdb1): bad tree block start, want 12345 have 0");
    REQUIRE(btrfs.has_value());
    CHECK(btrfs->obs_type == "fs.corruption");
    CHECK(btrfs->subject == "sdb1");

    // BTRFS may append " state X" before the ')': the device token stops at the space.
    const auto btrfs2 =
        classify_kernel_message("BTRFS error (device sdb1 state EA): bdev errors: wr 0, rd 1");
    REQUIRE(btrfs2.has_value());
    CHECK(btrfs2->subject == "sdb1");
}

// ── os.dirty_shutdown (LIVE-CAPTURED) ────────────────────────────────────────────

TEST_CASE("kmsg: EXT4 journal recovery → os.dirty_shutdown", "[guardian][dex][linux][kmsg]") {
    // Logged only when the journal needed replay = the prior shutdown was unclean.
    const auto obs = classify_kernel_message("EXT4-fs (loop17): recovery complete");
    REQUIRE(obs.has_value());
    CHECK(obs->obs_type == "os.dirty_shutdown");
    CHECK(obs->subject == "loop17");
    CHECK(obs->reason == "journal-recovery");
}

TEST_CASE("kmsg: XFS log recovery → os.dirty_shutdown", "[guardian][dex][linux][kmsg]") {
    const auto obs =
        classify_kernel_message("XFS (sda2): Starting recovery (logdev: internal)");
    REQUIRE(obs.has_value());
    CHECK(obs->obs_type == "os.dirty_shutdown");
    CHECK(obs->subject == "sda2");
}

TEST_CASE("kmsg: a normal (clean) EXT4 mount is NOT a dirty shutdown",
          "[guardian][dex][linux][kmsg]") {
    // The exact clean-mount line seen alongside the recovery line on the live box —
    // it must NOT fire os.dirty_shutdown (no "recovery complete").
    CHECK_FALSE(classify_kernel_message(
                    "EXT4-fs (loop17): mounted filesystem 53fd-… r/w with ordered data mode. Quota mode: none.")
                    .has_value());
}

// ── memory.exhausted (OOM logic, moved from parse_journal_line) ──────────────────

TEST_CASE("kmsg: kernel OOM-kill → memory.exhausted (both message forms)",
          "[guardian][dex][linux][kmsg]") {
    const auto sys = classify_kernel_message(
        "Out of memory: Killed process 4321 (mysqld) total-vm:9000000kB, anon-rss:8000000kB");
    REQUIRE(sys.has_value());
    CHECK(sys->obs_type == "memory.exhausted");
    CHECK(sys->subject == "mysqld");

    // cgroup-v2 form (the modern-systemd common case): leading "Out" is lower-cased.
    const auto cg = classify_kernel_message(
        "Memory cgroup out of memory: Killed process 1802705 (python3) total-vm:161112kB");
    REQUIRE(cg.has_value());
    CHECK(cg->subject == "python3");
}

TEST_CASE("kmsg: privacy — OOM ships the victim comm only, never the kernel memory figures",
          "[guardian][dex][linux][kmsg][privacy]") {
    // The OOM line carries total-vm / anon-rss / file-rss figures and the killed PID; only
    // the parenthesised victim comm may leave the device. (The OOM classifier moved into
    // dex_linux_kmsg this commit — pin its privacy contract here, symmetric with the fs /
    // disk pins.) Asserts the wire payload (signal_detail_json) is free of the figures.
    const auto obs = classify_kernel_message(
        "Out of memory: Killed process 4321 (mysqld) total-vm:9000000kB, anon-rss:8000000kB, file-rss:0kB");
    REQUIRE(obs.has_value());
    CHECK(obs->subject == "mysqld");
    const std::string detail = signal_detail_json(*obs);
    for (const std::string_view leak :
         {"total-vm", "anon-rss", "file-rss", "9000000", "8000000", "4321"}) {
        CHECK(obs->subject.find(leak) == std::string_view::npos);
        CHECK(obs->sentence.find(leak) == std::string_view::npos);
        CHECK(detail.find(leak) == std::string_view::npos);
    }
}

// ── os.bugcheck — FATAL panic only (fixture-pinned) ─ TODO(live-fire): panic reboots, capture a real record 

TEST_CASE("kmsg: kernel panic → os.bugcheck", "[guardian][dex][linux][kmsg]") {
    const auto obs =
        classify_kernel_message("Kernel panic - not syncing: Attempted to kill init! exitcode=0x00000009");
    REQUIRE(obs.has_value());
    CHECK(obs->obs_type == "os.bugcheck");
    CHECK(obs->subject == "kernel");
    CHECK(obs->kind == "panic");
}

TEST_CASE("kmsg: a survivable Oops is NOT mapped to os.bugcheck (fatal-only)",
          "[guardian][dex][linux][kmsg]") {
    // The box survives an Oops; mapping it to the BSOD-equivalent type would inflate
    // the bugcheck rate. Grilled decision: fatal panic only.
    CHECK_FALSE(classify_kernel_message("Oops: 0000 [#1] SMP NOPTI").has_value());
    CHECK_FALSE(classify_kernel_message("watchdog: BUG: soft lockup - CPU#0 stuck for 23s!")
                    .has_value());
}

// ── hw.error — machine-check (fixture-pinned, awaiting live-fire) ─────────────────

TEST_CASE("kmsg: machine-check / hardware error → hw.error", "[guardian][dex][linux][kmsg]") {
    CHECK(classify_kernel_message("mce: [Hardware Error]: Machine check events logged")->obs_type ==
          "hw.error");
    CHECK(classify_kernel_message(
              "[Hardware Error]: CPU 0: Machine Check: 0 Bank 5: bea0000000000108")
              ->obs_type == "hw.error");
}

TEST_CASE("kmsg: benign boot MCE-bank line is NOT a hardware error",
          "[guardian][dex][linux][kmsg]") {
    CHECK_FALSE(classify_kernel_message("mce: CPU supports 9 MCE banks").has_value());
}

// ── process.hung — hung-task watchdog (fixture-pinned, awaiting live-fire) ────────

TEST_CASE("kmsg: hung_task → process.hung (comm subject)", "[guardian][dex][linux][kmsg]") {
    const auto obs = classify_kernel_message("INFO: task dd:3968282 blocked for more than 8 seconds.");
    REQUIRE(obs.has_value());
    CHECK(obs->obs_type == "process.hung");
    CHECK(obs->subject == "dd"); // comm only, never the pid
    CHECK(obs->kind == "hang");
}

// ── noise / precedence ───────────────────────────────────────────────────────────

TEST_CASE("kmsg: an ordinary kernel line yields no observation",
          "[guardian][dex][linux][kmsg]") {
    CHECK_FALSE(
        classify_kernel_message("usb 1-1: new high-speed USB device number 5 using xhci_hcd")
            .has_value());
    CHECK_FALSE(classify_kernel_message("").has_value());
    CHECK_FALSE(classify_kernel_message("sd 4:0:0:0: [sdb] Mode Sense: 73 00 10 08").has_value());
}

TEST_CASE("kmsg_device_after extracts an infra device token, stops at ) , space :",
          "[guardian][dex][linux][kmsg]") {
    CHECK(kmsg_device_after("EXT4-fs error (device loop17): x", "EXT4-fs error (device ") ==
          "loop17");
    CHECK(kmsg_device_after("Buffer I/O error on dev sdb, logical block 0", "on dev ") == "sdb");
    CHECK(kmsg_device_after("nothing here", "(device ").empty());
}

// ── privacy: only infra-safe fields leave the device ─────────────────────────────

TEST_CASE("kmsg: privacy — fs.corruption ships the device only, never the raw line",
          "[guardian][dex][linux][kmsg][privacy]") {
    // The real EXT4-fs error line carries the accessing comm, the inode #, the bad
    // block #, and the kernel function:line — none may leave the device.
    const auto obs = classify_kernel_message(
        "EXT4-fs error (device loop17): __ext4_iget:5393: inode #13: block 9999999: comm cat: invalid block");
    REQUIRE(obs.has_value());
    const std::string detail = signal_detail_json(*obs);
    for (const std::string_view leak :
         {"comm cat", "9999999", "inode #13", "__ext4_iget", "5393"}) {
        CHECK(obs->subject.find(leak) == std::string_view::npos);
        CHECK(obs->sentence.find(leak) == std::string_view::npos);
        CHECK(detail.find(leak) == std::string_view::npos);
    }
}

TEST_CASE("kmsg: privacy — disk.error ships the device only, never the sector/op",
          "[guardian][dex][linux][kmsg][privacy]") {
    const auto obs = classify_kernel_message(
        "critical medium error, dev sdb, sector 24 op 0x0:(READ) flags 0x800000 phys_seg 1 prio class 2");
    REQUIRE(obs.has_value());
    const std::string detail = signal_detail_json(*obs);
    for (const std::string_view leak : {"sector 24", "op 0x0", "flags 0x800000", "phys_seg"}) {
        CHECK(obs->sentence.find(leak) == std::string_view::npos);
        CHECK(detail.find(leak) == std::string_view::npos);
    }
}
