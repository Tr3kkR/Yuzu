// Pure unit tests for confined_fs_rules.hpp's decide_entry. No filesystem,
// no OS headers -- this file includes ONLY confined_fs_rules.hpp.

#include <yuzu/agent/confined_fs_rules.hpp>

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <limits>

using namespace yuzu::agent::confined_fs;

namespace {

constexpr DeleteLimits kOpenLimits{
    /*max_entries=*/1000,
    /*max_bytes=*/1'000'000,
    /*max_wall=*/std::chrono::milliseconds{60'000},
    /*max_depth=*/32,
};

constexpr EntryMeta regular_file(std::uint64_t size = 100) {
    return EntryMeta{EntryType::RegularFile, size, /*same_device_as_root=*/true};
}

} // namespace

TEST_CASE("decide_entry rejects a symlink", "[confined_fs]") {
    EntryMeta meta{EntryType::Symlink, 0, true};
    Decision d = decide_entry(meta, kOpenLimits, WalkTally{}, false, false, true);
    REQUIRE(d.action == Action::SkipEntry);
    REQUIRE(d.reason == Reason::SymlinkRejected);
}

TEST_CASE("decide_entry rejects a reparse point/junction", "[confined_fs]") {
    EntryMeta meta{EntryType::Reparse, 0, true};
    Decision d = decide_entry(meta, kOpenLimits, WalkTally{}, false, false, true);
    REQUIRE(d.action == Action::SkipEntry);
    REQUIRE(d.reason == Reason::ReparseRejected);
}

TEST_CASE("decide_entry rejects crossing a device boundary", "[confined_fs]") {
    EntryMeta meta{EntryType::RegularFile, 10, /*same_device_as_root=*/false};
    Decision d = decide_entry(meta, kOpenLimits, WalkTally{}, false, false, true);
    REQUIRE(d.action == Action::SkipEntry);
    REQUIRE(d.reason == Reason::DeviceBoundary);
}

TEST_CASE("decide_entry stops the walk at the entry cap", "[confined_fs]") {
    DeleteLimits limits = kOpenLimits;
    limits.max_entries = 5;
    WalkTally tally{5, 0};
    Decision d = decide_entry(regular_file(), limits, tally, false, false, true);
    REQUIRE(d.action == Action::StopWalk);
    REQUIRE(d.reason == Reason::EntryCap);
}

TEST_CASE("decide_entry skips on the byte cap and a following smaller file still deletes",
          "[confined_fs]") {
    DeleteLimits limits = kOpenLimits;
    limits.max_bytes = 100;
    WalkTally tally{0, 0};

    Decision big = decide_entry(regular_file(500), limits, tally, false, false, true);
    REQUIRE(big.action == Action::SkipEntry);
    REQUIRE(big.reason == Reason::ByteCap);

    // Tally is unaffected by a skipped file (the walker only advances
    // bytes_deleted on success) -- a smaller file that fits still deletes.
    Decision small = decide_entry(regular_file(50), limits, tally, false, false, true);
    REQUIRE(small.action == Action::Unlink);
}

TEST_CASE("decide_entry stops the walk on wall-time exhaustion", "[confined_fs]") {
    Decision d = decide_entry(regular_file(), kOpenLimits, WalkTally{}, /*deadline_exceeded=*/true,
                               false, true);
    REQUIRE(d.action == Action::StopWalk);
    REQUIRE(d.reason == Reason::WallTimeCap);
}

TEST_CASE("decide_entry skips a directory past the depth cap", "[confined_fs]") {
    EntryMeta meta{EntryType::Directory, 0, true};
    Decision d = decide_entry(meta, kOpenLimits, WalkTally{}, false, /*depth_exceeded=*/true, true);
    REQUIRE(d.action == Action::SkipEntry);
    REQUIRE(d.reason == Reason::DepthCap);
}

TEST_CASE("decide_entry recurses into a directory under the depth cap", "[confined_fs]") {
    EntryMeta meta{EntryType::Directory, 0, true};
    Decision d = decide_entry(meta, kOpenLimits, WalkTally{}, false, /*depth_exceeded=*/false, true);
    REQUIRE(d.action == Action::RecurseIntoDir);
    REQUIRE(d.reason == Reason::None);
}

TEST_CASE("decide_entry rejects a non-regular-file entry", "[confined_fs]") {
    EntryMeta meta{EntryType::Other, 0, true};
    Decision d = decide_entry(meta, kOpenLimits, WalkTally{}, false, false, true);
    REQUIRE(d.action == Action::SkipEntry);
    REQUIRE(d.reason == Reason::NotRegularFile);
}

TEST_CASE("decide_entry skips a name the caller's match filtered out", "[confined_fs]") {
    Decision d = decide_entry(regular_file(), kOpenLimits, WalkTally{}, false, false,
                               /*name_matched=*/false);
    REQUIRE(d.action == Action::SkipEntry);
    REQUIRE(d.reason == Reason::NameFilteredOut);
}

TEST_CASE("default-constructed DeleteLimits permits no deletion", "[confined_fs]") {
    DeleteLimits zero{}; // fail-closed default: max_entries == 0
    Decision d = decide_entry(regular_file(1), zero, WalkTally{}, false, false, true);
    REQUIRE(d.action != Action::Unlink);
    REQUIRE(d.action == Action::StopWalk);
    REQUIRE(d.reason == Reason::EntryCap);
}

TEST_CASE("rule order: entry cap beats a symlink discovered past it", "[confined_fs]") {
    DeleteLimits limits = kOpenLimits;
    limits.max_entries = 3;
    WalkTally tally{3, 0};
    EntryMeta symlink{EntryType::Symlink, 0, true};
    Decision d = decide_entry(symlink, limits, tally, false, false, true);
    REQUIRE(d.action == Action::StopWalk);
    REQUIRE(d.reason == Reason::EntryCap);
}

TEST_CASE("rule order: a filtered-out reparse entry still reports ReparseRejected",
          "[confined_fs]") {
    EntryMeta reparse{EntryType::Reparse, 0, true};
    Decision d = decide_entry(reparse, kOpenLimits, WalkTally{}, false, false,
                               /*name_matched=*/false);
    REQUIRE(d.action == Action::SkipEntry);
    REQUIRE(d.reason == Reason::ReparseRejected);
}

TEST_CASE("byte-cap overflow boundary: near-UINT64_MAX size never authorizes Unlink",
          "[confined_fs]") {
    DeleteLimits limits = kOpenLimits;
    limits.max_bytes = 100;
    WalkTally tally{0, 90}; // bytes_deleted near max_bytes

    EntryMeta huge{EntryType::RegularFile, std::numeric_limits<std::uint64_t>::max(), true};
    Decision d = decide_entry(huge, limits, tally, false, false, true);
    REQUIRE(d.action == Action::SkipEntry);
    REQUIRE(d.reason == Reason::ByteCap);
}

TEST_CASE("byte-cap overflow boundary: bytes_deleted already at max_bytes rejects any size",
          "[confined_fs]") {
    DeleteLimits limits = kOpenLimits;
    limits.max_bytes = 100;
    WalkTally tally{0, 100}; // exactly at the cap

    EntryMeta any_size{EntryType::RegularFile, 1, true};
    Decision d = decide_entry(any_size, limits, tally, false, false, true);
    REQUIRE(d.action == Action::SkipEntry);
    REQUIRE(d.reason == Reason::ByteCap);
}

TEST_CASE("byte-cap overflow boundary: bytes_deleted somehow past max_bytes still rejects",
          "[confined_fs]") {
    DeleteLimits limits = kOpenLimits;
    limits.max_bytes = 100;
    WalkTally tally{0, 150}; // defense-in-depth clause: bytes_deleted > max_bytes

    EntryMeta any_size{EntryType::RegularFile, 0, true};
    Decision d = decide_entry(any_size, limits, tally, false, false, true);
    REQUIRE(d.action == Action::SkipEntry);
    REQUIRE(d.reason == Reason::ByteCap);
}

TEST_CASE("byte-cap boundary: exact fit deletes", "[confined_fs]") {
    DeleteLimits limits = kOpenLimits;
    limits.max_bytes = 100;
    WalkTally tally{0, 40};

    EntryMeta exact_fit{EntryType::RegularFile, 60, true};
    Decision d = decide_entry(exact_fit, limits, tally, false, false, true);
    REQUIRE(d.action == Action::Unlink);
}
