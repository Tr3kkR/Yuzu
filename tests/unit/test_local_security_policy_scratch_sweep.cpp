/**
 * Pure decisions behind the local_security_policy Windows leg (sweep selection,
 * secedit run/read classification). Unguarded, every OS, no spawn,
 * sleep or disk. Expectations are pinned literals; each group names the
 * mutation it fails under. The Win32/confined_fs shell is exercised on the rig.
 */

#include "local_security_policy_scratch_sweep.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <optional>
#include <string>

using namespace yuzu::local_security_policy;

namespace {
constexpr std::int64_t kMtime = 1'700'000'000;
constexpr const char* kName = "local_security_policy-0123456789abcdef0123456789abcdef";
} // namespace

// Fails if: the prefix literal changes, the 32-hex length becomes >=/<=, hex
// validation is dropped or made case-sensitive, or a suffix is tolerated.
TEST_CASE("is_scratch_dir_name: exact prefix + 32 hex only", "[local_security_policy][sweep]") {
    CHECK(is_scratch_dir_name(kName));
    CHECK(is_scratch_dir_name("local_security_policy-0123456789ABCDEF0123456789abcdef"));
    CHECK_FALSE(is_scratch_dir_name("local_security_policy-0123456789abcdef0123456789abcde"));
    CHECK_FALSE(is_scratch_dir_name("local_security_policy-0123456789abcdef0123456789abcdef0"));
    CHECK_FALSE(is_scratch_dir_name("local_security_policy-0123456789abcdefg123456789abcdef"));
    CHECK_FALSE(is_scratch_dir_name("execution_artifacts-0123456789abcdef0123456789abcdef"));
    CHECK_FALSE(is_scratch_dir_name("local_security_policy-0123456789abcdef0123456789abcdef/"));
    CHECK_FALSE(is_scratch_dir_name(""));
    CHECK(kScratchDirPrefix == "local_security_policy-");
}

// Fails if: the comparison becomes >=, an absolute value is taken, or the
// threshold constant changes from 3600.
TEST_CASE("is_stale: strictly greater than one hour; equal and future-dated are fresh",
          "[local_security_policy][sweep]") {
    CHECK(kScratchDirStaleAfterSecs == 3600);
    CHECK_FALSE(is_stale(kMtime, kMtime + 3600, 3600));
    CHECK(is_stale(kMtime, kMtime + 3601, 3600));
    CHECK_FALSE(is_stale(kMtime, kMtime - 10, 3600));
}

// Fails if: a non-directory or wrongly named entry is ever a candidate, a
// missing mtime is read as old, or the fresh/stale split is inverted.
TEST_CASE("classify_sweep_candidate: only stale, directory, correctly named entries qualify",
          "[local_security_policy][sweep]") {
    const std::int64_t now = kMtime + 7200;
    CHECK(classify_sweep_candidate(kName, true, kMtime, now, 3600) == SweepCandidate::Stale);
    CHECK(classify_sweep_candidate(kName, true, kMtime + 7000, now, 3600) == SweepCandidate::Fresh);
    CHECK(classify_sweep_candidate(kName, true, std::nullopt, now, 3600) == SweepCandidate::NoMtime);
    CHECK(classify_sweep_candidate(kName, false, kMtime, now, 3600) == SweepCandidate::NotCandidate);
    CHECK(classify_sweep_candidate("decoy", true, kMtime, now, 3600) == SweepCandidate::NotCandidate);
}

// Fails if: a directory owned by another SID is ever removable.
TEST_CASE("sweep_may_remove: a foreign-owned directory is never removed",
          "[local_security_policy][sweep]") {
    CHECK(sweep_may_remove(true));
    CHECK_FALSE(sweep_may_remove(false));
}

// Fails if: the summary shape, or which outcomes count as skipped, changes.
TEST_CASE("format_sweep_summary: removed/skipped, skipped = every non-removed outcome",
          "[local_security_policy][sweep]") {
    ScratchSweepResult r;
    r.removed = 2;
    r.skipped_fresh = 1;
    r.skipped_not_ours = 3;
    r.failed = 4;
    r.deferred = 5;
    CHECK(format_sweep_summary(r) == "scratch_sweep:2/13");
}

// Fails if: any run outcome other than a clean zero exit reads as success, or a
// token spelling changes (the tokens are the wire contract).
TEST_CASE("classify_export_run: only Exited with code 0 is success",
          "[local_security_policy][secedit]") {
    CHECK(classify_export_run(RunEnd::Exited, 0).empty());
    CHECK(classify_export_run(RunEnd::Exited, 1) == "secedit:exit_1");
    CHECK(classify_export_run(RunEnd::Exited, 5) == "secedit:exit_5");
    CHECK(classify_export_run(RunEnd::SpawnError, 0) == "secedit:spawn_error");
    CHECK(classify_export_run(RunEnd::Deadline, 0) == "secedit:timeout");
    CHECK(classify_export_run(RunEnd::Cancelled, 0) == "secedit:cancelled");
    CHECK(classify_export_run(RunEnd::Signaled, -1) == "secedit:signaled");
    CHECK(classify_export_run(RunEnd::Other, 0) == "secedit:unexpected_termination");
}

// Fails if: ERROR_ACCESS_DENIED stops being PERMISSION_DENIED, a missing file
// reads as anything but its own token, or another error loses its number.
TEST_CASE("classify_export_read_error: denied vs missing vs other",
          "[local_security_policy][secedit]") {
    const auto denied = classify_export_read_error(5);
    CHECK(denied.permission_denied);
    CHECK(denied.token == "secedit:access_denied");
    for (const unsigned long missing : {2ul, 3ul}) {
        const auto r = classify_export_read_error(missing);
        CHECK_FALSE(r.permission_denied);
        CHECK(r.token == "secedit:output_missing");
    }
    const auto other = classify_export_read_error(32);
    CHECK_FALSE(other.permission_denied);
    CHECK(other.token == "secedit:read_32");
    CHECK(kExportMaxBytes == 1048576);
    CHECK(kExportDeadlineMs == 30000);
}

// Fails under: a shape decision drifting back into the leg TU, where nothing off
// Windows can observe it. These three tokens are as much of the documented wire
// contract as the three above; they were the ones minted inline in read_export
// and collect_windows_policy, so no OS tested them.
TEST_CASE("classify_export_object: a reparse point or an oversized export is refused",
          "[local_security_policy][secedit]") {
    CHECK_FALSE(classify_export_object(false, 0).has_value());           // empty but well-shaped
    CHECK_FALSE(classify_export_object(false, kExportMaxBytes).has_value()); // exactly at the cap
    const auto not_regular = classify_export_object(true, 10);
    REQUIRE(not_regular.has_value());
    CHECK_FALSE(not_regular->permission_denied);
    CHECK(not_regular->token == "secedit:output_not_regular");
    const auto oversized = classify_export_object(false, kExportMaxBytes + 1);
    REQUIRE(oversized.has_value());
    CHECK_FALSE(oversized->permission_denied);
    CHECK(oversized->token == "secedit:output_oversized");
    // Shape is decided before size: a reparse point is refused as such whatever it measures.
    REQUIRE(classify_export_object(true, kExportMaxBytes + 1).has_value());
    CHECK(classify_export_object(true, kExportMaxBytes + 1)->token == "secedit:output_not_regular");
}

TEST_CASE("classify_export_read_length: a prefix of the export is never a complete one",
          "[local_security_policy][secedit]") {
    CHECK(classify_export_read_length(0, 0).empty());
    CHECK(classify_export_read_length(1274, 1274).empty());
    CHECK(classify_export_read_length(1274, 1273) == "secedit:output_short_read");
    CHECK(classify_export_read_length(1274, 0) == "secedit:output_short_read");
}

TEST_CASE("classify_decoded_export: a failed decode and an empty one are the same answer",
          "[local_security_policy][secedit]") {
    CHECK(classify_decoded_export(std::string{"[System Access]\r\n"}).empty());
    CHECK(classify_decoded_export(std::nullopt) == "secedit:decode_failed");
    CHECK(classify_decoded_export(std::string{}) == "secedit:decode_failed"); // a real export is never empty
}
