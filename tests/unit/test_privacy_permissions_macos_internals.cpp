/**
 * test_privacy_permissions_macos_internals.cpp -- TU-inclusion seam over
 * privacy_permissions_macos.cpp's internal-linkage `open_readonly` (K2/COD-FV-5, both external
 * code-review reviewers independently: the binding contract's single most important property --
 * a refused TCC.db open must never collapse into `absent` -- was proven only at the pure layer,
 * never against the real sqlite3_open_v2 call this leg actually makes).
 *
 * `open_readonly` and `read_tcc_source` take the db path as a parameter (default: the real
 * TCC.db) specifically so this test can force each outcome branch deterministically, without a
 * non-FDA identity and without touching any real TCC.db: a missing per-user db must read
 * `absent`, a missing SYSTEM db `unreadable`, and a present-but-unopenable file (mode 000,
 * the same SQLITE_CANTOPEN an SIP/TCC refusal produces) `denied` -- never absent.
 *
 * #if defined(__APPLE__) guards the WHOLE body -- empty TU elsewhere, mirroring every other
 * Apple-only internals-seam test in this tree (test_autoruns_macos_local.cpp's #4241 seam is the
 * direct precedent this file copies).
 */
#if !defined(__APPLE__)

// Nothing to test off macOS -- see the file banner above.

#else // defined(__APPLE__)

#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include <sys/stat.h>
#include <unistd.h>

#include "test_helpers.hpp"

// Direct source inclusion, macOS-only, mirroring autoruns_macos.cpp's
// YUZU_AUTORUNS_MACOS_UNIT_TEST_INTERNALS_ONLY seam (see that file's own banner, and
// YUZU_PRIVACY_PERMISSIONS_MACOS_UNIT_TEST_INTERNALS_ONLY's definition comment in
// privacy_permissions_macos.cpp): `open_readonly`, `read_tcc_source` and `DbHandle` have
// internal (anonymous-namespace) linkage, so there is no header seam to reach them through
// otherwise. This TU never statically links the real plugin either way
// (test_privacy_permissions_local_dispatcher.cpp loads it via PluginHandle::load/dlopen at
// runtime), so a second compilation of the same free functions here creates no ODR/duplicate-
// symbol conflict.
// Excluding collect_macos_permissions leaves enumerate_user_homes/DbHandle's move assignment
// with no caller in THIS compilation of the TU -- real, used call sites in the actual
// (non-test) build of this same file. -Wunused-function is non-fatal project-wide but is
// silenced narrowly here, scoped to just the include.
#define YUZU_PRIVACY_PERMISSIONS_MACOS_UNIT_TEST_INTERNALS_ONLY 1
#if defined(__clang__) || defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#endif
#include "../../agents/plugins/privacy_permissions/src/privacy_permissions_macos.cpp"
#if defined(__clang__) || defined(__GNUC__)
#pragma GCC diagnostic pop
#endif
#undef YUZU_PRIVACY_PERMISSIONS_MACOS_UNIT_TEST_INTERNALS_ONLY

namespace yuzu::privacy_permissions {

TEST_CASE("privacy_permissions macOS: open_readonly on a genuinely unopenable path fails "
          "through the same generic path a real TCC/SIP denial would, with a real "
          "sqlite3_errmsg diagnostic",
          "[privacy_permissions][macos][internals]") {
    std::optional<macos::SourceFailure> failure;
    auto db = open_readonly(failure, "/nonexistent/deliberately-broken/privacy_permissions_test.db");
    CHECK_FALSE(static_cast<bool>(db));
    REQUIRE(failure.has_value());
    CHECK(failure->cause.rfind("open_failed:", 0) == 0);
    CHECK(failure->cause.size() > std::string_view{"open_failed:"}.size());
    // A missing parent directory is SQLITE_CANTOPEN with ENOENT from the VFS -- not a refusal.
    CHECK(failure->outcome == macos::SourceOutcome::unreadable);
}

TEST_CASE("privacy_permissions macOS: read_tcc_source on a MISSING per-user db is one absent "
          "row with no token; a missing SYSTEM db is unreadable, never absent",
          "[privacy_permissions][macos][internals]") {
    const std::string missing =
        yuzu::test::unique_temp_path("yuzu_test_pp_missing_").string() + "/TCC.db";

    yuzu::shared::ConstraintAccumulator user_acc;
    std::vector<PermissionRow> user_rows;
    read_tcc_source("alice", missing, /*missing_is_absent=*/true, user_rows, user_acc);
    REQUIRE(user_rows.size() == 1);
    CHECK(format_row(user_rows[0]) == "permissions|macos|alice/-|-|absent|-|-|-");
    CHECK_FALSE(user_acc.any_failure());

    yuzu::shared::ConstraintAccumulator sys_acc;
    std::vector<PermissionRow> sys_rows;
    read_tcc_source({}, missing, /*missing_is_absent=*/false, sys_rows, sys_acc);
    REQUIRE(sys_rows.size() == 1);
    CHECK(sys_rows[0].state == PermissionState::unreadable);
    CHECK(sys_rows[0].raw == "tcc_db:missing");
    CHECK(select_status(sys_acc, any_denied(sys_rows), false).status ==
          YUZU_RESULT_STATUS_CONSTRAINED);
}

TEST_CASE("privacy_permissions macOS: read_tcc_source on a PRESENT file the process cannot open "
          "(mode 000 -- the same SQLITE_CANTOPEN a TCC refusal produces) is denied and promotes "
          "PERMISSION_DENIED, never absent",
          "[privacy_permissions][macos][internals]") {
    if (::geteuid() == 0) SKIP("root ignores mode 000 -- the refusal cannot be forced here");
    // Canonical: macOS's temp dir lives under the /var -> /private/var symlink, and
    // SQLITE_OPEN_NOFOLLOW refuses a symlink anywhere in the path (SQLITE_CANTOPEN_SYMLINK) --
    // this case must exercise the real EACCES refusal, not that one.
    const auto raw_path = yuzu::test::unique_temp_path("yuzu_test_pp_tcc_");
    const auto path = std::filesystem::canonical(raw_path.parent_path()) / raw_path.filename();
    { std::ofstream{path} << "x"; }
    REQUIRE(::chmod(path.c_str(), 0) == 0);

    yuzu::shared::ConstraintAccumulator acc;
    std::vector<PermissionRow> rows;
    read_tcc_source("alice", path.string(), /*missing_is_absent=*/true, rows, acc);
    ::chmod(path.c_str(), 0600);
    std::filesystem::remove(path);

    REQUIRE(rows.size() == 1);
    CHECK(rows[0].app_id == "alice\\-");
    CHECK(rows[0].state == PermissionState::denied);
    CHECK(rows[0].read_denied);
    CHECK(rows[0].raw.rfind("alice:tcc_db:open_failed:", 0) == 0);
    const auto st = select_status(acc, any_denied(rows), false);
    CHECK(st.status == YUZU_RESULT_STATUS_PERMISSION_DENIED);
    CHECK(st.completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
}

TEST_CASE("privacy_permissions macOS: read_tcc_source through a SYMLINKED directory is refused by "
          "SQLITE_OPEN_NOFOLLOW as unreadable (SQLITE_CANTOPEN_SYMLINK), never a false denied",
          "[privacy_permissions][macos][internals]") {
    yuzu::test::TempDir tmp{"yuzu_test_pp_link_"};
    std::filesystem::create_directories(tmp.path);
    const auto base = std::filesystem::canonical(tmp.path); // no symlink but the one below
    const auto real_dir = base / "real";
    const auto link_dir = base / "link";
    std::filesystem::create_directories(real_dir);
    std::filesystem::create_directory_symlink(real_dir, link_dir);
    { std::ofstream{real_dir / "TCC.db"} << "x"; }

    yuzu::shared::ConstraintAccumulator acc;
    std::vector<PermissionRow> rows;
    read_tcc_source("alice", (link_dir / "TCC.db").string(), /*missing_is_absent=*/true, rows, acc);

    REQUIRE(rows.size() == 1);
    CHECK(rows[0].state == PermissionState::unreadable);
    CHECK_FALSE(rows[0].read_denied);
    CHECK(rows[0].raw.rfind("alice:tcc_db:open_failed:", 0) == 0);
    CHECK(select_status(acc, any_denied(rows), false).status == YUZU_RESULT_STATUS_CONSTRAINED);
}

} // namespace yuzu::privacy_permissions

#endif // defined(__APPLE__)
