/**
 * test_privacy_permissions_macos_internals.cpp -- TU-inclusion seam over
 * privacy_permissions_macos.cpp's internal-linkage `open_readonly` (K2/COD-FV-5, both external
 * code-review reviewers independently: the binding contract's single most important property --
 * a refused TCC.db open must never collapse into `absent` -- was proven only at the pure layer,
 * never against the real sqlite3_open_v2 call this leg actually makes).
 *
 * `open_readonly` now takes `db_path` as a parameter (default: the real TCC.db) specifically so
 * this test can force the exact open-failure branch deterministically, without a non-FDA
 * identity: sqlite3_open_v2 with SQLITE_OPEN_READONLY on a path that genuinely cannot be opened
 * (missing directory, permission-denied file) fails through the SAME generic path a real SIP/TCC
 * refusal would -- the leg's own comment on `collect_macos_permissions` states there is no
 * finer-grained code to distinguish them, so a deterministic "path absent" failure exercises
 * exactly the code a real denial exercises.
 *
 * #if defined(__APPLE__) guards the WHOLE body -- empty TU elsewhere, mirroring every other
 * Apple-only internals-seam test in this tree (test_autoruns_macos_local.cpp's #4241 seam is the
 * direct precedent this file copies).
 */
#if !defined(__APPLE__)

// Nothing to test off macOS -- see the file banner above.

#else // defined(__APPLE__)

#include <catch2/catch_test_macros.hpp>

#include <string>

// Direct source inclusion, macOS-only, mirroring autoruns_macos.cpp's
// YUZU_AUTORUNS_MACOS_UNIT_TEST_INTERNALS_ONLY seam (see that file's own banner, and
// YUZU_PRIVACY_PERMISSIONS_MACOS_UNIT_TEST_INTERNALS_ONLY's definition comment in
// privacy_permissions_macos.cpp): `open_readonly`, `DbHandle`, `decode_auth_value` and
// `kTccServices` all have internal (anonymous-namespace or file-static) linkage, so there is no
// header seam to reach them through otherwise. This TU never statically links the real plugin
// either way (test_privacy_permissions_local_dispatcher.cpp loads it via
// PluginHandle::load/dlopen at runtime), so a second compilation of the same free functions here
// creates no ODR/duplicate-symbol conflict.
// Excluding collect_macos_permissions leaves decode_auth_value/kTccServices/DbHandle's move
// assignment with no caller in THIS compilation of the TU -- real, used call sites in the actual
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
    std::string err_msg;
    auto db = open_readonly(err_msg, "/nonexistent/deliberately-broken/privacy_permissions_test.db");
    CHECK_FALSE(static_cast<bool>(db));
    CHECK_FALSE(err_msg.empty());
}

TEST_CASE("privacy_permissions macOS: open_readonly against the real TCC.db path succeeds on "
          "this FDA-granted host (corroborates the dispatcher test's success-path evidence)",
          "[privacy_permissions][macos][internals]") {
    std::string err_msg;
    auto db = open_readonly(err_msg);
    CHECK(static_cast<bool>(db));
}

TEST_CASE("privacy_permissions macOS: composing a real open_readonly failure through "
          "whole_read_failed_row/select_status -- the exact two-statement shape "
          "collect_macos_permissions's open-failure branch uses -- yields denied, never absent",
          "[privacy_permissions][macos][internals]") {
    yuzu::shared::ConstraintAccumulator acc;
    std::string err_msg;
    auto db = open_readonly(err_msg, "/nonexistent/deliberately-broken/privacy_permissions_test.db");
    REQUIRE_FALSE(static_cast<bool>(db));

    // Same call collect_macos_permissions's `if (!db) { ... }` branch makes, verbatim.
    const auto row = whole_read_failed_row("macos", PermissionState::denied,
                                           "tcc_db:open_failed:" + err_msg, acc, true);
    CHECK(row.state == PermissionState::denied);
    CHECK(row.read_denied);
    CHECK(row.raw.rfind("tcc_db:open_failed:", 0) == 0);

    const std::vector<PermissionRow> rows{row};
    const auto st = select_status(acc, any_denied(rows), false);
    CHECK(st.status == YUZU_RESULT_STATUS_PERMISSION_DENIED);
    CHECK(st.completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
}

} // namespace yuzu::privacy_permissions

#endif // defined(__APPLE__)
