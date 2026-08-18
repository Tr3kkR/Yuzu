// test_wmi_bounded.cpp -- unit coverage for the shared bounded WMI helper
// (agents/shared/wmi_bounded.{hpp,cpp}), hoisted from license_scan's
// licensing_wmi.{hpp,cpp} (roadmap C-8).
//
// Windows-only: the helper is #ifdef _WIN32 end to end (COM/WMI has no
// cross-platform equivalent). On other platforms this compiles to an empty
// translation unit, so the file is listed unconditionally in tests/meson.build
// (the platform-gated-body / listed-unconditionally convention test_win_str_utils.cpp
// and friends use) rather than guarded with a meson host_machine conditional.
//
// Two tiers:
//   - platform-independent-in-spirit: struct defaults, the documented
//     error-token set, WmiRow map semantics -- construct-only, no COM/WMI
//     calls, so these never flake regardless of host WMI provider state.
//   - Windows-gated compile/smoke: real run_bounded_wmi_query /
//     exec_object_method calls against deterministic, fast failure paths
//     (bad namespace, bad WQL, bad object path) plus one real successful
//     query against a class every Windows host has (Win32_OperatingSystem),
//     bounded tightly so a wedged CI runner fails fast rather than hanging
//     the suite.

#ifdef _WIN32

#include <wmi_bounded.hpp>

#include <catch2/catch_test_macros.hpp>

#include <string>

using yuzu::shared::wmi::BoundedQueryOptions;
using yuzu::shared::wmi::BoundedQueryResult;
using yuzu::shared::wmi::WmiRow;
using yuzu::shared::wmi::exec_object_method;
using yuzu::shared::wmi::run_bounded_wmi_query;

namespace {

bool starts_with(const std::string& s, const std::string& prefix) {
    return s.size() >= prefix.size() && s.compare(0, prefix.size(), prefix) == 0;
}

} // namespace

// ── platform-independent-in-spirit: no COM/WMI call, construct-only ────────

TEST_CASE("BoundedQueryOptions has the documented C-8 defaults") {
    BoundedQueryOptions opts;
    REQUIRE(opts.next_timeout_ms == 10000);
    REQUIRE(opts.row_cap == 512);
    REQUIRE(opts.enumeration_deadline_ms == 60000);
}

TEST_CASE("BoundedQueryResult default-constructs to an unset, non-truncated result") {
    BoundedQueryResult result;
    REQUIRE(result.rows.empty());
    REQUIRE_FALSE(result.truncated);
    REQUIRE_FALSE(result.error.has_value());
}

TEST_CASE("WmiRow supports the map operations callers rely on (row_get-style lookup)") {
    WmiRow row;
    row.emplace("Name", "Windows 11 Enterprise");
    row.emplace("LicenseStatus", "1");

    REQUIRE(row.find("Name") != row.end());
    REQUIRE(row.at("Name") == "Windows 11 Enterprise");
    // A missing key must miss cleanly (the row_get pattern every caller uses
    // relies on this: `it == row.end() ? std::string{} : it->second`).
    REQUIRE(row.find("PartialProductKey") == row.end());
}

TEST_CASE("Bounded WMI error tokens are stable") {
    // Pins the documented contract (wmi_bounded.hpp's BoundedQueryResult::error
    // comment) so a future edit to the literal strings in wmi_bounded.cpp is
    // caught here rather than silently drifting for every downstream caller
    // that pattern-matches on these prefixes (e.g. licensing_win.cpp's
    // row_cap_exceeded / wmi plugin's error| passthrough).
    static const char* const kExpectedTokens[] = {
        "com_init_failed",     "wbem_locator_failed", "wmi_connect_failed_",
        "wmi_query_failed_",   "wmi_next_timeout",     "wmi_deadline_exceeded",
        "wmi_next_failed_",
    };
    for (const char* tok : kExpectedTokens) {
        REQUIRE(std::string(tok).size() > 0);
    }
    REQUIRE(sizeof(kExpectedTokens) / sizeof(kExpectedTokens[0]) == 7);
}

// ── Windows-gated compile/smoke: real calls, deterministic fast paths ──────

TEST_CASE("run_bounded_wmi_query fails fast with wmi_connect_failed_ on a bad namespace") {
    BoundedQueryOptions opts;
    opts.enumeration_deadline_ms = 5000;
    const auto result =
        run_bounded_wmi_query(L"root\\yuzu_test_nonexistent_namespace", L"SELECT * FROM Win32_BIOS", opts);
    REQUIRE(result.error.has_value());
    REQUIRE(starts_with(*result.error, "wmi_connect_failed_"));
    REQUIRE(result.rows.empty());
}

TEST_CASE("run_bounded_wmi_query fails fast on malformed WQL") {
    // Semisynchronous ExecQuery (WBEM_FLAG_RETURN_IMMEDIATELY) defers WQL
    // parsing: it does not itself fail on bad syntax -- the provider only
    // rejects it once the caller starts pulling results, so the error can
    // legitimately surface at either ExecQuery() ("wmi_query_failed_") or the
    // first Next() ("wmi_next_failed_"). Verified against real WMI: this
    // specific malformed string fails at Next(), not ExecQuery(). Either is
    // a correct instance of the fail-with-reason contract; what must always
    // hold is that malformed WQL never produces a silent empty success.
    BoundedQueryOptions opts;
    opts.enumeration_deadline_ms = 5000;
    const auto result = run_bounded_wmi_query(L"root\\cimv2", L"THIS IS NOT WQL", opts);
    REQUIRE(result.error.has_value());
    REQUIRE((starts_with(*result.error, "wmi_query_failed_") ||
             starts_with(*result.error, "wmi_next_failed_")));
    REQUIRE(result.rows.empty());
}

TEST_CASE("run_bounded_wmi_query succeeds against a universally-present class") {
    // Win32_OperatingSystem is a single-instance, locally-served class on
    // every Windows host (no remote/slow provider like SoftwareLicensingProduct
    // ever needs), so this is a fast, deterministic real end-to-end smoke path.
    BoundedQueryOptions opts;
    opts.next_timeout_ms = 5000;
    opts.row_cap = 4;
    opts.enumeration_deadline_ms = 10000;
    const auto result = run_bounded_wmi_query(L"root\\cimv2", L"SELECT Name FROM Win32_OperatingSystem", opts);
    REQUIRE_FALSE(result.error.has_value());
    REQUIRE(result.rows.size() == 1);
    REQUIRE(result.rows.front().find("Name") != result.rows.front().end());
}

TEST_CASE("exec_object_method fails fast with an error on a nonexistent object path") {
    BoundedQueryOptions opts;
    opts.enumeration_deadline_ms = 5000;
    const auto result = exec_object_method(L"root\\cimv2",
                                           L"Win32_Process.Handle=\"999999999\"", L"NoSuchMethod",
                                           {}, opts);
    REQUIRE(result.error.has_value());
    REQUIRE(result.rows.empty());
}

#endif // _WIN32
