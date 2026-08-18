/**
 * test_sccm_parsers.cpp — pure decision-logic tests for the sccm plugin
 * (agents/plugins/sccm/src/sccm_plugin.cpp).
 *
 * The plugin's own copies of this logic are Windows-typed (DWORD/IID) and
 * live inside its `#ifdef _WIN32` block, so they cannot be included directly
 * into this cross-platform TU. These are MIRRORS — kept in sync, not shared
 * — using plain types instead, the same pattern test_new_plugins.cpp uses
 * for rdp_control_plugin.cpp's is_valid_rdp_state / classify_fw_hr (see
 * Section 7b there). Three functions are mirrored:
 *
 *   - classify_service_status: the client_version action's native SCM query
 *     outcome -> service_status|<value> mapping.
 *   - select_authority_subkey: the site action's Authority-subkey picker —
 *     the fix for the dead literal "SMS:{}" registry fallback.
 *   - interpret_sms_invoke: the site action's late-bound
 *     IDispatch::Invoke result interpretation for the Microsoft.SMS.Client
 *     GetAssignedSite / GetCurrentManagementPoint calls.
 */

#include <catch2/catch_test_macros.hpp>

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace {

// ── Mirror of sccm_plugin.cpp: SvcOpenResult / classify_service_status —
// keep in sync. `state` uses the real SERVICE_RUNNING (4) / SERVICE_STOPPED
// (1) numeric values so the fixtures below double as documentation of the
// Win32 contract, without pulling in <windows.h> for this cross-platform TU.
enum class TestSvcOpenResult { ScmUnavailable, NotFound, OpenFailed, Opened };

std::string_view test_classify_service_status(TestSvcOpenResult open_result, bool query_ok,
                                               unsigned long state) {
    switch (open_result) {
    case TestSvcOpenResult::ScmUnavailable:
    case TestSvcOpenResult::OpenFailed:
        return "unavailable";
    case TestSvcOpenResult::NotFound:
        return "not_found";
    case TestSvcOpenResult::Opened:
        break;
    }
    if (!query_ok)
        return "unavailable";
    if (state == 4) // SERVICE_RUNNING
        return "running";
    if (state == 1) // SERVICE_STOPPED
        return "stopped";
    return "exists";
}

// Mirror of sccm_plugin.cpp: select_authority_subkey — keep in sync.
std::optional<std::string> test_select_authority_subkey(const std::vector<std::string>& subkeys,
                                                         std::string_view site_code) {
    if (!site_code.empty()) {
        const std::string exact = "SMS:" + std::string(site_code);
        for (const auto& k : subkeys) {
            if (k == exact)
                return k;
        }
    }
    for (const auto& k : subkeys) {
        if (k.rfind("SMS:", 0) == 0)
            return k;
    }
    return std::nullopt;
}

// Mirror of sccm_plugin.cpp: SmsInvokeOutcome / SmsInvokeResult /
// interpret_sms_invoke — keep in sync.
enum class TestSmsInvokeOutcome { Ok, Failed, WrongType };

struct TestSmsInvokeResult {
    TestSmsInvokeOutcome outcome = TestSmsInvokeOutcome::Failed;
    std::string value;
};

TestSmsInvokeResult test_interpret_sms_invoke(bool succeeded, bool is_bstr,
                                              std::string bstr_utf8) {
    if (!succeeded)
        return {TestSmsInvokeOutcome::Failed, {}};
    if (!is_bstr)
        return {TestSmsInvokeOutcome::WrongType, {}};
    return {TestSmsInvokeOutcome::Ok, std::move(bstr_utf8)};
}

} // namespace

// ============================================================================
// classify_service_status
// ============================================================================

TEST_CASE("sccm: service_status running/stopped map from the real state codes",
          "[plugins][sccm][validation]") {
    CHECK(test_classify_service_status(TestSvcOpenResult::Opened, true, 4) == "running");
    CHECK(test_classify_service_status(TestSvcOpenResult::Opened, true, 1) == "stopped");
}

TEST_CASE("sccm: service_status exists for any other live state",
          "[plugins][sccm][validation]") {
    // SERVICE_START_PENDING=2, SERVICE_STOP_PENDING=3, SERVICE_CONTINUE_PENDING=5,
    // SERVICE_PAUSE_PENDING=6, SERVICE_PAUSED=7 -- none are RUNNING/STOPPED.
    CHECK(test_classify_service_status(TestSvcOpenResult::Opened, true, 2) == "exists");
    CHECK(test_classify_service_status(TestSvcOpenResult::Opened, true, 7) == "exists");
}

TEST_CASE("sccm: service_status not_found only for a confirmed absent service",
          "[plugins][sccm][validation]") {
    CHECK(test_classify_service_status(TestSvcOpenResult::NotFound, false, 0) == "not_found");
}

TEST_CASE("sccm: service_status unavailable for every other failure mode "
          "(never silently collapsed into not_found)",
          "[plugins][sccm][validation]") {
    // SCM connect itself failed (e.g. a hardened/locked-down host).
    CHECK(test_classify_service_status(TestSvcOpenResult::ScmUnavailable, false, 0) ==
          "unavailable");
    // OpenServiceW failed for a reason OTHER than "does not exist" (e.g.
    // access denied) -- must NOT be reported as not_found, which would
    // falsely claim the service isn't installed.
    CHECK(test_classify_service_status(TestSvcOpenResult::OpenFailed, false, 0) == "unavailable");
    // The service opened but the status query itself failed.
    CHECK(test_classify_service_status(TestSvcOpenResult::Opened, false, 0) == "unavailable");
}

// ============================================================================
// select_authority_subkey — the "{}" registry bug fix
// ============================================================================

TEST_CASE("sccm: authority subkey — exact site-code match preferred",
          "[plugins][sccm][validation]") {
    std::vector<std::string> subkeys{"SMS:ABC", "SomeOtherKey"};
    auto picked = test_select_authority_subkey(subkeys, "ABC");
    REQUIRE(picked.has_value());
    CHECK(*picked == "SMS:ABC");
}

TEST_CASE("sccm: authority subkey — falls back to the first SMS:-prefixed "
          "subkey when the site code is unknown",
          "[plugins][sccm][validation]") {
    std::vector<std::string> subkeys{"SMS:ABC", "SomeOtherKey"};
    auto picked = test_select_authority_subkey(subkeys, "");
    REQUIRE(picked.has_value());
    CHECK(*picked == "SMS:ABC");
}

TEST_CASE("sccm: authority subkey — exact match wins over first-found "
          "when multiple SMS:* subkeys exist",
          "[plugins][sccm][validation]") {
    std::vector<std::string> subkeys{"SMS:XYZ", "SMS:ABC"};
    auto picked = test_select_authority_subkey(subkeys, "ABC");
    REQUIRE(picked.has_value());
    CHECK(*picked == "SMS:ABC"); // not SMS:XYZ, despite being first
}

TEST_CASE("sccm: authority subkey — first-found wins among multiple SMS:* "
          "matches when no site code is available",
          "[plugins][sccm][validation]") {
    std::vector<std::string> subkeys{"SMS:XYZ", "SMS:ABC"};
    auto picked = test_select_authority_subkey(subkeys, "");
    REQUIRE(picked.has_value());
    CHECK(*picked == "SMS:XYZ"); // deterministic: first encountered
}

TEST_CASE("sccm: authority subkey — a mismatched site code falls back to "
          "first-found rather than failing closed",
          "[plugins][sccm][validation]") {
    std::vector<std::string> subkeys{"SMS:XYZ", "SMS:ABC"};
    auto picked = test_select_authority_subkey(subkeys, "QQQ");
    REQUIRE(picked.has_value());
    CHECK(*picked == "SMS:XYZ");
}

TEST_CASE("sccm: authority subkey — zero matches returns nullopt",
          "[plugins][sccm][validation]") {
    std::vector<std::string> subkeys{"Foo", "Bar"};
    CHECK_FALSE(test_select_authority_subkey(subkeys, "ABC").has_value());
    CHECK_FALSE(test_select_authority_subkey({}, "ABC").has_value());
}

// ============================================================================
// interpret_sms_invoke
// ============================================================================

TEST_CASE("sccm: sms invoke — a successful BSTR result is passed through",
          "[plugins][sccm][validation]") {
    auto r = test_interpret_sms_invoke(true, true, "ABC");
    CHECK(r.outcome == TestSmsInvokeOutcome::Ok);
    CHECK(r.value == "ABC");
}

TEST_CASE("sccm: sms invoke — any failed HRESULT in the chain is 'failed', "
          "regardless of the VARIANT type flag",
          "[plugins][sccm][validation]") {
    // CLSIDFromProgID / CoCreateInstance / GetIDsOfNames / Invoke all funnel
    // through the same succeeded=false path in the plugin.
    auto r = test_interpret_sms_invoke(false, false, {});
    CHECK(r.outcome == TestSmsInvokeOutcome::Failed);
    CHECK(r.value.empty());
    // A stray true is_bstr must not override a failed round trip.
    auto r2 = test_interpret_sms_invoke(false, true, "should be ignored");
    CHECK(r2.outcome == TestSmsInvokeOutcome::Failed);
    CHECK(r2.value.empty());
}

TEST_CASE("sccm: sms invoke — a successful call with a non-BSTR VARIANT is "
          "'wrong_type', not silently treated as success",
          "[plugins][sccm][validation]") {
    auto r = test_interpret_sms_invoke(true, false, {});
    CHECK(r.outcome == TestSmsInvokeOutcome::WrongType);
    CHECK(r.value.empty());
}
