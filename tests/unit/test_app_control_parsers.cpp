/**
 * test_app_control_parsers.cpp -- pure tests for the app_control plugin's
 * mappers, row formatters, CIM namespace floor and fixture-dump parsers. Runs
 * on every OS: nothing here touches the registry, WMI or a process.
 *
 * The [capture] cases read REAL CAPTURES from the-rig
 * (tests/unit/fixtures/wave8/app_control/windows/<capture>.txt, each with a
 * .provenance.txt) and REQUIRE they exist -- never a hand-invented fixture.
 * Malformed / empty inputs and the CIM-present shape are inline reconstructions (the latter
 * labelled ASSUMED SHAPE: no AppLocker-configured host has been captured).
 */
#include <catch2/catch_test_macros.hpp>

#include "../../agents/plugins/app_control/src/app_control_parsers.hpp"

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <limits>
#include <sstream>
#include <string>
#include <system_error>
#include <unordered_set>
#include <vector>

namespace fs = std::filesystem;
using namespace yuzu::app_control;

namespace {

#ifndef YUZU_TEST_FIXTURE_DIR
#define YUZU_TEST_FIXTURE_DIR "tests/unit/fixtures"
#endif

std::string read_capture(const std::string& name) {
    const auto path = fs::path{YUZU_TEST_FIXTURE_DIR} / "wave8" / "app_control" / "windows" / name;
    INFO("fixture path: " << path.string());
    REQUIRE(fs::exists(path));
    REQUIRE(fs::exists(fs::path{path.string() + ".provenance.txt"}));
    std::ifstream f(path, std::ios::binary);
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

std::vector<std::string> split_fields(const std::string& row) {
    std::vector<std::string> f{1};
    for (char c : row) {
        if (c == '|')
            f.emplace_back();
        else
            f.back().push_back(c);
    }
    return f;
}

// Every PolicyState name, plus the row layer's `absent` (an optional, not a mapper output).
const std::unordered_set<std::string> kStateVocab = [] {
    std::unordered_set<std::string> vocab{"absent"};
    for (const auto s : {PolicyState::disabled, PolicyState::audit, PolicyState::enforced,
                         PolicyState::unmodelled})
        vocab.emplace(policy_state_name(s));
    return vocab;
}();
constexpr auto kMax = std::numeric_limits<std::uint32_t>::max();

// ASSUMED SHAPE, not a capture: property names per app_control_win.cpp's banner, unverified on
// hardware (no AppLocker-configured host has been captured).
const WmiRow kAssumedCimRow{{"Collection", "Exe"}, {"EnforcementMode", "1"}, {"RuleCount", "4"}};

} // namespace

TEST_CASE("app_control mappers: every value maps to a named state, unmodelled is distinct",
          "[app_control][parsers]") {
    CHECK(map_ci_policy_state(0) == PolicyState::disabled);
    CHECK(map_ci_policy_state(1) == PolicyState::enforced);
    CHECK(map_ci_policy_state(2) == PolicyState::audit);
    CHECK(map_enforcement_mode(0) == PolicyState::audit);
    CHECK(map_enforcement_mode(1) == PolicyState::enforced);
    for (const auto raw : {3u, kMax}) {
        CHECK(map_ci_policy_state(raw) == PolicyState::unmodelled);
        CHECK(map_enforcement_mode(raw) == PolicyState::unmodelled);
    }
    CHECK(map_enforcement_mode(2) == PolicyState::unmodelled);
}

TEST_CASE("app_control rows: wdac / cip / applocker / unsupported / constrained shapes",
          "[app_control][parsers]") {
    RegValueView v;
    v.name = "VerifiedAndReputablePolicyState";
    v.kind = RegValueKind::u32;
    v.u32 = 2;
    CHECK(format_wdac_row(v) == "wdac|VerifiedAndReputablePolicyState|2|audit");
    v.u32 = 9;
    CHECK(format_wdac_row(v) == "wdac|VerifiedAndReputablePolicyState|9|unmodelled");
    v.name = "SomethingElse"; // a 32-bit value the plugin does not model is never mapped
    v.u32 = 1;
    CHECK(format_wdac_row(v) == "wdac|SomethingElse|1|unmodelled");
    v.kind = RegValueKind::text; // untrusted text: newlines fold to spaces, backslash to '/'
    v.text = "C:\\a\r\nb";
    CHECK(format_wdac_row(v) == "wdac|SomethingElse|C:/a  b|unmodelled");
    v.kind = RegValueKind::other;
    v.byte_len = 12;
    CHECK(format_wdac_row(v) == "wdac|SomethingElse|opaque_12B|unmodelled");
    CHECK(format_wdac_key_absent_row() == "wdac|policy_key|-|absent");

    CHECK(is_cip_filename("{1234-ABCD}.cip"));
    CHECK(is_cip_filename("POLICY.CIP"));
    for (const char* n : {".cip", "policy.cip.bak", "policy.p7b", ""})
        CHECK_FALSE(is_cip_filename(n));
    CHECK(format_cip_row("{1234-ABCD}.cip") == "wdac_cip|{1234-ABCD}|present");
    CHECK(format_cip_none_row() == "wdac_cip|none|absent");

    CHECK(format_applocker_row("Exe", 1, 12) == "applocker|Exe|enforced|12");
    CHECK(format_applocker_row("Dll", 0, 0) == "applocker|Dll|audit|0");
    CHECK(format_applocker_row("Msi", 7, 3) == "applocker|Msi|unmodelled|3");
    CHECK(format_applocker_row("Script", std::nullopt, 5) == "applocker|Script|absent|5");
    CHECK(format_applocker_row("a|b", 1, 0) == "applocker|a\\|b|enforced|0"); // pipe escaped
    CHECK(format_applocker_none_row() == "applocker|none|absent|0");

    CHECK(format_unsupported_row("wdac_policy") == "wdac_policy|unsupported|windows_only_concept");
    CHECK(format_constrained_row("permission_denied,row_cap") ==
          "constrained|permission_denied,row_cap");
}

TEST_CASE("app_control CipScan: absent is definitive, a failed read never reads as absent",
          "[app_control][parsers][cip]") {
    const auto ec_of = [](std::errc e) { return std::make_error_code(e); };
    yuzu::shared::ConstraintAccumulator acc;
    bool denied = false;
    CipScan scan{acc, denied};

    SECTION("an existing directory that held nothing is a definitive none") {
        scan.finish({});
        CHECK(scan.none_row_due());
        CHECK(scan.names().empty());
        CHECK_FALSE(acc.any_failure());
    }
    SECTION("a missing directory is a definitive none, not a failure") {
        scan.finish(ec_of(std::errc::no_such_file_or_directory));
        CHECK(scan.none_row_due());
        CHECK_FALSE(acc.any_failure());
        CHECK_FALSE(denied);
    }
    SECTION("only regular .cip leaves are kept, sorted; other entries are ignored") {
        CHECK(scan.observe("{B}.cip", true, {}));
        CHECK(scan.observe("{A}.CIP", true, {}));
        CHECK(scan.observe("notes.txt", true, {}));
        CHECK(scan.observe("{C}.cip", false, {})); // a directory named like a policy
        scan.finish({});
        CHECK_FALSE(scan.none_row_due());
        CHECK(scan.names() == std::vector<std::string>{"{A}.CIP", "{B}.cip"});
        CHECK_FALSE(acc.any_failure());
    }
    SECTION("a failed stat is a failure and suppresses the absent row") {
        CHECK(scan.observe("{A}.cip", false, ec_of(std::errc::io_error)));
        scan.finish({});
        CHECK_FALSE(scan.none_row_due());
        CHECK(acc.any_failure());
        CHECK(acc.reason() == "cip_stat_failed_" + std::to_string(ec_of(std::errc::io_error).value()));
        CHECK_FALSE(denied);
    }
    SECTION("a permission-refused stat reaches the denied flag") {
        CHECK(scan.observe("{A}.cip", false, ec_of(std::errc::permission_denied)));
        scan.finish({});
        CHECK_FALSE(scan.none_row_due());
        CHECK(denied);
        CHECK(acc.reason() == "permission_denied");
    }
    SECTION("an iterator failure is a failure; permission refusal is denied") {
        scan.finish(ec_of(std::errc::io_error));
        CHECK_FALSE(scan.none_row_due());
        CHECK(acc.any_failure());
        CHECK_FALSE(denied);

        yuzu::shared::ConstraintAccumulator acc2;
        bool denied2 = false;
        CipScan refused{acc2, denied2};
        refused.finish(ec_of(std::errc::permission_denied));
        CHECK_FALSE(refused.none_row_due());
        CHECK(denied2);
    }
    SECTION("a directory that vanishes after entries were seen is a failure, not an absence") {
        CHECK(scan.observe("{A}.cip", true, {}));
        scan.finish(ec_of(std::errc::no_such_file_or_directory));
        CHECK(acc.any_failure());
        CHECK_FALSE(scan.none_row_due());
    }
    SECTION("the row cap stops the scan and records row_cap") {
        for (std::size_t i = 0; i < kMaxCipFiles; ++i)
            REQUIRE(scan.observe("{P" + std::to_string(i) + "}.cip", true, {}));
        CHECK_FALSE(scan.observe("{extra}.cip", true, {}));
        scan.finish({});
        CHECK(scan.names().size() == kMaxCipFiles);
        CHECK(acc.reason() == "row_cap");
    }
}

TEST_CASE("app_control win32 reads: absent is definitive, a failed read never reads as absent",
          "[app_control][parsers]") {
    // app_control_win.cpp static_asserts these against winerror.h; pinned here on every OS.
    CHECK(kErrorSuccess == 0u);      // ERROR_SUCCESS
    CHECK(kErrorFileNotFound == 2u); // ERROR_FILE_NOT_FOUND
    CHECK(kErrorPathNotFound == 3u); // ERROR_PATH_NOT_FOUND
    CHECK(kErrorAccessDenied == 5u); // ERROR_ACCESS_DENIED

    for (const auto err : {kErrorFileNotFound, kErrorPathNotFound}) {
        const auto f = classify_win32_read("ci_policy_open", err, ReadKind::open_or_query);
        INFO("err=" << err);
        CHECK(f.state == RegRead::absent);
        CHECK(f.token.empty()); // an absence is no failure: the run stays OK / FULL
        CHECK_FALSE(f.access_denied);
    }
    for (const auto kind : {ReadKind::open_or_query, ReadKind::enumerate}) {
        const auto d = classify_win32_read("ci_policy_open", kErrorAccessDenied, kind);
        CHECK(d.state == RegRead::unreadable);
        CHECK(d.token == "permission_denied");
        CHECK(d.access_denied);
    }
    CHECK(classify_win32_read("x", kErrorSuccess, ReadKind::open_or_query).state == RegRead::ok);
    CHECK(classify_win32_read("x", kErrorSuccess, ReadKind::enumerate).state == RegRead::ok);

    // Any other error is unreadable with exactly one token: lowercase hex, no padding.
    const struct {
        const char* what;
        std::uint32_t err;
        const char* token;
    } others[] = {{"enforcement_mode_read", 13, "enforcement_mode_read_0xd"},
                  {"ci_policy_enum", 234, "ci_policy_enum_0xea"},
                  {"srpv2_open", 1450, "srpv2_open_0x5aa"}};
    for (const auto& o : others) {
        const auto f = classify_win32_read(o.what, o.err, ReadKind::open_or_query);
        INFO("err=" << o.err);
        CHECK(f.state == RegRead::unreadable);
        CHECK(f.token == o.token);
        CHECK_FALSE(f.access_denied);
    }
    // Mid-enumeration a NOT_FOUND is a failure, never a silent early stop.
    for (const auto err : {kErrorFileNotFound, kErrorPathNotFound}) {
        const auto f = classify_win32_read("ci_policy_enum", err, ReadKind::enumerate);
        INFO("err=" << err);
        CHECK(f.state == RegRead::unreadable);
        CHECK(f.token == "ci_policy_enum_0x" + std::to_string(err));
        CHECK_FALSE(f.access_denied);
    }
    // Absent and unreadable never share a state, and only the failure carries a token.
    const auto absent = classify_win32_read("k", kErrorFileNotFound, ReadKind::open_or_query);
    const auto failed = classify_win32_read("k", kErrorAccessDenied, ReadKind::open_or_query);
    CHECK(absent.state != failed.state);
    CHECK(absent.token.empty());
    CHECK_FALSE(failed.token.empty());
}

TEST_CASE("app_control verdict: any recorded failure is never OK / FULL / rc 0",
          "[app_control][parsers]") {
    yuzu::shared::ConstraintAccumulator none;
    const auto ok = select_verdict(none, false, "registry_ci_policy");
    CHECK(ok.status == YUZU_RESULT_STATUS_OK);
    CHECK(ok.completeness == YUZU_RESULT_COMPLETENESS_FULL);
    CHECK(ok.provenance == "registry_ci_policy");
    CHECK(ok.rc == 0);
    CHECK_FALSE(ok.constrained_row_due);

    yuzu::shared::ConstraintAccumulator capped;
    capped.add_failure("row_cap");
    const auto c = select_verdict(capped, false, "registry_ci_policy");
    CHECK(c.status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(c.completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(c.provenance == "row_cap");
    CHECK(c.rc == 1);
    CHECK(c.constrained_row_due);

    yuzu::shared::ConstraintAccumulator refused;
    refused.add_failure("permission_denied");
    const auto d = select_verdict(refused, true, "registry_ci_policy");
    CHECK(d.status == YUZU_RESULT_STATUS_PERMISSION_DENIED);
    CHECK(d.completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(d.provenance == "permission_denied");
    CHECK(d.rc == 1);
    CHECK(d.constrained_row_due);

    // A classified failed read flows through to the verdict unchanged.
    yuzu::shared::ConstraintAccumulator acc;
    const auto f = classify_win32_read("ci_policy_enum", 234, ReadKind::enumerate);
    acc.add_failure(f.token);
    CHECK(select_verdict(acc, f.access_denied, "registry_ci_policy").provenance ==
          "ci_policy_enum_0xea");
}

TEST_CASE("app_control CIM floor: only the one allowlisted namespace passes",
          "[app_control][parsers]") {
    CHECK(is_allowed_cim_namespace(kCimNamespace));
    CHECK(is_allowed_cim_namespace("ROOT\\standardcimv2\\security\\applicationcontrol"));
    for (const char* ns :
         {"", "root\\CIMV2", "root\\StandardCimv2", "root\\StandardCimv2\\Security",
          "root\\StandardCimv2\\Security\\ApplicationControl\\",
          "root\\StandardCimv2\\Security\\ApplicationControlX",
          "root\\CIMV2\\Security\\MicrosoftVolumeEncryption"})
        CHECK_FALSE(is_allowed_cim_namespace(ns));
}

TEST_CASE("app_control CIM error classification and row mapping", "[app_control][parsers]") {
    const auto cls = [](const char* t) { return classify_cim_error(std::string{t}); };
    CHECK(classify_cim_error(std::nullopt) == CimOutcome::ok);
    CHECK(cls("wmi_connect_failed_0x8004100e") == CimOutcome::class_absent);
    CHECK(cls("wmi_query_failed_0x80041010") == CimOutcome::class_absent);
    CHECK(cls("wmi_connect_failed_0x80041003") == CimOutcome::permission_denied);
    CHECK(cls("wmi_query_failed_0x80070005") == CimOutcome::permission_denied);
    for (const char* t : {"wmi_deadline_exceeded", "com_init_failed", "namespace_not_allowed"})
        CHECK(cls(t) == CimOutcome::failed);

    const auto p = parse_cim_applocker_row(kAssumedCimRow); // ASSUMED SHAPE, not a capture
    REQUIRE(p.has_value());
    CHECK(p->collection == "Exe");
    CHECK(p->mode == std::optional<std::uint32_t>{1});
    CHECK(p->rules == 4);
    CHECK(parse_cim_applocker_row(
              {{"collection", "Dll"}, {"enforcementmode", "0"}, {"rulecount", "0"}})
              .has_value());
    for (const WmiRow& bad : std::vector<WmiRow>{
             {},
             {{"Collection", "Exe"}, {"RuleCount", "1"}},
             {{"Collection", "Exe"}, {"EnforcementMode", "on"}, {"RuleCount", "1"}},
             {{"Collection", "Exe"}, {"EnforcementMode", "1"}, {"RuleCount", "-1"}},
             {{"Collection", ""}, {"EnforcementMode", "1"}, {"RuleCount", "1"}}})
        CHECK_FALSE(parse_cim_applocker_row(bad).has_value());

    CHECK(parse_u32("4294967295") == std::optional<std::uint32_t>{kMax});
    for (const char* s : {"4294967296", " 1", "1x", "-1", ""})
        CHECK_FALSE(parse_u32(s).has_value());
}

TEST_CASE("app_control CIM plan: every failure is recorded; SrpV2 runs unless a row mapped",
          "[app_control][parsers]") {
    const WmiRow bad{{"Collection", "Exe"}}; // lacks EnforcementMode and RuleCount

    const auto mixed = plan_cim(std::nullopt, {kAssumedCimRow, bad}, false);
    REQUIRE(mixed.rows.size() == 1);
    CHECK(mixed.rows[0].collection == "Exe");
    CHECK(mixed.rows[0].mode == std::optional<std::uint32_t>{1});
    CHECK(mixed.rows[0].rules == 4);
    CHECK(mixed.failures == std::vector<std::string>{"cim_row_unrecognised"});
    CHECK(mixed.use_cim);

    const auto only_bad = plan_cim(std::nullopt, {bad}, false);
    CHECK(only_bad.rows.empty());
    CHECK(only_bad.failures == std::vector<std::string>{"cim_row_unrecognised"});
    CHECK_FALSE(only_bad.use_cim); // nothing usable: the SrpV2 walk runs

    const auto capped = plan_cim(std::nullopt, {kAssumedCimRow}, true);
    CHECK(capped.failures == std::vector<std::string>{"row_cap"});
    CHECK(capped.use_cim);

    const auto denied = plan_cim(std::string{"wmi_connect_failed_0x80041003"}, {}, false);
    CHECK(denied.denied);
    CHECK(denied.failures == std::vector<std::string>{"permission_denied"});
    CHECK_FALSE(denied.use_cim);

    const auto deadline = plan_cim(std::string{"wmi_deadline_exceeded"}, {}, false);
    CHECK_FALSE(deadline.denied);
    CHECK(deadline.failures == std::vector<std::string>{"wmi_deadline_exceeded"});
    CHECK_FALSE(deadline.use_cim);

    const auto empty = plan_cim(std::nullopt, {}, false); // class present, no rules configured
    CHECK(empty.rows.empty());
    CHECK(empty.failures.empty());
    CHECK_FALSE(empty.denied);
    CHECK_FALSE(empty.use_cim);
}

TEST_CASE("app_control dump parsers: empty and malformed input record a failure, never throw",
          "[app_control][parsers]") {
    for (const char* bad : {"", "\n\r\n", "no tabs\n", "a\tu32\tnn\n", "a\tzzz\t1\n", "\tu32\t1\n",
                            "a\tu32\n", "a\tu32\t1\tx\n"}) {
        INFO("input: " << bad);
        const auto ci = parse_ci_policy_dump(bad);
        CHECK(ci.acc.any_failure());
        CHECK(ci.values.empty());
    }
    for (const char* bad : {"", "garbage\n", "=v\n"}) {
        INFO("input: " << bad);
        const auto w = parse_wmi_probe_dump(bad);
        CHECK(w.acc.any_failure());
        CHECK(w.rows.empty());
    }
    // A good line beside a bad one keeps the good row AND records the failure.
    const auto mixed = parse_ci_policy_dump("A\tu32\t1\nB\ttext\thi\nC\tother\t7\r\nbroken\n");
    CHECK(mixed.values.size() == 3);
    CHECK(mixed.values[2].byte_len == 7);
    CHECK(mixed.acc.reason() == "malformed_line");
    const auto w = parse_wmi_probe_dump("A=1\nB=2\n--\nA=3\nerror=x\n");
    CHECK(w.rows.size() == 2);
    CHECK(w.error == std::optional<std::string>{"x"});
}

TEST_CASE("app_control real capture: CI\\Policy values format to the rig's exact rows",
          "[app_control][parsers][capture]") {
    const auto dump = parse_ci_policy_dump(read_capture("ci_policy_values.txt"));
    CHECK_FALSE(dump.acc.any_failure());
    std::vector<std::string> rows;
    for (const auto& v : dump.values) {
        rows.push_back(format_wdac_row(v));
        const auto f = split_fields(rows.back());
        REQUIRE(f.size() == 4);
        CHECK(f[0] == "wdac");
        CHECK(kStateVocab.contains(f[3]));
    }
    // Literal rows in capture order, never recomputed with the mapper under test.
    CHECK(rows == std::vector<std::string>{"wdac|EmodePolicyRequired|0|unmodelled",
                                           "wdac|SkuPolicyRequired|0|unmodelled",
                                           "wdac|VerifiedAndReputablePolicyState|0|disabled",
                                           "wdac|SAC_PreviousState|4294967295|unmodelled"});
}

TEST_CASE("app_control real capture: MSFT_ApplockerPolicy probe classifies and maps",
          "[app_control][parsers][capture]") {
    const auto probe = parse_wmi_probe_dump(read_capture("applocker_wmi_probe.txt"));
    CHECK_FALSE(probe.acc.any_failure());
    // The rig's answer: the namespace does not exist (WBEM_E_INVALID_NAMESPACE), no rows.
    CHECK(classify_cim_error(probe.error) == CimOutcome::class_absent);
    CHECK(probe.rows.empty());
    // The whole decision over that real answer: nothing recorded, the SrpV2 fallback selected.
    const auto plan = plan_cim(probe.error, probe.rows, false);
    CHECK(plan.rows.empty());
    CHECK(plan.failures.empty());
    CHECK_FALSE(plan.denied);
    CHECK_FALSE(plan.use_cim);
}
