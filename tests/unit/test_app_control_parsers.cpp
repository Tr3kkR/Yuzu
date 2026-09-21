/**
 * test_app_control_parsers.cpp -- pure tests for the app_control plugin's
 * mappers, row formatters, CIM namespace floor and fixture-dump parsers. Runs
 * on every OS: nothing here touches the registry, WMI or a process.
 *
 * The [capture] cases read REAL CAPTURES from the-rig
 * (tests/unit/fixtures/wave8/app_control/windows/<capture>.txt, each with a
 * .provenance.txt) and REQUIRE they exist -- never a hand-invented fixture.
 * Malformed / empty inputs are inline reconstructions, the only sanctioned use.
 */
#include <catch2/catch_test_macros.hpp>

#include "../../agents/plugins/app_control/src/app_control_parsers.hpp"

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <limits>
#include <sstream>
#include <string>
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

const std::unordered_set<std::string> kStateVocab{"disabled", "audit", "enforced", "unmodelled",
                                                  "absent"};
constexpr auto kMax = std::numeric_limits<std::uint32_t>::max();

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

    const auto p = parse_cim_applocker_row(
        {{"Collection", "Exe"}, {"EnforcementMode", "1"}, {"RuleCount", "4"}});
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

TEST_CASE("app_control real capture: CI\\Policy values format to closed-vocabulary rows",
          "[app_control][parsers][capture]") {
    const auto dump = parse_ci_policy_dump(read_capture("ci_policy_values.txt"));
    CHECK_FALSE(dump.acc.any_failure());
    for (const auto& v : dump.values) {
        const auto f = split_fields(format_wdac_row(v));
        REQUIRE(f.size() == 4);
        CHECK(f[0] == "wdac");
        CHECK(kStateVocab.contains(f[3]));
        if (v.name == kVerifiedAndReputableValue && v.kind == RegValueKind::u32)
            CHECK(f[3] == policy_state_name(map_ci_policy_state(v.u32)));
    }
}

TEST_CASE("app_control real capture: MSFT_ApplockerPolicy probe classifies and maps",
          "[app_control][parsers][capture]") {
    const auto probe = parse_wmi_probe_dump(read_capture("applocker_wmi_probe.txt"));
    CHECK_FALSE(probe.acc.any_failure());
    // Whichever way the rig answered, classification is total: an absent class
    // selects the registry fallback; any rows must map strictly.
    const auto outcome = classify_cim_error(probe.error);
    CHECK((outcome == CimOutcome::ok || outcome == CimOutcome::class_absent));
    if (outcome == CimOutcome::ok)
        for (const auto& row : probe.rows)
            CHECK(parse_cim_applocker_row(row).has_value());
}
