/**
 * test_pii_matcher.cpp — Unit tests for the pii_scan plugin's rule
 * parsing (pii_rules.hpp) and RE2 matching engine (pii_matcher.hpp).
 *
 * Pure in-memory fixtures throughout — no filesystem access, matching
 * the ssh_hardening_rules.hpp test convention.
 */

#include "pii_matcher.hpp"
#include "pii_rules.hpp"

#include <catch2/catch_test_macros.hpp>

using namespace yuzu::pii;

// ── pii_rules.hpp: JSON parsing ─────────────────────────────────────────

TEST_CASE("parse_rules_json: parses a well-formed rule", "[pii][rules][parse]") {
    std::string json = R"([{
        "id": "generic.email",
        "displayName": "Email Address",
        "jurisdiction": null,
        "category": "contact",
        "pattern": "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}",
        "checksum": null,
        "severity": "low",
        "complianceTags": ["GDPR", "CCPA"],
        "confidenceKeywords": [],
        "sourceConfidence": "HIGH",
        "notes": null
    }])";

    auto rules = parse_rules_json(json);
    REQUIRE(rules.size() == 1);
    CHECK(rules[0].id == "generic.email");
    CHECK(rules[0].display_name == "Email Address");
    CHECK_FALSE(rules[0].jurisdiction.has_value());
    CHECK(rules[0].category == "contact");
    CHECK_FALSE(rules[0].checksum.has_value());
    CHECK(rules[0].severity == "low");
    REQUIRE(rules[0].compliance_tags.size() == 2);
    CHECK(rules[0].compliance_tags[0] == "GDPR");
    CHECK(rules[0].source_confidence == "HIGH");
}

TEST_CASE("parse_rules_json: entries missing id or pattern are skipped, not fatal",
          "[pii][rules][parse]") {
    std::string json = R"([
        {"id": "a", "pattern": "\\d+"},
        {"displayName": "no id"},
        {"id": "b"},
        {"id": "c", "pattern": ""}
    ])";
    auto rules = parse_rules_json(json);
    REQUIRE(rules.size() == 1);
    CHECK(rules[0].id == "a");
}

TEST_CASE("parse_rules_json: malformed JSON returns an empty vector, not a crash",
          "[pii][rules][parse]") {
    auto rules = parse_rules_json("{not valid json");
    CHECK(rules.empty());
}

TEST_CASE("parse_rules_json: jurisdiction and checksum round-trip", "[pii][rules][parse]") {
    std::string json = R"([{
        "id": "gb.nino", "pattern": "[A-Z]{2}\\d{6}[A-D]",
        "jurisdiction": "GB", "checksum": "luhn"
    }])";
    auto rules = parse_rules_json(json);
    REQUIRE(rules.size() == 1);
    REQUIRE(rules[0].jurisdiction.has_value());
    CHECK(*rules[0].jurisdiction == "GB");
    REQUIRE(rules[0].checksum.has_value());
    CHECK(*rules[0].checksum == "luhn");
}

// ── pii_rules.hpp: jurisdiction / region filtering ──────────────────────

TEST_CASE("jurisdiction_matches_filter: empty filter matches everything", "[pii][rules][filter]") {
    CHECK(jurisdiction_matches_filter(std::optional<std::string>{"GB"}, {}));
    CHECK(jurisdiction_matches_filter(std::nullopt, {}));
}

TEST_CASE("jurisdiction_matches_filter: generic (nullopt) rules always pass regardless of filter",
          "[pii][rules][filter]") {
    CHECK(jurisdiction_matches_filter(std::nullopt, {"GB", "IE"}));
}

TEST_CASE("jurisdiction_matches_filter: exact code match", "[pii][rules][filter]") {
    CHECK(jurisdiction_matches_filter(std::optional<std::string>{"GB"}, {"GB", "IE"}));
    CHECK_FALSE(jurisdiction_matches_filter(std::optional<std::string>{"DE"}, {"GB", "IE"}));
}

TEST_CASE("jurisdiction_matches_filter: country prefix matches state-suffixed jurisdictions",
          "[pii][rules][filter]") {
    // A filter of "US" should match every US state's driver's-licence
    // rule (jurisdiction "US-CA", "US-NY", ...) without enumerating all 51.
    CHECK(jurisdiction_matches_filter(std::optional<std::string>{"US-CA"}, {"US"}));
    CHECK(jurisdiction_matches_filter(std::optional<std::string>{"CA-ON"}, {"CA"}));
    CHECK_FALSE(jurisdiction_matches_filter(std::optional<std::string>{"AU-NSW"}, {"US"}));
}

TEST_CASE("jurisdiction_matches_filter: a bare country code does not accidentally match an "
          "unrelated code sharing a prefix", "[pii][rules][filter]") {
    // "US" must not match "USA" or some other code that merely starts
    // with the same letters without the '-' separator.
    CHECK_FALSE(jurisdiction_matches_filter(std::optional<std::string>{"USA"}, {"US"}));
}

TEST_CASE("expand_jurisdiction_filter: region presets expand to member country codes",
          "[pii][rules][filter]") {
    auto expanded = expand_jurisdiction_filter({"EMEA"});
    bool has_gb = false, has_de = false, has_jp = false;
    for (const auto& c : expanded) {
        if (c == "GB")
            has_gb = true;
        if (c == "DE")
            has_de = true;
        if (c == "JP")
            has_jp = true;
    }
    CHECK(has_gb);
    CHECK(has_de);
    CHECK_FALSE(has_jp); // Japan is APAC, not EMEA
}

TEST_CASE("expand_jurisdiction_filter: region preset names are case-insensitive",
          "[pii][rules][filter]") {
    auto expanded = expand_jurisdiction_filter({"emea"});
    CHECK_FALSE(expanded.empty());
}

TEST_CASE("expand_jurisdiction_filter: a plain country code (not a region name) passes through",
          "[pii][rules][filter]") {
    auto expanded = expand_jurisdiction_filter({"GB"});
    REQUIRE(expanded.size() == 1);
    CHECK(expanded[0] == "GB");
}

TEST_CASE("filter_rules_by_jurisdiction: end-to-end — a UK-only filter keeps generic rules and "
          "GB rules, drops others", "[pii][rules][filter]") {
    std::vector<Rule> rules;
    Rule generic;
    generic.id = "generic.email";
    generic.pattern = "x";
    rules.push_back(generic);

    Rule gb;
    gb.id = "gb.nino";
    gb.jurisdiction = "GB";
    gb.pattern = "x";
    rules.push_back(gb);

    Rule jp;
    jp.id = "jp.my_number";
    jp.jurisdiction = "JP";
    jp.pattern = "x";
    rules.push_back(jp);

    auto filtered = filter_rules_by_jurisdiction(rules, {"EMEA"});
    REQUIRE(filtered.size() == 2);
    bool has_generic = false, has_gb = false;
    for (const auto& r : filtered) {
        if (r.id == "generic.email")
            has_generic = true;
        if (r.id == "gb.nino")
            has_gb = true;
    }
    CHECK(has_generic);
    CHECK(has_gb);
}

// ── pii_matcher.hpp: mask_value ─────────────────────────────────────────

TEST_CASE("mask_value: short values are fully masked", "[pii][matcher][mask]") {
    CHECK(mask_value("1234") == "****");
    CHECK(mask_value("12") == "**");
    CHECK(mask_value("") == "");
}

TEST_CASE("mask_value: longer values show only the last 4 characters", "[pii][matcher][mask]") {
    // 16 chars total: 12 '*' (16-4) + the last 4 kept.
    CHECK(mask_value("4111111111111111") == "************1111");
    CHECK(mask_value("4111111111111111").size() == 16);
    // never returns the raw value verbatim
    CHECK(mask_value("4111111111111111") != "4111111111111111");
}

// ── pii_matcher.hpp: scan_text ───────────────────────────────────────────

namespace {

Rule make_rule(std::string id, std::string pattern, std::optional<std::string> checksum = std::nullopt,
               std::vector<std::string> keywords = {}) {
    Rule r;
    r.id = std::move(id);
    r.display_name = r.id;
    r.category = "test";
    r.pattern = std::move(pattern);
    r.checksum = std::move(checksum);
    r.severity = "high";
    r.confidence_keywords = std::move(keywords);
    r.source_confidence = "HIGH";
    return r;
}

} // namespace

TEST_CASE("scan_text: a checksum PASS is reported at HIGH confidence", "[pii][matcher][scan]") {
    std::vector<Rule> rules = {make_rule("cc.visa", R"(4\d{15})", "luhn")};
    auto compiled = compile_rules(rules);
    REQUIRE(compiled.size() == 1);

    auto findings = scan_text(compiled, "card on file: 4111111111111111 thanks");
    REQUIRE(findings.size() == 1);
    CHECK(findings[0].finding_confidence == "HIGH");
    CHECK(findings[0].rule_id == "cc.visa");
    CHECK(findings[0].line_number == 1);
    CHECK(findings[0].masked_value.find("1111") != std::string::npos);
    CHECK(findings[0].masked_value != "4111111111111111"); // never the raw value
}

TEST_CASE("scan_text: a checksum FAILURE is dropped entirely, not just downgraded",
          "[pii][matcher][scan]") {
    std::vector<Rule> rules = {make_rule("cc.visa", R"(4\d{15})", "luhn")};
    auto compiled = compile_rules(rules);

    // 4111111111111112 has the right shape but fails Luhn.
    auto findings = scan_text(compiled, "not a real card: 4111111111111112");
    CHECK(findings.empty());
}

TEST_CASE("scan_text: no checksum + a nearby keyword yields MEDIUM confidence",
          "[pii][matcher][scan]") {
    std::vector<Rule> rules = {
        make_rule("us.ssn", R"(\d{3}-\d{2}-\d{4})", std::nullopt, {"ssn", "social security"})};
    auto compiled = compile_rules(rules);

    auto findings = scan_text(compiled, "Employee SSN: 123-45-6789");
    REQUIRE(findings.size() == 1);
    CHECK(findings[0].finding_confidence == "MEDIUM");
}

TEST_CASE("scan_text: no checksum + no nearby keyword yields LOW confidence",
          "[pii][matcher][scan]") {
    std::vector<Rule> rules = {
        make_rule("us.ssn", R"(\d{3}-\d{2}-\d{4})", std::nullopt, {"ssn", "social security"})};
    auto compiled = compile_rules(rules);

    auto findings = scan_text(compiled, "reference number: 123-45-6789");
    REQUIRE(findings.size() == 1);
    CHECK(findings[0].finding_confidence == "LOW");
}

TEST_CASE("scan_text: reports the correct 1-indexed line number for a multi-line blob",
          "[pii][matcher][scan]") {
    std::vector<Rule> rules = {make_rule("generic.email",
                                         R"([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})")};
    auto compiled = compile_rules(rules);

    auto findings = scan_text(compiled, "line one\nline two\ncontact: a@b.com\nline four");
    REQUIRE(findings.size() == 1);
    CHECK(findings[0].line_number == 3);
}

TEST_CASE("scan_text: finds multiple matches of the same rule on one line",
          "[pii][matcher][scan]") {
    std::vector<Rule> rules = {make_rule("generic.email",
                                         R"([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})")};
    auto compiled = compile_rules(rules);

    auto findings = scan_text(compiled, "cc: a@b.com, c@d.com");
    CHECK(findings.size() == 2);
}

TEST_CASE("scan_text: a rule with no matches in the text produces no findings",
          "[pii][matcher][scan]") {
    std::vector<Rule> rules = {make_rule("generic.email",
                                         R"([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})")};
    auto compiled = compile_rules(rules);

    auto findings = scan_text(compiled, "nothing sensitive here");
    CHECK(findings.empty());
}

TEST_CASE("compile_rules: an invalid regex is skipped, not fatal", "[pii][matcher][compile]") {
    std::vector<Rule> rules = {
        make_rule("bad", "[unterminated"),
        make_rule("good", R"(\d+)"),
    };
    std::vector<std::string> bad_ids;
    auto compiled = compile_rules(rules, &bad_ids);
    REQUIRE(bad_ids.size() == 1);
    CHECK(bad_ids[0] == "bad");
    REQUIRE(compiled.size() == 1);
    CHECK(compiled[0].rule->id == "good");
}
