/**
 * test_yaml_scan.cpp — the runtime YAML line-scanners (yaml_scan.{hpp,cpp}).
 *
 * These hand-rolled scanners were moved verbatim out of policy_store.cpp's
 * anonymous namespace in PR-E and are now load-bearing for scope_yaml's
 * parse_scope_block. They previously had only indirect coverage; these cases
 * pin the behaviour directly, including the adversarial inputs (governance
 * qe-SHOULD-2) that the scope-block parser relies on the scanners to handle.
 */

#include "yaml_scan.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

using namespace yuzu::server::yaml_scan;

TEST_CASE("yaml_scan: extract_yaml_value scalar / quoted / mapping", "[yaml_scan]") {
    CHECK(extract_yaml_value("name: hello\n", "name") == "hello");
    CHECK(extract_yaml_value("name: \"quoted value\"\n", "name") == "quoted value");
    CHECK(extract_yaml_value("name: 'single'\n", "name") == "single");
    // A key that opens a mapping returns empty (the signal scope_yaml uses to
    // fall through to block parsing).
    CHECK(extract_yaml_value("scope:\n  selector:\n    platform: x\n", "scope").empty());
    // Absent key.
    CHECK(extract_yaml_value("other: y\n", "name").empty());
}

TEST_CASE("yaml_scan: extract_yaml_list block and inline forms", "[yaml_scan]") {
    auto block = extract_yaml_list("tags:\n  - prod\n  - edge\n", "tags");
    REQUIRE(block.size() == 2);
    CHECK(block[0] == "prod");
    CHECK(block[1] == "edge");

    auto inline_form = extract_yaml_list("tags: [a, b, c]\n", "tags");
    REQUIRE(inline_form.size() == 3);
    CHECK(inline_form[0] == "a");
    CHECK(inline_form[2] == "c");
}

TEST_CASE("yaml_scan: extract_yaml_section walks a dotted path", "[yaml_scan]") {
    std::string yaml = "spec:\n"
                       "  scope:\n"
                       "    fromResultSet: rs_x\n"
                       "  assignment:\n"
                       "    mode: static\n";
    auto scope = extract_yaml_section(yaml, "spec.scope");
    CHECK(extract_yaml_value(scope, "fromResultSet") == "rs_x");
    auto asn = extract_yaml_section(yaml, "spec.assignment");
    CHECK(extract_yaml_value(asn, "mode") == "static");
    // A missing path returns empty.
    CHECK(extract_yaml_section(yaml, "spec.nope").empty());
}

TEST_CASE("yaml_scan: yaml_has_key anchors to line starts", "[yaml_scan]") {
    CHECK(yaml_has_key("  fromResultSet: rs_x\n", "fromResultSet"));
    // Present even when the key opens a mapping (where extract_yaml_value is empty).
    CHECK(yaml_has_key("selector:\n  platform: x\n", "selector"));
    CHECK_FALSE(yaml_has_key("other: y\n", "fromResultSet"));
}

TEST_CASE("yaml_scan: yaml_has_key skips comments and is not fooled by substrings",
          "[yaml_scan]") {
    // A commented-out key must not register.
    CHECK_FALSE(yaml_has_key("  # fromResultSet: rs_x\n", "fromResultSet"));
    // A key that is a prefix of a longer key must not match (the colon guards it).
    CHECK_FALSE(yaml_has_key("modeSwitch: x\n", "mode"));
    CHECK(yaml_has_key("mode: static\n", "mode"));
}

TEST_CASE("yaml_scan: a key inside a quoted value does not leak into a sibling section",
          "[yaml_scan]") {
    // Adversarial: 'fromResultSet' appears inside a description value, NOT as a
    // real scope key. After isolating spec.scope, it must not be visible.
    std::string yaml = "spec:\n"
                       "  description: \"mentions fromResultSet: rs_secret in prose\"\n"
                       "  scope:\n"
                       "    selector:\n"
                       "      platform: windows\n";
    auto scope = extract_yaml_section(yaml, "spec.scope");
    CHECK_FALSE(yaml_has_key(scope, "fromResultSet"));
    CHECK(yaml_has_key(scope, "selector"));
}
