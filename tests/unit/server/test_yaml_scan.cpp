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

TEST_CASE("yaml_scan: extract_yaml_value skips keys inside comments (#1221 MEDIUM-2)",
          "[yaml_scan]") {
    // A whole-line commented key must not be returned, even though its 'key:'
    // token is preceded by whitespace (the old anchor check alone passed it).
    CHECK(extract_yaml_value("  # fromResultSet: rs_evil\n", "fromResultSet").empty());
    // A real key AFTER a commented decoy line wins; the decoy is skipped, not
    // returned (regression guard for the policy scalar-scope footgun).
    CHECK(extract_yaml_value("  # fromResultSet: rs_evil\n  fromResultSet: rs_real\n",
                             "fromResultSet") == "rs_real");
    // An inline trailing comment that mentions a key-like token is not a key.
    CHECK(extract_yaml_value("selector:    # fromResultSet: rs_evil\n  platform: x\n",
                             "fromResultSet")
              .empty());
    // A '#' inside the value (no preceding whitespace) is NOT a comment marker —
    // a legitimate value containing '#' is still returned intact.
    CHECK(extract_yaml_value("channel: prod#1\n", "channel") == "prod#1");
}

TEST_CASE("yaml_scan: extract_yaml_section anchors to line-leading keys (#1215 H-2)",
          "[yaml_scan]") {
    // A `scope:` substring inside a description value must NOT mis-anchor the
    // section walk. Pre-fix, find() matched the substring, mis-computed the
    // indent, and returned an empty block — dropping the real scope (fail-OPEN
    // for policies). The real `scope:` block must still be returned intact.
    std::string yaml = "spec:\n"
                       "  description: \"see scope: foo for details\"\n"
                       "  scope:\n"
                       "    fromResultSet: rs_x\n";
    auto scope = extract_yaml_section(yaml, "spec.scope");
    CHECK(extract_yaml_value(scope, "fromResultSet") == "rs_x");
    // A commented section header must not be anchored to either.
    std::string yaml2 = "# scope: {fromResultSet: rs_evil}\n"
                        "spec:\n"
                        "  scope:\n"
                        "    fromResultSet: rs_real\n";
    auto scope2 = extract_yaml_section(yaml2, "spec.scope");
    CHECK(extract_yaml_value(scope2, "fromResultSet") == "rs_real");
}

TEST_CASE("yaml_scan: a commented inline-mapping scope: line is not extracted (#1215 H-1)",
          "[yaml_scan]") {
    // validate_definition_scope reads extract_yaml_value(yaml, "scope") to detect
    // the inline flow-mapping form. A *commented* `# scope: {...}` line must not
    // be picked up, or a legitimate definition keeping sample YAML in a comment
    // is falsely rejected. The real mapping scope: opens a block → returns empty.
    std::string yaml = "# scope: {fromResultSet: rs_evil}\n"
                       "spec:\n"
                       "  scope:\n"
                       "    fromResultSet: rs_abc\n";
    CHECK(extract_yaml_value(yaml, "scope").empty());
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
