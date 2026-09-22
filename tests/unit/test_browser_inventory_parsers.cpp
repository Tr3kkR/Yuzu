/**
 * test_browser_inventory_parsers.cpp — pure browser_inventory_parsers.hpp
 * tests. No plugin load, no OS call: everything here exercises
 * profiles_from_local_state() directly
 * against committed fixture files (real Edge capture + synthetic Chrome,
 * see tests/unit/fixtures/wave10/browser_inventory/{edge,chrome}/
 * provenance.txt) and small inline JSON literals for presence combinations
 * the fixtures don't exercise.
 */
#include "browser_inventory_parsers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>

using namespace yuzu::browser_inventory;
namespace fs = std::filesystem;

namespace {

fs::path fixture_dir() {
    return fs::path{YUZU_TEST_FIXTURE_DIR} / "wave10" / "browser_inventory";
}

/// Reads a fixture file's full text. REQUIREs it exists -- never silently
/// skipped, matching test_app_usage_parsers.cpp's fixture-loading
/// convention.
std::string read_fixture(const fs::path& rel) {
    const auto p = fixture_dir() / rel;
    REQUIRE(fs::exists(p));
    std::ifstream f(p, std::ios::binary);
    REQUIRE(f.good());
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

} // namespace

// ──────────────────────────────────────── profiles_from_local_state ──────

TEST_CASE("profiles_from_local_state: empty text is a legitimate absent-file result, not a "
          "parse failure",
          "[browser_inventory][profiles]") {
    const auto rows = profiles_from_local_state("");
    REQUIRE(rows.has_value());
    CHECK(rows->empty());
}

TEST_CASE("profiles_from_local_state: malformed JSON returns std::nullopt (parse-failed), "
          "not an empty vector",
          "[browser_inventory][profiles][fixture]") {
    const auto text = read_fixture("chrome/malformed_local_state.json");
    const auto rows = profiles_from_local_state(text);
    CHECK_FALSE(rows.has_value());
}

TEST_CASE("profiles_from_local_state: syntactically valid JSON with a schema-drifted field type "
          "returns std::nullopt, not an uncaught exception",
          "[browser_inventory][profiles]") {
    // Adversarial-review finding (2026-09-22): a numeric "last_used" (or
    // any other typed field mismatch) previously threw nlohmann::json::
    // type_error uncaught out of this function. MUTATION: removing the
    // try/catch around the semantic-extraction pass makes this test throw
    // instead of returning nullopt (Catch2 reports an uncaught exception
    // as a failure either way, but the point is the documented
    // CONSTRAINED/local_state_malformed contract, not merely "doesn't
    // crash").
    const auto text = std::string{R"({"profile":{"last_used":12345,)"} +
                       R"("info_cache":{"Default":{"name":"X"}}}})";
    const auto rows = profiles_from_local_state(text);
    CHECK_FALSE(rows.has_value());
}

TEST_CASE("profiles_from_local_state: REAL CAPTURE (Edge) — one profile, 'Default', marked "
          "active, display name is the generic profile label",
          "[browser_inventory][profiles][fixture]") {
    const auto text = read_fixture("edge/Local State");
    const auto rows = profiles_from_local_state(text);
    REQUIRE(rows.has_value());
    REQUIRE(rows->size() == 1);
    const auto& row = rows->at(0);
    CHECK(row.profile_dir == "Default");
    CHECK(row.display_name == "Profile 1");
    CHECK(row.active); // last_used == "Default"
    CHECK_FALSE(row.ephemeral);
}

TEST_CASE("profiles_from_local_state: REAL CAPTURE (Edge) — the row never carries "
          "user_name/gaia_id even though the source JSON has those keys "
          "(redacted, but present)",
          "[browser_inventory][profiles][privacy][fixture]") {
    // The struct itself has no such field -- this is a structural, not a
    // runtime, guarantee. This test documents and pins that guarantee: it
    // would fail to COMPILE if BrowserProfileRow ever grew a user_name or
    // gaia_id member, since nothing below references one.
    const auto text = read_fixture("edge/Local State");
    const auto rows = profiles_from_local_state(text);
    REQUIRE(rows.has_value());
    REQUIRE_FALSE(rows->empty());
    static_assert(sizeof(BrowserProfileRow) > 0);
    // Every member BrowserProfileRow has:
    const auto& row = rows->at(0);
    (void)row.profile_dir;
    (void)row.display_name;
    (void)row.active;
    (void)row.ephemeral;
    // No further members exist to reference -- adding one here that reads
    // row.user_name or row.gaia_id is precisely the change that should
    // fail review, not this test.
}

TEST_CASE("profiles_from_local_state: display_name deliberately passes through a real-name-shaped "
          "value -- the accepted exception, not a leak",
          "[browser_inventory][profiles][privacy]") {
    // Adversarial-review decision (2026-09-22): unlike user_name/gaia_id
    // (which the struct structurally cannot carry, see the sibling REAL
    // CAPTURE privacy test above), display_name IS a BrowserProfileRow
    // field and Chromium-family browsers commonly auto-populate it from
    // the signed-in account's real name -- this is an accepted residual
    // risk, not filtered. This inline (not a committed fixture) literal
    // documents that the parser forwards it as-is, matching the plugin
    // README's PRIVACY CONTRACT second exception.
    const auto text = std::string{R"({"profile":{"info_cache":{"Default":{)"} +
                       R"("name":"Jordan Smith"}}}})";
    const auto rows = profiles_from_local_state(text);
    REQUIRE(rows.has_value());
    REQUIRE(rows->size() == 1);
    CHECK(rows->front().display_name == "Jordan Smith");
}

TEST_CASE("profiles_from_local_state: SYNTHETIC (Chrome) — two profiles, second is ephemeral "
          "and not active; fabricated user_name/gaia_id in the source JSON still never "
          "reach a row",
          "[browser_inventory][profiles][fixture]") {
    const auto text = read_fixture("chrome/Local State");
    const auto rows = profiles_from_local_state(text);
    REQUIRE(rows.has_value());
    REQUIRE(rows->size() == 2);

    const auto& def = rows->at(0); // "Default" sorts before "Profile 2"
    CHECK(def.profile_dir == "Default");
    CHECK(def.display_name == "Person 1");
    CHECK(def.active);
    CHECK_FALSE(def.ephemeral);

    const auto& p2 = rows->at(1);
    CHECK(p2.profile_dir == "Profile 2");
    CHECK(p2.display_name == "Work (synthetic)");
    CHECK_FALSE(p2.active);
    CHECK(p2.ephemeral);
}

TEST_CASE("profiles_from_local_state: no 'profile' key, or 'profile' not an object, yields "
          "an empty vector",
          "[browser_inventory][profiles]") {
    CHECK(profiles_from_local_state(R"({"unrelated": 1})")->empty());
    CHECK(profiles_from_local_state(R"({"profile": "not-an-object"})")->empty());
    CHECK(profiles_from_local_state(R"({"profile": {}})")->empty());
    CHECK(profiles_from_local_state(R"({"profile": {"info_cache": {}}})")->empty());
}
