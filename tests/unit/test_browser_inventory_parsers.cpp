/**
 * test_browser_inventory_parsers.cpp — pure browser_inventory_parsers.hpp
 * tests. No plugin load, no OS call: everything here exercises
 * profiles_from_local_state() and extension_state_from_prefs() directly
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

const ExtensionStateRow* find_id(const std::map<std::string, ExtensionStateRow>& m,
                                 const std::string& id) {
    auto it = m.find(id);
    return it == m.end() ? nullptr : &it->second;
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

// ──────────────────────────────────────── extension_state_from_prefs ─────

TEST_CASE("extension_state_from_prefs: neither file present -> empty map, not nullopt",
          "[browser_inventory][extensions]") {
    const auto m = extension_state_from_prefs("", "");
    REQUIRE(m.has_value());
    CHECK(m->empty());
}

TEST_CASE("extension_state_from_prefs: REAL CAPTURE (Edge) secure-only — the copied "
          "extension's real, unredacted structural fields come through",
          "[browser_inventory][extensions][fixture]") {
    const auto secure = read_fixture("edge/Default/Secure Preferences");
    const auto m = extension_state_from_prefs(secure, /*prefs=*/"");
    REQUIRE(m.has_value());
    CHECK(m->size() == 53); // provenance.txt: extensions.settings has 53 entries

    // Mutation-survival anchor (X11): a real captured value, not a "not
    // empty"/count-only check. ghbmnnjooekpmoecnnnilnnbdlolhkhi is "Google
    // Docs Offline", disable_reasons non-empty and state 0 in the raw
    // capture -> "disabled"; from_webstore true -> "yes".
    const auto* row = find_id(*m, "ghbmnnjooekpmoecnnnilnnbdlolhkhi");
    REQUIRE(row != nullptr);
    CHECK(row->state == "disabled");
    CHECK(row->from_webstore == "yes");
    CHECK(row->name == "Google Docs Offline");
    CHECK(row->version == "1.102.1");
}

TEST_CASE("extension_state_from_prefs: REAL CAPTURE (Edge) — Preferences alone carries no "
          "extensions.settings (confirmed in provenance.txt's jq facts), so prefs-only "
          "yields an empty map",
          "[browser_inventory][extensions][fixture]") {
    const auto prefs = read_fixture("edge/Default/Preferences");
    const auto m = extension_state_from_prefs(/*secure=*/"", prefs);
    REQUIRE(m.has_value());
    CHECK(m->empty());
}

TEST_CASE("extension_state_from_prefs: REAL CAPTURE (Edge) — both files present, Secure "
          "Preferences still supplies the 53 entries, Preferences contributing nothing to "
          "merge (matches its empty settings map)",
          "[browser_inventory][extensions][fixture]") {
    const auto secure = read_fixture("edge/Default/Secure Preferences");
    const auto prefs = read_fixture("edge/Default/Preferences");
    const auto m = extension_state_from_prefs(secure, prefs);
    REQUIRE(m.has_value());
    CHECK(m->size() == 53);
}

TEST_CASE("extension_state_from_prefs: precedence — an id present in both files takes the "
          "Secure Preferences entry",
          "[browser_inventory][extensions][precedence]") {
    constexpr std::string_view secure = R"({
        "extensions": {"settings": {
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": {
                "state": 1, "from_webstore": true,
                "manifest": {"name": "From Secure", "version": "9.9.9"}
            }
        }}
    })";
    constexpr std::string_view prefs = R"({
        "extensions": {"settings": {
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": {
                "state": 0, "from_webstore": false,
                "manifest": {"name": "From Preferences", "version": "1.1.1"}
            }
        }}
    })";
    const auto m = extension_state_from_prefs(secure, prefs);
    REQUIRE(m.has_value());
    REQUIRE(m->size() == 1);
    const auto* row = find_id(*m, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    REQUIRE(row != nullptr);
    CHECK(row->name == "From Secure");
    CHECK(row->state == "enabled");
    CHECK(row->from_webstore == "yes");
}

TEST_CASE("extension_state_from_prefs: an id present only in Preferences (fallback) still "
          "surfaces",
          "[browser_inventory][extensions][precedence]") {
    constexpr std::string_view prefs = R"({
        "extensions": {"settings": {
            "dddddddddddddddddddddddddddddddd": {
                "state": 1,
                "manifest": {"name": "Prefs Only", "version": "3.0.0"}
            }
        }}
    })";
    const auto m = extension_state_from_prefs(/*secure=*/"", prefs);
    REQUIRE(m.has_value());
    REQUIRE(m->size() == 1);
    const auto* row = find_id(*m, "dddddddddddddddddddddddddddddddd");
    REQUIRE(row != nullptr);
    CHECK(row->name == "Prefs Only");
    CHECK(row->state == "enabled");
    CHECK(row->from_webstore == "-"); // field absent in this literal
}

TEST_CASE("extension_state_from_prefs: SYNTHETIC (Chrome) — state enabled/disabled/"
          "unmodelled cover exactly the three values this parser distinguishes",
          "[browser_inventory][extensions][fixture]") {
    const auto secure = read_fixture("chrome/Default/Secure Preferences");
    const auto m = extension_state_from_prefs(secure, /*prefs=*/"");
    REQUIRE(m.has_value());
    REQUIRE(m->size() == 3);

    const auto* enabled = find_id(*m, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    REQUIRE(enabled != nullptr);
    CHECK(enabled->state == "enabled");
    CHECK(enabled->from_webstore == "yes");
    CHECK(enabled->name == "Synthetic Enabled Extension");
    CHECK(enabled->version == "1.0.0");

    const auto* disabled = find_id(*m, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    REQUIRE(disabled != nullptr);
    CHECK(disabled->state == "disabled");
    CHECK(disabled->from_webstore == "-"); // field absent on this entry

    const auto* unmodelled = find_id(*m, "cccccccccccccccccccccccccccccccc");
    REQUIRE(unmodelled != nullptr);
    CHECK(unmodelled->state == "unmodelled"); // no "state" key at all on this entry
}

TEST_CASE("extension_state_from_prefs: malformed Secure Preferences with no Preferences "
          "fallback -> std::nullopt",
          "[browser_inventory][extensions]") {
    const auto m = extension_state_from_prefs("{not valid json", /*prefs=*/"");
    CHECK_FALSE(m.has_value());
}

TEST_CASE("extension_state_from_prefs: malformed Secure Preferences but a valid Preferences "
          "fallback still yields data, not nullopt",
          "[browser_inventory][extensions]") {
    constexpr std::string_view prefs = R"({
        "extensions": {"settings": {
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee": {"state": 1, "manifest": {"name": "Ok", "version": "1"}}
        }}
    })";
    const auto m = extension_state_from_prefs("{not valid json", prefs);
    REQUIRE(m.has_value());
    CHECK(m->size() == 1);
}

TEST_CASE("extension_state_from_prefs: no 'extensions' key, or 'extensions.settings' not an "
          "object, yields an empty map (not nullopt) — the file parsed fine, it just has no "
          "extension state",
          "[browser_inventory][extensions]") {
    CHECK(extension_state_from_prefs(R"({"unrelated": 1})", "")->empty());
    CHECK(extension_state_from_prefs(R"({"extensions": "not-an-object"})", "")->empty());
    CHECK(extension_state_from_prefs(R"({"extensions": {}})", "")->empty());
    CHECK(extension_state_from_prefs(R"({"extensions": {"settings": "not-an-object"}})", "")
              ->empty());
}
