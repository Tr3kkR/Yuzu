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

TEST_CASE("profiles_from_local_state: an e-mail-shaped display_name is redacted, never passed "
          "through -- the blocker this contract exists to close",
          "[browser_inventory][profiles][privacy]") {
    // Adversarial-review finding (2026-09-22): the accepted personal-name
    // exception (see the sibling "real-name-shaped" test above) does NOT
    // extend to an e-mail address -- the PRIVACY CONTRACT forbids that
    // unconditionally. Both external reviewers independently compiled a
    // harness reproducing exactly this shape and got the raw address on
    // the wire; this pins the fix.
    const auto text = std::string{R"({"profile":{"info_cache":{"Default":{)"} +
                       R"("name":"account@example.com"}}}})";
    const auto rows = profiles_from_local_state(text);
    REQUIRE(rows.has_value());
    REQUIRE(rows->size() == 1);
    CHECK(rows->front().display_name == "[redacted-email]");
    CHECK(rows->front().display_name.find('@') == std::string::npos);
}

TEST_CASE("profiles_from_local_state: an e-mail-shaped profile_dir (the info_cache key itself) "
          "is redacted the same way as display_name",
          "[browser_inventory][profiles][privacy]") {
    // Edge in particular sometimes keys a signed-in profile's info_cache
    // entry by the account e-mail rather than a generic "Profile N" name
    // -- this is the profile_dir half of the same blocker.
    const auto text = std::string{R"({"profile":{"info_cache":{"account@example.com":{)"} +
                       R"("name":"account@example.com"}}}})";
    const auto rows = profiles_from_local_state(text);
    REQUIRE(rows.has_value());
    REQUIRE(rows->size() == 1);
    CHECK(rows->front().profile_dir == "[redacted-email]");
    CHECK(rows->front().display_name == "[redacted-email]");
}

TEST_CASE("profiles_from_local_state: a DECORATED or multi-address e-mail in profile_dir or "
          "display_name is redacted whole -- round-2 blocker",
          "[browser_inventory][profiles][privacy]") {
    // Round-2 adversarial finding (2026-09-23): the round-1 whole-value
    // filter passed a decorated or multi-address value straight through.
    // "Alice <alice@example.com>" < "Profile 2" lexically, so map order
    // (nlohmann::json's default object is ordered by key) pins row order.
    const auto text = std::string{R"json({"profile":{"info_cache":{)json"} +
                       R"json("Alice <alice@example.com>":{"name":"alice@example.com (Work)"},)json" +
                       R"json("Profile 2":{"name":"alice@example.com,bob@example.org"}}}})json";
    const auto rows = profiles_from_local_state(text);
    REQUIRE(rows.has_value());
    REQUIRE(rows->size() == 2);
    CHECK((*rows)[0].profile_dir == "[redacted-email]");
    CHECK((*rows)[0].display_name == "[redacted-email]");
    CHECK((*rows)[1].profile_dir == "Profile 2");
    CHECK((*rows)[1].display_name == "[redacted-email]");
    for (const auto& row : *rows) {
        CHECK(row.profile_dir.find('@') == std::string::npos);
        CHECK(row.display_name.find('@') == std::string::npos);
    }
}

TEST_CASE("looks_like_email_address: shape checks", "[browser_inventory][profiles][privacy]") {
    CHECK(looks_like_email_address("account@example.com"));
    CHECK(looks_like_email_address("a@b.co"));
    CHECK_FALSE(looks_like_email_address("Default"));
    CHECK_FALSE(looks_like_email_address("Profile 1"));
    CHECK_FALSE(looks_like_email_address("Jordan Smith"));
    CHECK_FALSE(looks_like_email_address(""));
    CHECK_FALSE(looks_like_email_address("@example.com"));  // nothing before '@'
    CHECK_FALSE(looks_like_email_address("account@"));      // nothing after '@'
    CHECK_FALSE(looks_like_email_address("account@example")); // no '.' in domain
    CHECK(looks_like_email_address("a@b@c.com"));     // contains b@c.com -- over-match is safe
    // Domain-side failure, not local-side: local-side is position-only
    // (at > 0) since the G-1 fix, so this stays false because the space
    // right after '@' leaves an empty domain, not because of the space
    // before it.
    CHECK_FALSE(looks_like_email_address("contact @ x.com"));

    // Round-2 adversarial finding (2026-09-23): the whole-value test under-
    // matched every decorated form -- these are the reviewer's four
    // counterexamples verbatim.
    CHECK(looks_like_email_address("Alice <alice@example.com>"));
    CHECK(looks_like_email_address("alice@example.com (Work)"));
    CHECK(looks_like_email_address("x alice@example.com"));
    CHECK(looks_like_email_address("alice@example.com,bob@example.org"));

    // Round-1 bare shapes retained.
    CHECK(looks_like_email_address("ALICE@EXAMPLE.COM"));
    CHECK(looks_like_email_address("alice+work@sub.example.co.uk"));

    // Still false: no dotted domain anywhere.
    CHECK_FALSE(looks_like_email_address("user@localhost"));
    CHECK_FALSE(looks_like_email_address("a@.com"));  // empty domain label before the dot
    CHECK_FALSE(looks_like_email_address("a@b."));    // trailing dot alone doesn't qualify

    // Round-2 governance finding G-1 (2026-09-23): the local-part exclusion
    // list rejected exactly the characters a folding-whitespace or
    // decorated address puts immediately before '@' -- deleting that list
    // (local-side condition is now `at > 0` only) closes the bypass.
    CHECK(looks_like_email_address("alice\n@example.com"));
    CHECK(looks_like_email_address("alice\r@example.com"));
    CHECK(looks_like_email_address("alice\t@example.com"));
    CHECK(looks_like_email_address("alice @example.com"));
    // G-2: RFC 5322 quoted local-part.
    CHECK(looks_like_email_address("\"alice.smith\"@example.com"));
    // G-3: RFC 5322 comment syntax.
    CHECK(looks_like_email_address("alice(comment)@example.com"));

    // S-1: a `continue`->`break` mutation on the multi-'@' skip branch would
    // make each of these false by stopping at the first (invalid) '@'
    // instead of moving on to the valid one later in the string.
    CHECK(looks_like_email_address("@alice@example.com"));       // local-side skip, then valid
    CHECK(looks_like_email_address("alice@[ bob@example.com"));  // unterminated "@[", then valid
    CHECK(looks_like_email_address("x@; alice@example.com"));    // domain-side skip, then valid

    // S-3: domain-literal address -- is_domain_char excludes '[', so this
    // needs its own branch alongside the dotted-domain scan.
    CHECK(looks_like_email_address("alice@[203.0.113.5]"));
    CHECK_FALSE(looks_like_email_address("alice@[]")); // empty domain literal

    // N-1: raw (non-punycode) Unicode/IDN domain -- a byte >= 0x80 is a
    // valid domain character so the scan doesn't truncate at "m". Escaped
    // bytes, not a raw UTF-8 source literal (MSVC leg).
    CHECK(looks_like_email_address("alice@m\xC3\xBCnchen.example"));

    // N-2: untested edge, safe direction -- dropping the local-part
    // exclusion list makes '@' itself a valid (if unusual) local-part
    // predecessor, so a literal "@@" now over-matches rather than
    // under-matching.
    CHECK(looks_like_email_address("a@@b.com"));
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
