/**
 * test_user_profile_model.cpp — pure user-profile / registry-hive discovery
 * model (user_profile_model.hpp, PR1.7).
 *
 * The Reg*W calls (ProfileList enumeration, HKEY_USERS subkey listing,
 * RegLoadKeyW mounting) are the impure Win32 shell; the SID classification,
 * name derivation, hive-state classification, and wire-row rendering below
 * are header-pure and pinned here on every host (the firewall_parsers.hpp /
 * tar_module_etw.hpp pattern). All SIDs in fixtures are synthetic, matching
 * the convention in test_tar_netconn.cpp.
 */

#include "user_profile_model.hpp"

#include <catch2/catch_test_macros.hpp>

using namespace yuzu::profiles;

namespace {
constexpr std::string_view kAliceSid = "S-1-5-21-1111111111-2222222222-3333333333-1001";
constexpr std::string_view kBobSid = "S-1-5-21-1111111111-2222222222-3333333333-1002";
} // namespace

// ── is_system_sid ────────────────────────────────────────────────────────

TEST_CASE("is_system_sid: the three well-known local-system SIDs", "[profiles]") {
    CHECK(is_system_sid("S-1-5-18"));
    CHECK(is_system_sid("S-1-5-19"));
    CHECK(is_system_sid("S-1-5-20"));
}

TEST_CASE("is_system_sid: a real user SID is not a system SID", "[profiles]") {
    CHECK_FALSE(is_system_sid(kAliceSid));
    CHECK_FALSE(is_system_sid(""));
    CHECK_FALSE(is_system_sid("S-1-5-80-1234"));
}

// ── iequals_ascii ─────────────────────────────────────────────────────────

TEST_CASE("iequals_ascii: identical strings match", "[profiles]") {
    CHECK(iequals_ascii("alice", "alice"));
}

TEST_CASE("iequals_ascii: differing case matches (ordinal, not locale)", "[profiles]") {
    CHECK(iequals_ascii("Alice", "alice"));
    CHECK(iequals_ascii("ALICE", "alice"));
    CHECK(iequals_ascii("aLiCe", "AlIcE"));
}

TEST_CASE("iequals_ascii: different length never matches", "[profiles]") {
    CHECK_FALSE(iequals_ascii("alice", "alices"));
    CHECK_FALSE(iequals_ascii("alice", ""));
}

TEST_CASE("iequals_ascii: different content does not match", "[profiles]") {
    CHECK_FALSE(iequals_ascii("alice", "bob!!"));
}

TEST_CASE("iequals_ascii: two empty strings match", "[profiles]") {
    CHECK(iequals_ascii("", ""));
}

// ── profile_name_from_path ───────────────────────────────────────────────

TEST_CASE("profile_name_from_path: ordinary Windows path", "[profiles]") {
    CHECK(profile_name_from_path("C:\\Users\\alice") == "alice");
}

TEST_CASE("profile_name_from_path: trailing separator is stripped first", "[profiles]") {
    CHECK(profile_name_from_path("C:\\Users\\alice\\") == "alice");
}

TEST_CASE("profile_name_from_path: forward slashes", "[profiles]") {
    CHECK(profile_name_from_path("C:/Users/alice") == "alice");
}

TEST_CASE("profile_name_from_path: UNC-shaped path", "[profiles]") {
    CHECK(profile_name_from_path("\\\\server\\profiles$\\alice") == "alice");
}

TEST_CASE("profile_name_from_path: empty path resolves to empty, never a fallback", "[profiles]") {
    CHECK(profile_name_from_path("").empty());
}

TEST_CASE("profile_name_from_path: separators-only path resolves to empty", "[profiles]") {
    CHECK(profile_name_from_path("\\\\\\").empty());
    CHECK(profile_name_from_path("/").empty());
}

TEST_CASE("profile_name_from_path: no separator treats the whole value as the name", "[profiles]") {
    CHECK(profile_name_from_path("alice") == "alice");
}

// ── classify_hive_state ──────────────────────────────────────────────────

TEST_CASE("classify_hive_state: SID present in HKEY_USERS is loaded", "[profiles]") {
    std::vector<std::string> subkeys{std::string{kAliceSid}, std::string{kAliceSid} + "_Classes"};
    CHECK(classify_hive_state(kAliceSid, subkeys) == HiveState::loaded);
}

TEST_CASE("classify_hive_state: only the _Classes subkey is present", "[profiles]") {
    std::vector<std::string> subkeys{std::string{kAliceSid} + "_Classes"};
    CHECK(classify_hive_state(kAliceSid, subkeys) == HiveState::loaded_classes_only);
}

TEST_CASE("classify_hive_state: neither present", "[profiles]") {
    std::vector<std::string> subkeys{std::string{kBobSid}};
    CHECK(classify_hive_state(kAliceSid, subkeys) == HiveState::not_loaded);
}

TEST_CASE("classify_hive_state: empty HKEY_USERS snapshot", "[profiles]") {
    std::vector<std::string> subkeys{};
    CHECK(classify_hive_state(kAliceSid, subkeys) == HiveState::not_loaded);
}

TEST_CASE("classify_hive_state: the real hive outranks a _Classes-only sighting", "[profiles]") {
    std::vector<std::string> subkeys{std::string{kAliceSid} + "_Classes", std::string{kAliceSid}};
    CHECK(classify_hive_state(kAliceSid, subkeys) == HiveState::loaded);
}

// ── build_profile_list ───────────────────────────────────────────────────

TEST_CASE("build_profile_list: system SIDs are filtered out", "[profiles]") {
    std::vector<RawProfileRecord> records{
        {"S-1-5-18", "C:\\Windows\\system32\\config\\systemprofile"},
        {"S-1-5-19", "C:\\Windows\\ServiceProfiles\\LocalService"},
        {"S-1-5-20", "C:\\Windows\\ServiceProfiles\\NetworkService"},
        {std::string{kAliceSid}, "C:\\Users\\alice"},
    };
    std::vector<std::string> hku{};
    auto profiles = build_profile_list(records, hku);
    REQUIRE(profiles.size() == 1);
    CHECK(profiles[0].sid == kAliceSid);
    CHECK(profiles[0].profile_name == "alice");
}

TEST_CASE("build_profile_list: duplicate SIDs keep only the first occurrence", "[profiles]") {
    std::vector<RawProfileRecord> records{
        {std::string{kAliceSid}, "C:\\Users\\alice"},
        {std::string{kAliceSid}, "C:\\Users\\alice-stale-duplicate"},
    };
    std::vector<std::string> hku{};
    auto profiles = build_profile_list(records, hku);
    REQUIRE(profiles.size() == 1);
    CHECK(profiles[0].profile_path == "C:\\Users\\alice");
}

TEST_CASE("build_profile_list: empty input yields an empty list", "[profiles]") {
    std::vector<RawProfileRecord> records{};
    std::vector<std::string> hku{};
    CHECK(build_profile_list(records, hku).empty());
}

TEST_CASE("build_profile_list: unreadable ProfileImagePath yields an empty name, not a crash",
          "[profiles]") {
    std::vector<RawProfileRecord> records{{std::string{kAliceSid}, ""}};
    std::vector<std::string> hku{};
    auto profiles = build_profile_list(records, hku);
    REQUIRE(profiles.size() == 1);
    CHECK(profiles[0].profile_name.empty());
    CHECK(profiles[0].sid == kAliceSid); // never falls back to the sid (ADR-0024 D11)
}

TEST_CASE("build_profile_list: hive state carries through from the HKU snapshot", "[profiles]") {
    std::vector<RawProfileRecord> records{
        {std::string{kAliceSid}, "C:\\Users\\alice"},
        {std::string{kBobSid}, "C:\\Users\\bob"},
    };
    std::vector<std::string> hku{std::string{kAliceSid}};
    auto profiles = build_profile_list(records, hku);
    REQUIRE(profiles.size() == 2);
    CHECK(profiles[0].state == HiveState::loaded);
    CHECK(profiles[1].state == HiveState::not_loaded);
}

// ── find_sid_by_username ──────────────────────────────────────────────────

TEST_CASE("find_sid_by_username: exact match", "[profiles]") {
    std::vector<ProfileInfo> profiles{
        {std::string{kAliceSid}, "alice", "C:\\Users\\alice", HiveState::loaded},
        {std::string{kBobSid}, "bob", "C:\\Users\\bob", HiveState::not_loaded},
    };
    auto sid = find_sid_by_username(profiles, "bob");
    REQUIRE(sid.has_value());
    CHECK(*sid == kBobSid);
}

TEST_CASE("find_sid_by_username: case-insensitive match (Windows profile folder semantics)",
          "[profiles]") {
    // Regression pin: the pre-PR1.7 code built the NTUSER.DAT path directly
    // against a case-insensitive filesystem, so case never mattered for the
    // case it could reach. A case-sensitive comparison here would regress
    // that behaviour for no benefit.
    std::vector<ProfileInfo> profiles{
        {std::string{kAliceSid}, "alice", "C:\\Users\\alice", HiveState::loaded},
    };
    auto sid = find_sid_by_username(profiles, "Alice");
    REQUIRE(sid.has_value());
    CHECK(*sid == kAliceSid);
}

TEST_CASE("find_sid_by_username: no match", "[profiles]") {
    std::vector<ProfileInfo> profiles{
        {std::string{kAliceSid}, "alice", "C:\\Users\\alice", HiveState::loaded},
    };
    CHECK_FALSE(find_sid_by_username(profiles, "carol").has_value());
}

TEST_CASE("find_sid_by_username: empty username never matches", "[profiles]") {
    std::vector<ProfileInfo> profiles{
        {std::string{kAliceSid}, "alice", "C:\\Users\\alice", HiveState::loaded},
    };
    CHECK_FALSE(find_sid_by_username(profiles, "").has_value());
}

TEST_CASE("find_sid_by_username: an unresolved profile name never matches an empty lookup",
          "[profiles]") {
    std::vector<ProfileInfo> profiles{
        {std::string{kAliceSid}, "", "", HiveState::not_loaded},
    };
    CHECK_FALSE(find_sid_by_username(profiles, "").has_value());
}

TEST_CASE("find_sid_by_username: first match wins on a name collision", "[profiles]") {
    std::vector<ProfileInfo> profiles{
        {std::string{kAliceSid}, "shared", "C:\\Users\\alice", HiveState::loaded},
        {std::string{kBobSid}, "shared", "C:\\Users\\bob", HiveState::not_loaded},
    };
    auto sid = find_sid_by_username(profiles, "shared");
    REQUIRE(sid.has_value());
    CHECK(*sid == kAliceSid);
}

// ── sanitize_field / render_profile_row ──────────────────────────────────

TEST_CASE("sanitize_field: strips pipe, CR, LF", "[profiles]") {
    CHECK(sanitize_field("a|b\r\nc") == "a_b__c");
}

TEST_CASE("sanitize_field: ordinary text passes through unchanged", "[profiles]") {
    CHECK(sanitize_field("alice") == "alice");
}

TEST_CASE("render_profile_row: ordinary profile", "[profiles]") {
    ProfileInfo info{std::string{kAliceSid}, "alice", "C:\\Users\\alice", HiveState::loaded};
    CHECK(render_profile_row(info) == std::string{kAliceSid} + "|alice|C:\\Users\\alice|loaded");
}

TEST_CASE("render_profile_row: empty fields render as '-'", "[profiles]") {
    ProfileInfo info{std::string{kAliceSid}, "", "", HiveState::not_loaded};
    CHECK(render_profile_row(info) == std::string{kAliceSid} + "|-|-|not_loaded");
}

TEST_CASE("render_profile_row: a value containing '|' cannot forge a column", "[profiles]") {
    // Regression pin: registry_plugin.cpp's original sanitize_field only
    // covered the unknown-action error string, so a profile name/path
    // containing '|' could inject a synthetic column into the pipe-delimited
    // output. Every field this renderer emits must be sanitised.
    ProfileInfo info{std::string{kAliceSid}, "ali|ce", "C:\\Users\\a|b", HiveState::loaded};
    auto row = render_profile_row(info);
    CHECK(row.find("ali|ce") == std::string::npos);
    CHECK(row == std::string{kAliceSid} + "|ali_ce|C:\\Users\\a_b|loaded");
}

TEST_CASE("render_profile_row: exhaustive over every HiveState", "[profiles]") {
    CHECK(hive_state_name(HiveState::loaded) == "loaded");
    CHECK(hive_state_name(HiveState::loaded_classes_only) == "loaded_classes_only");
    CHECK(hive_state_name(HiveState::not_loaded) == "not_loaded");
}
