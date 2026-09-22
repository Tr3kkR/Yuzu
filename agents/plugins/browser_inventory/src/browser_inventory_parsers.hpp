/**
 * browser_inventory_parsers.hpp — pure, portable JSON parsers for the
 * Chromium-family profile file shape (Google Chrome / Microsoft Edge /
 * other Chromium forks all share the "Local State", "Preferences" and
 * "Secure Preferences" file layout). No OS read, no filesystem access, no
 * subprocess: every function here takes an already-loaded file's text and
 * returns a row model. The per-OS leg TUs (browser_inventory_linux.cpp /
 * _macos.cpp / _win.cpp) own locating and reading those files; this header
 * owns interpreting their bytes.
 *
 * PRIVACY CONTRACT (binding for this whole plugin): a row emitted from
 * these parsers NEVER carries an account identifier -- no user_name, no
 * gaia_id, no e-mail address, no browsing history, no cookies, no
 * bookmarks. This is enforced structurally: BrowserProfileRow simply has
 * no user_name/gaia_id field, so there is no code path that could put one
 * on the wire. See test_browser_inventory_parsers.cpp for a fixture that
 * carries those keys in its input and asserts they never reach a row.
 *
 * extensions.settings HANDLING: real-world Chromium keeps the per-extension
 * install/enable state in `Secure Preferences` on the platforms that
 * support OS-level file protection (confirmed for Microsoft Edge/Windows
 * by the REAL CAPTURE fixture under tests/unit/fixtures/wave10/
 * browser_inventory/edge/ -- see that directory's provenance.txt "which
 * file carries extensions.settings" section: Secure Preferences has 53
 * entries under extensions.settings, Preferences has an `extensions` key
 * but no `.settings` under it at all). extension_state_from_prefs() takes
 * both files' text and prefers Secure Preferences, falling back to
 * Preferences on any OS/build where the split doesn't hold. Its own
 * `protection` tree (a MAC/HMAC over the profile) is read by neither
 * caller here nor this header -- it is never parsed, let alone validated;
 * an attacker-writable Secure Preferences is exactly as trustworthy as any
 * other local, unprivileged filesystem write on this host, which is the
 * same trust model every other local-inventory plugin in this tree
 * operates under.
 *
 * JSON-parse idiom copied from agents/plugins/asset_tags/src/
 * asset_tags_plugin.cpp:87-109 (try/catch around nlohmann::json::parse, no
 * rethrow; `.contains()` guards before indexing; `.value("key", default)`
 * for optional fields) -- with one addition: this header's callers need to
 * tell a "found nothing" empty result apart from "the JSON didn't parse at
 * all", so parsing failure is surfaced as std::nullopt rather than swallowed
 * silently. See each function's doc comment for its exact nullopt contract.
 */
#pragma once

#include <nlohmann/json.hpp>

#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::browser_inventory {

/// One row of the "profiles" action. Deliberately has no user_name/gaia_id
/// field -- see the file banner's PRIVACY CONTRACT.
struct BrowserProfileRow {
    std::string profile_dir;  // the info_cache key, e.g. "Default", "Profile 1"
    std::string display_name; // info_cache[dir].name -- a user-editable
                               // label ("Profile 1", "Work"), never an
                               // account/real name field. "-" if absent.
    bool active{false};       // dir == profile.last_used
    bool ephemeral{false};    // info_cache[dir].is_ephemeral, default false
};

/// One row of the "extensions" action, keyed by 32-char extension id in the
/// map extension_state_from_prefs() returns.
struct ExtensionStateRow {
    // "enabled" (state==1), "disabled" (state==0), or "unmodelled" (state
    // missing or any other integer -- Chromium's Extension::State enum has
    // additional values this plugin does not attempt to interpret).
    std::string state{"unmodelled"};
    std::string from_webstore{"-"}; // "yes" / "no" / "-" (field absent)
    std::string name{"-"};          // manifest.name, "-" if absent
    std::string version{"-"};       // manifest.version, "-" if absent
};

namespace detail {

/// Parses `text` as JSON. Returns std::nullopt for an empty string (file
/// absent -- not a parse failure) as well as for genuinely malformed JSON,
/// but distinguishes the two via `out_malformed` so callers can tell
/// "absent" from "present but broken".
inline std::optional<nlohmann::json> try_parse(std::string_view text, bool& out_malformed) {
    out_malformed = false;
    if (text.empty())
        return std::nullopt;
    try {
        return nlohmann::json::parse(text);
    } catch (...) {
        out_malformed = true;
        return std::nullopt;
    }
}

/// Extracts extensions.settings as an id -> ExtensionStateRow map from an
/// already-parsed root object. An absent/non-object `extensions` or
/// `extensions.settings` key is a legitimate "no extension state in this
/// file" result (empty map), never an error.
inline std::map<std::string, ExtensionStateRow> extract_settings(const nlohmann::json& root) {
    std::map<std::string, ExtensionStateRow> out;
    if (!root.is_object() || !root.contains("extensions") || !root["extensions"].is_object())
        return out;
    const auto& ext = root["extensions"];
    if (!ext.contains("settings") || !ext["settings"].is_object())
        return out;
    for (const auto& [id, entry] : ext["settings"].items()) {
        if (!entry.is_object())
            continue;
        ExtensionStateRow row;
        if (entry.contains("state") && entry["state"].is_number_integer()) {
            const int state = entry["state"].get<int>();
            row.state = state == 1 ? "enabled" : state == 0 ? "disabled" : "unmodelled";
        } // else stays "unmodelled" (the struct default)
        if (entry.contains("from_webstore") && entry["from_webstore"].is_boolean())
            row.from_webstore = entry["from_webstore"].get<bool>() ? "yes" : "no";
        // else stays "-" (the struct default)
        if (entry.contains("manifest") && entry["manifest"].is_object()) {
            const auto& mf = entry["manifest"];
            row.name = mf.value("name", std::string{"-"});
            if (row.name.empty())
                row.name = "-";
            row.version = mf.value("version", std::string{"-"});
            if (row.version.empty())
                row.version = "-";
        }
        out.emplace(id, std::move(row));
    }
    return out;
}

} // namespace detail

/// Parses a Chromium/Edge "Local State" file and returns one row per
/// profile directory under profile.info_cache. `local_state_text` may be
/// empty (file absent) -- that yields an empty vector, not nullopt.
///
/// std::nullopt means the JSON did not parse at all (malformed input) --
/// the caller reports CONSTRAINED. An empty vector is a legitimate "valid
/// JSON, no profiles" or "file absent" result, never a failure.
[[nodiscard]] inline std::optional<std::vector<BrowserProfileRow>>
profiles_from_local_state(std::string_view local_state_text) {
    bool malformed = false;
    auto parsed = detail::try_parse(local_state_text, malformed);
    if (malformed)
        return std::nullopt;
    if (!parsed.has_value())
        return std::vector<BrowserProfileRow>{}; // absent file

    std::vector<BrowserProfileRow> rows;
    const auto& root = *parsed;
    if (!root.is_object() || !root.contains("profile") || !root["profile"].is_object())
        return rows;
    const auto& profile = root["profile"];
    const std::string last_used = profile.value("last_used", std::string{});
    if (!profile.contains("info_cache") || !profile["info_cache"].is_object())
        return rows;

    // nlohmann::json's default object type is ordered by key (std::map),
    // so this iteration -- and therefore row order -- is deterministic.
    for (const auto& [dir, info] : profile["info_cache"].items()) {
        if (!info.is_object())
            continue;
        BrowserProfileRow row;
        row.profile_dir = dir;
        row.display_name = info.value("name", std::string{});
        if (row.display_name.empty())
            row.display_name = "-";
        row.active = (dir == last_used);
        row.ephemeral = info.value("is_ephemeral", false);
        rows.push_back(std::move(row));
    }
    return rows;
}

/// Parses `extensions.settings` from Secure Preferences (preferred) and/or
/// Preferences (fallback), merging with Secure Preferences precedence per
/// extension id. Either text may be empty (that file doesn't exist on this
/// platform/profile) -- pass an empty string, not a guess.
///
/// std::nullopt only when every NON-EMPTY input text failed to parse as
/// JSON (both malformed, or the one non-empty text is malformed) -- the
/// caller reports CONSTRAINED. Two empty strings (neither file present) is
/// a legitimate "no extension state available" result: an empty map, not
/// nullopt. The HMAC/`protection` tree in either file is never read.
[[nodiscard]] inline std::optional<std::map<std::string, ExtensionStateRow>>
extension_state_from_prefs(std::string_view secure_prefs_text, std::string_view prefs_text) {
    const bool secure_present = !secure_prefs_text.empty();
    const bool prefs_present = !prefs_text.empty();

    bool secure_malformed = false;
    bool prefs_malformed = false;
    auto secure_json = detail::try_parse(secure_prefs_text, secure_malformed);
    auto prefs_json = detail::try_parse(prefs_text, prefs_malformed);

    const bool secure_ok = secure_json.has_value();
    const bool prefs_ok = prefs_json.has_value();

    // nullopt iff at least one input was present and EVERY present input
    // failed to parse -- i.e. we have zero usable JSON to work from.
    const bool any_present = secure_present || prefs_present;
    const bool any_ok = secure_ok || prefs_ok;
    if (any_present && !any_ok)
        return std::nullopt;

    // Start from Preferences (fallback), then overlay Secure Preferences
    // (preferred) so its entries win on a shared id.
    std::map<std::string, ExtensionStateRow> merged;
    if (prefs_ok)
        merged = detail::extract_settings(*prefs_json);
    if (secure_ok) {
        auto from_secure = detail::extract_settings(*secure_json);
        for (auto& [id, row] : from_secure)
            merged[id] = std::move(row);
    }
    return merged;
}

} // namespace yuzu::browser_inventory
