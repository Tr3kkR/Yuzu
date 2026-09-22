/**
 * browser_inventory_parsers.hpp — pure, portable JSON parsers for the
 * Chromium-family profile file shape (Google Chrome / Microsoft Edge /
 * other Chromium forks all share the "Local State" file layout at the
 * browser root). No OS read, no filesystem access, no subprocess: every
 * function here takes an already-loaded file's text and returns a row
 * model. The per-OS leg TUs (browser_inventory_linux.cpp / _macos.cpp /
 * _win.cpp) own locating and reading those files; this header owns
 * interpreting their bytes.
 *
 * PRIVACY CONTRACT (binding for this whole plugin): a row built from this
 * header's parsers NEVER carries a browsing-account identifier -- no
 * gaia_id, no e-mail address, no Chromium info_cache user_name/gaia_name,
 * no browsing history, no cookies, no bookmarks. This is enforced
 * structurally: BrowserProfileRow simply has no such field, so no code
 * path in this header could put one on the wire. See
 * test_browser_inventory_parsers.cpp for a fixture that carries those keys
 * in its input and asserts they never reach a row.
 * EXCEPTION (decided 2026-09-22, not part of this contract): the Linux
 * leg's wire-row builder (browser_inventory_linux_parsers.hpp) prepends
 * the LOCAL OS/home-directory username to disambiguate profiles across
 * users sharing a machine -- that value never passes through this header
 * or BrowserProfileRow, and is not a browsing-account identifier.
 * No file inside a profile directory ("Preferences", "Secure Preferences",
 * "History", "Cookies", ...) is read by any caller of this header in this
 * release; the per-profile `extensions` action follows as its own PR.
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

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::browser_inventory {

/// One row of the "profiles" action. Deliberately has no gaia_id/e-mail/
/// info_cache user_name field -- see the file banner's PRIVACY CONTRACT.
/// (The Linux leg's wire row separately carries the LOCAL OS username --
/// added by browser_inventory_linux_parsers.hpp, never a field here.)
struct BrowserProfileRow {
    std::string profile_dir;  // the info_cache key, e.g. "Default", "Profile 1"
    std::string display_name; // info_cache[dir].name -- a user-editable
                               // label ("Profile 1", "Work"), never an
                               // account/real name field. "-" if absent.
    bool active{false};       // dir == profile.last_used
    bool ephemeral{false};    // info_cache[dir].is_ephemeral, default false
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

} // namespace yuzu::browser_inventory
