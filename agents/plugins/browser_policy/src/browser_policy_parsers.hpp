/**
 * browser_policy_parsers.hpp — the PURE policy-row model for browser_policy.
 *
 * Everything here is a free function over plain data: no OS calls, no file
 * or registry I/O, no logging. It compiles and is unit-tested on EVERY OS
 * (the Windows registry leg, the Linux JSON-file leg and the macOS plist leg
 * all feed the same PolicyRow/format_policy_row), which is the repo's
 * standing "pure core, thin shell" discipline (peripherals_parsers.hpp is the
 * sibling shape).
 *
 * WIRE ROW (one per configured policy, 9 pipe-delimited fields):
 *
 *   policy|<browser>|<level>|<scope>|<name>|<type>|<value>|<source>|<detail>
 *
 *   browser  chrome | chromium | edge                       (fixed vocabulary)
 *   level    mandatory | recommended                        (fixed vocabulary)
 *   scope    machine | user:<name>                          (<name> untrusted)
 *   name     the policy name exactly as the browser documents it
 *   type     bool | int | real | string | list | dict | null | unmodelled
 *   value    bool "true"/"false"; int/real as decimal text; string verbatim;
 *            list/dict as compact JSON text; null "null"; unmodelled "-"
 *   source   root-relative file (or registry key) the policy was read from
 *   detail   "-" normally; a short qualifier for an `unmodelled` value
 *            (`date`, `data`, `cf_type`, `too_deep`, ...), a degraded
 *            container (`nested_unmodelled`), or `nul_replaced` (appended,
 *            comma-joined, when any free-text field held an embedded NUL)
 *
 * Every free-text field goes through yuzu::util::safe_output_field
 * (sdk/include/yuzu/string_utils.hpp): a value ending in a backslash or
 * containing a pipe can never shift the field count on the server decoder
 * (server/core/src/result_parsing.hpp find_unescaped_pipe). The escaper is
 * intentionally lossy (backslash folds to '/'), which is acceptable for an
 * inventory display value. An embedded NUL byte is replaced by U+FFFD and
 * flagged in `detail`: the plugin ABI passes rows as C strings
 * (CommandContext::write_output), so a NUL would otherwise truncate the row
 * before its source/detail fields while still reporting success.
 *
 * NO PLACEHOLDER ROWS. A host with no managed policy (browser not installed,
 * no policy files, no Managed Preferences) reports ZERO rows and a clean OK
 * status; a read that could not be completed reports CONSTRAINED with a
 * reason instead (see legs.hpp). The two are never conflated: a failure must
 * never read as absent.
 *
 * TYPE MAPPING. Every JSON (and, in browser_policy_macos.hpp, CoreFoundation)
 * value maps into PolicyType, and anything the mapper does not model lands on
 * the literal PolicyType::Unmodelled ("unmodelled") — distinct from no data,
 * so a consumer can tell "policy present, value not representable" from "no
 * such policy".
 *
 * JSON PARSING follows the asset_tags_plugin.cpp:87-109 nlohmann idiom
 * (parse guarded against throwing, `.is_*()` type checks before typed
 * reads) with ONE deliberate override: asset_tags' `catch (...) {}` silently
 * resets to an empty state, which here would make a corrupt policy file read
 * as "no policy configured". A parse failure instead returns a failure token
 * the caller records as CONSTRAINED (ConstraintAccumulator).
 */
#pragma once

#include <yuzu/string_utils.hpp>

#include <nlohmann/json.hpp>

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::browser_policy {

// ── bounds ───────────────────────────────────────────────────────────────

/// A policy file larger than this is a constraint ("oversized"), never a
/// silently truncated (and therefore unparseable) read.
inline constexpr std::size_t kMaxPolicyFileBytes = 1024 * 1024;
/// Total rows one leg emits per run; beyond it the leg records `row_cap`.
inline constexpr std::size_t kMaxPolicyRows = 8192;
/// Directory entries examined per directory (walk_dir_capped cap).
inline constexpr std::size_t kMaxEntriesPerDir = 4096;
/// Container nesting the mapper will descend; deeper is a constraint
/// (bounds nlohmann's recursive dump() and the CF recursion alike).
inline constexpr int kMaxNestingDepth = 32;

/// The walk bounds as a parameter so the unit suite can prove the saturation
/// paths (`row_cap`, oversized) at small, machine-independent sizes instead of
/// materializing thousands of files. Production always passes the defaults.
struct WalkLimits {
    std::size_t max_rows = kMaxPolicyRows;
    std::size_t max_entries_per_dir = kMaxEntriesPerDir;
    std::size_t max_file_bytes = kMaxPolicyFileBytes;
};

// ── failure tokens (string literals: `<os>:<detail>`) ────────────────────

inline constexpr std::string_view kTokenJsonUnparseable = "linux:json_unparseable";
inline constexpr std::string_view kTokenJsonNotObject = "linux:json_not_object";
inline constexpr std::string_view kTokenJsonTooDeep = "linux:json_too_deep";

// ── fixed vocabularies ───────────────────────────────────────────────────

enum class Browser { chrome, chromium, edge };
enum class Level { mandatory, recommended };
enum class PolicyType { Bool, Int, Real, String, List, Dict, Null, Unmodelled };

[[nodiscard]] constexpr std::string_view browser_token(Browser b) noexcept {
    switch (b) {
    case Browser::chrome:   return "chrome";
    case Browser::chromium: return "chromium";
    case Browser::edge:     return "edge";
    }
    return "chrome";
}

[[nodiscard]] constexpr std::string_view level_token(Level l) noexcept {
    switch (l) {
    case Level::mandatory:   return "mandatory";
    case Level::recommended: return "recommended";
    }
    return "mandatory";
}

[[nodiscard]] constexpr std::string_view type_token(PolicyType t) noexcept {
    switch (t) {
    case PolicyType::Bool:       return "bool";
    case PolicyType::Int:        return "int";
    case PolicyType::Real:       return "real";
    case PolicyType::String:     return "string";
    case PolicyType::List:       return "list";
    case PolicyType::Dict:       return "dict";
    case PolicyType::Null:       return "null";
    case PolicyType::Unmodelled: return "unmodelled";
    }
    return "unmodelled";
}

// ── the row model ────────────────────────────────────────────────────────

struct PolicyValue {
    PolicyType type = PolicyType::Unmodelled;
    std::string value;  // see the wire-row legend above
    std::string detail; // empty -> "-" on the wire
};

struct PolicyRow {
    Browser browser = Browser::chrome;
    Level level = Level::mandatory;
    std::string scope; // "machine" | "user:<name>"
    std::string name;
    PolicyValue value;
    std::string source;
};

[[nodiscard]] inline std::string machine_scope() { return "machine"; }
[[nodiscard]] inline std::string user_scope(std::string_view user) {
    return "user:" + std::string{user};
}

/// The literal "policy present, value not representable" outcome.
[[nodiscard]] inline PolicyValue unmodelled_value(std::string_view detail) {
    return PolicyValue{PolicyType::Unmodelled, "-", std::string{detail}};
}

namespace detail {
/// safe_output_field plus NUL handling: every embedded NUL becomes U+FFFD
/// and sets `nul_seen` (see the header note on C-string transport).
[[nodiscard]] inline std::string wire_field(std::string_view value, bool& nul_seen) {
    const std::string escaped = yuzu::util::safe_output_field(value);
    if (escaped.find('\0') == std::string::npos)
        return escaped;
    std::string out;
    out.reserve(escaped.size() + 8);
    for (char c : escaped) {
        if (c == '\0') {
            out += "\xEF\xBF\xBD";
            nul_seen = true;
        } else {
            out += c;
        }
    }
    return out;
}
} // namespace detail

/// Formats one row (no trailing newline: append_output() adds the separator).
/// The result never contains a NUL byte.
[[nodiscard]] inline std::string format_policy_row(const PolicyRow& r) {
    bool nul = false;
    std::string out = "policy|";
    out += browser_token(r.browser);
    out += '|';
    out += level_token(r.level);
    out += '|';
    out += detail::wire_field(r.scope, nul);
    out += '|';
    out += detail::wire_field(r.name, nul);
    out += '|';
    out += type_token(r.value.type);
    out += '|';
    out += detail::wire_field(r.value.value, nul);
    out += '|';
    out += detail::wire_field(r.source, nul);
    out += '|';
    std::string det = r.value.detail.empty() ? std::string{} : detail::wire_field(r.value.detail, nul);
    if (nul)
        det += det.empty() ? "nul_replaced" : ",nul_replaced";
    out += det.empty() ? std::string{"-"} : det;
    return out;
}

// ── JSON policy text (Linux managed/recommended files) ───────────────────

namespace detail {
/// Compact dump that can never throw on invalid UTF-8 inside a string value
/// (a hostile or mis-encoded policy file must not abort the leg).
[[nodiscard]] inline std::string dump_json(const nlohmann::json& j) {
    return j.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
}
} // namespace detail

/// Maps one parsed JSON value onto the type enum. Total: every nlohmann
/// value type lands on a PolicyType, with Unmodelled as the explicit
/// catch-all (only `binary`/`discarded` reach it — neither can come out of
/// a text parse, so the branch is defensive, not a data-loss path).
[[nodiscard]] inline PolicyValue json_to_policy_value(const nlohmann::json& j) {
    if (j.is_boolean())
        return {PolicyType::Bool, j.get<bool>() ? "true" : "false", {}};
    if (j.is_number_integer()) // signed and unsigned
        return {PolicyType::Int, detail::dump_json(j), {}};
    if (j.is_number_float())
        return {PolicyType::Real, detail::dump_json(j), {}};
    if (j.is_string())
        return {PolicyType::String, j.get<std::string>(), {}};
    if (j.is_array())
        return {PolicyType::List, detail::dump_json(j), {}};
    if (j.is_object())
        return {PolicyType::Dict, detail::dump_json(j), {}};
    if (j.is_null())
        return {PolicyType::Null, "null", {}};
    return unmodelled_value("json_type");
}

struct JsonPolicyParse {
    std::vector<PolicyRow> rows;
    /// Set (to one of the kToken* literals) when the text could not be read
    /// as a policy object; `rows` is then empty and the caller MUST record
    /// the failure — never treat it as "no policies".
    std::optional<std::string_view> failure;
};

/// Parses one policy JSON file's text into rows, one per top-level key,
/// sorted by name (nlohmann objects are key-ordered). `//` and block
/// comments are tolerated (Chromium's file policy loader accepts them).
/// Top-level must be an object; nesting deeper than kMaxNestingDepth is a
/// constraint, enforced through the parser callback so the deep value is
/// never materialised.
[[nodiscard]] inline JsonPolicyParse
rows_from_json_policy_text(std::string_view text, Browser browser, Level level,
                           std::string_view scope, std::string_view source) {
    JsonPolicyParse out;
    bool too_deep = false;
    nlohmann::json doc;
    try {
        doc = nlohmann::json::parse(
            text.begin(), text.end(),
            [&too_deep](int depth, nlohmann::json::parse_event_t event, nlohmann::json&) {
                if ((event == nlohmann::json::parse_event_t::object_start ||
                     event == nlohmann::json::parse_event_t::array_start) &&
                    depth >= kMaxNestingDepth) {
                    too_deep = true;
                    return false;
                }
                return true;
            },
            /*allow_exceptions=*/false, /*ignore_comments=*/true);
    } catch (...) {
        out.failure = kTokenJsonUnparseable;
        return out;
    }
    if (too_deep) {
        out.failure = kTokenJsonTooDeep;
        return out;
    }
    if (doc.is_discarded()) {
        out.failure = kTokenJsonUnparseable;
        return out;
    }
    if (!doc.is_object()) {
        out.failure = kTokenJsonNotObject;
        return out;
    }
    try {
        for (const auto& [key, val] : doc.items()) {
            PolicyRow row;
            row.browser = browser;
            row.level = level;
            row.scope = std::string{scope};
            row.name = key;
            row.value = json_to_policy_value(val);
            row.source = std::string{source};
            out.rows.push_back(std::move(row));
        }
    } catch (...) {
        out.rows.clear();
        out.failure = kTokenJsonUnparseable;
    }
    return out;
}

} // namespace yuzu::browser_policy
