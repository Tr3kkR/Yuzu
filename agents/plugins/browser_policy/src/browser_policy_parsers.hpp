/**
 * browser_policy_parsers.hpp — the PURE policy-row model for browser_policy.
 *
 * Everything here is a free function over plain data: no OS calls, no file
 * or registry I/O, no logging. It compiles and is unit-tested on EVERY OS
 * (the Linux JSON-file leg feeds PolicyRow/format_policy_row today; the
 * planned Windows registry and macOS plist legs will feed the same model),
 * which is the repo's standing "pure core, thin shell" discipline
 * (peripherals_parsers.hpp is the sibling shape).
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
 *            container (`nested_unmodelled`), or `nul_replaced` /
 *            `utf8_replaced` (appended, comma-joined, when any free-text
 *            field held an embedded NUL / a byte that is not valid UTF-8)
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
 * VALID UTF-8 ONLY. The command output travels in a protobuf `string` field,
 * and the receiver rejects the WHOLE response if any byte in it is not valid
 * UTF-8. JSON keys and values are validated by the parser, but a Linux file
 * name is arbitrary bytes and lands in `source`, so every free-text field is
 * repaired (repair_utf8: each offending byte becomes U+FFFD, flagged in
 * `detail`) before it is written.
 *
 * NO PLACEHOLDER ROWS. A host with no managed policy (browser not installed,
 * no policy files) reports ZERO rows and a clean OK status; a read that could
 * not be completed reports CONSTRAINED with a reason instead (see legs.hpp),
 * and a PLANNED leg that has not shipped reports UNAVAILABLE with an
 * `<os>:planned` reason (mark_result_planned). The three are never conflated:
 * a failure, or a host that was not inspected, must never read as absent.
 *
 * TYPE MAPPING. Every JSON value maps into PolicyType (the planned legs' native
 * registry/plist values will map into the same enum), and anything the mapper
 * does not model lands on the literal PolicyType::Unmodelled ("unmodelled") —
 * distinct from no data, so a consumer can tell "policy present, value not
 * representable" from "no such policy".
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
/// Total bytes of policy-file content one leg reads per run; beyond it the leg
/// records `byte_cap`. The per-file, per-directory and row caps are independent
/// and their product is far too large to be a real bound (thousands of files at
/// the per-file cap), so this is the one that bounds the run's I/O, parse work
/// and retained row text.
inline constexpr std::size_t kMaxPolicyTotalBytes = 16 * 1024 * 1024;
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
    std::size_t max_total_bytes = kMaxPolicyTotalBytes;
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
/// Strict UTF-8 repair: copies every well-formed sequence (Unicode Table 3-7:
/// no overlong forms, no surrogates, nothing above U+10FFFF) and replaces each
/// byte that does not begin or continue one with U+FFFD, setting `replaced`.
/// yuzu::util::sanitize_utf8 is deliberately NOT used: it only catches lone and
/// truncated bytes and passes overlong, surrogate and out-of-range sequences,
/// all of which the protobuf transport rejects.
[[nodiscard]] inline std::string repair_utf8(std::string_view s, bool& replaced) {
    const auto in_range = [&s](std::size_t i, unsigned lo, unsigned hi) {
        return i < s.size() && static_cast<unsigned char>(s[i]) >= lo &&
               static_cast<unsigned char>(s[i]) <= hi;
    };
    const auto cont = [&in_range](std::size_t i) { return in_range(i, 0x80, 0xBF); };
    std::string out;
    out.reserve(s.size());
    for (std::size_t i = 0; i < s.size();) {
        const auto c = static_cast<unsigned char>(s[i]);
        std::size_t n = 0; // length of the well-formed sequence starting here; 0 = none
        if (c < 0x80) {
            n = 1;
        } else if (c >= 0xC2 && c <= 0xDF) {
            n = cont(i + 1) ? 2 : 0;
        } else if (c == 0xE0) {
            n = in_range(i + 1, 0xA0, 0xBF) && cont(i + 2) ? 3 : 0;
        } else if (c == 0xED) {
            n = in_range(i + 1, 0x80, 0x9F) && cont(i + 2) ? 3 : 0; // not a surrogate
        } else if (c >= 0xE1 && c <= 0xEF) {
            n = cont(i + 1) && cont(i + 2) ? 3 : 0;
        } else if (c == 0xF0) {
            n = in_range(i + 1, 0x90, 0xBF) && cont(i + 2) && cont(i + 3) ? 4 : 0;
        } else if (c >= 0xF1 && c <= 0xF3) {
            n = cont(i + 1) && cont(i + 2) && cont(i + 3) ? 4 : 0;
        } else if (c == 0xF4) {
            n = in_range(i + 1, 0x80, 0x8F) && cont(i + 2) && cont(i + 3) ? 4 : 0; // <= U+10FFFF
        }
        if (n == 0) {
            out += "\xEF\xBF\xBD";
            replaced = true;
            ++i;
        } else {
            out.append(s.substr(i, n));
            i += n;
        }
    }
    return out;
}

/// safe_output_field plus the two transport repairs: every byte that is not
/// valid UTF-8 becomes U+FFFD and sets `utf8_seen`; every embedded NUL becomes
/// U+FFFD and sets `nul_seen` (see the header notes on the transport).
[[nodiscard]] inline std::string wire_field(std::string_view value, bool& nul_seen,
                                            bool& utf8_seen) {
    const std::string repaired = repair_utf8(value, utf8_seen);
    const std::string escaped = yuzu::util::safe_output_field(repaired);
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
    bool utf8 = false;
    std::string out = "policy|";
    out += browser_token(r.browser);
    out += '|';
    out += level_token(r.level);
    out += '|';
    out += detail::wire_field(r.scope, nul, utf8);
    out += '|';
    out += detail::wire_field(r.name, nul, utf8);
    out += '|';
    out += type_token(r.value.type);
    out += '|';
    out += detail::wire_field(r.value.value, nul, utf8);
    out += '|';
    out += detail::wire_field(r.source, nul, utf8);
    out += '|';
    std::string det =
        r.value.detail.empty() ? std::string{} : detail::wire_field(r.value.detail, nul, utf8);
    if (nul)
        det += det.empty() ? "nul_replaced" : ",nul_replaced";
    if (utf8)
        det += det.empty() ? "utf8_replaced" : ",utf8_replaced";
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
