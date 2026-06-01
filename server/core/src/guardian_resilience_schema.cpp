/// @file guardian_resilience_schema.cpp — see guardian_resilience_schema.hpp.

#include "guardian_resilience_schema.hpp"

#include <nlohmann/json.hpp>

#include <algorithm> // std::sort
#include <array>
#include <cctype>   // std::tolower
#include <charconv> // std::from_chars
#include <cstdint>

namespace yuzu::server::guardian {
namespace {

// Mode bitmask — one bit per ResilienceMode so a param can declare the set of
// modes it is load-bearing for.
enum ModeBit : unsigned {
    kPersist = 1u << 0,
    kBackoff = 1u << 1,
    kBounded = 1u << 2,
    kAll = kPersist | kBackoff | kBounded,
};

struct ParamSpec {
    std::string_view key;
    bool is_mode;          ///< the `mode` enum key (not numeric)
    std::uint64_t min;     ///< inclusive lower bound (numeric keys)
    std::uint64_t max;     ///< inclusive upper bound (numeric keys)
    std::uint64_t dflt;    ///< default when absent (numeric keys)
    unsigned modes;        ///< modes this param is load-bearing for
    std::string_view desc; ///< schema description
};

// ── THE single source of truth ──────────────────────────────────────────────
// Key names MUST equal the agent's resilience_keys (cross-check test enforces).
// Caps are overflow-safe: the agent multiplies the `*_s` keys by 1000 into a
// uint64 ms, and the 1-year second-cap (31 536 000) × 1000 stays far below
// UINT64_MAX — so an authored value can never wrap to a tiny window.
constexpr std::array<ParamSpec, 7> kParams = {{
    {"mode", true, 0, 0, 0, kAll, "Enforcement retry policy (design §8.5)."},
    {"max_attempts", false, 1, 1'000'000, 5, kBounded,
     "Bounded: consecutive re-fix cycles in one fight before giving up. Must be >= 1 "
     "(0 would never give up — use mode 'persist' for that)."},
    {"quiet_reset_s", false, 1, 31'536'000, 60, kBackoff | kBounded,
     "Sustained no-drift gap (seconds) that resets the Bounded counter / Backoff exponent."},
    {"resume_after_s", false, 0, 31'536'000, 0, kBounded,
     "Bounded: auto-resume remediation this long (seconds) after giving up. 0 = stay "
     "given up until an admin re-pushes."},
    {"backoff_initial_ms", false, 1, 86'400'000, 1000, kBackoff,
     "Backoff: initial delay (ms) between re-enforcements; doubles up to backoff_max_ms. "
     "Must be <= backoff_max_ms."},
    {"backoff_max_ms", false, 1, 86'400'000, 60000, kBackoff,
     "Backoff: cap (ms) on the exponential re-enforcement delay."},
    {"event_debounce_ms", false, 0, 3'600'000, 1000, kAll,
     "Collapse-with-count window (ms) for repeated drift events. 0 = emit every event."},
}};

const ParamSpec& spec_for(std::string_view key) {
    for (const auto& sp : kParams)
        if (sp.key == key)
            return sp;
    return kParams[0]; // unreachable for our fixed keys
}

unsigned parse_mode_bit(std::string_view s) {
    std::string l;
    l.reserve(s.size());
    for (char c : s)
        l.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    if (l == "persist")
        return kPersist;
    if (l == "backoff")
        return kBackoff;
    if (l == "bounded")
        return kBounded;
    return 0;
}

std::string_view mode_token(unsigned bit) {
    switch (bit) {
    case kBackoff:
        return "backoff";
    case kBounded:
        return "bounded";
    default:
        return "persist";
    }
}

// Lenient extraction: a clean non-negative integer from a JSON number OR a
// numeric string. Rejects negatives, fractions, garbage, and out-of-range
// (from_chars reports overflow). nullopt = not a usable whole number.
std::optional<std::uint64_t> as_uint(const nlohmann::json& v) {
    if (v.is_number_unsigned())
        return v.get<std::uint64_t>();
    if (v.is_number_integer()) {
        auto i = v.get<std::int64_t>();
        return i < 0 ? std::nullopt : std::optional<std::uint64_t>{static_cast<std::uint64_t>(i)};
    }
    if (v.is_number_float())
        return std::nullopt; // fractional not allowed
    if (v.is_string()) {
        const std::string& s = v.get_ref<const nlohmann::json::string_t&>();
        if (s.empty())
            return std::nullopt;
        std::uint64_t out{};
        auto [p, ec] = std::from_chars(s.data(), s.data() + s.size(), out);
        if (ec != std::errc{} || p != s.data() + s.size())
            return std::nullopt;
        return out;
    }
    return std::nullopt;
}

// Effective value of a numeric key for the chosen mode: the (already
// canonicalised) present value, else the table default.
std::uint64_t effective(const nlohmann::json& params, const ParamSpec& sp) {
    if (auto it = params.find(std::string(sp.key)); it != params.end())
        if (auto v = as_uint(*it))
            return *v;
    return sp.dflt;
}

} // namespace

std::optional<ResilienceParamError>
validate_and_canonicalize_resilience_params(nlohmann::json& params) {
    if (!params.is_object())
        return std::nullopt; // no resilience params to validate

    // 1. mode — the discriminator. Absent → Persist (the safe default).
    unsigned mode_bit = kPersist;
    if (auto it = params.find("mode"); it != params.end()) {
        if (!it->is_string())
            return ResilienceParamError{
                "resilience 'mode' must be a string (persist|backoff|bounded)",
                "set mode to one of: persist, backoff, bounded"};
        mode_bit = parse_mode_bit(it->get_ref<const nlohmann::json::string_t&>());
        if (mode_bit == 0)
            return ResilienceParamError{
                "resilience 'mode' must be persist|backoff|bounded, got '" +
                    it->get<std::string>() + "'",
                "set mode to one of: persist, backoff, bounded"};
        *it = std::string(mode_token(mode_bit)); // canonical lowercase token
    }

    // 2. numeric params: range-check + canonicalise the ones load-bearing for the
    //    chosen mode; pass through (untouched) any that are present but irrelevant
    //    to the mode (lenient-in — never 400 a Persist rule carrying backoff_*).
    for (const auto& sp : kParams) {
        if (sp.is_mode)
            continue;
        auto it = params.find(std::string(sp.key));
        if (it == params.end())
            continue; // absent → default (cross-field checks below use effective())
        if ((sp.modes & mode_bit) == 0)
            continue; // present but irrelevant to this mode → pass through
        auto val = as_uint(*it);
        if (!val)
            return ResilienceParamError{
                "resilience '" + std::string(sp.key) + "' must be a non-negative integer",
                "provide a whole number (" + std::to_string(sp.min) + "-" +
                    std::to_string(sp.max) + ")"};
        if (*val < sp.min || *val > sp.max)
            return ResilienceParamError{
                "resilience '" + std::string(sp.key) + "' (" + std::to_string(*val) +
                    ") out of range [" + std::to_string(sp.min) + ", " +
                    std::to_string(sp.max) + "]",
                "use a value between " + std::to_string(sp.min) + " and " +
                    std::to_string(sp.max)};
        *it = std::to_string(*val); // canonical decimal string
    }

    // 3. cross-field rule that no single-param range can express: Backoff's
    //    initial delay must not exceed its cap. Uses effective (present-or-default)
    //    values so initial=100000 against the default max=60000 is still caught.
    if (mode_bit == kBackoff) {
        const std::uint64_t init = effective(params, spec_for("backoff_initial_ms"));
        const std::uint64_t mx = effective(params, spec_for("backoff_max_ms"));
        if (init > mx)
            return ResilienceParamError{
                "backoff_initial_ms (" + std::to_string(init) +
                    ") must be <= backoff_max_ms (" + std::to_string(mx) + ")",
                "lower backoff_initial_ms or raise backoff_max_ms"};
    }
    return std::nullopt;
}

nlohmann::json resilience_params_schema() {
    using nlohmann::json;
    auto modes_of = [](unsigned m) {
        json a = json::array();
        if (m & kPersist)
            a.push_back("persist");
        if (m & kBackoff)
            a.push_back("backoff");
        if (m & kBounded)
            a.push_back("bounded");
        return a;
    };

    json props = json::object();
    for (const auto& sp : kParams) {
        if (sp.is_mode) {
            props[std::string(sp.key)] = {
                {"type", "string"},
                {"enum", json::array({"persist", "backoff", "bounded"})},
                {"default", "persist"},
                {"description", std::string(sp.desc)},
            };
            continue;
        }
        // Lenient-in: a numeric param is accepted as a JSON integer OR a numeric
        // string; minimum/maximum document the bound for the integer form.
        props[std::string(sp.key)] = {
            {"type", json::array({"integer", "string"})},
            {"minimum", sp.min},
            {"maximum", sp.max},
            {"default", sp.dflt},
            {"description", std::string(sp.desc)},
            {"x-applies-to-modes", modes_of(sp.modes)}, // machine-discoverable relevance
        };
    }

    return json{
        {"$schema", "https://json-schema.org/draft/2020-12/schema"},
        {"title", "Guardian resilience policy"},
        {"type", "object"},
        {"description",
         "Per-rule enforcement retry policy carried in remediation.params (design §8.5). "
         "Lenient-in / canonical-out: only the chosen mode's load-bearing params are "
         "enforced; values are stored canonical (mode lowercased, numerics as decimal "
         "strings). Backoff additionally requires backoff_initial_ms <= backoff_max_ms."},
        {"properties", std::move(props)},
        {"additionalProperties", true}, // other remediation params may coexist
    };
}

std::vector<std::string_view> resilience_param_keys() {
    std::vector<std::string_view> keys;
    keys.reserve(kParams.size());
    for (const auto& sp : kParams)
        keys.push_back(sp.key);
    std::sort(keys.begin(), keys.end());
    return keys;
}

} // namespace yuzu::server::guardian
