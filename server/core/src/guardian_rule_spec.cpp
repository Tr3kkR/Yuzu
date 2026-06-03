/// @file guardian_rule_spec.cpp — see guardian_rule_spec.hpp.

#include "guardian_rule_spec.hpp"

#include "guardian_resilience_schema.hpp"
#include "guardian_schema_registry.hpp" // supported_registry_hives / value_types

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <charconv>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server::guardian {
namespace {

// ASCII-lowercase copy for case-insensitive registry matching — registry hives,
// keys and value-type tokens are case-insensitive on Windows.
std::string ascii_lower(std::string_view s) {
    std::string out(s);
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

// True when an ENFORCE-mode registry write at `key` would land on a
// high-blast-radius persistence / privilege key. The agent performs this write
// with the deployment service account's privilege (SYSTEM in production) on every
// in-scope endpoint at once, so a single mis-scoped enforce rule aimed at one of
// these could change what boots — or what runs as SYSTEM — fleet-wide with no
// second check. Contract §6 made this denylist a hard gate before the enforce
// write path ships (H1). Over-blocking is deliberate: audit mode still observes
// these keys; only the *write* is refused. Match is case-insensitive on a
// separator-normalised path, so HKLM and HKCU autoruns are both covered. Returns
// the matched class (for the operator-facing error) or "" if the key is allowed.
std::string dangerous_enforce_key(std::string_view key) {
    std::string k = ascii_lower(key);
    for (auto& c : k)
        if (c == '/')
            c = '\\';
    struct Denied {
        std::string_view token;
        std::string_view why;
    };
    static constexpr Denied kDenied[] = {
        {"currentversion\\run", "an autorun key (Run / RunOnce / RunServices)"},
        {"image file execution options", "an Image File Execution Options key (debugger hijack)"},
        {"winlogon", "a Winlogon key (Userinit / Shell logon hijack)"},
        {"\\services\\", "a service-configuration key (ImagePath / Start / Type)"},
        {"\\policies\\", "a system / explorer policy key"},
        {"safeboot", "the SafeBoot configuration"},
        {"bootexecute", "the Session Manager BootExecute autorun"},
    };
    for (const auto& d : kDenied)
        if (k.find(d.token) != std::string::npos)
            return std::string(d.why);
    return {};
}

bool in_set(const std::vector<std::string_view>& set, const std::string& v) {
    return std::find(set.begin(), set.end(), v) != set.end();
}

// Whole-string non-negative integer? Rejects "123abc", "", "-1", "1.5" — mirrors
// the agent's hardened parse so the server boundary and the agent boundary agree
// on what a numeric param is (M1).
bool is_whole_u64(const std::string& s, std::uint64_t& out) {
    if (s.empty())
        return false;
    auto [p, ec] = std::from_chars(s.data(), s.data() + s.size(), out);
    return ec == std::errc{} && p == s.data() + s.size();
}

std::string str_param(const nlohmann::json& params, const char* k) {
    if (params.contains(k) && params[k].is_string())
        return params[k].get<std::string>();
    return {};
}

// Validate the assertion params against the published supported sets (H2), the
// enforce-write dangerous-key denylist (H1, contract §6) and basic file-assertion
// sanity (M1) — lenient where the agent is lenient, fail-loud where a value would
// arm a confidently-wrong guard (perpetual false drift / remediation.failed).
std::optional<ResilienceParamError>
validate_assertion_params(const std::string& assertion_type, const nlohmann::json& assertion,
                          const std::string& enforcement_mode) {
    const nlohmann::json params =
        (assertion.contains("params") && assertion["params"].is_object())
            ? assertion["params"]
            : nlohmann::json::object();

    if (assertion_type == "registry-value-equals") {
        const std::string hive = str_param(params, "hive");
        const std::string key = str_param(params, "key");
        const std::string value_type = str_param(params, "value_type");
        if (key.empty())
            return ResilienceParamError{
                "registry assertion requires a non-empty 'key'",
                "set assertion.params.key to the subkey path under the hive"};
        if (!in_set(supported_registry_hives(), hive))
            return ResilienceParamError{
                "unsupported registry hive '" + hive + "'",
                "use a hive published by GET /api/v1/guaranteed-state/schemas "
                "(HKLM, HKCU, HKCR, HKU)"};
        if (!in_set(supported_registry_value_types(), value_type))
            return ResilienceParamError{
                "unsupported registry value_type '" + value_type + "'",
                "use a value type published by GET /api/v1/guaranteed-state/schemas "
                "(REG_DWORD, REG_QWORD, REG_SZ, REG_EXPAND_SZ)"};
        if (enforcement_mode == "enforce")
            if (std::string why = dangerous_enforce_key(key); !why.empty())
                return ResilienceParamError{
                    "enforce-mode registry write to " + why + " is not permitted",
                    "author this Guard in audit mode (enforcement_mode=\"audit\") to observe "
                    "drift, or target a key outside the protected persistence / privilege set"};
        return std::nullopt;
    }

    if (assertion_type == "file-exists") {
        if (str_param(params, "path").empty())
            return ResilienceParamError{"file-exists assertion requires a non-empty 'path'",
                                        "set assertion.params.path to the absolute file path"};
        if (params.contains("expected") && params["expected"].is_string()) {
            const std::string e = params["expected"].get<std::string>();
            if (e != "present" && e != "absent")
                return ResilienceParamError{
                    "file-exists 'expected' must be 'present' or 'absent'",
                    "set assertion.params.expected to present or absent"};
        }
        return std::nullopt;
    }

    if (assertion_type == "file-hash-equals") {
        if (str_param(params, "path").empty())
            return ResilienceParamError{"file-hash-equals assertion requires a non-empty 'path'",
                                        "set assertion.params.path to the absolute file path"};
        const std::string h = str_param(params, "expected_hash");
        if (!h.empty() &&
            (h.size() != 64 ||
             !std::all_of(h.begin(), h.end(), [](unsigned char c) { return std::isxdigit(c); })))
            return ResilienceParamError{
                "expected_hash must be a 64-char SHA-256 hex digest (or empty)",
                "supply the 64-char hex digest, or leave it empty to baseline on arm"};
        // max_bytes / settle_ms are string-or-int on the wire; validate the
        // string form here (an integer passes through to the agent's bounded
        // parse). max_bytes=0 makes every covered file report <oversize>.
        std::uint64_t n = 0;
        if (params.contains("max_bytes") && params["max_bytes"].is_string() &&
            (!is_whole_u64(params["max_bytes"].get<std::string>(), n) || n == 0))
            return ResilienceParamError{
                "max_bytes must be a positive integer",
                "set assertion.params.max_bytes >= 1 (bytes), or omit it for the default cap"};
        if (params.contains("settle_ms") && params["settle_ms"].is_string() &&
            !is_whole_u64(params["settle_ms"].get<std::string>(), n))
            return ResilienceParamError{
                "settle_ms must be a non-negative integer",
                "set assertion.params.settle_ms in milliseconds, or omit it"};
        return std::nullopt;
    }

    // Unknown assertion type is not this validator's job to gate — the agent marks
    // an unknown assertion errored (G11). derive_rule_spec validates only the
    // types we publish in the schema catalog.
    return std::nullopt;
}

} // namespace

RuleSpecResult derive_rule_spec(const nlohmann::json& body, const std::string& name,
                                std::int64_t version, bool enabled,
                                const std::string& enforcement_mode) {
    RuleSpecResult out;

    auto json_block = [&](const char* key) -> nlohmann::json {
        if (body.contains(key) && body[key].is_object())
            return body[key];
        return nlohmann::json::object();
    };
    nlohmann::json spark = json_block("spark");
    nlohmann::json assertion = json_block("assertion");
    nlohmann::json remediation = json_block("remediation");
    const std::string spark_type = spark.value("type", std::string{});
    const std::string assertion_type = assertion.value("type", std::string{});

    const bool any_block = !spark.empty() || !assertion.empty() || !remediation.empty();
    const bool full = !spark_type.empty() && !assertion_type.empty();

    if (!full) {
        // A body carrying a structured block but not a complete spark+assertion
        // pair is rejected, NOT silently dropped (the silent-drop trap on update).
        // A body with no structured block at all is a legacy / metadata-only path
        // the caller owns.
        if (any_block)
            out.error = ResilienceParamError{
                "a structured Guard requires both a 'spark' and an 'assertion' block "
                "(each with a 'type')",
                "include spark.type and assertion.type, or omit all structured blocks for a "
                "metadata-only update"};
        return out;
    }

    // Validate the assertion params against the published supported sets (H2), the
    // enforce-write dangerous-key denylist (H1, contract §6) and file-assertion
    // sanity (M1) before building the spec. Rejected → HTTP 400 (A4 envelope).
    if (auto err = validate_assertion_params(assertion_type, assertion, enforcement_mode)) {
        out.error = std::move(err);
        return out;
    }

    // Detect-and-alert is the MVP default remediation.
    if (remediation.empty())
        remediation = {{"type", "alert-only"}, {"params", nlohmann::json::object()}};

    // C3b: validate + canonicalise the resilience policy in remediation.params.
    if (remediation.contains("params") && remediation["params"].is_object()) {
        if (auto err = validate_and_canonicalize_resilience_params(remediation["params"])) {
            out.error = std::move(err);
            return out;
        }
    }

    nlohmann::json spec;
    spec["name"] = name;
    spec["version"] = version;
    spec["enabled"] = enabled;
    spec["enforcement_mode"] = enforcement_mode;
    spec["spark"] = spark;
    spec["assertion"] = assertion;
    spec["remediation"] = remediation;

    out.structured = true;
    // Authoritative structured form. NOTE: a structured dump, not yet
    // JCS-canonicalised — full RFC-8785 canonicalisation lands with rule signing
    // (contract G3, deferred).
    out.spec_json = spec.dump();
    // yaml_source is a generated, never-parsed human-readable rendering (decision
    // 1). JSON is a valid YAML subset, so a header-commented pretty dump is honest.
    out.yaml_source =
        "# Guardian Guard (generated rendering — authoritative form is the structured spec)\n" +
        spec.dump(2) + "\n";
    return out;
}

} // namespace yuzu::server::guardian
