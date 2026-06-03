/**
 * test_guardian_resilience_schema.cpp — C3b server-side resilience param
 * validation + the published JSON Schema catalog (guardian_resilience_schema.hpp
 * / guardian_schema_registry.hpp).
 *
 * The DRIFT GUARD that matters: the param-spec table is the single source for
 * BOTH the validator and the schema, and the final TEST_CASE binds that table's
 * key set to the agent's resilience_keys (the contract G9 schema↔handler
 * cross-check). A rename on either side fails here. This file is the only place
 * the server test binary reaches into the agent include tree — header-only
 * constexpr, no link (see tests/meson.build).
 */

#include "guardian_resilience_schema.hpp"
#include "guardian_rule_spec.hpp" // derive_rule_spec + dangerous-key denylist (H1)
#include "guardian_schema_registry.hpp"

#include <yuzu/agent/guard_registry.hpp>      // registry_support::kHives / kValueTypes (cross-check)
#include <yuzu/agent/resilience_strategy.hpp> // resilience_keys (cross-check)

#include <catch2/catch_test_macros.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <string>
#include <string_view>
#include <vector>

using namespace yuzu::server::guardian;
using nlohmann::json;

namespace {
// Validate a params object built from a JSON literal; return the (mutated)
// params plus whether it was accepted.
struct Outcome {
    bool ok;
    std::string message;
    json params;
};
Outcome run(json params) {
    auto err = validate_and_canonicalize_resilience_params(params);
    return {!err.has_value(), err ? err->message : std::string{}, std::move(params)};
}
} // namespace

TEST_CASE("resilience validate: empty / persist defaults accepted", "[guardian][resilience][validate]") {
    CHECK(run(json::object()).ok);
    CHECK(run(json{{"mode", "persist"}}).ok);
    // mode canonicalised to lowercase token
    auto o = run(json{{"mode", "PERSIST"}});
    CHECK(o.ok);
    CHECK(o.params["mode"] == "persist");
}

TEST_CASE("resilience validate: mode must be a known token", "[guardian][resilience][validate]") {
    CHECK_FALSE(run(json{{"mode", "nonsense"}}).ok);
    CHECK_FALSE(run(json{{"mode", 3}}).ok); // not a string
    auto o = run(json{{"mode", "Backoff"}});
    CHECK(o.ok);
    CHECK(o.params["mode"] == "backoff");
}

TEST_CASE("resilience validate: Bounded max_attempts bounds", "[guardian][resilience][validate][bounded]") {
    // 0 degenerates to never-give-up (== Persist) — rejected (min 1).
    CHECK_FALSE(run(json{{"mode", "bounded"}, {"max_attempts", 0}}).ok);
    // absent → default 5, accepted.
    CHECK(run(json{{"mode", "bounded"}}).ok);
    // present + in range → accepted and canonicalised to a decimal string.
    auto o = run(json{{"mode", "bounded"}, {"max_attempts", 3}});
    CHECK(o.ok);
    CHECK(o.params["max_attempts"] == "3");
    // numeric string accepted equally (lenient-in).
    CHECK(run(json{{"mode", "bounded"}, {"max_attempts", "3"}}).ok);
}

TEST_CASE("resilience validate: quiet_reset_s=0 rejected when relevant",
          "[guardian][resilience][validate][bounded]") {
    // quiet_reset_s=0 → quiet always true → never gives up; min is 1.
    CHECK_FALSE(run(json{{"mode", "bounded"}, {"quiet_reset_s", 0}}).ok);
    CHECK(run(json{{"mode", "bounded"}, {"quiet_reset_s", 30}}).ok);
}

TEST_CASE("resilience validate: resume_after_s=0 and event_debounce_ms=0 are valid",
          "[guardian][resilience][validate]") {
    CHECK(run(json{{"mode", "bounded"}, {"resume_after_s", 0}}).ok); // 0 = stay given up
    CHECK(run(json{{"mode", "persist"}, {"event_debounce_ms", 0}}).ok); // 0 = no debounce
}

TEST_CASE("resilience validate: Backoff initial <= max cross-field",
          "[guardian][resilience][validate][backoff]") {
    CHECK(run(json{{"mode", "backoff"}, {"backoff_initial_ms", 500}, {"backoff_max_ms", 8000}}).ok);
    CHECK_FALSE(
        run(json{{"mode", "backoff"}, {"backoff_initial_ms", 8000}, {"backoff_max_ms", 500}}).ok);
    // initial against the DEFAULT max (60000): 100000 > 60000 → rejected even
    // though max is absent (effective-value cross-check).
    CHECK_FALSE(run(json{{"mode", "backoff"}, {"backoff_initial_ms", 100000}}).ok);
}

TEST_CASE("resilience validate: overflow-bounded seconds", "[guardian][resilience][validate]") {
    // Far beyond the 1-year cap — must reject, not wrap when the agent does *1000.
    CHECK_FALSE(run(json{{"mode", "bounded"}, {"quiet_reset_s", 99999999999ull}}).ok);
}

TEST_CASE("resilience validate: lenient-in passes through mode-irrelevant params",
          "[guardian][resilience][validate][lenient]") {
    // A Persist rule carrying backoff_* is NOT rejected, and the irrelevant value
    // is passed through untouched (even if it would be out of range / garbage for
    // Backoff).
    auto o = run(json{{"mode", "persist"}, {"backoff_initial_ms", 999999999}});
    CHECK(o.ok);
    CHECK(o.params["backoff_initial_ms"] == 999999999); // untouched (still a number)
    CHECK(run(json{{"mode", "persist"}, {"backoff_initial_ms", "fast"}}).ok); // garbage, irrelevant
}

TEST_CASE("resilience validate: load-bearing param must be a non-negative integer",
          "[guardian][resilience][validate]") {
    CHECK_FALSE(run(json{{"mode", "bounded"}, {"max_attempts", "abc"}}).ok);
    CHECK_FALSE(run(json{{"mode", "bounded"}, {"max_attempts", -1}}).ok);
    CHECK_FALSE(run(json{{"mode", "bounded"}, {"max_attempts", 1.5}}).ok);
}

TEST_CASE("resilience schema: shape + bounds", "[guardian][resilience][schema]") {
    auto s = resilience_params_schema();
    REQUIRE(s.is_object());
    CHECK(s["type"] == "object");
    const auto& props = s["properties"];
    REQUIRE(props.contains("mode"));
    CHECK(props["mode"]["enum"] == json::array({"persist", "backoff", "bounded"}));
    REQUIRE(props.contains("max_attempts"));
    CHECK(props["max_attempts"]["minimum"] == 1);
    // mode-relevance is machine-discoverable
    CHECK(props["max_attempts"]["x-applies-to-modes"] == json::array({"bounded"}));
    // other remediation params may coexist in remediation.params
    CHECK(s["additionalProperties"] == true);
}

TEST_CASE("schema catalog: parses, lists Slice-A types, stable content ETag",
          "[guardian][schema][catalog]") {
    const auto& cat = guardian_schema_catalog();
    CHECK_FALSE(cat.etag.empty());
    // built-once cache → identical ETag across calls
    CHECK(guardian_schema_catalog().etag == cat.etag);

    auto j = json::parse(cat.json);
    REQUIRE(j.contains("schemas"));
    REQUIRE(j["schemas"].is_array());
    std::vector<std::string> types;
    for (const auto& e : j["schemas"]) {
        CHECK(e.contains("kind"));
        CHECK(e.contains("type"));
        // G9 shape: {kind, type, json_schema} — the schema is nested and is a
        // WELL-FORMED JSON Schema (type:object), not the discriminator clobbered
        // over the schema's own type keyword.
        REQUIRE(e.contains("json_schema"));
        CHECK(e["json_schema"]["type"] == "object");
        CHECK(e["json_schema"]["properties"].contains("type"));
        types.push_back(e["type"].get<std::string>());
    }
    auto has = [&](const char* t) {
        return std::find(types.begin(), types.end(), t) != types.end();
    };
    CHECK(has("registry-change"));
    CHECK(has("registry-value-equals"));
    CHECK(has("alert-only"));
    CHECK(has("enforce"));
    // Change B file types.
    CHECK(has("file-change"));
    CHECK(has("file-exists"));
    CHECK(has("file-hash-equals"));

    // The assertion type publishes the registry value-equals params + the
    // discriminated `expected` encoding (decision 3).
    for (const auto& e : j["schemas"]) {
        if (e["type"] == "registry-value-equals") {
            const auto& props = e["json_schema"]["properties"]["params"]["properties"];
            CHECK(props.contains("hive"));
            CHECK(props.contains("value_type"));
            CHECK(props.contains("expected"));
            CHECK(e["json_schema"]["properties"]["params"].contains("allOf")); // discriminators
        }
        if (e["type"] == "file-hash-equals") {
            const auto& props = e["json_schema"]["properties"]["params"]["properties"];
            CHECK(props.contains("path"));
            CHECK(props.contains("expected_hash"));
            // hex-digest format check (the file-type analogue of the registry
            // discriminated subschemas).
            CHECK(props["expected_hash"].contains("pattern"));
        }
        if (e["type"] == "file-exists") {
            const auto& props = e["json_schema"]["properties"]["params"]["properties"];
            CHECK(props.contains("path"));
            CHECK(props["expected"]["enum"] == json::array({"present", "absent"}));
        }
    }
}

TEST_CASE("CROSS-CHECK: server param-spec keys == agent resilience_keys (G9 drift guard)",
          "[guardian][resilience][crosscheck]") {
    using namespace yuzu::agent::resilience_keys;
    std::vector<std::string_view> agent_keys = {kMode,
                                                kMaxAttempts,
                                                kQuietResetS,
                                                kResumeAfterS,
                                                kBackoffInitialMs,
                                                kBackoffMaxMs,
                                                kEventDebounceMs};
    std::sort(agent_keys.begin(), agent_keys.end());

    auto server_keys = resilience_param_keys(); // already sorted

    // If this fails, the server schema/validator and the agent parser disagree on
    // a key name — an author following GET /schemas would set a param the agent
    // silently ignores. Re-sync resilience_keys (agent) and the kParams table
    // (server) before merging.
    CHECK(server_keys.size() == agent_keys.size());
    CHECK(std::vector<std::string_view>(server_keys.begin(), server_keys.end()) == agent_keys);
}

namespace {
// Pull the `enum` array of a registry-value-equals param out of the published
// catalog, as sorted std::strings.
std::vector<std::string> schema_registry_enum(const char* param) {
    auto j = json::parse(guardian_schema_catalog().json);
    std::vector<std::string> out;
    for (const auto& e : j["schemas"]) {
        if (e["type"] == "registry-value-equals") {
            const auto& p = e["json_schema"]["properties"]["params"]["properties"][param]["enum"];
            for (const auto& v : p)
                out.push_back(v.get<std::string>());
        }
    }
    std::sort(out.begin(), out.end());
    return out;
}
std::vector<std::string> sorted_strings(const std::vector<std::string_view>& in) {
    std::vector<std::string> out;
    for (auto sv : in)
        out.emplace_back(sv);
    std::sort(out.begin(), out.end());
    return out;
}
template <std::size_t N>
std::vector<std::string> sorted_strings(const std::string_view (&in)[N]) {
    std::vector<std::string> out;
    for (auto sv : in)
        out.emplace_back(sv);
    std::sort(out.begin(), out.end());
    return out;
}
} // namespace

TEST_CASE("CROSS-CHECK: registry hive/value_type schema == server set == agent set (H2 drift guard)",
          "[guardian][registry][crosscheck]") {
    using namespace yuzu::agent;

    // If any of these fail, the menu we publish (and the dashboard form, and the
    // derive_rule_spec validator — all driven from the server accessors) offers a
    // registry hive or value type the agent's RegistryGuard can't read/write. A
    // guard authored against it reports perpetual false drift (audit) or perpetual
    // remediation.failed (enforce). Re-sync registry_support::kHives / kValueTypes
    // (agent) and kRegistryHives / kRegistryValueTypes (server) before merging.
    SECTION("hives") {
        auto schema = schema_registry_enum("hive");
        auto server = sorted_strings(supported_registry_hives());
        auto agent = sorted_strings(registry_support::kHives);
        CHECK(schema == server);
        CHECK(server == agent);
        // The unsupported hive that previously leaked through must be gone.
        CHECK(std::find(agent.begin(), agent.end(), "HKCC") == agent.end());
    }
    SECTION("value types") {
        auto schema = schema_registry_enum("value_type");
        auto server = sorted_strings(supported_registry_value_types());
        auto agent = sorted_strings(registry_support::kValueTypes);
        CHECK(schema == server);
        CHECK(server == agent);
        CHECK(std::find(agent.begin(), agent.end(), "REG_BINARY") == agent.end());
        CHECK(std::find(agent.begin(), agent.end(), "REG_MULTI_SZ") == agent.end());
    }
}

namespace {
// Build a registry-value-equals rule body for derive_rule_spec.
json reg_rule_body(const std::string& key, const std::string& remediation_type) {
    return json{
        {"spark", {{"type", "registry-change"}, {"params", json::object()}}},
        {"assertion",
         {{"type", "registry-value-equals"},
          {"params",
           {{"hive", "HKLM"}, {"key", key}, {"value_name", "Flag"}, {"value_type", "REG_SZ"},
            {"expected", "1"}}}}},
        {"remediation", {{"type", remediation_type}, {"params", json::object()}}},
    };
}
} // namespace

TEST_CASE("H1: enforce-mode write to a denylisted key is rejected (contract §6)",
          "[guardian][denylist][h1]") {
    // Every named §6 class is refused when the rule is in enforce mode.
    const std::vector<std::string> denied = {
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe",
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        "SYSTEM\\CurrentControlSet\\Services\\YuzuFake",
        "SOFTWARE\\Policies\\Microsoft\\Windows\\System",
    };
    for (const auto& key : denied) {
        INFO("denied key=" << key);
        auto r = derive_rule_spec(reg_rule_body(key, "enforce"), "g", 1, true, "enforce");
        CHECK(r.error.has_value());
    }
    // The SAME key is permitted in AUDIT mode — detection must still observe it.
    auto audit = derive_rule_spec(
        reg_rule_body("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "alert-only"), "g", 1,
        true, "audit");
    CHECK_FALSE(audit.error.has_value());
    CHECK(audit.structured);
    // A benign key in enforce mode is allowed.
    auto benign =
        derive_rule_spec(reg_rule_body("SOFTWARE\\YuzuTest\\Flag", "enforce"), "g", 1, true, "enforce");
    CHECK_FALSE(benign.error.has_value());
}

TEST_CASE("H1: denylist normalisation resists separator/case evasion",
          "[guardian][denylist][h1]") {
    // doubled backslash, forward slashes, leading separator, mixed case all canonicalise.
    CHECK_FALSE(dangerous_enforce_registry_key(
                    "software\\microsoft\\windows\\currentversion\\\\run")
                    .empty());
    CHECK_FALSE(dangerous_enforce_registry_key("SOFTWARE/Microsoft/Windows/CurrentVersion/Run")
                    .empty());
    CHECK_FALSE(
        dangerous_enforce_registry_key("\\SYSTEM\\CurrentControlSet\\Services\\Foo").empty());
    CHECK_FALSE(dangerous_enforce_registry_key("system\\currentcontrolset\\services\\bar").empty());
    // benign keys are not over-matched: 'run' as a non-autorun substring is fine.
    CHECK(dangerous_enforce_registry_key("software\\acme\\running_total").empty());
    CHECK(dangerous_enforce_registry_key("software\\acme\\services_list").empty());
    CHECK(dangerous_enforce_registry_key("software\\yuzutest\\flag").empty());
}

TEST_CASE("H1: dangerous_enforce_key_in_spec inspects the stored spec_json",
          "[guardian][denylist][h1]") {
    // The audit→enforce bypass guard relies on detecting a denylisted key in a
    // stored (already-created, audit-mode) spec.
    auto clean = derive_rule_spec(reg_rule_body("SOFTWARE\\YuzuTest\\Flag", "alert-only"), "g", 1,
                                  true, "audit");
    REQUIRE(clean.structured);
    CHECK(dangerous_enforce_key_in_spec(clean.spec_json).empty());

    auto stored = derive_rule_spec(
        reg_rule_body("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "alert-only"), "g", 1,
        true, "audit");
    REQUIRE(stored.structured);
    CHECK_FALSE(dangerous_enforce_key_in_spec(stored.spec_json).empty());

    // Robust to junk.
    CHECK(dangerous_enforce_key_in_spec("").empty());
    CHECK(dangerous_enforce_key_in_spec("not json").empty());
    CHECK(dangerous_enforce_key_in_spec("{}").empty());
}
