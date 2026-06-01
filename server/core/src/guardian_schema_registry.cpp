/// @file guardian_schema_registry.cpp — see guardian_schema_registry.hpp.

#include "guardian_schema_registry.hpp"

#include "guardian_resilience_schema.hpp"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <cstdio>

namespace yuzu::server::guardian {
namespace {

using nlohmann::json;

// A complete spec-block schema: {type: {const}, params: <params schema>}.
json block_schema(const char* type, const char* title, json params, bool params_required) {
    json props = {
        {"type", {{"const", type}}},
        {"params", std::move(params)},
    };
    json required = json::array({"type"});
    if (params_required)
        required.push_back("params");
    return json{
        {"title", title},
        {"type", "object"},
        {"properties", std::move(props)},
        {"required", std::move(required)},
        {"additionalProperties", false},
    };
}

// Assertion params for registry-value-equals (contract decision G4). `expected`
// is string-encoded per `value_type`; the discriminated subschemas below make the
// per-type encoding machine-discoverable rather than prose (decision 3).
json registry_value_equals_params() {
    json props = {
        {"hive",
         {{"type", "string"},
          {"enum", json::array({"HKLM", "HKCU", "HKCR", "HKU", "HKCC"})},
          {"description", "Registry hive."}}},
        {"key", {{"type", "string"}, {"description", "Key path under the hive, e.g. SOFTWARE\\\\YuzuTest."}}},
        {"value_name",
         {{"type", "string"}, {"description", "Value name; \"\" means the key's default value."}}},
        {"value_type",
         {{"type", "string"},
          {"enum", json::array({"REG_DWORD", "REG_QWORD", "REG_SZ", "REG_EXPAND_SZ", "REG_BINARY",
                                "REG_MULTI_SZ"})},
          {"description", "Registry value type; the comparison is type-aware (a type mismatch is drift)."}}},
        {"expected",
         {{"type", "string"},
          {"description", "Desired value, string-encoded per value_type: DWORD/QWORD decimal "
                          "(0x… accepted, canonical decimal); SZ/EXPAND_SZ literal; BINARY "
                          "lowercase even-length hex; MULTI_SZ JSON-array-string (deferred)."}}},
    };
    // Discriminated subschemas keyed on value_type (decision 3). Built explicitly
    // (not via nested brace-init) so the object/array shape is unambiguous.
    auto discriminator = [](json value_type_match, const char* expected_pattern) {
        json if_clause = json::object();
        if_clause["properties"]["value_type"] = std::move(value_type_match);
        json then_clause = json::object();
        then_clause["properties"]["expected"]["pattern"] = expected_pattern;
        json rule = json::object();
        rule["if"] = std::move(if_clause);
        rule["then"] = std::move(then_clause);
        return rule;
    };
    json discriminators = json::array();
    {
        json enum_match = json::object();
        enum_match["enum"] = json::array({"REG_DWORD", "REG_QWORD"});
        discriminators.push_back(discriminator(std::move(enum_match), "^(0x[0-9a-fA-F]+|[0-9]+)$"));
    }
    {
        json const_match = json::object();
        const_match["const"] = "REG_BINARY";
        discriminators.push_back(discriminator(std::move(const_match), "^([0-9a-f]{2})*$"));
    }
    return json{
        {"type", "object"},
        {"properties", std::move(props)},
        {"required", json::array({"hive", "key", "value_type", "expected"})},
        {"allOf", std::move(discriminators)},
        {"additionalProperties", false},
    };
}

// registry-change spark: matched on `type` only. The watched key is derived from
// the assertion's hive/key, so the spark carries no required params today.
json registry_change_params() {
    return json{
        {"type", "object"},
        {"description", "No params: the registry watch target is taken from the assertion's hive/key."},
        {"properties", json::object()},
        {"additionalProperties", true},
    };
}

json build_catalog() {
    json schemas = json::array();

    // {kind, type, json_schema} per G9 — the schema is NESTED under json_schema so
    // it keeps its own JSON-Schema "type":"object" (not overwritten by the
    // discriminator name) and the entry stays a well-formed catalog row.
    auto add = [&](const char* kind, const char* type_name, json schema) {
        json entry = json::object();
        entry["kind"] = kind;
        entry["type"] = type_name;
        entry["json_schema"] = std::move(schema);
        schemas.push_back(std::move(entry));
    };

    add("spark", "registry-change",
        block_schema("registry-change", "Registry change trigger", registry_change_params(),
                     /*params_required=*/false));
    add("assertion", "registry-value-equals",
        block_schema("registry-value-equals", "Registry value equals",
                     registry_value_equals_params(), /*params_required=*/true));
    // Resilience policy lives in remediation.params for BOTH actions (it is read
    // for every guard); the mode/backoff/bounded params take effect only when the
    // guard actually enforces — event_debounce_ms applies in alert-only too. The
    // schema documents that via resilience_params_schema()'s descriptions.
    add("remediation", "alert-only",
        block_schema("alert-only", "Detect and alert (no write-back)", resilience_params_schema(),
                     /*params_required=*/false));
    add("remediation", "enforce",
        block_schema("enforce", "Detect and write the expected value back",
                     resilience_params_schema(), /*params_required=*/false));

    return json{
        {"version", 1},
        {"description",
         "Guardian Guard authoring schemas (contract G9). A Guard is three "
         "{type, params} blocks — spark, assertion, remediation — plus "
         "enabled/enforcement_mode/version. enforcement_mode (enforce|audit) is the "
         "master gate; remediation.type is the authored action."},
        {"schemas", std::move(schemas)},
    };
}

// FNV-1a 64-bit over the serialised catalog → a strong, content-derived ETag so a
// schema edit invalidates caches automatically (no manual version bump needed).
std::string content_etag(const std::string& body) {
    std::uint64_t h = 1469598103934665603ull;
    for (unsigned char c : body) {
        h ^= c;
        h *= 1099511628211ull;
    }
    char buf[19];
    int n = std::snprintf(buf, sizeof(buf), "\"%016llx\"", static_cast<unsigned long long>(h));
    return std::string(buf, static_cast<std::size_t>(n));
}

} // namespace

const SchemaCatalog& guardian_schema_catalog() {
    static const SchemaCatalog catalog = [] {
        SchemaCatalog c;
        c.json = build_catalog().dump();
        c.etag = content_etag(c.json);
        return c;
    }();
    return catalog;
}

} // namespace yuzu::server::guardian
