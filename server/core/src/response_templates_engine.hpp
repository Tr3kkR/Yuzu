#pragma once

/// @file response_templates_engine.hpp
/// Server-side helper for issue #254 / Phase 8.2 — named response view
/// configurations on `InstructionDefinition`. The engine owns three
/// responsibilities:
///   1. Parse + validate a `response_templates_spec` JSON array (the value
///      stored in the `instruction_definitions.response_templates_spec`
///      column) into a typed list of templates.
///   2. Synthesise a `__default__` template from the definition's
///      `result_schema` (when populated) or the plugin's column schema
///      (`columns_for_plugin`) when no operator template is configured.
///      The synthesised default is what the dashboard renders when an
///      operator hasn't authored anything yet.
///   3. Apply a template to a request: produce the column subset, sort
///      column / direction, and filter list the dashboard should use.
///
/// The engine intentionally has no SQL knowledge — it operates on JSON
/// (storage form) and the in-memory column-name list. Routes layer
/// (rest_api_v1.cpp) and the dashboard layer (dashboard_routes.cpp) are
/// the only places that talk to the store / response_store.

#include <nlohmann/json.hpp>

#include <expected>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::server {

/// One filter clause inside a response template.
struct ResponseTemplateFilter {
    std::string column; // column name (case-insensitive match against the schema)
    std::string op;     // "equals" | "not_equals" | "contains" | "starts_with" | "ends_with"
    std::string value;
};

/// One named view configuration.
struct ResponseTemplate {
    std::string id;          // 32-hex; the synthesised default uses "__default__"
    std::string name;        // operator-facing label
    std::string description; // optional
    std::vector<std::string> columns; // ordered column names; empty means "all"
    std::string sort_column;          // empty means "sort by Agent"
    std::string sort_dir;             // "asc" | "desc"; empty defaults to "asc"
    std::vector<ResponseTemplateFilter> filters;
    bool is_default{false};
};

class ResponseTemplatesEngine {
public:
    /// Sentinel id for the synthesised default template returned when the
    /// definition has no operator-authored templates. Operators cannot
    /// create, update, or delete a template with this id — the routes
    /// layer rejects such writes with 400.
    static constexpr const char* kDefaultId = "__default__";

    /// Parse the JSON array stored in `response_templates_spec`. Returns
    /// the typed vector on success and a human-readable message on
    /// failure. Empty / "[]" / null spec yields an empty vector (caller
    /// then synthesises a default).
    [[nodiscard]] std::expected<std::vector<ResponseTemplate>, std::string>
    parse(std::string_view spec_json) const;

    /// Synthesise the `__default__` template from a definition's
    /// `result_schema` JSON (preferred) or, when result_schema is empty
    /// or unparseable, from the plugin's column schema. The returned
    /// template has `is_default=true`, no sort, no filters, and lists
    /// every available column in declaration order.
    [[nodiscard]] ResponseTemplate
    synthesise_default(const std::string& result_schema_json,
                       const std::string& plugin) const;

    /// Resolve a template-id → ResponseTemplate. The synthesised default
    /// is returned when:
    ///   * `template_id` is empty
    ///   * `template_id` equals `kDefaultId`
    ///   * the parsed templates list contains no entry with that id AND
    ///     no entry is marked `is_default=true`
    /// Otherwise the named template (or the explicit default) is
    /// returned. `templates` is the parsed result of `parse()`.
    [[nodiscard]] ResponseTemplate
    resolve(const std::vector<ResponseTemplate>& templates,
            const std::string& template_id,
            const std::string& result_schema_json,
            const std::string& plugin) const;

    /// Validate a single template payload (the body of a POST/PUT). When
    /// `assign_id` is true and the input has no id, a fresh 32-hex id is
    /// generated. `existing` is the pre-existing template list — used to
    /// reject id collisions and to enforce the "at most one is_default"
    /// invariant. Returns the canonicalised template on success, an
    /// error string on failure.
    [[nodiscard]] std::expected<ResponseTemplate, std::string>
    validate_payload(const nlohmann::json& payload,
                     const std::vector<ResponseTemplate>& existing,
                     const std::string& expected_id, // empty for POST
                     bool assign_id) const;

    /// Serialise a template list back to the canonical JSON array form
    /// stored in the `response_templates_spec` column.
    [[nodiscard]] std::string
    serialise(const std::vector<ResponseTemplate>& templates) const;

    /// Convert a single template to its REST-wire JSON shape
    /// (camelCase-friendly, sort+filters as nested objects).
    [[nodiscard]] nlohmann::json
    to_json(const ResponseTemplate& tmpl) const;
};

} // namespace yuzu::server
