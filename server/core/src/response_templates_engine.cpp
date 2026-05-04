#include "response_templates_engine.hpp"

#include "result_parsing.hpp"

#include <spdlog/spdlog.h>

#include <random>
#include <unordered_set>

namespace yuzu::server {

namespace {

/// Allowed filter operators. Mirrors the dashboard's filter UI plus the
/// substring/prefix/suffix variants the YAML DSL exposes.
const std::unordered_set<std::string>& allowed_ops() {
    static const std::unordered_set<std::string> ops{
        "equals", "not_equals", "contains", "starts_with", "ends_with"};
    return ops;
}

std::string generate_template_id() {
    static thread_local std::mt19937_64 rng(std::random_device{}());
    std::uniform_int_distribution<uint64_t> dist;
    char buf[33];
    std::snprintf(buf, sizeof(buf), "%016llx%016llx",
                  static_cast<unsigned long long>(dist(rng)),
                  static_cast<unsigned long long>(dist(rng)));
    return std::string(buf, 32);
}

/// Read a string field from the JSON payload, defaulting on absence.
/// Returns std::nullopt when present-but-not-string (caller turns this
/// into a 400 with the field name).
std::optional<std::string> opt_string(const nlohmann::json& j, const char* key) {
    if (!j.contains(key) || j[key].is_null()) return std::string{};
    if (!j[key].is_string()) return std::nullopt;
    return j[key].get<std::string>();
}

ResponseTemplate parse_one(const nlohmann::json& j) {
    ResponseTemplate t;
    if (auto v = opt_string(j, "id"); v) t.id = *v;
    if (auto v = opt_string(j, "name"); v) t.name = *v;
    if (auto v = opt_string(j, "description"); v) t.description = *v;
    if (j.contains("columns") && j["columns"].is_array()) {
        for (const auto& el : j["columns"]) {
            if (el.is_string()) t.columns.push_back(el.get<std::string>());
        }
    }
    if (j.contains("sort") && j["sort"].is_object()) {
        const auto& s = j["sort"];
        if (auto v = opt_string(s, "column"); v) t.sort_column = *v;
        if (auto v = opt_string(s, "dir"); v) t.sort_dir = *v;
    }
    if (j.contains("filters") && j["filters"].is_array()) {
        for (const auto& f : j["filters"]) {
            if (!f.is_object()) continue;
            ResponseTemplateFilter rf;
            if (auto v = opt_string(f, "column"); v) rf.column = *v;
            if (auto v = opt_string(f, "op"); v) rf.op = *v;
            if (auto v = opt_string(f, "value"); v) rf.value = *v;
            // Drop blanks rather than 500-ing on parse — validation runs
            // on writes; reads must remain forgiving in case the column
            // was hand-edited.
            if (rf.column.empty() || rf.op.empty()) continue;
            t.filters.push_back(std::move(rf));
        }
    }
    if (j.contains("default") && j["default"].is_boolean()) {
        t.is_default = j["default"].get<bool>();
    }
    return t;
}

std::vector<std::string> columns_from_result_schema(const std::string& schema_json) {
    std::vector<std::string> out;
    if (schema_json.empty() || schema_json == "{}" || schema_json == "[]") return out;
    auto parsed = nlohmann::json::parse(schema_json, nullptr, false);
    if (parsed.is_discarded()) return out;
    // Shape: result_schema is canonically an array of {name,type} objects
    // (legacy_shim, instructions docs §853). Tolerate object form (an
    // older shape used wrapping under a "columns" key).
    if (parsed.is_array()) {
        for (const auto& el : parsed) {
            if (el.is_object() && el.contains("name") && el["name"].is_string())
                out.push_back(el["name"].get<std::string>());
        }
        return out;
    }
    if (parsed.is_object() && parsed.contains("columns") && parsed["columns"].is_array()) {
        for (const auto& el : parsed["columns"]) {
            if (el.is_object() && el.contains("name") && el["name"].is_string())
                out.push_back(el["name"].get<std::string>());
        }
    }
    return out;
}

} // namespace

std::expected<std::vector<ResponseTemplate>, std::string>
ResponseTemplatesEngine::parse(std::string_view spec_json) const {
    if (spec_json.empty() || spec_json == "[]" || spec_json == "{}" || spec_json == "null") {
        return std::vector<ResponseTemplate>{};
    }
    auto parsed = nlohmann::json::parse(spec_json, nullptr, false);
    if (parsed.is_discarded()) {
        return std::unexpected("response_templates_spec is not valid JSON");
    }
    std::vector<ResponseTemplate> out;
    if (parsed.is_array()) {
        out.reserve(parsed.size());
        for (const auto& el : parsed) {
            if (!el.is_object()) continue;
            out.push_back(parse_one(el));
        }
    } else if (parsed.is_object()) {
        // Tolerate a single-object spec (some YAML converters emit one).
        out.push_back(parse_one(parsed));
    } else {
        return std::unexpected("response_templates_spec must be a JSON array of templates");
    }
    return out;
}

ResponseTemplate
ResponseTemplatesEngine::synthesise_default(const std::string& result_schema_json,
                                             const std::string& plugin) const {
    ResponseTemplate t;
    t.id = kDefaultId;
    t.name = "Default";
    t.description = "Auto-generated default view derived from the result schema.";
    t.is_default = true;
    // Prefer columns from result_schema when populated — that's the
    // typed shape the InstructionDefinition author actually declared.
    auto cols = columns_from_result_schema(result_schema_json);
    if (cols.empty()) {
        // Fallback: plugin's hard-coded column list, minus the leading
        // "Agent" pseudo-column which the dashboard always renders.
        const auto& plugin_cols = columns_for_plugin(plugin);
        for (size_t i = 1; i < plugin_cols.size(); ++i) {
            cols.push_back(plugin_cols[i]);
        }
    }
    t.columns = std::move(cols);
    return t;
}

ResponseTemplate
ResponseTemplatesEngine::resolve(const std::vector<ResponseTemplate>& templates,
                                  const std::string& template_id,
                                  const std::string& result_schema_json,
                                  const std::string& plugin) const {
    // Empty id or the synth-default sentinel → always synthesise.
    if (template_id.empty() || template_id == kDefaultId) {
        for (const auto& t : templates) if (t.is_default) return t;
        return synthesise_default(result_schema_json, plugin);
    }
    for (const auto& t : templates) {
        if (t.id == template_id) return t;
    }
    // Not found: caller chose an id we don't know. Fall back to the
    // operator's marked-default if any, else the synthesised default —
    // never a hard error, since the dashboard reads stale localStorage
    // ids and we don't want to 500 on a benign mismatch.
    for (const auto& t : templates) if (t.is_default) return t;
    return synthesise_default(result_schema_json, plugin);
}

std::expected<ResponseTemplate, std::string>
ResponseTemplatesEngine::validate_payload(const nlohmann::json& payload,
                                           const std::vector<ResponseTemplate>& existing,
                                           const std::string& expected_id,
                                           bool assign_id) const {
    if (!payload.is_object()) {
        return std::unexpected("template payload must be a JSON object");
    }
    auto t = parse_one(payload);

    // Reject the synth-default sentinel as a stored id — operators
    // cannot author or overwrite the synthesised default.
    if (t.id == kDefaultId) {
        return std::unexpected("'__default__' is reserved for the synthesised default template");
    }

    if (!expected_id.empty() && !t.id.empty() && t.id != expected_id) {
        return std::unexpected("path id and body id mismatch");
    }
    if (t.id.empty()) {
        t.id = expected_id.empty() ? (assign_id ? generate_template_id() : "") : expected_id;
    }
    if (t.id.empty()) {
        return std::unexpected("template id is required");
    }

    if (t.name.empty()) {
        return std::unexpected("name is required");
    }
    if (t.name.size() > 200) {
        return std::unexpected("name must be 200 characters or fewer");
    }

    if (!t.sort_dir.empty() && t.sort_dir != "asc" && t.sort_dir != "desc") {
        return std::unexpected("sort.dir must be 'asc' or 'desc'");
    }
    if (!t.sort_dir.empty() && t.sort_column.empty()) {
        return std::unexpected("sort.column is required when sort.dir is set");
    }

    // Column names: trim leading/trailing whitespace via copy, reject empties.
    for (const auto& c : t.columns) {
        if (c.empty()) return std::unexpected("columns must not contain empty strings");
    }

    for (const auto& f : t.filters) {
        if (f.column.empty())
            return std::unexpected("filter.column is required");
        if (f.op.empty())
            return std::unexpected("filter.op is required");
        if (!allowed_ops().contains(f.op)) {
            return std::unexpected("filter.op must be one of equals|not_equals|"
                                   "contains|starts_with|ends_with");
        }
    }

    // Reject duplicate id against `existing` UNLESS we're updating in
    // place (expected_id == t.id).
    for (const auto& e : existing) {
        if (e.id == t.id && e.id != expected_id) {
            return std::unexpected("template id collision");
        }
    }

    // At most one operator-authored template may be marked default.
    // The synthesised default is virtual and not in `existing`.
    if (t.is_default) {
        for (const auto& e : existing) {
            if (e.is_default && e.id != t.id) {
                return std::unexpected("another template is already marked default");
            }
        }
    }

    return t;
}

std::string
ResponseTemplatesEngine::serialise(const std::vector<ResponseTemplate>& templates) const {
    nlohmann::json arr = nlohmann::json::array();
    for (const auto& t : templates) {
        arr.push_back(to_json(t));
    }
    return arr.dump();
}

nlohmann::json
ResponseTemplatesEngine::to_json(const ResponseTemplate& t) const {
    nlohmann::json j;
    j["id"] = t.id;
    j["name"] = t.name;
    if (!t.description.empty()) j["description"] = t.description;
    j["columns"] = t.columns;
    if (!t.sort_column.empty()) {
        j["sort"] = nlohmann::json::object();
        j["sort"]["column"] = t.sort_column;
        j["sort"]["dir"] = t.sort_dir.empty() ? "asc" : t.sort_dir;
    }
    nlohmann::json fa = nlohmann::json::array();
    for (const auto& f : t.filters) {
        fa.push_back({{"column", f.column}, {"op", f.op}, {"value", f.value}});
    }
    j["filters"] = std::move(fa);
    j["default"] = t.is_default;
    return j;
}

} // namespace yuzu::server
