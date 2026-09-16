#pragma once

/// @file hardware_action_form.hpp
/// PURE JSON-Schema-subset -> HTML-form-field spec for the Hardware CI record's
/// Actions lens (the generic action runner). No httplib — parses a
/// `parameter_schema` string (an `InstructionDefinition`'s JSON-Schema-shaped
/// column, `instruction_store.hpp`) into a small, renderer-friendly field list.
/// Deliberately narrow: this is a v0 "make every action clickable" form, not a
/// general JSON-Schema form generator — object/array/anyOf properties fall back
/// to a plain text input rather than growing this parser to handle them.

#include "sensitive_instruction_params.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server {

struct ActionFormField {
    std::string name;
    enum class Kind { Text, Integer, Number, Boolean, Enum } kind{Kind::Text};
    std::vector<std::string> enum_values;
    std::string description;
    std::string default_value; // stringified; "" = no default
    bool required{false};
    bool sensitive{false};
};

struct ActionFormSpec {
    std::vector<ActionFormField> fields;
    bool schema_usable{false}; // false => render a free-form key=value textarea instead
};

/// `schema_json` is an `InstructionDefinition::parameter_schema` value (may be
/// empty, malformed, or a non-object schema — all three degrade to
/// `schema_usable=false` rather than throwing).
[[nodiscard]] inline ActionFormSpec parse_action_form_spec(std::string_view schema_json) {
    ActionFormSpec spec;
    if (schema_json.empty())
        return spec;
    auto parsed = nlohmann::json::parse(schema_json, nullptr, false);
    if (parsed.is_discarded() || !parsed.is_object())
        return spec;
    auto props_it = parsed.find("properties");
    if (props_it == parsed.end() || !props_it->is_object())
        return spec;

    std::vector<std::string> required;
    if (auto req_it = parsed.find("required"); req_it != parsed.end() && req_it->is_array())
        for (const auto& r : *req_it)
            if (r.is_string())
                required.push_back(r.get<std::string>());

    for (auto it = props_it->begin(); it != props_it->end(); ++it) {
        const std::string& name = it.key();
        const nlohmann::json& p = it.value();
        if (!p.is_object())
            continue;
        ActionFormField f;
        f.name = name;
        f.required = std::find(required.begin(), required.end(), name) != required.end();
        f.sensitive = is_redacted_instruction_param_key(name);
        if (auto d = p.find("description"); d != p.end() && d->is_string())
            f.description = d->get<std::string>();

        if (auto e = p.find("enum"); e != p.end() && e->is_array() && !e->empty()) {
            f.kind = ActionFormField::Kind::Enum;
            for (const auto& v : *e)
                if (v.is_string())
                    f.enum_values.push_back(v.get<std::string>());
                else if (!v.is_null())
                    f.enum_values.push_back(v.dump());
        } else {
            std::string type;
            if (auto t = p.find("type"); t != p.end() && t->is_string())
                type = t->get<std::string>();
            if (type == "integer") f.kind = ActionFormField::Kind::Integer;
            else if (type == "number") f.kind = ActionFormField::Kind::Number;
            else if (type == "boolean") f.kind = ActionFormField::Kind::Boolean;
            else f.kind = ActionFormField::Kind::Text; // string, object, array, or unspecified
        }

        if (auto d = p.find("default"); d != p.end() && !d->is_null()) {
            f.default_value = d->is_string() ? d->get<std::string>() : d->dump();
        }
        spec.fields.push_back(std::move(f));
    }
    spec.schema_usable = !spec.fields.empty();
    return spec;
}

} // namespace yuzu::server
