#include "yuzu/server/scim_json.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>

namespace yuzu::server::scim {

namespace {

/// Case-insensitive ASCII compare — SCIM attribute names and op verbs are
/// case-insensitive per RFC 7644 §3.5.2.
bool ieq(std::string_view a, std::string_view b) {
    return a.size() == b.size() &&
           std::equal(a.begin(), a.end(), b.begin(), [](char x, char y) {
               return std::tolower(static_cast<unsigned char>(x)) ==
                      std::tolower(static_cast<unsigned char>(y));
           });
}

} // namespace

// ── User resource codec ─────────────────────────────────────────────────────

nlohmann::json user_to_json(const ScimResource& r, std::string_view location_base) {
    nlohmann::json j;
    j["schemas"] = nlohmann::json::array({kSchemaUser});
    j["id"] = r.scim_id;
    j["userName"] = r.username;
    j["active"] = r.active;
    if (!r.external_id.empty())
        j["externalId"] = r.external_id;

    nlohmann::json meta;
    meta["resourceType"] = "User";
    meta["created"] = r.created_at;
    meta["lastModified"] = r.updated_at;
    meta["version"] = "W/\"" + std::to_string(r.etag_version) + "\"";
    meta["location"] = std::string(location_base) + "/" + r.scim_id;
    j["meta"] = std::move(meta);

    return j;
}

std::expected<ScimUserInput, ScimError> parse_user(const nlohmann::json& body) {
    if (!body.is_object()) {
        return std::unexpected(
            ScimError{400, "invalidValue", "request body must be a JSON object"});
    }

    ScimUserInput input;
    // FIX-3 (Hermes LOW): body.value<std::string>(...) throws
    // nlohmann::json::type_error when the key is present but holds a
    // non-string (e.g. {"userName":123}) — that escapes this function's
    // std::expected contract and surfaces as an unhandled 500 instead of a
    // clean SCIM 400. Guard the type before extracting.
    if (body.contains("userName") && !body["userName"].is_string()) {
        return std::unexpected(ScimError{400, "invalidValue", "userName must be a string"});
    }
    input.user_name = body.value("userName", std::string{});
    if (input.user_name.empty()) {
        return std::unexpected(ScimError{400, "invalidValue", "userName is required"});
    }

    if (body.contains("externalId") && !body["externalId"].is_string()) {
        return std::unexpected(ScimError{400, "invalidValue", "externalId must be a string"});
    }
    input.external_id = body.value("externalId", std::string{});
    if (input.external_id.size() > kMaxExternalIdLength) {
        return std::unexpected(
            ScimError{400, "invalidValue",
                     "externalId exceeds the maximum length of " +
                         std::to_string(kMaxExternalIdLength) + " bytes"});
    }

    if (body.contains("active") && body["active"].is_boolean())
        input.active = body["active"].get<bool>();

    // Unknown fields (name, emails, phoneNumbers, groups, ...) are
    // intentionally ignored — real IdPs (Okta/Entra) send them, Yuzu's
    // resource mapping doesn't model them in this slice.
    return input;
}

std::expected<ScimPatch, ScimError> parse_patch(const nlohmann::json& body) {
    if (!body.is_object() || !body.contains("Operations") ||
        !body["Operations"].is_array() || body["Operations"].empty()) {
        return std::unexpected(
            ScimError{400, "invalidValue", "Operations array is required and must not be empty"});
    }

    ScimPatch patch;

    for (const auto& operation : body["Operations"]) {
        if (!operation.is_object() || !operation.contains("op") ||
            !operation["op"].is_string()) {
            return std::unexpected(
                ScimError{400, "invalidValue", "each operation requires a string 'op'"});
        }

        const std::string op = operation["op"].get<std::string>();
        const bool is_replace_like = ieq(op, "replace") || ieq(op, "add");

        if (ieq(op, "remove")) {
            // `remove` on `active` (or any of our attrs) has no well-defined
            // meaning for a boolean/required field — treat as a no-op rather
            // than erroring, since some IdPs send a bare `{"op":"remove",
            // "path":"active"}` defensively before a `replace`. Nothing to
            // apply, so just continue to the next operation.
            continue;
        }

        if (!is_replace_like) {
            return std::unexpected(
                ScimError{400, "invalidValue", "unsupported PatchOp op: " + op});
        }

        std::string path;
        if (operation.contains("path") && operation["path"].is_string())
            path = operation["path"].get<std::string>();

        if (!operation.contains("value")) {
            return std::unexpected(
                ScimError{400, "invalidValue", "operation requires a 'value'"});
        }
        const auto& value = operation["value"];

        if (!path.empty()) {
            // Explicit-path form: {"op":"replace","path":"active","value":false}
            if (ieq(path, "active")) {
                if (!value.is_boolean()) {
                    return std::unexpected(
                        ScimError{400, "invalidValue", "active value must be boolean"});
                }
                patch.active = value.get<bool>();
            } else if (ieq(path, "userName")) {
                if (!value.is_string()) {
                    return std::unexpected(
                        ScimError{400, "invalidValue", "userName value must be a string"});
                }
                patch.user_name = value.get<std::string>();
            } else if (ieq(path, "externalId")) {
                if (!value.is_string()) {
                    return std::unexpected(
                        ScimError{400, "invalidValue", "externalId value must be a string"});
                }
                if (value.get_ref<const std::string&>().size() > kMaxExternalIdLength) {
                    return std::unexpected(ScimError{
                        400, "invalidValue",
                        "externalId exceeds the maximum length of " +
                            std::to_string(kMaxExternalIdLength) + " bytes"});
                }
                patch.external_id = value.get<std::string>();
            } else {
                return std::unexpected(
                    ScimError{400, "invalidPath", "unsupported PatchOp path: " + path});
            }
        } else {
            // Pathless value-object form:
            // {"op":"replace","value":{"active":false}} — Okta/Entra's
            // deprovision shape.
            if (!value.is_object()) {
                return std::unexpected(ScimError{
                    400, "invalidValue",
                    "pathless PatchOp value must be an object of attribute:value pairs"});
            }
            if (value.contains("active")) {
                if (!value["active"].is_boolean()) {
                    return std::unexpected(
                        ScimError{400, "invalidValue", "active value must be boolean"});
                }
                patch.active = value["active"].get<bool>();
            }
            if (value.contains("userName")) {
                if (!value["userName"].is_string()) {
                    return std::unexpected(
                        ScimError{400, "invalidValue", "userName value must be a string"});
                }
                patch.user_name = value["userName"].get<std::string>();
            }
            if (value.contains("externalId")) {
                if (!value["externalId"].is_string()) {
                    return std::unexpected(
                        ScimError{400, "invalidValue", "externalId value must be a string"});
                }
                if (value["externalId"].get_ref<const std::string&>().size() >
                    kMaxExternalIdLength) {
                    return std::unexpected(ScimError{
                        400, "invalidValue",
                        "externalId exceeds the maximum length of " +
                            std::to_string(kMaxExternalIdLength) + " bytes"});
                }
                patch.external_id = value["externalId"].get<std::string>();
            }
        }
    }

    return patch;
}

// ── Envelopes ────────────────────────────────────────────────────────────────

nlohmann::json error(int status, std::string_view detail, std::string_view scim_type) {
    nlohmann::json j;
    j["schemas"] = nlohmann::json::array({kSchemaError});
    j["status"] = std::to_string(status); // SCIM `status` is a STRING.
    if (!scim_type.empty())
        j["scimType"] = std::string(scim_type);
    j["detail"] = std::string(detail);
    return j;
}

nlohmann::json error(const ScimError& e) {
    return error(e.status, e.detail, e.scim_type);
}

nlohmann::json list_response(const std::vector<nlohmann::json>& resources, int total_results,
                             int start_index, int items_per_page) {
    nlohmann::json j;
    j["schemas"] = nlohmann::json::array({kSchemaListResponse});
    j["totalResults"] = total_results;
    j["startIndex"] = start_index;
    j["itemsPerPage"] = items_per_page;
    j["Resources"] = resources;
    return j;
}

// ── Filter parsing ───────────────────────────────────────────────────────────

std::expected<std::string, ScimError> parse_username_filter(std::string_view filter) {
    // Expected shape: `userName eq "value"` — attribute + operator
    // case-insensitive, value double-quoted with \" and \\ escapes.
    auto fail = [] {
        return std::unexpected(ScimError{400, "invalidFilter", "unsupported filter"});
    };

    std::string_view s = filter;
    // Trim leading/trailing whitespace.
    auto trim = [](std::string_view v) {
        size_t b = v.find_first_not_of(" \t");
        if (b == std::string_view::npos)
            return std::string_view{};
        size_t e = v.find_last_not_of(" \t");
        return v.substr(b, e - b + 1);
    };
    s = trim(s);

    // Split off the attribute token (up to first whitespace).
    size_t sp1 = s.find_first_of(" \t");
    if (sp1 == std::string_view::npos)
        return fail();
    std::string_view attr = s.substr(0, sp1);
    if (!ieq(attr, "userName"))
        return fail();

    s = trim(s.substr(sp1));

    // Split off the operator token.
    size_t sp2 = s.find_first_of(" \t");
    if (sp2 == std::string_view::npos)
        return fail();
    std::string_view op = s.substr(0, sp2);
    if (!ieq(op, "eq"))
        return fail();

    s = trim(s.substr(sp2));

    // Remainder must be a double-quoted string.
    if (s.size() < 2 || s.front() != '"' || s.back() != '"')
        return fail();
    std::string_view quoted = s.substr(1, s.size() - 2);

    std::string value;
    value.reserve(quoted.size());
    for (size_t i = 0; i < quoted.size(); ++i) {
        char c = quoted[i];
        if (c == '\\' && i + 1 < quoted.size() &&
            (quoted[i + 1] == '"' || quoted[i + 1] == '\\')) {
            value.push_back(quoted[i + 1]);
            ++i;
        } else if (c == '"' || c == '\\') {
            // An unescaped quote/backslash inside the value means the
            // filter wasn't well-formed (a real closing quote would have
            // ended the `quoted` slice already).
            return fail();
        } else {
            value.push_back(c);
        }
    }

    return value;
}

// ── Discovery documents ──────────────────────────────────────────────────────

nlohmann::json service_provider_config() {
    nlohmann::json j;
    j["schemas"] = nlohmann::json::array({kSchemaServiceProviderConfig});
    j["patch"] = {{"supported", true}};
    j["bulk"] = {{"supported", false}, {"maxOperations", 0}, {"maxPayloadSize", 0}};
    j["filter"] = {{"supported", true}, {"maxResults", kMaxScimListResults}};
    j["changePassword"] = {{"supported", false}};
    j["sort"] = {{"supported", false}};
    // S-ETAG-FALSE: `meta.version`/`ETag` are emitted as informational
    // versioning only — there is no `If-Match` conditional-write enforcement
    // on PUT/PATCH in this slice, so advertising etag support would invite a
    // connector to rely on 412 semantics that never fire.
    j["etag"] = {{"supported", false}};
    j["authenticationSchemes"] = nlohmann::json::array(
        {{{"type", "oauthbearertoken"}, {"name", "OAuth Bearer Token"}, {"primary", true}}});
    j["meta"] = {{"resourceType", "ServiceProviderConfig"}};
    return j;
}

nlohmann::json resource_types() {
    nlohmann::json user_type;
    user_type["id"] = "User";
    user_type["name"] = "User";
    user_type["endpoint"] = "/Users";
    user_type["schema"] = kSchemaUser;
    user_type["meta"] = {{"resourceType", "ResourceType"}};

    return list_response({user_type}, 1, 1, 1);
}

nlohmann::json schemas() {
    nlohmann::json user_schema;
    user_schema["id"] = kSchemaUser;
    user_schema["name"] = "User";
    user_schema["description"] = "Yuzu SCIM User";
    user_schema["attributes"] = nlohmann::json::array(
        {{{"name", "userName"},
          {"type", "string"},
          {"required", true},
          {"uniqueness", "server"}},
         {{"name", "active"}, {"type", "boolean"}, {"required", false}},
         {{"name", "externalId"}, {"type", "string"}, {"required", false}}});
    user_schema["meta"] = {{"resourceType", "Schema"}};

    return list_response({user_schema}, 1, 1, 1);
}

} // namespace yuzu::server::scim
