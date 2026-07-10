#pragma once

/**
 * scim_json.hpp — JSON codec + discovery-doc layer for SCIM v2 provisioning
 * (slice 2 of 3).
 *
 * PURE functions only: serialize `ScimResource` (server/core/include/yuzu/
 * server/scim_store.hpp) to/from SCIM JSON, build the SCIM error/ListResponse
 * envelopes, parse the `userName eq "..."` filter IdPs use for existence
 * checks, and emit the three static discovery documents
 * (ServiceProviderConfig / ResourceTypes / Schemas). No HTTP route, no
 * database access — a sibling junior (slice 3) wires these into routes that
 * call `ScimStore`.
 *
 * Spec reference: RFC 7643 (SCIM Core Schema) / RFC 7644 (SCIM Protocol).
 */

#include "yuzu/server/scim_store.hpp"

#include <nlohmann/json_fwd.hpp>

#include <cstddef>
#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server::scim {

// ── SCIM schema URNs ────────────────────────────────────────────────────────

inline constexpr std::string_view kSchemaUser = "urn:ietf:params:scim:schemas:core:2.0:User";
inline constexpr std::string_view kSchemaError =
    "urn:ietf:params:scim:api:messages:2.0:Error";
inline constexpr std::string_view kSchemaListResponse =
    "urn:ietf:params:scim:api:messages:2.0:ListResponse";
inline constexpr std::string_view kSchemaPatchOp =
    "urn:ietf:params:scim:api:messages:2.0:PatchOp";
inline constexpr std::string_view kSchemaServiceProviderConfig =
    "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig";
inline constexpr std::string_view kSchemaResourceType =
    "urn:ietf:params:scim:schemas:core:2.0:ResourceType";
inline constexpr std::string_view kSchemaSchema = "urn:ietf:params:scim:schemas:core:2.0:Schema";

/// Bound on `externalId` (S-EXTID, UP-13): IdP-supplied opaque identifiers
/// are typically GUIDs/short opaque strings; 256 bytes is generous headroom
/// while refusing an absurdly oversized value on a field Yuzu only stores
/// and echoes back, never interprets. Uniqueness enforcement on this field
/// is NOT implemented (out of scope for this slice).
inline constexpr std::size_t kMaxExternalIdLength = 256;

/// The `filter.maxResults` this server advertises in ServiceProviderConfig
/// (S-CLAMP-COUNT). `ScimRoutes`'s GET /Users list handler clamps a
/// caller-supplied `count` to this same constant so the advertised cap is
/// actually enforced, not just documented.
inline constexpr int kMaxScimListResults = 200;

/// A structured SCIM error: `status` is the HTTP status to send AND is
/// serialized as a JSON *string* per RFC 7644 §3.12; `scim_type` is the
/// optional detail enum (e.g. "invalidValue", "invalidPath", "invalidFilter")
/// — empty omits the field.
struct ScimError {
    int status{400};
    std::string scim_type;
    std::string detail;
};

/// Parsed body of a SCIM User POST/PUT. Unknown fields (name, emails, etc.,
/// which real IdPs send) are tolerated and ignored — only the fields Yuzu's
/// resource mapping cares about are extracted.
struct ScimUserInput {
    std::string user_name;
    std::string external_id;
    std::optional<bool> active;
};

/// Parsed, flattened result of a SCIM PatchOp body. Only `replace` (and
/// `add`, treated identically) on `active`/`userName`/`externalId` is
/// supported — see scim_json.cpp for the full op/path support matrix.
struct ScimPatch {
    std::optional<bool> active;
    std::optional<std::string> user_name;
    std::optional<std::string> external_id;
};

// ── User resource codec ─────────────────────────────────────────────────────

/// Serialize a stored `ScimResource` to a SCIM User JSON representation.
/// `location_base` is the collection URL (e.g. "https://host/scim/v2/Users")
/// — the per-resource `meta.location` is `"<location_base>/<scim_id>"`.
nlohmann::json user_to_json(const ScimResource& r, std::string_view location_base);

/// Parse a SCIM User create/replace body. Requires a non-empty `userName`.
std::expected<ScimUserInput, ScimError> parse_user(const nlohmann::json& body);

/// Parse a SCIM PatchOp body (`Operations` array). See scim_json.cpp for the
/// supported op/path combinations.
std::expected<ScimPatch, ScimError> parse_patch(const nlohmann::json& body);

// ── Envelopes ────────────────────────────────────────────────────────────────

/// Build the SCIM error envelope (RFC 7644 §3.12). `status` is emitted as a
/// JSON string. `scim_type` is omitted from the envelope when empty.
nlohmann::json error(int status, std::string_view detail, std::string_view scim_type = "");

/// Convenience overload building the envelope directly from a `ScimError`.
nlohmann::json error(const ScimError& e);

/// Build a SCIM `ListResponse` envelope wrapping already-serialized resource
/// JSON objects (see `user_to_json`).
nlohmann::json list_response(const std::vector<nlohmann::json>& resources, int total_results,
                             int start_index, int items_per_page);

// ── Filter parsing ───────────────────────────────────────────────────────────

/// Parse a SCIM filter expression, supporting exactly `userName eq "value"`
/// (attribute + operator case-insensitive; value double-quoted with `\"`/`\\`
/// escapes). Returns the unescaped value, or a `{400,"invalidFilter",...}`
/// error for any other attribute/operator/malformed input.
std::expected<std::string, ScimError> parse_username_filter(std::string_view filter);

// ── Discovery documents ──────────────────────────────────────────────────────

/// `GET /ServiceProviderConfig` — static capability document.
nlohmann::json service_provider_config();

/// `GET /ResourceTypes` — a ListResponse describing the User resource type.
nlohmann::json resource_types();

/// `GET /Schemas` — a ListResponse describing the core User schema.
nlohmann::json schemas();

} // namespace yuzu::server::scim
