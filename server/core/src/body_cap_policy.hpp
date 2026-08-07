#pragma once

#include <cstddef>
#include <string_view>

/// @file body_cap_policy.hpp
/// The ONE table deciding the pre-auth request-body byte cap per route class
/// (#2407).
///
/// THE DEFECT: an unauthenticated caller can make the server buffer up to
/// httplib's 100 MiB default (`CPPHTTPLIB_PAYLOAD_MAX_LENGTH`, httplib.h:130)
/// on every route except `/mcp/`, which `server.cpp`'s pre-routing handler
/// already caps at 4 MiB (#2437, `mcp_body_exceeds_cap`/`mcp_body_unmeasurable`
/// in `web_utils.hpp`). This header generalizes that per-path cap into one
/// table so every other route family gets a bound sized to what it actually
/// needs, instead of either httplib's 100 MiB backstop everywhere (too loose)
/// or one global 4 MiB cap (too tight — it would break the ~70 MiB live-query
/// bundle route outright).
///
/// THE RULE, stated once: the cap is enforced in `server.cpp`'s pre-routing
/// handler, the SAME chokepoint the existing `/mcp/` cap already runs from —
/// NEVER inside a route handler. httplib invokes the pre-routing handler
/// BEFORE it reads the request body (httplib.h: `routing()` calls the
/// pre-routing handler, then `read_content()`, in that order), so a rejection
/// returned from there costs a header parse and never buffers the oversized
/// payload. Enforcing the same bound inside a handler is too late — by the
/// time a handler runs, httplib has already buffered the body up to its own
/// 100 MiB backstop. This header is deliberately NOT a
/// `Server::set_payload_max_length` call: that knob is server-global and
/// would also squeeze the certificate-chain upload and content-distribution
/// staging on the same httplib instance — the issue text proposes it and it
/// is deliberately rejected here.
///
/// EXTEND this table, never fork it — a second cap list is exactly the kind
/// of drift `authz_topology_floor.hpp` and `dispatch_confined_arms.hpp` exist
/// to prevent for their own chokepoints.
///
/// MATCHING: the key is `{method, segment-boundary path prefix}`, NOT path
/// alone. Path-only matching is insufficient — the real route table carries
/// method-specific AND regex registrations on the very same literal prefix
/// (e.g. `rest_api_v1.cpp:7759`'s `POST /api/v1/guaranteed-state/rules` vs
/// `:7904`'s regex `PUT /api/v1/guaranteed-state/rules/{id}`), so a
/// path-only cap could not tell a bulk-create request from a single-rule
/// update even if they warranted different bounds. Matching is on SEGMENT
/// BOUNDARIES: `/api/v1/bundlesevil` must NOT match the `/api/v1/bundles`
/// entry (`body_cap_prefix_matches` requires the byte immediately after the
/// prefix to be `/`, or the prefix to already end in `/`, or an exact-length
/// match). Longest match wins, so a narrow, more specific entry (e.g.
/// `/scim/v2/`) always beats the always-matching catch-all default. There is
/// an explicit catch-all default entry (empty prefix, matches every method)
/// so `resolve_body_cap` never has "no answer" for an unlisted route.
///
/// `requires_measurable` decides whether a body this server cannot size in
/// advance — chunked `Transfer-Encoding`, or POST/PUT/PATCH with no
/// `Content-Length` — is REFUSED outright rather than admitted up to the
/// cap. Chunked request bodies are legal HTTP, and this repo does not
/// control every client that will ever talk to these routes, so the bit
/// DEFAULTS OFF and is opted into per class, not per table. It is ON only
/// for `/mcp/`: that surface's own protocol/client contract already requires
/// `Content-Length` on every framed body (see `web_utils.hpp:577`'s
/// `mcp_body_unmeasurable` rationale), so refusing an unmeasurable MCP body
/// costs a conforming client nothing. Every other class below — public REST
/// (bundles), SCIM, certificate import (REST + dashboard), the plugin trust
/// bundle, product-pack/workflow authoring, and the OTA upload — keeps it
/// OFF and falls back to httplib's 100 MiB backstop for a body it cannot
/// size, until a Content-Length contract is documented and a representative
/// client population is tested against it. That is a scoping decision for
/// THIS change, not a claim those routes are safe unmeasured forever.
///
/// The numbers below are MEASURED against the cited call sites, not
/// invented — each entry's comment names the exact source. Three classes
/// (`guardian_rule_authoring`, `workflow_yaml`, `product_pack_yaml`) are the
/// documented exception: they accept arbitrary YAML/legacy `yaml_source`
/// bodies with no aggregate size contract defined yet anywhere in the
/// codebase, so their cap is an explicit, generous, ADMITTEDLY-JUDGMENT-CALL
/// bound (still three orders of magnitude below httplib's 100 MiB backstop)
/// rather than a squeeze — do not tighten them without a real contract to
/// measure against, and do not read their presence as license to guess a
/// number for any OTHER class.
namespace yuzu::server {

/// Sentinel method value meaning "matches every HTTP method". Used ONLY
/// where the cap genuinely does not depend on method — today that is
/// `/mcp/` (server.cpp's existing #2437 gate scopes it by path alone across
/// GET SSE, POST JSON-RPC, and DELETE session teardown) and the catch-all
/// default.
inline constexpr std::string_view kBodyCapAnyMethod = "*";

/// One `{method, path-prefix}` -> `{cap, requires_measurable, metric label}`
/// row.
struct BodyCapEntry {
    /// Exact HTTP method (e.g. "POST"), or `kBodyCapAnyMethod`.
    std::string_view method;
    /// Segment-boundary path prefix — see `body_cap_prefix_matches`.
    std::string_view path_prefix;
    /// The enforced cap, in bytes. Never zero (locked by test).
    std::size_t max_body_bytes;
    /// Refuse a chunked / Content-Length-less body for this class instead of
    /// admitting it up to the cap. Defaults OFF per-class; see file header.
    bool requires_measurable;
    /// Stable short label for a metric dimension. MUST be a fixed string
    /// literal from this table — NEVER derived from the raw, attacker-
    /// controlled request path (unbounded cardinality on a pre-auth metric
    /// is its own DoS surface).
    std::string_view path_class;
};

/// THE table. Longest matching `path_prefix` wins among entries whose
/// `method` also matches (exact, or `kBodyCapAnyMethod`). See the file
/// header for the enforcement chokepoint, the matching rule, and the
/// `requires_measurable` default.
inline constexpr BodyCapEntry kBodyCapTable[] = {
    // /mcp/ — unchanged from #2437. ANY method: is_mcp_path() (web_utils.hpp)
    // scopes this by path alone, and the pre-routing cap must cover every
    // method reaching that surface (GET SSE, POST JSON-RPC, DELETE session
    // teardown), not just POST. requires_measurable=true: MCP's own client
    // contract already requires Content-Length (web_utils.hpp:577).
    // Source: mcp_jsonrpc.hpp:63 (kMcpMaxRequestBodyBytes).
    {kBodyCapAnyMethod, "/mcp/", 4u * 1024 * 1024, true, "mcp"},

    // POST /api/v1/bundles — live-query bundle dispatch (rest_api_v1.cpp:1417).
    // bundle_service.hpp:24-33 admits up to kMaxBundleSteps(32) steps x
    // kMaxParamCountPerStep(32) params x kMaxParamValueLen(64 KiB) = 64 MiB
    // of raw param VALUE bytes alone; JSON structural overhead (keys,
    // quotes, braces, plugin/action strings) adds more on top. 70 MiB
    // leaves ~6 MiB of headroom above that computed 64 MiB floor. A 4 MiB
    // default (the catch-all below) would break this route outright — do
    // not "simplify" this entry away.
    {"POST", "/api/v1/bundles", 70u * 1024 * 1024, false, "bundles"},

    // POST /api/settings/updates/upload — OTA agent binary upload
    // (settings_routes.cpp:5146 handler start, :5206 the unbounded file
    // read). No route-local limit exists today; keep httplib's own 100 MiB
    // default (httplib.h:130, CPPHTTPLIB_PAYLOAD_MAX_LENGTH) as the outer
    // backstop rather than squeeze a legitimate multi-ten-MB installer
    // binary. This entry exists so the class is an explicit, reviewed
    // decision rather than an accidental fallthrough to the catch-all.
    {"POST", "/api/settings/updates/upload", 100u * 1024 * 1024, false, "ota_upload"},

    // POST /api/v1/ca/import-chain — subordinate CA chain import, JSON body
    // (ca_routes.cpp:24 kMaxImportBody, enforced at :516). Mirrors the
    // handler's own 256 KiB bound exactly, so this pre-routing gate never
    // rejects anything the handler itself would still admit.
    {"POST", "/api/v1/ca/import-chain", 256u * 1024, false, "ca_import_chain"},

    // POST /api/settings/ca/import-chain — the dashboard (HTMX,
    // application/x-www-form-urlencoded) twin of the above
    // (ca_routes.cpp:727). It has NO raw-body size check of its own, so
    // this pre-routing entry is its ONLY bound. Doubled versus the REST
    // JSON cap as conservative headroom for form percent-encoding overhead
    // (worst case 3x per byte on '+', '/', '=', and the line-wrap '\n's in
    // the base64 PEM text; real overhead is far smaller) plus the two form
    // field names/framing — still three orders of magnitude below
    // httplib's 100 MiB backstop.
    {"POST", "/api/settings/ca/import-chain", 512u * 1024, false,
     "ca_import_chain_dashboard"},

    // POST /api/settings/plugin-signing/upload — plugin code-signing trust
    // bundle (settings_routes.cpp:3445 upload handler, :3461 the 256 KiB
    // check). That check bounds the PARSED multipart file CONTENT, not the
    // raw request body (boundary markers, part headers, the filename
    // field). Doubled for that framing overhead, same reasoning as the CA
    // dashboard twin above.
    {"POST", "/api/settings/plugin-signing/upload", 512u * 1024, false,
     "plugin_trust_bundle"},

    // SCIM mutations — scim_routes.cpp:65 kMaxBodyBytes, currently checked
    // only AFTER buffering (first call site :827). This moves the same
    // bound BEFORE the buffer. Three entries (POST create, PUT replace,
    // PATCH partial-update), one path prefix shared by both /Users and
    // /Groups sub-resources (scim_routes.cpp's six route registrations all
    // resolve under "/scim/v2/").
    {"POST", "/scim/v2/", 64u * 1024, false, "scim"},
    {"PUT", "/scim/v2/", 64u * 1024, false, "scim"},
    {"PATCH", "/scim/v2/", 64u * 1024, false, "scim"},

    // POST /saml/acs — SAML assertion consumer service
    // (auth_routes.cpp:2794-2798, kSamlMaxBodyBytes). A legitimate signed
    // SAMLResponse is well under 64 KiB; 1 MiB is generous headroom while
    // refusing a plaintext-amplification DoS via an oversized fake
    // SAMLResponse field.
    {"POST", "/saml/acs", 1u * 1024 * 1024, false, "saml_acs"},

    // POST/PUT /api/v1/definitions/{id}/response-templates[/{template_id}]
    // (rest_api_v1.cpp:4237 kRtMaxBodyBytes, checked at :4376 and :4461).
    // The id segments are regex-captured, so the widest LITERAL prefix this
    // table's segment-boundary matcher can key on is
    // "/api/v1/definitions/" — the whole subtree, not just the
    // response-templates sub-resource. That is safe today because those are
    // the ONLY two POST/PUT registrations under this prefix (verified
    // against rest_api_v1.cpp); a future mutation route added elsewhere
    // under /api/v1/definitions/ inherits this 64 KiB cap too unless it
    // gets its own, more specific entry ABOVE this one (longest match wins,
    // so a new entry naming its own longer literal prefix takes priority
    // automatically).
    {"POST", "/api/v1/definitions/", 64u * 1024, false, "response_templates"},
    {"PUT", "/api/v1/definitions/", 64u * 1024, false, "response_templates"},

    // POST /api/dashboard/tar-execute — TAR warehouse SQL query, HTMX form
    // field (dashboard_routes.cpp: `sql.size() > 4096` check). Bound on the
    // literal cited value; unlike the CA/plugin-trust dashboard classes
    // above, no extra form-encoding margin is added here — the brief this
    // table implements pins this class at a flat 4 KiB.
    {"POST", "/api/dashboard/tar-execute", 4u * 1024, false, "tar_dashboard_sql"},

    // POST /api/v1/result-sets/from-tar-query — TAR result-set SQL, JSON
    // body (rest_api_v1.cpp:6797, `sql.size() > 100000` check). 100 KiB
    // (102400 bytes) is a few hundred bytes above that literal 100000-byte
    // handler check, so this pre-routing gate never rejects a body the
    // handler would still admit.
    {"POST", "/api/v1/result-sets/from-tar-query", 100u * 1024, false,
     "tar_result_set_sql"},

    // POST /api/v1/guaranteed-state/rules — Guardian rule authoring
    // (rest_api_v1.cpp:7759 handler start; :7842 the legacy path that
    // accepts an arbitrary supplied `yaml_source` verbatim). No aggregate
    // rule-size contract exists yet anywhere in the codebase, so this is a
    // deliberate, generous EXPLICIT entry rather than a squeeze — see the
    // file header. Do NOT tighten this without a real contract to measure
    // against. Scoped to POST only (the creation route this brief measured);
    // the sibling regex PUT update route at :7904 falls through to the
    // catch-all default until it gets its own reviewed entry.
    {"POST", "/api/v1/guaranteed-state/rules", 16u * 1024 * 1024, false,
     "guardian_rule_authoring"},

    // POST /api/workflows — workflow authoring from a YAML bundle
    // (workflow_routes.cpp:1023). Same "no aggregate contract yet" shape as
    // guardian rule authoring above — deliberate, generous, explicit.
    {"POST", "/api/workflows", 16u * 1024 * 1024, false, "workflow_yaml"},

    // POST /api/product-packs — product-pack installation from a YAML
    // bundle (workflow_routes.cpp:1746). A pack holds MULTIPLE YAML
    // documents (product_pack_store.cpp:122's `split_yaml_documents`), so
    // this needs the same generous headroom as workflow authoring, not the
    // single-document default.
    {"POST", "/api/product-packs", 16u * 1024 * 1024, false, "product_pack_yaml"},

    // The catch-all default. ANY method, empty prefix — always matches, and
    // always loses a longest-match comparison against every entry above.
    // Ordinary JSON/form traffic (most REST mutation routes) lands here.
    {kBodyCapAnyMethod, "", 4u * 1024 * 1024, false, "default"},
};

/// True when `path` matches `prefix` at a segment boundary: `path` starts
/// with `prefix`, and either the match consumes the whole path, `prefix`
/// itself already ends in `/`, or the next byte of `path` after the prefix
/// is `/`. This is what stops `/api/v1/bundlesevil` from matching the
/// `/api/v1/bundles` entry — a plain `starts_with` would let it through.
[[nodiscard]] constexpr bool body_cap_prefix_matches(std::string_view path,
                                                     std::string_view prefix) noexcept {
    if (!path.starts_with(prefix))
        return false;
    if (path.size() == prefix.size())
        return true;
    if (prefix.ends_with('/'))
        return true;
    return path[prefix.size()] == '/';
}

/// The resolved cap for one `(method, path)` pair — a copy of the matched
/// entry's non-key fields.
struct BodyCapMatch {
    std::size_t max_body_bytes;
    bool requires_measurable;
    std::string_view path_class;
};

/// Resolve the body-cap policy for one request. Longest matching
/// `path_prefix` wins among entries whose `method` also matches (exact
/// method, or `kBodyCapAnyMethod`); the catch-all default entry guarantees a
/// match always exists. `noexcept` — this is a pure table lookup called from
/// the pre-routing handler for every request server-wide, with no error path
/// to report through (mirrors `dispatch_confined_arms.hpp`'s style).
[[nodiscard]] constexpr BodyCapMatch resolve_body_cap(std::string_view method,
                                                      std::string_view path) noexcept {
    const BodyCapEntry* best = nullptr;
    for (const auto& entry : kBodyCapTable) {
        if (entry.method != kBodyCapAnyMethod && entry.method != method)
            continue;
        if (!body_cap_prefix_matches(path, entry.path_prefix))
            continue;
        if (best == nullptr || entry.path_prefix.size() > best->path_prefix.size())
            best = &entry;
    }
    // Unreachable in practice — the catch-all default (empty prefix,
    // kBodyCapAnyMethod) matches every (method, path), so `best` is always
    // set. Guarded rather than dereferenced blindly so a future edit that
    // accidentally removes or mis-scopes the default entry fails LOUD (a
    // zero-byte cap that rejects everything) instead of invoking UB.
    if (best == nullptr)
        return {0, true, "unmatched"};
    return {best->max_body_bytes, best->requires_measurable, best->path_class};
}

} // namespace yuzu::server
