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
/// KNOWN LIMITATION, recorded deliberately, not implied away: because of the
/// default above, a chunked or Content-Length-less body is NOT refused on
/// any class but `/mcp/` — it falls through this entire gate uncapped to
/// httplib's own 100 MiB backstop. A comment or doc that says chunked bodies
/// are "refused" without naming `/mcp/` as the sole exception is wrong. This
/// is a recorded adjudication, not an oversight — see the paragraph above
/// for why — kept in sync with `docs/user-manual/rest-api.md` "Pre-Auth
/// Request Body Caps".
///
/// NO ROUTED-CONCERN ROW YET, and that is a known gap rather than an
/// oversight: `.claude/routed-concerns.md` is at its size ceiling (measured
/// 39,996 of 40,000 bytes on `dev`, i.e. four bytes free) and physically
/// cannot take one. Until the table is split, THIS HEADER is the only
/// statement of the chokepoint's invariants — treat it as load-bearing and
/// do not trim it for brevity. The invariants a row would carry: this table
/// is the single per-route body-cap chokepoint, EXTEND it and never fork it;
/// `path_class` is the only legal metric label, never the attacker-supplied
/// path; matching is segment-boundary, never bare `starts_with`; a new
/// mutating route needs its own entry or a reviewed catch-all decision, and
/// should prefer an any-method row, because verb-scoping silently drops the
/// whole prefix to the catch-all.
///
/// The numbers below are grounded in the cited call sites, not invented —
/// but "grounded" is not "measured byte-for-byte": two different kinds of
/// reasoning appear beside the exact matches, and BOTH are reasoned rather
/// than measured. (1) MEASURED-PLUS-MARGIN (`ca_import_chain_dashboard`,
/// `plugin_trust_bundle`, `tar_dashboard_sql`, `tar_result_set_sql`,
/// `instruction_yaml`): a real handler-level check exists and is cited, but
/// the pre-routing gate checks the RAW body while the handler checks a
/// DECODED/PARSED value (form-decoded, JSON-unescaped, or multipart-
/// extracted), so the cap adds an explicit margin over the handler's own
/// number instead of mirroring it — getting this wrong rejects legitimate
/// traffic, which is exactly what happened to the two TAR entries before
/// this fix (see their comments). (2) JUDGMENT CALL, NO CONTRACT
/// (`guardian_rule_authoring`, `workflow_yaml`, `product_pack_yaml`,
/// `instruction_import`, `nvd_match`): no aggregate size contract is defined
/// anywhere in the codebase for what these accept — arbitrary YAML/legacy
/// `yaml_source` bodies for the first three, an unbounded `responseTemplates`
/// array for `instruction_import`, an unbounded software-inventory array for
/// `nvd_match` — so each cap is an explicit, ADMITTEDLY-JUDGMENT-CALL bound
/// reasoned against that class's OWN realistic scale (not copy-pasted from a
/// sibling), rather than a squeeze. That is TEN of the table's entries
/// reasoned rather than exactly measured — do not tighten any of them
/// without a real contract to measure against, and do not read their
/// presence as license to guess a number for any OTHER class; every other
/// entry below mirrors a cited, decoded-equals-raw byte count exactly. A
/// THIRD, distinct category — `ota_upload` and `json_to_csv_export` — is
/// pinned at httplib's own 100 MiB backstop rather than squeezed OR given a
/// judgment-call MiB number: both carry content whose legitimate size is a
/// direct function of something this table cannot bound (an installer
/// binary's real size; an export's size following directly from the
/// operator's own prior query), so there is no smaller number to reason
/// toward — the entry's only job is making that an explicit, reviewed
/// decision instead of an accidental fallthrough to the catch-all.
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

    // POST /api/export/json-to-csv — generic JSON-array-to-CSV export
    // (server.cpp:10809; the entire raw body is handed to
    // `data_export::json_array_to_csv` verbatim). Unbounded BY DESIGN: this
    // converts a full exported dataset (responses, audit rows, inventory —
    // whatever REST query the caller ran) to CSV, and there is no natural
    // "this export is too big" line to draw; a large legitimate export is
    // the expected case, not an abuse case. Choice made here: an EXPLICIT
    // entry pinned at httplib's own 100 MiB backstop, mirroring the
    // ota_upload treatment immediately above — NOT squeezed to a judgment-
    // call MiB number, because unlike guardian_rule_authoring/workflow_yaml/
    // product_pack_yaml (arbitrary but SINGLE-DOCUMENT content, where a
    // generous MiB-scale cap is a defensible judgment call) an export's
    // size is a direct, unbounded function of how much data the operator's
    // own prior query returned — there is no analogous "one document" scale
    // to be generous relative to. This entry's only job is to make that a
    // reviewed decision instead of an accidental fallthrough to the 4 MiB
    // catch-all, which would break real exports outright.
    {"POST", "/api/export/json-to-csv", 100u * 1024 * 1024, false, "json_to_csv_export"},

    // POST /api/nvd/match — software-inventory vulnerability match
    // (server.cpp:9258; parses a JSON body's `inventory` array of
    // {name, version} pairs, no size check anywhere in the handler or
    // `NvdDatabase::match_inventory`). No aggregate contract exists, but
    // unlike json_to_csv_export above this content IS naturally bounded in
    // scale — one call carries one device's installed-software census.
    // Sized to that: even a maximal per-item JSON encoding (long name +
    // version strings, keys, braces, comma) is well under 200 bytes/item,
    // so 8 MiB admits roughly 40000+ inventory items — an order of
    // magnitude above any real single-device software census (a heavily
    // packaged Linux workstation or a Windows box with a large registry
    // Programs list runs to a few thousand entries at most). Reasoned to
    // this specific content's realistic scale, not borrowed from the
    // arbitrary-YAML judgment-call classes below; still two orders of
    // magnitude below httplib's 100 MiB backstop.
    {"POST", "/api/nvd/match", 8u * 1024 * 1024, false, "nvd_match"},

    // POST /api/v1/ca/import-chain — subordinate CA chain import, JSON body
    // (ca_routes.cpp:24 kMaxImportBody, enforced at :516). Mirrors the
    // handler's own 256 KiB bound exactly, so this pre-routing gate never
    // rejects anything the handler itself would still admit.
    {"POST", "/api/v1/ca/import-chain", 256u * 1024, false, "ca_import_chain"},

    // POST /api/v1/ca/revoke — serial-scoped cert revocation, JSON body
    // (ca_routes.cpp:24 kMaxRevokeBody, enforced at ca_routes.cpp:394 before
    // the body reaches nlohmann::json::parse). Mirrors that bound exactly —
    // same reasoning as the import-chain entry above. Without this entry the
    // route silently fell through to the 4 MiB catch-all, two authorities
    // (this table and the handler) disagreeing on the same route.
    {"POST", "/api/v1/ca/revoke", 64u * 1024, false, "ca_revoke"},

    // POST /api/v1/secrets/kek/rotate|rewrap — both take zero body fields
    // (kek_routes.cpp:46 kMaxKekBody, enforced at :54 in validate_empty_body,
    // shared by both handlers before either parses JSON). One entry covers
    // both routes: they share the literal prefix "/api/v1/secrets/kek/" and
    // the segment-boundary matcher treats a prefix already ending in '/' as
    // matching every child segment (see body_cap_prefix_matches). Mirrors
    // kMaxKekBody exactly — same two-authority-split fix as ca_revoke above.
    {"POST", "/api/v1/secrets/kek/", 64u * 1024, false, "kek_ops"},

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

    // SCIM — scim_routes.cpp:65 kMaxBodyBytes, currently checked only AFTER
    // buffering (first call site :827). This moves the same bound BEFORE the
    // buffer. One path prefix covers both /Users and /Groups sub-resources
    // (scim_routes.cpp's route registrations all resolve under "/scim/v2/").
    //
    // ANY-METHOD, deliberately, and do NOT narrow this back to the three
    // mutating verbs. An adversarial review found that method-scoping let a
    // verb switch (DELETE, OPTIONS, or a GET carrying a body) drop the whole
    // prefix to the 4 MiB catch-all — 64x this class's bound. That is not a
    // widening in the capability sense, since the catch-all already offers
    // 4 MiB on every (method, path) by explicit reviewed decision, which is
    // why it was adjudicated MEDIUM rather than blocking. It is still wrong
    // here specifically: SCIM DELETE routes are real (scim_routes.cpp:1577,
    // :2316), every /scim/v2/* path is session-auth-exempt, and httplib
    // buffers before the in-handler require_bearer runs — so this prefix is
    // reachable pre-auth on more verbs than the three that mutate. A class
    // whose bound is justified by the shape of its payload should not depend
    // on the verb used to deliver it.
    {kBodyCapAnyMethod, "/scim/v2/", 64u * 1024, false, "scim"},

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
    // fields `sql` + `scope` (dashboard_routes.cpp:866 `sql.size() > 4096`
    // check on the FORM-DECODED value). The #2407-as-shipped 4096-byte cap
    // capped the RAW body at the SAME number the handler checks against the
    // DECODED field — a unit mismatch, not a margin. The raw body is
    // `"sql=" + percent-encoded(sql) + "&scope=" + percent-encoded(scope)`,
    // so a 4093-4096 character query was unconditionally rejected before the
    // handler ever ran, and any query containing a `'`, `(`, `)`, `=`, `,`,
    // or a newline was rejected far earlier (percent-encoding is up to 3x
    // per character worst case). Measured case: a 4085-character realistic
    // query produced a 5078-byte raw body, 24% over the old 4096-byte cap —
    // legitimate traffic, rejected. Fix: 3 x 4096 (worst-case percent-
    // encoding of the full 4096-char decoded `sql` value the handler still
    // admits) + 4 KiB flat headroom for the "sql="/"&scope=" field-name
    // framing and the `scope` field's own percent-encoded value (which has
    // no size contract of its own — `scope` is normally an agent id or
    // "group:<name>", short, but nothing bounds it today) = 12288 + 4096 =
    // 16384 bytes exactly. Reasoned margin, not a byte-for-byte measurement
    // — same category as the CA/plugin-trust dashboard classes below.
    {"POST", "/api/dashboard/tar-execute", 16u * 1024, false, "tar_dashboard_sql"},

    // POST /api/v1/result-sets/from-tar-query — TAR result-set SQL, JSON
    // body (rest_api_v1.cpp:6802, `sql.size() > 100000` check on the JSON-
    // PARSED `sql` field). Same unit mismatch as tar_dashboard_sql above,
    // with almost no headroom to hide it: the old 102400-byte cap left only
    // 2400 bytes over the handler's 100000-character check to absorb JSON
    // string-escaping (quotes, backslashes, and control characters expand
    // under JSON escaping — a raw control byte with no named escape costs 6
    // bytes as `\u00XX`) plus the request's other keys (`include_empty`,
    // `parent_id`, object braces). The old comment claimed "this pre-routing
    // gate never rejects a body the handler would still admit" — false; a
    // legitimate 99000+-character query containing a modest amount of
    // escaping could exceed 102400 raw bytes and be rejected here while the
    // handler would have admitted it. Fix: double the handler's 100000-byte
    // check for escaping headroom (200000 bytes), which also covers the
    // other JSON keys — 200 KiB (204800 bytes) exactly. NOTE the asymmetry
    // this table cannot erase: the handler answers `400 RESULT_SET_BAD_
    // REQUEST` for an over-100000-character `sql` field; this pre-routing
    // gate answers `413` for an over-200-KiB raw body. They are not the same
    // check re-run twice — a raw body between 100000 and 204800 bytes whose
    // decoded `sql` value is still <=100000 characters passes here and is
    // then decided by the handler's own check, as intended; a raw body over
    // 204800 bytes never reaches the handler at all.
    {"POST", "/api/v1/result-sets/from-tar-query", 200u * 1024, false,
     "tar_result_set_sql"},

    // POST /api/v1/guaranteed-state/rules — Guardian rule authoring
    // (rest_api_v1.cpp:7759 handler start; :7842 the legacy path that
    // accepts an arbitrary supplied `yaml_source` verbatim). No aggregate
    // rule-size contract exists yet anywhere in the codebase, so this is a
    // deliberate, generous EXPLICIT entry rather than a squeeze — see the
    // file header. Do NOT tighten this without a real contract to measure
    // against.
    {"POST", "/api/v1/guaranteed-state/rules", 16u * 1024 * 1024, false,
     "guardian_rule_authoring"},

    // PUT /api/v1/guaranteed-state/rules/{id} — the sibling regex UPDATE
    // route (rest_api_v1.cpp:7904). #2407-as-shipped scoped the entry above
    // to POST only, so a PUT fell through to the 4 MiB catch-all default —
    // a rule created at up to 16 MiB (the entry above) could then never be
    // edited back through the same-sized route. Same class, same "no
    // contract yet" reasoning as the POST entry, so the same 16 MiB bound.
    // Path prefix ends in '/' so the segment-boundary matcher
    // (body_cap_prefix_matches) covers the regex-captured `{id}` suffix —
    // see the file header's MATCHING section for why path-only matching
    // could not otherwise tell this apart from the POST create route on the
    // identical literal prefix.
    {"PUT", "/api/v1/guaranteed-state/rules/", 16u * 1024 * 1024, false,
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

    // POST /api/instructions/import — JSON instruction-definition import,
    // whole raw body forwarded verbatim to `import_definition_json`
    // (server.cpp:11130 -> instruction_store.cpp:954 -> create_definition_
    // impl:434, which DOES hard-reject an oversized `yaml_source` field at
    // 1048576 bytes via validate_definition_scope, instruction_store.cpp:
    // 411). That real check does NOT bound the whole request, though: an
    // imported definition also carries an optional `responseTemplates`
    // field, and when it is supplied as a native JSON array/object (not a
    // pre-serialized string) `normalise_templates_array` applies NO size
    // limit at all (the 256 KiB `kMaxImportTemplateStringBytes` guard,
    // instruction_store.cpp:904, only fires on the string-form branch) — so
    // a well-formed request with a huge templates array is not rejected by
    // anything downstream. No genuine aggregate contract, therefore: same
    // "no contract yet" judgment-call category as guardian_rule_authoring/
    // workflow_yaml/product_pack_yaml above, and the same peer bound.
    {"POST", "/api/instructions/import", 16u * 1024 * 1024, false, "instruction_import"},

    // POST /api/instructions/yaml (save), POST /api/instructions/validate-
    // yaml, POST /fragments/instructions/yaml-preview — three FORM-encoded
    // (application/x-www-form-urlencoded) twins of one shape: a single
    // `yaml_source` field (save also carries a small `id` field), all three
    // routed through the SAME check — server.cpp:6493 `validate_yaml_source`
    // -> `instruction_yaml::validate_definition_yaml`, which hard-rejects
    // `yaml_source.size() > 1048576` at instruction_yaml.cpp:165 (the exact
    // 1 MiB decoded-value contract create/update also enforce). This is the
    // SAME raw-vs-decoded shape as tar_dashboard_sql (C1) — the pre-routing
    // gate sees the percent-encoded RAW body, the handler checks the
    // DECODED `yaml_source` value — so the cap must NOT mirror 1048576
    // directly (the #2407-as-shipped defect this table already paid for
    // once). Fix, same method as C1: 3x1048576 (worst-case percent-encoding
    // of the full 1 MiB decoded value the handler still admits) + 4 KiB
    // flat headroom for the "yaml_source="/"&id=" field-name framing (the
    // `id` field itself has no length contract anywhere in the codebase) =
    // 3145728 + 4096 = 3149824 bytes exactly. One shared cap+label across
    // all three routes — same size-defense reasoning, same check, distinct
    // literal paths (no common prefix to key one table entry on).
    {"POST", "/api/instructions/yaml", 3149824u, false, "instruction_yaml"},
    {"POST", "/api/instructions/validate-yaml", 3149824u, false, "instruction_yaml"},
    {"POST", "/fragments/instructions/yaml-preview", 3149824u, false, "instruction_yaml"},

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
    //
    // UNDOCUMENTED-METRIC GAP (recorded, not yet closed): `path_class=
    // "unmatched"` is a real value this function can emit, but it is not a
    // row in `kBodyCapTable`, so `server.cpp`'s boot-time pre-seed loop
    // (which iterates `kBodyCapTable` to pre-seed `yuzu_body_cap_rejected_
    // total`'s closed label set to 0) never seeds it — the series would
    // appear unannounced the first time this sentinel is ever reached.
    // `server.cpp` owns that seeding loop; this header only owns documenting
    // the gap so it is not silently assumed closed.
    if (best == nullptr)
        return {0, true, "unmatched"};
    return {best->max_body_bytes, best->requires_measurable, best->path_class};
}

} // namespace yuzu::server
