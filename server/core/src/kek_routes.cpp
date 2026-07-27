#include "kek_routes.hpp"

#include "rest_a4_envelope.hpp"

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <cstddef>
#include <string>
#include <utility>

namespace yuzu::server {

namespace {

using detail::error_json_a4;
using detail::make_correlation_id;

constexpr const char* kJson = "application/json";
// All three operations take zero parameters; the body must be absent or
// `{}`. Cap it defensively before parsing (mirrors ca_routes.cpp's
// kMaxRevokeBody) — a multi-GB POST must not reach nlohmann::json::parse on
// this privileged endpoint.
constexpr std::size_t kMaxKekBody = 64 * 1024;

/// Validate that `req.body` is either empty or parses to `{}`. This is the
/// mass-assignment guard from ca_routes.cpp:418-428, specialised for a route
/// that accepts zero fields — so ANY key present makes the body unknown.
/// On failure, writes the A4 error response and returns false; the caller
/// must `return` immediately in that case.
bool validate_empty_body(const httplib::Request& req, httplib::Response& res) {
    if (req.body.size() > kMaxKekBody) {
        res.status = 413;
        res.set_content(error_json_a4(413, "request body too large", make_correlation_id()), kJson);
        return false;
    }
    if (req.body.empty())
        return true;
    // Hermes-style defensive parse (matches ca_routes.cpp's revoke handler):
    // allow_exceptions=false turns a parse error into a discarded value
    // (caught by !is_object below), and the try/catch guards against an
    // impl-specific throw (e.g. bad_alloc) reaching this privileged endpoint.
    nlohmann::json body;
    try {
        body = nlohmann::json::parse(req.body, nullptr, false);
    } catch (...) {
        res.status = 400;
        res.set_content(error_json_a4(400, "invalid JSON body", make_correlation_id()), kJson);
        return false;
    }
    if (!body.is_object()) {
        res.status = 400;
        res.set_content(error_json_a4(400, "invalid JSON body", make_correlation_id()), kJson);
        return false;
    }
    if (!body.empty()) {
        res.status = 400;
        res.set_content(error_json_a4(400, "unknown field in request body", make_correlation_id(),
                                      "this operation takes no parameters; send an empty body or {}"),
                        kJson);
        return false;
    }
    return true;
}

/// Short, static (never seam-supplied) tag for the audit `detail` column —
/// safe to log verbatim, unlike anything the seam might have classified as
/// Internal (rule B: a codec-internal error string must never surface here
/// either, in the audit trail or the HTTP body).
const char* failure_tag(KekOpResult::Failure failure) {
    switch (failure) {
    case KekOpResult::Failure::Unavailable:
        return "failure=unavailable";
    case KekOpResult::Failure::Conflict:
        return "failure=conflict";
    case KekOpResult::Failure::Cooldown:
        return "failure=cooldown";
    case KekOpResult::Failure::HalfCommitted:
        return "failure=half_committed";
    case KekOpResult::Failure::Internal:
    case KekOpResult::Failure::None:
        return "failure=internal";
    }
    return "failure=internal";
}

/// Map a `KekOpResult::Failure` to the A4 error envelope and write it to
/// `res`. Rule A (#2395): HalfCommitted's remediation is the single most
/// important string in this module — it MUST tell the operator to call
/// `/rewrap` to resume and MUST NOT invite a `/rotate` retry (which would
/// mint a spurious extra version on top of an already-half-rotated state).
/// Rule B: Internal NEVER interpolates any seam-supplied string — generic
/// message + correlation id only.
void write_failure(httplib::Response& res, KekOpResult::Failure failure) {
    switch (failure) {
    case KekOpResult::Failure::Unavailable:
        res.status = 503;
        res.set_content(error_json_a4(503, "KEK service unavailable", make_correlation_id(),
                                      /*retry_after_ms=*/5000,
                                      "the Postgres substrate or secrets codec is not available; "
                                      "retry once the server reports it is ready"),
                        kJson);
        return;
    case KekOpResult::Failure::Conflict:
        res.status = 409;
        // Retryable, and NOT the caller's fault — another rotation holds the
        // cluster-wide advisory lock. Carries an honest retry_after_ms so an
        // agentic caller backs off rather than guessing, matching the MCP
        // twin's Conflict branch exactly (agentic-first A5).
        res.set_content(error_json_a4(409, "another KEK operation is in progress",
                                      make_correlation_id(), /*retry_after_ms=*/5000,
                                      "another rotation or re-wrap holds the KEK operation lock; "
                                      "retry once it completes"),
                        kJson);
        return;
    case KekOpResult::Failure::Cooldown:
        // Distinct from Conflict on purpose (Hermes pass 2, MEDIUM 2c): telling
        // an operator "another rotation holds the lock" when in fact they
        // attempted one two minutes ago is simply false, and sends them hunting
        // a concurrent operation that does not exist.
        res.status = 429;
        res.set_content(error_json_a4(429, "KEK rotation is in its cooldown window",
                                      make_correlation_id(), /*retry_after_ms=*/300000,
                                      "a KEK rotation was attempted very recently; rotation "
                                      "attempts are rate-limited. If you are finishing a "
                                      "half-committed rotation, call the rewrap route instead — "
                                      "it is NOT rate-limited and is the correct way to resume"),
                        kJson);
        return;
    case KekOpResult::Failure::HalfCommitted:
        res.status = 500;
        res.set_content(
            error_json_a4(500, "KEK rotation did not finish re-wrapping every secret",
                          make_correlation_id(),
                          "the new KEK version was registered but re-wrapping did not finish; "
                          "call POST /api/v1/secrets/kek/rewrap to resume — do NOT retry "
                          "POST /api/v1/secrets/kek/rotate, which would mint a spurious extra "
                          "version"),
            kJson);
        return;
    case KekOpResult::Failure::Internal:
    case KekOpResult::Failure::None: // unreachable on this path; treat as internal
        res.status = 500;
        res.set_content(error_json_a4(500, "internal error", make_correlation_id()), kJson);
        return;
    }
}

} // namespace

void KekRoutes::register_routes(httplib::Server& svr, PermFn perm_fn, AuditFn audit_fn, KekOps ops) {
    HttplibRouteSink sink(svr);
    register_routes(sink, std::move(perm_fn), std::move(audit_fn), std::move(ops));
}

void KekRoutes::register_routes(HttpRouteSink& sink, PermFn perm_fn, AuditFn audit_fn, KekOps ops) {
    spdlog::info("KEK routes: registering /api/v1/secrets/kek/*");

    // ── POST /api/v1/secrets/kek/rotate ── Security:Write. ────────────────────
    // Mints a new KEK version and re-wraps every registered secret row under
    // it. No request parameters. On a HalfCommitted failure the new version
    // is already active — the operator resumes via /rewrap, never by retrying
    // this route (see write_failure's HalfCommitted branch, #2395 rule A).
    sink.Post("/api/v1/secrets/kek/rotate",
             [perm_fn, audit_fn, ops](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn(req, res, "Security", "Write"))
                     return;
                 if (!ops.rotate) {
                     res.status = 503;
                     res.set_content(
                         error_json_a4(503, "KEK service unavailable", make_correlation_id(),
                                      /*retry_after_ms=*/5000,
                                      "the Postgres substrate or secrets codec is not available; "
                                      "retry once the server reports it is ready"),
                         kJson);
                     return;
                 }
                 if (!validate_empty_body(req, res))
                     return;
                 const KekOpResult result = ops.rotate();
                 if (result.failure != KekOpResult::Failure::None) {
                     (void)audit_fn(req, "kek.rotate", "failure", "Secret", "kek",
                                    failure_tag(result.failure));
                     write_failure(res, result.failure);
                     return;
                 }
                 if (!audit_fn(req, "kek.rotate", "success", "Secret", "kek",
                               "new_version=" + std::to_string(result.new_version)))
                     res.set_header("Sec-Audit-Failed", "true");
                 // Deliberately NO rows_rewrapped here: rotate_kek() discards
                 // its internal rewrap_all()'s count, so any number we printed
                 // would be a guess. `rotation_complete` is the honest signal
                 // and the one ADR-0010 §3 defines as the completion criterion.
                 // Call /rewrap if you want a real count.
                 nlohmann::json out = {{"new_version", result.new_version},
                                       {"rotation_complete", result.rotation_complete},
                                       {"meta", {{"api_version", "v1"}}}};
                 res.set_content(out.dump(), kJson);
             });

    // ── POST /api/v1/secrets/kek/rewrap ── Security:Write. ────────────────────
    // Idempotent RESUME: re-wraps every row still on a non-active version
    // under the current active version. Safe to call repeatedly (including
    // when nothing is left to do — rows_rewrapped==0 is a normal outcome, not
    // an error). No request parameters.
    sink.Post("/api/v1/secrets/kek/rewrap",
             [perm_fn, audit_fn, ops](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn(req, res, "Security", "Write"))
                     return;
                 if (!ops.rewrap) {
                     res.status = 503;
                     res.set_content(
                         error_json_a4(503, "KEK service unavailable", make_correlation_id(),
                                      /*retry_after_ms=*/5000,
                                      "the Postgres substrate or secrets codec is not available; "
                                      "retry once the server reports it is ready"),
                         kJson);
                     return;
                 }
                 if (!validate_empty_body(req, res))
                     return;
                 const KekOpResult result = ops.rewrap();
                 if (result.failure != KekOpResult::Failure::None) {
                     (void)audit_fn(req, "kek.rewrap", "failure", "Secret", "kek",
                                    failure_tag(result.failure));
                     write_failure(res, result.failure);
                     return;
                 }
                 if (!audit_fn(req, "kek.rewrap", "success", "Secret", "kek",
                               "rows_rewrapped=" + std::to_string(result.rows_rewrapped)))
                     res.set_header("Sec-Audit-Failed", "true");
                 nlohmann::json out = {{"rows_rewrapped", result.rows_rewrapped},
                                       {"meta", {{"api_version", "v1"}}}};
                 res.set_content(out.dump(), kJson);
             });

    // ── GET /api/v1/secrets/kek/status ── Security:Read. ──────────────────────
    // Read-only; not audited (matches the CA read routes — GET /ca/issued
    // etc. don't audit either). `oldest_in_use` is null when no secret rows
    // exist at all (nothing to rewrap, trivially "complete").
    sink.Get("/api/v1/secrets/kek/status",
            [perm_fn, ops](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn(req, res, "Security", "Read"))
                    return;
                if (!ops.status) {
                    res.status = 503;
                    res.set_content(
                        error_json_a4(503, "KEK service unavailable", make_correlation_id(),
                                     /*retry_after_ms=*/5000,
                                     "the Postgres substrate or secrets codec is not available; "
                                     "retry once the server reports it is ready"),
                        kJson);
                    return;
                }
                const KekOpResult result = ops.status();
                if (result.failure != KekOpResult::Failure::None) {
                    write_failure(res, result.failure);
                    return;
                }
                nlohmann::json out = {
                    {"active_version", result.active_version},
                    {"oldest_in_use", result.oldest_in_use.has_value()
                                          ? nlohmann::json(*result.oldest_in_use)
                                          : nlohmann::json(nullptr)},
                    {"rotation_complete", result.rotation_complete},
                    {"meta", {{"api_version", "v1"}}}};
                res.set_content(out.dump(), kJson);
            });
}

} // namespace yuzu::server
