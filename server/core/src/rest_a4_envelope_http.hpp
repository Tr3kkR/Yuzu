#pragma once

/// @file rest_a4_envelope_http.hpp
///
/// The httplib-coupled half of the unified A4 error/denial envelope. The pure
/// JSON-string builders live in `rest_a4_envelope.hpp` (no httplib include, so
/// they are testable in isolation via TestRouteSink). This header adds the thin
/// `httplib::Response&`-taking wrapper that (1) mints or reuses the request's
/// `X-Correlation-Id` header so the header and the body's `correlation_id`
/// always agree, then (2) returns the A4 body string. Kept out of the pure
/// header so nothing that only needs the shape contract pulls in httplib.
///
/// Both auth_routes.cpp (the RBAC/admin denial gates) and rest_api_v1.cpp (the
/// #1470 error_json → error_json_a4 migration) include this — one wrapper, one
/// wire shape. This is the fold-home for the old `a4_denial` that used to live
/// in auth_routes.cpp's anonymous namespace.

#include "rest_a4_envelope.hpp"

#include <httplib.h>

#include <string>
#include <string_view>

namespace yuzu::server::detail {

/// Ensure `res` carries an `X-Correlation-Id` header, minting one if absent,
/// and return the value. Idempotent: a cid an upstream gate already set is
/// reused (header and any body cid stay consistent across the response).
inline std::string ensure_correlation_id(httplib::Response& res) {
    std::string cid = res.get_header_value("X-Correlation-Id");
    if (cid.empty()) {
        cid = make_correlation_id();
        res.set_header("X-Correlation-Id", cid);
    }
    return cid;
}

/// Unified A4 denial/error body with an explicit HTTP `code`. Mints/reuses the
/// X-Correlation-Id header, then builds the envelope carrying that cid plus any
/// `opts` (retry_after_ms / remediation / permission / approval_id+status_url).
/// Use this where the status is semantically fixed (e.g. a 403 permission gate).
/// Does NOT set `res.status` — the caller owns the status line.
inline std::string a4_denial(httplib::Response& res, int code, std::string_view message,
                             const A4ErrorOpts& opts = {}) {
    return error_json_a4(code, message, ensure_correlation_id(res), opts);
}

/// Unified A4 error body that derives the envelope `code` from `res.status`.
/// The #1470 migration path: at every legacy `error_json(...)` site the handler
/// has already set `res.status`, so this makes the body `code` equal the HTTP
/// status by construction (no hand-copied code to drift). Mints/reuses the
/// X-Correlation-Id header. Overloadable with `opts` for the rare retryable case.
inline std::string a4_error(httplib::Response& res, std::string_view message,
                            const A4ErrorOpts& opts = {}) {
    return error_json_a4(res.status, message, ensure_correlation_id(res), opts);
}

} // namespace yuzu::server::detail
