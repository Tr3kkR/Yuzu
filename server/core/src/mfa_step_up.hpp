#pragma once

/// @file mfa_step_up.hpp
///
/// Step-up gate for high-risk REST + Settings handlers (PR2 of the MFA
/// ladder; SOC 2 CC6.6 — privileged access requires fresh proof of
/// presence). PR1 established `Session::mfa_verified_at` as the
/// timestamp of the most recent successful MFA proof on a session;
/// this helper compares it against `cfg.mfa_step_up_window_secs` and
/// blocks the caller if the proof is stale.
///
/// Contract: returns true if the caller may proceed; false means the
/// helper has already written a 401 + A4 envelope to `res` and the
/// caller MUST return immediately without further response mutation
/// or audit emission.
///
/// Skips entirely (returns true) for:
///   - API token / MCP token principals — the bearer credential IS
///     the step-up moment (per `/auth-and-authz` skill, "MFA on every
///     API-token call" is explicitly out of scope; token issuance
///     happened with full MFA).
///   - Sessions belonging to users without MFA enrolled — consistent
///     with PR1's enforcement model (`optional` mode only kicks in
///     once a user opts into MFA).
///   - `window_secs == 0` — operator-disabled the gate (escape hatch
///     for diagnostic / break-glass scenarios; emits a startup WARN
///     in main.cpp).
///
/// Requires step-up (returns false) when:
///   - principal is a session ("local" or "oidc" auth_source) AND
///   - user is MFA-enrolled AND
///   - `now - session.mfa_verified_at > window_secs`
///
/// Side effects on failure:
///   - `res.status = 401`
///   - `res.body` = A4 envelope: `{"error":{"code":401,"message":
///     "MFA step-up required","correlation_id":"req-...",
///     "remediation":"POST /login/mfa/stepup with current TOTP code or
///     a recovery code, then retry"},"meta":{"api_version":"v1",
///     "mfa_step_up_required":true,"challenge_url":"/login/mfa/stepup"}}`
///   - emits audit row: `mfa.step_up.required`, result=`error`,
///     target_type=`Endpoint`, target_id=`<action_label>`, detail=
///     username + age of last MFA proof in seconds.

#include "rest_a4_envelope.hpp"
#include <yuzu/server/auth.hpp>
#include <yuzu/server/auth_db.hpp>

#include <functional>
#include <string>

namespace httplib {
struct Request;
struct Response;
} // namespace httplib

namespace yuzu::server {

/// Audit callback typedef — matches `RestApiV1::AuditFn` shape so
/// step-up audit emission is wire-identical to neighbouring handlers.
/// Return value is currently discarded (`mfa.step_up.required` is a
/// trace event; the access denial is the primary signal), but the
/// typedef keeps the signature uniform across the codebase.
using StepUpAuditFn = std::function<bool(const httplib::Request&,
                                         const std::string& action,
                                         const std::string& result,
                                         const std::string& target_type,
                                         const std::string& target_id,
                                         const std::string& detail)>;

bool require_mfa_step_up(const httplib::Request& req, httplib::Response& res,
                         const auth::Session& session, AuthDB& auth_db,
                         int window_secs, const StepUpAuditFn& audit_fn,
                         const std::string& action_label);

/// Per-surface adapter — wires AuthDB + window_secs + audit_fn into a
/// 3-argument callable that downstream `register_routes` overloads can
/// take alongside auth_fn/perm_fn/audit_fn. Lives in this header so
/// rest_api_v1, settings_routes, and tests construct identical
/// closures.
using StepUpFn = std::function<bool(const httplib::Request&,
                                    httplib::Response&,
                                    const auth::Session&,
                                    const std::string& action_label)>;

} // namespace yuzu::server
