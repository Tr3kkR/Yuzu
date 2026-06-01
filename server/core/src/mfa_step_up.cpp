/// @file mfa_step_up.cpp — see header for the gate contract.

#include "mfa_step_up.hpp"

#include "rest_a4_envelope.hpp"

#include <httplib.h>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <chrono>

namespace yuzu::server {

bool require_mfa_step_up(const httplib::Request& req, httplib::Response& res,
                         const auth::Session& session, AuthDB& auth_db, int window_secs,
                         const StepUpAuditFn& audit_fn, const std::string& action_label) {
    // Escape hatch — operator disabled the gate. Treated as fresh.
    if (window_secs <= 0) {
        return true;
    }

    // Bearer-credential principals are step-up-exempt by design. Token
    // issuance was the step-up moment; the token itself does not
    // re-prompt. Mirrors the /auth-and-authz skill's documented scope.
    //
    // OIDC/SSO sessions are also exempt for now. The identity lives in
    // the IdP: `create_oidc_session` never writes a `users` row, so
    // there is no local TOTP secret to step up against and no way for
    // the operator to clear the gate. Without this exemption every OIDC
    // session fails the `mfa_status()` lookup below with `UserNotFound`
    // and is permanently locked out of all gated endpoints (PR #1199
    // review HIGH). Enforcing MFA on SSO sessions via the `amr` claim is
    // the documented PR3 work; until then SSO MFA is the IdP's job. The
    // auth-source check (rather than discriminating on `UserNotFound`
    // below) is deliberate: it keeps a local user deleted mid-request
    // fail-closed, exempting only genuine external identities.
    if (session.auth_source == "api_token" || session.auth_source == "mcp_token" ||
        session.auth_source == "oidc") {
        return true;
    }

    // Look up the user's MFA enrollment status. Distinguish two cases:
    //
    //   (a) store error / user-deleted-mid-request (`!status`) — fail
    //       CLOSED: the gate cannot evaluate, so the request is denied.
    //       Fail-open here would let an attacker exploit auth_db
    //       transients (lock contention, corrupted row, deleted-then-
    //       requested user) to bypass step-up entirely on every gated
    //       site. Governance Gate 4 UP-4 / unhappy-path BLOCKING.
    //
    //   (b) user not enrolled (`!status->enrolled`) — fall through to
    //       the existing role/permission gate. Under
    //       `mfa_enforcement != optional` such a user would have been
    //       rejected at login, so reaching here implies `optional`
    //       mode. Consistent with PR1's enforcement model.
    auto status = auth_db.mfa_status(session.username);
    if (!status) {
        // Fail closed. Emit a distinct audit verb so SRE can grep for
        // store-error events vs legitimate stale-session denials.
        if (audit_fn) {
            try {
                (void)audit_fn(req, "mfa.step_up.required", "error", "Endpoint",
                               action_label,
                               "user=" + session.username +
                                   " reason=mfa_status_unavailable (fail-closed)");
            } catch (const std::exception& ex) {
                spdlog::warn("mfa_step_up: audit emission threw: {}", ex.what());
            } catch (...) {
                spdlog::warn("mfa_step_up: audit emission threw non-std exception");
            }
        }
        spdlog::error("require_mfa_step_up: mfa_status({}) failed — failing closed",
                      session.username);
        nlohmann::json envelope_fail = {
            {"error",
             {{"code", 401},
              {"message", "MFA step-up required"},
              {"correlation_id", detail::make_correlation_id()},
              {"remediation",
               "auth_db unavailable — retry shortly or contact an administrator"}}},
            {"meta",
             {{"api_version", "v1"},
              {"mfa_step_up_required", true},
              {"challenge_url", "/login/mfa/stepup"}}}};
        res.status = 401;
        res.set_content(envelope_fail.dump(), "application/json");
        return false;
    }
    if (!status->enrolled) {
        return true;
    }

    // Compute proof age. A default-constructed `mfa_verified_at`
    // (time_since_epoch() == 0) signals "no MFA proof on this
    // session yet" — treat as infinitely stale.
    const auto now = std::chrono::steady_clock::now();
    const bool no_proof = session.mfa_verified_at.time_since_epoch().count() == 0;
    const auto age = no_proof ? std::chrono::seconds::max()
                              : std::chrono::duration_cast<std::chrono::seconds>(
                                    now - session.mfa_verified_at);
    if (!no_proof && age <= std::chrono::seconds(window_secs)) {
        return true;
    }

    // Step-up required. Build the 401 A4 envelope with the extra
    // `meta.mfa_step_up_required` + `meta.challenge_url` fields the
    // dashboard JS / agentic-worker client uses to drive the
    // re-prompt flow.
    const auto cid = detail::make_correlation_id();
    nlohmann::json envelope = {
        {"error",
         {{"code", 401},
          {"message", "MFA step-up required"},
          {"correlation_id", cid},
          {"remediation",
           "POST /login/mfa/stepup with current TOTP code or a recovery code, then retry"}}},
        {"meta",
         {{"api_version", "v1"},
          {"mfa_step_up_required", true},
          {"challenge_url", "/login/mfa/stepup"}}}};
    res.status = 401;
    res.set_content(envelope.dump(), "application/json");

    // Audit. `age` may be seconds::max() in the no-proof case — clamp
    // to a printable bound (window_secs * 1000) so the audit detail
    // stays grep-friendly.
    long long age_secs = no_proof ? -1 : age.count();
    std::string detail_str = "user=" + session.username +
                             " age_secs=" + std::to_string(age_secs) +
                             " window_secs=" + std::to_string(window_secs);
    if (audit_fn) {
        try {
            (void)audit_fn(req, "mfa.step_up.required", "error", "Endpoint", action_label,
                           detail_str);
        } catch (const std::exception& ex) {
            spdlog::warn("mfa_step_up: audit emission threw: {}", ex.what());
        } catch (...) {
            spdlog::warn("mfa_step_up: audit emission threw non-std exception");
        }
    }
    return false;
}

} // namespace yuzu::server
