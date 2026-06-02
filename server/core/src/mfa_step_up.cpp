/// @file mfa_step_up.cpp — see header for the gate contract.

#include "mfa_step_up.hpp"

#include "rest_a4_envelope.hpp"

#include <httplib.h>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <chrono>
#include <string_view>

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
    if (session.auth_source == "api_token" || session.auth_source == "mcp_token") {
        return true;
    }

    // OIDC/SSO sessions (PR3) carry no local `users` row, so the
    // enrollment lookup below would return `UserNotFound` and — were we
    // to run it — fail closed and lock every SSO operator out of the
    // gated endpoints (the PR #1199 HIGH the old blanket exemption
    // guarded). Instead we skip the local lookup entirely and gate the
    // OIDC session purely on `session.mfa_verified_at`, which
    // /auth/callback seeds from the IdP `amr` claim. A local TOTP step-up
    // is meaningless for an external identity, so the remediation steers
    // the operator back through SSO (see the source-specific challenge
    // URL on the failure path below).
    const bool is_oidc = session.auth_source == "oidc";

    if (!is_oidc) {
        // Look up the local user's MFA enrollment status. Distinguish:
        //
        //   (a) store error / user-deleted-mid-request (`!status`) — fail
        //       CLOSED: the gate cannot evaluate, so the request is
        //       denied. Fail-open here would let an attacker exploit
        //       auth_db transients (lock contention, corrupted row,
        //       deleted-then-requested user) to bypass step-up on every
        //       gated site. Governance Gate 4 UP-4 / unhappy-path
        //       BLOCKING.
        //
        //   (b) user not enrolled (`!status->enrolled`) — fall through to
        //       the existing role/permission gate. Under
        //       `mfa_enforcement != optional` such a user is required to
        //       enrol at login (PR3), so a not-enrolled local session
        //       reaching here implies `optional` mode.
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
    }

    // Compute proof age. A default-constructed `mfa_verified_at`
    // (time_since_epoch() == 0) signals "no MFA proof on this
    // session yet" — treat as infinitely stale.
    const auto now = std::chrono::steady_clock::now();
    const bool no_proof = session.mfa_verified_at.time_since_epoch().count() == 0;

    // OIDC sessions whose IdP did not attest MFA carry no seeded proof
    // (no `amr` → `/auth/callback` never set `mfa_verified_at`). They have
    // no second factor to step up against, exactly like an un-enrolled
    // local user — so they PASS, not fail. Gating them here would 401 →
    // `/auth/oidc/start` → silent re-SSO → same `amr`-less token → 401 …
    // an infinite lockout loop, re-opening the PR #1199 HIGH for every
    // non-MFA IdP (governance UP-5/UP-6). MFA on a non-MFA-IdP SSO session
    // is the IdP's responsibility; Yuzu cannot mint a factor for an
    // external identity. An OIDC session that DOES carry an `amr`-seeded
    // proof falls through to the freshness check below (stale → re-SSO),
    // so this is never weaker than the PR2 blanket exemption it replaces.
    // A future opt-in (`--mfa-oidc-amr-required`) can harden this for
    // operators who have confirmed their IdP asserts `amr`.
    if (is_oidc && no_proof) {
        return true;
    }

    const auto age = no_proof ? std::chrono::seconds::max()
                              : std::chrono::duration_cast<std::chrono::seconds>(
                                    now - session.mfa_verified_at);
    if (!no_proof && age <= std::chrono::seconds(window_secs)) {
        return true;
    }

    // Step-up required. Build the 401 A4 envelope with the extra
    // `meta.mfa_step_up_required` + `meta.challenge_url` fields the
    // dashboard JS / agentic-worker client uses to drive the
    // re-prompt flow. The challenge differs by identity source: a local
    // session re-proves via the TOTP step-up endpoint; an OIDC session
    // has no local secret, so it must re-authenticate through SSO to
    // refresh the IdP MFA assertion.
    const char* challenge_url = is_oidc ? "/auth/oidc/start" : "/login/mfa/stepup";
    const char* remediation =
        is_oidc ? "Re-authenticate via SSO to refresh the identity provider's MFA assertion, "
                  "then retry"
                : "POST /login/mfa/stepup with current TOTP code or a recovery code, then retry";
    const auto cid = detail::make_correlation_id();
    nlohmann::json envelope = {
        {"error",
         {{"code", 401},
          {"message", "MFA step-up required"},
          {"correlation_id", cid},
          {"remediation", remediation}}},
        {"meta",
         {{"api_version", "v1"},
          {"mfa_step_up_required", true},
          {"challenge_url", challenge_url}}}};
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

bool amr_asserts_mfa(const std::vector<std::string>& amr) {
    // RFC 8176 method references that constitute (or imply) a factor
    // beyond a shared secret, plus Entra's non-standard "mfa" aggregate.
    // Matches the allowlist documented in docs/auth-mfa-design.md "OIDC
    // interop". Deliberately EXCLUDED:
    //   - "pwd": the single factor step-up exists to strengthen.
    //   - "pin"/"user": single-factor presence/knowledge (device-unlock PIN,
    //     "user presence") — not a second factor. Admitting them let a
    //     non-MFA login satisfy the gate (governance UP-7). "sms"/"tel" are
    //     weak but ARE a possession-based second factor, so they stay; a
    //     future --mfa-oidc-amr-strong flag can tighten further.
    static constexpr std::string_view kMfaMethods[] = {"mfa",  "otp", "hwk", "face",
                                                       "fpt",  "iris", "sms", "swk",
                                                       "tel"};
    for (const auto& m : amr) {
        for (const auto& known : kMfaMethods) {
            if (m == known) {
                return true;
            }
        }
    }
    return false;
}

bool mfa_enforcement_protects(std::string_view mode, auth::Role role) {
    if (mode == "required") {
        return true;
    }
    if (mode == "admin-only") {
        return role == auth::Role::admin;
    }
    // "optional", or any value CLI validation should have rejected → not
    // enforced. Fail-safe: an unexpected mode never silently locks anyone
    // out, and CLI11 IsMember already rejects unknown values at startup.
    return false;
}

} // namespace yuzu::server
