#pragma once

/// @file oidc_scim_link.hpp
///
/// ADR-2001 §2/D2 — the login-site orchestration that forms a durable
/// SCIM<->OIDC identity link and records the D2 login-observation signal.
/// Extracted out of the `/auth/callback` handler (`auth_routes.cpp`) into a
/// free function so it is unit-testable directly against a real `ScimStore`
/// without a live IdP (mirrors `oidc_principal_id` in `oidc_principal.hpp` —
/// the same "pull the orchestration out of the handler" pattern Task 1
/// already established for the principal-string builder).
///
/// Deliberately `void` and never throws: this is the fail-OPEN half of
/// ADR-2001 §2 ("a failed write never fails the login"). Every ScimStore
/// call failure is logged and swallowed here so the caller never has to
/// check a return value or catch anything to keep that guarantee — a future
/// call site cannot accidentally wire this into a fail-closed path.
///
/// Governance Gate 7 BLOCKING fix (D2 tripwire, the crux): the headline D2
/// misconfiguration is an operator running `--oidc-scim-link-claim=sub`
/// while the SCIM externalId is actually the Entra `oid` — under the prior
/// "record the configured claim only" behaviour, the login observation held
/// the sub-value, never the oid-value, so a deprovision's
/// `observation_matches(external_id)` (keyed on the oid value) never
/// matched and D2 never fired for the exact case it exists to catch. This
/// function now records an observation for EACH candidate claim (`sub` AND
/// `oid`, when present and sane) regardless of which one is configured for
/// LINK FORMATION — see `oidc_scim_link.cpp`'s `is_sane_claim_value`.

#include <string>

namespace yuzu {
class MetricsRegistry;
}

namespace yuzu::server {
class ScimStore;
}

namespace yuzu::server::oidc {

/// Resolves `link_claim_value` (the validated `sub` or `oid`, per
/// `--oidc-scim-link-claim`) against `scim_store`'s active SCIM resources:
///  - Exactly one active match: upserts an `identity_links` row for
///    `(iss, sub)` -> that resource's `scim_id`.
///  - Zero or more-than-one match: forms NO link — an ambiguous
///    `external_id` is never resolved arbitrarily (ADR-2001 §2 mis-link
///    guard; `ScimStore::find_unique_active_by_external_id` already encodes
///    this, this function just consumes it).
/// LINK FORMATION uses ONLY `link_claim_value` (the configured claim) —
/// unchanged from before.
///
/// ALWAYS records a login observation for EACH of `sub` and `oid` that is
/// non-empty and passes basic claim-value sanitation (`is_sane_claim_value`
/// in the .cpp — mirrors `OidcProvider::validate_claims`'s length/control-
/// byte rule), regardless of whether a link formed and regardless of which
/// one is the configured link claim — the D2 detector's data source
/// (`ScimStore::observation_matches`). `oid` may be unsanitized/malformed
/// here: `OidcProvider::validate_claims` only validates it when it is the
/// CONFIGURED link claim (a missing/malformed `oid` must not fail a login
/// under the default `sub` link-claim configuration), so this function
/// re-applies the same sanitation rule before trusting it into a durable
/// row.
///
/// `metrics` may be null (test/CLI contexts) — bumps
/// `yuzu_scim_oidc_link_write_failures_total` on any `upsert_link`/
/// `record_login_observation` failure (UP-6); a no-op counter otherwise.
///
/// `scim_store` may be null (no PG configured, or the store failed to open
/// at boot) — a safe no-op in that case, same fail-OPEN posture as every
/// other failure this function absorbs. Never fails/throws — the caller's
/// login has already succeeded by the time this runs and must not be
/// undone by a store hiccup here.
void link_oidc_login_to_scim(ScimStore* scim_store, const std::string& iss, const std::string& sub,
                             const std::string& oid, const std::string& link_claim_name,
                             const std::string& link_claim_value,
                             yuzu::MetricsRegistry* metrics = nullptr);

} // namespace yuzu::server::oidc
