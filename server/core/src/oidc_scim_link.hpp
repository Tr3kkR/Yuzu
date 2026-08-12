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

#include <string>

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
/// ALWAYS records a login observation `(iss, sub, link_claim_name,
/// link_claim_value)` regardless of whether a link formed — the D2
/// detector's data source (`ScimStore::observation_matches`).
///
/// `scim_store` may be null (no PG configured, or the store failed to open
/// at boot) — a safe no-op in that case, same fail-OPEN posture as every
/// other failure this function absorbs. Never fails/throws — the caller's
/// login has already succeeded by the time this runs and must not be
/// undone by a store hiccup here.
void link_oidc_login_to_scim(ScimStore* scim_store, const std::string& iss, const std::string& sub,
                             const std::string& link_claim_name,
                             const std::string& link_claim_value);

} // namespace yuzu::server::oidc
