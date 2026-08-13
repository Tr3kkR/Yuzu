#pragma once

/// @file saml_scim_link.hpp
///
/// ADR-2001 PR4a — the SAML analogue of `oidc_scim_link.hpp`: the login-site
/// orchestration that forms a durable SCIM<->SAML identity link. Extracted
/// out of the `/saml/acs` handler (`auth_routes.cpp`) into a free function so
/// it is unit-testable directly against a real `ScimStore` without a live IdP
/// (mirrors `oidc_scim_link.hpp`'s own rationale — see
/// test_oidc_routes.cpp's docstring for why the full `/saml/acs` success path
/// itself is instead covered end-to-end in test_saml_routes.cpp, which DOES
/// have a signing harness, unlike the OIDC side).
///
/// Deliberately `void` and never throws: this is the fail-OPEN half of
/// ADR-2001's login-time linking contract — a link-write/lookup failure
/// never fails the login. Every `ScimStore` call failure is logged and
/// swallowed here, mirroring `link_oidc_login_to_scim` exactly. Unlike the
/// OIDC side, there is no login-observation/D2 analogue here: OIDC's D2
/// detector exists specifically to catch a MISCONFIGURED
/// `--oidc-scim-link-claim` (the operator chose the wrong claim among
/// several candidates); SAML has exactly one candidate join key (the
/// NameID) and no equivalent claim-selection knob, so there is no
/// "should-have-matched-a-different-candidate" case to detect.
///
/// NameID Format gate (architect BLOCK fix, ADR-2001 PR4a plan review): a
/// SAML NameID is only a safe join key when it is STABLE across logins and
/// equals the SCIM `externalId`. Transient/unspecified NameID Formats
/// silently fail or mislink if trusted the same way. This function forms a
/// link ONLY when the NameID Format is one of the STABLE formats
/// (`urn:oasis:names:tc:SAML:2.0:nameid-format:persistent` or the SAML 1.1
/// `emailAddress` format) — a missing/empty Format is treated
/// CONSERVATIVELY as NOT linkable, never coerced/normalized into one that
/// is. A non-linkable-format NameID still mints a session (the login
/// succeeds); the identity is simply unlinkable/unrevocable-via-SCIM for
/// that login — the documented residual (see docs/adr/2001-scim-oidc-
/// identity-linkage.md).

#include <string>

namespace yuzu {
class MetricsRegistry;
}

namespace yuzu::server {
class ScimStore;
}

namespace yuzu::server::saml {

/// True iff `name_id_format` is one of the SAML 2.0 NameID Format URIs this
/// codebase treats as STABLE (i.e. safe to use as a durable SCIM
/// `externalId` join key):
///  - `urn:oasis:names:tc:SAML:2.0:nameid-format:persistent`
///  - `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress`
/// An empty (missing/unspecified) Format — and any other value, including
/// `transient` — is conservatively treated as NOT linkable.
[[nodiscard]] bool is_linkable_name_id_format(const std::string& name_id_format);

/// Resolves `name_id` (the caller MUST have already sanitised it — see
/// `saml_principal.hpp`'s `is_valid_saml_component`, applied at the ACS
/// handler before either this call or session mint) against `scim_store`'s
/// active SCIM resources, but ONLY when `name_id_format` is linkable
/// (`is_linkable_name_id_format`):
///  - Exactly one active match: upserts a `saml_identity_links` row for
///    `(entity_id, name_id)` -> that resource's `scim_id`.
///  - Zero or more-than-one match, OR a non-linkable Format: forms NO link
///    — an ambiguous `externalId` (or an unstable NameID) is never resolved
///    arbitrarily (ADR-2001 §2 mis-link guard, mirrored from the OIDC side;
///    `ScimStore::find_unique_active_by_external_id` already encodes the
///    ambiguity rule, this function just consumes it).
///
/// `metrics` may be null (test/CLI contexts) — bumps
/// `yuzu_scim_saml_link_write_failures_total` on an `upsert_saml_link`
/// failure; a no-op counter otherwise.
///
/// `scim_store` may be null (no PG configured, or the store failed to open
/// at boot) — a safe no-op in that case, same fail-OPEN posture as every
/// other failure this function absorbs. Never fails/throws — the caller's
/// login has already succeeded (or is about to) by the time this runs and
/// must not be undone by a store hiccup here.
void link_saml_login_to_scim(ScimStore* scim_store, const std::string& entity_id,
                             const std::string& name_id, const std::string& name_id_format,
                             yuzu::MetricsRegistry* metrics = nullptr);

} // namespace yuzu::server::saml
