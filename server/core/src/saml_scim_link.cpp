#include "saml_scim_link.hpp"

#include <yuzu/metrics.hpp>
#include <yuzu/server/scim_store.hpp>

#include <spdlog/spdlog.h>

namespace yuzu::server::saml {

namespace {

// The two NameID Format URIs this codebase treats as STABLE — see the
// header doc. `test_saml_provider.cpp`'s fixture default matches the
// emailAddress one, so the existing (pre-PR4a) test suite's default
// assertions are already linkable without modification.
constexpr const char* kPersistentFormat = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
constexpr const char* kEmail11Format    = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";

void bump_link_write_failure(yuzu::MetricsRegistry* metrics) {
    if (metrics)
        metrics->counter("yuzu_scim_saml_link_write_failures_total").increment();
}

} // namespace

bool is_linkable_name_id_format(const std::string& name_id_format) {
    return name_id_format == kPersistentFormat || name_id_format == kEmail11Format;
}

void link_saml_login_to_scim(ScimStore* scim_store, const std::string& entity_id,
                             const std::string& name_id, const std::string& name_id_format,
                             yuzu::MetricsRegistry* metrics) {
    if (!scim_store)
        return;
    if (!is_linkable_name_id_format(name_id_format))
        return; // transient/unspecified/missing — never a durable join key

    auto match = scim_store->find_unique_active_by_external_id(name_id);
    if (!match)
        return; // zero or ambiguous matches — no link, no error (ADR-2001 §2 posture)

    if (!scim_store->upsert_saml_link(entity_id, name_id, match->scim_id)) {
        spdlog::warn("ADR-2001 PR4a: failed to persist SAML identity link (entity_id={}, "
                    "scim_id={}) — login proceeds",
                    entity_id, match->scim_id);
        bump_link_write_failure(metrics);
    }
}

SamlLoginDenyDecision saml_login_denied_deprovisioned(ScimStore* scim_store,
                                                       const std::string& entity_id,
                                                       const std::string& name_id) {
    // No store configured at all — SCIM/ADR-2001 linkage cannot have formed,
    // so there is nothing to deny against. Deliberately DIFFERENT from a
    // non-null-but-unusable store (below), which fails closed.
    if (!scim_store)
        return {.denied = false, .scim_id = std::nullopt};

    auto result = scim_store->saml_linked_resource_active(entity_id, name_id);
    if (!result)
        return {.denied = true, .scim_id = std::nullopt}; // store could not answer: deny, no id to name

    if (!result->scim_id)
        return {.denied = false, .scim_id = std::nullopt}; // no linked identity: proceed

    if (!result->active) {
        // Orphaned: the linked scim_id's scim_resources row is gone
        // (hard-DELETEd). Distinguish "genuinely deleted" from "DELETE'd
        // then re-CREATE'd under a new scim_id" before denying, or a
        // returning re-provisioned user is permanently locked out (the
        // re-link that would repoint the stale (entity_id,name_id) row
        // runs AFTER this check, at link_saml_login_to_scim). Deliberately
        // NOT applied to the explicit-inactive branch below — same
        // rationale as the OIDC helper (see the .hpp doc comment).
        //
        // SAML has no separate link_claim_value — the join key is always
        // name_id itself (see the .hpp doc comment).
        if (scim_store->find_unique_active_by_external_id(name_id)) {
            // An ACTIVE resource now exists for this externalId — the
            // identity was re-provisioned under a new scim_id. Proceed;
            // the imminent link_saml_login_to_scim call repoints the stale
            // link row to the new id, so the NEXT login resolves clean via
            // the ordinary active-link path.
            return {.denied = false, .scim_id = std::nullopt};
        }
        // No active resource for this externalId — genuinely deprovisioned
        // (not re-provisioned). Deny and name the stale (now-gone) resource.
        return {.denied = true, .scim_id = result->scim_id};
    }

    if (!*result->active) {
        // Explicitly deactivated (active == false, resource still exists) —
        // deny unconditionally. No reprovision check here: reactivation is
        // active:true on the SAME scim_id (the very next read already
        // resolves PROCEED), and the partial-unique index on
        // scim_resources.external_id blocks a second active resource
        // sharing this externalId while the inactive row still holds it.
        return {.denied = true, .scim_id = result->scim_id};
    }

    return {.denied = false, .scim_id = std::nullopt}; // active == true: proceed
}

} // namespace yuzu::server::saml
