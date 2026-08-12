#include "oidc_scim_link.hpp"

#include <yuzu/server/scim_store.hpp>

#include <spdlog/spdlog.h>

namespace yuzu::server::oidc {

void link_oidc_login_to_scim(ScimStore* scim_store, const std::string& iss, const std::string& sub,
                             const std::string& link_claim_name,
                             const std::string& link_claim_value) {
    if (!scim_store)
        return;

    if (!link_claim_value.empty()) {
        if (auto match = scim_store->find_unique_active_by_external_id(link_claim_value)) {
            // Exactly one active match — `find_unique_active_by_external_id`
            // already folded zero AND more-than-one matches into nullopt, so
            // reaching here means the link is unambiguous.
            if (!scim_store->upsert_link(iss, sub, match->scim_id)) {
                spdlog::warn("ADR-2001: failed to persist identity link (iss={}, scim_id={}) — "
                            "login proceeds; D2 detector will surface this via the login "
                            "observation",
                            iss, match->scim_id);
            }
        }
    }

    if (!scim_store->record_login_observation(iss, sub, link_claim_name, link_claim_value)) {
        spdlog::warn("ADR-2001: failed to record OIDC login observation (iss={})", iss);
    }
}

} // namespace yuzu::server::oidc
