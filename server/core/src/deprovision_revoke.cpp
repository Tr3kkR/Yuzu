#include "deprovision_revoke.hpp"

#include "api_token_store.hpp"
#include "oidc_principal.hpp"

#include <yuzu/server/auth.hpp>
#include <yuzu/server/scim_store.hpp>

namespace yuzu::server {

std::optional<std::vector<std::string>>
resolve_deprovision_principals(ScimStore& scim_store, const std::string& scim_id,
                               const std::string& slug_username) {
    auto links = scim_store.links_for_scim_id(scim_id);
    if (!links.has_value())
        return std::nullopt; // fail closed — the store could not answer

    std::vector<std::string> principals;
    principals.reserve(1 + links->size());
    principals.push_back(slug_username);
    for (const auto& linked : *links)
        principals.push_back(oidc::oidc_principal_id(linked.iss, linked.sub));
    return principals;
}

std::optional<std::vector<std::string>>
resolve_deprovision_principals_for_username(ScimStore* scim_store, const std::string& username) {
    if (!scim_store || !scim_store->is_open()) {
        // No SCIM store wired — no scim_resources/identity_links row can
        // exist under this configuration, so there is provably nothing to
        // link. Degrade to the slug-only set rather than failing closed
        // (see the header doc — this differs deliberately from a genuine
        // link-lookup failure on a KNOWN SCIM user, below).
        return std::vector<std::string>{username};
    }
    auto resource = scim_store->get_by_username(username);
    if (!resource) {
        // Not a SCIM-provisioned user (or an ambiguous read that this
        // wrapper — matching get_by_username's existing collapsed contract
        // — treats the same way): no possible identity_links row either
        // way.
        return std::vector<std::string>{username};
    }
    return resolve_deprovision_principals(*scim_store, resource->scim_id, username);
}

DeprovisionRevokeResult
revoke_deprovision_credentials(ApiTokenStore& token_store, auth::AuthManager& auth_mgr,
                               const std::vector<std::string>& principals) {
    DeprovisionRevokeResult result;
    for (const auto& principal : principals) {
        // Credentials FIRST — tokens before sessions, this principal fully
        // handled before the next. Never a lease from token_store held
        // while calling auth_mgr (or vice versa): each call below is
        // self-contained and returns before the next begins.
        auto revoked = token_store.revoke_for_principal(principal);
        if (!revoked.has_value()) {
            result.api_tokens_persisted = false;
        } else {
            result.api_tokens_revoked += *revoked;
        }
        auto sessions = auth_mgr.invalidate_user_sessions(principal);
        result.sessions_revoked += sessions.count;
        // Sessions are in-memory-only (AuthManager::invalidate_user_sessions
        // ' RevokeResult::db_persisted is always true today — no durable
        // session surface exists to fail to persist to) — nothing to fold
        // into api_tokens_persisted here.
    }
    return result;
}

} // namespace yuzu::server
