#pragma once

/// @file settings_routes.hpp
/// Extracted from server.cpp — Settings page HTMX routes, fragment renderers,
/// and YAML helpers.  Phase 1 of the god-object decomposition.

#include <yuzu/server/auth.hpp>
#include <yuzu/server/auto_approve.hpp>

#include "api_token_store.hpp"
#include "audit_store.hpp"
#include "management_group_store.hpp"
#include "oidc_provider.hpp"
#include "runtime_config_store.hpp"
#include "tag_store.hpp"
#include "update_registry.hpp"

#include <httplib.h>

#include <cstddef>
#include <functional>
#include <memory>
#include <optional>
#include <shared_mutex>
#include <string>

namespace yuzu::server {

struct Config;

/// Settings page routes — all /settings, /fragments/settings/*, /api/settings/* routes.
class SettingsRoutes {
public:
    using AuthFn =
        std::function<std::optional<auth::Session>(const httplib::Request&, httplib::Response&)>;
    using AdminFn =
        std::function<bool(const httplib::Request&, httplib::Response&)>;
    using PermFn =
        std::function<bool(const httplib::Request&, httplib::Response&,
                           const std::string& securable_type, const std::string& operation)>;
    using AuditFn = std::function<void(const httplib::Request&, const std::string& action,
                                       const std::string& result, const std::string& target_type,
                                       const std::string& target_id, const std::string& detail)>;

    /// Callback to get agents JSON from AgentRegistry (avoids incomplete-type dep).
    using AgentsJsonFn = std::function<std::string()>;

    /// Callback to get gateway session count (avoids incomplete-type dep).
    using GatewaySessionCountFn = std::function<std::size_t()>;

    /// Register all settings-related routes on the given server.
    void register_routes(httplib::Server& svr,
                         AuthFn auth_fn,
                         AdminFn admin_fn,
                         PermFn perm_fn,
                         AuditFn audit_fn,
                         Config& cfg,
                         auth::AuthManager& auth_mgr,
                         auth::AutoApproveEngine& auto_approve,
                         ApiTokenStore* api_token_store,
                         ManagementGroupStore* mgmt_group_store,
                         TagStore* tag_store,
                         UpdateRegistry* update_registry,
                         RuntimeConfigStore* runtime_config_store,
                         AuditStore* audit_store,
                         bool gateway_enabled,
                         GatewaySessionCountFn gateway_session_count_fn,
                         AgentsJsonFn agents_json_fn,
                         std::shared_mutex& oidc_mu,
                         std::unique_ptr<oidc::OidcProvider>& oidc_provider);

private:
    // -- Fragment renderers (called by route handlers) -------------------------

    std::string render_server_config_fragment();
    std::string render_tls_fragment();
    /// Render the Users settings fragment.
    ///
    /// @param current_username  Username of the currently authenticated
    ///                          operator. The row matching this name is
    ///                          rendered without a "Remove" button to
    ///                          prevent self-deletion lockout (#397/#403).
    ///                          No default is provided — every caller must
    ///                          pass an explicit value (typically
    ///                          `session->username`) so a future call site
    ///                          omitting the argument is a compile error,
    ///                          not a silent UI regression that re-renders
    ///                          the pre-fix Remove button on the self row.
    std::string render_users_fragment(const std::string& current_username);
    std::string render_tokens_fragment(const std::string& new_raw_token = {});
    /// Render the API tokens settings fragment.
    ///
    /// @param new_raw_token   Raw token value just minted (displayed once), or empty.
    /// @param filter_principal When non-empty, list only tokens owned by this
    ///                         principal. Empty = show every token (admin view).
    ///                         Callers must pass session->username for non-admin
    ///                         sessions to prevent cross-user token enumeration
    ///                         (governance Gate 4 finding C1).
    std::string render_api_tokens_fragment(const std::string& new_raw_token = {},
                                           const std::string& filter_principal = {});
    std::string render_pending_fragment();
    std::string render_auto_approve_fragment();
    std::string render_tag_compliance_fragment();
    std::string render_management_groups_fragment();
    std::string render_updates_fragment();
    std::string render_gateway_fragment();
    std::string render_https_fragment();
    std::string render_analytics_fragment();
    std::string render_data_retention_fragment();
    std::string render_mcp_fragment();
    std::string render_nvd_fragment();
    std::string render_directory_fragment();

    // -- Dependency pointers (stored by register_routes) -----------------------

    AuthFn auth_fn_;
    AdminFn admin_fn_;
    PermFn perm_fn_;
    AuditFn audit_fn_;
    Config* cfg_{};
    auth::AuthManager* auth_mgr_{};
    auth::AutoApproveEngine* auto_approve_{};
    ApiTokenStore* api_token_store_{};
    ManagementGroupStore* mgmt_group_store_{};
    TagStore* tag_store_{};
    UpdateRegistry* update_registry_{};
    RuntimeConfigStore* runtime_config_store_{};
    AuditStore* audit_store_{};
    bool gateway_enabled_{};
    GatewaySessionCountFn gateway_session_count_fn_;
    AgentsJsonFn agents_json_fn_;
    std::shared_mutex* oidc_mu_{};
    std::unique_ptr<oidc::OidcProvider>* oidc_provider_{};
};

} // namespace yuzu::server
