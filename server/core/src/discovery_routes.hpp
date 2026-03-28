#pragma once

#include <yuzu/server/auth.hpp>

#include "deployment_store.hpp"
#include "directory_sync.hpp"
#include "discovery_store.hpp"
#include "patch_manager.hpp"

#include <httplib.h>

#include <functional>
#include <optional>
#include <string>

namespace yuzu::server {

/// Directory sync, patch management, deployment, and discovery REST endpoints.
/// Replaces the former directory_patch_routes.inc and deployment_discovery_routes.inc
/// files that were textually #included into start_web_server().
class DiscoveryRoutes {
public:
    using AuthFn =
        std::function<std::optional<auth::Session>(const httplib::Request&, httplib::Response&)>;
    using PermFn =
        std::function<bool(const httplib::Request&, httplib::Response&,
                           const std::string& securable_type, const std::string& operation)>;
    using AuditFn = std::function<void(const httplib::Request&, const std::string& action,
                                       const std::string& result, const std::string& target_type,
                                       const std::string& target_id, const std::string& detail)>;

    void register_routes(httplib::Server& svr, AuthFn auth_fn, PermFn perm_fn, AuditFn audit_fn,
                         DirectorySync* directory_sync, PatchManager* patch_manager,
                         DeploymentStore* deployment_store, DiscoveryStore* discovery_store);
};

} // namespace yuzu::server
