#pragma once

/// @file route_types.hpp
/// Shared callback type aliases for HTTP route modules.
/// Every route module (RestApiV1, McpServer, SettingsRoutes, etc.) uses these
/// callback types to receive auth, permission, and audit functionality from
/// the ServerImpl composition root.

#include <yuzu/server/auth.hpp>

#include <httplib.h>

#include <functional>
#include <optional>
#include <string>

namespace yuzu::server {

/// Auth callback: validates session cookie or Bearer token.
/// Returns the Session on success, or sets a 401 response and returns nullopt.
using AuthFn =
    std::function<std::optional<auth::Session>(const httplib::Request&, httplib::Response&)>;

/// Permission callback: checks RBAC permission for (securable_type, operation).
/// Returns true if allowed, or sets a 403 response and returns false.
using PermFn =
    std::function<bool(const httplib::Request&, httplib::Response&,
                       const std::string& securable_type, const std::string& operation)>;

/// Scoped permission callback: checks RBAC permission within a scope expression.
using ScopedPermFn =
    std::function<bool(const httplib::Request&, httplib::Response&,
                       const std::string& securable_type, const std::string& operation,
                       const std::string& scope_expr)>;

/// Audit callback: logs an audit trail entry for the request.
using AuditFn = std::function<void(const httplib::Request&, const std::string& action,
                                   const std::string& result, const std::string& target_type,
                                   const std::string& target_id, const std::string& detail)>;

} // namespace yuzu::server
