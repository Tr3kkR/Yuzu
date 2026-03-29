#pragma once

/// @file dashboard_routes.hpp
/// HTMX fragment routes for the dashboard: filterable/sortable results,
/// group creation from filtered results, scope panel with groups,
/// and HTMX-native instruction dispatch.

#include <functional>
#include <optional>
#include <string>
#include <vector>

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <yuzu/server/auth.hpp>

namespace yuzu::server {

// Forward declarations
class ResponseStore;
class ManagementGroupStore;
class TagStore;
struct FacetFilter;

namespace detail {
class AgentRegistry;
class EventBus;
} // namespace detail

class DashboardRoutes {
public:
    using AuthFn = std::function<std::optional<auth::Session>(
        const httplib::Request&, httplib::Response&)>;
    using PermFn = std::function<bool(const httplib::Request&, httplib::Response&,
                                      const std::string&, const std::string&)>;
    using AuditFn = std::function<void(const httplib::Request&, const std::string&,
                                       const std::string&, const std::string&,
                                       const std::string&, const std::string&)>;

    /// Agents JSON callback — returns JSON array of visible agent objects.
    using AgentsJsonFn = std::function<std::string()>;

    /// Send command callback — dispatches a command and returns (command_id, agents_reached).
    using DispatchFn = std::function<std::pair<std::string, int>(
        const std::string& plugin, const std::string& action,
        const std::vector<std::string>& agent_ids, const std::string& scope_expr)>;

    /// Resolve instruction text → (plugin, action). Empty strings on failure.
    using ResolveFn = std::function<std::pair<std::string, std::string>(
        const std::string& instruction_text)>;

    void register_routes(httplib::Server& svr,
                         AuthFn auth_fn,
                         PermFn perm_fn,
                         AuditFn audit_fn,
                         ResponseStore* response_store,
                         ManagementGroupStore* mgmt_group_store,
                         detail::AgentRegistry* registry,
                         TagStore* tag_store,
                         detail::EventBus* event_bus,
                         AgentsJsonFn agents_json_fn,
                         DispatchFn dispatch_fn,
                         ResolveFn resolve_fn);

private:
    AuthFn auth_fn_;
    PermFn perm_fn_;
    AuditFn audit_fn_;
    ResponseStore* response_store_{nullptr};
    ManagementGroupStore* mgmt_group_store_{nullptr};
    detail::AgentRegistry* registry_{nullptr};
    TagStore* tag_store_{nullptr};
    detail::EventBus* event_bus_{nullptr};
    AgentsJsonFn agents_json_fn_;
    DispatchFn dispatch_fn_;
    ResolveFn resolve_fn_;

    // -- Fragment renderers ---------------------------------------------------

    /// Render filtered/sorted/paginated result rows + OOB thead, pagination, summary.
    std::string render_results(const std::string& command_id, const std::string& plugin,
                               const std::string& sort_col, const std::string& sort_dir,
                               int page, int per_page,
                               const std::vector<FacetFilter>& filters,
                               const std::string& text_query);

    /// Render filter controls for a plugin schema.
    std::string render_filter_bar(const std::string& command_id, const std::string& plugin);

    /// Render group creation form.
    std::string render_create_group_form(const std::string& command_id,
                                          const std::string& plugin,
                                          const std::vector<FacetFilter>& filters,
                                          int64_t agent_count);

    /// Render scope list with groups section.
    std::string render_scope_list(const std::string& selected, const std::string& username);

    /// Parse f_* filter params from request into FacetFilter vector.
    std::vector<FacetFilter> parse_filters(const httplib::Request& req,
                                            const std::string& plugin) const;
};

} // namespace yuzu::server
