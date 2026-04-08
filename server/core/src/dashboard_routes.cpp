#include "dashboard_routes.hpp"

#include <algorithm>
#include <cmath>
#include <sstream>

#include <spdlog/spdlog.h>

#include "agent_registry.hpp" // provides detail::AgentRegistry
#include "event_bus.hpp"
#include "management_group_store.hpp"
#include "response_store.hpp"
#include "result_parsing.hpp"
#include "tag_store.hpp"
#include "web_utils.hpp"

namespace yuzu::server {

// -- Helper: clamp an integer to [lo, hi] -------------------------------------
static int clamp(int val, int lo, int hi) {
    return std::max(lo, std::min(val, hi));
}

// -- Helper: safe int from query param ----------------------------------------
static int param_int(const httplib::Request& req, const char* name, int def) {
    if (!req.has_param(name)) return def;
    try { return std::stoi(req.get_param_value(name)); }
    catch (...) { return def; }
}

// -- Helper: column index by name (case-insensitive, excl. Agent col) ---------
static int col_index_for_name(const std::string& plugin, const std::string& name) {
    auto& cols = columns_for_plugin(plugin);
    // cols[0] is "Agent" — field indices are 0-based starting after Agent
    for (size_t i = 1; i < cols.size(); ++i) {
        auto& c = cols[i];
        if (c.size() == name.size() &&
            std::equal(c.begin(), c.end(), name.begin(),
                       [](char a, char b) { return std::tolower(a) == std::tolower(b); })) {
            return static_cast<int>(i - 1); // field index (0-based, excl. Agent)
        }
    }
    return -1;
}

/// Parse CLI-style "plugin action key=val key2=\"quoted val\"" into command + params.
static std::pair<std::string, std::unordered_map<std::string, std::string>>
parse_instruction_params(const std::string& text) {
    std::unordered_map<std::string, std::string> params;
    std::string command;

    size_t pos = 0;
    size_t len = text.size();

    while (pos < len) {
        // Skip whitespace
        while (pos < len && text[pos] == ' ') ++pos;
        if (pos >= len) break;

        // Look ahead to find '=' in this token
        size_t scan = pos;
        while (scan < len && text[scan] != ' ' && text[scan] != '=') ++scan;

        if (scan < len && text[scan] == '=' && scan > pos) {
            // key=value pair — key is lowercase, value preserves case
            std::string key = text.substr(pos, scan - pos);
            for (auto& c : key) c = static_cast<char>(std::tolower(c));
            ++scan; // skip '='

            std::string val;
            if (scan < len && text[scan] == '"') {
                // Quoted value: read until closing quote
                ++scan;
                size_t close = text.find('"', scan);
                if (close == std::string::npos) close = len;
                val = text.substr(scan, close - scan);
                pos = (close < len) ? close + 1 : len;
            } else {
                // Unquoted value: read until space
                size_t vstart = scan;
                while (scan < len && text[scan] != ' ') ++scan;
                val = text.substr(vstart, scan - vstart);
                pos = scan;
            }
            params[key] = val;
        } else {
            // Regular word — part of the command
            size_t end = pos;
            while (end < len && text[end] != ' ') ++end;
            if (!command.empty()) command += ' ';
            command += text.substr(pos, end - pos);
            pos = end;
        }
    }
    return {command, params};
}

// ---------------------------------------------------------------------------
// register_routes
// ---------------------------------------------------------------------------

void DashboardRoutes::register_routes(httplib::Server& svr,
                                       AuthFn auth_fn, PermFn perm_fn, AuditFn audit_fn,
                                       ResponseStore* response_store,
                                       ManagementGroupStore* mgmt_group_store,
                                       detail::AgentRegistry* registry, TagStore* tag_store,
                                       detail::EventBus* event_bus,
                                       AgentsJsonFn agents_json_fn,
                                       DispatchFn dispatch_fn,
                                       ResolveFn resolve_fn) {
    auth_fn_ = std::move(auth_fn);
    perm_fn_ = std::move(perm_fn);
    audit_fn_ = std::move(audit_fn);
    response_store_ = response_store;
    mgmt_group_store_ = mgmt_group_store;
    registry_ = registry;
    tag_store_ = tag_store;
    event_bus_ = event_bus;
    agents_json_fn_ = std::move(agents_json_fn);
    dispatch_fn_ = std::move(dispatch_fn);
    resolve_fn_ = std::move(resolve_fn);

    // -- GET /fragments/results -----------------------------------------------
    svr.Get("/fragments/results",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn_(req, res, "Response", "Read")) return;

                auto command_id = req.get_param_value("command_id");
                auto plugin = req.get_param_value("plugin");
                if (command_id.empty() || plugin.empty()) {
                    res.status = 400;
                    res.set_content(
                        "<tbody id=\"results-tbody\"><tr><td class=\"empty-state\">"
                        "Missing command_id or plugin.</td></tr></tbody>",
                        "text/html; charset=utf-8");
                    return;
                }

                auto sort_col = req.get_param_value("sort");
                auto sort_dir = req.get_param_value("dir");
                if (sort_col.empty()) sort_col = "agent";
                if (sort_dir.empty()) sort_dir = "asc";

                int page = clamp(param_int(req, "page", 1), 1, 100000);
                int per_page = clamp(param_int(req, "per_page", 50), 10, 200);

                auto filters = parse_filters(req, plugin);
                auto text_query = req.get_param_value("q");

                auto html = render_results(command_id, plugin, sort_col, sort_dir,
                                           page, per_page, filters, text_query);
                res.set_content(html, "text/html; charset=utf-8");
            });

    // -- GET /fragments/results/filter-bar ------------------------------------
    svr.Get("/fragments/results/filter-bar",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn_(req, res, "Response", "Read")) return;

                auto command_id = req.get_param_value("command_id");
                auto plugin = req.get_param_value("plugin");
                if (command_id.empty() || plugin.empty()) {
                    res.status = 400;
                    res.set_content("<div id=\"filter-bar\"></div>",
                                    "text/html; charset=utf-8");
                    return;
                }

                auto html = render_filter_bar(command_id, plugin);
                res.set_content(html, "text/html; charset=utf-8");
            });

    // -- GET /fragments/create-group-form -------------------------------------
    svr.Get("/fragments/create-group-form",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn_(req, res, "ManagementGroup", "Write")) return;

                auto command_id = req.get_param_value("command_id");
                auto plugin = req.get_param_value("plugin");
                auto filters = parse_filters(req, plugin);

                int64_t agent_count = 0;
                if (response_store_ && !filters.empty())
                    agent_count = response_store_->facet_agent_count(command_id, filters);

                auto html = render_create_group_form(command_id, plugin, filters,
                                                      agent_count);
                res.set_content(html, "text/html; charset=utf-8");
            });

    // -- POST /api/dashboard/group-from-results -------------------------------
    svr.Post("/api/dashboard/group-from-results",
             [this](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn_(req, res, "ManagementGroup", "Write")) return;
                 auto session = auth_fn_(req, res);
                 if (!session) return;

                 auto group_name = extract_form_value(req.body, "group_name");
                 auto command_id = extract_form_value(req.body, "command_id");
                 auto plugin = extract_form_value(req.body, "plugin");

                 if (group_name.empty()) {
                     res.status = 400;
                     res.set_header("HX-Retarget", "#group-form-slot");
                     res.set_content(
                         "<span class=\"feedback-error\">Group name is required.</span>",
                         "text/html; charset=utf-8");
                     return;
                 }

                 // Reconstruct filters from form
                 auto filters = parse_filters(req, plugin);

                 if (!response_store_ || !mgmt_group_store_) {
                     res.status = 500;
                     res.set_content(
                         "<span class=\"feedback-error\">Server not configured.</span>",
                         "text/html; charset=utf-8");
                     return;
                 }

                 // Get matching agent IDs from faceted index
                 auto agent_ids = response_store_->facet_agent_ids(command_id, filters);
                 if (agent_ids.empty()) {
                     res.status = 422;
                     res.set_header("HX-Retarget", "#group-form-slot");
                     res.set_content(
                         "<span class=\"feedback-error\">"
                         "No agents match the current filters.</span>",
                         "text/html; charset=utf-8");
                     return;
                 }

                 // Check for duplicate name
                 auto existing = mgmt_group_store_->find_group_by_name(group_name);
                 if (existing) {
                     res.status = 400;
                     res.set_header("HX-Retarget", "#group-form-slot");
                     res.set_content(
                         "<span class=\"feedback-error\">"
                         "A group with that name already exists.</span>",
                         "text/html; charset=utf-8");
                     return;
                 }

                 // Create the static group
                 ManagementGroup mg;
                 mg.name = group_name;
                 mg.description = "Created from filtered results (command " +
                                  command_id + ")";
                 mg.membership_type = "static";
                 mg.created_by = session->username;
                 auto group_result = mgmt_group_store_->create_group(mg);
                 if (!group_result) {
                     res.status = 500;
                     res.set_content(
                         "<span class=\"feedback-error\">"
                         "Failed to create group: " +
                         html_escape(group_result.error()) + "</span>",
                         "text/html; charset=utf-8");
                     return;
                 }
                 auto& group_id = *group_result;

                 // Add all matching agents as static members
                 for (const auto& aid : agent_ids) {
                     mgmt_group_store_->add_member(group_id, aid);
                 }

                 audit_fn_(req, "group.create_from_results", "success",
                          "ManagementGroup", group_id,
                          group_name + " (" + std::to_string(agent_ids.size()) +
                              " agents from " + command_id + ")");

                 // Response: no body, side-effects via HX-Trigger headers
                 res.set_header("HX-Trigger",
                     R"({"showToast":{"message":"Group ')" +
                     html_escape(group_name) + "' created with " +
                     std::to_string(agent_ids.size()) +
                     R"( agents","level":"success"},"agentChanged":true})");
                 res.set_content("", "text/html; charset=utf-8");
             });

    // -- POST /api/dashboard/execute — HTMX-native instruction dispatch --------
    svr.Post("/api/dashboard/execute",
             [this](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn_(req, res, "Execution", "Execute")) return;

                 auto instruction = extract_form_value(req.body, "instruction");
                 auto scope = extract_form_value(req.body, "scope");

                 if (instruction.empty()) {
                     res.set_content(
                         "<span id=\"result-context\" hx-swap-oob=\"true\""
                         " style=\"font-size:0.75rem;color:#f85149\">"
                         "No instruction entered.</span>",
                         "text/html; charset=utf-8");
                     return;
                 }

                 // Parse CLI-style key=value parameters from instruction text
                 auto [command_text, inline_params] = parse_instruction_params(instruction);

                 // Handle built-in "help" command — render directly
                 auto lower_cmd = command_text;
                 for (auto& c : lower_cmd) c = static_cast<char>(std::tolower(c));
                 if (lower_cmd == "help" || lower_cmd.starts_with("help ")) {
                     std::string filter;
                     if (lower_cmd.size() > 5)
                         filter = lower_cmd.substr(5);

                     // Get help content — contains <tr> rows then OOB elements.
                     // Extract only the <tr> rows (everything up to the first
                     // <span or <thead OOB tag) for the tbody swap.
                     auto full = registry_->help_html(filter);
                     auto oob_start = full.find("<span ");
                     std::string rows_only = (oob_start != std::string::npos)
                                                 ? full.substr(0, oob_start)
                                                 : full;
                     // Count rows (each data row is a <tr class="result-row">)
                     int row_count = 0;
                     for (size_t p = 0; (p = rows_only.find("result-row", p)) != std::string::npos; ++p)
                         ++row_count;

                     std::string context = filter.empty() ? "help \u2014 all plugins"
                                                           : "help " + html_escape(filter);

                     // Build OOB response — each element is a standalone OOB swap
                     std::string html;
                     html += "<thead id=\"results-thead\" hx-swap-oob=\"innerHTML\">"
                             "<tr><th class=\"col-agent\">Plugin</th>"
                             "<th>Action</th><th>Description</th></tr></thead>";
                     html += "<tbody id=\"results-tbody\" hx-swap-oob=\"innerHTML\">"
                             + rows_only + "</tbody>";
                     html += "<span id=\"result-context\" hx-swap-oob=\"true\""
                             " style=\"font-size:0.75rem;color:#8b949e\">"
                             + html_escape(context) + "</span>";
                     html += "<strong id=\"row-count\" hx-swap-oob=\"true\">"
                             + std::to_string(row_count) + "</strong>";
                     // Clear filter bar and pagination for help display
                     html += "<div id=\"filter-bar\" hx-swap-oob=\"innerHTML\"></div>";
                     html += "<nav id=\"result-pagination\" hx-swap-oob=\"innerHTML\"></nav>";
                     html += "<div id=\"result-summary\" hx-swap-oob=\"innerHTML\"></div>";
                     html += "<div id=\"group-form-slot\" hx-swap-oob=\"innerHTML\"></div>";
                     res.set_content(html, "text/html; charset=utf-8");
                     return;
                 }

                 // Resolve instruction text → plugin/action
                 auto [plugin, action] = resolve_fn_(lower_cmd);
                 if (plugin.empty()) {
                     res.set_content(
                         "<span id=\"result-context\" hx-swap-oob=\"true\""
                         " style=\"font-size:0.75rem;color:#f85149\">"
                         "Unknown command: &quot;" + html_escape(instruction) +
                         "&quot;. Type &quot;help&quot; to list all commands.</span>",
                         "text/html; charset=utf-8");
                     return;
                 }

                 // Resolve scope → agent_ids or scope expression
                 std::vector<std::string> agent_ids;
                 std::string scope_expr;
                 if (!scope.empty() && scope.starts_with("group:")) {
                     scope_expr = scope;
                 } else if (!scope.empty() && scope != "__all__") {
                     agent_ids.push_back(scope);
                 }
                 // scope == "__all__" or empty → broadcast (empty agent_ids + empty scope)

                 // Dispatch with inline CLI parameters
                 auto [command_id, sent] = dispatch_fn_(plugin, action, agent_ids, scope_expr, inline_params);
                 if (sent == 0) {
                     res.set_content(
                         "<span id=\"result-context\" hx-swap-oob=\"true\""
                         " style=\"font-size:0.75rem;color:#f85149\">"
                         "No agents connected. Cannot dispatch command.</span>",
                         "text/html; charset=utf-8");
                     return;
                 }

                 // Success: return OOB swaps for the results area
                 auto& col_names = columns_for_plugin(plugin);

                 std::string html;
                 html.reserve(4096);

                 // OOB: thead with column headers
                 html += "<thead id=\"results-thead\" hx-swap-oob=\"true\"><tr>";
                 for (size_t i = 0; i < col_names.size(); ++i) {
                     html += (i == 0) ? "<th class=\"col-agent\">" : "<th>";
                     html += html_escape(col_names[i]);
                     html += "</th>";
                 }
                 html += "</tr></thead>";

                 // tbody is cleared via the SSE command-status:RUNNING
                 // event (published by the DispatchFn before this POST
                 // response returns).  Clearing it here would race with
                 // SSE output events — fast agents respond before the
                 // browser receives this POST reply, so an innerHTML OOB
                 // here would wipe already-displayed result rows.

                 // Status badge and row count are set by the SSE
                 // command-status:RUNNING event (no OOB here — it
                 // would race with SSE updates from fast agents).

                 // OOB: result context (only set here, no SSE race)
                 html += "<span id=\"result-context\" hx-swap-oob=\"true\""
                         " style=\"font-size:0.75rem;color:#8b949e\">" +
                         html_escape(instruction) + " &rarr; " +
                         std::to_string(sent) + " agent" +
                         (sent != 1 ? "s" : "") + "</span>";

                 // OOB: filter bar — initially empty, self-refreshes after
                 // results arrive (facets are stored when agent responds,
                 // which is after this HTTP response returns)
                 html += "<div id=\"filter-bar\" hx-swap-oob=\"true\""
                         " hx-get=\"/fragments/results/filter-bar?command_id=" +
                         html_escape(command_id) + "&plugin=" + html_escape(plugin) +
                         "\" hx-trigger=\"load delay:2s\" hx-swap=\"outerHTML\"></div>";

                 // OOB: clear pagination and summary
                 html += "<nav id=\"result-pagination\" hx-swap-oob=\"true\"></nav>";
                 html += "<div id=\"result-summary\" hx-swap-oob=\"true\"></div>";
                 html += "<div id=\"group-form-slot\" hx-swap-oob=\"true\"></div>";

                 // Toast via HX-Trigger
                 res.set_header("HX-Trigger",
                     "{\"showToast\":{\"message\":\"Command sent to " +
                     std::to_string(sent) +
                     " agent(s)\",\"level\":\"success\"}}");

                 audit_fn_(req, "command.dispatch", "success", "command", command_id,
                          plugin + ":" + action + " -> " + std::to_string(sent) + " agent(s)");

                 res.set_content(html, "text/html; charset=utf-8");
             });

    // -- POST /api/dashboard/tar-execute (TAR warehouse SQL query) -------------
    svr.Post("/api/dashboard/tar-execute",
             [this](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn_(req, res, "Execution", "Execute")) return;

                 auto sql = req.get_param_value("sql");
                 if (sql.empty()) {
                     res.set_content("<span id=\"result-context\" hx-swap-oob=\"true\""
                                     " style=\"font-size:0.75rem;color:#f85149\">"
                                     "Missing SQL query.</span>",
                                     "text/html; charset=utf-8");
                     return;
                 }

                 // M5: Server-side SQL validation with keyword blocklist (defense in depth)
                 if (sql.size() > 4096) {
                     res.set_content("<span id=\"result-context\" hx-swap-oob=\"true\""
                                     " style=\"font-size:0.75rem;color:#f85149\">"
                                     "SQL query exceeds 4KB limit.</span>",
                                     "text/html; charset=utf-8");
                     return;
                 }
                 {
                     auto upper = sql;
                     for (auto& c : upper) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
                     size_t start = upper.find_first_not_of(" \t\r\n");
                     if (start == std::string::npos || !upper.substr(start).starts_with("SELECT")) {
                         res.set_content("<span id=\"result-context\" hx-swap-oob=\"true\""
                                         " style=\"font-size:0.75rem;color:#f85149\">"
                                         "Only SELECT queries are allowed.</span>",
                                         "text/html; charset=utf-8");
                         return;
                     }
                     // Block dangerous keywords server-side too
                     static const char* blocked[] = {
                         "INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "CREATE",
                         "ATTACH", "DETACH", "PRAGMA", "LOAD_EXTENSION", nullptr
                     };
                     for (auto kw = blocked; *kw; ++kw) {
                         if (upper.find(*kw) != std::string::npos) {
                             res.set_content("<span id=\"result-context\" hx-swap-oob=\"true\""
                                             " style=\"font-size:0.75rem;color:#f85149\">"
                                             "Query contains forbidden keyword.</span>",
                                             "text/html; charset=utf-8");
                             return;
                         }
                     }
                 }

                 auto scope = req.get_param_value("scope");
                 std::vector<std::string> agent_ids;
                 std::string scope_expr;
                 if (!scope.empty() && scope.starts_with("group:")) {
                     scope_expr = scope;
                 } else if (!scope.empty() && scope != "__all__") {
                     agent_ids.push_back(scope);
                 }

                 std::unordered_map<std::string, std::string> params;
                 params["sql"] = sql;
                 auto [command_id, sent] = dispatch_fn_("tar", "sql", agent_ids, scope_expr, params);

                 if (sent == 0) {
                     res.set_content("<span id=\"result-context\" hx-swap-oob=\"true\""
                                     " style=\"font-size:0.75rem;color:#f85149\">"
                                     "No agents connected.</span>",
                                     "text/html; charset=utf-8");
                     return;
                 }

                 // Success: return OOB swaps for the results area
                 std::string html;
                 html += "<thead id=\"results-thead\" hx-swap-oob=\"innerHTML\">"
                         "<tr><th class=\"col-agent\">Agent</th>"
                         "<th>Waiting for schema...</th></tr></thead>";
                 html += "<tbody id=\"results-tbody\" hx-swap-oob=\"innerHTML\">"
                         "<tr id=\"empty-row\"><td colspan=\"99\" style=\"text-align:center;"
                         "color:#8b949e;padding:2rem 0\">"
                         "Waiting for results...</td></tr></tbody>";
                 html += "<span id=\"status-badge\" class=\"badge-running\""
                         " hx-swap-oob=\"outerHTML\">RUNNING</span>";
                 html += "<span id=\"result-context\" hx-swap-oob=\"true\""
                         " style=\"font-size:0.75rem;color:#8b949e\">TAR SQL &rarr; " +
                         std::to_string(sent) + " agent" +
                         (sent != 1 ? "s" : "") + "</span>";
                 html += "<strong id=\"row-count\" hx-swap-oob=\"true\">0</strong>";
                 html += "<nav id=\"result-pagination\" hx-swap-oob=\"true\"></nav>";
                 html += "<div id=\"result-summary\" hx-swap-oob=\"true\"></div>";

                 res.set_header("HX-Trigger",
                     "{\"showToast\":{\"message\":\"TAR query sent to " +
                     std::to_string(sent) +
                     " agent(s)\",\"level\":\"success\"}}");

                 audit_fn_(req, "tar.sql", "success", "command", command_id,
                          "TAR SQL -> " + std::to_string(sent) + " agent(s)");

                 res.set_content(html, "text/html; charset=utf-8");
             });

    // -- GET /fragments/scope-list (enhanced with groups) ----------------------
    svr.Get("/fragments/scope-list",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn_(req, res, "Infrastructure", "Read")) return;
                auto session = auth_fn_(req, res);
                if (!session) return;

                std::string selected = req.get_param_value("selected");
                if (selected.empty()) selected = "__all__";

                auto html = render_scope_list(selected, session->username);
                res.set_content(html, "text/html; charset=utf-8");
            });

    spdlog::info("DashboardRoutes: registered fragment endpoints");
}

// ---------------------------------------------------------------------------
// parse_filters — extract f_<column_name>=value from request params
// ---------------------------------------------------------------------------

std::vector<FacetFilter> DashboardRoutes::parse_filters(const httplib::Request& req,
                                                         const std::string& plugin) const {
    std::vector<FacetFilter> filters;
    auto& cols = columns_for_plugin(plugin);
    // cols[0] is "Agent" — skip it, field indices are 0-based after Agent
    for (size_t i = 1; i < cols.size(); ++i) {
        std::string param_name = "f_";
        // Lowercase the column name for the param key
        for (char c : cols[i]) {
            if (c == ' ' || c == '-') param_name += '_';
            else param_name += static_cast<char>(std::tolower(c));
        }
        auto val = req.get_param_value(param_name);
        if (val.empty()) {
            // Also try form-encoded body
            val = extract_form_value(req.body, param_name);
        }
        if (!val.empty()) {
            FacetFilter f;
            f.col_idx = static_cast<int>(i - 1);
            f.value = val;
            filters.push_back(f);
        }
    }
    return filters;
}

// ---------------------------------------------------------------------------
// render_results
// ---------------------------------------------------------------------------

std::string DashboardRoutes::render_results(
    const std::string& command_id, const std::string& plugin,
    const std::string& sort_col, const std::string& sort_dir,
    int page, int per_page,
    const std::vector<FacetFilter>& filters,
    const std::string& text_query) {

    if (!response_store_) {
        return "<tbody id=\"results-tbody\"><tr><td class=\"empty-state\">"
               "Response store not available.</td></tr></tbody>";
    }

    auto& col_names = columns_for_plugin(plugin);

    // Phase 1: determine which responses match the filters
    std::vector<StoredResponse> responses;
    int64_t total_agent_count = 0;

    if (filters.empty()) {
        // No filters — load all responses for this instruction
        ResponseQuery q;
        q.limit = 10000; // upper bound
        responses = response_store_->query(command_id, q);
        total_agent_count = static_cast<int64_t>(responses.size());
    } else {
        // Use faceted index to get matching response IDs, then load them
        auto resp_ids = response_store_->facet_response_ids(command_id, filters, 10000, 0);
        responses = response_store_->query_by_ids(resp_ids);
        total_agent_count = response_store_->facet_agent_count(command_id, filters);
    }

    // Phase 2: parse output lines, apply per-line filters and text search
    struct ResultLine {
        std::string agent_name;
        std::vector<std::string> fields; // excludes Agent column
    };
    std::vector<ResultLine> all_lines;
    all_lines.reserve(responses.size() * 4);

    for (const auto& resp : responses) {
        auto agent_name = registry_ ? registry_->display_name(resp.agent_id)
                                     : resp.agent_id;
        auto lines = split_output_lines(resp.output);
        for (const auto& line : lines) {
            auto fields = split_fields(plugin, line);

            // Apply per-field filters
            bool match = true;
            for (const auto& f : filters) {
                if (f.col_idx >= 0 && f.col_idx < static_cast<int>(fields.size())) {
                    if (fields[f.col_idx] != f.value) { match = false; break; }
                }
            }
            if (!match) continue;

            // Apply free-text search
            if (!text_query.empty()) {
                bool found = false;
                for (const auto& fld : fields) {
                    if (fld.find(text_query) != std::string::npos) { found = true; break; }
                }
                if (!found && agent_name.find(text_query) == std::string::npos)
                    continue;
            }

            ResultLine rl;
            rl.agent_name = agent_name;
            rl.fields = std::move(fields);
            all_lines.push_back(std::move(rl));
        }
    }

    // Phase 3: sort
    int sort_idx = -1; // -1 = sort by agent name
    if (sort_col != "agent") {
        sort_idx = col_index_for_name(plugin, sort_col);
    }
    bool ascending = (sort_dir == "asc");

    std::sort(all_lines.begin(), all_lines.end(),
              [sort_idx, ascending](const ResultLine& a, const ResultLine& b) {
                  std::string va, vb;
                  if (sort_idx < 0) {
                      va = a.agent_name;
                      vb = b.agent_name;
                  } else {
                      va = (sort_idx < static_cast<int>(a.fields.size())) ? a.fields[sort_idx] : "";
                      vb = (sort_idx < static_cast<int>(b.fields.size())) ? b.fields[sort_idx] : "";
                  }
                  return ascending ? (va < vb) : (va > vb);
              });

    // Phase 4: paginate
    int64_t total_lines = static_cast<int64_t>(all_lines.size());
    int64_t total_pages = std::max(int64_t{1}, (total_lines + per_page - 1) / per_page);
    if (page > total_pages) page = static_cast<int>(total_pages);
    int64_t start = static_cast<int64_t>(page - 1) * per_page;
    int64_t end = std::min(start + per_page, total_lines);

    // Phase 5: render HTML

    // Build base URL for sort/page links (preserving all current params)
    auto base_url = [&](const std::string& new_sort, const std::string& new_dir,
                        int new_page) {
        std::string url = "/fragments/results?command_id=" + html_escape(command_id) +
                          "&amp;plugin=" + html_escape(plugin) +
                          "&amp;sort=" + html_escape(new_sort) +
                          "&amp;dir=" + html_escape(new_dir) +
                          "&amp;page=" + std::to_string(new_page) +
                          "&amp;per_page=" + std::to_string(per_page);
        for (const auto& f : filters) {
            // Reconstruct f_<col> params
            if (f.col_idx >= 0 && f.col_idx + 1 < static_cast<int>(col_names.size())) {
                std::string pname = "f_";
                for (char c : col_names[f.col_idx + 1]) {
                    if (c == ' ' || c == '-') pname += '_';
                    else pname += static_cast<char>(std::tolower(c));
                }
                url += "&amp;" + pname + "=" + html_escape(f.value);
            }
        }
        if (!text_query.empty())
            url += "&amp;q=" + html_escape(text_query);
        return url;
    };

    std::string html;
    html.reserve(all_lines.size() * 300 + 4096);

    // Primary: tbody rows
    html += "<tbody id=\"results-tbody\">";
    if (all_lines.empty()) {
        html += "<tr><td colspan=\"" + std::to_string(col_names.size()) +
                "\" class=\"empty-state\">No results match your filters.</td></tr>";
    } else {
        for (int64_t i = start; i < end; ++i) {
            const auto& rl = all_lines[i];
            // Data row
            html += "<tr class=\"result-row\" onclick=\"toggleDetail(this)\">";
            // Agent column
            html += "<td class=\"col-agent\" title=\"" + html_escape(rl.agent_name) +
                    "\">" + html_escape(rl.agent_name) + "</td>";
            // Field columns
            for (size_t c = 0; c < rl.fields.size(); ++c) {
                auto esc = html_escape(rl.fields[c]);
                html += "<td title=\"" + esc + "\">" + esc + "</td>";
            }
            html += "</tr>";
            // Detail drawer
            html += "<tr class=\"result-detail\"><td colspan=\"" +
                    std::to_string(1 + rl.fields.size()) +
                    "\"><div class=\"detail-content\">";
            html += "<div class=\"detail-label\">Agent</div>"
                    "<div class=\"detail-value\">" + html_escape(rl.agent_name) + "</div>";
            for (size_t c = 0; c < rl.fields.size(); ++c) {
                auto label = (c + 1 < col_names.size()) ? col_names[c + 1]
                                                         : ("Column " + std::to_string(c + 2));
                html += "<div class=\"detail-label\">" + html_escape(label) + "</div>"
                        "<div class=\"detail-value\">" + html_escape(rl.fields[c]) + "</div>";
            }
            html += "</div></td></tr>";
        }
    }
    html += "</tbody>";

    // OOB: thead with sort indicators
    html += "<thead id=\"results-thead\" hx-swap-oob=\"true\"><tr>";
    // Agent column header
    {
        auto new_dir = (sort_col == "agent" && sort_dir == "asc") ? "desc" : "asc";
        html += "<th class=\"col-agent sortable\" hx-get=\"" +
                base_url("agent", new_dir, 1) +
                "\" hx-target=\"#results-tbody\" hx-sync=\"this:abort\""
                " hx-indicator=\"#results-loading\">"
                "Agent";
        if (sort_col == "agent")
            html += (sort_dir == "asc") ? " &#9650;" : " &#9660;";
        html += "</th>";
    }
    // Other column headers
    for (size_t i = 1; i < col_names.size(); ++i) {
        std::string col_key;
        for (char c : col_names[i]) {
            if (c == ' ' || c == '-') col_key += '_';
            else col_key += static_cast<char>(std::tolower(c));
        }
        auto new_dir = (sort_col == col_key && sort_dir == "asc") ? "desc" : "asc";
        html += "<th class=\"sortable\" hx-get=\"" +
                base_url(col_key, new_dir, 1) +
                "\" hx-target=\"#results-tbody\" hx-sync=\"this:abort\""
                " hx-indicator=\"#results-loading\">" +
                html_escape(col_names[i]);
        if (sort_col == col_key)
            html += (sort_dir == "asc") ? " &#9650;" : " &#9660;";
        html += "</th>";
    }
    html += "</tr></thead>";

    // OOB: pagination
    html += "<nav id=\"result-pagination\" hx-swap-oob=\"true\">";
    if (total_lines > 0) {
        html += "<span>Showing " + std::to_string(start + 1) + "-" +
                std::to_string(end) + " of " + std::to_string(total_lines) + "</span>";
        if (page > 1) {
            html += " <button class=\"btn-page\" hx-get=\"" +
                    base_url(sort_col, sort_dir, page - 1) +
                    "\" hx-target=\"#results-tbody\" hx-sync=\"this:abort\">"
                    "Prev</button>";
        }
        if (page < static_cast<int>(total_pages)) {
            html += " <button class=\"btn-page\" hx-get=\"" +
                    base_url(sort_col, sort_dir, page + 1) +
                    "\" hx-target=\"#results-tbody\" hx-sync=\"this:abort\">"
                    "Next</button>";
        }
    }
    html += "</nav>";

    // OOB: summary with group-creation affordance
    html += "<div id=\"result-summary\" hx-swap-oob=\"true\">";
    if (total_lines > 0) {
        html += std::to_string(total_lines) + " result" +
                (total_lines != 1 ? "s" : "") + " across " +
                std::to_string(total_agent_count) + " agent" +
                (total_agent_count != 1 ? "s" : "");

        if (!filters.empty() && total_agent_count > 0) {
            // Build filter params for the create-group-form URL
            std::string filter_params;
            for (const auto& f : filters) {
                if (f.col_idx >= 0 && f.col_idx + 1 < static_cast<int>(col_names.size())) {
                    std::string pname = "f_";
                    for (char c : col_names[f.col_idx + 1]) {
                        if (c == ' ' || c == '-') pname += '_';
                        else pname += static_cast<char>(std::tolower(c));
                    }
                    filter_params += "&amp;" + pname + "=" + html_escape(f.value);
                }
            }
            html += " <button class=\"btn-create-group\" hx-get=\"/fragments/create-group-form"
                    "?command_id=" + html_escape(command_id) +
                    "&amp;plugin=" + html_escape(plugin) + filter_params +
                    "\" hx-target=\"#group-form-slot\" hx-swap=\"innerHTML\">"
                    "Create Group from " + std::to_string(total_agent_count) +
                    " Agent" + (total_agent_count != 1 ? "s" : "") + "</button>";
        }
    }
    html += "</div>";

    return html;
}

// ---------------------------------------------------------------------------
// render_filter_bar
// ---------------------------------------------------------------------------

std::string DashboardRoutes::render_filter_bar(const std::string& command_id,
                                                const std::string& plugin) {
    auto& cols = columns_for_plugin(plugin);

    std::string html;
    html += "<form id=\"filter-bar\" class=\"filter-bar\" hx-sync=\"this:abort\">"
            "<input type=\"hidden\" name=\"command_id\" value=\"" +
            html_escape(command_id) + "\">"
            "<input type=\"hidden\" name=\"plugin\" value=\"" +
            html_escape(plugin) + "\">";

    // Per-column filter controls (skip Agent at index 0)
    for (size_t i = 1; i < cols.size(); ++i) {
        std::string param_name = "f_";
        for (char c : cols[i]) {
            if (c == ' ' || c == '-') param_name += '_';
            else param_name += static_cast<char>(std::tolower(c));
        }

        // Get distinct facet values for this column
        int col_idx = static_cast<int>(i - 1);
        std::vector<FacetValue> facet_vals;
        if (response_store_)
            facet_vals = response_store_->facet_values(command_id, col_idx);

        html += "<label>" + html_escape(cols[i]) + "</label>";

        if (facet_vals.size() <= 20) {
            // Dropdown for small cardinality
            html += "<select name=\"" + param_name + "\""
                    " hx-get=\"/fragments/results\" hx-target=\"#results-tbody\""
                    " hx-include=\"#filter-bar\" hx-indicator=\"#results-loading\""
                    " hx-sync=\"closest form:abort\">"
                    "<option value=\"\">All</option>";
            for (const auto& fv : facet_vals) {
                html += "<option value=\"" + html_escape(fv.value) + "\">" +
                        html_escape(fv.value) + " (" + std::to_string(fv.line_count) +
                        ")</option>";
            }
            html += "</select>";
        } else {
            // Text input for high cardinality
            html += "<input type=\"text\" name=\"" + param_name + "\""
                    " placeholder=\"Filter " + html_escape(cols[i]) + "...\""
                    " hx-get=\"/fragments/results\" hx-target=\"#results-tbody\""
                    " hx-include=\"#filter-bar\" hx-indicator=\"#results-loading\""
                    " hx-trigger=\"input changed delay:300ms\""
                    " hx-sync=\"closest form:abort\">";
        }
    }

    // Free-text search
    html += "<label>Search</label>"
            "<input type=\"search\" name=\"q\" placeholder=\"Free text...\""
            " hx-get=\"/fragments/results\" hx-target=\"#results-tbody\""
            " hx-include=\"#filter-bar\" hx-indicator=\"#results-loading\""
            " hx-trigger=\"input changed delay:300ms\""
            " hx-sync=\"closest form:abort\">";

    html += "</form>";
    return html;
}

// ---------------------------------------------------------------------------
// render_create_group_form
// ---------------------------------------------------------------------------

std::string DashboardRoutes::render_create_group_form(
    const std::string& command_id, const std::string& plugin,
    const std::vector<FacetFilter>& filters, int64_t agent_count) {

    auto& col_names = columns_for_plugin(plugin);

    std::string html;
    html += "<form class=\"create-group-form\""
            " hx-post=\"/api/dashboard/group-from-results\" hx-swap=\"none\""
            " hx-indicator=\"#group-form-slot\">"
            "<input type=\"hidden\" name=\"command_id\" value=\"" +
            html_escape(command_id) + "\">"
            "<input type=\"hidden\" name=\"plugin\" value=\"" +
            html_escape(plugin) + "\">";

    // Include current filter values as hidden fields
    for (const auto& f : filters) {
        if (f.col_idx >= 0 && f.col_idx + 1 < static_cast<int>(col_names.size())) {
            std::string pname = "f_";
            for (char c : col_names[f.col_idx + 1]) {
                if (c == ' ' || c == '-') pname += '_';
                else pname += static_cast<char>(std::tolower(c));
            }
            html += "<input type=\"hidden\" name=\"" + pname + "\" value=\"" +
                    html_escape(f.value) + "\">";
        }
    }

    html += "<input name=\"group_name\" type=\"text\" placeholder=\"Group name\""
            " required maxlength=\"128\" autofocus>"
            " <button type=\"submit\">Create Static Group</button>"
            " <span class=\"form-hint\">" + std::to_string(agent_count) +
            " agent" + (agent_count != 1 ? "s" : "") +
            " will be added</span></form>";

    return html;
}

// ---------------------------------------------------------------------------
// render_scope_list
// ---------------------------------------------------------------------------

std::string DashboardRoutes::render_scope_list(const std::string& selected,
                                                const std::string& username) {
    std::string html;
    html.reserve(4096);

    // "All Agents" item
    html += "<div class=\"scope-item";
    if (selected == "__all__") html += " selected";
    html += "\" data-scope=\"__all__\" onclick=\"selectScope(this)\">"
            "<span class=\"scope-item-name scope-item-all\">All Agents</span>"
            "<span class=\"scope-item-meta\">Broadcast to every connected agent</span>"
            "</div>";

    // Groups section
    if (mgmt_group_store_) {
        auto groups = mgmt_group_store_->list_groups();
        if (!groups.empty()) {
            html += "<div class=\"scope-section-header\">Groups</div>";
            for (const auto& g : groups) {
                auto members = mgmt_group_store_->get_members(g.id);
                auto member_count = members.size();
                std::string scope_key = "group:" + g.id;

                html += "<div class=\"scope-item";
                if (selected == scope_key) html += " selected";
                html += "\" data-scope=\"" + html_escape(scope_key) +
                        "\" onclick=\"selectScope(this)\">"
                        "<span class=\"scope-item-name\">" +
                        html_escape(g.name) + "</span>"
                        "<span class=\"scope-item-meta\">" +
                        std::to_string(member_count) + " agent" +
                        (member_count != 1 ? "s" : "") + " &middot; " +
                        html_escape(g.membership_type) + "</span></div>";
            }
        }
    }

    // Individual agents section
    if (agents_json_fn_) {
        auto agents_json_str = agents_json_fn_();
        auto agents_arr = nlohmann::json::parse(agents_json_str, nullptr, false);
        if (agents_arr.is_array()) {
            std::sort(agents_arr.begin(), agents_arr.end(),
                      [](const nlohmann::json& a, const nlohmann::json& b) {
                          return a.value("agent_id", "") < b.value("agent_id", "");
                      });

            html += "<div class=\"scope-section-header\">Agents</div>";
            for (const auto& a : agents_arr) {
                auto id = a.value("agent_id", "");
                auto hostname = a.value("hostname", "");
                auto os = a.value("os", "?");
                auto arch = a.value("arch", "?");
                auto version = a.value("agent_version", "");
                auto short_id = (id.size() > 12) ? id.substr(0, 12) : id;

                html += "<div class=\"scope-item";
                if (selected == id) html += " selected";
                html += "\" data-scope=\"" + html_escape(id) +
                        "\" onclick=\"selectScope(this)\">"
                        "<span class=\"scope-item-name\"><span class=\"online-dot\"></span>" +
                        html_escape(hostname.empty() ? id : hostname) +
                        "</span><span class=\"scope-item-meta\">" +
                        html_escape(short_id) + " &middot; " +
                        html_escape(os) + "/" + html_escape(arch) +
                        (version.empty() ? "" : " &middot; v" + html_escape(version)) +
                        "</span></div>";
            }

            // OOB: agent count badge
            auto count = agents_arr.size();
            html += "<span id=\"agent-count\" hx-swap-oob=\"true\">" +
                    std::to_string(count) + " agent" +
                    (count != 1u ? "s" : "") + "</span>";

            // Hidden data carrier
            html += "<div id=\"scope-data\" data-agents=\"" +
                    html_escape(agents_arr.dump()) +
                    "\" style=\"display:none\"></div>";
        }
    }

    return html;
}

} // namespace yuzu::server
