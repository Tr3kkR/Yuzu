#include "workflow_routes.hpp"

#include "compliance_eval.hpp"
#include "scope_engine.hpp"
#include "web_utils.hpp"

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <expected>
#include <map>
#include <string>
#include <unordered_map>
#include <vector>

namespace yuzu::server {

void WorkflowRoutes::register_routes(
    httplib::Server& svr, AuthFn auth_fn, PermFn perm_fn, AuditFn audit_fn,
    EmitEventFn emit_fn, ScopeEstimateFn scope_fn,
    WorkflowEngine* workflow_engine,
    ExecutionTracker* execution_tracker,
    ScheduleEngine* schedule_engine,
    ProductPackStore* product_pack_store,
    InstructionStore* instruction_store,
    PolicyStore* policy_store,
    CommandDispatchFn command_dispatch_fn) {

    auto cmd_dispatch = std::move(command_dispatch_fn);

    // -- HTMX fragments --------------------------------------------------------

    // GET /fragments/executions -- execution history HTMX fragment
    svr.Get("/fragments/executions",
        [auth_fn, execution_tracker](const httplib::Request& req, httplib::Response& res) {
            auto session = auth_fn(req, res);
            if (!session)
                return;
            if (!execution_tracker) {
                res.set_content("<div class=\"empty-state\">Not available</div>", "text/html");
                return;
            }

            ExecutionQuery q;
            q.limit = 50;
            auto execs = execution_tracker->query_executions(q);
            std::string html;
            if (execs.empty()) {
                html = "<div class=\"empty-state\">No executions yet.</div>";
            } else {
                html = "<table><thead><tr><th>ID</th><th>Status</th><th>Progress</"
                       "th><th>Dispatched By</th><th>Time</th></tr></thead><tbody>";
                for (const auto& e : execs) {
                    auto pct =
                        e.agents_targeted > 0 ? (e.agents_responded * 100 / e.agents_targeted) : 0;
                    auto status_cls = "status-" + e.status;
                    html += "<tr><td><code style=\"font-size:0.7rem\">" +
                            html_escape(e.id.substr(0, 12)) +
                            "</code></td>"
                            "<td><span class=\"status-badge " +
                            status_cls + "\">" + html_escape(e.status) +
                            "</span></td>"
                            "<td><div class=\"progress-bar\"><div class=\"progress-fill\" "
                            "style=\"width:" +
                            std::to_string(pct) +
                            "%\"></div></div>"
                            "<span style=\"font-size:0.65rem\">" +
                            std::to_string(e.agents_responded) + "/" +
                            std::to_string(e.agents_targeted) +
                            "</span></td>"
                            "<td>" +
                            html_escape(e.dispatched_by) +
                            "</td>"
                            "<td style=\"font-size:0.7rem\">" +
                            std::to_string(e.dispatched_at) + "</td></tr>";
                }
                html += "</tbody></table>";
            }
            res.set_content(html, "text/html; charset=utf-8");
        });

    // GET /fragments/schedules -- schedule list HTMX fragment
    svr.Get("/fragments/schedules",
        [auth_fn, schedule_engine](const httplib::Request& req, httplib::Response& res) {
            auto session = auth_fn(req, res);
            if (!session)
                return;
            if (!schedule_engine) {
                res.set_content("<div class=\"empty-state\">Not available</div>", "text/html");
                return;
            }

            auto scheds = schedule_engine->query_schedules();
            std::string html;
            if (scheds.empty()) {
                html = "<div class=\"empty-state\">No schedules configured.</div>";
            } else {
                html = "<table><thead><tr><th>Name</th><th>Frequency</th><th>Enabled</th><th>Next "
                       "Run</th><th>Count</th><th></th></tr></thead><tbody>";
                for (const auto& s : scheds) {
                    html += "<tr><td>" + html_escape(s.name) +
                            "</td>"
                            "<td><code>" +
                            html_escape(s.frequency_type) +
                            "</code></td>"
                            "<td>" +
                            std::string(s.enabled ? "Yes" : "No") +
                            "</td>"
                            "<td style=\"font-size:0.7rem\">" +
                            (s.next_execution_at > 0 ? std::to_string(s.next_execution_at) : "-") +
                            "</td>"
                            "<td>" +
                            std::to_string(s.execution_count) +
                            "</td>"
                            "<td><button class=\"btn btn-danger\" "
                            "style=\"font-size:0.65rem;padding:0.15rem 0.5rem\" "
                            "hx-delete=\"/api/schedules/" +
                            s.id +
                            "\" hx-target=\"#tab-schedules\" hx-swap=\"innerHTML\" "
                            "hx-confirm=\"Delete schedule?\">Delete</button></td></tr>";
                }
                html += "</tbody></table>";
            }
            res.set_content(html, "text/html; charset=utf-8");
        });

    // -- Scope estimate API ----------------------------------------------------

    // POST /api/scope/estimate -- scope expression target count
    svr.Post("/api/scope/estimate",
        [auth_fn, scope_fn](const httplib::Request& req, httplib::Response& res) {
            auto session = auth_fn(req, res);
            if (!session)
                return;

            // Extract expression from body
            std::string expression;
            try {
                auto j = nlohmann::json::parse(req.body);
                if (j.contains("expression") && j["expression"].is_string())
                    expression = j["expression"].get<std::string>();
            } catch (...) {}

            if (expression.empty()) {
                res.status = 400;
                res.set_content(R"({"error":{"code":400,"message":"expression required"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }

            auto parsed = yuzu::scope::parse(expression);
            if (!parsed) {
                res.status = 400;
                res.set_content(nlohmann::json({{"error", parsed.error()}}).dump(),
                                "application/json");
                return;
            }

            auto [matched, total] = scope_fn(expression);
            res.set_content(
                nlohmann::json({{"matched", matched}, {"total", total}})
                    .dump(),
                "application/json");
        });

    // -- Workflow Engine API (Phase 7) -----------------------------------------

    // GET /api/workflows -- list all workflows
    svr.Get("/api/workflows",
        [perm_fn, workflow_engine](const httplib::Request& req, httplib::Response& res) {
            if (!perm_fn(req, res, "Workflow", "Read"))
                return;
            if (!workflow_engine || !workflow_engine->is_open()) {
                res.status = 503;
                res.set_content(R"({"error":{"code":503,"message":"workflow engine not available"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }

            WorkflowQuery q;
            if (req.has_param("name"))
                q.name_filter = req.get_param_value("name");
            try {
                if (req.has_param("limit"))
                    q.limit = std::stoi(req.get_param_value("limit"));
            } catch (const std::exception&) {
                res.status = 400;
                res.set_content(R"({"error":{"code":400,"message":"invalid numeric query parameter"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }

            auto workflows = workflow_engine->list_workflows(q);
            nlohmann::json arr = nlohmann::json::array();
            for (const auto& w : workflows) {
                nlohmann::json steps_arr = nlohmann::json::array();
                for (const auto& s : w.steps) {
                    steps_arr.push_back({{"index", s.index},
                                         {"instruction_id", s.instruction_id},
                                         {"label", s.label},
                                         {"condition", s.condition},
                                         {"retry_count", s.retry_count},
                                         {"foreach", s.foreach_source},
                                         {"on_failure", s.on_failure}});
                }
                arr.push_back({{"id", w.id},
                               {"name", w.name},
                               {"description", w.description},
                               {"steps", steps_arr},
                               {"step_count", w.steps.size()},
                               {"created_at", w.created_at},
                               {"updated_at", w.updated_at}});
            }
            res.set_content(
                nlohmann::json({{"workflows", arr}, {"count", arr.size()}}).dump(),
                "application/json");
        });

    // POST /api/workflows -- create workflow from YAML
    svr.Post("/api/workflows",
        [perm_fn, audit_fn, emit_fn, workflow_engine](const httplib::Request& req, httplib::Response& res) {
            if (!perm_fn(req, res, "Workflow", "Write"))
                return;
            if (!workflow_engine || !workflow_engine->is_open()) {
                res.status = 503;
                res.set_content(R"({"error":{"code":503,"message":"workflow engine not available"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }

            std::string yaml_source;
            if (req.get_header_value("Content-Type").find("application/json") != std::string::npos) {
                try {
                    auto j = nlohmann::json::parse(req.body);
                    yaml_source = j.value("yaml_source", "");
                } catch (const std::exception& e) {
                    res.status = 400;
                    res.set_content(nlohmann::json({{"error", e.what()}}).dump(), "application/json");
                    return;
                }
            } else {
                yaml_source = req.body;
            }

            auto result = workflow_engine->create_workflow(yaml_source);
            if (!result) {
                res.status = 400;
                res.set_content(nlohmann::json({{"error", result.error()}}).dump(), "application/json");
                return;
            }
            audit_fn(req, "workflow.create", "success", "workflow", *result, "");
            emit_fn("workflow.created", req);
            res.set_header("HX-Trigger",
                R"({"showToast":{"message":"Workflow created","level":"success"}})");
            res.status = 201;
            res.set_content(nlohmann::json({{"id", *result}, {"status", "created"}}).dump(),
                            "application/json");
        });

    // GET /api/workflows/:id -- get workflow detail
    svr.Get(R"(/api/workflows/([^/]+))",
        [perm_fn, workflow_engine](const httplib::Request& req, httplib::Response& res) {
            if (!perm_fn(req, res, "Workflow", "Read"))
                return;
            if (!workflow_engine) {
                res.status = 503;
                res.set_content(R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }

            auto id = req.matches[1].str();
            auto workflow = workflow_engine->get_workflow(id);
            if (!workflow) {
                res.status = 404;
                res.set_content(R"({"error":{"code":404,"message":"workflow not found"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }

            nlohmann::json steps_arr = nlohmann::json::array();
            for (const auto& s : workflow->steps) {
                steps_arr.push_back({{"index", s.index},
                                     {"instruction_id", s.instruction_id},
                                     {"label", s.label},
                                     {"condition", s.condition},
                                     {"retry_count", s.retry_count},
                                     {"retry_delay_seconds", s.retry_delay_seconds},
                                     {"foreach", s.foreach_source},
                                     {"on_failure", s.on_failure}});
            }

            res.set_content(
                nlohmann::json({{"id", workflow->id},
                                {"name", workflow->name},
                                {"description", workflow->description},
                                {"yaml_source", workflow->yaml_source},
                                {"steps", steps_arr},
                                {"created_at", workflow->created_at},
                                {"updated_at", workflow->updated_at}})
                    .dump(),
                "application/json");
        });

    // DELETE /api/workflows/:id -- delete workflow
    svr.Delete(R"(/api/workflows/([^/]+))",
        [perm_fn, audit_fn, emit_fn, workflow_engine](const httplib::Request& req, httplib::Response& res) {
            if (!perm_fn(req, res, "Workflow", "Delete"))
                return;
            if (!workflow_engine) {
                res.status = 503;
                res.set_content(R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }

            auto id = req.matches[1].str();
            bool deleted = workflow_engine->delete_workflow(id);
            if (deleted) {
                audit_fn(req, "workflow.delete", "success", "workflow", id, "");
                emit_fn("workflow.deleted", req);
                res.set_header("HX-Trigger",
                    R"({"showToast":{"message":"Workflow deleted","level":"success"}})");
            }
            res.set_content(nlohmann::json({{"deleted", deleted}}).dump(), "application/json");
        });

    // POST /api/workflows/:id/execute -- execute workflow against agents
    svr.Post(R"(/api/workflows/([^/]+)/execute)",
        [perm_fn, audit_fn, emit_fn, workflow_engine, instruction_store, cmd_dispatch](const httplib::Request& req, httplib::Response& res) {
            if (!perm_fn(req, res, "Workflow", "Execute"))
                return;
            if (!workflow_engine || !workflow_engine->is_open()) {
                res.status = 503;
                res.set_content(R"({"error":{"code":503,"message":"workflow engine not available"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }

            auto workflow_id = req.matches[1].str();

            // Parse agent_ids from request body
            std::vector<std::string> agent_ids;
            try {
                auto j = nlohmann::json::parse(req.body);
                if (j.contains("agent_ids") && j["agent_ids"].is_array()) {
                    for (const auto& aid : j["agent_ids"])
                        agent_ids.push_back(aid.get<std::string>());
                }
            } catch (const std::exception& e) {
                res.status = 400;
                res.set_content(nlohmann::json({{"error", e.what()}}).dump(), "application/json");
                return;
            }

            if (agent_ids.empty()) {
                res.status = 400;
                res.set_content(R"({"error":{"code":400,"message":"agent_ids array is required"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }

            // Create a dispatch function that uses the real command dispatch
            auto dispatch_fn = [instruction_store, &cmd_dispatch](
                                    const std::string& instruction_id,
                                    const std::string& agent_ids_json,
                                    const std::string& parameters_json)
                -> std::expected<std::string, std::string> {
                // Look up the instruction definition to get plugin + action
                if (!instruction_store || !instruction_store->is_open())
                    return std::unexpected<std::string>("instruction store not available");

                auto def = instruction_store->get_definition(instruction_id);
                if (!def)
                    return std::unexpected<std::string>("unknown instruction: " + instruction_id);

                // Parse agent_ids from JSON array
                std::vector<std::string> target_ids;
                try {
                    auto j = nlohmann::json::parse(agent_ids_json);
                    if (j.is_array()) {
                        for (const auto& a : j)
                            target_ids.push_back(a.get<std::string>());
                    }
                } catch (...) {}

                // Parse parameters from JSON object
                std::unordered_map<std::string, std::string> params;
                try {
                    auto j = nlohmann::json::parse(parameters_json);
                    if (j.is_object()) {
                        for (auto& [k, v] : j.items())
                            params[k] = v.is_string() ? v.get<std::string>() : v.dump();
                    }
                } catch (...) {}

                // Dispatch via gRPC
                auto [command_id, sent] = cmd_dispatch(
                    def->plugin, def->action, target_ids, "", params);

                if (sent == 0)
                    return std::unexpected<std::string>("no agents reached for " + instruction_id);

                return nlohmann::json({
                    {"status", "dispatched"},
                    {"command_id", command_id},
                    {"agents_reached", sent}
                }).dump();
            };

            // Condition evaluator using compliance_eval
            auto condition_fn = [](const std::string& expression,
                                   const std::map<std::string, std::string>& fields) -> bool {
                return evaluate_compliance_bool(expression, fields);
            };

            auto result = workflow_engine->execute(
                workflow_id, agent_ids, dispatch_fn, condition_fn);

            if (!result) {
                res.status = 400;
                res.set_content(nlohmann::json({{"error", result.error()}}).dump(), "application/json");
                return;
            }
            audit_fn(req, "workflow.execute", "success", "workflow", workflow_id,
                      "execution_id=" + *result);
            emit_fn("workflow.executed", req);
            res.set_header("HX-Trigger",
                R"({"showToast":{"message":"Workflow execution started","level":"success"}})");
            res.status = 202;
            res.set_content(
                nlohmann::json({{"execution_id", *result}, {"status", "running"}}).dump(),
                "application/json");
        });

    // GET /api/workflow-executions/:id -- get execution status
    svr.Get(R"(/api/workflow-executions/([^/]+))",
        [perm_fn, workflow_engine](const httplib::Request& req, httplib::Response& res) {
            if (!perm_fn(req, res, "Workflow", "Read"))
                return;
            if (!workflow_engine) {
                res.status = 503;
                res.set_content(R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }

            auto id = req.matches[1].str();
            auto exec = workflow_engine->get_execution(id);
            if (!exec) {
                res.status = 404;
                res.set_content(R"({"error":{"code":404,"message":"execution not found"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }

            nlohmann::json steps_arr = nlohmann::json::array();
            for (const auto& sr : exec->step_results) {
                steps_arr.push_back({{"step_index", sr.step_index},
                                     {"instruction_id", sr.instruction_id},
                                     {"status", sr.status},
                                     {"result", nlohmann::json::parse(sr.result_json, nullptr, false)},
                                     {"started_at", sr.started_at},
                                     {"completed_at", sr.completed_at},
                                     {"attempt", sr.attempt}});
            }

            res.set_content(
                nlohmann::json({{"id", exec->id},
                                {"workflow_id", exec->workflow_id},
                                {"status", exec->status},
                                {"agent_ids", nlohmann::json::parse(exec->agent_ids_json, nullptr, false)},
                                {"current_step", exec->current_step},
                                {"started_at", exec->started_at},
                                {"completed_at", exec->completed_at},
                                {"steps", steps_arr}})
                    .dump(),
                "application/json");
        });

    // -- Single Instruction Execution API --------------------------------------

    // POST /api/instructions/:id/execute — dispatch a single instruction definition
    svr.Post(R"(/api/instructions/([^/]+)/execute)",
        [perm_fn, audit_fn, emit_fn, instruction_store, cmd_dispatch, execution_tracker](
            const httplib::Request& req, httplib::Response& res) {
            if (!perm_fn(req, res, "Execution", "Execute"))
                return;
            if (!instruction_store || !instruction_store->is_open()) {
                res.status = 503;
                res.set_content(R"({"error":{"code":503,"message":"instruction store not available"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }

            auto def_id = req.matches[1].str();
            auto def = instruction_store->get_definition(def_id);
            if (!def) {
                res.status = 404;
                res.set_content(R"({"error":{"code":404,"message":"instruction definition not found"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }

            // Parse request body
            std::vector<std::string> agent_ids;
            std::string scope_expr;
            std::unordered_map<std::string, std::string> params;
            try {
                auto j = nlohmann::json::parse(req.body);
                if (j.contains("agent_ids") && j["agent_ids"].is_array()) {
                    for (const auto& a : j["agent_ids"])
                        agent_ids.push_back(a.get<std::string>());
                }
                if (j.contains("scope") && j["scope"].is_string())
                    scope_expr = j["scope"].get<std::string>();
                if (j.contains("params") && j["params"].is_object()) {
                    for (auto& [k, v] : j["params"].items())
                        params[k] = v.is_string() ? v.get<std::string>() : v.dump();
                }
            } catch (const std::exception& e) {
                res.status = 400;
                res.set_content(nlohmann::json({{"error", e.what()}}).dump(), "application/json");
                return;
            }

            // Empty agent_ids + empty scope = broadcast to all agents

            // Dispatch
            auto [command_id, sent] = cmd_dispatch(
                def->plugin, def->action, agent_ids, scope_expr, params);

            if (sent == 0) {
                res.status = 503;
                res.set_content(R"({"error":{"code":503,"message":"no agents reached"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }

            // Record execution if tracker available
            if (execution_tracker) {
                Execution exec;
                exec.definition_id = def_id;
                exec.status = "running";
                exec.scope_expression = scope_expr;
                exec.parameter_values = nlohmann::json(params).dump();
                exec.agents_targeted = sent;
                exec.dispatched_by = "api";
                execution_tracker->create_execution(exec);
            }

            audit_fn(req, "instruction.execute", "success", "instruction", def_id,
                      "command_id=" + command_id + " agents=" + std::to_string(sent));
            emit_fn("instruction.executed", req);

            auto trigger_msg = std::string("{\"showToast\":{\"message\":\"Instruction dispatched to ")
                + std::to_string(sent) + " agent(s)\",\"level\":\"success\"}}";
            res.set_header("HX-Trigger", trigger_msg);
            res.set_content(
                nlohmann::json({{"command_id", command_id}, {"agents_reached", sent}, {"definition_id", def_id}}).dump(),
                "application/json");
        });

    // -- Product Pack API (Phase 7) -------------------------------------------

    // GET /api/product-packs -- list installed product packs
    svr.Get("/api/product-packs",
        [perm_fn, product_pack_store](const httplib::Request& req, httplib::Response& res) {
            if (!perm_fn(req, res, "ProductPack", "Read"))
                return;
            if (!product_pack_store || !product_pack_store->is_open()) {
                res.status = 503;
                res.set_content(R"({"error":{"code":503,"message":"product pack store not available"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }

            ProductPackQuery q;
            if (req.has_param("name"))
                q.name_filter = req.get_param_value("name");
            try {
                if (req.has_param("limit"))
                    q.limit = std::stoi(req.get_param_value("limit"));
            } catch (const std::exception&) {
                res.status = 400;
                res.set_content(R"({"error":{"code":400,"message":"invalid numeric query parameter"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }

            auto packs = product_pack_store->list(q);
            nlohmann::json arr = nlohmann::json::array();
            for (const auto& p : packs) {
                nlohmann::json items_arr = nlohmann::json::array();
                for (const auto& item : p.items) {
                    items_arr.push_back({{"kind", item.kind},
                                         {"item_id", item.item_id},
                                         {"name", item.name}});
                }
                arr.push_back({{"id", p.id},
                               {"name", p.name},
                               {"version", p.version},
                               {"description", p.description},
                               {"item_count", p.items.size()},
                               {"items", items_arr},
                               {"installed_at", p.installed_at},
                               {"verified", p.verified}});
            }
            res.set_content(
                nlohmann::json({{"product_packs", arr}, {"count", arr.size()}}).dump(),
                "application/json");
        });

    // POST /api/product-packs -- install product pack from YAML bundle
    svr.Post("/api/product-packs",
        [perm_fn, audit_fn, emit_fn, product_pack_store, instruction_store, policy_store,
         workflow_engine](const httplib::Request& req, httplib::Response& res) {
            if (!perm_fn(req, res, "ProductPack", "Write"))
                return;
            if (!product_pack_store || !product_pack_store->is_open()) {
                res.status = 503;
                res.set_content(R"({"error":{"code":503,"message":"product pack store not available"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }

            std::string yaml_bundle;
            if (req.get_header_value("Content-Type").find("application/json") != std::string::npos) {
                try {
                    auto j = nlohmann::json::parse(req.body);
                    yaml_bundle = j.value("yaml_source", "");
                } catch (const std::exception& e) {
                    res.status = 400;
                    res.set_content(nlohmann::json({{"error", e.what()}}).dump(), "application/json");
                    return;
                }
            } else {
                yaml_bundle = req.body;
            }

            // Install callback: delegate each document to the appropriate store
            auto install_fn = [instruction_store, policy_store, workflow_engine](
                                  const std::string& kind,
                                  const std::string& yaml_source)
                -> std::expected<std::string, std::string> {
                if (kind == "InstructionDefinition") {
                    if (!instruction_store || !instruction_store->is_open())
                        return std::unexpected("instruction store not available");
                    // Parse YAML into InstructionDefinition and create
                    InstructionDefinition def;
                    def.name = ProductPackStore::extract_yaml_value(yaml_source, "displayName");
                    if (def.name.empty())
                        def.name = ProductPackStore::extract_yaml_value(yaml_source, "name");
                    def.version = ProductPackStore::extract_yaml_value(yaml_source, "version");
                    if (def.version.empty()) def.version = "1.0.0";
                    def.type = ProductPackStore::extract_yaml_value(yaml_source, "type");
                    if (def.type.empty()) def.type = "question";
                    def.plugin = ProductPackStore::extract_yaml_value(yaml_source, "plugin");
                    def.action = ProductPackStore::extract_yaml_value(yaml_source, "action");
                    def.description = ProductPackStore::extract_yaml_value(yaml_source, "description");
                    def.yaml_source = yaml_source;
                    def.platforms = ProductPackStore::extract_yaml_value(yaml_source, "platforms");
                    def.approval_mode = ProductPackStore::extract_yaml_value(yaml_source, "mode");
                    if (def.approval_mode.empty()) def.approval_mode = "auto";
                    return instruction_store->create_definition(def);
                } else if (kind == "PolicyFragment") {
                    if (!policy_store || !policy_store->is_open())
                        return std::unexpected("policy store not available");
                    return policy_store->create_fragment(yaml_source);
                } else if (kind == "Policy") {
                    if (!policy_store || !policy_store->is_open())
                        return std::unexpected("policy store not available");
                    return policy_store->create_policy(yaml_source);
                } else if (kind == "Workflow") {
                    if (!workflow_engine || !workflow_engine->is_open())
                        return std::unexpected("workflow engine not available");
                    return workflow_engine->create_workflow(yaml_source);
                } else {
                    return std::unexpected("unsupported kind: " + kind);
                }
            };

            auto result = product_pack_store->install(yaml_bundle, install_fn);
            if (!result) {
                res.status = 400;
                res.set_content(nlohmann::json({{"error", result.error()}}).dump(), "application/json");
                return;
            }
            audit_fn(req, "product_pack.install", "success", "product_pack", *result, "");
            emit_fn("product_pack.installed", req);
            res.set_header("HX-Trigger",
                R"({"showToast":{"message":"Product pack installed","level":"success"}})");
            res.status = 201;
            res.set_content(nlohmann::json({{"id", *result}, {"status", "installed"}}).dump(),
                            "application/json");
        });

    // GET /api/product-packs/:id -- get product pack detail
    svr.Get(R"(/api/product-packs/([^/]+))",
        [perm_fn, product_pack_store](const httplib::Request& req, httplib::Response& res) {
            if (!perm_fn(req, res, "ProductPack", "Read"))
                return;
            if (!product_pack_store) {
                res.status = 503;
                res.set_content(R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }

            auto id = req.matches[1].str();
            auto pack = product_pack_store->get(id);
            if (!pack) {
                res.status = 404;
                res.set_content(R"({"error":{"code":404,"message":"product pack not found"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }

            nlohmann::json items_arr = nlohmann::json::array();
            for (const auto& item : pack->items) {
                items_arr.push_back({{"kind", item.kind},
                                     {"item_id", item.item_id},
                                     {"name", item.name},
                                     {"yaml_source", item.yaml_source}});
            }

            res.set_content(
                nlohmann::json({{"id", pack->id},
                                {"name", pack->name},
                                {"version", pack->version},
                                {"description", pack->description},
                                {"yaml_source", pack->yaml_source},
                                {"items", items_arr},
                                {"installed_at", pack->installed_at},
                                {"verified", pack->verified}})
                    .dump(),
                "application/json");
        });

    // DELETE /api/product-packs/:id -- uninstall product pack
    svr.Delete(R"(/api/product-packs/([^/]+))",
        [perm_fn, audit_fn, emit_fn, product_pack_store, instruction_store, policy_store,
         workflow_engine](const httplib::Request& req, httplib::Response& res) {
            if (!perm_fn(req, res, "ProductPack", "Delete"))
                return;
            if (!product_pack_store) {
                res.status = 503;
                res.set_content(R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }

            auto id = req.matches[1].str();

            // Uninstall callback: delegate to the appropriate store
            auto uninstall_fn = [instruction_store, policy_store, workflow_engine](
                                    const std::string& kind,
                                    const std::string& item_id) -> bool {
                if (kind == "InstructionDefinition") {
                    return instruction_store && instruction_store->delete_definition(item_id);
                } else if (kind == "PolicyFragment") {
                    return policy_store && policy_store->delete_fragment(item_id);
                } else if (kind == "Policy") {
                    return policy_store && policy_store->delete_policy(item_id);
                } else if (kind == "Workflow") {
                    return workflow_engine && workflow_engine->delete_workflow(item_id);
                }
                return false;
            };

            auto result = product_pack_store->uninstall(id, uninstall_fn);
            if (!result) {
                res.status = 400;
                res.set_content(nlohmann::json({{"error", result.error()}}).dump(), "application/json");
                return;
            }
            audit_fn(req, "product_pack.uninstall", "success", "product_pack", id, "");
            emit_fn("product_pack.uninstalled", req);
            res.set_header("HX-Trigger",
                R"({"showToast":{"message":"Product pack uninstalled","level":"success"}})");
            res.set_content(R"({"status":"uninstalled"})", "application/json");
        });
}

} // namespace yuzu::server
