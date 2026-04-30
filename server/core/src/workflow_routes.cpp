#include "workflow_routes.hpp"

#include "compliance_eval.hpp"
#include "http_route_sink.hpp"
#include "scope_engine.hpp"
#include "web_utils.hpp"

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <expected>
#include <format>
#include <map>
#include <string>
#include <unordered_map>
#include <vector>

namespace yuzu::server {

// Production overload — wraps the Server in an HttplibRouteSink and forwards
// to the sink-based body. Defined first so callers see a familiar signature.
void WorkflowRoutes::register_routes(
    httplib::Server& svr, AuthFn auth_fn, PermFn perm_fn, AuditFn audit_fn,
    EmitEventFn emit_fn, ScopeEstimateFn scope_fn,
    WorkflowEngine* workflow_engine,
    ExecutionTracker* execution_tracker,
    ScheduleEngine* schedule_engine,
    ProductPackStore* product_pack_store,
    InstructionStore* instruction_store,
    PolicyStore* policy_store,
    CommandDispatchFn command_dispatch_fn,
    ApprovalManager* approval_manager,
    ResponseStore* response_store) {
    HttplibRouteSink sink(svr);
    register_routes(sink, std::move(auth_fn), std::move(perm_fn), std::move(audit_fn),
                    std::move(emit_fn), std::move(scope_fn), workflow_engine,
                    execution_tracker, schedule_engine, product_pack_store,
                    instruction_store, policy_store, std::move(command_dispatch_fn),
                    approval_manager, response_store);
}

// Sink-based body — every route registration goes through `sink`, not `svr`,
// so the in-process TestRouteSink can capture handlers and dispatch synthesised
// requests against them without standing up an httplib::Server (#438).
void WorkflowRoutes::register_routes(
    HttpRouteSink& sink, AuthFn auth_fn, PermFn perm_fn, AuditFn audit_fn,
    EmitEventFn emit_fn, ScopeEstimateFn scope_fn,
    WorkflowEngine* workflow_engine,
    ExecutionTracker* execution_tracker,
    ScheduleEngine* schedule_engine,
    ProductPackStore* product_pack_store,
    InstructionStore* instruction_store,
    PolicyStore* policy_store,
    CommandDispatchFn command_dispatch_fn,
    ApprovalManager* approval_manager,
    ResponseStore* response_store) {

    auto cmd_dispatch = std::move(command_dispatch_fn);

    // -- HTMX fragments --------------------------------------------------------

    // GET /fragments/executions -- execution history HTMX fragment.
    //
    // Information design:
    //   - Status icon + .exec-row--{class} carries the headline pre-attentively;
    //     failed rows get a red left-border stripe so the eye finds them without
    //     re-sorting.
    //   - Fan-out is encoded as a 4-segment SVG sparkbar (succeeded / failed /
    //     pending / running). Length = count, hue = status. See
    //     `render_status_sparkbar` for the rounding-safe renderer.
    //   - Time renders as a coarse "3m ago" string; ISO-8601 UTC lives in the
    //     cell title= for forensic copy/paste. Mixed-timezone display is a
    //     known failure mode.
    //   - For failed rows we show a 1-line truncation (UTF-8-safe, 80 chars)
    //     of the most recent agent error_detail, populated via correlated
    //     subquery in `query_executions` so there is no N×M lookup.
    //   - Each row carries `hx-trigger="click once"` so the detail fragment is
    //     fetched at most once per row; subsequent clicks toggle visibility.
    //
    // The optional `definition_id` query param filters the list to one
    // definition. Click-handling on the trend sparkline (PR 4) and the
    // dashboard's per-instruction detail page (future) pass it through.
    sink.Get("/fragments/executions",
        [auth_fn, perm_fn, execution_tracker, instruction_store](const httplib::Request& req,
                                                                  httplib::Response& res) {
            auto session = auth_fn(req, res);
            if (!session)
                return;
            // sec-M1: Execution:Read gate. The LIST exposes definition_name
            // and last_error_detail (per-agent error preview) — same data
            // class as the DETAIL handler, so it earns the same RBAC gate.
            // Mirrors MCP list_executions and REST /api/v1/execution-statistics.
            if (!perm_fn(req, res, "Execution", "Read"))
                return;
            if (!execution_tracker) {
                res.set_content("<div class=\"empty-state\">Not available</div>", "text/html");
                return;
            }

            ExecutionQuery q;
            q.limit = 50;
            // Only the LIST fragment renders last_error_detail inline; opt
            // into the correlated subquery here. Other consumers (health
            // probes, metrics ticks at server.cpp:1727) leave the default
            // false and pay zero subquery cost (arch-B2 / perf-B1).
            q.include_error_detail = true;
            if (req.has_param("definition_id")) {
                q.definition_id = req.get_param_value("definition_id");
            }
            auto execs = execution_tracker->query_executions(q);
            std::string html;
            if (execs.empty()) {
                html = "<div class=\"empty-state\">No executions yet.</div>";
                res.set_content(html, "text/html; charset=utf-8");
                return;
            }

            const int64_t now = now_epoch_seconds();
            html = "<table class=\"exec-table\"><thead><tr>"
                   "<th>Status</th>"
                   "<th>Definition</th>"
                   "<th>Fan-out</th>"
                   "<th>Agents</th>"
                   "<th>Result preview</th>"
                   "<th>Dispatched by</th>"
                   "<th>Time</th>"
                   "</tr></thead><tbody>";

            for (const auto& e : execs) {
                // Status hue + row stripe.
                std::string row_class = "exec-row exec-row--" + e.status;
                std::string status_cls = "status-" + e.status;

                // Fan-out counts. The list-view bar shows succeeded / failed /
                // pending — running is folded into pending here because
                // agents_responded only counts terminal statuses; PR 1.4's
                // detail drawer queries per-agent statuses and shows the full
                // 4-bucket breakdown.
                int succeeded = e.agents_success;
                int failed = e.agents_failure;
                int responded = e.agents_responded;
                int targeted = e.agents_targeted;
                int pending = targeted > responded ? (targeted - responded) : 0;
                int running = 0; // distinguishable only in the detail drawer

                // Definition name (or fallback to truncated id).
                std::string def_label;
                std::string def_title;
                if (instruction_store && instruction_store->is_open() &&
                    !e.definition_id.empty()) {
                    auto def = instruction_store->get_definition(e.definition_id);
                    if (def && !def->name.empty()) {
                        def_label = def->name;
                        def_title = e.definition_id;
                    }
                }
                if (def_label.empty()) {
                    def_label = e.definition_id.empty()
                                    ? std::string{"<unknown>"}
                                    : e.definition_id.substr(0, 12);
                    def_title = e.definition_id;
                }

                std::string first_error;
                if (failed > 0 && !e.last_error_detail.empty()) {
                    first_error = truncate_utf8(e.last_error_detail, 80);
                }

                std::string time_iso = format_iso_utc(e.dispatched_at);
                std::string time_rel = format_relative_time(e.dispatched_at, now);

                html += "<tr class=\"" + row_class +
                        "\" tabindex=\"0\" "
                        "onclick=\"toggleExecDetail(this)\" "
                        "onkeydown=\"if(event.key==='Enter'||event.key===' ')"
                        "{event.preventDefault();toggleExecDetail(this);}\" "
                        "hx-get=\"/fragments/executions/" +
                        html_escape(e.id) +
                        "/detail\" "
                        "hx-target=\"next .exec-detail-content\" "
                        "hx-trigger=\"click once\" "
                        "hx-swap=\"innerHTML\">";
                html += "<td><span class=\"status-badge " + status_cls + "\">" +
                        html_escape(e.status) + "</span></td>";
                html += "<td><span class=\"exec-def-name\" title=\"" +
                        html_escape(def_title) + "\">" + html_escape(def_label) +
                        "</span></td>";
                html += "<td>" + render_status_sparkbar(succeeded, failed, running, pending) +
                        "</td>";
                html += "<td class=\"exec-agent-count\">" + std::to_string(succeeded) + "/" +
                        std::to_string(failed) + " of " + std::to_string(targeted) + "</td>";
                html += "<td class=\"exec-error-preview\" title=\"" +
                        html_escape(e.last_error_detail) + "\">" + html_escape(first_error) +
                        "</td>";
                html += "<td>" + html_escape(e.dispatched_by) + "</td>";
                html += "<td class=\"exec-time\" title=\"" + html_escape(time_iso) + "\">" +
                        html_escape(time_rel) + "</td>";
                html += "</tr>";

                // Empty drawer placeholder; HTMX targets the inner div on first
                // click. CSS hides this row until JS toggles `.exec-detail.open`.
                html += "<tr class=\"exec-detail\"><td colspan=\"7\">"
                        "<div class=\"exec-detail-content\">"
                        "<div class=\"empty-state\">Loading…</div>"
                        "</div></td></tr>";
            }
            html += "</tbody></table>";
            res.set_content(html, "text/html; charset=utf-8");
        });

    // GET /fragments/executions/{id}/detail -- per-execution detail drawer.
    //
    // Information design:
    //   - KPI strip (top): Total, Succeeded, Failed, p50, p95 — primary scan
    //     target. p50/p95 fall back to "—" if any agent is still running.
    //   - Agent grid: one CSS-grid cell per agent, colored by status. Small
    //     multiples for fan-out — discloses cluster-of-failures patterns that
    //     a 200-row table never could. Bucketed into deciles when fan-out
    //     exceeds 1024 to keep the DOM tractable.
    //   - Per-agent table: failed-first, then duration DESC. Inline
    //     server-rendered horizontal duration bars scaled to the slowest
    //     agent in this run so tail-latency outliers pop visually.
    //   - Responses: collapsed by default (<details>) so opening a drawer
    //     doesn't dump 500 rows. Long output rows collapse individually.
    //   - Sidebar: definition + scope + parameters + dispatched_by/at —
    //     reference data, not scan data.
    //
    // RBAC: Read on Execution. Same securable as MCP `get_execution_status`.
    // Correlation with responses uses the timestamp+agent join (PR 2 swaps
    // to exact `execution_id` correlation transparently).
    sink.Get(R"(/fragments/executions/([A-Za-z0-9_-]{1,128})/detail)",
        [auth_fn, perm_fn, audit_fn, execution_tracker, instruction_store,
         response_store](const httplib::Request& req, httplib::Response& res) {
            auto session = auth_fn(req, res);
            if (!session)
                return;
            if (!perm_fn(req, res, "Execution", "Read"))
                return;
            if (!execution_tracker) {
                res.status = 503;
                res.set_content("<div class=\"empty-state\">Tracker not available</div>",
                                "text/html; charset=utf-8");
                return;
            }
            auto exec_id = req.matches[1].str();
            auto exec_opt = execution_tracker->get_execution(exec_id);
            if (!exec_opt) {
                res.status = 404;
                res.set_content("<div class=\"empty-state\">Execution not found</div>",
                                "text/html; charset=utf-8");
                return;
            }
            const auto& exec = *exec_opt;
            auto agents = execution_tracker->get_agent_statuses(exec_id);

            // -- Definition lookup -------------------------------------------
            std::string def_name = exec.definition_id;
            if (instruction_store && instruction_store->is_open() &&
                !exec.definition_id.empty()) {
                if (auto def = instruction_store->get_definition(exec.definition_id);
                    def && !def->name.empty()) {
                    def_name = def->name;
                }
            }

            // -- Per-agent metrics: bucket counts + duration vector ----------
            int succeeded = 0, failed = 0, running = 0, pending = 0;
            int64_t max_dur_ms = 0;
            std::vector<int64_t> durations_ms;
            durations_ms.reserve(agents.size());
            bool any_running = false;
            for (const auto& a : agents) {
                if (a.status == "success") ++succeeded;
                else if (a.status == "failure" || a.status == "timeout" ||
                         a.status == "rejected") ++failed;
                else if (a.status == "running") { ++running; any_running = true; }
                else ++pending;

                int64_t dispatched = a.dispatched_at;
                int64_t completed = a.completed_at;
                if (dispatched > 0 && completed > dispatched) {
                    int64_t dur = (completed - dispatched) * 1000; // → ms
                    durations_ms.push_back(dur);
                    if (dur > max_dur_ms) max_dur_ms = dur;
                }
            }

            // -- KPI strip ---------------------------------------------------
            // Sort once; both p50 and p95 index into the same sorted vector
            // (perf-B2 / cpp-S3). Empty when any agent is still running, the
            // sentinel branch in fmt_pct returns "—" without a sort.
            std::vector<int64_t> sorted_durations;
            if (!any_running && !durations_ms.empty()) {
                sorted_durations = durations_ms;
                std::sort(sorted_durations.begin(), sorted_durations.end());
            }
            auto fmt_pct = [&](double p) -> std::string {
                if (sorted_durations.empty()) return std::string{"—"};
                std::size_t idx = static_cast<std::size_t>(
                    p * (sorted_durations.size() - 1));
                if (idx >= sorted_durations.size()) idx = sorted_durations.size() - 1;
                int64_t v = sorted_durations[idx];
                if (v < 1000) return std::format("{} ms", v);
                if (v < 60000) return std::format("{:.1f} s", v / 1000.0);
                return std::format("{}m {}s", v / 60000, (v % 60000) / 1000);
            };

            std::string html;
            html.reserve(8192);
            html += "<div class=\"exec-detail-grid\">";

            // KPI strip
            html += "<div class=\"exec-kpi-strip\">";
            html += std::format(
                "<div class=\"exec-kpi\"><div class=\"exec-kpi-value\">{}</div>"
                "<div class=\"exec-kpi-label\">Total</div></div>",
                exec.agents_targeted);
            html += std::format(
                "<div class=\"exec-kpi\"><div class=\"exec-kpi-value exec-kpi-value--ok\">{}</div>"
                "<div class=\"exec-kpi-label\">Succeeded</div></div>",
                succeeded);
            html += std::format(
                "<div class=\"exec-kpi\"><div class=\"exec-kpi-value exec-kpi-value--err\">{}</div>"
                "<div class=\"exec-kpi-label\">Failed</div></div>",
                failed);
            html += std::format(
                "<div class=\"exec-kpi\"><div class=\"exec-kpi-value\">{}</div>"
                "<div class=\"exec-kpi-label\">p50 duration</div></div>",
                fmt_pct(0.5));
            html += std::format(
                "<div class=\"exec-kpi\"><div class=\"exec-kpi-value\">{}</div>"
                "<div class=\"exec-kpi-label\">p95 duration</div></div>",
                fmt_pct(0.95));
            html += "</div>";

            // -- Agent grid (small multiples) -------------------------------
            html += "<div class=\"agent-grid-wrap\">";
            html += "<h4>Agent fan-out</h4>";
            html += "<div class=\"agent-grid\" id=\"agent-grid-" + html_escape(exec.id) +
                    "\">";

            constexpr std::size_t kBucketThreshold = 1024;
            if (agents.size() > kBucketThreshold) {
                // Decile bucketing — render 10 buckets per status.
                // Keeps DOM bounded for huge fan-outs while preserving the
                // proportional-area read.
                struct Bucket { int succeeded{0}, failed{0}, running{0}, pending{0}; };
                Bucket buckets[10] = {};
                for (std::size_t i = 0; i < agents.size(); ++i) {
                    std::size_t b = i * 10 / agents.size();
                    if (b >= 10) b = 9;
                    const auto& a = agents[i];
                    if (a.status == "success") ++buckets[b].succeeded;
                    else if (a.status == "failure" || a.status == "timeout" ||
                             a.status == "rejected") ++buckets[b].failed;
                    else if (a.status == "running") ++buckets[b].running;
                    else ++buckets[b].pending;
                }
                for (int i = 0; i < 10; ++i) {
                    const auto& b = buckets[i];
                    int total = b.succeeded + b.failed + b.running + b.pending;
                    const char* dom_status =
                        b.failed > 0 ? "failed"
                                     : b.running > 0 ? "running"
                                                     : b.pending > b.succeeded ? "pending"
                                                                                : "succeeded";
                    auto label = std::format(
                        "Decile {}: {} succeeded / {} failed / {} running / {} pending",
                        i + 1, b.succeeded, b.failed, b.running, b.pending);
                    html += std::format(
                        "<div class=\"agent-cell agent-cell--bucket agent-cell--{}\" "
                        "title=\"{}\" aria-label=\"{}\">{}</div>",
                        dom_status, html_escape(label), html_escape(label), total);
                }
            } else {
                for (const auto& a : agents) {
                    std::string dom_status;
                    if (a.status == "success") dom_status = "succeeded";
                    else if (a.status == "failure" || a.status == "timeout" ||
                             a.status == "rejected") dom_status = "failed";
                    else if (a.status == "running") dom_status = "running";
                    else dom_status = "pending";

                    int64_t dur_ms = 0;
                    if (a.dispatched_at > 0 && a.completed_at > a.dispatched_at) {
                        dur_ms = (a.completed_at - a.dispatched_at) * 1000;
                    }
                    auto title = std::format("{} · {} · {} ms",
                                              a.agent_id, a.status, dur_ms);
                    // Bind agent_id and exec_id via data-* attributes rather
                    // than interpolating into a JS string literal in an
                    // onclick handler. html_escape converts ' to &#39; which
                    // the HTML parser un-escapes BEFORE the JS lexer sees the
                    // attribute value, so a single quote in agent_id would
                    // terminate the JS literal and inject (UP-1). agent_id is
                    // wire-provided by the agent on Register and is not yet
                    // schema-validated. data-attribute + delegated listener
                    // in instruction_ui.cpp keeps the user-controlled bytes
                    // out of any JS-string context.
                    html += std::format(
                        "<div class=\"agent-cell agent-cell--{}\" "
                        "title=\"{}\" aria-label=\"{}\" "
                        "data-agent-id=\"{}\" data-exec-id=\"{}\"></div>",
                        dom_status, html_escape(title), html_escape(title),
                        html_escape(a.agent_id), html_escape(exec.id));
                }
            }
            html += "</div></div>"; // agent-grid + agent-grid-wrap

            // -- Per-agent table (failed first, then duration DESC) ----------
            html += "<div class=\"per-agent-table-wrap\">";
            html += "<h4>Agent results</h4>";
            html += "<table class=\"per-agent-table\"><thead><tr>"
                    "<th>Agent</th><th>Status</th><th>Exit</th><th>Duration</th>"
                    "<th>Error</th></tr></thead><tbody>";

            std::vector<AgentExecStatus> sorted_agents = agents;
            std::sort(sorted_agents.begin(), sorted_agents.end(),
                      [](const AgentExecStatus& l, const AgentExecStatus& r) {
                          auto rank = [](const std::string& s) {
                              if (s == "failure" || s == "timeout" || s == "rejected") return 0;
                              if (s == "running") return 1;
                              if (s == "pending") return 2;
                              return 3; // success last
                          };
                          int rl = rank(l.status), rr = rank(r.status);
                          if (rl != rr) return rl < rr;
                          int64_t dl = (l.dispatched_at > 0 && l.completed_at > l.dispatched_at)
                                            ? (l.completed_at - l.dispatched_at) : -1;
                          int64_t dr = (r.dispatched_at > 0 && r.completed_at > r.dispatched_at)
                                            ? (r.completed_at - r.dispatched_at) : -1;
                          return dl > dr;
                      });

            for (const auto& a : sorted_agents) {
                std::string dom_status;
                std::string status_cls = "status-" + a.status;
                if (a.status == "success") dom_status = "succeeded";
                else if (a.status == "failure" || a.status == "timeout" ||
                         a.status == "rejected") dom_status = "failed";
                else if (a.status == "running") dom_status = "running";
                else dom_status = "pending";

                int64_t dur_ms = 0;
                if (a.dispatched_at > 0 && a.completed_at > a.dispatched_at) {
                    dur_ms = (a.completed_at - a.dispatched_at) * 1000;
                }
                auto err_short = truncate_utf8(a.error_detail, 120);

                // data-* attributes (not id=) are the binding contract for
                // the agent-grid → row scroll. The legacy id is kept for any
                // future deep-link case but the click handler in
                // instruction_ui.cpp matches via getAttribute('data-agent-id')
                // so dash-in-id collisions (UP-19) cannot occur.
                html += std::format(
                    "<tr id=\"per-agent-row-{}-{}\" "
                    "data-exec-id=\"{}\" data-agent-id=\"{}\">"
                    "<td><code>{}</code></td>",
                    html_escape(exec.id), html_escape(a.agent_id),
                    html_escape(exec.id), html_escape(a.agent_id),
                    html_escape(a.agent_id));
                html += "<td><span class=\"status-badge " + status_cls + "\">" +
                        html_escape(a.status) + "</span></td>";
                html += "<td>" + std::to_string(a.exit_code) + "</td>";
                html += "<td>" + render_duration_bar_html(dur_ms, max_dur_ms, dom_status) +
                        std::format(" <span class=\"duration-text\">{} ms</span>", dur_ms) +
                        "</td>";
                html += "<td title=\"" + html_escape(a.error_detail) + "\">" +
                        html_escape(err_short) + "</td></tr>";
            }
            html += "</tbody></table></div>";

            // -- Responses (collapsed) ---------------------------------------
            html += "<div class=\"per-agent-responses-wrap\">";
            if (response_store && response_store->is_open()) {
                ResponseQuery rq;
                rq.since = exec.dispatched_at;
                rq.until = exec.completed_at > 0 ? exec.completed_at : now_epoch_seconds();
                rq.limit = 500;
                auto responses = response_store->query(exec.definition_id, rq);
                // Filter to agents that appear in this execution's status set.
                std::unordered_map<std::string, bool> in_set;
                in_set.reserve(agents.size());
                for (const auto& a : agents) in_set[a.agent_id] = true;
                std::vector<StoredResponse> filtered;
                filtered.reserve(responses.size());
                for (auto& r : responses) {
                    if (in_set.count(r.agent_id))
                        filtered.push_back(std::move(r));
                }

                html += std::format(
                    "<details class=\"per-agent-responses\">"
                    "<summary>Show responses ({})</summary>",
                    filtered.size());
                if (filtered.empty()) {
                    html += "<div class=\"empty-state\">No responses recorded.</div>";
                } else {
                    html += "<table class=\"per-agent-responses-table\"><thead><tr>"
                            "<th>Agent</th><th>Time</th><th>Status</th><th>Output</th>"
                            "<th>Error</th></tr></thead><tbody>";
                    for (const auto& r : filtered) {
                        html += "<tr><td><code>" + html_escape(r.agent_id) + "</code></td>";
                        html += "<td title=\"" + format_iso_utc(r.timestamp) + "\">" +
                                format_iso_utc(r.timestamp) + "</td>";
                        html += "<td>" + std::to_string(r.status) + "</td>";
                        html += "<td><details class=\"resp-output\"><summary>output</summary>"
                                "<pre>" + html_escape(r.output) + "</pre></details></td>";
                        html += "<td>" + html_escape(r.error_detail) + "</td></tr>";
                    }
                    html += "</tbody></table>";
                }
                html += "</details>";
            } else {
                html += "<div class=\"empty-state\">Response store not available.</div>";
            }
            html += "</div>";

            // -- Sidebar metadata --------------------------------------------
            html += "<aside class=\"exec-detail-sidebar\">";
            html += "<h4>Definition</h4><div>" + html_escape(def_name) + "</div>"
                    "<div class=\"exec-detail-meta-id\"><code>" +
                    html_escape(exec.definition_id) + "</code></div>";
            html += "<h4>Dispatched by</h4><div>" + html_escape(exec.dispatched_by) +
                    "</div>";
            html += "<h4>Dispatched at</h4><div>" + html_escape(format_iso_utc(exec.dispatched_at)) +
                    "</div>";
            html += "<h4>Completed at</h4><div>" + html_escape(format_iso_utc(exec.completed_at)) +
                    "</div>";
            if (!exec.scope_expression.empty()) {
                html += "<h4>Scope</h4><code class=\"exec-detail-scope\">" +
                        html_escape(exec.scope_expression) + "</code>";
            }
            if (!exec.parameter_values.empty()) {
                html += "<h4>Parameters</h4><pre class=\"exec-detail-params\">" +
                        html_escape(exec.parameter_values) + "</pre>";
            }
            html += "</aside>";

            html += "</div>"; // exec-detail-grid
            res.set_content(html, "text/html; charset=utf-8");

            // sec-M2: emit audit on the forensic-data read so SOC 2 can
            // answer "who viewed execution X's per-agent error data and
            // parameters between dates A and B?". Mirrors MCP
            // get_execution_status's audit pattern. The LIST handler
            // intentionally does not audit per the documented fragment-route
            // policy (only routes returning forensic-grade content audit).
            audit_fn(req, "execution.detail.view", "success", "Execution",
                     exec.id, "");
        });

    // GET /fragments/schedules -- schedule list HTMX fragment
    sink.Get("/fragments/schedules",
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
    sink.Post("/api/scope/estimate",
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
    sink.Get("/api/workflows",
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
    sink.Post("/api/workflows",
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
                } catch (const std::exception&) {
                    res.status = 400;
                    res.set_content(R"({"error":{"code":400,"message":"invalid request body"},"meta":{"api_version":"v1"}})", "application/json");
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
    sink.Get(R"(/api/workflows/([^/]+))",
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
    sink.Delete(R"(/api/workflows/([^/]+))",
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
    sink.Post(R"(/api/workflows/([^/]+)/execute)",
        [auth_fn, perm_fn, audit_fn, emit_fn, workflow_engine, instruction_store,
         cmd_dispatch, approval_manager](const httplib::Request& req, httplib::Response& res) {
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
            } catch (const std::exception&) {
                res.status = 400;
                res.set_content(R"({"error":{"code":400,"message":"invalid request body"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }

            if (agent_ids.empty()) {
                res.status = 400;
                res.set_content(R"({"error":{"code":400,"message":"agent_ids array is required"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }

            // --- Pre-validate approval gates on all workflow steps ---------------
            // If any instruction in the workflow requires approval, reject the
            // entire execution rather than allowing partial bypass.
            if (approval_manager && instruction_store && instruction_store->is_open()) {
                auto workflow = workflow_engine->get_workflow(workflow_id);
                if (workflow) {
                    auto session = auth_fn(req, res);
                    if (!session)
                        return;
                    for (const auto& step : workflow->steps) {
                        auto step_def = instruction_store->get_definition(step.instruction_id);
                        if (!step_def) {
                            res.status = 400;
                            res.set_content(
                                nlohmann::json({{"error", {{"code", 400},
                                    {"message", "workflow step '" + step.label +
                                     "' references unknown instruction: " +
                                     step.instruction_id}}},
                                    {"meta", {{"api_version", "v1"}}}}).dump(),
                                "application/json");
                            return;
                        }
                        if (step_def->approval_mode == "auto")
                            continue;
                        bool blocked = false;
                        if (step_def->approval_mode == "always") {
                            blocked = true;
                        } else if (step_def->approval_mode == "role-gated") {
                            blocked = (session->role != auth::Role::admin);
                        } else {
                            blocked = true; // unknown mode — fail closed
                        }
                        if (blocked) {
                            res.status = 403;
                            res.set_content(
                                nlohmann::json({{"error", {{"code", 403},
                                    {"message", "workflow step '" + step.label +
                                     "' references instruction '" + step.instruction_id +
                                     "' which requires approval (mode: " +
                                     step_def->approval_mode +
                                     "). Submit each instruction individually for approval."}}},
                                    {"meta", {{"api_version", "v1"}}}}).dump(),
                                "application/json");
                            return;
                        }
                    }
                }
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
    sink.Get(R"(/api/workflow-executions/([^/]+))",
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
    sink.Post(R"(/api/instructions/([^/]+)/execute)",
        [auth_fn, perm_fn, audit_fn, emit_fn, instruction_store, cmd_dispatch,
         execution_tracker, approval_manager](
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
            } catch (const std::exception&) {
                res.status = 400;
                res.set_content(R"({"error":{"code":400,"message":"invalid request body"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }

            // Resolve the authenticated user once for audit and approval.
            auto session = auth_fn(req, res);
            if (!session)
                return;

            // --- Approval gate ---------------------------------------------------
            // If the definition requires approval and the approval manager is
            // available, create a pending approval instead of dispatching immediately.
            // Unknown approval_mode values are treated as requiring approval
            // (fail-closed) to prevent typos from silently bypassing the gate.
            if (!approval_manager && def->approval_mode != "auto") {
                spdlog::error("instruction '{}' requires approval (mode={}) but "
                              "approval_manager is not available — rejecting execution",
                              def_id, def->approval_mode);
                res.status = 503;
                res.set_content(
                    R"({"error":{"code":503,"message":"approval system unavailable — cannot execute approval-gated instruction"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }
            if (approval_manager && def->approval_mode != "auto") {
                bool needs_approval = false;
                if (def->approval_mode == "always") {
                    needs_approval = true;
                } else if (def->approval_mode == "role-gated") {
                    // role-gated: admins bypass, all others need approval
                    needs_approval = (session->role != auth::Role::admin);
                } else {
                    // Unknown mode — fail closed (require approval)
                    spdlog::warn("instruction '{}' has unrecognized approval_mode '{}' "
                                 "— requiring approval (fail-closed)",
                                 def_id, def->approval_mode);
                    needs_approval = true;
                }

                if (needs_approval) {
                    auto result = approval_manager->submit(
                        def_id, session->username, scope_expr);
                    if (!result) {
                        spdlog::error("approval submit failed for '{}': {}",
                                      def_id, result.error());
                        res.status = 500;
                        res.set_content(
                            R"({"error":{"code":500,"message":"failed to create approval request"},"meta":{"api_version":"v1"}})",
                            "application/json");
                        return;
                    }
                    audit_fn(req, "instruction.approval_required", "pending",
                             "instruction", def_id,
                             "approval_id=" + *result + " mode=" + def->approval_mode);
                    emit_fn("approval.created", req);
                    res.set_header("HX-Trigger",
                        R"({"showToast":{"message":"Approval required — request submitted","level":"warning"}})");
                    res.status = 202;
                    res.set_content(
                        nlohmann::json({{"status", "pending_approval"},
                                        {"approval_id", *result},
                                        {"definition_id", def_id}}).dump(),
                        "application/json");
                    return;
                }
            }

            // Empty agent_ids + empty scope = broadcast to all agents

            // Dispatch
            std::string command_id;
            int sent = 0;
            try {
                std::tie(command_id, sent) = cmd_dispatch(
                    def->plugin, def->action, agent_ids, scope_expr, params);
            } catch (const std::exception& e) {
                spdlog::error("instruction dispatch failed: {}", e.what());
                res.status = 500;
                res.set_content(R"({"error":{"code":500,"message":"dispatch failed"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }

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
                exec.dispatched_by = session->username;
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
    sink.Get("/api/product-packs",
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
    sink.Post("/api/product-packs",
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
                } catch (const std::exception&) {
                    res.status = 400;
                    res.set_content(R"({"error":{"code":400,"message":"invalid request body"},"meta":{"api_version":"v1"}})", "application/json");
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
                    // Normalize action to lowercase — agent plugins match case-sensitively
                    for (auto& c : def.action)
                        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                    def.description = ProductPackStore::extract_yaml_value(yaml_source, "description");
                    def.yaml_source = yaml_source;
                    def.platforms = ProductPackStore::extract_yaml_value(yaml_source, "platforms");
                    def.approval_mode = ProductPackStore::extract_yaml_value(yaml_source, "mode");
                    if (def.approval_mode.empty()) def.approval_mode = "auto";
                    // Validate approval_mode — reject unknown values at creation time
                    if (def.approval_mode != "auto" &&
                        def.approval_mode != "role-gated" &&
                        def.approval_mode != "always") {
                        return std::unexpected("invalid approval mode: " + def.approval_mode +
                                               " (must be auto, role-gated, or always)");
                    }
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
    sink.Get(R"(/api/product-packs/([^/]+))",
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
    sink.Delete(R"(/api/product-packs/([^/]+))",
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
