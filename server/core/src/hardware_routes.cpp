/// @file hardware_routes.cpp
/// /hardware route registration — the page shells + the read-only HTMX fragments +
/// the REST v1 twins (`GET /api/v1/hardware`, `GET /api/v1/hardware/{id}`), all
/// self-registered on the shared `HttpRouteSink` (the preflight_routes.cpp pattern)
/// so this module owns its own REST surface without growing rest_api_v1.cpp's
/// register_routes argument list. Renderers live in hardware_ui.cpp; query/sort/
/// filter/paginate/JSON logic in hardware_list_model.{hpp,cpp}.

#include "hardware_routes.hpp"

#include "authz_model.hpp"          // authz::in_scope
#include "http_route_sink.hpp"
#include "rest_a4_envelope_http.hpp" // detail::a4_error, ensure_correlation_id
#include "rest_audit.hpp"            // detail::emit_behavioral_audit, try_persist_audit

#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <string>

// Shared full-page shell (defined at GLOBAL scope in guardian_page_ui.cpp).
extern const char* const kGuardianDetailPageHtml;

namespace yuzu::server {

namespace {

void send_html(httplib::Response& res, std::string body) {
    res.set_content(std::move(body), "text/html; charset=utf-8");
}

std::string page_shell(const std::string& title, const std::string& fragment_url) {
    std::string html(kGuardianDetailPageHtml);
    auto sub = [&](const std::string& tok, const std::string& val) {
        for (auto p = html.find(tok); p != std::string::npos; p = html.find(tok, p + val.size()))
            html.replace(p, tok.size(), val);
    };
    sub("{{TITLE}}", title);
    sub("{{FRAGMENT}}", fragment_url);
    sub("<a href=\"/guardian\" class=\"nav-link active\">Guardian</a>",
        "<a href=\"/guardian\" class=\"nav-link\">Guardian</a>");
    // The nav-sweep (10 shells) hasn't landed yet at this point in the branch history
    // in a fresh checkout of this file alone — once it has, this activates the real
    // Hardware nav link. Until then this is a silent no-op (the `sub` idiom's own
    // known failure mode), which is exactly why test_nav_shells.cpp pins it.
    sub("<a href=\"/hardware\" class=\"nav-link\">Hardware</a>",
        "<a href=\"/hardware\" class=\"nav-link active\">Hardware</a>");
    return html;
}

std::string url_encode_id(const std::string& s) {
    static const char* kHex = "0123456789ABCDEF";
    std::string out;
    for (unsigned char c : s) {
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' ||
            c == '_' || c == '.' || c == '~') {
            out.push_back(static_cast<char>(c));
        } else {
            out.push_back('%');
            out.push_back(kHex[c >> 4]);
            out.push_back(kHex[c & 0x0f]);
        }
    }
    return out;
}

// Same accepted-character set + length cap as command_routes.cpp's bad_ident
// (that copy is anonymous-namespace/internal linkage, so this file defines its
// own rather than exporting a shared one) — a plugin/action string outside this
// set is refused by POST /api/command before it would ever dispatch, so an
// action row built from one is never offered a Run control (hardware_ui side)
// and a result poll naming one is rejected here too.
bool bad_hw_ident(std::string_view v) {
    constexpr std::size_t kIdentMax = 128;
    if (v.empty() || v.size() > kIdentMax)
        return true;
    return std::any_of(v.begin(), v.end(), [](unsigned char c) {
        return !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                 c == '_' || c == '.' || c == '-');
    });
}

std::int64_t now_secs() {
    return std::chrono::duration_cast<std::chrono::seconds>(
              std::chrono::system_clock::now().time_since_epoch())
        .count();
}

HardwareListQuery query_from_request(const httplib::Request& req) {
    HardwareListQuery q;
    if (req.has_param("q")) q.q = req.get_param_value("q");
    if (req.has_param("os")) q.os = req.get_param_value("os");
    if (req.has_param("status")) q.status = req.get_param_value("status");
    if (req.has_param("sort")) q.sort = req.get_param_value("sort");
    if (req.has_param("dir")) q.desc = req.get_param_value("dir") == "desc";
    auto parse_u = [&](const char* name, std::size_t dflt) -> std::size_t {
        if (!req.has_param(name)) return dflt;
        try {
            long long v = std::stoll(req.get_param_value(name));
            return v < 0 ? 0 : static_cast<std::size_t>(v);
        } catch (...) { return dflt; }
    };
    q.offset = parse_u("offset", 0);
    q.limit = parse_u("limit", 50);
    return q;
}

// Assemble the operator-visible roster: the UNFILTERED roster from RosterFn, scope-
// filtered by the FleetReadGate's own scope (the SOLE filter — never double up with
// a second scope predicate). Returns the filtered roster + the drop count.
std::pair<std::vector<InventoryDeviceRow>, std::size_t>
scoped_roster(const InventoryDevicesResult& all, const authz::VisibleSet& scope) {
    std::vector<InventoryDeviceRow> out;
    std::size_t dropped = 0;
    out.reserve(all.rows.size());
    for (const auto& row : all.rows) {
        if (!authz::in_scope(scope, row.agent_id)) { ++dropped; continue; }
        out.push_back(row);
    }
    return {std::move(out), dropped};
}

} // namespace

void HardwareRoutes::register_routes(httplib::Server& svr, Deps deps) {
    HttplibRouteSink sink(svr);
    register_routes(sink, std::move(deps));
}

void HardwareRoutes::register_routes(HttpRouteSink& sink, Deps deps) {
    deps_ = std::move(deps);

    // -- Page shells (auth-only chrome; fragments carry the real gates) --
    sink.Get("/hardware", [this](const httplib::Request& req, httplib::Response& res) {
        auto session = deps_.auth_fn(req, res);
        if (!session) { res.set_redirect("/login"); return; }
        res.set_header("Cache-Control", "no-cache, no-store, must-revalidate");
        send_html(res, page_shell("Yuzu \xE2\x80\x94 Hardware", "/fragments/hardware/list"));
    });

    sink.Get("/hardware/ci", [this](const httplib::Request& req, httplib::Response& res) {
        auto session = deps_.auth_fn(req, res);
        if (!session) { res.set_redirect("/login"); return; }
        const std::string id = req.has_param("id") ? req.get_param_value("id") : "";
        res.set_header("Cache-Control", "no-cache, no-store, must-revalidate");
        send_html(res, page_shell("Yuzu \xE2\x80\x94 Hardware",
                                  "/fragments/hardware/ci?id=" + url_encode_id(id)));
    });

    // -- Fragment: CI list --
    sink.Get("/fragments/hardware/list", [this](const httplib::Request& req, httplib::Response& res) {
        auto gate = deps_.fleet_read_fn ? deps_.fleet_read_fn(req, res, "Inventory", "Read")
                                       : authz::FleetReadGate{};
        if (!deps_.fleet_read_fn) {
            res.status = 503;
            send_html(res, "<div class=\"gp-placeholder\">Hardware list unavailable on this server.</div>");
            return;
        }
        if (!gate.admitted) return; // response already written by fleet_read_fn

        if (!deps_.roster_fn) {
            (void)detail::try_persist_audit(deps_.audit_fn, req, "inventory.devices", "failure",
                                            "Inventory", "", "hardware roster provider unwired");
            send_html(res, "<div class=\"gp-placeholder\"><b>Hardware roster unavailable.</b> No "
                          "provider is wired on this server.</div>");
            return;
        }
        const InventoryDevicesResult all = deps_.roster_fn();
        auto [scoped, omitted] = scoped_roster(all, gate.scope);

        auto raw = query_from_request(req);
        auto normalised = normalise_hardware_query(raw);
        if (!normalised) {
            res.status = 400;
            send_html(res, "<div class=\"gp-placeholder\"><b>Bad request.</b> Unrecognised sort, "
                          "direction, OS, or status filter.</div>");
            return;
        }
        HardwareListPage page = build_hardware_list_page(std::move(scoped), *normalised);

        const bool persisted = detail::emit_behavioral_audit(
            deps_.audit_fn, req, res, "inventory.devices", "success", "Inventory", "",
            "hardware list: devices=" + std::to_string(page.total_matching) +
                " omitted=" + std::to_string(omitted));
        (void)persisted; // HTML fragment: set-and-proceed — the header is the signal

        send_html(res, render_hardware_list_fragment(page, all.ci_degraded, false));
    });

    // -- Fragment: CI record (overview / installed software / tags lenses) --
    sink.Get("/fragments/hardware/ci", [this](const httplib::Request& req, httplib::Response& res) {
        const std::string id = req.has_param("id") ? req.get_param_value("id") : "";
        if (id.empty()) {
            res.status = 400;
            send_html(res, "<div class=\"gp-placeholder\">Missing device id.</div>");
            return;
        }
        if (!deps_.scoped_perm_fn(req, res, "Inventory", "Read", id)) return;

        const std::string lens = req.has_param("lens") ? req.get_param_value("lens") : "overview";
        if (!deps_.ci_detail_fn) {
            res.status = 503;
            send_html(res, "<div class=\"gp-placeholder\">Hardware CI record unavailable on this "
                          "server.</div>");
            return;
        }
        const HardwareCiDetail detail = deps_.ci_detail_fn(id);

        std::string verb = "inventory.device.ci";
        std::string state = !detail.ci.has_value() ? "store degraded"
                            : !detail.ci->has_value() ? "absent" : "found";
        if (lens == "software") verb = "inventory.device.software";
        (void)detail::emit_behavioral_audit(deps_.audit_fn, req, res, verb, "success", "Agent", id,
                                            "hardware CI lens=" + lens + " state=" + state);

        send_html(res, render_hardware_ci_fragment(id, detail, lens, now_secs()));
    });

    // -- REST v1: GET /api/v1/hardware --
    sink.Get("/api/v1/hardware", [this](const httplib::Request& req, httplib::Response& res) {
        detail::ensure_correlation_id(res);
        if (!deps_.fleet_read_fn) {
            res.status = 503;
            res.set_content(detail::a4_error(res, "hardware service unavailable"), "application/json");
            return;
        }
        auto gate = deps_.fleet_read_fn(req, res, "Inventory", "Read");
        if (!gate.admitted) return;

        if (!deps_.roster_fn) {
            (void)detail::try_persist_audit(deps_.audit_fn, req, "inventory.devices", "failure",
                                            "Inventory", "", "hardware roster provider unwired");
            res.status = 503;
            res.set_content(detail::a4_error(res, "hardware roster unavailable"), "application/json");
            return;
        }
        const InventoryDevicesResult all = deps_.roster_fn();
        auto [scoped, omitted] = scoped_roster(all, gate.scope);

        auto raw = query_from_request(req);
        auto normalised = normalise_hardware_query(raw);
        if (!normalised) {
            res.status = 400;
            res.set_content(detail::a4_error(res, "unrecognised sort, dir, os, or status token"),
                            "application/json");
            return;
        }
        HardwareListPage page = build_hardware_list_page(std::move(scoped), *normalised);

        const bool persisted = detail::emit_behavioral_audit(
            deps_.audit_fn, req, res, "inventory.devices", "success", "Inventory", "",
            "hardware list (REST): devices=" + std::to_string(page.total_matching) +
                " omitted=" + std::to_string(omitted));
        if (!persisted) {
            res.status = 503;
            res.set_content(detail::a4_error(res, "audit subsystem unavailable — request not served",
                                             {.retry_after_ms = 5000}),
                            "application/json");
            return;
        }

        nlohmann::json body = hardware_list_json(page, all.ci_degraded, omitted);
        nlohmann::json out = {
            {"data", body},
            {"pagination", {{"total", page.total_matching}, {"start", page.query.offset},
                            {"page_size", page.query.limit}}},
            {"meta", {{"api_version", "v1"}}},
        };
        res.set_content(out.dump(), "application/json");
    });

    // -- REST v1: GET /api/v1/hardware/{id} --
    sink.Get(R"(/api/v1/hardware/([^/]+))", [this](const httplib::Request& req, httplib::Response& res) {
        detail::ensure_correlation_id(res);
        if (!deps_.fleet_read_fn) {
            res.status = 503;
            res.set_content(detail::a4_error(res, "hardware service unavailable"), "application/json");
            return;
        }
        auto gate = deps_.fleet_read_fn(req, res, "Inventory", "Read");
        if (!gate.admitted) return;

        const std::string agent_id = req.matches[1].str();
        if (!authz::in_scope(gate.scope, agent_id)) {
            // Out-of-scope collapses to the same "not found" as a genuinely
            // nonexistent id — the existence-oracle closure `/api/v1/devices/{id}`
            // uses (rest_api_v1.cpp).
            res.status = 404;
            res.set_content(detail::a4_error(res, "not found"), "application/json");
            return;
        }
        if (!deps_.ci_detail_fn) {
            res.status = 503;
            res.set_content(detail::a4_error(res, "hardware CI record unavailable"), "application/json");
            return;
        }
        const HardwareCiDetail detail = deps_.ci_detail_fn(agent_id);
        const bool truly_absent = !detail.identity &&
                                  (!detail.ci.has_value() ? false : !detail.ci->has_value()) &&
                                  (!detail.software || detail.software->empty()) &&
                                  (!detail.tags || detail.tags->empty());
        if (truly_absent) {
            res.status = 404;
            res.set_content(detail::a4_error(res, "not found"), "application/json");
            return;
        }

        std::string state = !detail.ci.has_value() ? "store degraded"
                            : !detail.ci->has_value() ? "absent" : "found";
        const bool persisted = detail::emit_behavioral_audit(
            deps_.audit_fn, req, res, "inventory.device.ci", "success", "Agent", agent_id,
            "hardware CI record (REST) state=" + state);
        if (!persisted) {
            res.status = 503;
            res.set_content(detail::a4_error(res, "audit subsystem unavailable — request not served",
                                             {.retry_after_ms = 5000}),
                            "application/json");
            return;
        }

        nlohmann::json out = {
            {"data", hardware_ci_json(detail, now_secs())},
            {"meta", {{"api_version", "v1"}}},
        };
        res.set_content(out.dump(), "application/json");
    });

    // -- Fragment: Actions lens (the generic action runner catalogue) --
    // Dispatch itself is NOT a route here — the `hwRunAction` JS helper
    // (guardian_page_ui.cpp) posts straight to the EXISTING `POST /api/command`
    // route, so classify/authorize/destructive-gate/audit/executions-tracking all
    // apply with zero duplication, and that route IS the REST twin of "run an
    // action" by construction.
    sink.Get("/fragments/hardware/ci/actions", [this](const httplib::Request& req,
                                                      httplib::Response& res) {
        const std::string id = req.has_param("id") ? req.get_param_value("id") : "";
        if (id.empty()) { res.status = 400; send_html(res, "bad request"); return; }
        if (!deps_.scoped_perm_fn(req, res, "Inventory", "Read", id)) return;

        if (!deps_.exec_probe_fn || !deps_.exec_probe_fn(req, id)) {
            send_html(res, render_hardware_actions_lens(id, id, {}, HwActionsState::NoExecute));
            return;
        }
        if (!deps_.actions_fn) {
            send_html(res, render_hardware_actions_lens(id, id, {}, HwActionsState::Unavailable));
            return;
        }
        auto plugins = deps_.actions_fn(id);
        if (!plugins) {
            send_html(res, render_hardware_actions_lens(id, id, {}, HwActionsState::Offline));
            return;
        }

        const std::string hostname = [&] {
            auto ident = deps_.ci_detail_fn ? deps_.ci_detail_fn(id).identity : std::nullopt;
            return ident && !ident->hostname.empty() ? ident->hostname : id;
        }();

        std::vector<HwActionRow> rows;
        for (const auto& plugin : *plugins) {
            std::unordered_map<std::string, std::string> schemas =
                deps_.schema_fn ? deps_.schema_fn(plugin.name)
                                : std::unordered_map<std::string, std::string>{};
            for (const auto& action : plugin.actions) {
                HwActionRow row;
                row.plugin = plugin.name;
                row.action = action;
                row.bad_ident = bad_hw_ident(plugin.name) || bad_hw_ident(action);
                if (deps_.action_descriptions) {
                    auto it = deps_.action_descriptions->find(plugin.name + "." + action);
                    if (it != deps_.action_descriptions->end())
                        row.description = it->second;
                }
                if (!row.bad_ident && deps_.classify_fn) {
                    auto cap = deps_.classify_fn(plugin.name, action);
                    if (cap) row.cap = *cap;
                    else row.ambiguous = cap.error() == ClassificationError::Ambiguous;
                }
                if (row.cap) {
                    auto s_it = schemas.find(action);
                    if (s_it != schemas.end())
                        row.form = parse_action_form_spec(s_it->second);
                }
                rows.push_back(std::move(row));
            }
        }
        (void)detail::try_persist_audit(deps_.audit_fn, req, "hardware.actions.view", "success",
                                        "Agent", id,
                                        "actions catalogue: " + std::to_string(rows.size()) + " rows");
        send_html(res, render_hardware_actions_lens(id, hostname, rows, HwActionsState::Ready));
    });

    // -- Fragment: dispatch-result poll for the Actions lens --
    sink.Get("/fragments/hardware/ci/result", [this](const httplib::Request& req,
                                                     httplib::Response& res) {
        const std::string id = req.has_param("id") ? req.get_param_value("id") : "";
        const std::string command_id = req.has_param("command_id") ? req.get_param_value("command_id") : "";
        const std::string plugin = req.has_param("plugin") ? req.get_param_value("plugin") : "";
        if (id.empty()) { res.status = 400; send_html(res, "bad request"); return; }
        if (!deps_.scoped_perm_fn(req, res, "Inventory", "Read", id)) return;

        if (bad_hw_ident(plugin) || command_id.size() > 64 ||
            !command_id.starts_with(plugin + "-")) {
            res.status = 400;
            send_html(res, "bad request");
            return;
        }
        int attempt = 1;
        if (req.has_param("n")) {
            try { attempt = std::clamp(std::stoi(req.get_param_value("n")), 1, 50); } catch (...) {}
        }
        if (!deps_.exec_probe_fn || !deps_.exec_probe_fn(req, id)) {
            send_html(res, "<div class=\"gp-placeholder\">Running actions needs the "
                          "<b>Execute</b> permission for this device.</div>");
            return;
        }
        if (!deps_.responses_fn) {
            send_html(res, "<div class=\"gp-mute\">Result polling unavailable on this server.</div>");
            return;
        }
        const auto rows = deps_.responses_fn(command_id, id);
        const DexAgentResponse* with_output = nullptr;
        const DexAgentResponse* terminal = nullptr;
        for (const auto& r : rows) {
            if (r.agent_id != id) continue; // another agent's rows are never rendered here
            if (!r.output.empty()) with_output = &r;
            if (r.status >= 1) terminal = &r; // 1=SUCCESS, 2+=FAILURE/TIMEOUT/REJECTED
        }

        HwActionResultView view;
        view.attempt = attempt;
        if (with_output && with_output->status == 1) {
            view.phase = HwActionResultView::Phase::Rendered;
            view.output = with_output->output;
        } else if (terminal && terminal->status == 1) {
            view.phase = HwActionResultView::Phase::RenderedEmpty;
        } else if (terminal) {
            view.phase = HwActionResultView::Phase::Failed;
            view.error_detail = terminal->error_detail;
        } else if (attempt >= 40) {
            view.phase = HwActionResultView::Phase::TimedOut;
        } else {
            send_html(res, render_hardware_result_pending(id, command_id, plugin, attempt + 1));
            return;
        }

        (void)detail::emit_behavioral_audit(
            deps_.audit_fn, req, res, "hardware.action.result", "success", "Agent", id,
            plugin + " command_id=" + command_id + " phase=" +
                std::to_string(static_cast<int>(view.phase)));
        // action name isn't carried on the wire (only plugin + command_id are, to
        // keep the poll URL short) — the panel only needs it for the RenderedEmpty
        // caption, so an empty string there is a cosmetic-only gap.
        send_html(res, render_hardware_action_result(plugin, "", view));
    });
}

} // namespace yuzu::server
