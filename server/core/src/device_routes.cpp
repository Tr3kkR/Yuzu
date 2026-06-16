/// @file device_routes.cpp
/// Route registration for the shared device surfaces — `/devices` (list) +
/// `/device?id=` (the entity page) page shells, and the read-only HTMX fragments.
/// Renderers live in device_ui.cpp. SLICE 1 is auth-only (matches the current
/// agent-list posture); later slices add the perm/privacy gates for the behavioural
/// DEX lens + the live pull (see device_routes.hpp header).

#include "device_routes.hpp"

#include "dex_routes.hpp"             // dex_device_score, dex_iso_since
#include "guaranteed_state_store.hpp" // dex_device_signal_summary, agent_rule_statuses, list_rules
#include "http_route_sink.hpp"
#include "web_utils.hpp"              // html_escape

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

// Shared full-page shell (global scope, defined in guardian_page_ui.cpp).
extern const char* const kGuardianDetailPageHtml;

namespace yuzu::server {

namespace {

std::string to_lower(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

// Render the shared page shell with the title + initial fragment substituted, and
// the default-active Guardian nav item de-activated (these pages are cross-cutting,
// not under Guardian). Mirrors NetworkRoutes' shell handling.
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
    return html;
}

bool matches(const DeviceRow& d, const std::string& q) {
    if (q.empty()) return true;
    std::string hay = to_lower(d.hostname + " " + d.agent_id + " " + d.os + " " + d.arch + " " +
                               d.segment);
    for (const auto& t : d.tags) hay += " " + to_lower(t);
    return hay.find(q) != std::string::npos;
}

// One "Get live info" panel = one real plugin instruction dispatched at the
// device NOW. The kind is an ALLOWLIST token (validated before it drives a
// dispatch or reaches markup); each kind carries its own audit verb so a
// usage-class read (what processes a person is running) stays separately
// countable from a machine-health read (uptime) — the works-council access-audit
// posture the DEX per-app panel established (dex_routes.cpp PR2 rationale).
struct LiveKind {
    std::string plugin;
    std::string action;
    std::string label;
    std::string audit_action;
};

std::optional<LiveKind> resolve_live_kind(const std::string& kind) {
    if (kind == "uptime")
        return LiveKind{"os_info", "uptime", "Uptime", "device.live.uptime"};
    if (kind == "processes")
        return LiveKind{"processes", "list_hashed", "Running processes", "device.live.processes"};
    return std::nullopt;
}

// Parse the newline-joined plugin output (one write_output() line each, possible
// trailing \r) into the matching live renderer. os_info/uptime -> a value tile;
// processes/list -> a PID/name table.
std::string render_live_result(const LiveKind& lk, const std::string& output) {
    std::vector<std::string> lines;
    std::size_t pos = 0;
    while (pos < output.size()) {
        const auto nl = output.find('\n', pos);
        std::string line = output.substr(pos, (nl == std::string::npos ? output.size() : nl) - pos);
        pos = (nl == std::string::npos) ? output.size() : nl + 1;
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (!line.empty()) lines.push_back(std::move(line));
    }
    if (lk.plugin == "os_info") {
        std::string value;
        for (const auto& l : lines)
            if (l.starts_with("uptime_display|")) { value = l.substr(15); break; }
        return render_device_live_value(lk.label, value);
    }
    if (lk.plugin == "processes") {
        std::vector<LiveProcess> procs;
        for (const auto& l : lines) {
            if (!l.starts_with("proc|")) continue; // proc|pid|name|sha256|path
            const auto a = l.find('|');            // after "proc"
            const auto b = l.find('|', a + 1);     // after pid
            if (b == std::string::npos) continue;
            const auto c = l.find('|', b + 1);     // after name
            LiveProcess lp;
            try { lp.pid = std::stoi(l.substr(a + 1, b - a - 1)); } catch (...) { lp.pid = 0; }
            if (c == std::string::npos) {
                lp.name = l.substr(b + 1); // tolerate the old proc|pid|name shape
            } else {
                lp.name = l.substr(b + 1, c - b - 1);
                const auto d = l.find('|', c + 1); // after sha256 (path may contain none)
                if (d == std::string::npos) {
                    lp.sha256 = l.substr(c + 1);
                } else {
                    lp.sha256 = l.substr(c + 1, d - c - 1);
                    lp.path = l.substr(d + 1);
                }
            }
            procs.push_back(std::move(lp));
        }
        return render_device_live_processes(procs);
    }
    return "<div class=\"gp-note\">Unsupported live result.</div>";
}

} // namespace

void DeviceRoutes::register_routes(httplib::Server& svr, AuthFn auth_fn, PermFn perm_fn,
                                   DevicesFn devices_fn, const GuaranteedStateStore* store,
                                   DispatchFn dispatch_fn, ResponsesFn responses_fn,
                                   AuditFn audit_fn) {
    HttplibRouteSink sink(svr);
    register_routes(sink, std::move(auth_fn), std::move(perm_fn), std::move(devices_fn), store,
                    std::move(dispatch_fn), std::move(responses_fn), std::move(audit_fn));
}

void DeviceRoutes::register_routes(HttpRouteSink& sink, AuthFn auth_fn, PermFn perm_fn,
                                   DevicesFn devices_fn, const GuaranteedStateStore* store,
                                   DispatchFn dispatch_fn, ResponsesFn responses_fn,
                                   AuditFn audit_fn) {
    auth_fn_ = std::move(auth_fn);
    perm_fn_ = std::move(perm_fn);
    devices_fn_ = std::move(devices_fn);
    store_ = store;
    dispatch_fn_ = std::move(dispatch_fn);
    responses_fn_ = std::move(responses_fn);
    audit_fn_ = std::move(audit_fn);

    // -- /devices page shell (auth-only static chrome) --
    sink.Get("/devices", [this](const httplib::Request& req, httplib::Response& res) {
        if (!auth_fn_(req, res)) {
            res.set_redirect("/login");
            return;
        }
        res.set_header("Cache-Control", "no-cache, no-store, must-revalidate");
        res.set_content(page_shell("Yuzu \xE2\x80\x94 Devices", "/fragments/devices/list"),
                        "text/html; charset=utf-8");
    });

    // -- /device?id= page shell (auth-only) --
    sink.Get("/device", [this](const httplib::Request& req, httplib::Response& res) {
        if (!auth_fn_(req, res)) {
            res.set_redirect("/login");
            return;
        }
        std::string id = req.has_param("id") ? req.get_param_value("id") : "";
        // The shell hx-loads the page-body fragment (which carries the id forward).
        std::string frag = "/fragments/device/page";
        if (!id.empty()) {
            // Minimal query-safe echo; the fragment handler re-reads `id` from params.
            std::string enc;
            static const char* kHex = "0123456789ABCDEF";
            for (unsigned char c : id) {
                if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~')
                    enc += static_cast<char>(c);
                else { enc += '%'; enc += kHex[c >> 4]; enc += kHex[c & 0x0F]; }
            }
            frag += "?id=" + enc;
        }
        res.set_header("Cache-Control", "no-cache, no-store, must-revalidate");
        res.set_content(page_shell("Yuzu \xE2\x80\x94 Device", frag), "text/html; charset=utf-8");
    });

    // -- /fragments/devices/list (auth-only; slice 1) --
    sink.Get("/fragments/devices/list", [this](const httplib::Request& req,
                                               httplib::Response& res) {
        if (!auth_fn_(req, res)) { res.status = 401; res.set_content("auth required", "text/plain"); return; }
        std::vector<DeviceRow> all = devices_fn_ ? devices_fn_() : std::vector<DeviceRow>{};
        const std::string q = to_lower(req.has_param("q") ? req.get_param_value("q") : "");
        std::string os = req.has_param("os") ? req.get_param_value("os") : "all";
        std::string status = req.has_param("status") ? req.get_param_value("status") : "all";
        if (os.empty()) os = "all";
        if (status.empty()) status = "all";

        std::size_t total = all.size();
        std::size_t online = static_cast<std::size_t>(
            std::count_if(all.begin(), all.end(), [](const DeviceRow& d) { return d.online; }));

        std::vector<DeviceRow> rows;
        for (auto& d : all) {
            if (os != "all" && to_lower(d.os) != to_lower(os) &&
                !(os == "macos" && (d.os == "darwin")))
                continue;
            if (status == "online" && !d.online) continue;
            if (status == "offline" && d.online) continue;
            if (!matches(d, q)) continue;
            rows.push_back(d);
        }
        std::sort(rows.begin(), rows.end(), [](const DeviceRow& a, const DeviceRow& b) {
            return (a.hostname.empty() ? a.agent_id : a.hostname) <
                   (b.hostname.empty() ? b.agent_id : b.hostname);
        });
        res.set_content(render_devices_list_fragment(rows, req.has_param("q") ? req.get_param_value("q") : "",
                                                     os, status, online, total),
                        "text/html; charset=utf-8");
    });

    // Resolve one device from the live list (slice 1: scan; a get_one(id) resolver
    // replaces this at fleet scale).
    auto find_one = [this](const std::string& id) -> std::optional<DeviceRow> {
        if (!devices_fn_) return std::nullopt;
        for (auto& d : devices_fn_())
            if (d.agent_id == id) return d;
        return std::nullopt;
    };

    // -- /fragments/device/page (the full page body: identity + lens tabs + lens) --
    sink.Get("/fragments/device/page", [this, find_one](const httplib::Request& req,
                                                        httplib::Response& res) {
        if (!auth_fn_(req, res)) { res.status = 401; res.set_content("auth required", "text/plain"); return; }
        const std::string id = req.has_param("id") ? req.get_param_value("id") : "";
        auto d = find_one(id);
        res.set_content(d ? render_device_page(*d) : render_device_not_found(id),
                        "text/html; charset=utf-8");
    });

    // -- /fragments/device/info (the Device-info lens, for tab switching) --
    sink.Get("/fragments/device/info", [this, find_one](const httplib::Request& req,
                                                        httplib::Response& res) {
        if (!auth_fn_(req, res)) { res.status = 401; res.set_content("auth required", "text/plain"); return; }
        const std::string id = req.has_param("id") ? req.get_param_value("id") : "";
        auto d = find_one(id);
        res.set_content(d ? render_device_info_fragment(*d) : render_device_not_found(id),
                        "text/html; charset=utf-8");
    });

    // -- DEX lens: per-device score + signal summary (+ link to the full drill) --
    sink.Get("/fragments/device/dex", [this](const httplib::Request& req, httplib::Response& res) {
        if (!auth_fn_(req, res)) { res.status = 401; res.set_content("auth required", "text/plain"); return; }
        const std::string id = req.has_param("id") ? req.get_param_value("id") : "";
        if (!store_) {
            res.set_content(render_device_lens_placeholder("dex", id, "DEX store unavailable."),
                            "text/html; charset=utf-8");
            return;
        }
        const std::string since = dex_iso_since(7);
        const int score = dex_device_score(store_, id, since);
        std::vector<std::pair<std::string, std::int64_t>> sigs;
        for (const auto& s : store_->dex_device_signal_summary(id, since))
            sigs.emplace_back(s.obs_type, s.count);
        res.set_content(render_device_dex_lens(id, score, sigs), "text/html; charset=utf-8");
    });
    // -- Guardian lens: per-guard compliance state for this device --
    sink.Get("/fragments/device/guardian", [this](const httplib::Request& req,
                                                  httplib::Response& res) {
        if (!auth_fn_(req, res)) { res.status = 401; res.set_content("auth required", "text/plain"); return; }
        const std::string id = req.has_param("id") ? req.get_param_value("id") : "";
        if (!store_) {
            res.set_content(render_device_lens_placeholder("guardian", id, "Guardian store unavailable."),
                            "text/html; charset=utf-8");
            return;
        }
        std::unordered_map<std::string, std::string> rule_names;
        for (const auto& r : store_->list_rules())
            rule_names[r.rule_id] = r.name;
        std::vector<DeviceGuardRow> guards;
        for (const auto& st : store_->agent_rule_statuses()) { // all; filter to this agent
            if (st.agent_id != id)
                continue;
            DeviceGuardRow g;
            auto it = rule_names.find(st.rule_id);
            g.name = (it != rule_names.end() && !it->second.empty()) ? it->second : st.rule_id;
            g.state = st.state;
            g.updated_at = st.updated_at;
            guards.push_back(std::move(g));
        }
        res.set_content(render_device_guardian_lens(id, guards), "text/html; charset=utf-8");
    });

    // -- "Get live info": dispatch REAL plugin instructions at the device NOW and
    // poll the response store for the result. NOT the 30s heartbeat, NOT the
    // warehouse — each panel runs an instruction that queries the live OS. The
    // shell embeds one auto-loading panel per kind; each panel hx-gets .../run
    // (which dispatches + returns a polling div) and the div polls .../result.
    //
    // Posture mirrors the DEX device-perf dispatch (dex_routes.cpp): auth, then
    // an Execute PROBE against a throwaway response (htmx swallows a raw 403, so
    // a read-only operator gets an honest in-panel note instead), then dispatch
    // through the shared chokepoint, audited per-kind.
    auto note = [](httplib::Response& res, const std::string& text) {
        res.set_content("<div class=\"gp-note\">" + text + "</div>", "text/html; charset=utf-8");
    };
    auto can_execute = [this](const httplib::Request& req) {
        httplib::Response probe;
        return perm_fn_ && perm_fn_(req, probe, "Execution", "Execute");
    };
    auto url_enc = [](const std::string& s) {
        static const char* kHex = "0123456789ABCDEF";
        std::string out;
        for (unsigned char c : s) {
            if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~')
                out += static_cast<char>(c);
            else { out += '%'; out += kHex[c >> 4]; out += kHex[c & 0x0F]; }
        }
        return out;
    };
    // `kind` is already validated against the allowlist before this is called.
    auto live_pending = [url_enc](const std::string& command_id, const std::string& agent_id,
                                  const std::string& kind, int attempt) {
        return "<div hx-get=\"/fragments/device/live/result?command_id=" + url_enc(command_id) +
               "&amp;agent_id=" + url_enc(agent_id) + "&amp;kind=" + url_enc(kind) +
               "&amp;n=" + std::to_string(attempt) +
               "\" hx-trigger=\"load delay:700ms\" hx-swap=\"outerHTML\" class=\"gp-note\">"
               "Waiting for the device to respond&hellip;</div>";
    };

    // Shell: a header + one auto-loading panel per live instruction.
    sink.Get("/fragments/device/live", [this](const httplib::Request& req, httplib::Response& res) {
        if (!auth_fn_(req, res)) { res.status = 401; res.set_content("auth required", "text/plain"); return; }
        const std::string id = req.has_param("id") ? req.get_param_value("id") : "";
        res.set_content(render_device_live_shell(id), "text/html; charset=utf-8");
    });

    // Run: validate kind (allowlist) -> Execute probe -> dispatch -> audit -> poll.
    sink.Get("/fragments/device/live/run", [this, note, can_execute, live_pending](
                                               const httplib::Request& req,
                                               httplib::Response& res) {
        if (!auth_fn_(req, res)) { res.status = 401; res.set_content("auth required", "text/plain"); return; }
        const std::string id = req.has_param("id") ? req.get_param_value("id") : "";
        const std::string kind = req.has_param("kind") ? req.get_param_value("kind") : "";
        const auto lk = resolve_live_kind(kind);
        if (!lk || id.empty()) { res.status = 400; res.set_content("bad request", "text/plain"); return; }
        if (!can_execute(req)) {
            note(res, "Live device info needs the <b>Execute</b> permission &mdash; it runs a "
                      "read-only instruction on the device.");
            return;
        }
        if (!dispatch_fn_ || !responses_fn_) {
            note(res, "Live device query unavailable on this server.");
            return;
        }
        const auto [command_id, sent] =
            dispatch_fn_(lk->plugin, lk->action, {id}, "", {});
        if (audit_fn_)
            audit_fn_(req, lk->audit_action, sent > 0 ? "success" : "no_agents", "Agent", id,
                      lk->plugin + "/" + lk->action + " -> " + std::to_string(sent) +
                          " agent(s) command_id=" + command_id);
        if (sent == 0) {
            note(res, "Device offline &mdash; live info needs a connected agent.");
            return;
        }
        res.set_content(live_pending(command_id, id, kind, 1), "text/html; charset=utf-8");
    });

    // Result: re-validate kind + Execute + command_id prefix + agent match, then
    // poll the response store and render (data rides RUNNING rows, the
    // response-store contract DexRoutes relies on).
    sink.Get("/fragments/device/live/result", [this, note, can_execute, live_pending](
                                                  const httplib::Request& req,
                                                  httplib::Response& res) {
        if (!auth_fn_(req, res)) { res.status = 401; res.set_content("auth required", "text/plain"); return; }
        const std::string kind = req.has_param("kind") ? req.get_param_value("kind") : "";
        const auto lk = resolve_live_kind(kind);
        if (!lk) { res.status = 400; res.set_content("bad request", "text/plain"); return; }
        if (!can_execute(req)) {
            note(res, "Live device info needs the <b>Execute</b> permission.");
            return;
        }
        if (!responses_fn_) {
            note(res, "Live device query unavailable on this server.");
            return;
        }
        const std::string command_id =
            req.has_param("command_id") ? req.get_param_value("command_id") : "";
        const std::string id = req.has_param("agent_id") ? req.get_param_value("agent_id") : "";
        // Only THIS kind's plugin commands are pollable here, only for the named
        // agent — narrows what a guessed/stolen command_id can read via this route.
        if (id.empty() || command_id.size() > 64 || !command_id.starts_with(lk->plugin + "-")) {
            res.status = 400; res.set_content("bad request", "text/plain"); return;
        }
        int attempt = 1;
        if (req.has_param("n")) {
            try { attempt = std::clamp(std::stoi(req.get_param_value("n")), 1, 30); } catch (...) {}
        }
        // Hoist the responses into a named local: pointers below must outlive the
        // loop, so iterating the temporary directly would dangle (use-after-free).
        const auto rows = responses_fn_(command_id);
        const DexAgentResponse* with_output = nullptr;
        const DexAgentResponse* failed = nullptr;
        for (const auto& r : rows) {
            if (r.agent_id != id) continue; // another agent's rows are never rendered here
            if (!r.output.empty()) with_output = &r;
            else if (r.status >= 2) failed = &r; // FAILURE / TIMEOUT / REJECTED terminal frame
        }
        if (with_output) {
            if (with_output->output.starts_with("error|")) {
                note(res, "The device reported an error: " +
                              html_escape(with_output->output.substr(6, 200)));
                return;
            }
            res.set_content(render_live_result(*lk, with_output->output),
                            "text/html; charset=utf-8");
            return;
        }
        if (failed) {
            note(res, "Query failed on the device: " + html_escape(failed->error_detail.substr(0, 200)));
            return;
        }
        if (attempt >= 20) {
            note(res, "No response from the device (timed out) &mdash; it may have gone offline. "
                      "Reload to retry.");
            return;
        }
        res.set_content(live_pending(command_id, id, kind, attempt + 1), "text/html; charset=utf-8");
    });
}

} // namespace yuzu::server
