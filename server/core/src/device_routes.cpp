/// @file device_routes.cpp
/// Route registration for the shared device surfaces — `/devices` (list) +
/// `/device?id=` (the entity page) page shells, and the read-only HTMX fragments.
/// Renderers live in device_ui.cpp. SLICE 1 is auth-only (matches the current
/// agent-list posture); later slices add the perm/privacy gates for the behavioural
/// DEX lens + the live pull (see device_routes.hpp header).

#include "device_routes.hpp"

#include "dex_routes.hpp"             // dex_device_score, dex_iso_since
#include "live_kinds.hpp"             // shared live-read kind table + parser (S2)
#include "guaranteed_state_store.hpp" // dex_device_signal_summary, agent_rule_statuses, list_rules
#include "http_route_sink.hpp"
#include "rest_audit.hpp"             // detail::emit_behavioral_audit (Sec-Audit-Failed, #1647)
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

// The live-read kind table + wire-format parsing are shared with the REST JSON
// path via live_kinds.hpp (governance S2) so the two surfaces can't drift.
// `LiveKind` / `resolve_live_kind` are thin aliases over that shared header.
using yuzu::server::live::LiveKind;
inline std::optional<LiveKind> resolve_live_kind(const std::string& kind) {
    return yuzu::server::live::resolve_kind(kind);
}

// Parse the newline-joined plugin output into the matching live renderer (shared
// parser): os_info/uptime -> a value tile; processes/list -> a PID/name table.
std::string render_live_result(const LiveKind& lk, const std::string& output) {
    if (lk.plugin == "os_info") {
        const auto u = yuzu::server::live::parse_uptime(output);
        return render_device_live_value(lk.label, u.display.value_or(""));
    }
    if (lk.plugin == "processes") {
        std::vector<LiveProcess> procs;
        for (const auto& p : yuzu::server::live::parse_processes(output))
            procs.push_back(LiveProcess{static_cast<int>(p.pid), p.name, p.sha256, p.path});
        return render_device_live_processes(procs);
    }
    return "<div class=\"gp-note\">Unsupported live result.</div>";
}

} // namespace

void DeviceRoutes::register_routes(httplib::Server& svr, AuthFn auth_fn, PermFn perm_fn,
                                   ScopedPermFn scoped_perm_fn, DevicesFn devices_fn,
                                   LookupFn lookup_fn, const GuaranteedStateStore* store,
                                   DispatchFn dispatch_fn, ResponsesFn responses_fn,
                                   AuditFn audit_fn) {
    HttplibRouteSink sink(svr);
    register_routes(sink, std::move(auth_fn), std::move(perm_fn), std::move(scoped_perm_fn),
                    std::move(devices_fn), std::move(lookup_fn), store, std::move(dispatch_fn),
                    std::move(responses_fn), std::move(audit_fn));
}

void DeviceRoutes::register_routes(HttpRouteSink& sink, AuthFn auth_fn, PermFn perm_fn,
                                   ScopedPermFn scoped_perm_fn, DevicesFn devices_fn,
                                   LookupFn lookup_fn, const GuaranteedStateStore* store,
                                   DispatchFn dispatch_fn, ResponsesFn responses_fn,
                                   AuditFn audit_fn) {
    auth_fn_ = std::move(auth_fn);
    perm_fn_ = std::move(perm_fn);
    scoped_perm_fn_ = std::move(scoped_perm_fn);
    devices_fn_ = std::move(devices_fn);
    lookup_fn_ = std::move(lookup_fn);
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

    // -- /fragments/devices/list — global Infrastructure:Read + per-operator scope.
    // Exact /api/agents parity: the gate admits Infrastructure:Read operators and
    // the provider (get_visible_agents_json) returns only the caller's visible
    // devices, so an operator never enumerates devices outside their scope. --
    sink.Get("/fragments/devices/list", [this](const httplib::Request& req,
                                               httplib::Response& res) {
        auto session = auth_fn_(req, res);
        if (!session) { res.status = 401; res.set_content("auth required", "text/plain"); return; }
        if (!perm_fn_(req, res, "Infrastructure", "Read")) return;
        std::vector<DeviceRow> all =
            devices_fn_ ? devices_fn_(session->username) : std::vector<DeviceRow>{};
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
        // Score ONLY the rows we render (post-filter) — devices_fn_ no longer
        // scores the fleet, so a filtered/searched list never pays for the
        // devices it excludes. (Fleet-scale pagination of this set is a tracked
        // follow-up; the win here is killing the score-all-then-filter waste.)
        if (store_) {
            const std::string since = dex_iso_since(7);
            for (auto& d : rows)
                d.dex_score = dex_device_score(store_, d.agent_id, since);
        }
        res.set_content(render_devices_list_fragment(rows, req.has_param("q") ? req.get_param_value("q") : "",
                                                     os, status, online, total),
                        "text/html; charset=utf-8");
    });

    // Resolve one device's identity row, UNSCOPED. Authz is the scoped_perm_fn_ gate
    // each per-device route runs FIRST; this is the post-authz row fetch. It must NOT
    // re-scope (see LookupFn doc: list scoping is non-ancestor, the gate is
    // ancestor-aware — re-scoping here would 404 a parent-group-authorized device).
    auto get_one = [this](const std::string& id) -> std::optional<DeviceRow> {
        return lookup_fn_ ? lookup_fn_(id) : std::nullopt;
    };

    // -- /fragments/device/page (the full page body: identity + lens tabs + lens) --
    sink.Get("/fragments/device/page", [this, get_one](const httplib::Request& req,
                                                       httplib::Response& res) {
        auto session = auth_fn_(req, res);
        if (!session) { res.status = 401; res.set_content("auth required", "text/plain"); return; }
        const std::string id = req.has_param("id") ? req.get_param_value("id") : "";
        // Per-device scope: Infrastructure:Read for THIS device (tier + management
        // group, ancestor-aware). 403 = outside scope; an in-scope-but-absent device
        // falls through to the honest not-found body below.
        if (!scoped_perm_fn_(req, res, "Infrastructure", "Read", id)) return;
        auto d = get_one(id);
        // Score ONLY this device — devices_fn_ no longer scores the fleet (a page
        // open must not pay an N-device cost; the score badge needs just this one).
        if (d && store_)
            d->dex_score = dex_device_score(store_, d->agent_id, dex_iso_since(7));
        res.set_content(d ? render_device_page(*d) : render_device_not_found(id),
                        "text/html; charset=utf-8");
    });

    // -- /fragments/device/info (the Device-info lens, for tab switching) --
    sink.Get("/fragments/device/info", [this, get_one](const httplib::Request& req,
                                                       httplib::Response& res) {
        auto session = auth_fn_(req, res);
        if (!session) { res.status = 401; res.set_content("auth required", "text/plain"); return; }
        const std::string id = req.has_param("id") ? req.get_param_value("id") : "";
        if (!scoped_perm_fn_(req, res, "Infrastructure", "Read", id)) return; // per-device scope
        auto d = get_one(id);
        res.set_content(d ? render_device_info_fragment(*d) : render_device_not_found(id),
                        "text/html; charset=utf-8");
    });

    // -- DEX lens: per-device score + signal summary (+ link to the full drill) --
    sink.Get("/fragments/device/dex", [this](const httplib::Request& req, httplib::Response& res) {
        const std::string id = req.has_param("id") ? req.get_param_value("id") : "";
        // Per-device behavioral data (PII): GuaranteedState:Read SCOPED to this
        // device (tier + management group) + audit-on-open. Stronger than the
        // sibling /fragments/dex/device's bare Read gate — closes the cross-scope
        // read of another team's per-device DEX summary.
        if (!scoped_perm_fn_(req, res, "GuaranteedState", "Read", id)) return;
        if (!store_) {
            res.set_content(render_device_lens_placeholder("dex", id, "DEX store unavailable."),
                            "text/html; charset=utf-8");
            return;
        }
        // Behavioural-PII access audit. HTML dashboard fragment → set-and-proceed:
        // a dropped evidence row flags via Sec-Audit-Failed but STILL renders, so
        // a transient audit hiccup never blanks the operator's lens (#1647). The
        // shared helper captures the persist bool behind a try/catch (the throw
        // arm is otherwise silent) — one pattern across every behavioural route.
        detail::emit_behavioral_audit(audit_fn_, req, res, "dex.device.view", "success", "Agent",
                                      id, "device DEX lens (per-device signal summary)");
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
        const std::string id = req.has_param("id") ? req.get_param_value("id") : "";
        // Per-device compliance state: GuaranteedState:Read SCOPED to this device
        // (tier + management group) + audit-on-open (parity with the DEX lens above).
        if (!scoped_perm_fn_(req, res, "GuaranteedState", "Read", id)) return;
        if (!store_) {
            res.set_content(render_device_lens_placeholder("guardian", id, "Guardian store unavailable."),
                            "text/html; charset=utf-8");
            return;
        }
        // Behavioural-PII access audit — set-and-proceed (HTML fragment), parity
        // with the DEX lens above and the shared #1647 helper.
        detail::emit_behavioral_audit(audit_fn_, req, res, "guardian.device.view", "success",
                                      "Agent", id, "device Guardian lens (per-guard compliance)");
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
    auto can_execute = [this](const httplib::Request& req, const std::string& id) {
        httplib::Response probe; // throwaway: htmx swallows a raw 403, so probe -> note
        return scoped_perm_fn_ && scoped_perm_fn_(req, probe, "Execution", "Execute", id);
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
        const std::string id = req.has_param("id") ? req.get_param_value("id") : "";
        // Per-device live surface: scoped Read floor (the run panels re-gate Read +
        // Execute per dispatch). 403 = outside the caller's management scope.
        if (!scoped_perm_fn_(req, res, "GuaranteedState", "Read", id)) return;
        res.set_content(render_device_live_shell(id), "text/html; charset=utf-8");
    });

    // Run: validate kind (allowlist) -> Execute probe -> dispatch -> audit -> poll.
    sink.Get("/fragments/device/live/run", [this, note, can_execute, live_pending](
                                               const httplib::Request& req,
                                               httplib::Response& res) {
        const std::string id = req.has_param("id") ? req.get_param_value("id") : "";
        const std::string kind = req.has_param("kind") ? req.get_param_value("kind") : "";
        // Per-device scoped Read floor (tier + management group for THIS device);
        // the Execute probe below is the soft, htmx-friendly note for a read-only
        // operator. Gate before any dispatch so an out-of-scope agent_id is refused.
        if (!scoped_perm_fn_(req, res, "GuaranteedState", "Read", id)) return;
        const auto lk = resolve_live_kind(kind);
        if (!lk || id.empty()) { res.status = 400; res.set_content("bad request", "text/plain"); return; }
        if (!can_execute(req, id)) {
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
        // Audit the DISPATCH with an honest result: "dispatched" (not "success") —
        // the outcome isn't known yet (the browser polls /result separately).
        // NOTE (#1549): the REST sibling now audits "requested" PRE-dispatch
        // (fail-closed audit-on-open); this dashboard emitter still audits
        // post-dispatch "dispatched" — a deliberate, tracked divergence (see
        // audit-log.md "Two emitters, by design") pending alignment of this path to
        // the pre-dispatch model. Until then a SIEM result= query for device.live.*
        // must match BOTH tokens.
        if (audit_fn_)
            audit_fn_(req, lk->audit_action, sent > 0 ? "dispatched" : "no_agents", "Agent", id,
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
        const std::string kind = req.has_param("kind") ? req.get_param_value("kind") : "";
        const std::string command_id =
            req.has_param("command_id") ? req.get_param_value("command_id") : "";
        const std::string id = req.has_param("agent_id") ? req.get_param_value("agent_id") : "";
        // Per-device scoped Read floor — a poll must honour the same management
        // scope as the dispatch (an out-of-scope agent_id is refused even with a
        // guessed command_id).
        if (!scoped_perm_fn_(req, res, "GuaranteedState", "Read", id)) return;
        const auto lk = resolve_live_kind(kind);
        if (!lk) { res.status = 400; res.set_content("bad request", "text/plain"); return; }
        // Only THIS kind's plugin commands are pollable here, only for the named
        // agent — narrows what a guessed/stolen command_id can read via this route.
        if (id.empty() || command_id.size() > 64 || !command_id.starts_with(lk->plugin + "-")) {
            res.status = 400; res.set_content("bad request", "text/plain"); return;
        }
        if (!can_execute(req, id)) {
            note(res, "Live device info needs the <b>Execute</b> permission.");
            return;
        }
        if (!responses_fn_) {
            note(res, "Live device query unavailable on this server.");
            return;
        }
        // Poll budget: hashing every running binary (processes/list_hashed) can
        // take longer than a warehouse query, so allow more attempts before
        // declaring a timeout (~28s at 700ms cadence).
        constexpr int kMaxAttempts = 40;
        int attempt = 1;
        if (req.has_param("n")) {
            try { attempt = std::clamp(std::stoi(req.get_param_value("n")), 1, 50); } catch (...) {}
        }
        // Hoist the responses into a named local: pointers below must outlive the
        // loop, so iterating the temporary directly would dangle (use-after-free).
        const auto rows = responses_fn_(command_id);
        const DexAgentResponse* with_output = nullptr;
        const DexAgentResponse* terminal = nullptr; // SUCCESS or any failure terminal
        for (const auto& r : rows) {
            if (r.agent_id != id) continue; // another agent's rows are never rendered here
            if (!r.output.empty()) with_output = &r;
            if (r.status >= 1) terminal = &r; // 1=SUCCESS, 2+=FAILURE/TIMEOUT/REJECTED
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
        if (terminal) {
            // The command COMPLETED. Failure → honest note; success-with-no-output
            // → render the empty result now (don't poll to a false timeout — UP-1).
            if (terminal->status >= 2) {
                note(res, "Query failed on the device: " +
                              html_escape(terminal->error_detail.substr(0, 200)));
                return;
            }
            res.set_content(render_live_result(*lk, ""), "text/html; charset=utf-8");
            return;
        }
        if (attempt >= kMaxAttempts) {
            note(res, "No response from the device (timed out) &mdash; it may have gone offline. "
                      "Reload to retry.");
            return;
        }
        res.set_content(live_pending(command_id, id, kind, attempt + 1), "text/html; charset=utf-8");
    });
}

} // namespace yuzu::server
