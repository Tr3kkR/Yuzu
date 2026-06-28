/// @file preflight_routes.cpp
/// `/auto` page shell + config / run / result-poll fragments. See
/// preflight_routes.hpp for the auth/scope contract. Run dispatches the configured
/// checks to the operator-visible devices in the chosen group; the result poll
/// applies the operator's thresholds (preflight_parse.hpp `evaluate`) to the raw
/// facts and aggregates pass/fail BY CHECK (self-repolling until terminal).

#include "preflight_routes.hpp"

#include "preflight_parse.hpp" // kPreflightChecks, extract_cell, evaluate, PreflightConfig
#include "web_utils.hpp"       // html_escape

#include <algorithm>
#include <array>
#include <cctype>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

// Defined in guardian_page_ui.cpp — the shared dark-theme full-page shell. Declared
// at GLOBAL scope (not inside yuzu::server) to match the definition's linkage, the
// same way device_routes.cpp does it.
extern const char* const kGuardianDetailPageHtml;

namespace yuzu::server {

namespace {

std::string url_encode(const std::string& s) {
    static const char* kHex = "0123456789ABCDEF";
    std::string out;
    out.reserve(s.size());
    for (unsigned char c : s) {
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~')
            out += static_cast<char>(c);
        else {
            out += '%';
            out += kHex[c >> 4];
            out += kHex[c & 0x0F];
        }
    }
    return out;
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
    return html;
}

std::string param(const httplib::Request& req, const char* key) {
    return req.has_param(key) ? req.get_param_value(key) : std::string{};
}

// Read the operator's config from the request (POST form on run, query on poll —
// httplib merges both into get_param_value).
preflight::PreflightConfig config_from_req(const httplib::Request& req) {
    preflight::PreflightConfig c;
    c.app_name = param(req, "app_name");
    c.app_min_version = param(req, "app_min");
    c.app_max_version = param(req, "app_max");
    c.os_min_version = param(req, "os_min");
    c.req_arch = param(req, "arch");
    c.min_free_gib = preflight::parse_i64(param(req, "min_gib"));
    c.volume = param(req, "volume");
    c.reboot_block = param(req, "reboot") != "warn"; // default block
    return c;
}

// A check runs only when configured: `app` needs a target name; the rest always.
bool check_applicable(std::string_view key, const preflight::PreflightConfig& cfg) {
    if (key == "app")
        return !cfg.app_name.empty();
    return true;
}

std::unordered_map<std::string, std::string> dispatch_params(std::string_view key,
                                                             const preflight::PreflightConfig& cfg) {
    if (key == "app")
        return {{"name", cfg.app_name}};
    if (key == "disk" && !cfg.volume.empty())
        return {{"path", cfg.volume}};
    return {};
}

// One-check threshold phrase; prefixed so it reads standalone in the config-summary
// line ("AcmeVPN ≥ 4.2.0 ≤ 4.9.99 · OS ≥ 10.0.19045 · arch x86_64 · …").
std::string threshold_text(std::string_view key, const preflight::PreflightConfig& cfg) {
    if (key == "app") {
        std::string s = cfg.app_name;
        if (cfg.app_min_version.empty() && cfg.app_max_version.empty())
            return s + " installed";
        if (!cfg.app_min_version.empty())
            s += " \xE2\x89\xA5 " + cfg.app_min_version;
        if (!cfg.app_max_version.empty())
            s += " \xE2\x89\xA4 " + cfg.app_max_version;
        return s;
    }
    if (key == "osver")
        return cfg.os_min_version.empty() ? "OS any" : ("OS \xE2\x89\xA5 " + cfg.os_min_version);
    if (key == "osarch")
        return std::string("arch ") + (cfg.req_arch.empty() ? "any" : cfg.req_arch);
    if (key == "disk")
        return "disk \xE2\x89\xA5 " + std::to_string(cfg.min_free_gib) + " GiB" +
               (cfg.volume.empty() ? "" : (" on " + cfg.volume));
    if (key == "reboot")
        return cfg.reboot_block ? "reboot must be clear" : "reboot warn-only";
    return {};
}

// The one-line threshold recap shown above the result grid (applicable checks only).
std::string config_summary(const preflight::PreflightConfig& cfg) {
    std::string s;
    for (const auto& c : preflight::kPreflightChecks) {
        if (!check_applicable(c.key, cfg))
            continue;
        if (!s.empty())
            s += " \xC2\xB7 ";
        s += threshold_text(c.key, cfg);
    }
    return s;
}

// One in-flight check + its per-agent (status,output). Empty byAgent (initial
// render) → every device reads Unknown.
struct ActiveCheck {
    std::string key;
    std::string label;
    std::unordered_map<std::string, std::pair<int, std::string>> byAgent;
};

// Build the canonical per-device result set. Sets `any_pending` if any
// device×check still lacks a terminal response (drives the self-repoll). The
// bucket is preflight::classify_device over the device's verdicts.
std::vector<PreflightDeviceResult> build_results(const std::vector<DeviceRow>& targets,
                                                 const std::vector<ActiveCheck>& active,
                                                 const preflight::PreflightConfig& cfg,
                                                 bool& any_pending) {
    std::vector<PreflightDeviceResult> out;
    out.reserve(targets.size());
    for (const auto& d : targets) {
        PreflightDeviceResult dr;
        dr.agent_id = d.agent_id;
        dr.hostname = d.hostname;
        dr.os = d.os;
        std::vector<preflight::Verdict> verdicts;
        verdicts.reserve(active.size());
        for (const auto& ac : active) {
            PreflightDeviceCheck ck;
            ck.key = ac.key;
            ck.label = ac.label;
            bool terminal = false;
            auto it = ac.byAgent.find(d.agent_id);
            if (it != ac.byAgent.end()) {
                const int status = it->second.first;
                const std::string& outp = it->second.second;
                if (!outp.empty()) {
                    terminal = true;
                    if (outp.rfind("error|", 0) == 0) {
                        ck.value = "error";
                    } else {
                        ck.verdict = preflight::evaluate(ac.key, outp, cfg);
                        if (auto disp = preflight::extract_cell(ac.key, outp))
                            ck.value = *disp;
                    }
                } else if (status >= 2) {
                    terminal = true;
                    ck.value = "error";
                } else if (status == 1) {
                    terminal = true; // success, no output → no fact
                    ck.value = "\xE2\x80\x94";
                }
            }
            if (!terminal)
                any_pending = true;
            verdicts.push_back(ck.verdict);
            dr.checks.push_back(std::move(ck));
        }
        dr.bucket = preflight::classify_device(verdicts);
        out.push_back(std::move(dr));
    }
    return out;
}

// Operator-visible devices in `group_id` (empty → all visible), then narrowed by
// OS family (`os_filter` empty/"any" → no OS narrowing). IDOR-safe: the visible
// set is always devices_fn(username) ∩ group, never a raw fleet read.
std::vector<DeviceRow> resolve_targets(const PreflightRoutes::DevicesFn& devices_fn,
                                       const PreflightRoutes::GroupMembersFn& members_fn,
                                       const std::string& username, const std::string& group_id,
                                       const std::string& os_filter) {
    auto visible = devices_fn ? devices_fn(username) : std::vector<DeviceRow>{};
    std::vector<DeviceRow> scoped;
    if (group_id.empty()) {
        scoped = std::move(visible);
    } else {
        std::unordered_set<std::string> members;
        if (members_fn)
            for (const auto& m : members_fn(group_id))
                members.insert(m);
        for (const auto& d : visible)
            if (members.count(d.agent_id))
                scoped.push_back(d);
    }
    if (os_filter.empty() || os_filter == "any")
        return scoped;
    std::vector<DeviceRow> out;
    for (const auto& d : scoped)
        if (d.os == os_filter)
            out.push_back(d);
    return out;
}

std::string scope_label(const PreflightRoutes::GroupsFn& groups_fn, const std::string& group_id) {
    if (group_id.empty())
        return "all visible devices";
    if (groups_fn)
        for (const auto& [id, name] : groups_fn())
            if (id == group_id)
                return name;
    return group_id;
}

// Append the operator's config (thresholds + params) to a result-poll URL. The
// result handler re-reads these to evaluate verdicts, so EVERY poll URL — the
// initial one and every repoll — must carry them, or the first poll would score
// against an empty config.
void append_config_params(std::string& url, const httplib::Request& req) {
    static const char* kCfg[] = {"app_name", "app_min", "app_max", "os_min",    "arch",
                                 "min_gib",  "volume",  "reboot",  "os_filter", "window"};
    for (const char* k : kCfg)
        url += "&" + std::string(k) + "=" + url_encode(param(req, k));
}

// Append config + the cmd_<key> command ids (for repoll, where both come off the
// previous poll's query string).
void append_run_params(std::string& url, const httplib::Request& req) {
    append_config_params(url, req);
    for (const auto& c : preflight::kPreflightChecks) {
        const std::string p = std::string("cmd_") + c.key;
        if (req.has_param(p))
            url += "&" + p + "=" + url_encode(req.get_param_value(p));
    }
}

} // namespace

void PreflightRoutes::register_routes(httplib::Server& svr, AuthFn auth_fn, PermFn perm_fn,
                                      DevicesFn devices_fn, GroupsFn groups_fn,
                                      GroupMembersFn group_members_fn, DispatchFn dispatch_fn,
                                      ResponsesAllFn responses_all_fn, AuditFn audit_fn) {
    auth_fn_ = std::move(auth_fn);
    perm_fn_ = std::move(perm_fn);
    devices_fn_ = std::move(devices_fn);
    groups_fn_ = std::move(groups_fn);
    group_members_fn_ = std::move(group_members_fn);
    dispatch_fn_ = std::move(dispatch_fn);
    responses_all_fn_ = std::move(responses_all_fn);
    audit_fn_ = std::move(audit_fn);

    // ── Page shell — auth-only chrome ────────────────────────────────────────
    svr.Get("/auto", [this](const httplib::Request& req, httplib::Response& res) {
        if (!auth_fn_ || !auth_fn_(req, res)) {
            res.status = 401;
            res.set_content("auth required", "text/plain");
            return;
        }
        res.set_content(page_shell("Yuzu \xE2\x80\x94 Pre-flight", "/fragments/auto"),
                        "text/html; charset=utf-8");
    });

    // ── Config fragment ──────────────────────────────────────────────────────
    svr.Get("/fragments/auto", [this](const httplib::Request& req, httplib::Response& res) {
        auto session = auth_fn_ ? auth_fn_(req, res) : std::optional<auth::Session>{};
        if (!session) {
            res.status = 401;
            res.set_content("auth required", "text/plain");
            return;
        }
        if (!perm_fn_ || !perm_fn_(req, res, "Infrastructure", "Read"))
            return;
        std::vector<std::pair<std::string, std::string>> groups;
        if (groups_fn_)
            groups = groups_fn_();
        res.set_content(render_auto_config(groups), "text/html; charset=utf-8");
    });

    // ── Run — dispatch the configured checks to the visible cohort ────────────
    svr.Post("/fragments/auto/run", [this](const httplib::Request& req, httplib::Response& res) {
        auto session = auth_fn_ ? auth_fn_(req, res) : std::optional<auth::Session>{};
        if (!session) {
            res.status = 401;
            res.set_content("auth required", "text/plain");
            return;
        }
        if (!perm_fn_ || !perm_fn_(req, res, "Execution", "Execute"))
            return;
        if (!dispatch_fn_) {
            res.set_content(render_auto_note("Live dispatch is unavailable on this server."),
                            "text/html; charset=utf-8");
            return;
        }
        const auto cfg = config_from_req(req);
        const std::string group_id = param(req, "group");
        const std::string os_filter = param(req, "os_filter");
        auto targets =
            resolve_targets(devices_fn_, group_members_fn_, session->username, group_id, os_filter);
        if (targets.empty()) {
            res.set_content(render_auto_note("No visible devices in that scope."),
                            "text/html; charset=utf-8");
            return;
        }
        std::vector<std::string> agent_ids;
        agent_ids.reserve(targets.size());
        for (const auto& d : targets)
            agent_ids.push_back(d.agent_id);

        // Dispatch each APPLICABLE check (explicit agent_ids, no scope_expr, untracked
        // exec) and thread the command_ids + the config into the result-poll URL.
        std::string poll = "/fragments/auto/result?group=" + url_encode(group_id) + "&n=1";
        int dispatched = 0;
        for (const auto& c : preflight::kPreflightChecks) {
            if (!check_applicable(c.key, cfg))
                continue;
            auto [cmd, reached] = dispatch_fn_(c.plugin, c.action, agent_ids, "", dispatch_params(c.key, cfg));
            (void)reached;
            poll += "&cmd_" + std::string(c.key) + "=" + url_encode(cmd);
            ++dispatched;
        }
        append_config_params(poll, req); // first poll must carry the thresholds too
        if (audit_fn_)
            audit_fn_(req, "preflight.run", "success", "Scope",
                      group_id.empty() ? std::string("all-visible") : group_id,
                      "checks=" + std::to_string(dispatched) +
                          " devices=" + std::to_string(agent_ids.size()));

        // Initial render: every applicable check pending → every device incomplete;
        // the wrapper repolls immediately.
        std::vector<ActiveCheck> active;
        for (const auto& c : preflight::kPreflightChecks)
            if (check_applicable(c.key, cfg))
                active.push_back({c.key, c.label, {}});
        bool any_pending = false;
        auto devices = build_results(targets, active, cfg, any_pending);
        res.set_content(render_auto_results(devices, config_summary(cfg),
                                            scope_label(groups_fn_, group_id), poll),
                        "text/html; charset=utf-8");
    });

    // ── Result poll — apply thresholds + aggregate by check ──────────────────
    svr.Get("/fragments/auto/result", [this](const httplib::Request& req, httplib::Response& res) {
        auto session = auth_fn_ ? auth_fn_(req, res) : std::optional<auth::Session>{};
        if (!session) {
            res.status = 401;
            res.set_content("auth required", "text/plain");
            return;
        }
        if (!perm_fn_ || !perm_fn_(req, res, "Infrastructure", "Read"))
            return;
        if (!responses_all_fn_) {
            res.set_content(render_auto_note("Result store is unavailable on this server."),
                            "text/html; charset=utf-8");
            return;
        }
        const auto cfg = config_from_req(req);
        const std::string group_id = param(req, "group");
        const std::string os_filter = param(req, "os_filter");
        int window_min = static_cast<int>(preflight::parse_i64(param(req, "window")));
        if (window_min <= 0)
            window_min = 30;
        // 700ms cadence; Slice-1 caps page-polling at ~10 min. (Slice 2 makes the
        // window a true server-side run that survives page close + re-dispatches.)
        const int max_attempts = std::clamp(window_min * 86, 40, 860);
        int attempt = 1;
        if (req.has_param("n")) {
            try {
                attempt = std::clamp(std::stoi(req.get_param_value("n")), 1, 2000);
            } catch (...) {
            }
        }
        auto targets =
            resolve_targets(devices_fn_, group_members_fn_, session->username, group_id, os_filter);

        // Which checks are in this run (a cmd_<key> param present) + each agent's
        // best response so far (terminal output / highest status wins).
        std::vector<ActiveCheck> active;
        for (const auto& c : preflight::kPreflightChecks) {
            const std::string p = std::string("cmd_") + c.key;
            if (!req.has_param(p) || req.get_param_value(p).empty())
                continue;
            ActiveCheck ac;
            ac.key = c.key;
            ac.label = c.label;
            for (const auto& r : responses_all_fn_(req.get_param_value(p))) {
                auto& slot = ac.byAgent[r.agent_id];
                const bool better = (!r.output.empty() && slot.second.empty()) || (r.status > slot.first);
                if (better) {
                    slot.first = r.status;
                    slot.second = r.output;
                }
            }
            active.push_back(std::move(ac));
        }

        bool any_pending = false;
        auto devices = build_results(targets, active, cfg, any_pending);

        const bool done = !any_pending || attempt >= max_attempts;
        std::string repoll;
        if (!done) {
            repoll = "/fragments/auto/result?group=" + url_encode(group_id) + "&n=" +
                     std::to_string(attempt + 1);
            append_run_params(repoll, req);
        }
        res.set_content(render_auto_results(devices, config_summary(cfg),
                                            scope_label(groups_fn_, group_id), repoll),
                        "text/html; charset=utf-8");
    });
}

} // namespace yuzu::server
