/// @file device_routes.cpp
/// Route registration for the shared device surfaces — `/devices` (list) +
/// `/device?id=` (the entity page) page shells, and the read-only HTMX fragments.
/// Renderers live in device_ui.cpp. SLICE 1 is auth-only (matches the current
/// agent-list posture); later slices add the perm/privacy gates for the behavioural
/// DEX lens + the live pull (see device_routes.hpp header).

#include "device_routes.hpp"

#include "http_route_sink.hpp"

#include <algorithm>
#include <cctype>
#include <string>
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

} // namespace

void DeviceRoutes::register_routes(httplib::Server& svr, AuthFn auth_fn, PermFn perm_fn,
                                   DevicesFn devices_fn) {
    HttplibRouteSink sink(svr);
    register_routes(sink, std::move(auth_fn), std::move(perm_fn), std::move(devices_fn));
}

void DeviceRoutes::register_routes(HttpRouteSink& sink, AuthFn auth_fn, PermFn perm_fn,
                                   DevicesFn devices_fn) {
    auth_fn_ = std::move(auth_fn);
    perm_fn_ = std::move(perm_fn);
    devices_fn_ = std::move(devices_fn);

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

    // -- DEX / Guardian lenses: placeholders until their slices land --
    sink.Get("/fragments/device/dex", [this](const httplib::Request& req, httplib::Response& res) {
        if (!auth_fn_(req, res)) { res.status = 401; res.set_content("auth required", "text/plain"); return; }
        const std::string id = req.has_param("id") ? req.get_param_value("id") : "";
        res.set_content(render_device_lens_placeholder(
                            "dex", id,
                            "The DEX experience lens (reusing the device signal drill + a "
                            "per-device score) lands with the per-device-scoring decision."),
                        "text/html; charset=utf-8");
    });
    sink.Get("/fragments/device/guardian", [this](const httplib::Request& req,
                                                  httplib::Response& res) {
        if (!auth_fn_(req, res)) { res.status = 401; res.set_content("auth required", "text/plain"); return; }
        const std::string id = req.has_param("id") ? req.get_param_value("id") : "";
        res.set_content(render_device_lens_placeholder(
                            "guardian", id,
                            "The Guardian compliance lens (baselines + per-guard state from "
                            "guardian_agent_rule_status) lands next."),
                        "text/html; charset=utf-8");
    });
}

} // namespace yuzu::server
