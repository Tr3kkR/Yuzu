/// @file network_routes.cpp
/// /network route registration — the page shell + the read-only HTMX fragments.
/// Renderers live in network_ui.cpp; the model in network_perf_model.cpp. The
/// data-bearing fragments gate on GuaranteedState:Read; an unwired provider
/// degrades to an honest "unavailable" placeholder (the slice-2 state).

#include "network_routes.hpp"

#include "http_route_sink.hpp"

#include <algorithm>
#include <optional>
#include <string>
#include <utility>

// Shared full-page shell (defined at GLOBAL scope in guardian_page_ui.cpp);
// declared at global scope to match the definition (the symbol is not namespaced).
extern const char* const kGuardianDetailPageHtml;

namespace yuzu::server {

namespace {

std::string unavailable_placeholder() {
    return "<div class=\"gp-placeholder\"><b>Network telemetry unavailable</b>"
           "This server has no network snapshot provider wired yet.</div>";
}

} // namespace

void NetworkRoutes::register_routes(httplib::Server& svr, AuthFn auth_fn, PermFn perm_fn,
                                    PerfFn perf_fn) {
    // Production adapter: wrap the httplib server in the route-sink seam and
    // delegate to the testable overload (mirrors DexRoutes / GuardianRoutes).
    HttplibRouteSink sink(svr);
    register_routes(sink, std::move(auth_fn), std::move(perm_fn), std::move(perf_fn));
}

void NetworkRoutes::register_routes(HttpRouteSink& sink, AuthFn auth_fn, PermFn perm_fn,
                                    PerfFn perf_fn) {
    auth_fn_ = std::move(auth_fn);
    perm_fn_ = std::move(perm_fn);
    perf_fn_ = std::move(perf_fn);

    // -- Page shell (auth-only static chrome; the fragment it loads gates on Read) --
    sink.Get("/network", [this](const httplib::Request& req, httplib::Response& res) {
        auto session = auth_fn_(req, res);
        if (!session) {
            res.set_redirect("/login");
            return;
        }
        std::string html(kGuardianDetailPageHtml);
        auto sub = [&](const std::string& tok, const std::string& val) {
            for (auto p = html.find(tok); p != std::string::npos; p = html.find(tok, p + val.size()))
                html.replace(p, tok.size(), val);
        };
        sub("{{TITLE}}", "Yuzu \xE2\x80\x94 Network");
        sub("{{FRAGMENT}}", "/fragments/network/overview");
        // The shared shell marks Guardian active by default; on /network the
        // Network link is the active one. Plain string swaps on static chrome.
        sub("<a href=\"/guardian\" class=\"nav-link active\">Guardian</a>",
            "<a href=\"/guardian\" class=\"nav-link\">Guardian</a>");
        sub("<a href=\"/network\" class=\"nav-link\">Network</a>",
            "<a href=\"/network\" class=\"nav-link active\">Network</a>");
        res.set_header("Cache-Control", "no-cache, no-store, must-revalidate");
        res.set_content(std::move(html), "text/html; charset=utf-8");
    });

    // -- Overview fragment (gates on GuaranteedState:Read) --
    sink.Get("/fragments/network/overview", [this](const httplib::Request& req,
                                                   httplib::Response& res) {
        if (!perm_fn_(req, res, "GuaranteedState", "Read"))
            return;
        if (!perf_fn_) {
            res.set_content(unavailable_placeholder(), "text/html; charset=utf-8");
            return;
        }
        std::string key = req.has_param("key") ? req.get_param_value("key") : "";
        if (key.size() > 64) // light guard; the provider validates against TagStore
            key.clear();
        res.set_content(render_network_overview_fragment(perf_fn_(key)),
                        "text/html; charset=utf-8");
    });

    // -- Devices drill (worst-by-metric / co-occurrence band / not-reporting / cohort) --
    sink.Get("/fragments/network/devices", [this](const httplib::Request& req,
                                                  httplib::Response& res) {
        if (!perm_fn_(req, res, "GuaranteedState", "Read"))
            return;
        if (!perf_fn_) {
            res.set_content(unavailable_placeholder(), "text/html; charset=utf-8");
            return;
        }
        const NetPerfMetric metric = net_perf_metric_from_token(
            req.has_param("metric") ? req.get_param_value("metric") : "rtt");
        const bool not_reporting =
            req.has_param("filter") && req.get_param_value("filter") == "not_reporting";
        const NetCoocFilter cooc =
            req.has_param("cooc") ? net_cooc_from_token(req.get_param_value("cooc"))
                                  : NetCoocFilter::kNone;
        std::optional<std::string> cohort_filter;
        if (req.has_param("cohort_value"))
            cohort_filter = req.get_param_value("cohort_value");
        std::string key = req.has_param("key") ? req.get_param_value("key") : "";
        if (key.size() > 64)
            key.clear();
        int limit = 50;
        if (req.has_param("limit")) {
            try {
                limit = std::clamp(std::stoi(req.get_param_value("limit")), 1, 500);
            } catch (...) {}
        }
        res.set_content(render_network_devices_fragment(perf_fn_(key), metric, not_reporting, cooc,
                                                        cohort_filter, limit),
                        "text/html; charset=utf-8");
    });
}

} // namespace yuzu::server
