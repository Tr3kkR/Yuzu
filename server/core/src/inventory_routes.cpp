/// @file inventory_routes.cpp
/// /inventory route registration — the page shell + the read-only HTMX fragments.
/// Renderers live in inventory_ui.cpp. SOFTWARE catalogue / version drill / FIND are
/// FLEET-WIDE aggregates gated on the GLOBAL Inventory:Read; FIND additionally applies
/// the per-row management-group drop filter (+ omission audit) the REST sibling does.
/// The PER-DEVICE software drill gates on scoped_perm_fn(Inventory,Read,id) and audits
/// the access (set-and-proceed — machine-scope data, lower sensitivity than the
/// behavioural-PII device lenses). An unwired provider degrades to an honest banner.

#include "inventory_routes.hpp"

#include "http_route_sink.hpp"
#include "rest_audit.hpp" // detail::try_persist_audit — throw-safe set-and-proceed audit kernel (#1647)

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <utility>

// Shared full-page shell (defined at GLOBAL scope in guardian_page_ui.cpp).
extern const char* const kGuardianDetailPageHtml;

namespace yuzu::server {

namespace {

// Clamp a `limit` query param into [1, hi] in 64-bit BEFORE narrowing, so a
// negative/wrapped value can't defeat the cap (mirrors the REST route).
int clamp_limit(const httplib::Request& req, int dflt, int hi) {
    if (!req.has_param("limit"))
        return dflt;
    try {
        std::int64_t want = std::stoll(req.get_param_value("limit"));
        return static_cast<int>(std::clamp<std::int64_t>(want, 1, hi));
    } catch (...) {
        return dflt;
    }
}

void send_html(httplib::Response& res, std::string body) {
    res.set_content(std::move(body), "text/html; charset=utf-8");
}

} // namespace

void InventoryRoutes::register_routes(httplib::Server& svr, AuthFn auth_fn, PermFn perm_fn,
                                      ScopedPermFn scoped_perm_fn, CatalogFn catalog_fn,
                                      CatalogMetaFn catalog_meta_fn, VersionsFn versions_fn,
                                      FleetSoftwareFn fleet_fn, AgentSoftwareFn agent_sw_fn,
                                      DevicesFn devices_fn, ScopeFn scope_fn, StaleFn stale_fn,
                                      AuditFn audit_fn) {
    HttplibRouteSink sink(svr);
    register_routes(sink, std::move(auth_fn), std::move(perm_fn), std::move(scoped_perm_fn),
                    std::move(catalog_fn), std::move(catalog_meta_fn), std::move(versions_fn),
                    std::move(fleet_fn), std::move(agent_sw_fn), std::move(devices_fn),
                    std::move(scope_fn), std::move(stale_fn), std::move(audit_fn));
}

void InventoryRoutes::register_routes(HttpRouteSink& sink, AuthFn auth_fn, PermFn perm_fn,
                                      ScopedPermFn scoped_perm_fn, CatalogFn catalog_fn,
                                      CatalogMetaFn catalog_meta_fn, VersionsFn versions_fn,
                                      FleetSoftwareFn fleet_fn, AgentSoftwareFn agent_sw_fn,
                                      DevicesFn devices_fn, ScopeFn scope_fn, StaleFn stale_fn,
                                      AuditFn audit_fn) {
    auth_fn_ = std::move(auth_fn);
    perm_fn_ = std::move(perm_fn);
    scoped_perm_fn_ = std::move(scoped_perm_fn);
    catalog_fn_ = std::move(catalog_fn);
    catalog_meta_fn_ = std::move(catalog_meta_fn);
    versions_fn_ = std::move(versions_fn);
    fleet_fn_ = std::move(fleet_fn);
    agent_sw_fn_ = std::move(agent_sw_fn);
    devices_fn_ = std::move(devices_fn);
    scope_fn_ = std::move(scope_fn);
    stale_fn_ = std::move(stale_fn);
    audit_fn_ = std::move(audit_fn);

    // -- Page shell (auth-only static chrome; the fragments gate on Inventory:Read) --
    sink.Get("/inventory", [this](const httplib::Request& req, httplib::Response& res) {
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
        sub("{{TITLE}}", "Yuzu \xE2\x80\x94 Inventory");
        sub("{{FRAGMENT}}", "/fragments/inventory/software");
        // Mark the Inventory nav item active, Guardian (the shell default) inactive.
        sub("<a href=\"/guardian\" class=\"nav-link active\">Guardian</a>",
            "<a href=\"/guardian\" class=\"nav-link\">Guardian</a>");
        sub("<a href=\"/inventory\" class=\"nav-link\">Inventory</a>",
            "<a href=\"/inventory\" class=\"nav-link active\">Inventory</a>");
        res.set_header("Cache-Control", "no-cache, no-store, must-revalidate");
        send_html(res, std::move(html));
    });

    // -- SOFTWARE catalogue (fleet-wide aggregate; global Inventory:Read) --
    sink.Get("/fragments/inventory/software",
             [this](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn_(req, res, "Inventory", "Read"))
                     return;
                 SoftwareCatalogQuery q;
                 q.name_filter = req.has_param("q") ? req.get_param_value("q") : "";
                 q.limit = clamp_limit(req, 200, 2000);
                 std::optional<std::vector<SoftwareCatalogRow>> cat;
                 if (catalog_fn_)
                     cat = catalog_fn_(q);
                 std::optional<CatalogRollupMeta> meta;
                 if (catalog_meta_fn_)
                     meta = catalog_meta_fn_();
                 const bool capped = cat && static_cast<int>(cat->size()) == q.limit;
                 std::optional<std::int64_t> stale;
                 if (stale_fn_)
                     stale = stale_fn_();
                 const std::int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
                                              std::chrono::system_clock::now().time_since_epoch())
                                              .count();
                 // Set-and-proceed audit via the #1647 throw-safe kernel (a throwing
                 // audit sink → false, never an httplib 500): parity with the REST sibling.
                 (void)detail::try_persist_audit(
                     audit_fn_, req, "inventory.software.catalog", cat ? "success" : "failure",
                     "Inventory", q.name_filter.empty() ? "fleet" : ("q=" + q.name_filter),
                     cat ? ("titles=" + std::to_string(cat->size())) : "store degraded");
                 send_html(res, render_inventory_software_fragment(cat, meta, q.name_filter, stale,
                                                                   capped, now));
             });

    // -- SOFTWARE version drill (installs per version for one title) --
    sink.Get("/fragments/inventory/software/versions",
             [this](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn_(req, res, "Inventory", "Read"))
                     return;
                 const std::string name = req.has_param("name") ? req.get_param_value("name") : "";
                 std::optional<std::vector<SoftwareVersionCount>> vers;
                 if (versions_fn_ && !name.empty())
                     vers = versions_fn_(name, 500);
                 if (!name.empty())
                     (void)detail::try_persist_audit(
                         audit_fn_, req, "inventory.software.versions", vers ? "success" : "failure",
                         "Inventory", "name=" + name,
                         vers ? ("versions=" + std::to_string(vers->size())) : "store degraded");
                 send_html(res, render_inventory_versions_fragment(name, vers));
             });

    // -- DEVICES (thin CI list; global Inventory:Read, scoped provider) --
    sink.Get("/fragments/inventory/devices",
             [this](const httplib::Request& req, httplib::Response& res) {
                 auto session = auth_fn_(req, res);
                 if (!session)
                     return;
                 if (!perm_fn_(req, res, "Inventory", "Read"))
                     return;
                 std::vector<InventoryDeviceRow> rows;
                 if (devices_fn_)
                     rows = devices_fn_(session->username);
                 // Audit the identity-bearing roster read (hostnames + agent_ids) for parity
                 // with the other inventory surfaces (gov review #1759). Set-and-proceed via
                 // the throw-safe kernel — scope-confined at devices_fn_, machine-scope data.
                 (void)detail::try_persist_audit(audit_fn_, req, "inventory.devices", "success",
                                                 "Inventory", "fleet",
                                                 "devices=" + std::to_string(rows.size()));
                 send_html(res, render_inventory_devices_fragment(rows, "", "", ""));
             });

    // -- PER-DEVICE software drill (scoped per-device; audited) --
    sink.Get("/fragments/inventory/device",
             [this](const httplib::Request& req, httplib::Response& res) {
                 const std::string id = req.has_param("id") ? req.get_param_value("id") : "";
                 const std::string host = req.has_param("host") ? req.get_param_value("host") : "";
                 const bool online =
                     req.has_param("online") && req.get_param_value("online") == "1";
                 if (id.empty()) {
                     res.status = 400;
                     send_html(res, "<div class=\"inv-empty\">Missing device id.</div>");
                     return;
                 }
                 // Tier + management-group scope gate (writes 403 on deny).
                 if (!scoped_perm_fn_(req, res, "Inventory", "Read", id))
                     return;
                 std::optional<std::vector<SoftwareEntry>> sw;
                 if (agent_sw_fn_)
                     sw = agent_sw_fn_(id);
                 // Set-and-proceed audit (machine-scope data; HTML surface still renders)
                 // via the #1647 throw-safe kernel.
                 (void)detail::try_persist_audit(
                     audit_fn_, req, "inventory.device.software", sw ? "success" : "failure",
                     "Inventory", "agent=" + id,
                     sw ? ("rows=" + std::to_string(sw->size())) : "store degraded");
                 send_html(res, render_inventory_device_software_fragment(id, host, sw, online));
             });

    // -- FIND shell (search box + empty results container) --
    sink.Get("/fragments/inventory/find",
             [this](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn_(req, res, "Inventory", "Read"))
                     return;
                 const std::string init = req.has_param("name") ? req.get_param_value("name") : "";
                 send_html(res, render_inventory_find_fragment(init));
             });

    // -- FIND results (which devices run X; per-row management-group scope filter) --
    sink.Get("/fragments/inventory/find/results",
             [this](const httplib::Request& req, httplib::Response& res) {
                 auto session = auth_fn_(req, res);
                 if (!session)
                     return;
                 if (!perm_fn_(req, res, "Inventory", "Read"))
                     return;
                 const std::string name = req.has_param("name") ? req.get_param_value("name") : "";
                 SoftwareFleetQuery q;
                 q.name = name;
                 q.limit = clamp_limit(req, 1000, 1000);
                 std::optional<std::vector<SoftwareFleetRow>> rows_opt;
                 if (fleet_fn_ && !name.empty())
                     rows_opt = fleet_fn_(q);

                 if (name.empty()) {
                     // No name → no data read → nothing to audit (the renderer prompts for input).
                     send_html(res, render_inventory_find_results_fragment(name, std::nullopt, false, 0));
                     return;
                 }
                 if (!rows_opt) {
                     (void)detail::try_persist_audit(audit_fn_, req, "inventory.software.query",
                                                     "failure", "Inventory", "name=" + name,
                                                     "store degraded");
                     send_html(res,
                               render_inventory_find_results_fragment(name, std::nullopt, false, 0));
                     return;
                 }
                 auto& rows = *rows_opt;
                 // Cap hit captured BEFORE the scope filter shrinks `rows` (mirrors REST).
                 const bool hit_cap = static_cast<int>(rows.size()) == q.limit;

                 // Per-agent management-group drop filter (mirrors the REST route / MCP tool):
                 // memoised per distinct agent_id. Unwired (RBAC-off / test) → no filter.
                 std::size_t dropped = 0;
                 if (scope_fn_) {
                     std::unordered_map<std::string, bool> memo;
                     std::vector<SoftwareFleetRow> visible;
                     visible.reserve(rows.size());
                     for (auto& r : rows) {
                         auto [m, inserted] = memo.try_emplace(r.agent_id, false);
                         if (inserted)
                             m->second = scope_fn_(session->username, r.agent_id);
                         if (m->second)
                             visible.push_back(std::move(r));
                         else if (inserted)
                             ++dropped;
                     }
                     rows.swap(visible);
                 }
                 // Set-and-proceed via the throw-safe kernel. A scope drop emits BOTH a
                 // `denied` row (the dropped count, for cross-operator isolation evidence)
                 // AND the `success` row for the visible rows — mirrors the REST sibling.
                 if (dropped > 0)
                     (void)detail::try_persist_audit(
                         audit_fn_, req, "inventory.software.query", "denied", "Inventory",
                         "name=" + name,
                         "scope: filtered " + std::to_string(dropped) +
                             " out-of-management-group device(s)");
                 (void)detail::try_persist_audit(audit_fn_, req, "inventory.software.query", "success",
                                                 "Inventory", "name=" + name,
                                                 "rows=" + std::to_string(rows.size()));
                 send_html(res,
                           render_inventory_find_results_fragment(name, rows_opt, hit_cap, dropped));
             });
}

} // namespace yuzu::server
