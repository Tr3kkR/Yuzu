#pragma once

/// @file inventory_routes.hpp
/// Dedicated /inventory dashboard — the SOFTWARE inventory lens (installed-software
/// list: title -> installs -> versions -> installs-per-version, daily-synced,
/// ADR-0016) plus a THIN device-CI inventory tab (host / OS / online / last-seen,
/// sourced from the persisted, offline-survivable endpoint_state store so offline
/// devices still appear) and a fleet "find software" tab (which devices run X).
///
/// The device tab is deliberately thin in round 1: it enriches into a full
/// ServiceNow-style CI record (serial / model / CPU / RAM / MAC / owner ...) once a
/// device-CI daily-sync SOURCE + DeviceInventoryStore land (the same ADR-0016
/// framework installed_software is source #1 of). Clicking a device shows that
/// device's installed software (get_agent_software).
///
/// Product UI: HTMX, server-rendered, dark-theme only, htmx core attrs only (CSP
/// blocks hx-on — onclick/oninput helpers instead). Reuses the shared full-page
/// shell (guardian_page_ui.cpp kGuardianDetailPageHtml) + its `.gp-*` component CSS.
///
/// AUTH: the /inventory page shell is auth-only chrome. The data fragments gate on
/// the GLOBAL `Inventory:Read` (the same securable + scope predicate the REST
/// /api/v1/inventory/software route + the MCP query_installed_software tool use):
///   * SOFTWARE catalogue / version drill / FIND are FLEET-WIDE aggregates — gated on
///     global Inventory:Read; the catalogue/version counts are NOT management-group
///     scoped (ADR-0017 confinement inert under the global gate — caveated in the UI),
///     and FIND applies the same per-row management-group drop filter the REST sibling
///     does (+ audits the omission);
///   * the PER-DEVICE software drill gates on `scoped_perm_fn(Inventory,Read,id)` — the
///     tier + management-group chokepoint — so an operator only reads a device inside
///     their scope, and audits the access (set-and-proceed; machine-scope data, lower
///     sensitivity than the behavioural-PII device lenses).

#include <yuzu/server/auth.hpp>

#include "software_inventory_store.hpp" // SoftwareCatalogRow / SoftwareVersionCount / SoftwareEntry / SoftwareFleetRow / *Query

#include <httplib.h>

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::server {

class HttpRouteSink;

/// One row of the THIN device-CI inventory list. Round-1 fields only — sourced from
/// the persisted endpoint_state store (+ the live registry's online set). The CI
/// columns (serial / model / CPU / RAM / MAC ...) arrive with the device-CI sync
/// source; until then they render greyed/placeholder.
struct InventoryDeviceRow {
    std::string agent_id;
    std::string hostname;
    std::string os;        ///< "windows" | "linux" | "darwin" | "?"
    bool online = false;   ///< has a live Subscribe stream right now (registry)
    std::string last_seen; ///< human-ish ("now", "12m ago", "3d ago"); "" if unknown
    bool stale = false;    ///< last heartbeat older than the staleness window
};

// ── PURE renderers (implemented in inventory_ui.cpp) ─────────────────────────────
// Each returns a self-contained fragment: the inventory sub-nav + the active tab's
// content. A `std::nullopt` data argument is a STORE DEGRADE → an honest
// "data unavailable" banner, NEVER an empty table (authoritative reads, ADR-0016 §7:
// an empty table reads as "installed nowhere" — the fail-open the store forbids).

/// SOFTWARE tab: the fleet catalogue table (title · publisher · installs · versions ·
/// installs-per-version bar) + an empty drill container. `name_filter` is echoed into
/// the search box; `capped` flags that the row set hit the catalogue cap; `stale_count`
/// feeds the freshness KPI (nullopt → "—").
std::string render_inventory_software_fragment(
    const std::optional<std::vector<SoftwareCatalogRow>>& catalogue, const std::string& name_filter,
    std::optional<std::int64_t> stale_count, bool capped);

/// SOFTWARE drill: installs-per-version for one title (the catalogue row click target).
std::string render_inventory_versions_fragment(
    const std::string& name, const std::optional<std::vector<SoftwareVersionCount>>& versions);

/// DEVICES tab (thin CI): the device list + an empty drill container. `q`/`os_token`/
/// `status_token` are echoed into the controls so the fragment is self-describing.
std::string render_inventory_devices_fragment(const std::vector<InventoryDeviceRow>& rows,
                                              const std::string& q, const std::string& os_token,
                                              const std::string& status_token);

/// PER-DEVICE drill: one device's installed software (get_agent_software). `online`
/// drives the "live vs last daily sync" note for an offline device.
std::string render_inventory_device_software_fragment(
    const std::string& agent_id, const std::string& hostname,
    const std::optional<std::vector<SoftwareEntry>>& software, bool online);

/// FIND tab shell: the search box (hx-get -> the results endpoint) + an empty results
/// container. No data read here (the shell is just chrome under Inventory:Read).
std::string render_inventory_find_fragment(const std::string& initial_name);

/// FIND results: which devices run software `name` (already scope-filtered). `hit_cap`
/// flags a truncated page; `devices_omitted` is the management-group drop count.
std::string render_inventory_find_results_fragment(
    const std::string& name, const std::optional<std::vector<SoftwareFleetRow>>& rows, bool hit_cap,
    std::size_t devices_omitted);

/// /inventory routes — the page shell + the read-only HTMX fragments. Providers are
/// injected closures (store-decoupled) so the handlers are unit-testable via
/// TestRouteSink without a live Postgres.
class InventoryRoutes {
public:
    using AuthFn =
        std::function<std::optional<auth::Session>(const httplib::Request&, httplib::Response&)>;
    using PermFn = std::function<bool(const httplib::Request&, httplib::Response&,
                                      const std::string& securable_type, const std::string& operation)>;
    /// Per-device tier + management-group scope gate (wraps require_scoped_permission).
    using ScopedPermFn =
        std::function<bool(const httplib::Request&, httplib::Response&,
                           const std::string& securable_type, const std::string& operation,
                           const std::string& agent_id)>;

    /// FLEET-WIDE software catalogue / version drill / fleet name query. Each returns
    /// nullopt on a store degrade (the renderer shows the banner). Empty closures =
    /// no provider wired → the route renders the "unavailable" state.
    using CatalogFn =
        std::function<std::optional<std::vector<SoftwareCatalogRow>>(const SoftwareCatalogQuery&)>;
    using VersionsFn = std::function<std::optional<std::vector<SoftwareVersionCount>>(
        const std::string& name, int limit)>;
    using FleetSoftwareFn =
        std::function<std::optional<std::vector<SoftwareFleetRow>>(const SoftwareFleetQuery&)>;

    /// One device's installed software (per-device drill, post-authz).
    using AgentSoftwareFn =
        std::function<std::optional<std::vector<SoftwareEntry>>(const std::string& agent_id)>;

    /// The THIN device-CI list, scoped to `username` (offline-inclusive; assembled in
    /// server.cpp from endpoint_state + the registry online set + the visible-agent set).
    using DevicesFn = std::function<std::vector<InventoryDeviceRow>(const std::string& username)>;

    /// Per-(operator, agent) management-group predicate for the FIND per-row scope drop
    /// (the same Inventory:Read scope predicate the REST route uses). Empty = no filter.
    using ScopeFn =
        std::function<bool(const std::string& username, const std::string& agent_id)>;

    /// Current count of agents whose installed_software inventory is stale (freshness
    /// KPI). Empty / nullopt → the KPI renders "—".
    using StaleFn = std::function<std::optional<std::int64_t>()>;

    /// who/when/what audit sink (bool = persisted). Reused from the shared audit_fn.
    using AuditFn = std::function<bool(const httplib::Request& req, const std::string& action,
                                       const std::string& result, const std::string& target_type,
                                       const std::string& target_id, const std::string& detail)>;

    void register_routes(httplib::Server& svr, AuthFn auth_fn, PermFn perm_fn,
                         ScopedPermFn scoped_perm_fn, CatalogFn catalog_fn, VersionsFn versions_fn,
                         FleetSoftwareFn fleet_fn, AgentSoftwareFn agent_sw_fn, DevicesFn devices_fn,
                         ScopeFn scope_fn = {}, StaleFn stale_fn = {}, AuditFn audit_fn = {});

    /// HttpRouteSink overload — testable in-process via TestRouteSink (no httplib
    /// acceptor; the #438 TSan trap). The httplib::Server& overload wraps + delegates.
    void register_routes(HttpRouteSink& sink, AuthFn auth_fn, PermFn perm_fn,
                         ScopedPermFn scoped_perm_fn, CatalogFn catalog_fn, VersionsFn versions_fn,
                         FleetSoftwareFn fleet_fn, AgentSoftwareFn agent_sw_fn, DevicesFn devices_fn,
                         ScopeFn scope_fn = {}, StaleFn stale_fn = {}, AuditFn audit_fn = {});

private:
    AuthFn auth_fn_;
    PermFn perm_fn_;
    ScopedPermFn scoped_perm_fn_;
    CatalogFn catalog_fn_;
    VersionsFn versions_fn_;
    FleetSoftwareFn fleet_fn_;
    AgentSoftwareFn agent_sw_fn_;
    DevicesFn devices_fn_;
    ScopeFn scope_fn_;
    StaleFn stale_fn_;
    AuditFn audit_fn_;
};

} // namespace yuzu::server
