/// @file test_inventory_routes.cpp
/// Tests for the /inventory dashboard — the PURE renderers (data-in / HTML-out) and
/// the route wiring driven in-process through TestRouteSink (no httplib acceptor,
/// #438). Focus areas: the authoritative-read DEGRADE-≠-EMPTY contract (a nullopt
/// data arg → an "unavailable" banner, never a silent empty table), the FIND per-row
/// management-group scope drop (+ omission audit, mirroring the REST sibling), the
/// per-device scoped-permission gate, and the truncated-cap signal.

#include "inventory_routes.hpp"
#include "test_route_sink.hpp"

#include <catch2/catch_test_macros.hpp>

#include <optional>
#include <string>
#include <vector>

using namespace yuzu::server;

namespace {

bool contains(const std::string& hay, const std::string& needle) {
    return hay.find(needle) != std::string::npos;
}

SoftwareCatalogRow cat_row(std::string n, std::string pub, std::int64_t dev, std::int64_t vers) {
    SoftwareCatalogRow r;
    r.name = std::move(n);
    r.publisher = std::move(pub);
    r.device_count = dev;
    r.version_count = vers;
    return r;
}

SoftwareFleetRow fleet_row(std::string agent, std::string name, std::string ver) {
    SoftwareFleetRow r;
    r.agent_id = std::move(agent);
    r.entry.name = std::move(name);
    r.entry.version = std::move(ver);
    return r;
}

} // namespace

// ───────────────────────── PURE renderers ──────────────────────────────────────

TEST_CASE("software fragment: degrade is a banner, never an empty table", "[inventory][ui]") {
    const std::string degraded = render_inventory_software_fragment(std::nullopt, "", std::nullopt, false);
    REQUIRE(contains(degraded, "unavailable"));
    REQUIRE(contains(degraded, "authoritative"));
    // A degrade must NOT masquerade as a genuine "nothing installed".
    REQUIRE_FALSE(contains(degraded, "No installed-software inventory has been reported"));
}

TEST_CASE("software fragment: genuine empty is an honest note, not a degrade", "[inventory][ui]") {
    const std::string empty = render_inventory_software_fragment(
        std::optional<std::vector<SoftwareCatalogRow>>(std::vector<SoftwareCatalogRow>{}), "",
        std::int64_t{0}, false);
    REQUIRE(contains(empty, "No installed-software inventory has been reported"));
    REQUIRE_FALSE(contains(empty, "unavailable"));
}

TEST_CASE("software fragment: rows render with counts + a drill link", "[inventory][ui]") {
    std::vector<SoftwareCatalogRow> rows{cat_row("Google Chrome", "Google LLC", 1180, 3),
                                         cat_row("7-Zip", "Igor Pavlov", 889, 1)};
    const std::string html =
        render_inventory_software_fragment(rows, "", std::int64_t{37}, /*capped=*/false);
    REQUIRE(contains(html, "Google Chrome"));
    REQUIRE(contains(html, "1180"));
    REQUIRE(contains(html, "Igor Pavlov"));
    // Each row drills into the version breakdown.
    REQUIRE(contains(html, "/fragments/inventory/software/versions?name=Google%20Chrome"));
    // Freshness KPI surfaces the stale count.
    REQUIRE(contains(html, "37"));
    // Fleet-wide scope caveat is present (ADR-0017 honesty).
    REQUIRE(contains(html, "not yet effective"));
}

TEST_CASE("software fragment: capped marks the title count with a '+'", "[inventory][ui]") {
    std::vector<SoftwareCatalogRow> rows{cat_row("A", "p", 1, 1)};
    const std::string html =
        render_inventory_software_fragment(rows, "", std::nullopt, /*capped=*/true);
    REQUIRE(contains(html, "1+"));
    REQUIRE(contains(html, "list capped"));
}

TEST_CASE("versions fragment: degrade banner vs empty vs share bars", "[inventory][ui]") {
    // nullopt = store degrade → banner.
    REQUIRE(contains(render_inventory_versions_fragment("Chrome", std::nullopt), "unavailable"));

    // Empty-non-null (a title since fully uninstalled) = honest empty, NOT a degrade (gov F2).
    const std::string empty = render_inventory_versions_fragment(
        "Chrome", std::optional<std::vector<SoftwareVersionCount>>(std::vector<SoftwareVersionCount>{}));
    REQUIRE(contains(empty, "No version data"));
    REQUIRE_FALSE(contains(empty, "unavailable"));

    // Empty name = precondition miss → "select a title" note, NOT the store-failed banner (gov happy-NICE).
    const std::string noname = render_inventory_versions_fragment("", std::nullopt);
    REQUIRE(contains(noname, "Select a title"));
    REQUIRE_FALSE(contains(noname, "unavailable"));

    std::vector<SoftwareVersionCount> vers{{"126.0", 742}, {"125.0", 301}};
    const std::string html = render_inventory_versions_fragment("Chrome", vers);
    REQUIRE(contains(html, "126.0"));
    REQUIRE(contains(html, "742"));
    REQUIRE(contains(html, "Installs per version"));
    REQUIRE(contains(html, "width:100%")); // the top version is the full-width bar
}

TEST_CASE("device-software fragment: degrade vs empty vs rows; offline note", "[inventory][ui]") {
    REQUIRE(contains(render_inventory_device_software_fragment("a1", "HOST", std::nullopt, true),
                     "unavailable"));

    const std::string empty = render_inventory_device_software_fragment(
        "a1", "HOST", std::optional<std::vector<SoftwareEntry>>(std::vector<SoftwareEntry>{}), true);
    REQUIRE(contains(empty, "No installed software recorded"));
    REQUIRE_FALSE(contains(empty, "unavailable"));

    SoftwareEntry e;
    e.name = "Slack";
    e.version = "4.38";
    const std::string offline = render_inventory_device_software_fragment(
        "a1", "HOST", std::optional<std::vector<SoftwareEntry>>(std::vector<SoftwareEntry>{e}),
        /*online=*/false);
    REQUIRE(contains(offline, "Slack"));
    REQUIRE(contains(offline, "offline")); // the "last daily sync, not live" note
}

TEST_CASE("devices fragment: thin CI list + offline-inclusive rows", "[inventory][ui]") {
    std::vector<InventoryDeviceRow> rows;
    InventoryDeviceRow on;
    on.agent_id = "a1";
    on.hostname = "WIN-1";
    on.os = "windows";
    on.online = true;
    on.last_seen = "now";
    InventoryDeviceRow off;
    off.agent_id = "a2";
    off.hostname = "UB-2";
    off.os = "linux";
    off.online = false;
    off.stale = true;
    off.last_seen = "3d ago";
    rows.push_back(on);
    rows.push_back(off);
    const std::string html = render_inventory_devices_fragment(rows, "", "", "");
    REQUIRE(contains(html, "WIN-1"));
    REQUIRE(contains(html, "UB-2"));      // offline device still appears
    REQUIRE(contains(html, "3d ago"));
    REQUIRE(contains(html, "stale"));
    // The per-device drill carries host + online into the URL.
    REQUIRE(contains(html, "/fragments/inventory/device?id=a1&host=WIN-1&online=1"));
}

TEST_CASE("find results: truncated + omitted signals; degrade vs empty", "[inventory][ui]") {
    REQUIRE(contains(render_inventory_find_results_fragment("X", std::nullopt, false, 0),
                     "unavailable"));

    // Empty (non-null) → honest "no devices in scope", not a degrade.
    const std::string empty = render_inventory_find_results_fragment(
        "X", std::optional<std::vector<SoftwareFleetRow>>(std::vector<SoftwareFleetRow>{}), false, 0);
    REQUIRE(contains(empty, "No devices in your scope"));

    std::vector<SoftwareFleetRow> rows{fleet_row("a1", "X", "1.0")};
    const std::string html = render_inventory_find_results_fragment("X", rows, /*hit_cap=*/true,
                                                                    /*devices_omitted=*/2);
    REQUIRE(contains(html, "truncated at cap"));
    REQUIRE(contains(html, "2 device(s) outside your scope"));
    REQUIRE(contains(html, "a1"));
}

// ───────────────────────── route wiring ────────────────────────────────────────

namespace {

struct InvHarness {
    yuzu::server::test::TestRouteSink sink;
    InventoryRoutes routes;

    bool allow_perm = true;          // global Inventory:Read
    bool allow_scoped = true;        // per-device scoped Inventory:Read
    bool degrade = false;            // make every store provider return nullopt
    std::vector<SoftwareFleetRow> fleet_rows;
    std::vector<std::string> in_scope_agents; // FIND per-row scope predicate allow-list
    std::vector<std::string> audits;          // "action|result"
    std::vector<std::string> audit_full;      // "action|result|target_type|target_id" (parity check)

    InvHarness() {
        auto auth = [](const httplib::Request&, httplib::Response&) {
            return std::optional<auth::Session>(auth::Session{});
        };
        auto perm = [this](const httplib::Request&, httplib::Response& res, const std::string&,
                           const std::string&) {
            if (!allow_perm)
                res.status = 403;
            return allow_perm;
        };
        auto scoped = [this](const httplib::Request&, httplib::Response& res, const std::string&,
                             const std::string&, const std::string&) {
            if (!allow_scoped)
                res.status = 403;
            return allow_scoped;
        };
        auto catalog = [this](const SoftwareCatalogQuery&)
            -> std::optional<std::vector<SoftwareCatalogRow>> {
            if (degrade)
                return std::nullopt;
            return std::vector<SoftwareCatalogRow>{cat_row("Chrome", "Google", 5, 2)};
        };
        auto versions = [this](const std::string&, int)
            -> std::optional<std::vector<SoftwareVersionCount>> {
            if (degrade)
                return std::nullopt;
            return std::vector<SoftwareVersionCount>{{"1.0", 5}};
        };
        auto fleet = [this](const SoftwareFleetQuery&)
            -> std::optional<std::vector<SoftwareFleetRow>> {
            if (degrade)
                return std::nullopt;
            return fleet_rows;
        };
        auto agent_sw = [this](const std::string&) -> std::optional<std::vector<SoftwareEntry>> {
            if (degrade)
                return std::nullopt;
            SoftwareEntry e;
            e.name = "Slack";
            return std::vector<SoftwareEntry>{e};
        };
        auto devices = [](const std::string&) {
            InventoryDeviceRow r;
            r.agent_id = "a1";
            r.hostname = "WIN-1";
            r.os = "windows";
            r.online = true;
            r.last_seen = "now";
            return std::vector<InventoryDeviceRow>{r};
        };
        auto scope = [this](const std::string&, const std::string& agent_id) {
            for (const auto& a : in_scope_agents)
                if (a == agent_id)
                    return true;
            return false;
        };
        auto stale = [this]() -> std::optional<std::int64_t> {
            return degrade ? std::nullopt : std::optional<std::int64_t>(7);
        };
        auto audit = [this](const httplib::Request&, const std::string& a, const std::string& r,
                            const std::string& tt, const std::string& tid, const std::string&) {
            audits.push_back(a + "|" + r);
            audit_full.push_back(a + "|" + r + "|" + tt + "|" + tid);
            return true;
        };
        routes.register_routes(sink, auth, perm, scoped, catalog, versions, fleet, agent_sw, devices,
                               scope, stale, audit);
    }
};

} // namespace

TEST_CASE("route: software fragment denied without Inventory:Read", "[inventory][route]") {
    InvHarness h;
    h.allow_perm = false;
    auto res = h.sink.Get("/fragments/inventory/software");
    REQUIRE(res);
    REQUIRE(res->status == 403);
    REQUIRE_FALSE(contains(res->body, "Chrome"));
}

TEST_CASE("route: software fragment renders catalogue + audits", "[inventory][route]") {
    InvHarness h;
    auto res = h.sink.Get("/fragments/inventory/software");
    REQUIRE(res);
    REQUIRE(contains(res->body, "Chrome"));
    bool audited = false;
    for (const auto& a : h.audits)
        if (a == "inventory.software.catalog|success")
            audited = true;
    REQUIRE(audited);
    // Securable + target_id parity with audit-log.md (gov consistency NICE-1): a rename of
    // the securable or the target shape away from the doc must fail a test.
    bool target_ok = false;
    for (const auto& a : h.audit_full)
        if (a == "inventory.software.catalog|success|Inventory|fleet")
            target_ok = true;
    REQUIRE(target_ok);
}

TEST_CASE("route: software fragment degrade → banner, audited failure", "[inventory][route]") {
    InvHarness h;
    h.degrade = true;
    auto res = h.sink.Get("/fragments/inventory/software");
    REQUIRE(res);
    REQUIRE(contains(res->body, "unavailable"));
    bool failed = false;
    for (const auto& a : h.audits)
        if (a == "inventory.software.catalog|failure")
            failed = true;
    REQUIRE(failed);
}

TEST_CASE("route: per-device drill is scope-gated", "[inventory][route]") {
    InvHarness h;
    h.allow_scoped = false;
    auto denied = h.sink.Get("/fragments/inventory/device?id=a1&host=WIN-1&online=1");
    REQUIRE(denied);
    REQUIRE(denied->status == 403);
    REQUIRE_FALSE(contains(denied->body, "Slack"));

    h.allow_scoped = true;
    auto ok = h.sink.Get("/fragments/inventory/device?id=a1&host=WIN-1&online=1");
    REQUIRE(ok);
    REQUIRE(contains(ok->body, "Slack"));
}

TEST_CASE("route: find results apply the per-row management-group drop filter", "[inventory][route]") {
    InvHarness h;
    // Unambiguous IDs (gov F5): a short literal like "a2" risks incidental HTML matches.
    h.fleet_rows = {fleet_row("agent-alpha", "Chrome", "1.0"),
                    fleet_row("agent-bravo", "Chrome", "2.0")};
    h.in_scope_agents = {"agent-alpha"}; // agent-bravo is out of the operator's scope

    auto res = h.sink.Get("/fragments/inventory/find/results?name=Chrome");
    REQUIRE(res);
    REQUIRE(contains(res->body, "agent-alpha"));
    REQUIRE_FALSE(contains(res->body, "agent-bravo"));   // dropped, not leaked
    REQUIRE(contains(res->body, "1 device(s) outside")); // omission surfaced
    bool denied = false, ok = false;
    for (const auto& a : h.audits) {
        denied = denied || a == "inventory.software.query|denied";
        ok = ok || a == "inventory.software.query|success";
    }
    REQUIRE(denied);
    REQUIRE(ok);
}

TEST_CASE("route: find results empty name short-circuits (no store read)", "[inventory][route]") {
    InvHarness h;
    auto res = h.sink.Get("/fragments/inventory/find/results?name=");
    REQUIRE(res);
    REQUIRE(contains(res->body, "Type an exact software name"));
    // No data read → no audit row (gov compliance NICE / F4 boundary).
    REQUIRE(h.audits.empty());
}

TEST_CASE("route: find results degrade → banner + audited failure", "[inventory][route]") {
    InvHarness h;
    h.degrade = true; // fleet_fn_ returns nullopt for a non-empty name
    auto res = h.sink.Get("/fragments/inventory/find/results?name=Chrome");
    REQUIRE(res);
    REQUIRE(contains(res->body, "unavailable"));
    bool failed = false;
    for (const auto& a : h.audits)
        if (a == "inventory.software.query|failure")
            failed = true;
    REQUIRE(failed);
}

TEST_CASE("route: version drill — deny, success+audit, degrade", "[inventory][route]") {
    {
        InvHarness h;
        h.allow_perm = false;
        auto res = h.sink.Get("/fragments/inventory/software/versions?name=Chrome");
        REQUIRE(res);
        REQUIRE(res->status == 403);
    }
    {
        InvHarness h;
        auto res = h.sink.Get("/fragments/inventory/software/versions?name=Chrome");
        REQUIRE(res);
        REQUIRE(contains(res->body, "Installs per version"));
        bool ok = false;
        for (const auto& a : h.audits)
            if (a == "inventory.software.versions|success")
                ok = true;
        REQUIRE(ok);
    }
    {
        InvHarness h;
        h.degrade = true;
        auto res = h.sink.Get("/fragments/inventory/software/versions?name=Chrome");
        REQUIRE(res);
        REQUIRE(contains(res->body, "unavailable"));
        bool failed = false;
        for (const auto& a : h.audits)
            if (a == "inventory.software.versions|failure")
                failed = true;
        REQUIRE(failed);
    }
}

TEST_CASE("route: devices list — deny vs success (offline-inclusive, list not audited)",
          "[inventory][route]") {
    {
        InvHarness h;
        h.allow_perm = false;
        auto res = h.sink.Get("/fragments/inventory/devices");
        REQUIRE(res);
        REQUIRE(res->status == 403);
        REQUIRE_FALSE(contains(res->body, "WIN-1"));
    }
    {
        InvHarness h;
        auto res = h.sink.Get("/fragments/inventory/devices");
        REQUIRE(res);
        REQUIRE(contains(res->body, "WIN-1"));
        // House convention: the list read is gate-only, not audited (parity with
        // /fragments/devices/list); only the per-device drill audits.
        REQUIRE(h.audits.empty());
    }
}

TEST_CASE("route: find shell gates on Inventory:Read", "[inventory][route]") {
    InvHarness h;
    h.allow_perm = false;
    auto res = h.sink.Get("/fragments/inventory/find");
    REQUIRE(res);
    REQUIRE(res->status == 403);
}
