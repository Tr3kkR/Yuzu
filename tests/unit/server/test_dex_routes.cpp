/**
 * test_dex_routes.cpp — DEX dashboard render + route gating (multi-signal).
 *
 * Pure render tests against a seeded GuaranteedStateStore:
 *   - null / empty store renders the "no data" placeholder (NO mock data)
 *   - a seeded store renders REAL aggregations (signals / apps / boot / modules)
 *   - crash-free-% computes from the fleet denominator; no denominator → honest "—"
 *   - hang column + boot panel + friendly signal labels (incl. unknown-type fallback)
 *   - agent-reported values are HTML-escaped (no stored XSS)
 *   - route gating: authed renders / unauth → 302 / perm-denied → 403 before audit
 */
#include "dex_routes.hpp"
#include "guaranteed_state_store.hpp"
#include "test_route_sink.hpp"

#include <catch2/catch_test_macros.hpp>

#include <optional>
#include <string>

using namespace yuzu::server;

namespace {
void seed_signal(GuaranteedStateStore& store, const std::string& id, const std::string& agent,
                 const std::string& type, const std::string& detail_json, const std::string& ts) {
    GuaranteedStateEventRow e;
    e.event_id = id;
    e.rule_id = "__observation__";
    e.agent_id = agent;
    e.event_type = type;
    e.severity = "info";
    e.detail_json = detail_json;
    e.timestamp = ts;
    REQUIRE(store.insert_event(e));
}

void seed_crash(GuaranteedStateStore& store, const std::string& id, const std::string& agent,
                const std::string& proc, const std::string& mod, const std::string& plat,
                const std::string& ts) {
    seed_signal(store, id, agent, "process.crashed",
                "{\"subject\":\"" + proc + "\",\"reason\":\"0xC0000005\","
                "\"symbolic\":\"ACCESS_VIOLATION\",\"component\":\"" + mod +
                "\",\"platform\":\"" + plat + "\"}",
                ts);
}

void seed_hang(GuaranteedStateStore& store, const std::string& id, const std::string& agent,
               const std::string& proc, const std::string& ts) {
    seed_signal(store, id, agent, "process.hung",
                "{\"subject\":\"" + proc + "\",\"symbolic\":\"NOT_RESPONDING\","
                "\"platform\":\"windows\"}",
                ts);
}

void seed_boot(GuaranteedStateStore& store, const std::string& id, const std::string& agent,
               double ms, const std::string& ts) {
    seed_signal(store, id, agent, "os.boot",
                "{\"subject\":\"boot\",\"metric\":" + std::to_string(ms) +
                    ",\"platform\":\"windows\"}",
                ts);
}
} // namespace

TEST_CASE("DEX overview: null store renders no-data placeholder", "[dex][routes]") {
    auto html = render_dex_overview_fragment(nullptr, "", 7, DexFleet{});
    CHECK(html.find("gp-placeholder") != std::string::npos);
    CHECK(html.find("unavailable") != std::string::npos);
}

TEST_CASE("DEX overview: empty store still lists ALL 103 monitored signal types, grouped",
          "[dex][routes]") {
    // Visibility contract (Dave 2026-06-10): operators must see what the fleet
    // is MONITORING, not just what fired — every catalogued type renders inside
    // its group, quiet ones as muted real-zero rows. Zeros are facts, not mock
    // data. This label list mirrors kAllObsTypes in test_dex_signals.cpp — the
    // two-sided drift net for catalogue additions.
    GuaranteedStateStore store(":memory:");
    auto html = render_dex_overview_fragment(&store, "", 7, DexFleet{});

    // The 12 group headings.
    for (const char* group :
         {"App reliability", "Boot, start-up &amp; shutdown", "Service health",
          "System stability", "Hardware &amp; storage", "File system", "Network",
          "Identity &amp; logon", "Security &amp; protection", "Updates &amp; installs",
          "Policy &amp; management", "Printing"})
        CHECK(html.find(group) != std::string::npos);

    // All 70 labels.
    for (const char* label :
         {// wave 1
          "App crash", "App hang", "Service crash", "Service start failure",
          "Blue screen (bugcheck)", "Unexpected reboot", "Display driver reset",
          "Hardware error", "Disk error", "Filesystem corruption", "Memory exhaustion",
          ">Boot<", "Update failure", "App install failure", "Profile failure",
          "Group Policy failure", "Wi-Fi disconnect", "DNS timeout", "IP address conflict",
          "Print failure",
          // wave 2
          "Slow boot: application", "Slow boot: driver", "Slow boot: service",
          "Slow boot: device", ">Shutdown<", "Slow shutdown: application", "Standby/resume",
          "Slow resume", "Slow logon (subscriber)", "Uptime report", "Dirty shutdown",
          "Clock unsynchronized", "Windows activation failure", "Shadow copy error",
          "Registry hive recovered", "Disk check at boot", "App crash (.NET)",
          "App dependency error", "App activation failure", "COM server failure",
          "Error dialog shown", "App blocked shutdown", "Service hung",
          "Service start timeout", "Service logon failure", "Service recovery failure",
          "Disk SMART warning", "Storage port reset", "Lost delayed write",
          "Database corruption", "Device start failure", "CPU throttled",
          "Wi-Fi connect failure", "DHCP failure", "VPN failure", "File share failure",
          "Name conflict", "No domain controller", "Kerberos error",
          "Profile unload blocked", "Folder redirection failure", "Real-time protection off",
          "Malware detected", "AV update failure", "Tamper attempt blocked",
          "App uninstall failure", "Store app install failure", "Download failure (BITS)",
          "Printer driver failure", "Print spooler plug-in failure",
          // wave 3
          "Fast startup failure", "Resume from sleep", "Restart initiated",
          "Restore points lost", "Crash dump disabled", "Window manager exited",
          "App file-access failure", "Notification platform error", "File association reset",
          "App repository error", "Service dependency failure", "Disk flush failure",
          "Peripheral driver error", "TPM error", "TCP port exhaustion", "Share write lost",
          "DNS registration failure", "Remote session disconnect", "Logon process terminated",
          "Machine trust failure", "Biometric sensor error", "Windows Hello error",
          "Entra ID token error", "Authentication error", "TLS failure",
          "Threat removal failure", "Protection engine error", "BitLocker error",
          "Certificate enrollment failure", "Update check failure", "Update download failure",
          "Policy extension failure", "MDM/Intune error"})
        CHECK(html.find(label) != std::string::npos);

    CHECK(html.find("All 103 monitored signal types") != std::string::npos);
    // No fabricated numbers: quiet rows carry a literal zero count.
    CHECK(html.find("<td class=\"gp-num\">0</td>") != std::string::npos);
}

TEST_CASE("DEX overview: renders real multi-signal aggregations", "[dex][routes]") {
    GuaranteedStateStore store(":memory:");
    seed_crash(store, "e1", "WS-1", "chrome.exe", "ntdll.dll", "windows", "2026-06-08T10:00:00Z");
    seed_crash(store, "e2", "WS-1", "chrome.exe", "ntdll.dll", "windows", "2026-06-08T11:00:00Z");
    seed_hang(store, "e3", "WS-2", "chrome.exe", "2026-06-09T09:00:00Z");
    seed_signal(store, "e4", "WS-2", "service.crashed",
                R"({"subject":"Spooler","reason":"7031","symbolic":"SERVICE_CRASHED","platform":"windows"})",
                "2026-06-09T10:00:00Z");
    seed_boot(store, "e5", "WS-1", 43210.0, "2026-06-09T08:00:00Z");
    seed_boot(store, "e6", "WS-2", 91000.0, "2026-06-09T08:05:00Z");

    auto html = render_dex_overview_fragment(&store, "", 7, DexFleet{10, 12});
    CHECK(html.find("Digital Employee Experience") != std::string::npos);
    // All-signals rollup with FRIENDLY labels.
    CHECK(html.find("All signals") != std::string::npos);
    CHECK(html.find("App crash") != std::string::npos);
    CHECK(html.find("App hang") != std::string::npos);
    CHECK(html.find("Service crash") != std::string::npos);
    // App reliability table spans crashes + hangs.
    CHECK(html.find("App reliability") != std::string::npos);
    CHECK(html.find("chrome.exe") != std::string::npos);
    CHECK(html.find("Hangs") != std::string::npos);
    // Boot panel from the metric column.
    CHECK(html.find("Boot performance") != std::string::npos);
    CHECK(html.find("Average boot") != std::string::npos);
    CHECK(html.find("91.0 s") != std::string::npos); // slowest boot, humanised
    // Crash detail panels still present.
    CHECK(html.find("ntdll.dll") != std::string::npos);
    CHECK(html.find("WS-1") != std::string::npos);
    CHECK(html.find("gp-table") != std::string::npos);
}

TEST_CASE("DEX overview: unknown obs_type falls back to the raw label under 'Other'",
          "[dex][routes]") {
    // Forward-compat: a signal added agent-side renders with NO server change,
    // grouped under "Other".
    GuaranteedStateStore store(":memory:");
    seed_signal(store, "e1", "WS-1", "future.signal_type",
                R"({"subject":"thing","platform":"windows"})", "2026-06-09T10:00:00Z");
    auto html = render_dex_overview_fragment(&store, "", 7, DexFleet{4, 5});
    CHECK(html.find("future.signal_type") != std::string::npos);
    CHECK(html.find(">Other") != std::string::npos);
}

TEST_CASE("DEX overview: crash-free rate from fleet denominator; none → honest no-data",
          "[dex][routes]") {
    GuaranteedStateStore store(":memory:");
    seed_crash(store, "e1", "WS-1", "chrome.exe", "ntdll.dll", "windows", "2026-06-08T10:00:00Z");

    // 1 device impacted of 4 reporting Windows agents → crash-free 75.0%.
    auto html = render_dex_overview_fragment(&store, "", 7, DexFleet{4, 5});
    CHECK(html.find("75.0%") != std::string::npos);
    CHECK(html.find("Crash-free devices") != std::string::npos);
    CHECK(html.find("Crashes / 1k device-days") != std::string::npos);

    // No denominator → no fabricated rate.
    auto html2 = render_dex_overview_fragment(&store, "", 7, DexFleet{0, 0});
    CHECK(html2.find("75.0%") == std::string::npos);
    CHECK(html2.find("no reporting agents") != std::string::npos);
}

TEST_CASE("DEX overview: hangs alone keep the crash-free rate honest (100%)",
          "[dex][routes]") {
    // A hang is not a crash: the headline crash-free rate must stay crash-scoped.
    GuaranteedStateStore store(":memory:");
    seed_hang(store, "e1", "WS-1", "Teams.exe", "2026-06-09T09:00:00Z");
    auto html = render_dex_overview_fragment(&store, "", 7, DexFleet{4, 5});
    CHECK(html.find("100.0%") != std::string::npos); // 0 crash-impacted of 4
    CHECK(html.find("App hang") != std::string::npos); // but the hang IS surfaced
}

TEST_CASE("DEX overview: escapes nasty subjects (no XSS)", "[dex][routes][security]") {
    GuaranteedStateStore store(":memory:");
    seed_crash(store, "e1", "WS-1", "<img src=x onerror=alert(1)>", "ntdll.dll", "windows",
               "2026-06-08T10:00:00Z");
    auto html = render_dex_overview_fragment(&store, "", 7, DexFleet{10, 12});
    CHECK(html.find("<img src=x") == std::string::npos);     // raw tag must not appear
    CHECK(html.find("&lt;img src=x") != std::string::npos);  // escaped form does
}

TEST_CASE("DEX app drill-down: blast radius + hangs + modules + exceptions + devices",
          "[dex][routes]") {
    GuaranteedStateStore store(":memory:");
    seed_crash(store, "e1", "WS-1", "chrome.exe", "ntdll.dll", "windows", "2026-06-08T10:00:00Z");
    seed_crash(store, "e2", "WS-2", "chrome.exe", "chrome.dll", "windows", "2026-06-09T10:00:00Z");
    seed_hang(store, "e3", "WS-2", "chrome.exe", "2026-06-09T11:00:00Z");

    auto html = render_dex_app_fragment(&store, "chrome.exe", "");
    CHECK(html.find("chrome.exe") != std::string::npos);
    CHECK(html.find("Devices affected") != std::string::npos);
    CHECK(html.find("Hangs") != std::string::npos); // crash + hang summary tiles
    CHECK(html.find("Faulting modules") != std::string::npos);
    CHECK(html.find("Exceptions") != std::string::npos);
    CHECK(html.find("Affected devices") != std::string::npos);
    CHECK(html.find("ntdll.dll") != std::string::npos);
    CHECK(html.find("ACCESS_VIOLATION") != std::string::npos);
    CHECK(html.find("/fragments/dex/device?id=WS-1") != std::string::npos); // drill to device
}

TEST_CASE("DEX app drill-down: unknown app → no-crashes placeholder", "[dex][routes]") {
    GuaranteedStateStore store(":memory:");
    auto html = render_dex_app_fragment(&store, "nope.exe", "");
    CHECK(html.find("No crashes") != std::string::npos);
}

TEST_CASE("DEX device drill-down: friendly multi-signal history (UP-4)",
          "[dex][routes]") {
    GuaranteedStateStore store(":memory:");
    seed_crash(store, "e1", "WS-7", "AcmeCRM.exe", "AcmeCRM.dll", "windows",
               "2026-06-08T10:00:00Z");
    seed_signal(store, "e2", "WS-7", "service.crashed",
                R"({"subject":"Spooler","reason":"7031","symbolic":"SERVICE_CRASHED","platform":"windows"})",
                "2026-06-09T10:00:00Z");
    seed_boot(store, "e3", "WS-7", 43210.0, "2026-06-09T08:00:00Z");

    auto html = render_dex_device_fragment(&store, "WS-7", "");
    CHECK(html.find("Behavioral data") == std::string::npos); // banner removed (Dave 2026-06-10);
                                                              // the gate + audit remain route-side
    CHECK(html.find("Signal history") != std::string::npos);
    CHECK(html.find("AcmeCRM.exe") != std::string::npos);
    CHECK(html.find("ACCESS_VIOLATION") != std::string::npos);
    // Friendly labels for non-crash rows; boot rows show the humanised duration
    // (>=10 s renders as seconds).
    CHECK(html.find("Service crash") != std::string::npos);
    CHECK(html.find("43.2 s") != std::string::npos);
    CHECK(html.find("__observation__") == std::string::npos); // friendly rows, not the sentinel
}

TEST_CASE("DEX device drill-down: escapes agent_id + subject (no XSS)",
          "[dex][routes][security]") {
    GuaranteedStateStore store(":memory:");
    seed_crash(store, "e1", "<b>evil</b>", "<img src=x>", "ntdll.dll", "windows",
               "2026-06-08T10:00:00Z");
    auto html = render_dex_device_fragment(&store, "<b>evil</b>", "");
    CHECK(html.find("<b>evil</b>") == std::string::npos);
    CHECK(html.find("&lt;b&gt;evil") != std::string::npos);
}

TEST_CASE("DEX routes: auth/perm gating + dispatch", "[dex][routes][rbac]") {
    GuaranteedStateStore store(":memory:");
    seed_crash(store, "e1", "WS-1", "chrome.exe", "ntdll.dll", "windows", "2026-06-08T10:00:00Z");

    auto okAuth = [](const httplib::Request&, httplib::Response&) {
        return std::optional<auth::Session>(auth::Session{});
    };
    auto noAuth = [](const httplib::Request&, httplib::Response&) {
        return std::optional<auth::Session>(std::nullopt);
    };
    auto okPerm = [](const httplib::Request&, httplib::Response&, const std::string&,
                     const std::string&) { return true; };
    auto noPerm = [](const httplib::Request&, httplib::Response& res, const std::string&,
                     const std::string&) {
        res.status = 403;
        return false;
    };
    auto fleet = []() { return DexFleet{4, 5}; };
    std::string audited;
    auto audit = [&](const httplib::Request&, const std::string& a, const std::string&,
                     const std::string&, const std::string& tid, const std::string&) {
        audited = a + "|" + tid;
    };

    SECTION("authed shell + permitted fragments render") {
        yuzu::server::test::TestRouteSink sink;
        DexRoutes routes;
        routes.register_routes(sink, okAuth, okPerm, &store, fleet, audit);

        auto page = sink.Get("/dex");
        REQUIRE(page);
        CHECK(page->status == 200);
        CHECK(page->body.find("/fragments/dex/overview") != std::string::npos);

        auto ov = sink.Get("/fragments/dex/overview?window=7d");
        REQUIRE(ov);
        CHECK(ov->status == 200);
        CHECK(ov->body.find("chrome.exe") != std::string::npos);

        auto app = sink.Get("/fragments/dex/app?name=chrome.exe");
        REQUIRE(app);
        CHECK(app->body.find("Faulting modules") != std::string::npos);

        auto dev = sink.Get("/fragments/dex/device?id=WS-1");
        REQUIRE(dev);
        CHECK(dev->body.find("Signal history") != std::string::npos);
        CHECK(audited == "dex.device.view|WS-1"); // per-device open is audited (PII)
    }

    SECTION("unauthenticated shell redirects to /login") {
        yuzu::server::test::TestRouteSink sink;
        DexRoutes routes;
        routes.register_routes(sink, noAuth, okPerm, &store, fleet, audit);
        auto page = sink.Get("/dex");
        REQUIRE(page);
        CHECK(page->status == 302);
        CHECK(page->get_header_value("Location") == "/login");
    }

    SECTION("fragments denied without GuaranteedState:Read, before audit/render") {
        yuzu::server::test::TestRouteSink sink;
        DexRoutes routes;
        routes.register_routes(sink, okAuth, noPerm, &store, fleet, audit);

        auto ov = sink.Get("/fragments/dex/overview");
        REQUIRE(ov);
        CHECK(ov->status == 403);
        CHECK(ov->body.find("chrome.exe") == std::string::npos); // no data leaked

        auto dev = sink.Get("/fragments/dex/device?id=WS-1");
        REQUIRE(dev);
        CHECK(dev->status == 403);
        CHECK(audited.empty()); // perm gate runs BEFORE the audit + render
    }
}
