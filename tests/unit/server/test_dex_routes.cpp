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

#include <algorithm>
#include <optional>
#include <set>
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

// Route fragments filter signals by a now()-relative window (the handler computes
// `dex_iso_since(window_to_days)` as the cutoff), so seeds with hardcoded calendar
// dates age out of the window and the route tests start failing once the wall
// clock passes them — they did on 2026-06-15, when the old 2026-06-08/09 seeds
// fell outside the default 7-day window. Anchor seed dates a few days back from
// *now* instead. Date-only: each seed appends its own "Thh:mm:ssZ" suffix, so
// intra-test ordering is preserved. dex_iso_since is the very helper the route
// cutoff uses, so these can never drift from it.
const std::string kDayA = dex_iso_since(3).substr(0, 10); // older (was 2026-06-08)
const std::string kDayB = dex_iso_since(2).substr(0, 10); // newer (was 2026-06-09)
} // namespace

TEST_CASE("DEX overview: null store renders no-data placeholder", "[dex][routes]") {
    auto html = render_dex_overview_fragment(nullptr, "", 7, DexFleet{});
    CHECK(html.find("gp-placeholder") != std::string::npos);
    CHECK(html.find("unavailable") != std::string::npos);
}

TEST_CASE("DEX catalogue: family fragments surface ALL 114 monitored types, quiet ones too",
          "[dex][routes][catalogue]") {
    // Visibility contract (Dave 2026-06-10): operators must see what the fleet
    // is MONITORING, not just what fired — every catalogued type renders inside
    // its family, quiet ones as muted real-zero rows. Zeros are facts, not mock
    // data. The hub slimmed to summarise-and-link (the old All-signals panel was
    // retired), so the contract now lives on the Catalogue: rendering all 12
    // family fragments must surface every label. This list mirrors kAllObsTypes
    // in test_dex_signals.cpp — the two-sided drift net for catalogue additions.
    GuaranteedStateStore store(":memory:");
    // Raw family names (literal '&') match dex_signal_groups(); a wrong name
    // would render "Unknown family" and its labels would go missing below.
    std::string html;
    // All three platforms connected → every catalogued type is MONITORED
    // (coverage-first), so quiet types render as watched real-zero rows.
    const DexFleet all_os{1, 1, {"windows", "linux", "darwin"}};
    for (const char* family :
         {"App reliability", "Boot, start-up & shutdown", "Service health", "System stability",
          "Hardware & storage", "Performance", "File system", "Network", "Identity & logon",
          "Security & protection", "Updates & installs", "Policy & management", "Printing"})
        html += render_dex_catalogue_group_fragment(&store, "", 7, family, all_os);

    // All 114 labels.
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
          "Disk SMART warning", "Disk nearly full", "Storage port reset", "Lost delayed write",
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
          "Policy extension failure", "MDM/Intune error",
          // A3 sustained perf breaches (Windows state poll, dex_perf_breach)
          "Sustained high CPU", "Memory pressure", "High disk latency",
          // wave 4 (2026-06-22) — power-management + driver reliability
          "Modern standby exit", "Adapter driver dump", "Driver load failure",
          "Battery error",
          // wave 4 batch 2 — cheap additions on already-armed channels
          "Service unresponsive", "Service shutdown failure", "Adapter reset"})
        CHECK(html.find(label) != std::string::npos);

    // No fabricated numbers: quiet rows carry a literal zero count. (The "All
    // 114 monitored signal types" headline is asserted on Catalogue View 1 by
    // the "lists every family + the sub-nav" test below.)
    CHECK(html.find("<td class=\"gp-num\">0</td>") != std::string::npos);
}

TEST_CASE("DEX catalogue grid lists every family + the sub-nav", "[dex][routes][catalogue]") {
    GuaranteedStateStore store(":memory:");
    // windows connected → all 114 catalogue types are monitored (coverage-first).
    const auto html =
        render_dex_catalogue_fragment(&store, "", 7, DexFleet{2, 2, {"windows"}}, "all");
    // shared DEX sub-nav (Overview + Catalogue live; Health/Trends muted)
    CHECK(html.find("/fragments/dex/overview") != std::string::npos);
    CHECK(html.find("gp-subnav") != std::string::npos);
    CHECK(html.find("actively monitored") != std::string::npos);
    CHECK(html.find("of 114 signal types") != std::string::npos);
    // every family heading renders as a card (escaped where needed)
    for (const char* fam : {"App reliability", "Network", "Hardware &amp; storage", "Printing",
                            "Service health", "Identity &amp; logon"})
        CHECK(html.find(fam) != std::string::npos);
    // a card drills into the family-detail fragment
    CHECK(html.find("/fragments/dex/catalogue/group?name=") != std::string::npos);
}

TEST_CASE("DEX catalogue family lists its signals; unknown family is escaped",
          "[dex][routes][catalogue]") {
    GuaranteedStateStore store(":memory:");
    // Windows connected → the Windows-collected Network types are MONITORED.
    const DexFleet win{1, 1, {"windows"}};
    const auto net = render_dex_catalogue_group_fragment(&store, "", 7, "Network", win);
    CHECK(net.find("Wi-Fi disconnect") != std::string::npos); // friendly label
    CHECK(net.find("monitored") != std::string::npos);        // coverage-first pill
    CHECK(net.find("Windows") != std::string::npos);          // coverage detail
    CHECK(net.find("&larr; All families") != std::string::npos);
    // OS chips are present IN the family view so the filter is changeable in place.
    CHECK(net.find("/fragments/dex/catalogue/group?name=Network&window=7d&os=windows") !=
          std::string::npos);
    // unknown family → placeholder; the reflected name is HTML-escaped (no XSS)
    const auto bad = render_dex_catalogue_group_fragment(&store, "", 7, "<script>x</script>", win);
    CHECK(bad.find("Unknown family") != std::string::npos);
    CHECK(bad.find("<script>") == std::string::npos);
    // OS filter persists: the back-link to the grid carries the lens.
    const DexFleet lin_fleet{0, 0, {"linux"}};
    const auto lin = render_dex_catalogue_group_fragment(&store, "", 7, "Network", lin_fleet, "linux");
    CHECK(lin.find("/fragments/dex/catalogue?window=7d&os=linux") != std::string::npos);
    // Coverage-first: a Windows-only type reads "not collected" under the Linux lens.
    CHECK(lin.find("not collected") != std::string::npos);
}

TEST_CASE("DEX catalogue signal drill-down: subjects + live OS split; type escaped",
          "[dex][routes][catalogue]") {
    GuaranteedStateStore store(":memory:");
    auto obs = [&](const std::string& id, const std::string& agent, const std::string& subject,
                   const std::string& plat) {
        GuaranteedStateEventRow r;
        r.event_id = id;
        r.rule_id = "__observation__";
        r.agent_id = agent;
        r.event_type = "network.wifi_drop";
        r.severity = "info";
        r.detail_json = "{\"subject\":\"" + subject + "\",\"platform\":\"" + plat + "\"}";
        r.timestamp = kDayB + "T10:00:00Z";
        REQUIRE(store.insert_event(r));
    };
    obs("a", "agent-A", "CorpNet", "windows");
    obs("b", "agent-B", "CorpNet", "windows");
    obs("c", "mac-1", "Wi-Fi", "macos");

    const auto html = render_dex_catalogue_signal_fragment(&store, "", 7, "network.wifi_drop");
    CHECK(html.find("Wi-Fi disconnect") != std::string::npos); // friendly label (title)
    CHECK(html.find("Top subjects") != std::string::npos);
    CHECK(html.find("CorpNet") != std::string::npos);          // top subject
    CHECK(html.find("Windows + macOS") != std::string::npos);  // DERIVED-LIVE collected-on
    CHECK(html.find("Behavioral data") != std::string::npos);  // per-device PII banner
    CHECK(html.find("/fragments/dex/catalogue/group?name=") != std::string::npos); // back link

    // empty selection + a nasty obs_type (reflected) are handled safely
    CHECK(render_dex_catalogue_signal_fragment(&store, "", 7, "").find("No signal selected") !=
          std::string::npos);
    const auto bad = render_dex_catalogue_signal_fragment(&store, "", 7, "<img src=x onerror=y>");
    CHECK(bad.find("<img src=x") == std::string::npos); // escaped, no XSS
}

TEST_CASE("DEX health score: transparent composite, decomposition, suppression",
          "[dex][routes][health]") {
    GuaranteedStateStore store(":memory:");
    auto obs = [&](const std::string& id, const std::string& agent, const std::string& type,
                   const std::string& plat) {
        GuaranteedStateEventRow r;
        r.event_id = id;
        r.rule_id = "__observation__";
        r.agent_id = agent;
        r.event_type = type;
        r.severity = "info";
        r.detail_json = "{\"subject\":\"x\",\"platform\":\"" + plat + "\"}";
        r.timestamp = kDayB + "T10:00:00Z";
        REQUIRE(store.insert_event(r));
    };
    obs("a", "agent-A", "process.crashed", "windows");
    obs("b", "agent-B", "network.wifi_drop", "windows");

    DexFleet fleet;
    fleet.windows_online = 10;
    const auto html = render_dex_health_fragment(&store, "", 7, fleet, "default");
    CHECK(html.find("Experience health") != std::string::npos);
    CHECK(html.find("100 &minus; weighted deductions") != std::string::npos); // the formula is shown
    CHECK(html.find("derived &middot; secondary") != std::string::npos);
    CHECK(html.find("Why this score") != std::string::npos);
    CHECK(html.find("weighting:") != std::string::npos); // server-round-tripped presets
    // Every display family carries a weight entry (a family missing from
    // dex_family_weights silently never contributes to the score) — pin the
    // A3 addition via its per-family sub-score card.
    CHECK(html.find("Performance") != std::string::npos);

    // No reporting agents → suppressed (NEVER a fabricated 100).
    const auto suppressed = render_dex_health_fragment(&store, "", 7, DexFleet{}, "default");
    CHECK(suppressed.find("Index suppressed") != std::string::npos);

    // A bogus weighting falls back to "default" — the raw param is never echoed.
    const auto bad = render_dex_health_fragment(&store, "", 7, fleet, "<script>x</script>");
    CHECK(bad.find("<script>") == std::string::npos);
}

TEST_CASE("DEX trends: cross-OS cards (live scope), small-multiples, heatmap",
          "[dex][routes][trends]") {
    GuaranteedStateStore store(":memory:");
    auto obs = [&](const std::string& id, const std::string& agent, const std::string& type,
                   const std::string& plat, const std::string& day) {
        GuaranteedStateEventRow r;
        r.event_id = id;
        r.rule_id = "__observation__";
        r.agent_id = agent;
        r.event_type = type;
        r.severity = "info";
        r.detail_json = "{\"subject\":\"x\",\"platform\":\"" + plat + "\"}";
        r.timestamp = day + "T10:00:00Z";
        REQUIRE(store.insert_event(r));
    };
    obs("1", "w", "process.crashed", "windows", kDayA);
    obs("2", "w", "network.wifi_drop", "windows", kDayB);
    obs("3", "m", "process.crashed", "macos", kDayB);

    DexFleet fleet;
    fleet.windows_online = 5;
    const auto html = render_dex_trends_fragment(&store, "", 30, fleet);
    CHECK(html.find("Cross-OS") != std::string::npos);
    CHECK(html.find("By operating system") != std::string::npos);
    CHECK(html.find("Windows") != std::string::npos);
    CHECK(html.find("macOS") != std::string::npos);
    CHECK(html.find("gp-oscard pending") != std::string::npos);          // Linux pending (no data)
    CHECK(html.find("Signal families over time") != std::string::npos);  // small-multiples
    CHECK(html.find("Activity heatmap") != std::string::npos);           // heatmap
    CHECK(html.find("App reliability") != std::string::npos);            // a family row
    // DERIVED-LIVE scope caption — "of 114 signal types", not the mockup's stale 6
    CHECK(html.find("of 114 signal types") != std::string::npos);
}

TEST_CASE("DEX overview hub: explore cards link into the three deep pages",
          "[dex][routes][hub]") {
    GuaranteedStateStore store(":memory:");
    DexFleet fleet;
    fleet.windows_online = 5;
    const auto html = render_dex_overview_fragment(&store, "", 7, fleet);
    CHECK(html.find("Explore") != std::string::npos);
    CHECK(html.find("Signal catalogue") != std::string::npos);
    CHECK(html.find("Experience health") != std::string::npos);
    CHECK(html.find("Cross-OS &amp; trends") != std::string::npos);
    // each card drills into its deep page
    CHECK(html.find("/fragments/dex/catalogue?window=") != std::string::npos);
    CHECK(html.find("/fragments/dex/health?window=") != std::string::npos);
    CHECK(html.find("/fragments/dex/trends?window=") != std::string::npos);
    // with reporting agents the health teaser computes (not suppressed)
    CHECK(html.find("suppressed") == std::string::npos);

    // with no reporting agents the health teaser is suppressed (no fabricated score)
    const auto sup = render_dex_overview_fragment(&store, "", 7, DexFleet{});
    CHECK(sup.find("suppressed") != std::string::npos);
}

TEST_CASE("DEX overview: renders real multi-signal aggregations", "[dex][routes]") {
    GuaranteedStateStore store(":memory:");
    seed_crash(store, "e1", "WS-1", "chrome.exe", "ntdll.dll", "windows", kDayA + "T10:00:00Z");
    seed_crash(store, "e2", "WS-1", "chrome.exe", "ntdll.dll", "windows", kDayA + "T11:00:00Z");
    seed_hang(store, "e3", "WS-2", "chrome.exe", kDayB + "T09:00:00Z");
    seed_signal(store, "e4", "WS-2", "service.crashed",
                R"({"subject":"Spooler","reason":"7031","symbolic":"SERVICE_CRASHED","platform":"windows"})",
                kDayB + "T10:00:00Z");
    seed_boot(store, "e5", "WS-1", 43210.0, kDayB + "T08:00:00Z");
    seed_boot(store, "e6", "WS-2", 91000.0, kDayB + "T08:05:00Z");

    auto html = render_dex_overview_fragment(&store, "", 7, DexFleet{10, 12});
    CHECK(html.find("Digital Employee Experience") != std::string::npos);
    // Hub slim: the All-signals / boot / faulting-modules panels moved to the
    // deep pages (Catalogue + App reliability) — the hub summarises and links.
    CHECK(html.find("All signals") == std::string::npos);
    CHECK(html.find("Boot performance") == std::string::npos);
    CHECK(html.find("Top faulting modules") == std::string::npos);
    // Top crashing apps table spans crashes + hangs, with a deep-page CTA.
    CHECK(html.find("Top crashing apps") != std::string::npos);
    CHECK(html.find("App reliability") != std::string::npos); // section CTA → catalogue family
    CHECK(html.find("chrome.exe") != std::string::npos);
    CHECK(html.find("Hangs") != std::string::npos);
    // Most-affected devices (crash-scoped) + the By-OS coverage teaser.
    CHECK(html.find("Most-affected devices") != std::string::npos);
    CHECK(html.find("WS-1") != std::string::npos);
    CHECK(html.find("By operating system") != std::string::npos);
    CHECK(html.find("Windows") != std::string::npos); // the one OS that reported
    CHECK(html.find("gp-table") != std::string::npos);
}

TEST_CASE("DEX catalogue: unknown obs_type falls back to the raw label under 'Other'",
          "[dex][routes][catalogue]") {
    // Forward-compat: a signal added agent-side renders with NO server change.
    // The slimmed hub no longer carries the per-type rollup, so the "Other"
    // (uncatalogued) fallback now surfaces on the Catalogue.
    GuaranteedStateStore store(":memory:");
    seed_signal(store, "e1", "WS-1", "future.signal_type",
                R"({"subject":"thing","platform":"windows"})", kDayB + "T10:00:00Z");
    auto html = render_dex_catalogue_fragment(&store, "", 7, DexFleet{}, "all");
    CHECK(html.find("future.signal_type") != std::string::npos);
    CHECK(html.find(">Other") != std::string::npos);
}

TEST_CASE("DEX per-device score: clean 100; failures deduct; benign don't; null=-1",
          "[dex][score]") {
    GuaranteedStateStore store(":memory:");
    // Null store → n/a sentinel.
    CHECK(dex_device_score(nullptr, "WS-1", "") == -1);
    // A device with no observations is a clean 100.
    CHECK(dex_device_score(&store, "CLEAN-1", "") == 100);
    // A failure signal (process.crashed = App reliability, high severity) deducts.
    seed_signal(store, "e1", "WS-1", "process.crashed",
                R"({"subject":"chrome.exe","platform":"windows"})", kDayA + "T10:00:00Z");
    CHECK(dex_device_score(&store, "WS-1", "") < 100);
    // The score is per-device: a different device is unaffected.
    CHECK(dex_device_score(&store, "OTHER-1", "") == 100);
    // Benign reports (uptime) never deduct → still 100.
    seed_signal(store, "e2", "BENIGN-1", "os.uptime_report",
                R"({"subject":"host","platform":"windows"})", kDayA + "T10:00:00Z");
    CHECK(dex_device_score(&store, "BENIGN-1", "") == 100);
    // os.modern_standby_exit (wave 4) fires on EVERY resume — it lives in the
    // benign "Boot, start-up & shutdown" family, so a laptop that sleeps a lot
    // must NOT have its score dragged down (mirrors os.uptime_report above).
    seed_signal(store, "e3", "SLEEPER-1", "os.modern_standby_exit",
                R"({"subject":"modern standby","reason":"32","metric":0,"platform":"windows"})",
                kDayA + "T10:00:00Z");
    CHECK(dex_device_score(&store, "SLEEPER-1", "") == 100);
}

TEST_CASE("DEX overview: Experience hero — per-device distribution + D/A/N; crashes demoted",
          "[dex][routes]") {
    GuaranteedStateStore store(":memory:");
    seed_signal(store, "e1", "WS-1", "process.crashed",
                R"({"subject":"chrome.exe","platform":"windows"})", kDayA + "T10:00:00Z");
    // 2 connected Windows agents: WS-1 crashed (<100), WS-2 clean (100).
    DexFleet fleet{2, 2, {"windows"}, {{"WS-1", "windows"}, {"WS-2", "windows"}}};
    auto html = render_dex_overview_fragment(&store, "", 7, fleet);
    CHECK(html.find("Experience") != std::string::npos);         // new headline section
    CHECK(html.find("Overall experience") != std::string::npos); // per-device median tile
    CHECK(html.find("great") != std::string::npos);              // the distribution bar
    CHECK(html.find("Experience by segment") != std::string::npos); // the segment breakdown
    CHECK(html.find("Crash-free devices") != std::string::npos); // crashes demoted, not removed
}

TEST_CASE("DEX overview: crash-free rate from fleet denominator; none → honest no-data",
          "[dex][routes]") {
    GuaranteedStateStore store(":memory:");
    seed_crash(store, "e1", "WS-1", "chrome.exe", "ntdll.dll", "windows", kDayA + "T10:00:00Z");

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
    seed_hang(store, "e1", "WS-1", "Teams.exe", kDayB + "T09:00:00Z");
    auto html = render_dex_overview_fragment(&store, "", 7, DexFleet{4, 5});
    CHECK(html.find("100.0%") != std::string::npos);    // 0 crash-impacted of 4
    CHECK(html.find("Teams.exe") != std::string::npos); // the hung app still surfaces (Hangs col)
}

TEST_CASE("DEX overview: escapes nasty subjects (no XSS)", "[dex][routes][security]") {
    GuaranteedStateStore store(":memory:");
    seed_crash(store, "e1", "WS-1", "<img src=x onerror=alert(1)>", "ntdll.dll", "windows",
               kDayA + "T10:00:00Z");
    auto html = render_dex_overview_fragment(&store, "", 7, DexFleet{10, 12});
    CHECK(html.find("<img src=x") == std::string::npos);     // raw tag must not appear
    CHECK(html.find("&lt;img src=x") != std::string::npos);  // escaped form does
}

TEST_CASE("DEX app drill-down: blast radius + hangs + modules + exceptions + devices",
          "[dex][routes]") {
    GuaranteedStateStore store(":memory:");
    seed_crash(store, "e1", "WS-1", "chrome.exe", "ntdll.dll", "windows", kDayA + "T10:00:00Z");
    seed_crash(store, "e2", "WS-2", "chrome.exe", "chrome.dll", "windows", kDayB + "T10:00:00Z");
    seed_hang(store, "e3", "WS-2", "chrome.exe", kDayB + "T11:00:00Z");

    auto html = render_dex_app_fragment(&store, "chrome.exe", "all");
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
    auto html = render_dex_app_fragment(&store, "nope.exe", "all");
    CHECK(html.find("No crashes") != std::string::npos);
}

TEST_CASE("DEX device drill-down: friendly multi-signal history (UP-4)",
          "[dex][routes]") {
    GuaranteedStateStore store(":memory:");
    seed_crash(store, "e1", "WS-7", "AcmeCRM.exe", "AcmeCRM.dll", "windows",
               kDayA + "T10:00:00Z");
    seed_signal(store, "e2", "WS-7", "service.crashed",
                R"({"subject":"Spooler","reason":"7031","symbolic":"SERVICE_CRASHED","platform":"windows"})",
                kDayB + "T10:00:00Z");
    seed_boot(store, "e3", "WS-7", 43210.0, kDayB + "T08:00:00Z");

    auto html = render_dex_device_fragment(&store, "WS-7", "all");
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
               kDayA + "T10:00:00Z");
    auto html = render_dex_device_fragment(&store, "<b>evil</b>", "all");
    CHECK(html.find("<b>evil</b>") == std::string::npos);
    CHECK(html.find("&lt;b&gt;evil") != std::string::npos);
}

TEST_CASE("DEX single-observation detail: store lookup + render", "[dex][routes]") {
    GuaranteedStateStore store(":memory:");
    seed_signal(store, "ev-100", "WS-7", "app.staterepo_error",
                R"({"subject":"app state repository","reason":"sr-100",)"
                R"("symbolic":"STATEREPO_ERROR","platform":"windows"})",
                kDayA + "T11:27:41Z");

    // store: indexed point lookup by event_id; unknown / empty id → nullopt
    auto obs = store.dex_observation("ev-100");
    REQUIRE(obs.has_value());
    CHECK(obs->agent_id == "WS-7");
    CHECK(obs->obs_type == "app.staterepo_error");
    CHECK(obs->reason == "sr-100");
    CHECK(obs->symbolic == "STATEREPO_ERROR");
    CHECK_FALSE(store.dex_observation("nope").has_value());
    CHECK_FALSE(store.dex_observation("").has_value());

    // render: friendly label + the raw obs_type + every captured field
    auto html = render_dex_observation_fragment(*obs);
    CHECK(html.find("App repository error") != std::string::npos);
    CHECK(html.find("app.staterepo_error") != std::string::npos);
    CHECK(html.find("sr-100") != std::string::npos);
    CHECK(html.find("STATEREPO_ERROR") != std::string::npos);
    CHECK(html.find("WS-7") != std::string::npos);
}

TEST_CASE("DEX single-observation detail: escapes fields (no XSS)",
          "[dex][routes][security]") {
    GuaranteedStateStore store(":memory:");
    seed_signal(store, "ev-x", "WS-7", "process.crashed",
                R"({"subject":"<img src=x>","reason":"0x1",)"
                R"("symbolic":"<b>evil</b>","platform":"windows"})",
                kDayA + "T10:00:00Z");
    auto obs = store.dex_observation("ev-x");
    REQUIRE(obs.has_value());
    auto html = render_dex_observation_fragment(*obs);
    CHECK(html.find("<img src=x>") == std::string::npos);
    CHECK(html.find("<b>evil</b>") == std::string::npos);
    CHECK(html.find("&lt;b&gt;evil") != std::string::npos);
}

TEST_CASE("DEX observation render: metric 0 → em-dash; unknown obs_type → escaped fallback",
          "[dex][routes]") {
    GuardianObservationRow r;
    r.event_id = "ev-z";
    r.agent_id = "WS-1";
    r.obs_type = "<weird>future.type"; // uncatalogued + hostile
    r.subject = "x";
    r.platform = "windows";
    r.metric = 0.0; // "no metric" sentinel — the Metric cell shows an em-dash, not "0"
    const auto html = render_dex_observation_fragment(r);
    CHECK(html.find("Metric</span><code>&mdash;</code>") != std::string::npos);
    // unknown obs_type falls back to the escaped raw label (no XSS, no crash)
    CHECK(html.find("<weird>") == std::string::npos);
    CHECK(html.find("&lt;weird&gt;future.type") != std::string::npos);
    // a real metric DOES render (no sci-notation for in-range values)
    r.metric = 75.0;
    const auto html2 = render_dex_observation_fragment(r);
    CHECK(html2.find("Metric</span><code>75</code>") != std::string::npos);
}

TEST_CASE("DEX observation render: metric is unit-formatted per obs_type (polymorphic)",
          "[dex][routes]") {
    auto render = [](const std::string& obs_type, double metric) {
        GuardianObservationRow r;
        r.event_id = "e";
        r.agent_id = "WS-1";
        r.platform = "windows";
        r.obs_type = obs_type;
        r.metric = metric;
        return render_dex_observation_fragment(r);
    };
    // DRIPS residency is a PERCENT, not a duration — must NOT render as "75 ms".
    CHECK(render("os.modern_standby_exit", 75.0).find("Metric</span><code>75%</code>") !=
          std::string::npos);
    // 0% DRIPS is a REAL reading (never reached deep idle) — it must render "0%",
    // NOT the "no metric" em-dash (grill #1: the signal's headline value was hidden).
    CHECK(render("os.modern_standby_exit", 0.0).find("Metric</span><code>0%</code>") !=
          std::string::npos);
    CHECK(render("os.modern_standby_exit", 0.0).find("Metric</span><code>&mdash;</code>") ==
          std::string::npos);
    // A forged negative DRIPS can't arise (extractor clamps [0,100]) but pins the
    // new guard's negative arm → em-dash, never a bogus "-1%".
    CHECK(render("os.modern_standby_exit", -1.0).find("Metric</span><code>&mdash;</code>") !=
          std::string::npos);
    // Duration metrics humanize ms → s.
    CHECK(render("os.boot", 64934.0).find("Metric</span><code>64.9 s</code>") != std::string::npos);
    // A long boot never flips to scientific notation (the bare-{:g} hazard).
    const auto big = render("os.boot", 1200000.0);
    CHECK(big.find("e+0") == std::string::npos);
    CHECK(big.find("Metric</span><code>1200.0 s</code>") != std::string::npos);
    // Seconds-valued (uptime) humanizes across all fmt_secs branches (d / h / min / s).
    CHECK(render("os.uptime_report", 90000.0).find("Metric</span><code>1.0 d</code>") !=
          std::string::npos);
    CHECK(render("os.uptime_report", 7200.0).find("Metric</span><code>2.0 h</code>") !=
          std::string::npos);
    CHECK(render("os.uptime_report", 300.0).find("Metric</span><code>5.0 min</code>") !=
          std::string::npos);
    CHECK(render("os.uptime_report", 30.0).find("Metric</span><code>30 s</code>") !=
          std::string::npos);
    // Counts + uncatalogued render as plain integers (no unit, no sci).
    CHECK(render("hw.battery_error", 2.0).find("Metric</span><code>2</code>") != std::string::npos);
}

TEST_CASE("DEX device history rows drill to the observation detail", "[dex][routes]") {
    GuaranteedStateStore store(":memory:");
    seed_crash(store, "ev-1", "WS-7", "AcmeCRM.exe", "AcmeCRM.dll", "windows",
               kDayA + "T10:00:00Z");
    auto html = render_dex_device_fragment(&store, "WS-7", "all");
    // each row hx-gets its single-observation detail into the slot div
    CHECK(html.find("/fragments/dex/observation?agent_id=WS-7&amp;event_id=ev-1") !=
          std::string::npos);
    CHECK(html.find("id=\"dex-obs-detail\"") != std::string::npos);
}

TEST_CASE("DEX apps list: ranks apps by crashes+hangs, drillable", "[dex][routes]") {
    GuaranteedStateStore store(":memory:");
    seed_crash(store, "c1", "WS-1", "AcmeCRM.exe", "AcmeCRM.dll", "windows", kDayA + "T10:00:00Z");
    seed_crash(store, "c2", "WS-2", "AcmeCRM.exe", "ntdll.dll", "windows", kDayA + "T11:00:00Z");
    seed_hang(store, "h1", "WS-1", "chrome.exe", kDayA + "T12:00:00Z");

    auto html = render_dex_apps_fragment(&store, "", 7);
    CHECK(html.find("Applications") != std::string::npos);
    CHECK(html.find("AcmeCRM.exe") != std::string::npos);
    CHECK(html.find("chrome.exe") != std::string::npos);
    // app rows drill to the per-app blast-radius view; the Apps subnav tab is present
    CHECK(html.find("name=AcmeCRM.exe") != std::string::npos);
    CHECK(html.find("/fragments/dex/apps") != std::string::npos);
}

TEST_CASE("DEX apps list: empty store → no-data placeholder", "[dex][routes]") {
    GuaranteedStateStore store(":memory:");
    auto html = render_dex_apps_fragment(&store, "", 7);
    CHECK(html.find("No data") != std::string::npos);
}

TEST_CASE("DEX routes: auth/perm gating + dispatch", "[dex][routes][rbac]") {
    GuaranteedStateStore store(":memory:");
    seed_crash(store, "e1", "WS-1", "chrome.exe", "ntdll.dll", "windows", kDayA + "T10:00:00Z");

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
    std::string audited, audited_detail;
    auto audit = [&](const httplib::Request&, const std::string& a, const std::string&,
                     const std::string& ttype, const std::string& tid, const std::string& detail) {
        audited = a + "|" + ttype + "|" + tid; // capture target_type to pin the PascalCase fix
        audited_detail = detail;               // capture detail to pin obs_type (works-council)
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
        CHECK(audited == "dex.device.view|Agent|WS-1"); // per-device open audited (PII), PascalCase target_type

        // The per-signal Catalogue view lists most-affected DEVICES for an
        // obs_type (behavioral data) AND shows an "audit-logged on open" banner —
        // so the route MUST audit each open, mirroring the device view (gov B4).
        auto sig = sink.Get("/fragments/dex/catalogue/signal?type=process.crashed");
        REQUIRE(sig);
        CHECK(sig->status == 200);
        CHECK(audited == "dex.signal.view|ObsType|process.crashed");
    }

    SECTION("signal drill-down 'Collected on' reflects the coverage map, incl. Linux") {
        yuzu::server::test::TestRouteSink sink;
        DexRoutes routes;
        routes.register_routes(sink, okAuth, okPerm, &store, fleet, audit);
        // process.crashed is collected on all three platforms; the caption is derived
        // from dex_obs_platforms (coverage), not observed events, so it must name
        // Linux and never regress to the old event-derived "Windows only". The
        // " + "-joined form is unique to the coverage caption (the by_os table can't
        // produce it), so this can't pass on incidental seeded Linux rows.
        auto sig = sink.Get("/fragments/dex/catalogue/signal?type=process.crashed");
        REQUIRE(sig);
        CHECK(sig->status == 200);
        CHECK(sig->body.find("Collected on") != std::string::npos);
        CHECK(sig->body.find("Windows + Linux + macOS") != std::string::npos);
        CHECK(sig->body.find("Windows only") == std::string::npos);
    }

    // Per-event observation route: the novel security-load-bearing logic (scope
    // gate before audit, binding-404 against a foreign event_id, audit-on-success
    // with the obs_type in the detail) must be exercised THROUGH the route, not
    // just via the store/render fns (gov QE BLOCKING; F1 works-council).
    SECTION("per-event /observation: permitted opens audit obs_type+event; foreign id is an opaque placeholder") {
        yuzu::server::test::TestRouteSink sink;
        DexRoutes routes;
        routes.register_routes(sink, okAuth, okPerm, &store, fleet, audit);

        // (1) Permitted open of the seeded WS-1 crash (event_id "e1") → 200 + audit;
        //     the detail carries the obs_type (usage-class countability) + the event id.
        auto ok = sink.Get("/fragments/dex/observation?agent_id=WS-1&event_id=e1");
        REQUIRE(ok);
        CHECK(ok->status == 200);
        CHECK(audited == "dex.observation.view|Agent|WS-1");
        CHECK(audited_detail.find("process.crashed") != std::string::npos); // F1 obs_type
        CHECK(audited_detail.find("e1") != std::string::npos);              // event id traceable

        // (2) Binding case: the event exists but on a DIFFERENT device → the same
        //     "Observation not found" placeholder as a genuinely-unknown id, with NO
        //     foreign data leaked. Status is 200 NOT 404 — the dashboard htmx config
        //     drops 4xx bodies (swap:false), so a 404 would blank the slot; 200 still
        //     closes the enumeration oracle (foreign == absent, indistinguishable) and
        //     the not-found branch does NOT audit.
        audited.clear();
        auto foreign = sink.Get("/fragments/dex/observation?agent_id=WS-2&event_id=e1");
        REQUIRE(foreign);
        CHECK(foreign->status == 200);
        CHECK(foreign->body.find("Observation not found") != std::string::npos);
        CHECK(foreign->body.find("chrome.exe") == std::string::npos); // WS-1's data does not leak
        auto unknown = sink.Get("/fragments/dex/observation?agent_id=WS-2&event_id=nope");
        REQUIRE(unknown);
        CHECK(unknown->status == 200);
        CHECK(foreign->body == unknown->body); // indistinguishable — oracle closed
        // Empty event_id (the degenerate guard) also lands on the placeholder, not a 500.
        auto empty = sink.Get("/fragments/dex/observation?agent_id=WS-1&event_id=");
        REQUIRE(empty);
        CHECK(empty->status == 200);
        CHECK(empty->body == unknown->body); // complete oracle closure: empty ≡ unknown ≡ foreign
        CHECK(audited.empty());              // none of the not-found paths audit
    }

    SECTION("per-event /observation + /apps: perm gate runs before audit/render") {
        yuzu::server::test::TestRouteSink sink;
        DexRoutes routes;
        routes.register_routes(sink, okAuth, noPerm, &store, fleet, audit);

        auto obsv = sink.Get("/fragments/dex/observation?agent_id=WS-1&event_id=e1");
        REQUIRE(obsv);
        CHECK(obsv->status == 403);
        CHECK(audited.empty()); // perm gate before audit

        auto apps = sink.Get("/fragments/dex/apps");
        REQUIRE(apps);
        CHECK(apps->status == 403);
    }

    SECTION("per-event /observation is management-scoped: out-of-scope device → 403 before audit") {
        seed_crash(store, "e9", "WS-OTHER", "chrome.exe", "ntdll.dll", "windows",
                   kDayA + "T12:00:00Z");
        auto scopedPerm = [](const httplib::Request&, httplib::Response& res, const std::string&,
                             const std::string&, const std::string& id) {
            if (id == "WS-OTHER") {
                res.status = 403;
                return false;
            }
            return true;
        };
        yuzu::server::test::TestRouteSink sink;
        DexRoutes routes;
        routes.register_routes(sink, okAuth, okPerm, &store, fleet, audit, {}, {}, {}, scopedPerm);
        auto other = sink.Get("/fragments/dex/observation?agent_id=WS-OTHER&event_id=e9");
        REQUIRE(other);
        CHECK(other->status == 403);
        CHECK(audited.empty()); // scoped denial neither audits nor renders
        auto mine = sink.Get("/fragments/dex/observation?agent_id=WS-1&event_id=e1");
        REQUIRE(mine);
        CHECK(mine->status == 200);
    }

    SECTION("/fragments/dex/apps renders the ranked app table when permitted") {
        yuzu::server::test::TestRouteSink sink;
        DexRoutes routes;
        routes.register_routes(sink, okAuth, okPerm, &store, fleet, audit);
        auto apps = sink.Get("/fragments/dex/apps");
        REQUIRE(apps);
        CHECK(apps->status == 200);
        CHECK(apps->body.find("chrome.exe") != std::string::npos); // the seeded crasher ranks
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

        // Same for the per-signal device list — perm gate before audit/render, so
        // a denied caller neither sees data nor produces an audit row (gov B4).
        auto sig = sink.Get("/fragments/dex/catalogue/signal?type=process.crashed");
        REQUIRE(sig);
        CHECK(sig->status == 403);
        CHECK(audited.empty());
    }

    // Re-review blocker: the per-device DEX surface must be management-scoped (mirror
    // the /device routes) — an operator can't drill another team's device, and the
    // device-id lists must not enumerate out-of-scope agents.
    SECTION("per-device DEX surface is scoped: drill 403 + lists drop out-of-scope ids") {
        seed_crash(store, "e9", "WS-OTHER", "chrome.exe", "ntdll.dll", "windows",
                   kDayA + "T12:00:00Z");
        // Scoped gate: deny the per-device drill for the out-of-scope agent.
        auto scopedPerm = [](const httplib::Request&, httplib::Response& res, const std::string&,
                             const std::string&, const std::string& id) {
            if (id == "WS-OTHER") {
                res.status = 403;
                return false;
            }
            return true;
        };
        // Visible set: only WS-1 is in the caller's scope (the lists must drop WS-OTHER).
        auto visibleSet = [](const std::string&) -> std::optional<std::set<std::string>> {
            return std::set<std::string>{"WS-1"};
        };
        yuzu::server::test::TestRouteSink sink;
        DexRoutes routes;
        routes.register_routes(sink, okAuth, okPerm, &store, fleet, audit, {}, {}, {}, scopedPerm,
                               visibleSet);

        // (1) The per-device drill is scoped: out-of-scope → 403, in-scope still opens.
        auto other = sink.Get("/fragments/dex/device?id=WS-OTHER");
        REQUIRE(other);
        CHECK(other->status == 403);
        auto mine = sink.Get("/fragments/dex/device?id=WS-1");
        REQUIRE(mine);
        CHECK(mine->status == 200);

        // (2) The device-id lists drop the out-of-scope agent (no enumeration), while
        //     still showing the in-scope one.
        auto sig = sink.Get("/fragments/dex/catalogue/signal?type=process.crashed");
        REQUIRE(sig);
        CHECK(sig->status == 200);
        CHECK(sig->body.find("WS-1") != std::string::npos);
        CHECK(sig->body.find("WS-OTHER") == std::string::npos);

        auto app = sink.Get("/fragments/dex/app?name=chrome.exe");
        REQUIRE(app);
        CHECK(app->body.find("WS-OTHER") == std::string::npos);

        auto ov = sink.Get("/fragments/dex/overview?window=7d");
        REQUIRE(ov);
        CHECK(ov->body.find("WS-OTHER") == std::string::npos);
    }

    SECTION("hostile ?window= is canonicalised, never reflected into markup (Gate-8 XSS)") {
        // The raw window param flows into hx-get="…" attributes in drill-down
        // links; the route MUST canonicalise it to one of the four fixed tokens
        // before render. Must be exercised through the ROUTE (the raw param
        // entry point) — calling the render fns directly with a clean token
        // masks the bug. CSP is script-src 'self' 'unsafe-inline', so a
        // reflected attribute-break would execute.
        yuzu::server::test::TestRouteSink sink;
        DexRoutes routes;
        routes.register_routes(sink, okAuth, okPerm, &store, fleet, audit);
        const char* payload = R"(window="><script>alert(1)</script>)";

        auto ov = sink.Get(std::string("/fragments/dex/overview?window=") + payload);
        REQUIRE(ov);
        CHECK(ov->body.find("<script>") == std::string::npos);
        CHECK(ov->body.find("alert(1)") == std::string::npos); // payload not reflected anywhere

        auto app = sink.Get(std::string("/fragments/dex/app?name=chrome.exe&window=") + payload);
        REQUIRE(app);
        CHECK(app->body.find("<script>") == std::string::npos);
        CHECK(app->body.find("alert(1)") == std::string::npos);

        auto dev = sink.Get(std::string("/fragments/dex/device?id=WS-1&window=") + payload);
        REQUIRE(dev);
        CHECK(dev->body.find("<script>") == std::string::npos);
        CHECK(dev->body.find("alert(1)") == std::string::npos);
    }
}

// ── A4: device perf sparklines (federated TAR query) ────────────────────────

TEST_CASE("DEX perf parse: schema-mapped columns, trailer skipped, chronological",
          "[dex][perf][parse]") {
    // Rows arrive DESC (the canned query's ORDER BY); parse must sort ASC and
    // skip the "total|N" trailer + map columns by NAME from the schema line.
    const std::string out = "__schema__|hour_ts|cpu_avg|mem_avg|read_lat_us_avg|write_lat_us_avg\n"
                            "7200|55.5|60.1|3000|1000\n"
                            "3600|20.0|40.0|500|2500\n"
                            "total|2\n";
    const auto pts = parse_dex_perf_output(out);
    REQUIRE(pts.size() == 2);
    CHECK(pts[0].hour_ts == 3600);
    CHECK(pts[0].cpu_avg == 20.0);
    CHECK(pts[0].disk_lat_ms == 2.5); // worse of read/write, us -> ms
    CHECK(pts[1].hour_ts == 7200);
    CHECK(pts[1].mem_avg == 60.1);
    CHECK(pts[1].disk_lat_ms == 3.0);
}

TEST_CASE("DEX perf parse: column order is schema-driven, not positional",
          "[dex][perf][parse]") {
    const std::string out = "__schema__|cpu_avg|hour_ts|write_lat_us_avg|mem_avg|read_lat_us_avg\n"
                            "75.0|3600|0|50.0|0\n";
    const auto pts = parse_dex_perf_output(out);
    REQUIRE(pts.size() == 1);
    CHECK(pts[0].cpu_avg == 75.0);
    CHECK(pts[0].hour_ts == 3600);
    CHECK(pts[0].mem_avg == 50.0);
}

TEST_CASE("DEX perf parse: error payload / wrong shape / garbage rows never render",
          "[dex][perf][parse]") {
    CHECK(parse_dex_perf_output("error|no such table").empty());
    CHECK(parse_dex_perf_output("").empty());
    // Schema missing a required column -> refuse rather than guess.
    CHECK(parse_dex_perf_output("__schema__|hour_ts|cpu_avg\n3600|50\n").empty());
    // Garbage cells: non-finite / negative / non-numeric rows are skipped;
    // a >100% percentage is clamped (forged data must not distort the chart).
    const std::string out = "__schema__|hour_ts|cpu_avg|mem_avg|read_lat_us_avg|write_lat_us_avg\n"
                            "3600|inf|50|0|0\n"
                            "3600|-5|50|0|0\n"
                            "3600|garbage|50|0|0\n"
                            "7200|9000|50|0|0\n";
    const auto pts = parse_dex_perf_output(out);
    REQUIRE(pts.size() == 1);
    CHECK(pts[0].cpu_avg == 100.0); // clamped
}

TEST_CASE("DEX perf parse: a forged disk latency is clamped, never crushes the sparkline",
          "[dex][perf][parse]") {
    // The SVG y-axis auto-scales to the series range, so one absurd-but-finite
    // disk-latency row (1e9 µs = 1e6 ms) would otherwise flatten every real
    // point to an invisible line. cell_double accepts it (finite, >=0, <=32
    // chars); the clamp at 1000 ms is the defence (gov QE B1).
    const std::string out = "__schema__|hour_ts|cpu_avg|mem_avg|read_lat_us_avg|write_lat_us_avg\n"
                            "3600|10|40|2000|1500\n"      // ~2 ms, real
                            "7200|10|40|1000000000|0\n";  // 1e9 µs forged
    const auto pts = parse_dex_perf_output(out);
    REQUIRE(pts.size() == 2);
    CHECK(pts[0].disk_lat_ms == 2.0);       // real point intact
    CHECK(pts[1].disk_lat_ms == 1000.0);    // forged row clamped, not 1e6
}

TEST_CASE("DEX perf panel: sparklines + now/min/max; empty input is honest",
          "[dex][perf][render]") {
    CHECK(render_dex_perf_panel({}).find("No performance history") != std::string::npos);

    std::vector<DexPerfPoint> pts;
    for (int i = 0; i < 5; ++i)
        pts.push_back({3600 * (i + 1), 10.0 * (i + 1), 42.0, 1.5});
    const auto html = render_dex_perf_panel(pts);
    CHECK(html.find("<svg") != std::string::npos); // server-rendered SVG, no JS
    CHECK(html.find("<polyline") != std::string::npos);
    CHECK(html.find("CPU busy") != std::string::npos);
    CHECK(html.find("Memory used") != std::string::npos);
    CHECK(html.find("Disk latency") != std::string::npos);
    CHECK(html.find("now 50%") != std::string::npos); // CPU last value
    CHECK(html.find("min 10%") != std::string::npos);
    CHECK(html.find("max 50%") != std::string::npos);
    CHECK(html.find("5 hourly rollups") != std::string::npos);
    CHECK(html.find("hx-on") == std::string::npos); // CSP rule: never hx-on
}

TEST_CASE("DEX device fragment embeds the CLICK-to-load perf panel", "[dex][perf][render]") {
    GuaranteedStateStore store(":memory:");
    // With signals AND without - a quiet device still has perf history.
    const auto quiet = render_dex_device_fragment(&store, "WS-9", "7d");
    CHECK(quiet.find("/fragments/dex/device/perf?agent_id=WS-9") != std::string::npos);
    seed_crash(store, "e1", "WS-9", "app.exe", "m.dll", "windows", kDayB + "T10:00:00Z");
    const auto busy = render_dex_device_fragment(&store, "WS-9", "7d");
    CHECK(busy.find("/fragments/dex/device/perf?agent_id=WS-9") != std::string::npos);
    // Click-to-load, NEVER auto-load: the route dispatches a real command and
    // probes Execute (which audit-logs denials) — auto-loading would fire both
    // on every page view (grill finding 1). Pin the button + the absence of an
    // hx-trigger="load" auto-fire anywhere in the fragment.
    CHECK(busy.find("<button") != std::string::npos);
    CHECK(busy.find("Load performance") != std::string::npos);
    CHECK(busy.find("hx-trigger=\"load\"") == std::string::npos);
}

TEST_CASE("DEX perf routes: dispatch, poll, degrade, and authz posture",
          "[dex][perf][routes][rbac]") {
    GuaranteedStateStore store(":memory:");
    auto okAuth = [](const httplib::Request&, httplib::Response&) {
        return std::optional<auth::Session>(auth::Session{});
    };
    auto okPerm = [](const httplib::Request&, httplib::Response&, const std::string&,
                     const std::string&) { return true; };
    auto fleet = []() { return DexFleet{1, 1}; };
    std::string audited;
    auto audit = [&](const httplib::Request&, const std::string& a, const std::string& r,
                     const std::string&, const std::string& tid, const std::string&) {
        audited = a + "|" + r + "|" + tid;
    };

    // Fake dispatch + response store.
    int dispatched = 0;
    std::string seen_sql;
    int fake_sent = 1;
    auto dispatch = [&](const std::string& plugin, const std::string& action,
                        const std::vector<std::string>& ids, const std::string&,
                        const std::unordered_map<std::string, std::string>& params)
        -> std::pair<std::string, int> {
        ++dispatched;
        CHECK(plugin == "tar");
        CHECK(action == "sql");
        REQUIRE(ids.size() == 1);
        seen_sql = params.count("sql") ? params.at("sql") : "";
        return {"tar-deadbeef", fake_sent};
    };
    std::vector<DexAgentResponse> fake_rows;
    auto responses = [&](const std::string& command_id) {
        CHECK(command_id == "tar-deadbeef");
        return fake_rows;
    };

    yuzu::server::test::TestRouteSink sink;
    DexRoutes routes;
    routes.register_routes(sink, okAuth, okPerm, &store, fleet, audit, dispatch, responses);

    SECTION("dispatch returns the polling stub + audits the query") {
        auto r = sink.Get("/fragments/dex/device/perf?agent_id=WS-1");
        REQUIRE(r);
        CHECK(r->status == 200);
        CHECK(dispatched == 1);
        CHECK(seen_sql.find("$Perf_Hourly") != std::string::npos);
        CHECK(r->body.find("/fragments/dex/device/perf/result?command_id=tar-deadbeef") !=
              std::string::npos);
        CHECK(audited == "dex.device.perf.query|success|WS-1");
    }

    SECTION("offline device renders the honest note, no polling") {
        fake_sent = 0;
        auto r = sink.Get("/fragments/dex/device/perf?agent_id=WS-1");
        REQUIRE(r);
        CHECK(r->body.find("Device offline") != std::string::npos);
        CHECK(r->body.find("hx-trigger") == std::string::npos);
    }

    SECTION("result poll: pending -> re-poll with n+1; data -> panel; error -> note") {
        auto pending =
            sink.Get("/fragments/dex/device/perf/result?command_id=tar-deadbeef&agent_id=WS-1&n=1");
        REQUIRE(pending);
        CHECK(pending->body.find("&amp;n=2") != std::string::npos); // re-poll bumps the attempt

        fake_rows = {{"WS-1", 0,
                      "__schema__|hour_ts|cpu_avg|mem_avg|read_lat_us_avg|write_lat_us_avg\n"
                      "3600|33|44|0|0\n",
                      ""}};
        auto done =
            sink.Get("/fragments/dex/device/perf/result?command_id=tar-deadbeef&agent_id=WS-1&n=1");
        REQUIRE(done);
        CHECK(done->body.find("<svg") != std::string::npos);
        CHECK(done->body.find("hx-trigger") == std::string::npos); // polling stopped

        fake_rows = {{"WS-1", 0, "error|<b>no such table</b>", ""}};
        auto err =
            sink.Get("/fragments/dex/device/perf/result?command_id=tar-deadbeef&agent_id=WS-1&n=1");
        REQUIRE(err);
        CHECK(err->body.find("reported an error") != std::string::npos);
        CHECK(err->body.find("<b>no such table</b>") == std::string::npos); // escaped, not raw
    }

    SECTION("result poll: a valid-but-empty result renders 'no history', stops polling (gov S3)") {
        // The agent is online and answered, but $Perf_Hourly has no rows yet
        // (fresh agent, no rollup completed). Distinct from offline/timeout:
        // schema present, zero data rows. Must show the honest panel, not
        // re-poll forever — exercised THROUGH the route, not the render fn.
        fake_rows = {{"WS-1", 0,
                      "__schema__|hour_ts|cpu_avg|mem_avg|read_lat_us_avg|write_lat_us_avg\n"
                      "total|0\n",
                      ""}};
        auto empty =
            sink.Get("/fragments/dex/device/perf/result?command_id=tar-deadbeef&agent_id=WS-1&n=1");
        REQUIRE(empty);
        CHECK(empty->body.find("No performance history") != std::string::npos);
        CHECK(empty->body.find("hx-trigger") == std::string::npos); // not re-polled
        CHECK(empty->body.find("<svg") == std::string::npos);
    }

    SECTION("result poll: another agent's rows never render; timeout is honest") {
        fake_rows = {{"OTHER-AGENT", 0,
                      "__schema__|hour_ts|cpu_avg|mem_avg|read_lat_us_avg|write_lat_us_avg\n"
                      "3600|33|44|0|0\n",
                      ""}};
        auto r =
            sink.Get("/fragments/dex/device/perf/result?command_id=tar-deadbeef&agent_id=WS-1&n=1");
        REQUIRE(r);
        CHECK(r->body.find("<svg") == std::string::npos); // filtered out

        auto timeout = sink.Get(
            "/fragments/dex/device/perf/result?command_id=tar-deadbeef&agent_id=WS-1&n=20");
        REQUIRE(timeout);
        CHECK(timeout->body.find("timed out") != std::string::npos);
        CHECK(timeout->body.find("hx-trigger") == std::string::npos);
    }

    SECTION("non-tar command_id is rejected - this route polls only tar dispatches") {
        auto r = sink.Get(
            "/fragments/dex/device/perf/result?command_id=script_exec-123&agent_id=WS-1&n=1");
        REQUIRE(r);
        CHECK(r->status == 400);
    }

    SECTION("read-only operator gets the in-panel Execute note, no dispatch") {
        auto readOnly = [](const httplib::Request&, httplib::Response& res,
                           const std::string& securable, const std::string& op) {
            if (securable == "Execution" && op == "Execute") {
                res.status = 403;
                return false;
            }
            return true;
        };
        yuzu::server::test::TestRouteSink sink2;
        DexRoutes routes2;
        routes2.register_routes(sink2, okAuth, readOnly, &store, fleet, audit, dispatch,
                                responses);
        auto r = sink2.Get("/fragments/dex/device/perf?agent_id=WS-1");
        REQUIRE(r);
        CHECK(r->status == 200); // in-panel note, NOT a swallowed 403
        CHECK(r->body.find("Execute") != std::string::npos);
        CHECK(dispatched == 0);
        auto poll = sink2.Get(
            "/fragments/dex/device/perf/result?command_id=tar-deadbeef&agent_id=WS-1&n=1");
        REQUIRE(poll);
        CHECK(poll->body.find("Execute") != std::string::npos); // result leg gated too
    }

    SECTION("no dispatch/responses wiring degrades to the unavailable note") {
        yuzu::server::test::TestRouteSink sink3;
        DexRoutes routes3;
        routes3.register_routes(sink3, okAuth, okPerm, &store, fleet, audit);
        auto r = sink3.Get("/fragments/dex/device/perf?agent_id=WS-1");
        REQUIRE(r);
        CHECK(r->body.find("unavailable") != std::string::npos);
    }
}

// ── Drift-net for the per-OS coverage map (dex_obs_platforms). The map must claim
// a platform collects a signal type ONLY when an agent on that platform actually
// emits it. This is the guard the comment by dex_obs_platforms promises but that
// never existed — its absence let the Linux column advertise kernel/sysfs signals
// whose collectors live in a separate PR (#1523), so a Linux fleet would read
// "monitored, quiet" as healthy for signals nothing collects. The server suite
// can't introspect the agent collectors, so the emitted set is pinned here; when
// collectors are added or removed, update BOTH the collector and the set below in
// the same change (that conscious edit is the point). ──
TEST_CASE("dex coverage map does not overclaim Linux beyond emitted signals",
          "[dex][coverage]") {
    // What a Linux agent emits today: dex_linux_proc + dex_linux_storage polls and
    // dex_linux_journal mappings. The expanded kmsg/sysfs set arrives with #1523.
    const std::set<std::string> kLinuxEmitted = {
        "perf.cpu_sustained", "perf.memory_pressure", "storage.low", "os.uptime_report",
        "process.crashed",    "service.crashed",      "memory.exhausted"};

    auto claims = [](const std::string& obs_type, const char* os) {
        const auto p = dex_obs_platforms(obs_type);
        return std::find(p.begin(), p.end(), os) != p.end();
    };

    // Overclaim guard: every catalogued type the map marks "linux" must be emitted.
    for (const auto& g : dex_signal_groups()) {
        for (const char* t : g.types) {
            if (claims(t, "linux")) {
                INFO("coverage map claims Linux collects '"
                     << t << "' but no Linux collector emits it (see dex_obs_platforms)");
                CHECK(kLinuxEmitted.count(t) == 1);
            }
        }
    }

    // Underclaim guard: every emitted Linux signal is actually advertised.
    for (const auto& t : kLinuxEmitted) {
        INFO("emitted Linux signal '" << t << "' is missing from the coverage map");
        CHECK(claims(t, "linux"));
    }

    // Windows is the whole EvtSubscribe catalogue — always present and first.
    const auto win = dex_obs_platforms("process.crashed");
    REQUIRE_FALSE(win.empty());
    CHECK(win.front() == "windows");
}
