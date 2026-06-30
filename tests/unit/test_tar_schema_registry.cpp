// test_tar_schema_registry.cpp -- Pin OS compatibility metadata + capture
// method validation introduced by issue #59.
//
// These tests anchor invariants the TAR plugin relies on at runtime:
//   * every capture source declares OsSupport for windows/linux/macos so
//     the `compatibility` action can never silently report a missing OS;
//   * every supported (non-`kUnsupported`) row carries a non-empty
//     `capture_method` so operators reading the matrix always see *how*
//     the data is gathered;
//   * the `accepted_capture_methods` accept-list returned to
//     `do_configure` is the de-duplicated union of all non-Unsupported
//     methods, sorted, so error messages are stable.

#include "tar_schema_registry.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <set>
#include <string>

using namespace yuzu::tar;

TEST_CASE("TAR schema: every source has windows/linux/macos OsSupport rows",
          "[tar][schema][issue59]") {
    const auto& sources = capture_sources();
    REQUIRE(!sources.empty());

    for (const auto& src : sources) {
        std::set<std::string> oses;
        for (const auto& s : src.os_support) {
            oses.insert(std::string{s.os});
        }
        INFO("source=" << src.name);
        CHECK(oses.contains("windows"));
        CHECK(oses.contains("linux"));
        CHECK(oses.contains("macos"));
    }
}

TEST_CASE("TAR schema: every supported OsSupport row has a capture_method and notes",
          "[tar][schema][issue59]") {
    for (const auto& src : capture_sources()) {
        for (const auto& os : src.os_support) {
            if (os.status == OsSupportStatus::kUnsupported)
                continue;  // unsupported rows can omit method/notes
            INFO("source=" << src.name << " os=" << os.os);
            CHECK_FALSE(os.capture_method.empty());
            CHECK_FALSE(os.notes.empty());
        }
    }
}

TEST_CASE("TAR schema: accepted_capture_methods returns the deduped sorted union",
          "[tar][schema][issue59]") {
    auto methods = accepted_capture_methods("tcp");

    REQUIRE_FALSE(methods.empty());

    // Sorted check
    auto copy = methods;
    std::sort(copy.begin(), copy.end());
    CHECK(copy == methods);

    // Deduped check
    std::set<std::string> unique{methods.begin(), methods.end()};
    CHECK(unique.size() == methods.size());

    // The current TCP source declares iphlpapi (Windows), procfs (Linux),
    // and proc_pidfdinfo (macOS — libproc-based, replaced the original
    // `lsof` declaration in 5a41db5 to match the actual collector
    // implementation). All three should be in the accept-list.
    CHECK(unique.contains("iphlpapi"));
    CHECK(unique.contains("procfs"));
    CHECK(unique.contains("proc_pidfdinfo"));
}

TEST_CASE("TAR schema: accepted_capture_methods is empty for an unknown source",
          "[tar][schema][issue59]") {
    auto methods = accepted_capture_methods("nope_does_not_exist");
    CHECK(methods.empty());
}

TEST_CASE("TAR schema: kPlanned methods stay in the accept-list",
          "[tar][schema][issue59]") {
    // The accept-list intentionally includes kPlanned methods so operators
    // can pre-stage configuration. Verify the contract: any method whose
    // status is kPlanned must appear in accepted_capture_methods so a
    // configure call with that value succeeds (and the plugin separately
    // emits a `warn|...` line that the implementation isn't yet wired).
    int planned_rows_checked = 0;
    for (const auto& src : capture_sources()) {
        auto accepted = accepted_capture_methods(src.name);
        for (const auto& os : src.os_support) {
            if (os.status == OsSupportStatus::kPlanned) {
                ++planned_rows_checked;
                INFO("source=" << src.name << " planned method=" << os.capture_method);
                CHECK(std::find(accepted.begin(), accepted.end(),
                                std::string{os.capture_method}) != accepted.end());
            }
        }
    }
    // #544 — guard against silent vacuity: with zero kPlanned rows the loop runs
    // no assertions and the pre-staging contract goes untested (the original bug
    // — the test "passed" while checking nothing). Require at least one so this
    // fails loudly if the kPlanned methods are ever removed.
    REQUIRE(planned_rows_checked > 0);
}

TEST_CASE("TAR schema: kUnsupported methods are excluded from the accept-list",
          "[tar][schema][issue59]") {
    // Symmetric invariant: an OsSupport row marked kUnsupported must not
    // contribute its capture_method to the accept-list (an operator
    // configuring a method we cannot deliver should be rejected at
    // configure time, not silently downgraded at collect time).
    for (const auto& src : capture_sources()) {
        auto accepted = accepted_capture_methods(src.name);
        for (const auto& os : src.os_support) {
            if (os.status != OsSupportStatus::kUnsupported)
                continue;
            if (os.capture_method.empty())
                continue;  // unsupported rows often omit method
            // Only fail if no other row provides the same method as supported.
            bool covered_elsewhere = false;
            for (const auto& other : src.os_support) {
                if (&other == &os) continue;
                if (other.status != OsSupportStatus::kUnsupported &&
                    other.capture_method == os.capture_method) {
                    covered_elsewhere = true;
                    break;
                }
            }
            if (!covered_elsewhere) {
                INFO("source=" << src.name << " unsupported-only method=" << os.capture_method);
                CHECK(std::find(accepted.begin(), accepted.end(),
                                std::string{os.capture_method}) == accepted.end());
            }
        }
    }
}

// ── #540: per-OS capture-method accept-list ────────────────────────────────

TEST_CASE("TAR schema: accepted_capture_methods_for_os is OS-specific (#540)",
          "[tar][schema][issue59]") {
    // The OS-blind union accepts every method across all platforms — which is
    // exactly the #540 bug: a Linux agent could store the Windows-only
    // 'iphlpapi'. The per-OS accessor must NOT leak another OS's methods.
    auto unioned = accepted_capture_methods("tcp");
    auto contains = [](const std::vector<std::string>& v, const std::string& s) {
        return std::find(v.begin(), v.end(), s) != v.end();
    };

    // The union (the buggy validation surface) contains all platforms' methods.
    CHECK(contains(unioned, "iphlpapi"));    // windows
    CHECK(contains(unioned, "procfs"));      // linux
    CHECK(contains(unioned, "proc_pidfdinfo")); // macos

    auto linux_ok = accepted_capture_methods_for_os("tcp", "linux");
    CHECK(contains(linux_ok, "procfs"));
    CHECK_FALSE(contains(linux_ok, "iphlpapi"));      // Windows-only — must be rejected on Linux
    CHECK_FALSE(contains(linux_ok, "proc_pidfdinfo")); // macOS-only

    auto win_ok = accepted_capture_methods_for_os("tcp", "windows");
    CHECK(contains(win_ok, "iphlpapi"));
    CHECK_FALSE(contains(win_ok, "procfs"));

    auto mac_ok = accepted_capture_methods_for_os("tcp", "macos");
    CHECK(contains(mac_ok, "proc_pidfdinfo"));
    CHECK_FALSE(contains(mac_ok, "iphlpapi"));

    // An unknown OS yields an empty accept-list (everything rejected, fail-safe).
    CHECK(accepted_capture_methods_for_os("tcp", "plan9").empty());
}

TEST_CASE("TAR schema: current_platform_os is one of the supported triplet",
          "[tar][schema][issue59]") {
    auto os = current_platform_os();
    CHECK((os == "windows" || os == "linux" || os == "macos"));
    // And the running platform's tcp accept-list is non-empty (every supported
    // OS has at least a polling-equivalent capture method).
    CHECK_FALSE(accepted_capture_methods_for_os("tcp", os).empty());
}

TEST_CASE("TAR schema: effective network capture method is always polling today",
          "[tar][schema][issue1528]") {
    // `do_configure` stores any `network_capture_method` in
    // accepted_capture_methods("tcp") (plus the "polling" sentinel), but
    // collect_fast always polls via enumerate_connections() regardless.
    // effective_network_capture_method() is the single source of truth the
    // `status` action reports so it can never claim a stored-but-unwired method
    // is the active mechanism. Until a kernel-event collector lands, every
    // configured value must collapse to "polling".

    // Round-trip: the documented default maps to itself.
    CHECK(effective_network_capture_method("polling") == "polling");

    // Core invariant (issue #1528 acceptance): EVERY value `do_configure` will
    // accept for network_capture_method must report effective "polling" and must
    // NOT be reported back as the active mechanism. The tcp accept-list is the
    // exact configurable set; the kSupported platform APIs (procfs / iphlpapi /
    // proc_pidfdinfo) ARE the polling implementation, so the status field
    // reports the logical "polling" rather than the underlying API -- and a
    // cross-OS value (e.g. iphlpapi stored on a Linux box reading /proc/net) can
    // never masquerade as the active mechanism.
    auto configurable = accepted_capture_methods("tcp");
    REQUIRE_FALSE(configurable.empty());  // guard against a vacuous loop
    for (const auto& method : configurable) {
        INFO("configurable network_capture_method=" << method);
        CHECK(effective_network_capture_method(method) == "polling");
        CHECK(effective_network_capture_method(method) != method);
    }

    // Forward-looking: etw / endpoint_security are named in the issue and the
    // tar.yaml/tar.md prose as the kernel-event methods that would be pre-staged
    // once their collectors land (they are NOT in the tcp accept-list today, so
    // they appear here as explicit literals, not via the registry). The helper
    // is total -- it must collapse them to "polling" too until those collectors
    // are wired, which is when this function gains its runtime branch.
    CHECK(effective_network_capture_method("etw") == "polling");
    CHECK(effective_network_capture_method("endpoint_security") == "polling");

    // Total-function contract: empty and unknown inputs are inert (the helper
    // ignores `configured` today) and still report the truthful mechanism.
    CHECK(effective_network_capture_method("") == "polling");
    CHECK(effective_network_capture_method("not_a_real_method") == "polling");
}

// ── Per-source default-enabled (review R1) ──────────────────────────────────

TEST_CASE("TAR schema: opt-in sources declare default_enabled=false",
          "[tar][schema][default-off]") {
    // default_enabled is the single source of truth the plugin's source_enabled(),
    // do_status(), apply_source_enabled_transition(), and run_retention() all
    // read. The high-volume usage-class sources (module ~100× process volume,
    // procperf per-app, netqual per-connection) are opt-in and must report
    // disabled on a fresh agent; software is opt-in too (off by default — the
    // cautious posture for a new capture source, #1620); everything else is
    // always-on.
    for (const auto* name : {"module", "procperf", "netqual", "arp", "dns", "software"}) {
        INFO("opt-in source=" << name);
        CHECK_FALSE(source_default_enabled(name));
    }
    for (const auto* name : {"process", "tcp", "service", "user", "perf"}) {
        INFO("always-on source=" << name);
        CHECK(source_default_enabled(name));
    }
    // An unknown source falls back to the always-on default.
    CHECK(source_default_enabled("does_not_exist"));

    // The field and the lookup must agree for every registered source.
    for (const auto& src : capture_sources()) {
        INFO("source=" << src.name);
        CHECK(source_default_enabled(src.name) == src.default_enabled);
    }
}

TEST_CASE("TAR schema: software source is registered with three tiers + Windows support",
          "[tar][schema][software]") {
    const auto& sources = capture_sources();
    auto it = std::find_if(sources.begin(), sources.end(),
                           [](const CaptureSourceDef& s) { return s.name == "software"; });
    REQUIRE(it != sources.end());
    CHECK(it->dollar_name == "Software");
    CHECK_FALSE(it->default_enabled); // opt-in (off by default) — cautious new-source posture (#1620)

    // live + daily + monthly, in that declaration order (so run_aggregation rolls
    // daily-from-live before monthly-from-daily within one tick).
    REQUIRE(it->granularities.size() == 3);
    CHECK(it->granularities[0].suffix == "live");
    CHECK(it->granularities[1].suffix == "daily");
    CHECK(it->granularities[2].suffix == "monthly");
    CHECK(it->granularities[0].retention_type == RetentionType::kRowCount);

    // Windows is fully supported; Linux/macOS are planned (queryable-empty).
    for (const auto& os : it->os_support) {
        if (os.os == "windows")
            CHECK(os.status == OsSupportStatus::kSupported);
        else
            CHECK(os.status == OsSupportStatus::kPlanned);
    }
}

TEST_CASE("TAR schema: $Software dollar-names translate and DDL has the columns",
          "[tar][schema][software]") {
    CHECK(translate_dollar_name("$Software_Live") == "software_live");
    CHECK(translate_dollar_name("$Software_Daily") == "software_daily");
    CHECK(translate_dollar_name("$Software_Monthly") == "software_monthly");

    // The warehouse tables are allowlisted for the read-only tar.sql sandbox.
    CHECK(is_queryable_table("software_live"));
    CHECK(is_queryable_table("software_daily"));

    const auto ddl = generate_warehouse_ddl();
    CHECK(ddl.find("CREATE TABLE IF NOT EXISTS software_live") != std::string::npos);
    CHECK(ddl.find("prev_version") != std::string::npos);

    // live carries the full event columns (machine scope only — no scope/user);
    // daily/monthly carry the count rollup.
    auto live_cols = columns_for_table("software_live");
    for (const auto* c : {"action", "name", "version", "prev_version", "publisher",
                          "install_date"}) {
        INFO("software_live column=" << c);
        CHECK(std::find(live_cols.begin(), live_cols.end(), c) != live_cols.end());
    }
    // scope/user were dropped with per-user scope (#1620) — they must NOT exist.
    for (const auto* c : {"scope", "user"}) {
        INFO("software_live must NOT have column=" << c);
        CHECK(std::find(live_cols.begin(), live_cols.end(), c) == live_cols.end());
    }
    auto daily_cols = columns_for_table("software_daily");
    for (const auto* c : {"install_count", "remove_count", "upgrade_count"}) {
        INFO("software_daily column=" << c);
        CHECK(std::find(daily_cols.begin(), daily_cols.end(), c) != daily_cols.end());
    }
}
