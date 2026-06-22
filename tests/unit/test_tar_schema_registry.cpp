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
    for (const auto& src : capture_sources()) {
        auto accepted = accepted_capture_methods(src.name);
        for (const auto& os : src.os_support) {
            if (os.status == OsSupportStatus::kPlanned) {
                INFO("source=" << src.name << " planned method=" << os.capture_method);
                CHECK(std::find(accepted.begin(), accepted.end(),
                                std::string{os.capture_method}) != accepted.end());
            }
        }
    }
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

// ── Per-source default-enabled (review R1) ──────────────────────────────────

TEST_CASE("TAR schema: opt-in sources declare default_enabled=false",
          "[tar][schema][default-off]") {
    // default_enabled is the single source of truth the plugin's source_enabled(),
    // do_status(), apply_source_enabled_transition(), and run_retention() all
    // read. The high-volume usage-class sources (module ~100× process volume,
    // procperf per-app, netqual per-connection) are opt-in and must report
    // disabled on a fresh agent; everything else is always-on.
    for (const auto* name : {"module", "procperf", "netqual"}) {
        INFO("opt-in source=" << name);
        CHECK_FALSE(source_default_enabled(name));
    }
    for (const auto* name : {"process", "tcp", "service", "user", "perf", "software"}) {
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
    CHECK(it->default_enabled); // asset/security data — on by default

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
    CHECK(ddl.find("scope") != std::string::npos);

    // live carries the full event columns; daily/monthly carry the count rollup.
    auto live_cols = columns_for_table("software_live");
    for (const auto* c : {"action", "name", "version", "prev_version", "publisher", "scope",
                          "user", "install_date"}) {
        INFO("software_live column=" << c);
        CHECK(std::find(live_cols.begin(), live_cols.end(), c) != live_cols.end());
    }
    auto daily_cols = columns_for_table("software_daily");
    for (const auto* c : {"install_count", "remove_count", "upgrade_count"}) {
        INFO("software_daily column=" << c);
        CHECK(std::find(daily_cols.begin(), daily_cols.end(), c) != daily_cols.end());
    }
}
