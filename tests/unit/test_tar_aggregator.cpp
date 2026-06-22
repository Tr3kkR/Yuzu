/**
 * test_tar_aggregator.cpp -- Unit tests for the TAR rollup + retention engine
 *
 * Anchors the contract documented in `tar_plugin.cpp` `configure` and
 * `docs/user-manual/tar.md`: disabling a source via `<source>_enabled=false`
 * leaves existing rows queryable. Without the per-source guard in
 * `run_retention()`, time-based retention drains the hourly tier within 24h,
 * the daily tier within 31d, and the monthly tier within ~365d after disable
 * — see issue #539 and the chaos-injector CHAOS-2 reproduction.
 */

#include "tar_aggregator.hpp"
#include "tar_db.hpp"
#include "tar_schema_registry.hpp"
#include "test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <format>
#include <set>
#include <string>
#include <string_view>

using namespace yuzu::tar;

namespace {

// Issue #539 anchor: 24h cutoff for the hourly tier in the schema registry.
// If the registry's `process_hourly` retention_default ever changes, the
// helpers below have to follow.
constexpr int64_t kHourlyCutoffSec = 24 * 3600;

int64_t row_count(TarDatabase& db, const std::string& table) {
    auto res = db.execute_query("SELECT COUNT(*) FROM " + table);
    REQUIRE(res.has_value());
    REQUIRE(res->rows.size() == 1);
    return std::stoll(res->rows[0][0]);
}

// Seed 48 hourly rows centered on t_now so half (h=0..23) fall inside the
// 24h retention window and half (h=24..47) fall outside it. With the source
// enabled, retention at t_now deletes the outside half only; with the source
// disabled, retention preserves all 48.
void seed_process_hourly(TarDatabase& db, int64_t t_now) {
    for (int h = 0; h < 48; ++h) {
        REQUIRE(db.execute_sql(std::format(
            "INSERT INTO process_hourly "
            "(hour_ts,name,user,start_count,stop_count) "
            "VALUES ({}, 'svc.exe', 'SYSTEM', 1, 1)",
            t_now - h * 3600)));
    }
}

void seed_tcp_hourly(TarDatabase& db, int64_t t_now) {
    for (int h = 0; h < 48; ++h) {
        REQUIRE(db.execute_sql(std::format(
            "INSERT INTO tcp_hourly "
            "(hour_ts,remote_addr,remote_port,proto,process_name,"
            "connect_count,disconnect_count) "
            "VALUES ({}, '10.0.0.1', 5000, 'tcp', 'sshd', 1, 1)",
            t_now - h * 3600)));
    }
}

} // namespace

// ── #539 anchor: retention pauses while a source is disabled ────────────────

TEST_CASE("TAR retention: disabled source preserves hourly rows past cutoff",
          "[tar][retention][issue539]") {
    // Reproduction of /governance chaos-injector CHAOS-2. Without the
    // per-source guard, two retention passes (t0+1h and t0+25h) drain
    // process_hourly entirely after the operator disables process_enabled
    // — even though the configure docstring promises queryability.
    yuzu::test::TempDbFile tmp{std::string_view{"tar-issue539-"}};
    auto opened = TarDatabase::open(tmp.path);
    REQUIRE(opened.has_value());
    TarDatabase db = std::move(*opened);
    REQUIRE(db.create_warehouse_tables());

    const int64_t t0 = 1'735'689'600;  // 2025-01-01 00:00:00 UTC
    seed_process_hourly(db, t0);
    REQUIRE(row_count(db, "process_hourly") == 48);

    db.set_config("process_enabled", "false");

    run_retention(db, t0 + 3600);
    run_retention(db, t0 + kHourlyCutoffSec + 3600);

    CHECK(row_count(db, "process_hourly") == 48);
}

TEST_CASE("TAR retention: enabled sources still age out past cutoff",
          "[tar][retention][issue539]") {
    // Counter-test: an enabled source must continue to age out, otherwise
    // the #539 fix would silently disable retention everywhere. With the
    // 48-row centered seed, exactly the rows with hour_ts < (t_now -
    // retention_default) are deleted.
    yuzu::test::TempDbFile tmp{std::string_view{"tar-issue539-enabled-"}};
    auto opened = TarDatabase::open(tmp.path);
    REQUIRE(opened.has_value());
    TarDatabase db = std::move(*opened);
    REQUIRE(db.create_warehouse_tables());

    const int64_t t_now = 1'735'689'600 + kHourlyCutoffSec;
    seed_process_hourly(db, t_now);

    REQUIRE(db.get_config("process_enabled", "true") == "true");

    run_retention(db, t_now);

    auto remaining = row_count(db, "process_hourly");
    CHECK(remaining > 0);
    CHECK(remaining < 48);
}

TEST_CASE("TAR retention: re-enabling a source resumes retention",
          "[tar][retention][issue539]") {
    // Operator journey: freeze for analysis, take an export, re-enable to
    // resume normal aging. The guard is purely config-driven, so flipping
    // <source>_enabled back to "true" must immediately re-arm time-based
    // retention on the next rollup tick.
    yuzu::test::TempDbFile tmp{std::string_view{"tar-issue539-resume-"}};
    auto opened = TarDatabase::open(tmp.path);
    REQUIRE(opened.has_value());
    TarDatabase db = std::move(*opened);
    REQUIRE(db.create_warehouse_tables());

    const int64_t t_now = 1'735'689'600 + kHourlyCutoffSec;
    seed_process_hourly(db, t_now);

    db.set_config("process_enabled", "false");
    run_retention(db, t_now);
    REQUIRE(row_count(db, "process_hourly") == 48);

    db.set_config("process_enabled", "true");
    run_retention(db, t_now);

    auto after_resume = row_count(db, "process_hourly");
    CHECK(after_resume > 0);
    CHECK(after_resume < 48);
}

// ── PR-A (#547): apply_source_enabled_transition + paused_at semantics ─────

TEST_CASE("TAR paused_at: enabled→disabled writes the timestamp",
          "[tar][paused_at][pr-a]") {
    // Operator transitions process_enabled from default ("true") to "false"
    // — paused_at must record the wall-clock now passed to the helper.
    yuzu::test::TempDbFile tmp{std::string_view{"tar-pra-disable-"}};
    auto opened = TarDatabase::open(tmp.path);
    REQUIRE(opened.has_value());
    TarDatabase db = std::move(*opened);
    REQUIRE(db.create_warehouse_tables());

    REQUIRE(db.get_config("process_enabled", "true") == "true");
    REQUIRE(db.get_config("process_paused_at", "0") == "0");

    const int64_t t_now = 1'735'689'600;
    REQUIRE(apply_source_enabled_transition(db, "process", "false", t_now));

    CHECK(db.get_config("process_enabled", "true") == "false");
    CHECK(db.get_config("process_paused_at", "0") ==
          std::to_string(t_now));
}

TEST_CASE("TAR paused_at: disabled→enabled clears the timestamp to \"0\"",
          "[tar][paused_at][pr-a]") {
    // After re-enable, paused_at must read "0" (not absent — operators
    // distinguish "never paused" from "no key present"). The reverse
    // transition is the operator-journey close-out: freeze → export →
    // re-enable; the row drops out of the dashboard's retention-paused list.
    yuzu::test::TempDbFile tmp{std::string_view{"tar-pra-reenable-"}};
    auto opened = TarDatabase::open(tmp.path);
    REQUIRE(opened.has_value());
    TarDatabase db = std::move(*opened);
    REQUIRE(db.create_warehouse_tables());

    REQUIRE(apply_source_enabled_transition(db, "tcp", "false", 1'735'689'600));
    REQUIRE(db.get_config("tcp_paused_at", "0") == "1735689600");

    REQUIRE(apply_source_enabled_transition(db, "tcp", "true", 1'735'700'000));

    CHECK(db.get_config("tcp_enabled", "true") == "true");
    CHECK(db.get_config("tcp_paused_at", "0") == "0");
}

TEST_CASE("TAR paused_at: idempotent re-set leaves the timestamp untouched",
          "[tar][paused_at][pr-a]") {
    // If the operator submits configure with the same value the source
    // already holds, paused_at must NOT advance — otherwise repeated
    // configure round-trips would pretend the pause is fresher than it is,
    // misleading the retention-paused list's "paused since" column.
    yuzu::test::TempDbFile tmp{std::string_view{"tar-pra-idem-"}};
    auto opened = TarDatabase::open(tmp.path);
    REQUIRE(opened.has_value());
    TarDatabase db = std::move(*opened);
    REQUIRE(db.create_warehouse_tables());

    REQUIRE(apply_source_enabled_transition(db, "service", "false", 1'735'689'600));
    REQUIRE(db.get_config("service_paused_at", "0") == "1735689600");

    REQUIRE(apply_source_enabled_transition(db, "service", "false", 1'735'700'000));

    CHECK(db.get_config("service_paused_at", "0") == "1735689600");
}

TEST_CASE("TAR paused_at: per-source isolation",
          "[tar][paused_at][pr-a]") {
    // Disabling process must not touch tcp / service / user paused_at — the
    // PR-A retention-paused list relies on per-source rows being independent.
    yuzu::test::TempDbFile tmp{std::string_view{"tar-pra-iso-"}};
    auto opened = TarDatabase::open(tmp.path);
    REQUIRE(opened.has_value());
    TarDatabase db = std::move(*opened);
    REQUIRE(db.create_warehouse_tables());

    REQUIRE(apply_source_enabled_transition(db, "process", "false", 1'735'689'600));

    CHECK(db.get_config("process_paused_at", "0") == "1735689600");
    CHECK(db.get_config("tcp_paused_at", "0") == "0");
    CHECK(db.get_config("service_paused_at", "0") == "0");
    CHECK(db.get_config("user_paused_at", "0") == "0");
}

// ── #538: enabled→disabled clears the snapshot-diff baseline ──────────────
// The lock that serialises this against the collectors lives in the plugin
// (collect_mu_, do_configure) and is not unit-testable here; what IS
// deterministically verifiable — and what fails on pre-fix code — is that the
// transition wipes the diff baseline (so a later re-enable starts clean instead
// of emitting ghost "stopped" events) AND that it wipes the CORRECT key
// (tcp→"network", the easy-to-get-wrong mapping).

TEST_CASE("TAR #538: enabled→disabled clears the diff baseline state",
          "[tar][paused_at][issue538]") {
    yuzu::test::TempDbFile tmp{std::string_view{"tar-538-clear-"}};
    auto opened = TarDatabase::open(tmp.path);
    REQUIRE(opened.has_value());
    TarDatabase db = std::move(*opened);
    REQUIRE(db.create_warehouse_tables());

    // Seed a non-empty process baseline (as a live collect cycle would).
    REQUIRE(db.set_state("process", R"([{"pid":1,"name":"init"}])"));
    REQUIRE_FALSE(db.get_state("process").empty());

    REQUIRE(apply_source_enabled_transition(db, "process", "false", 1'735'689'600));

    CHECK(db.get_config("process_enabled", "true") == "false");
    CHECK(db.get_config("process_paused_at", "0") == "1735689600");
    // The baseline is gone — re-enable will rebuild from a clean snapshot.
    CHECK(db.get_state("process").empty());
}

TEST_CASE("TAR #538: disabling tcp clears the 'network' baseline key, not 'tcp'",
          "[tar][paused_at][issue538]") {
    // tcp's snapshot-diff baseline lives under "network" (diff_state_key). A
    // clear that targeted the literal source name "tcp" would be a silent no-op
    // and the ghost-death bug would survive — pin the mapping here.
    yuzu::test::TempDbFile tmp{std::string_view{"tar-538-tcpmap-"}};
    auto opened = TarDatabase::open(tmp.path);
    REQUIRE(opened.has_value());
    TarDatabase db = std::move(*opened);
    REQUIRE(db.create_warehouse_tables());

    REQUIRE(db.set_state("network", R"([{"laddr":"0.0.0.0:22"}])"));
    REQUIRE_FALSE(db.get_state("network").empty());

    REQUIRE(apply_source_enabled_transition(db, "tcp", "false", 1'735'689'600));

    CHECK(db.get_state("network").empty());
}

TEST_CASE("TAR #538: every snapshot-diff source clears its mapped baseline",
          "[tar][paused_at][issue538]") {
    struct Case { const char* source; const char* state_key; };
    const Case cases[] = {{"process", "process"}, {"tcp", "network"},
                          {"service", "service"}, {"user", "user"},
                          {"arp", "arp"}, {"dns", "dns"}}; // ADR-0011 snapshot-diff sources

    yuzu::test::TempDbFile tmp{std::string_view{"tar-538-parity-"}};
    auto opened = TarDatabase::open(tmp.path);
    REQUIRE(opened.has_value());
    TarDatabase db = std::move(*opened);
    REQUIRE(db.create_warehouse_tables());

    for (const auto& c : cases) {
        // Distinct {source,state_key} per row and a fresh source each iteration,
        // so a single shared db is safe (no _enabled carry-over between rows).
        // Seed enabled first: the opt-in sources (arp/dns, default_enabled=false)
        // would otherwise see their first `=false` as a no-op (already off), so
        // the disable leg never fires and the baseline is never cleared. Setting
        // `<source>_enabled=true` makes the subsequent disable a real transition
        // for every source uniformly.
        db.set_config(std::format("{}_enabled", c.source), "true");
        REQUIRE(db.set_state(c.state_key, R"([{"x":1}])"));
        REQUIRE_FALSE(db.get_state(c.state_key).empty());

        REQUIRE(apply_source_enabled_transition(db, c.source, "false", 1'735'689'600));

        CHECK(db.get_state(c.state_key).empty());
    }
}

TEST_CASE("TAR #538: disabling one source does not clear another's baseline",
          "[tar][paused_at][issue538]") {
    // Cross-source isolation: a regression that cleared ALL keys instead of the
    // targeted one would still pass the per-source parity test above. Seed all
    // four side-by-side, disable one, assert only its key is wiped.
    yuzu::test::TempDbFile tmp{std::string_view{"tar-538-xsrc-"}};
    auto opened = TarDatabase::open(tmp.path);
    REQUIRE(opened.has_value());
    TarDatabase db = std::move(*opened);
    REQUIRE(db.create_warehouse_tables());

    REQUIRE(db.set_state("process", R"([{"pid":1}])"));
    REQUIRE(db.set_state("network", R"([{"laddr":"0.0.0.0:22"}])"));
    REQUIRE(db.set_state("service", R"([{"name":"sshd"}])"));
    REQUIRE(db.set_state("user", R"([{"name":"root"}])"));

    REQUIRE(apply_source_enabled_transition(db, "process", "false", 1'735'689'600));

    CHECK(db.get_state("process").empty());          // targeted source cleared
    CHECK_FALSE(db.get_state("network").empty());    // others untouched
    CHECK_FALSE(db.get_state("service").empty());
    CHECK_FALSE(db.get_state("user").empty());
}

TEST_CASE("TAR #538: a failed baseline clear leaves the source ENABLED (UP-1)",
          "[tar][paused_at][issue538]") {
    // Fail-safe ordering: if the baseline clear cannot persist, the disable must
    // NOT take effect — otherwise we'd have a disabled source with a stale
    // baseline, which reintroduces ghost "stopped" events on re-enable while the
    // operator saw success. Inject a clear failure by dropping tar_state so the
    // set_state INSERT prepare fails.
    yuzu::test::TempDbFile tmp{std::string_view{"tar-538-clearfail-"}};
    auto opened = TarDatabase::open(tmp.path);
    REQUIRE(opened.has_value());
    TarDatabase db = std::move(*opened);
    REQUIRE(db.create_warehouse_tables());

    db.execute_sql("DROP TABLE tar_state");

    // The disable must report failure and leave the flag enabled.
    CHECK_FALSE(apply_source_enabled_transition(db, "process", "false", 1'735'689'600));
    CHECK(db.get_config("process_enabled", "true") == "true"); // still enabled
    CHECK(db.get_config("process_paused_at", "0") == "0");      // never paused
}

TEST_CASE("TAR #538: only the enable→disable TRANSITION clears (idempotent)",
          "[tar][paused_at][issue538]") {
    // The clear must fire on the transition, not on every false-write — a
    // repeated `configure ..._enabled=false` after a re-seed must NOT wipe a
    // freshly-rebuilt baseline (that would re-introduce the race by another door).
    yuzu::test::TempDbFile tmp{std::string_view{"tar-538-idem-"}};
    auto opened = TarDatabase::open(tmp.path);
    REQUIRE(opened.has_value());
    TarDatabase db = std::move(*opened);
    REQUIRE(db.create_warehouse_tables());

    REQUIRE(db.set_state("process", R"([{"pid":1}])"));
    REQUIRE(apply_source_enabled_transition(db, "process", "false", 1'735'689'600)); // clears
    REQUIRE(db.get_state("process").empty());

    // Something re-seeds the baseline; a second false-write is NOT a transition.
    REQUIRE(db.set_state("process", R"([{"pid":2}])"));
    REQUIRE(apply_source_enabled_transition(db, "process", "false", 1'735'700'000));

    CHECK_FALSE(db.get_state("process").empty());                   // untouched
    CHECK(db.get_config("process_paused_at", "0") == "1735689600"); // not advanced
}

TEST_CASE("TAR #538: re-enable neither clears nor resurrects the baseline",
          "[tar][paused_at][issue538]") {
    yuzu::test::TempDbFile tmp{std::string_view{"tar-538-reenable-"}};
    auto opened = TarDatabase::open(tmp.path);
    REQUIRE(opened.has_value());
    TarDatabase db = std::move(*opened);
    REQUIRE(db.create_warehouse_tables());

    REQUIRE(db.set_state("process", R"([{"pid":1}])"));
    REQUIRE(apply_source_enabled_transition(db, "process", "false", 1'735'689'600)); // clears
    REQUIRE(db.get_state("process").empty());

    REQUIRE(apply_source_enabled_transition(db, "process", "true", 1'735'700'000));

    CHECK(db.get_config("process_enabled", "true") == "true");
    CHECK(db.get_config("process_paused_at", "0") == "0");
    CHECK(db.get_state("process").empty()); // clean baseline preserved
}

TEST_CASE("TAR #538: diff_state_key mapping is the single source of truth",
          "[tar][issue538]") {
    CHECK(diff_state_key("process") == "process");
    CHECK(diff_state_key("tcp") == "network"); // NOT "tcp"
    CHECK(diff_state_key("service") == "service");
    CHECK(diff_state_key("user") == "user");
    CHECK(diff_state_key("arp") == "arp"); // ADR-0011
    CHECK(diff_state_key("dns") == "dns"); // ADR-0011
    // No snapshot-diff baseline: disabling these is a state no-op.
    CHECK(diff_state_key("perf").empty());
    CHECK(diff_state_key("procperf").empty());
    CHECK(diff_state_key("netqual").empty());
    CHECK(diff_state_key("nonsense").empty());
}

TEST_CASE("TAR #538: every registered capture source is classified by diff_state_key",
          "[tar][issue538]") {
    // Drift guard: diff_state_key and capture_sources() are independent lists.
    // If someone adds a 5th snapshot-diff source to the registry but forgets to
    // map it here, diff_state_key would return empty → the disable-clear becomes
    // a silent no-op and #538 silently regresses for the new source. Pin every
    // registered source to an explicit classification so a new one fails loudly.
    const std::set<std::string_view> diff_sources = {"process", "tcp", "service", "user",
                                                      "arp", "dns"};
    // module is a stream-drained source (EventRing, like the process ETW/ES
    // stream) with no snapshot-diff baseline, so diff_state_key("module") is
    // empty and disabling it is a state no-op — non-diff, same as perf/netqual.
    const std::set<std::string_view> non_diff_sources = {"perf", "procperf", "netqual", "module"};

    for (const auto& src : capture_sources()) {
        const bool is_diff = diff_sources.contains(src.name);
        const bool is_non_diff = non_diff_sources.contains(src.name);
        INFO("source: " << src.name);
        // Every registered source must be explicitly classified as one or the
        // other — a brand-new source matches neither set and fails here.
        CHECK(is_diff != is_non_diff);
        // …and diff_state_key must agree with that classification.
        CHECK(diff_state_key(src.name).empty() == is_non_diff);
    }
}

TEST_CASE("TAR #538: disabling perf/procperf does not touch any baseline state",
          "[tar][paused_at][issue538]") {
    // perf/procperf keep an in-memory previous reading (out of scope for #538);
    // the transition must not error and must leave the state store untouched.
    yuzu::test::TempDbFile tmp{std::string_view{"tar-538-perf-"}};
    auto opened = TarDatabase::open(tmp.path);
    REQUIRE(opened.has_value());
    TarDatabase db = std::move(*opened);
    REQUIRE(db.create_warehouse_tables());

    REQUIRE(db.set_state("process", R"([{"pid":1}])")); // unrelated baseline must survive
    REQUIRE(apply_source_enabled_transition(db, "perf", "false", 1'735'689'600));
    REQUIRE(apply_source_enabled_transition(db, "procperf", "false", 1'735'689'600));

    CHECK(db.get_config("perf_enabled", "true") == "false");
    CHECK_FALSE(db.get_state("process").empty());
}

TEST_CASE("TAR retention: disabling one source does not pause others",
          "[tar][retention][issue539]") {
    // Independence invariant: the guard is per-source. Disabling
    // process_enabled must not freeze tcp / service / user retention —
    // otherwise a future refactor could turn the per-source guard into a
    // global switch without deleting a named test.
    yuzu::test::TempDbFile tmp{std::string_view{"tar-issue539-isolation-"}};
    auto opened = TarDatabase::open(tmp.path);
    REQUIRE(opened.has_value());
    TarDatabase db = std::move(*opened);
    REQUIRE(db.create_warehouse_tables());

    const int64_t t_now = 1'735'689'600 + kHourlyCutoffSec;
    seed_process_hourly(db, t_now);
    seed_tcp_hourly(db, t_now);

    db.set_config("process_enabled", "false");
    // tcp_enabled left at default => "true"
    run_retention(db, t_now);

    CHECK(row_count(db, "process_hourly") == 48);   // disabled, preserved
    auto tcp_remaining = row_count(db, "tcp_hourly");
    CHECK(tcp_remaining > 0);                       // enabled, partially aged
    CHECK(tcp_remaining < 48);
}

// ── $Module rollup wiring (M1 hardening — governance UP-1 / architect BLOCKING) ─

TEST_CASE("TAR rollup: $Module hourly aggregation fires and counts loads only",
          "[tar][module][rollup]") {
    // run_aggregation is now data-driven over capture_sources(); this proves the
    // $Module hourly rollup actually executes (the old hand-maintained steps[]
    // array omitted it, so the registered rollup SQL was dead code) AND that
    // load_count counts only the 'loaded' action — a 'blocked' BYOVD load stays
    // full-fidelity in module_live but is excluded from the aggregate count.
    yuzu::test::TempDbFile tmp{std::string_view{"tar-module-rollup-"}};
    auto opened = TarDatabase::open(tmp.path);
    REQUIRE(opened.has_value());
    TarDatabase db = std::move(*opened);
    REQUIRE(db.create_warehouse_tables());

    const int64_t t0 = 1'735'689'600; // 2025-01-01 00:00:00 UTC (an hour boundary)
    auto insert_module = [&](std::string_view action) {
        REQUIRE(db.execute_sql(std::format(
            "INSERT INTO module_live "
            "(ts,snapshot_id,action,pid,process_name,module_name,module_dir,"
            "signed_state,signer,is_kernel) "
            "VALUES ({}, 1, '{}', 100, 'app.exe', 'evil.dll', 'appdir', "
            "'unsigned', '', 0)",
            t0, action)));
    };
    insert_module("loaded");
    insert_module("loaded");
    insert_module("loaded");
    // Every non-'loaded' action must be EXCLUDED from load_count while staying
    // full-fidelity in module_live: a 'blocked' BYOVD load, a boot-gap 'seed',
    // and an 'unloaded' event. They share evil.dll's GROUP-BY tuple (module_name,
    // signer, signed_state, is_kernel), so they fold into the same hourly row —
    // proving the rollup's `action='loaded'` predicate, not just row identity,
    // is what filters them.
    insert_module("blocked");
    insert_module("seed");
    insert_module("unloaded");

    REQUIRE(row_count(db, "module_live") == 6);
    REQUIRE(row_count(db, "module_hourly") == 0);

    run_aggregation(db, t0 + 7200); // boundary two hours on → window covers t0

    REQUIRE(row_count(db, "module_hourly") == 1);
    auto res = db.execute_query("SELECT load_count FROM module_hourly");
    REQUIRE(res.has_value());
    REQUIRE(res->rows.size() == 1);
    CHECK(std::stoll(res->rows[0][0]) == 3); // only the 3 'loaded'; blocked/seed/unloaded excluded
}

// ── Default-off opt-in sources (review R1 — module/procperf/netqual) ─────────

TEST_CASE("TAR default-off: opt-in source's first disable is a no-op transition",
          "[tar][module][paused_at][default-off]") {
    // The required M1 fix: `module` (and procperf/netqual) default DISABLED on a
    // fresh DB. apply_source_enabled_transition routes the `prev` default through
    // CaptureSourceDef::default_enabled, so the first-ever `module_enabled=false`
    // is NOT an enabled→disabled transition and must write NO paused_at — whereas
    // the same call for the always-on `process` IS a real transition. This is the
    // testable proxy for "tar.status reports module disabled while default-on
    // sources stay enabled" (do_status itself reads the same default_enabled
    // field but is not compiled into the unit-test exe).
    yuzu::test::TempDbFile tmp{std::string_view{"tar-default-off-"}};
    auto opened = TarDatabase::open(tmp.path);
    REQUIRE(opened.has_value());
    TarDatabase db = std::move(*opened);
    REQUIRE(db.create_warehouse_tables());

    const int64_t t_now = 1'735'689'600;

    // Opt-in sources default false → first disable is idempotent, no paused_at.
    for (const auto* src : {"module", "procperf", "netqual"}) {
        INFO("opt-in source=" << src);
        CHECK_FALSE(source_default_enabled(src));
        apply_source_enabled_transition(db, src, "false", t_now);
        CHECK(db.get_config(std::format("{}_paused_at", src), "0") == "0");
    }

    // An always-on source defaults true → first disable is a real transition.
    CHECK(source_default_enabled("process"));
    apply_source_enabled_transition(db, "process", "false", t_now);
    CHECK(db.get_config("process_paused_at", "0") == std::to_string(t_now));

    // And enabling an opt-in source IS a transition from its default-off state:
    // it clears paused_at to "0" (present, not absent).
    apply_source_enabled_transition(db, "module", "true", t_now + 100);
    CHECK(db.get_config("module_enabled", "false") == "true");
    CHECK(db.get_config("module_paused_at", "0") == "0");
}
