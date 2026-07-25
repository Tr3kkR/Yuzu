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
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

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
        REQUIRE(db.execute_sql(std::format("INSERT INTO process_hourly "
                                           "(hour_ts,name,user,start_count,stop_count) "
                                           "VALUES ({}, 'svc.exe', 'SYSTEM', 1, 1)",
                                           t_now - h * 3600)));
    }
}

void seed_tcp_hourly(TarDatabase& db, int64_t t_now) {
    for (int h = 0; h < 48; ++h) {
        REQUIRE(db.execute_sql(std::format("INSERT INTO tcp_hourly "
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
    yuzu::tar::RetentionGuardState guard;
    // Reproduction of /governance chaos-injector CHAOS-2. Without the
    // per-source guard, two retention passes (t0+1h and t0+25h) drain
    // process_hourly entirely after the operator disables process_enabled
    // — even though the configure docstring promises queryability.
    yuzu::test::TempDbFile tmp{std::string_view{"tar-issue539-"}};
    auto opened = TarDatabase::open(tmp.path);
    REQUIRE(opened.has_value());
    TarDatabase db = std::move(*opened);
    REQUIRE(db.create_warehouse_tables());

    const int64_t t0 = 1'735'689'600; // 2025-01-01 00:00:00 UTC
    seed_process_hourly(db, t0);
    REQUIRE(row_count(db, "process_hourly") == 48);

    db.set_config("process_enabled", "false");

    run_retention(db, t0 + 3600, guard);
    run_retention(db, t0 + kHourlyCutoffSec + 3600, guard);

    CHECK(row_count(db, "process_hourly") == 48);
}

TEST_CASE("TAR retention: enabled sources still age out past cutoff",
          "[tar][retention][issue539]") {
    yuzu::tar::RetentionGuardState guard;
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

    run_retention(db, t_now, guard);

    auto remaining = row_count(db, "process_hourly");
    CHECK(remaining > 0);
    CHECK(remaining < 48);
}

TEST_CASE("TAR retention: re-enabling a source resumes retention", "[tar][retention][issue539]") {
    yuzu::tar::RetentionGuardState guard;
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
    run_retention(db, t_now, guard);
    REQUIRE(row_count(db, "process_hourly") == 48);

    db.set_config("process_enabled", "true");
    run_retention(db, t_now, guard);

    auto after_resume = row_count(db, "process_hourly");
    CHECK(after_resume > 0);
    CHECK(after_resume < 48);
}

// ── PR-A (#547): apply_source_enabled_transition + paused_at semantics ─────

TEST_CASE("TAR paused_at: enabled→disabled writes the timestamp", "[tar][paused_at][pr-a]") {
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
    CHECK(db.get_config("process_paused_at", "0") == std::to_string(t_now));
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

TEST_CASE("TAR paused_at: recovering an errored source via =true clears the timestamp (#560)",
          "[tar][paused_at][source-lifecycle]") {
    // Regression for the fjarvis-review asymmetry: the disable leg fires on any
    // non-"false" prev ("errored" included), but the re-enable leg used to reset
    // paused_at ONLY on prev == "false". So recovering a corrupt/tampered source
    // — `configure <src>_enabled=true` from an "errored" value — resumed
    // collection yet left a stale non-zero paused_at, and `status` then reported
    // enabled=true alongside a paused timestamp (dashboard renders a collecting
    // source as paused). Both legs now gate on the canonical tri-state, so the
    // recovery clears paused_at. Pre-fix this CHECK held the stale 1735689600.
    yuzu::test::TempDbFile tmp{std::string_view{"tar-560-errored-reenable-"}};
    auto opened = TarDatabase::open(tmp.path);
    REQUIRE(opened.has_value());
    TarDatabase db = std::move(*opened);
    REQUIRE(db.create_warehouse_tables());

    // 1) Pause the source for real → paused_at records the wall-clock now.
    REQUIRE(apply_source_enabled_transition(db, "process", "false", 1'735'689'600));
    REQUIRE(db.get_config("process_paused_at", "0") == "1735689600");

    // 2) The on-disk _enabled value is then clobbered to a value the plugin
    //    never writes (corruption / tampering) → canonicalises to "errored".
    db.set_config("process_enabled", "maybe");
    REQUIRE(canonical_source_enabled(db.get_config("process_enabled", "true")) == "errored");

    // 3) Operator recovers the source: configure process_enabled=true.
    REQUIRE(apply_source_enabled_transition(db, "process", "true", 1'735'700'000));

    CHECK(db.get_config("process_enabled", "true") == "true");
    CHECK(db.get_config("process_paused_at", "0") == "0");
}

TEST_CASE("TAR source_enabled: the destructive-purge paused-guard predicate (15.A)",
          "[tar][source-enabled][purge]") {
    // source_enabled is the authoritative guard for tar.purge_source: the action
    // refuses unless this returns false (source is paused). Pin the exact predicate
    // the plugin branches on so a regression that mis-reads the enabled-state — and
    // would let a purge hit an actively-collecting source, or wrongly refuse a
    // paused one — is caught here even though do_purge_source itself lives in the
    // (test-unlinked) plugin TU. Governance B1.
    yuzu::test::TempDbFile tmp{std::string_view{"tar-15a-guard-"}};
    auto opened = TarDatabase::open(tmp.path);
    REQUIRE(opened.has_value());
    TarDatabase db = std::move(*opened);
    REQUIRE(db.create_warehouse_tables());

    // Never configured: a purge-whitelisted source defaults ENABLED → guard refuses
    // (you cannot purge a source you never deliberately paused).
    REQUIRE(source_default_enabled("process"));
    CHECK(source_enabled(db, "process")); // → tar.purge_source REFUSES

    // Paused: enabled=false → guard allows the purge.
    db.set_config("process_enabled", "false");
    CHECK_FALSE(source_enabled(db, "process")); // → tar.purge_source ALLOWED

    // Re-enabled between scan and purge (the TOCTOU the guard closes): true → refuse.
    db.set_config("process_enabled", "true");
    CHECK(source_enabled(db, "process")); // → tar.purge_source REFUSES

    // #560 fail-closed: a tampered/corrupt flag canonicalises to "errored", which
    // is NOT "true", so the source reads disabled — a purge is allowed (operator-
    // targeted, and the flag is already invalid), never wrongly treated as enabled.
    db.set_config("process_enabled", "maybe");
    CHECK_FALSE(source_enabled(db, "process")); // → tar.purge_source ALLOWED (fail-closed)
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

TEST_CASE("TAR paused_at: per-source isolation", "[tar][paused_at][pr-a]") {
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
    struct Case {
        const char* source;
        const char* state_key;
    };
    const Case cases[] = {{"process", "process"}, {"tcp", "network"},
                          {"service", "service"}, {"user", "user"},
                          {"software", "software"},
                          {"arp", "arp"},         {"dns", "dns"}}; // ADR-0015 snapshot-diff sources

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

    CHECK(db.get_state("process").empty());       // targeted source cleared
    CHECK_FALSE(db.get_state("network").empty()); // others untouched
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
    CHECK(db.get_config("process_paused_at", "0") == "0");     // never paused
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

TEST_CASE("TAR #538: diff_state_key mapping is the single source of truth", "[tar][issue538]") {
    CHECK(diff_state_key("process") == "process");
    CHECK(diff_state_key("tcp") == "network"); // NOT "tcp"
    CHECK(diff_state_key("service") == "service");
    CHECK(diff_state_key("user") == "user");
    CHECK(diff_state_key("software") == "software");
    CHECK(diff_state_key("arp") == "arp"); // ADR-0015
    CHECK(diff_state_key("dns") == "dns"); // ADR-0015
    CHECK(diff_state_key("mapdrive") == "mapdrive"); // §3.8
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
    const std::set<std::string_view> diff_sources = {"process", "tcp",  "service",  "user",
                                                      "software", "arp", "dns", "mapdrive"};
    // module is a stream-drained source (EventRing, like the process ETW/ES
    // stream) with no snapshot-diff baseline, so diff_state_key("module") is
    // empty and disabling it is a state no-op — non-diff, same as perf/netqual.
    // netconn (ADR-0020) is high-water-mark based: its only state is the
    // netconn_backfill_hwm config key, and keeping it across a disable is the
    // FEATURE (the OS event log retains the paused window, so a re-enable
    // recovers it losslessly — no ghost events possible, nothing to clear).
    const std::set<std::string_view> non_diff_sources = {"perf", "procperf", "netqual", "module",
                                                          "netconn"};

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
    yuzu::tar::RetentionGuardState guard;
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
    run_retention(db, t_now, guard);

    CHECK(row_count(db, "process_hourly") == 48); // disabled, preserved
    auto tcp_remaining = row_count(db, "tcp_hourly");
    CHECK(tcp_remaining > 0); // enabled, partially aged
    CHECK(tcp_remaining < 48);
}

// ── #541: configure-time pattern validation ────────────────────────────────

TEST_CASE("TAR validate_config_pattern enforces the length cap", "[tar][configure][issue541]") {
    const std::string ok(yuzu::tar::kMaxPatternLength, 'a');
    const std::string too_long(yuzu::tar::kMaxPatternLength + 1, 'a');
    CHECK_FALSE(yuzu::tar::validate_config_pattern(ok, /*require_min_core_len=*/false).has_value());
    CHECK(yuzu::tar::validate_config_pattern(too_long, false).has_value());
    CHECK(yuzu::tar::validate_config_pattern(too_long, true).has_value());
}

TEST_CASE("TAR validate_config_pattern enforces the min core length on the STRIPPED core",
          "[tar][configure][issue541]") {
    // require_min_core_len=true (process_stabilization_exclusions): the floor is
    // measured on the EFFECTIVE substring after stripping leading/trailing '*'.
    CHECK(yuzu::tar::validate_config_pattern("a", true).has_value());
    CHECK(yuzu::tar::validate_config_pattern("ab", true).has_value());
    CHECK_FALSE(yuzu::tar::validate_config_pattern("abc", true).has_value());
    // `*` does NOT bypass the floor — "*a*" strips to core "a" and would still
    // match almost every process (gov UP-2 / security MEDIUM-1).
    CHECK(yuzu::tar::validate_config_pattern("*a*", true).has_value());
    CHECK(yuzu::tar::validate_config_pattern("a*", true).has_value());
    CHECK(yuzu::tar::validate_config_pattern("*", true).has_value());  // core empty
    CHECK(yuzu::tar::validate_config_pattern("**", true).has_value()); // core empty
    // A long-enough core with wildcards is fine.
    CHECK_FALSE(yuzu::tar::validate_config_pattern("*abc*", true).has_value());
    CHECK_FALSE(yuzu::tar::validate_config_pattern("chrome-helper", true).has_value());

    // require_min_core_len=false (redaction_patterns): short patterns allowed —
    // a short redaction substring over-redacts, it does not silently drop events.
    CHECK_FALSE(yuzu::tar::validate_config_pattern("a", false).has_value());
    CHECK_FALSE(yuzu::tar::validate_config_pattern("*a*", false).has_value());
}

TEST_CASE("TAR parse_pattern_config clamps + sanitises at load (#541 UP-1)",
          "[tar][configure][issue541]") {
    using yuzu::tar::parse_pattern_config;

    // A non-array stored value → nullopt (caller falls back to its default).
    CHECK_FALSE(parse_pattern_config("not json").has_value());
    CHECK_FALSE(parse_pattern_config("\"a string\"").has_value());
    CHECK_FALSE(parse_pattern_config("{\"k\":1}").has_value());

    // Valid empty array → empty vector (explicit "no patterns", not the default).
    auto empty = parse_pattern_config("[]");
    REQUIRE(empty.has_value());
    CHECK(empty->empty());

    // Non-string / empty / over-long elements are dropped; valid ones kept.
    std::string over_long(yuzu::tar::kMaxPatternLength + 1, 'x');
    auto mixed = parse_pattern_config(
        std::format("[123, \"keep1\", \"\", \"{}\", true, \"keep2\"]", over_long));
    REQUIRE(mixed.has_value());
    REQUIRE(mixed->size() == 2);
    CHECK((*mixed)[0] == "keep1");
    CHECK((*mixed)[1] == "keep2");

    // Element-count cap: an array of 300 valid strings truncates to the cap.
    std::string big = "[";
    for (int i = 0; i < 300; ++i)
        big += (i ? ",\"pat" : "\"pat") + std::to_string(i) + "\"";
    big += "]";
    auto clamped = parse_pattern_config(big);
    REQUIRE(clamped.has_value());
    CHECK(clamped->size() == yuzu::tar::kMaxPatternArrayElements);

    // Pre-parse byte cap (gov MEDIUM): a blob larger than kMaxPatternConfigBytes is
    // rejected as unparseable (nullopt) BEFORE json::parse, so a multi-MB tampered/
    // legacy value can't be fully parsed + copied every fast cycle. A maximal valid
    // array (just under the cap) still parses.
    std::string oversized = "[\"" + std::string(yuzu::tar::kMaxPatternConfigBytes, 'x') + "\"]";
    CHECK_FALSE(parse_pattern_config(oversized).has_value());
}

TEST_CASE("TAR parse_pattern_config enforces the min-core floor on the LOAD path (#541)",
          "[tar][configure][issue541]") {
    // The REQUIRED gap: load_stabilization_exclusions re-parses the stored value
    // every fast cycle, so the ≥3-char effective-core floor must be enforced HERE
    // (require_min_core_len=true), not only at configure. Otherwise a sub-floor
    // value persisted before the floor existed (a no-tamper upgrade) or written
    // out of band reaches should_redact and silently drops most process events.
    using yuzu::tar::parse_pattern_config;

    // Exclusions loader (floor ON): "a" and "*a*" (core "a") drop, "abc" kept.
    auto excl = parse_pattern_config(R"(["a","*a*","abc"])", /*require_min_core_len=*/true);
    REQUIRE(excl.has_value());
    REQUIRE(excl->size() == 1);
    CHECK((*excl)[0] == "abc");

    // Mixed: only cores ≥3 chars survive; '*' does not buy a pass.
    auto mixed = parse_pattern_config(R"(["ab","*x*","chrome-helper","*abc*"])", true);
    REQUIRE(mixed.has_value());
    REQUIRE(mixed->size() == 2);
    CHECK((*mixed)[0] == "chrome-helper");
    CHECK((*mixed)[1] == "*abc*");

    // Redaction loader (floor OFF, the default): short cores are KEPT — a short
    // redaction substring over-redacts a command line, it never drops an event.
    auto redact = parse_pattern_config(R"(["a","*a*","abc"])");
    REQUIRE(redact.has_value());
    CHECK(redact->size() == 3);
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
        REQUIRE(db.execute_sql(
            std::format("INSERT INTO module_live "
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

TEST_CASE("TAR rollup: $Software live→daily→monthly counts by action",
          "[tar][software][rollup]") {
    // The software source has no hourly tier (live → daily → monthly), proving
    // the data-driven aggregator handles a non-uniform granularity set: daily
    // rolls from live and monthly rolls from daily in one pass. Each action gets
    // its own count column.
    yuzu::test::TempDbFile tmp{std::string_view{"tar-software-rollup-"}};
    auto opened = TarDatabase::open(tmp.path);
    REQUIRE(opened.has_value());
    TarDatabase db = std::move(*opened);
    REQUIRE(db.create_warehouse_tables());

    const int64_t t0 = 1'735'689'600; // 2025-01-01 00:00:00 UTC (day + month boundary)
    auto insert_sw = [&](std::string_view action, std::string_view version,
                         std::string_view prev_version) {
        REQUIRE(db.execute_sql(std::format(
            "INSERT INTO software_live "
            "(ts,snapshot_id,action,name,version,prev_version,publisher,install_date) "
            "VALUES ({}, 1, '{}', '7-Zip', '{}', '{}', 'Acme', '20250101')",
            t0, action, version, prev_version)));
    };
    insert_sw("installed", "23.01", "");
    insert_sw("installed", "23.01", "");
    insert_sw("removed", "23.01", "");
    insert_sw("upgraded", "24.00", "23.01");

    REQUIRE(row_count(db, "software_live") == 4);
    REQUIRE(row_count(db, "software_daily") == 0);
    REQUIRE(row_count(db, "software_monthly") == 0);

    // Aggregate from a point in the FOLLOWING month so both the daily window
    // (covers t0's day) and the monthly window (covers t0's whole month) include
    // the seeded events in a single pass.
    run_aggregation(db, t0 + 45 * 86400); // ~2025-02-15

    REQUIRE(row_count(db, "software_daily") == 1);
    auto daily = db.execute_query(
        "SELECT install_count, remove_count, upgrade_count FROM software_daily");
    REQUIRE(daily.has_value());
    REQUIRE(daily->rows.size() == 1);
    CHECK(std::stoll(daily->rows[0][0]) == 2); // installed
    CHECK(std::stoll(daily->rows[0][1]) == 1); // removed
    CHECK(std::stoll(daily->rows[0][2]) == 1); // upgraded

    REQUIRE(row_count(db, "software_monthly") == 1);
    auto monthly = db.execute_query(
        "SELECT install_count, remove_count, upgrade_count FROM software_monthly");
    REQUIRE(monthly.has_value());
    REQUIRE(monthly->rows.size() == 1);
    CHECK(std::stoll(monthly->rows[0][0]) == 2);
    CHECK(std::stoll(monthly->rows[0][1]) == 1);
    CHECK(std::stoll(monthly->rows[0][2]) == 1);
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

TEST_CASE("TAR retention: a corrupt/errored _enabled value preserves rows, never prunes (#560)",
          "[tar][retention][source-lifecycle]") {
    yuzu::tar::RetentionGuardState guard;
    // The collect-time gate (source_enabled) fails closed on a non-canonical
    // _enabled value, mapping it to "errored". Retention MUST agree and preserve
    // that source's rows — otherwise a tampered or bit-flipped value would stop
    // collection (per the gate) yet still let run_retention prune the forensic
    // window the operator believes is paused, the exact breach #560/#559 guard.
    yuzu::test::TempDbFile tmp{std::string_view{"tar-560-retention-"}};
    auto opened = TarDatabase::open(tmp.path);
    REQUIRE(opened.has_value());
    TarDatabase db = std::move(*opened);
    REQUIRE(db.create_warehouse_tables());

    const int64_t t_now = 1'735'689'600 + kHourlyCutoffSec;
    seed_process_hourly(db, t_now);
    seed_tcp_hourly(db, t_now);

    // A value the plugin never writes — canonical_source_enabled => "errored".
    db.set_config("process_enabled", "maybe");
    REQUIRE(canonical_source_enabled(db.get_config("process_enabled", "true")) == "errored");
    // tcp_enabled left at default => "true" (actively, validly enabled).
    run_retention(db, t_now, guard);

    CHECK(row_count(db, "process_hourly") == 48); // errored => preserved, not pruned
    auto tcp_remaining = row_count(db, "tcp_hourly");
    CHECK(tcp_remaining > 0); // enabled => aged normally
    CHECK(tcp_remaining < 48);
}

TEST_CASE("TAR canonical_source_enabled is a strict tri-state (#560)", "[tar][source-lifecycle]") {
    CHECK(canonical_source_enabled("true") == "true");
    CHECK(canonical_source_enabled("false") == "false");
    // Anything the plugin never writes is flagged, never coerced/guessed.
    CHECK(canonical_source_enabled("FALSE") == "errored");
    CHECK(canonical_source_enabled("0") == "errored");
    CHECK(canonical_source_enabled(" false ") == "errored");
    CHECK(canonical_source_enabled("yes") == "errored");
    CHECK(canonical_source_enabled("") == "errored");
}

// ── #2361: the retention clock guard ───────────────────────────────────────
//
// Time-based retention deletes rows older than `now - retention_default`, with
// `now` read from the endpoint's own clock - the clock in the fleet most likely
// to be wrong (dead CMOS battery, long suspend, cloned VM, boot before NTP
// converges). The delete used to be unbounded, so one bad reading took the
// whole forensic window with it. These tests drive `run_retention` at explicit
// timestamps, so nothing here depends on the real clock.

namespace {

// Insert `count` process_hourly rows all stamped at exactly `ts`.
void seed_process_hourly_at(TarDatabase& db, int64_t ts, int count) {
    REQUIRE(db.execute_sql("BEGIN TRANSACTION"));
    for (int i = 0; i < count; ++i) {
        REQUIRE(db.execute_sql(std::format("INSERT INTO process_hourly "
                                           "(hour_ts,name,user,start_count,stop_count) "
                                           "VALUES ({}, 'svc.exe', 'SYSTEM', 1, 1)",
                                           ts)));
    }
    REQUIRE(db.execute_sql("COMMIT"));
}

struct TarGuardFixture {
    yuzu::test::TempDbFile tmp{std::string_view{"tar-2361-"}};
    std::optional<TarDatabase> db;
    yuzu::tar::RetentionGuardState guard;

    TarGuardFixture() {
        auto opened = TarDatabase::open(tmp.path);
        REQUIRE(opened.has_value());
        db.emplace(std::move(*opened));
        REQUIRE(db->create_warehouse_tables());
    }
};

// A fixed "now" far from both the epoch and the real clock.
constexpr int64_t kT0 = 1'735'689'600; // 2025-01-01 00:00:00 UTC

} // namespace

TEST_CASE("TAR #2361: a pass that would delete every datable row declines once",
          "[tar][retention][clock-guard]") {
    TarGuardFixture f;
    // Every row well past the 24h hourly cutoff: a forward clock jump looks
    // exactly like this.
    seed_process_hourly_at(*f.db, kT0 - 10 * kHourlyCutoffSec, 20);

    run_retention(*f.db, kT0, f.guard);

    CHECK(row_count(*f.db, "process_hourly") == 20); // nothing deleted
    CHECK(f.guard.declines["process_hourly"] == 1);
}

TEST_CASE("TAR #2361: the decline is latched, so a genuine backlog still drains",
          "[tar][retention][clock-guard]") {
    // Declining every pass would turn the guard into a permanent retention leak
    // on any endpoint whose warehouse is legitimately all-expired.
    TarGuardFixture f;
    seed_process_hourly_at(*f.db, kT0 - 10 * kHourlyCutoffSec, 20);

    run_retention(*f.db, kT0, f.guard);
    REQUIRE(row_count(*f.db, "process_hourly") == 20);

    run_retention(*f.db, kT0 + 1, f.guard); // latched: accepted this time
    CHECK(row_count(*f.db, "process_hourly") == 0);
    CHECK(f.guard.declines["process_hourly"] == 1); // not counted twice
}

TEST_CASE("TAR #2361: the latch clears once the backlog drains, re-arming the guard",
          "[tar][retention][clock-guard]") {
    TarGuardFixture f;
    seed_process_hourly_at(*f.db, kT0 - 10 * kHourlyCutoffSec, 20);

    run_retention(*f.db, kT0, f.guard);     // decline #1
    run_retention(*f.db, kT0 + 1, f.guard); // drain
    run_retention(*f.db, kT0 + 2, f.guard); // nothing expired -> latch clears
    REQUIRE(row_count(*f.db, "process_hourly") == 0);

    seed_process_hourly_at(*f.db, kT0 - 10 * kHourlyCutoffSec, 5); // fresh anomaly
    run_retention(*f.db, kT0 + 3, f.guard);
    CHECK(row_count(*f.db, "process_hourly") == 5);
    CHECK(f.guard.declines["process_hourly"] == 2);
}

TEST_CASE("TAR #2361: one future-dated row cannot disarm the guard",
          "[tar][retention][clock-guard]") {
    // A row stamped implausibly far ahead - written while the clock was skewed
    // forward, or carried in by a VM clone - can never itself be too old. If it
    // counted as an ordinary survivor it would answer "no, this pass would not
    // delete everything" for the life of the endpoint, disarming the guard
    // exactly when it is needed.
    TarGuardFixture f;
    seed_process_hourly_at(*f.db, kT0 - 10 * kHourlyCutoffSec, 20);
    seed_process_hourly_at(*f.db, kT0 + yuzu::tar::kTarRetentionFutureSlackSec + 3600, 1);

    run_retention(*f.db, kT0, f.guard);

    CHECK(row_count(*f.db, "process_hourly") == 21); // still declines
    CHECK(f.guard.declines["process_hourly"] == 1);
}

TEST_CASE("TAR #2361: an in-window survivor means no wipe, so the pass deletes immediately",
          "[tar][retention][clock-guard]") {
    // The healthy steady state. The guard must be invisible here.
    TarGuardFixture f;
    seed_process_hourly_at(*f.db, kT0 - 10 * kHourlyCutoffSec, 20);
    seed_process_hourly_at(*f.db, kT0 - 3600, 1); // inside the 24h window

    run_retention(*f.db, kT0, f.guard);

    CHECK(row_count(*f.db, "process_hourly") == 1);
    CHECK(f.guard.declines["process_hourly"] == 0);
}

TEST_CASE("TAR #2361: a sub-window forward jump is caught by the step check",
          "[tar][retention][clock-guard]") {
    // The outcome test alone only fires when a jump exceeds a table's WHOLE
    // retention window. A jump of just over one window expires a large slice
    // while leaving survivors, which the cap bounds but nothing would report.
    TarGuardFixture f;
    const int64_t later = kT0 + kHourlyCutoffSec + 1;

    seed_process_hourly_at(*f.db, kT0 - 10 * kHourlyCutoffSec, 5); // expired at both readings
    seed_process_hourly_at(*f.db, later - 60, 1); // survivor at BOTH readings
    run_retention(*f.db, kT0, f.guard);
    REQUIRE(row_count(*f.db, "process_hourly") == 1);
    REQUIRE(f.guard.declines["process_hourly"] == 0);

    seed_process_hourly_at(*f.db, kT0 - 9 * kHourlyCutoffSec, 5);
    run_retention(*f.db, later, f.guard);

    CHECK(row_count(*f.db, "process_hourly") == 6); // nothing deleted
    CHECK(f.guard.declines["process_hourly"] == 1);
}

TEST_CASE("TAR #2361: an ordinary over-cap backlog does NOT arm the latch",
          "[tar][retention][clock-guard]") {
    // The latch tracks the WIPE condition, not the backlog. Arming it on any
    // capped pass would leave a busy endpoint permanently latched, and a real
    // clock anomaly arriving next would then delete with no decline and no
    // counter. kSurplus is deliberately independent of the cap.
    constexpr int64_t kSurplus = 7;
    TarGuardFixture f;
    seed_process_hourly_at(*f.db, kT0 - 10 * kHourlyCutoffSec,
                           static_cast<int>(yuzu::tar::kMaxTarDeletesPerTablePerPass + kSurplus));
    seed_process_hourly_at(*f.db, kT0 - 3600, 1); // survivor: a backlog, not an anomaly

    run_retention(*f.db, kT0, f.guard);
    CHECK(row_count(*f.db, "process_hourly") == kSurplus + 1); // one cap's worth deleted
    CHECK(f.guard.declines["process_hourly"] == 0);

    run_retention(*f.db, kT0 + 1, f.guard); // finish the backlog
    CHECK(row_count(*f.db, "process_hourly") == 1);
    CHECK(f.guard.declines["process_hourly"] == 0);

    // Now a real anomaly. An armed latch would let this delete silently.
    REQUIRE(f.db->execute_sql("DELETE FROM process_hourly"));
    seed_process_hourly_at(*f.db, kT0 - 10 * kHourlyCutoffSec, 3);
    run_retention(*f.db, kT0 + 2, f.guard);
    CHECK(row_count(*f.db, "process_hourly") == 3);
    CHECK(f.guard.declines["process_hourly"] == 1);
}

TEST_CASE("TAR #2361: a disabled source with all-expired rows neither declines nor deletes",
          "[tar][retention][clock-guard][issue539]") {
    // The #539/#560 source gate stays strictly ahead of any guard bookkeeping. A
    // paused or errored source is not a candidate for deletion, so it must not
    // burn a decline counter (or an operator-facing warn) either - that would
    // report a clock anomaly on an endpoint whose clock is fine.
    TarGuardFixture f;
    seed_process_hourly_at(*f.db, kT0 - 10 * kHourlyCutoffSec, 20);

    SECTION("paused") { f.db->set_config("process_enabled", "false"); }
    SECTION("errored") { f.db->set_config("process_enabled", "maybe"); }

    run_retention(*f.db, kT0, f.guard);

    CHECK(row_count(*f.db, "process_hourly") == 20);
    CHECK(f.guard.declines["process_hourly"] == 0);
}

TEST_CASE("TAR #2361: row-count retention still trims, unguarded, under a bad clock",
          "[tar][retention][clock-guard]") {
    // Row-count retention trims only the excess over a fixed ceiling and is
    // computed with no clock at all, so no clock reading can make it delete more
    // than it always would. It is therefore deliberately NOT guarded, NOT capped,
    // and NOT declined. `netqual_boot` has a 400-row ceiling, small enough to
    // exercise the trim directly: seeding 410 ancient rows must still leave
    // exactly 400 and must not touch the decline counters.
    constexpr int kBootCeiling = 400;
    constexpr int kOver = 10;
    TarGuardFixture f;
    f.db->set_config("netqual_enabled", "true"); // opt-in source
    REQUIRE(f.db->execute_sql("BEGIN TRANSACTION"));
    for (int i = 0; i < kBootCeiling + kOver; ++i) {
        REQUIRE(f.db->execute_sql(std::format("INSERT INTO netqual_boot (ts,boot_ts,window_s) "
                                              "VALUES ({}, {}, 60)",
                                              kT0 - 10 * kHourlyCutoffSec,
                                              kT0 - 10 * kHourlyCutoffSec - 60)));
    }
    REQUIRE(f.db->execute_sql("COMMIT"));

    // Every row is "ancient" by the clock the pass is handed.
    run_retention(*f.db, kT0, f.guard);

    CHECK(row_count(*f.db, "netqual_boot") == kBootCeiling);
    CHECK(f.guard.declines["netqual_boot"] == 0);
    CHECK(f.guard.latched["netqual_boot"] == false);
}

TEST_CASE("TAR #2361: a table whose count cannot be read is skipped, not declined",
          "[tar][retention][clock-guard]") {
    // Fail closed on an unreadable count: a count we could not read is not
    // evidence that deleting is safe. The table is skipped for the pass, its
    // latch is left alone (an unread count says nothing about the clock), no
    // decline is recorded against it, and the rest of the sweep still runs.
    //
    // Dropping the table is the cheap way to force the count to error. Note this
    // covers the skip, the no-spurious-decline, and the keep-going properties;
    // the "delete anyway" variant is not separable here, because every cheap way
    // to break the count also breaks the delete that would follow it.
    TarGuardFixture f;
    seed_process_hourly_at(*f.db, kT0 - 10 * kHourlyCutoffSec, 20);
    for (int h = 0; h < 20; ++h) {
        REQUIRE(f.db->execute_sql(
            std::format("INSERT INTO tcp_hourly (hour_ts,remote_addr,remote_port,proto,"
                        "process_name,connect_count,disconnect_count) "
                        "VALUES ({}, '10.0.0.1', 5000, 'tcp', 'sshd', 1, 1)",
                        kT0 - 10 * kHourlyCutoffSec)));
    }
    REQUIRE(f.db->execute_sql("DROP TABLE process_hourly"));

    run_retention(*f.db, kT0, f.guard);

    CHECK(f.guard.declines["process_hourly"] == 0); // unreadable, not "anomalous"
    CHECK(f.guard.latched["process_hourly"] == false);
    // The sweep kept going: tcp_hourly is all-expired, so it declines normally.
    CHECK(f.guard.declines["tcp_hourly"] == 1);
    CHECK(row_count(*f.db, "tcp_hourly") == 20);
}

TEST_CASE("TAR #2361: concurrent rollup passes are race-free when the caller serialises",
          "[tar][retention][clock-guard]") {
    // do_rollup is reachable from two places at once: the 900s `tar.rollup`
    // trigger and an operator-issued manual `tar rollup`. RetentionGuardState is
    // plain in-memory maps that run_retention reads and writes WITHOUT holding
    // db_->mu_ (that mutex only serialises individual statements), so two
    // concurrent passes would race the latch and the decline counters.
    //
    // TarPlugin owns `rollup_mu_` for exactly this. TarPlugin itself is not
    // reachable from a unit test (it is a translation-unit-local class), so this
    // exercises the same shape the plugin uses and is the TSan target for the
    // contract: remove the lock_guard below and TSan reports on guard.latched /
    // guard.declines.
    TarGuardFixture f;
    seed_process_hourly_at(*f.db, kT0 - 10 * kHourlyCutoffSec, 200);

    std::mutex rollup_mu;
    std::vector<std::thread> threads;
    for (int t = 0; t < 4; ++t) {
        threads.emplace_back([&, t] {
            for (int i = 0; i < 5; ++i) {
                std::lock_guard lock(rollup_mu);
                run_retention(*f.db, kT0 + t * 10 + i, f.guard);
            }
        });
    }
    for (auto& th : threads)
        th.join();

    // First pass declines, the rest drain it. The exact interleaving is not
    // pinned -- what is pinned is that the state stays coherent: the table ends
    // empty and exactly one decline was recorded.
    CHECK(row_count(*f.db, "process_hourly") == 0);
    CHECK(f.guard.declines["process_hourly"] == 1);
}

TEST_CASE("TAR #2361: retention_sql's SQL text is unchanged (the guard reroutes at the caller)",
          "[tar][retention][clock-guard]") {
    // test_tar_warehouse.cpp and test_tar_perf.cpp pin retention_sql's exact
    // output. The guard therefore lives in run_retention, NOT in retention_sql -
    // this restates that contract locally so a future refactor that "tidies" the
    // guard into retention_sql fails here rather than in an unrelated file.
    const auto time_based = retention_sql("process_hourly", kT0);
    CHECK(time_based == std::format("DELETE FROM process_hourly WHERE hour_ts < {}",
                                    kT0 - kHourlyCutoffSec));
    CHECK(time_based.find("LIMIT") == std::string::npos);
}
