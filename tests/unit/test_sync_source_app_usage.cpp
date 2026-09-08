// app_usage daily-sync source tests (wave 7 PR7.2). Covers the `last_used`
// wire parse (field order, malformed-line tolerance, empty-exe_key drop), the
// `constrained|...` skip-cycle guard (never an empty replace), blob framing
// (leading cfg|scope|machine + sorted/deduped lu| records), and the
// plugin-not-loaded idle path. Plugin output is injected through a fake
// descriptor whose `last_used` action writes canned lines (mirrors
// test_licensing_sync.cpp's fixture pattern) — no real plugin, no network.
//
// FIXTURE PROVENANCE: the `last_used|` lines below are hand-built to the exact
// byte shape `agents/plugins/app_usage/src/app_usage_parsers.hpp`'s
// `format_last_used_row` emits (pinned by that file's own
// test_app_usage_parsers.cpp `format_last_used_row shapes` case) — this
// engineer package cannot build/run the app_usage plugin (no builds
// permitted; static verification only), so this is a shape-accurate
// hand-construction, NOT a live LocalDispatcher capture off the real dylib.
// Flagged in the package report for the integrator to swap in (or corroborate
// with) a real capture if higher fidelity is wanted.

#include <catch2/catch_test_macros.hpp>

#include "local_dispatcher.hpp"
#include "sync_canonical.hpp" // sha256_hex
#include "sync_scheduler.hpp" // SyncScheduler composition test
#include "sync_source_app_usage.hpp"

#include <yuzu/plugin.h>

#include <algorithm>
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

using yuzu::agent::AppUsageParse;
using yuzu::agent::AppUsageRow;
using yuzu::agent::make_app_usage_source;
using yuzu::agent::parse_app_usage_last_used_output;
using yuzu::agent::SyncScheduler;
using yuzu::agent::render_app_usage_blob;
using yuzu::agent::sha256_hex;
using yuzu::agent::SyncSource;

namespace {

// ── fake app_usage descriptor: its `last_used` action emits whatever the
//    current test placed in g_output. ────────────────────────────────────────
std::string g_output;
int g_rc = 0;

int fake_execute(YuzuCommandContext* ctx, const char* action, const YuzuParam* /*params*/,
                 std::size_t /*param_count*/) {
    if (std::string_view(action) == "last_used") {
        yuzu_ctx_write_output(ctx, g_output.c_str());
        return g_rc;
    }
    return 1; // unknown action
}

const char* const kFakeActions[] = {"last_used", nullptr};

const YuzuPluginDescriptor kFakeDescriptor = {
    /*abi_version=*/YUZU_PLUGIN_ABI_VERSION,
    /*name=*/"app_usage",
    /*version=*/"1.0.0",
    /*description=*/"test-only app_usage fixture",
    /*actions=*/kFakeActions,
    /*init=*/nullptr,
    /*shutdown=*/nullptr,
    /*execute=*/fake_execute,
    /*sdk_version=*/nullptr,
};

} // namespace

// ── parse: wire shape ────────────────────────────────────────────────────────

TEST_CASE("parse: last_used| rows project exe_key/last_seen/first_seen/run_count/"
          "total_seconds",
          "[app_usage_sync][parse]") {
    // Shape-accurate to format_last_used_row: last_used|<exe_key>|<last_seen>|
    // <first_seen>|<run_count_30d>|<total_seconds_30d>.
    const std::string captured = "last_used|chrome.exe|1700000500|1699000000|12|43200\n";
    AppUsageParse p = parse_app_usage_last_used_output(captured);
    REQUIRE(p.rows.size() == 1);
    CHECK_FALSE(p.constrained);
    CHECK(p.rows[0].exe_key == "chrome.exe");
    CHECK(p.rows[0].last_seen == 1700000500);
    CHECK(p.rows[0].first_seen == 1699000000);
    CHECK(p.rows[0].run_count_30d == 12);
    CHECK(p.rows[0].total_seconds_30d == 43200);
}

TEST_CASE("parse: multiple rows, blank lines and CRLF are tolerated",
          "[app_usage_sync][parse]") {
    const std::string captured = "last_used|chrome.exe|1700000500|1699000000|12|43200\r\n"
                                 "\r\n"
                                 "last_used|word.exe|1700000600|1698000000|3|900\n";
    AppUsageParse p = parse_app_usage_last_used_output(captured);
    REQUIRE(p.rows.size() == 2);
    CHECK(p.rows[0].exe_key == "chrome.exe");
    CHECK(p.rows[1].exe_key == "word.exe");
}

TEST_CASE("parse: a malformed (too-short) last_used line is skipped, not fatal",
          "[app_usage_sync][parse]") {
    const std::string captured = "last_used|chrome.exe|1700000500\n"
                                 "last_used|word.exe|1700000600|1698000000|3|900\n";
    AppUsageParse p = parse_app_usage_last_used_output(captured);
    REQUIRE(p.rows.size() == 1);
    CHECK(p.rows[0].exe_key == "word.exe");
}

TEST_CASE("parse: an empty exe_key row is dropped (no row identity)",
          "[app_usage_sync][parse]") {
    const std::string captured = "last_used||1700000500|1699000000|12|43200\n"
                                 "last_used|word.exe|1700000600|1698000000|3|900\n";
    AppUsageParse p = parse_app_usage_last_used_output(captured);
    REQUIRE(p.rows.size() == 1);
    CHECK(p.rows[0].exe_key == "word.exe");
}

TEST_CASE("parse: negative numeric fields clamp to 0", "[app_usage_sync][parse]") {
    const std::string captured = "last_used|chrome.exe|-5|-9|-1|-100\n";
    AppUsageParse p = parse_app_usage_last_used_output(captured);
    REQUIRE(p.rows.size() == 1);
    CHECK(p.rows[0].last_seen == 0);
    CHECK(p.rows[0].first_seen == 0);
    CHECK(p.rows[0].run_count_30d == 0);
    CHECK(p.rows[0].total_seconds_30d == 0);
}

TEST_CASE("parse: unknown line kinds are skipped without error (forward-compat)",
          "[app_usage_sync][parse]") {
    const std::string captured = "meta|window_days|30|coverage_since|-\n"
                                 "last_used|chrome.exe|1700000500|1699000000|12|43200\n"
                                 "error|bad_param|by\n"
                                 "totally_new_kind|x|y\n";
    AppUsageParse p = parse_app_usage_last_used_output(captured);
    REQUIRE(p.rows.size() == 1);
    CHECK_FALSE(p.constrained);
}

// ── parse: constrained (never an empty blob) ─────────────────────────────────

TEST_CASE("parse: a constrained| line sets constrained and stops collecting rows",
          "[app_usage_sync][parse]") {
    SECTION("usage source disabled") {
        AppUsageParse p = parse_app_usage_last_used_output("constrained|usage_source_disabled\n");
        CHECK(p.constrained);
        CHECK(p.rows.empty());
    }
    SECTION("tar.db unavailable, with prior rows in the buffer") {
        // Even if rows had somehow already been captured, a constrained
        // report must not be treated as a valid detected-empty state.
        AppUsageParse p = parse_app_usage_last_used_output(
            "last_used|chrome.exe|1700000500|1699000000|12|43200\n"
            "constrained|tar_db_unavailable|/var/lib/yuzu/agent/tar.db|no such file\n");
        CHECK(p.constrained);
    }
}

// ── render: blob framing ─────────────────────────────────────────────────────

TEST_CASE("render: leading cfg|scope|machine record, then sorted+deduped lu| records",
          "[app_usage_sync][render]") {
    std::vector<AppUsageRow> rows;
    rows.push_back({"word.exe", 1698000000, 1700000600, 3, 900});
    rows.push_back({"chrome.exe", 1699000000, 1700000500, 12, 43200});
    rows.push_back({"chrome.exe", 1699000000, 1700000500, 12, 43200}); // exact dup
    std::string blob = render_app_usage_blob(rows);
    CHECK(blob.rfind("cfg\x1fscope\x1fmachine\x1e", 0) == 0);
    const std::string chrome_rec =
        "lu\x1f"
        "chrome.exe\x1f"
        "1699000000\x1f"
        "1700000500\x1f"
        "12\x1f"
        "43200\x1e";
    const std::string word_rec =
        "lu\x1f"
        "word.exe\x1f"
        "1698000000\x1f"
        "1700000600\x1f"
        "3\x1f"
        "900\x1e";
    // Deduped: exactly one chrome.exe record, sorted before word.exe.
    CHECK(blob == "cfg\x1fscope\x1fmachine\x1e" + chrome_rec + word_rec);
}

TEST_CASE("render: an empty row set still carries the cfg| record",
          "[app_usage_sync][render]") {
    std::string blob = render_app_usage_blob({});
    CHECK(blob == "cfg\x1fscope\x1fmachine\x1e");
}

TEST_CASE("hash: sha256_hex is deterministic over the rendered blob",
          "[app_usage_sync][hash]") {
    std::vector<AppUsageRow> rows = {{"chrome.exe", 1699000000, 1700000500, 12, 43200}};
    const std::string blob1 = render_app_usage_blob(rows);
    const std::string blob2 = render_app_usage_blob(rows);
    CHECK(blob1 == blob2);
    CHECK(sha256_hex(blob1) == sha256_hex(blob2));
}

// ── make_app_usage_source: collect() end-to-end via the fake descriptor ─────

TEST_CASE("make_app_usage_source: null descriptor idles (plugin not loaded)",
          "[app_usage_sync][source]") {
    SyncSource src = make_app_usage_source(nullptr);
    CHECK(src.name == "app_usage");
    CHECK_FALSE(src.collect().has_value());
}

TEST_CASE("make_app_usage_source: a normal capture yields a blob + hash",
          "[app_usage_sync][source]") {
    g_output = "last_used|chrome.exe|1700000500|1699000000|12|43200\n";
    g_rc = 0;
    SyncSource src = make_app_usage_source(&kFakeDescriptor);
    auto result = src.collect();
    REQUIRE(result.has_value());
    CHECK(result->first.find("chrome.exe") != std::string::npos);
    CHECK(result->second == sha256_hex(result->first));
}

TEST_CASE("make_app_usage_source: a constrained capture skips the cycle — never an "
          "empty blob",
          "[app_usage_sync][source]") {
    g_output = "constrained|usage_source_disabled\n";
    g_rc = 0;
    SyncSource src = make_app_usage_source(&kFakeDescriptor);
    CHECK_FALSE(src.collect().has_value());
}

TEST_CASE("make_app_usage_source: a nonzero plugin rc skips the cycle",
          "[app_usage_sync][source]") {
    g_output = "unavailable|query_failed|disk error\n";
    g_rc = 1;
    SyncSource src = make_app_usage_source(&kFakeDescriptor);
    CHECK_FALSE(src.collect().has_value());
    g_rc = 0; // restore for any later test ordering
}

// ── Composition: make_app_usage_source wired into a REAL SyncScheduler ──────
//
// The four tests above prove make_app_usage_source's own collect() behavior
// in isolation. Nothing previously proved the source actually PARTICIPATES
// in a daily-sync pass once composed into a `SyncScheduler` the way
// `agent.cpp`'s daily-sync thread wires it (`scheduler.add_source(make_app_
// usage_source(app_usage_descriptor))`, alongside installed_software/
// app_perf/device_ci/software_licensing) — i.e. that its name reaches
// `ReportInventory`'s content_hashes on a due tick, not merely that its
// `collect()` function returns something when called directly.
//
// `agent.cpp`'s own composition has no test seam (it is wired inline inside
// the daily-sync thread's lambda body, same as every OTHER ADR-0016 source —
// no source's scheduling is currently unit-tested at that literal call
// site), so this reproduces the identical `SyncScheduler` + `SyncSource`
// composition `agent.cpp` performs, using the REAL `make_app_usage_source`
// production function, rather than driving `agent.cpp`'s private thread
// directly. A future extraction of agent.cpp's source list into a testable
// free function would let this test (and its four ADR-0016 siblings, none of
// which have one today either) drive the literal startup path instead.
TEST_CASE("make_app_usage_source composed into SyncScheduler: a due tick reports "
          "app_usage's hash via the sender callback",
          "[app_usage_sync][source][composition]") {
    g_output = "last_used|chrome.exe|1700000500|1699000000|12|43200\n";
    g_rc = 0;

    std::unordered_map<std::string, std::string> kv;
    auto kv_get = [&](const std::string& key) -> std::string {
        auto it = kv.find(key);
        return it == kv.end() ? std::string{} : it->second;
    };
    auto kv_set = [&](const std::string& key, const std::string& value) { kv[key] = value; };

    std::vector<std::string> sent_hash_keys;
    auto sender = [&](const std::vector<std::pair<std::string, std::string>>& hashes,
                      const std::vector<std::pair<std::string, std::string>>&)
        -> std::optional<std::vector<std::string>> {
        for (const auto& [name, hash] : hashes)
            sent_hash_keys.push_back(name);
        return std::vector<std::string>{}; // need_full: none
    };

    yuzu::agent::SyncScheduler scheduler("test-agent", kv_get, kv_set, sender);
    scheduler.add_source(make_app_usage_source(&kFakeDescriptor));
    // A never-before-seen source schedules its first fire jittered into
    // [now, now + kStartupJitterWindow) (10 minutes, mass-enroll herd
    // avoidance) rather than firing on the very first tick — so this drives
    // two ticks: one to establish the jittered next_fire, a second past the
    // full jitter window to guarantee the source is due.
    constexpr std::int64_t kStartupJitterWindowSecs = 10 * 60;
    scheduler.tick(/*now_secs=*/1700000000);
    scheduler.tick(/*now_secs=*/1700000000 + kStartupJitterWindowSecs + 1);

    CHECK(std::find(sent_hash_keys.begin(), sent_hash_keys.end(), "app_usage") !=
          sent_hash_keys.end());
}
