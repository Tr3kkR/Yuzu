/**
 * test_tar_proc_perf.cpp — per-app top-N sampling for the TAR edge warehouse
 * (BRD A2).
 *
 * Two halves:
 *  1. derive_proc_samples (pure): the per-process cumulative-CPU → per-app
 *     share-of-capacity math — name aggregation, PID-reuse identity, new-
 *     process baselining, regression saturation, redaction, and the
 *     top-N-by-CPU ∪ top-N-by-working-set selection.
 *  2. Schema-registry pins: the procperf source's tables exist, translate,
 *     are operator-queryable, and roll up hourly per (hour, name).
 *
 * The NtQuerySystemInformation read is the impure shell, exercised on a live
 * box; the rest runs on every host.
 */

#include "tar_proc_perf.hpp"
#include "tar_schema_registry.hpp"

#include <catch2/catch_approx.hpp>
#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

using namespace yuzu::tar;
using Catch::Approx;

namespace {

constexpr std::uint64_t kSec100ns = 10'000'000ULL; // 100 ns units per second

ProcCounter proc(std::uint32_t pid, std::int64_t created, std::uint64_t cpu,
                 std::uint64_t ws, std::string name) {
    ProcCounter p;
    p.pid = pid;
    p.create_time_100ns = created;
    p.cpu_100ns = cpu;
    p.ws_bytes = ws;
    p.name = std::move(name);
    return p;
}

// A 4-core snapshot pair 30 s apart; tests add processes to both.
ProcSnapshot snap(std::int64_t ts) {
    ProcSnapshot s;
    s.valid = true;
    s.ts_epoch = ts;
    s.ncores = 4;
    return s;
}

const std::vector<std::string> kNoRedaction{};

} // namespace

// ── derive_proc_samples ──────────────────────────────────────────────────────

TEST_CASE("procperf derive: invalid snapshots / zero elapsed / zero cores never derive",
          "[tar][procperf]") {
    auto prev = snap(1000), cur = snap(1030);
    prev.procs.push_back(proc(10, 1, 0, 100, "a.exe"));
    cur.procs.push_back(proc(10, 1, kSec100ns, 100, "a.exe"));

    ProcSnapshot invalid;
    CHECK(derive_proc_samples(invalid, cur, kNoRedaction).empty());
    CHECK(derive_proc_samples(prev, invalid, kNoRedaction).empty());
    CHECK(derive_proc_samples(cur, prev, kNoRedaction).empty()); // elapsed < 0
    auto nocores = cur;
    nocores.ncores = 0;
    CHECK(derive_proc_samples(prev, nocores, kNoRedaction).empty());
}

TEST_CASE("procperf derive: CPU is the app's share of TOTAL capacity", "[tar][procperf]") {
    // One process burns exactly one full core for 30 s on a 4-core box → 25%.
    auto prev = snap(1000), cur = snap(1030);
    prev.procs.push_back(proc(10, 1, 0, 50 << 20, "burner.exe"));
    cur.procs.push_back(proc(10, 1, 30 * kSec100ns, 50 << 20, "burner.exe"));
    const auto out = derive_proc_samples(prev, cur, kNoRedaction);
    REQUIRE(out.size() == 1);
    CHECK(out[0].name == "burner.exe");
    CHECK(out[0].cpu_pct == Approx(25.0));
    CHECK(out[0].ws_bytes == (50 << 20));
    CHECK(out[0].instances == 1);
}

TEST_CASE("procperf derive: same-name processes aggregate into one app row",
          "[tar][procperf]") {
    auto prev = snap(1000), cur = snap(1030);
    for (std::uint32_t pid : {11u, 12u, 13u}) {
        prev.procs.push_back(proc(pid, 1, 0, 100 << 20, "chrome.exe"));
        cur.procs.push_back(proc(pid, 1, 10 * kSec100ns, 100 << 20, "chrome.exe"));
    }
    const auto out = derive_proc_samples(prev, cur, kNoRedaction);
    REQUIRE(out.size() == 1);
    CHECK(out[0].instances == 3);
    CHECK(out[0].cpu_pct == Approx(25.0)); // 3 × 10 s of CPU over 120 core-seconds
    CHECK(out[0].ws_bytes == 3LL * (100 << 20));
}

TEST_CASE("procperf derive: PID reuse (different create_time) finds no baseline",
          "[tar][procperf]") {
    // Same PID, different create_time = a DIFFERENT process. Its inherited
    // cumulative CPU must not read as this interval's burn.
    auto prev = snap(1000), cur = snap(1030);
    prev.procs.push_back(proc(10, /*created=*/111, 5 * kSec100ns, 10 << 20, "old.exe"));
    cur.procs.push_back(proc(10, /*created=*/999, 20 * kSec100ns, 10 << 20, "new.exe"));
    const auto out = derive_proc_samples(prev, cur, kNoRedaction);
    REQUIRE(out.size() == 1);
    CHECK(out[0].name == "new.exe");
    CHECK(out[0].cpu_pct == 0.0);          // baselines this interval
    CHECK(out[0].ws_bytes == (10 << 20)); // working set still real
}

TEST_CASE("procperf derive: CPU counter regression saturates to zero", "[tar][procperf]") {
    auto prev = snap(1000), cur = snap(1030);
    prev.procs.push_back(proc(10, 1, 50 * kSec100ns, 1 << 20, "a.exe"));
    cur.procs.push_back(proc(10, 1, 40 * kSec100ns, 1 << 20, "a.exe")); // impossible: went down
    const auto out = derive_proc_samples(prev, cur, kNoRedaction);
    REQUIRE(out.size() == 1);
    CHECK(out[0].cpu_pct == 0.0);
}

TEST_CASE("procperf derive: redacted and empty names never appear", "[tar][procperf]") {
    auto prev = snap(1000), cur = snap(1030);
    prev.procs.push_back(proc(10, 1, 0, 1 << 20, "secret-tool.exe"));
    cur.procs.push_back(proc(10, 1, kSec100ns, 1 << 20, "secret-tool.exe"));
    prev.procs.push_back(proc(11, 1, 0, 1 << 20, "normal.exe"));
    cur.procs.push_back(proc(11, 1, kSec100ns, 1 << 20, "normal.exe"));
    cur.procs.push_back(proc(12, 1, 0, 1 << 20, "")); // unnameable kernel entry

    const std::vector<std::string> redaction{"secret*"};
    const auto out = derive_proc_samples(prev, cur, redaction);
    REQUIRE(out.size() == 1);
    CHECK(out[0].name == "normal.exe");
}

TEST_CASE("procperf derive: top-N union keeps the CPU-idle memory hog visible",
          "[tar][procperf]") {
    auto prev = snap(1000), cur = snap(1030);
    // 12 CPU-busy small apps (descending burn so the top-10 cut is decided)…
    for (std::uint32_t i = 0; i < 12; ++i) {
        const auto cpu = static_cast<std::uint64_t>(12 - i) * kSec100ns;
        prev.procs.push_back(proc(100 + i, 1, 0, 1 << 20, "busy" + std::to_string(i) + ".exe"));
        cur.procs.push_back(
            proc(100 + i, 1, cpu, 1 << 20, "busy" + std::to_string(i) + ".exe"));
    }
    // …and one CPU-idle app holding 8 GiB.
    prev.procs.push_back(proc(200, 1, 0, 8ULL << 30, "hog.exe"));
    cur.procs.push_back(proc(200, 1, 0, 8ULL << 30, "hog.exe"));

    const auto out = derive_proc_samples(prev, cur, kNoRedaction);
    // 13 apps: top-10 by CPU (busy0..busy9) ∪ top-10 by WS (hog + 9 others).
    CHECK(out.size() <= 2 * static_cast<std::size_t>(kProcTopN));
    const bool hog_present = std::any_of(out.begin(), out.end(), [](const ProcPerfSample& s) {
        return s.name == "hog.exe";
    });
    CHECK(hog_present);
    // Presentation order: CPU-heaviest first.
    REQUIRE(out.size() >= 2);
    CHECK(out[0].cpu_pct >= out[1].cpu_pct);
    // The least CPU-busy app (busy11) made neither top list… unless the WS
    // tie pulled it in — assert only the structural bound + hog presence.
}

TEST_CASE("procperf derive: an absurd delta clamps at 100%", "[tar][procperf]") {
    auto prev = snap(1000), cur = snap(1030);
    // 10x more CPU time than the interval has capacity (forged/garbage).
    prev.procs.push_back(proc(10, 1, 0, 1 << 20, "liar.exe"));
    cur.procs.push_back(proc(10, 1, 30 * 4 * 10 * kSec100ns, 1 << 20, "liar.exe"));
    const auto out = derive_proc_samples(prev, cur, kNoRedaction);
    REQUIRE(out.size() == 1);
    CHECK(out[0].cpu_pct == 100.0);
}

TEST_CASE("procperf derive: the representative is the largest-working-set instance",
          "[tar][procperf]") {
    // version resolution (off-lock, Windows) targets ONE instance per app — the
    // biggest-WS one. derive must surface that pid + its create_time as rep_*,
    // and leave version "" (the resolver fills it later).
    auto prev = snap(1000), cur = snap(1030);
    struct Inst { std::uint32_t pid; std::int64_t ct; std::uint64_t ws; };
    const Inst insts[] = {{11, 4001, 100u << 20}, {12, 4002, 300u << 20}, {13, 4003, 200u << 20}};
    for (const auto& i : insts) {
        prev.procs.push_back(proc(i.pid, i.ct, 0, i.ws, "chrome.exe"));
        cur.procs.push_back(proc(i.pid, i.ct, kSec100ns, i.ws, "chrome.exe"));
    }
    const auto out = derive_proc_samples(prev, cur, kNoRedaction);
    REQUIRE(out.size() == 1);
    CHECK(out[0].instances == 3);
    CHECK(out[0].rep_pid == 12);                 // the 300 MiB instance
    CHECK(out[0].rep_create_time_100ns == 4002); // its identity, for the PID-reuse guard
    CHECK(out[0].version.empty());               // unresolved until resolve_proc_versions
}

// ── format_file_version (pure) ───────────────────────────────────────────────

TEST_CASE("procperf version: VS_FIXEDFILEINFO words format as a.b.c.d", "[tar][procperf]") {
    // ms = HIWORD.LOWORD, ls = HIWORD.LOWORD — e.g. Chrome 124.0.6367.91.
    CHECK(format_file_version(0x007C0000u, 0x18DF005Bu) == "124.0.6367.91");
    CHECK(format_file_version(0u, 0u) == "0.0.0.0");
    CHECK(format_file_version(0xFFFFFFFFu, 0xFFFFFFFFu) == "65535.65535.65535.65535");
    CHECK(format_file_version(0x000A0001u, 0x00000000u) == "10.1.0.0");
}

TEST_CASE("procperf version: resolve_proc_versions is a no-op when there is no representative",
          "[tar][procperf]") {
    // A sample with rep_pid==0 (no instance recorded) is left version="" and the
    // cache untouched — and off Windows the whole call is a no-op, so this holds
    // on every host.
    std::vector<ProcPerfSample> samples(1);
    samples[0].name = "ghost.exe";
    std::unordered_map<std::uint64_t, std::string> cache;
    resolve_proc_versions(samples, cache);
    CHECK(samples[0].version.empty());
}

// ── Schema-registry pins ─────────────────────────────────────────────────────

TEST_CASE("procperf: registry declares both tiers, dollar names translate",
          "[tar][procperf][schema]") {
    auto live = translate_dollar_name("$ProcPerf_Live");
    REQUIRE(live.has_value());
    CHECK(*live == "procperf_live");
    auto hourly = translate_dollar_name("$ProcPerf_Hourly");
    REQUIRE(hourly.has_value());
    CHECK(*hourly == "procperf_hourly");
    CHECK(is_queryable_table("procperf_live"));
    CHECK(is_queryable_table("procperf_hourly"));
}

TEST_CASE("procperf: hourly rollup SQL exists and groups per (hour, name, version)",
          "[tar][procperf][schema]") {
    const auto sql = rollup_sql("procperf", "hourly");
    REQUIRE(!sql.empty());
    CHECK(sql.find("procperf_hourly") != std::string::npos);
    // version is part of the app identity — it must appear in BOTH the column
    // list and the GROUP BY, or the hourly tier would collapse distinct
    // versions of one app into a single (mislabelled) row.
    CHECK(sql.find("GROUP BY (ts / 3600) * 3600, name, version") != std::string::npos);
    CHECK(sql.find("(hour_ts, name, version,") != std::string::npos);
    CHECK(sql.find("MAX(instances)") != std::string::npos);
}

TEST_CASE("procperf: live columns carry name but never a cmdline", "[tar][procperf][schema]") {
    // Privacy pin: the A2 tier records image NAMES only. A cmdline column
    // appearing here is a design regression, not an addition.
    const auto ddl = generate_warehouse_ddl();
    const auto pos = ddl.find("CREATE TABLE IF NOT EXISTS procperf_live");
    REQUIRE(pos != std::string::npos);
    const auto end = ddl.find(");", pos);
    const auto table_ddl = ddl.substr(pos, end - pos);
    CHECK(table_ddl.find("name TEXT") != std::string::npos);
    CHECK(table_ddl.find("version TEXT") != std::string::npos); // the app-identity dimension
    CHECK(table_ddl.find("cmdline") == std::string::npos);
    CHECK(table_ddl.find("user") == std::string::npos);
    CHECK(table_ddl.find("path") == std::string::npos); // never the image PATH (privacy)
}

TEST_CASE("procperf #538: a reset baseline (post-disable) emits no off-period-spanning row",
          "[tar][procperf][source-lifecycle]") {
    // do_collect_perf's procperf disable branch installs a default-constructed
    // ProcSnapshot as prev_proc_ (valid=false). On the first tick after a
    // re-enable, deriving against that reset baseline must yield NO samples (it
    // re-baselines) even though the app accrued CPU during the paused window — so
    // the first post-re-enable row never covers the opt-out window. Without the
    // reset, prev_proc_ would still hold the pre-disable snapshot and this call
    // would emit a per-app row spanning the gap (the privacy leak on the opt-in
    // source procperf, off by default for exactly this reason).
    auto after_gap = snap(100'000);                                 // long pause elapsed
    after_gap.procs.push_back(proc(10, 1, 900 * kSec100ns, 100, "a.exe")); // lots of CPU

    // The disable branch's reset == a default-constructed prev → no rows.
    CHECK(derive_proc_samples(ProcSnapshot{}, after_gap, kNoRedaction).empty());
    // Sanity: against a real pre-gap baseline it WOULD emit a row — the
    // off-period leak the reset prevents.
    auto prev = snap(1000);
    prev.procs.push_back(proc(10, 1, 0, 100, "a.exe"));
    CHECK_FALSE(derive_proc_samples(prev, after_gap, kNoRedaction).empty());
}

#if defined(_WIN32)
// HIDDEN ([.]) — a manual, live-box smoke for the impure version-capture path
// (OpenProcess → GetProcessTimes guard → QueryFullProcessImageNameW →
// GetFileVersionInfo). It depends on the host's live process set and so is NOT
// in the default suite; run explicitly with the [live] tag. Builds samples
// straight off one snapshot (the rep is each process itself) to exercise
// resolve_proc_versions without the two-snapshot CPU timing.
TEST_CASE("procperf version: LIVE capture resolves real versions", "[.][procperf][live]") {
    const auto snapshot = read_proc_counters();
    REQUIRE(snapshot.valid);
    REQUIRE(!snapshot.procs.empty());

    std::vector<ProcPerfSample> samples;
    for (const auto& p : snapshot.procs) {
        if (p.name.empty())
            continue;
        ProcPerfSample s;
        s.name = p.name;
        s.rep_pid = p.pid;
        s.rep_create_time_100ns = p.create_time_100ns;
        samples.push_back(std::move(s));
        if (samples.size() >= 80)
            break;
    }
    std::unordered_map<std::uint64_t, std::string> cache;
    resolve_proc_versions(samples, cache);

    int resolved = 0;
    for (const auto& s : samples) {
        if (!s.version.empty()) {
            ++resolved;
            WARN(s.name << " -> " << s.version); // visible run output: the data point
        }
    }
    // Any real Windows host runs versioned system/vendor images (explorer.exe,
    // svchost.exe, the test exe). At least one must resolve to a.b.c.d — proof
    // the OpenProcess + file-version path works end-to-end, not just in theory.
    CHECK(resolved > 0);
}
#endif
