// Agent daily-sync tests (ADR-0016): the canonical-hash cross-pin with the
// server, installed_apps output parsing, and the SyncScheduler hash-skip /
// need_full / first-run state machine (gRPC + KV injected — no network).

#include <catch2/catch_test_macros.hpp>

#include "sync_scheduler.hpp"
#include "sync_source_installed_software.hpp"

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

using yuzu::agent::installed_software_canonical_blob;
using yuzu::agent::parse_installed_apps_output;
using yuzu::agent::sha256_hex;
using yuzu::agent::SwEntry;
using yuzu::agent::SyncScheduler;
using yuzu::agent::SyncSource;

namespace {
// THE cross-side pin (ADR-0016 §4): the server computes the SAME hash for the
// SAME input (tests/unit/server/test_software_inventory_store.cpp — identical
// constant). A one-byte drift in either canonicalisation fails one assertion.
constexpr const char* kCrossPinHash =
    "d7a11c1cc4987d05049f7d3226b23b9324f5fa703c8474ba0c36b4807ee5f9b8";
} // namespace

TEST_CASE("installed_software canonical hash matches the cross-pin", "[sync][hash]") {
    // Unsorted + duplicate: canonical_blob must sort + dedup to the exact bytes
    // the constant was computed from.
    std::vector<SwEntry> e = {
        {"Zeta", "9", "", ""},
        {"Acme Reader", "1.2", "Acme", "2026-01-02"},
        {"Acme Reader", "1.2", "Acme", "2026-01-02"},
    };
    CHECK(sha256_hex(installed_software_canonical_blob(e)) == kCrossPinHash);
}

TEST_CASE("parse_installed_apps_output keeps machine-scope app rows only", "[sync][parse]") {
    const std::string out = "app|Chrome|119|Google|2026-01-01\n"
                            "user_app|bob|UserThing|1|Acme|2026-01-01\n" // per-user → dropped
                            "app|No applications found|-|-|-\n"          // sentinel → dropped
                            "error|something failed\n"                   // error → dropped
                            "app|Firefox|120|Mozilla|-\n";
    auto entries = parse_installed_apps_output(out);
    REQUIRE(entries.size() == 2);
    CHECK(entries[0].name == "Chrome");
    CHECK(entries[0].version == "119");
    CHECK(entries[1].name == "Firefox");
    CHECK(entries[1].install_date == "-");
}

TEST_CASE("SyncScheduler: first-run jitter, hash-skip, change, need_full", "[sync][scheduler]") {
    std::map<std::string, std::string> kv;
    auto kv_get = [&](const std::string& k) {
        auto it = kv.find(k);
        return it == kv.end() ? std::string{} : it->second;
    };
    auto kv_set = [&](const std::string& k, const std::string& v) { kv[k] = v; };

    int calls = 0;
    bool last_had_blob = false;
    std::vector<std::string> next_need; // what the server returns as need_full
    auto sender = [&](const std::vector<std::pair<std::string, std::string>>& /*hashes*/,
                      const std::vector<std::pair<std::string, std::string>>& blobs)
        -> std::optional<std::vector<std::string>> {
        ++calls;
        last_had_blob = !blobs.empty();
        return next_need; // non-nullopt = RPC success
    };

    std::string cur_hash = "h1";
    std::string cur_blob = "b1";
    SyncSource src;
    src.name = "installed_software";
    src.interval = std::chrono::seconds{86400};
    src.collect = [&]() -> std::optional<std::pair<std::string, std::string>> {
        return std::make_pair(cur_blob, cur_hash);
    };

    SyncScheduler sched("agent-1", kv_get, kv_set, sender);
    sched.add_source(src);

    // First tick only schedules the startup-jittered first fire — not yet due.
    sched.tick(1000);
    CHECK(calls == 0);

    // Past the max startup-jitter window (10 min) → due; first send is FULL
    // (no last_hash yet).
    sched.tick(1000 + 700);
    REQUIRE(calls == 1);
    CHECK(last_had_blob);

    // Unchanged content one interval later → hash-only (no blob).
    std::int64_t t2 = 1000 + 700 + 86400 + 1;
    sched.tick(t2);
    REQUIRE(calls == 2);
    CHECK_FALSE(last_had_blob);

    // Changed content → FULL.
    cur_hash = "h2";
    cur_blob = "b2";
    std::int64_t t3 = t2 + 86400 + 1;
    sched.tick(t3);
    REQUIRE(calls == 3);
    CHECK(last_had_blob);

    // Server asks for a resend (need_full): this cycle is hash-only (unchanged),
    // but the scheduler then force-fulls on the next pass.
    next_need = {"installed_software"};
    std::int64_t t4 = t3 + 86400 + 1;
    sched.tick(t4);
    REQUIRE(calls == 4);
    CHECK_FALSE(last_had_blob); // hash-only send that the server nacked

    next_need = {}; // server satisfied now
    // Past the jittered need_full reschedule (kMinTickSeconds + up to
    // kNeedFullJitterWindow).
    std::int64_t t5 = t4 + SyncScheduler::kMinTickSeconds.count() +
                      SyncScheduler::kNeedFullJitterWindow.count() + 1;
    sched.tick(t5);
    REQUIRE(calls == 5);
    CHECK(last_had_blob); // forced FULL resend
}

TEST_CASE("SyncScheduler: RPC failure does not advance state (retries)", "[sync][scheduler]") {
    std::map<std::string, std::string> kv;
    auto kv_get = [&](const std::string& k) {
        auto it = kv.find(k);
        return it == kv.end() ? std::string{} : it->second;
    };
    auto kv_set = [&](const std::string& k, const std::string& v) { kv[k] = v; };

    int calls = 0;
    bool fail = true;
    auto sender = [&](const std::vector<std::pair<std::string, std::string>>&,
                      const std::vector<std::pair<std::string, std::string>>&)
        -> std::optional<std::vector<std::string>> {
        ++calls;
        if (fail)
            return std::nullopt; // RPC failure
        return std::vector<std::string>{};
    };

    SyncSource src;
    src.name = "installed_software";
    src.interval = std::chrono::seconds{86400};
    src.collect = [&]() -> std::optional<std::pair<std::string, std::string>> {
        return std::make_pair(std::string{"b"}, std::string{"h"});
    };
    SyncScheduler sched("agent-2", kv_get, kv_set, sender);
    sched.add_source(src);

    sched.tick(1000);          // schedule
    sched.tick(1000 + 700);    // due → send, but RPC fails
    REQUIRE(calls == 1);
    // State not advanced: a soon retry (within the clamped tick window) sends again.
    fail = false;
    sched.tick(1000 + 700 + SyncScheduler::kMinTickSeconds.count());
    CHECK(calls == 2);
}

// --- Parsing edge cases (clamp / separators / empty-name / empty inventory) ---

TEST_CASE("clamp_field strips framing separators and truncates over-long fields",
          "[sync][parse]") {
    // 0x1F (field sep) and 0x1E (record sep) embedded in a field must be stripped
    // so a value can never corrupt the canonical wire structure the server splits
    // on. (octal \037 == 0x1F, \036 == 0x1E.)
    auto e = parse_installed_apps_output(std::string("app|na\037me|1\0362|pub|d\n"));
    REQUIRE(e.size() == 1);
    CHECK(e[0].name == "name");    // 0x1F stripped
    CHECK(e[0].version == "12");   // 0x1E stripped

    std::string longname(2000, 'x');
    auto e2 = parse_installed_apps_output("app|" + longname + "|1|p|d\n");
    REQUIRE(e2.size() == 1);
    CHECK(e2[0].name.size() == 1024); // truncated to kMaxFieldLen
}

TEST_CASE("a name that becomes empty after clamping is dropped (UP-1 hash parity)",
          "[sync][parse]") {
    // A separator-only name clamps to "" — the server's parse_software_blob drops
    // empty-name rows, so the agent must too, or the two canonical hashes diverge
    // and the source is stuck always-full.
    auto e = parse_installed_apps_output(std::string("app|\037|1|p|d\napp|Real|2|q|e\n"));
    REQUIRE(e.size() == 1);
    CHECK(e[0].name == "Real");
}

TEST_CASE("canonical blob is the exact wire format the server parses", "[sync][hash]") {
    // Pins the byte layout (not just the hash): sorted, 0x1F between fields, 0x1E
    // terminating each entry. The server's parse_software_blob reads this same
    // form (tests/unit/server/test_software_inventory_store.cpp blob1()).
    std::vector<SwEntry> e = {{"B", "2", "", ""}, {"A", "1", "P", "D"}}; // unsorted
    // A|1|P|D<rec>  B|2|<empty>|<empty><rec>  (| == 0x1F, <rec> == 0x1E) = 14 bytes.
    CHECK(installed_software_canonical_blob(e) ==
          std::string("A\0371\037P\037D\036B\0372\037\037\036"));
}

TEST_CASE("empty inventory parses to no entries and a stable empty hash",
          "[sync][parse]") {
    // A host with zero machine-scope apps must still hash-skip cleanly, not look
    // broken: empty list → empty canonical blob → the well-known SHA-256 of "".
    auto e = parse_installed_apps_output("user_app|x|y|1|p|d\napp|No applications found|-|-|-\n");
    CHECK(e.empty());
    CHECK(installed_software_canonical_blob({}) == "");
    CHECK(sha256_hex("") ==
          "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

// --- Scheduler edge cases (phase spread, full-floor, collect-nothing) ---

namespace {
// First scheduled fire (epoch s) for a fresh agent at now=1000, read straight
// from the injected KV — exercises the startup-jitter offset path.
std::int64_t first_fire_for(const std::string& agent) {
    std::map<std::string, std::string> kv;
    auto g = [&](const std::string& k) {
        auto it = kv.find(k);
        return it == kv.end() ? std::string{} : it->second;
    };
    auto s = [&](const std::string& k, const std::string& v) { kv[k] = v; };
    SyncScheduler sched(agent, g, s,
                        [](const std::vector<std::pair<std::string, std::string>>&,
                           const std::vector<std::pair<std::string, std::string>>&)
                            -> std::optional<std::vector<std::string>> {
                            return std::vector<std::string>{};
                        });
    SyncSource src;
    src.name = "installed_software";
    src.interval = std::chrono::seconds{86400};
    src.collect = []() -> std::optional<std::pair<std::string, std::string>> {
        return std::make_pair(std::string{"b"}, std::string{"h"});
    };
    sched.add_source(src);
    sched.tick(1000); // schedules the startup-jittered first fire (does not send)
    return std::strtoll(kv["sync.installed_software.next_fire"].c_str(), nullptr, 10);
}
} // namespace

TEST_CASE("SyncScheduler: per-agent phase offset spreads the fleet, stable per agent",
          "[sync][scheduler]") {
    // Reboot stability: the same agent_id always lands on the same offset (a
    // restart must not re-cluster the fleet — ADR-0016 §3).
    CHECK(first_fire_for("agent-stable") == first_fire_for("agent-stable"));

    // Spread: many agents land on many distinct first-fire times, all within the
    // startup-jitter window.
    std::set<std::int64_t> fires;
    for (int i = 0; i < 50; ++i)
        fires.insert(first_fire_for("agent-" + std::to_string(i)));
    CHECK(fires.size() > 20); // negligible collision probability over a 600 s window
    for (auto f : fires) {
        CHECK(f >= 1000);
        CHECK(f < 1000 + SyncScheduler::kStartupJitterWindow.count());
    }
}

TEST_CASE("SyncScheduler: weekly full-floor resends a full payload even when unchanged",
          "[sync][scheduler]") {
    std::map<std::string, std::string> kv;
    auto g = [&](const std::string& k) {
        auto it = kv.find(k);
        return it == kv.end() ? std::string{} : it->second;
    };
    auto s = [&](const std::string& k, const std::string& v) { kv[k] = v; };
    int calls = 0;
    bool last_had_blob = false;
    auto sender = [&](const std::vector<std::pair<std::string, std::string>>&,
                      const std::vector<std::pair<std::string, std::string>>& blobs)
        -> std::optional<std::vector<std::string>> {
        ++calls;
        last_had_blob = !blobs.empty();
        return std::vector<std::string>{};
    };
    SyncSource src;
    src.name = "installed_software";
    src.interval = std::chrono::seconds{86400};
    src.collect = []() -> std::optional<std::pair<std::string, std::string>> {
        return std::make_pair(std::string{"b"}, std::string{"h"}); // never changes
    };
    SyncScheduler sched("agent-floor", g, s, sender);
    sched.add_source(src);

    sched.tick(1000);
    sched.tick(1000 + 700); // first send → FULL (last_full = 1700)
    REQUIRE(calls == 1);
    REQUIRE(last_had_blob);

    sched.tick(1700 + 86400 + 1); // unchanged, within the floor → hash-only
    REQUIRE(calls == 2);
    REQUIRE_FALSE(last_had_blob);

    // Past last_full + kFullFloor, still unchanged → forced FULL.
    sched.tick(1700 + SyncScheduler::kFullFloor.count() + 1);
    REQUIRE(calls == 3);
    CHECK(last_had_blob);
}

TEST_CASE("SyncScheduler: collect returning nothing sends no RPC and retries next interval",
          "[sync][scheduler]") {
    std::map<std::string, std::string> kv;
    auto g = [&](const std::string& k) {
        auto it = kv.find(k);
        return it == kv.end() ? std::string{} : it->second;
    };
    auto s = [&](const std::string& k, const std::string& v) { kv[k] = v; };
    int calls = 0;
    auto sender = [&](const std::vector<std::pair<std::string, std::string>>&,
                      const std::vector<std::pair<std::string, std::string>>&)
        -> std::optional<std::vector<std::string>> {
        ++calls;
        return std::vector<std::string>{};
    };
    SyncSource src;
    src.name = "installed_software";
    src.interval = std::chrono::seconds{86400};
    src.collect = []() -> std::optional<std::pair<std::string, std::string>> {
        return std::nullopt; // source unavailable (e.g. plugin not loaded)
    };
    SyncScheduler sched("agent-nocollect", g, s, sender);
    sched.add_source(src);

    sched.tick(1000);       // schedule
    sched.tick(1000 + 700); // due, but collect yields nothing → no send
    CHECK(calls == 0);
    // Retry is rescheduled one interval out (now + interval), not hammered.
    CHECK(std::strtoll(kv["sync.installed_software.next_fire"].c_str(), nullptr, 10) ==
          1700 + 86400);
}
