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

TEST_CASE("clamp_field truncates on a UTF-8 codepoint boundary, not mid-sequence (UP-10)",
          "[sync][parse]") {
    // A 2-byte 'é' (0xC3 0xA9) straddling the 1024-byte cut must be dropped WHOLE,
    // not split into a lone lead byte 0xC3 — invalid UTF-8 would make PostgreSQL's
    // TEXT column reject the row → permanent need_full loop (governance UP-10).
    std::string name = std::string(1023, 'a') + "\xc3\xa9"; // 1025 bytes; é at [1023,1024]
    auto e = parse_installed_apps_output("app|" + name + "|1|p|d\n");
    REQUIRE(e.size() == 1);
    CHECK(e[0].name == std::string(1023, 'a')); // é dropped whole; no trailing 0xC3
    CHECK(e[0].name.size() == 1023);
}

TEST_CASE("clamp_field scrubs invalid UTF-8 to U+FFFD before hashing (UP-IN1)",
          "[sync][parse]") {
    // cp1252 "Café" = 43 61 66 E9; the lone 0xE9 is invalid UTF-8 and PostgreSQL's
    // TEXT column rejects it (22021) → the whole full-replace rolls back → kError →
    // the agent resends the identical poison forever. clamp_field must replace any
    // invalid byte with U+FFFD (EF BF BD) so the canonical blob the agent hashes is
    // valid UTF-8 and the server stores it. This scrub MUST run before truncation
    // and match the server's parse_software_blob byte-for-byte.
    auto e = parse_installed_apps_output(std::string("app|Caf\xe9|1|Acme|2020\n"));
    REQUIRE(e.size() == 1);
    CHECK(e[0].name == std::string("Caf\xef\xbf\xbd")); // 0xE9 → U+FFFD
    CHECK(e[0].name.find('\xe9') == std::string::npos); // no raw byte survives
    // The whole canonical blob is valid UTF-8 (no stray invalid byte).
    CHECK(installed_software_canonical_blob(e).find('\xe9') == std::string::npos);
}

// Raw bytes exercising EVERY PG-strict rejection branch (overlong, surrogate,
// > U+10FFFF, stray lead) plus valid 2- and 4-byte passthrough, and the EXACT
// expected scrub output. These two literals are duplicated verbatim in the server
// suite (test_software_inventory_store.cpp) — the whole anti-loop contract rests on
// the agent's clamp_field and the server's parse_software_blob scrubbing IDENTICALLY,
// and this pins both copies to the same spec so editing one without the other fails
// a test (gov Gate-8 cpp-safety/unhappy-path drift guard).
namespace {
const std::string kScrubVectorRaw = std::string("X") + "\xc0\x80" + // overlong NUL → 2× U+FFFD
                                    "\xed\xa0\x80" +                 // lone surrogate U+D800 → 3×
                                    "\xf4\x90\x80\x80" +             // > U+10FFFF → 4×
                                    "\xc3\xa9" +                     // é valid 2-byte (passthrough)
                                    "\xf0\x9f\x98\x80" +             // 😀 valid 4-byte (passthrough)
                                    "\xf5";                          // invalid lead → 1×
const std::string kScrubVectorExpected =
    std::string("X") + "\xef\xbf\xbd\xef\xbf\xbd" +                       // C0 80
    "\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd" +                              // ED A0 80
    "\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd" +                  // F4 90 80 80
    "\xc3\xa9" + "\xf0\x9f\x98\x80" + "\xef\xbf\xbd";                     // é 😀 F5
} // namespace

TEST_CASE("clamp_field scrub: PG-strict edge-branch parity vector (UP-IN1 drift guard)",
          "[sync][parse]") {
    auto e = parse_installed_apps_output("app|" + kScrubVectorRaw + "|1|p|d\n");
    REQUIRE(e.size() == 1);
    CHECK(e[0].name == kScrubVectorExpected);
}

TEST_CASE("collect skips an empty inventory rather than wiping stored rows (UP-IN6)",
          "[sync][parse]") {
    // A transient empty parse (plugin hiccup / "No applications found" sentinel) must
    // NOT be turned into an empty full payload — that would DELETE the agent's stored
    // inventory and the server would record the wipe as a successful store. The
    // collector returns nullopt on an empty parse; here we assert the parse itself is
    // empty for the sentinel so the guard upstream fires.
    auto e = parse_installed_apps_output("app|No applications found|-|-|-\n");
    CHECK(e.empty());
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
    // FNV-1a over the fixed ids "agent-0".."agent-49" is deterministic — this is
    // not a probabilistic check; it yields the same distinct count every run.
    CHECK(fires.size() > 20);
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

TEST_CASE("SyncScheduler: consecutive need_full nacks back off, reset on clean sync",
          "[sync][scheduler]") {
    // UP-5: a sustained server cold-cache / store outage must NOT resend full at a
    // flat 30s cadence forever. Each consecutive need_full doubles the delay; a
    // clean sync resets it. The per-(agent,source) jitter is constant across ticks
    // (same FNV input), so the delay GROWS monotonically across nacks.
    std::map<std::string, std::string> kv;
    auto g = [&](const std::string& k) {
        auto it = kv.find(k);
        return it == kv.end() ? std::string{} : it->second;
    };
    auto s = [&](const std::string& k, const std::string& v) { kv[k] = v; };
    bool nack = true;
    auto sender = [&](const std::vector<std::pair<std::string, std::string>>&,
                      const std::vector<std::pair<std::string, std::string>>&)
        -> std::optional<std::vector<std::string>> {
        return nack ? std::vector<std::string>{"installed_software"} : std::vector<std::string>{};
    };
    SyncSource src;
    src.name = "installed_software";
    src.interval = std::chrono::seconds{86400};
    src.collect = []() -> std::optional<std::pair<std::string, std::string>> {
        return std::make_pair(std::string{"b"}, std::string{"h"});
    };
    SyncScheduler sched("agent-backoff", g, s, sender);
    sched.add_source(src);

    auto next_fire = [&]() {
        return std::strtoll(kv["sync.installed_software.next_fire"].c_str(), nullptr, 10);
    };

    sched.tick(1000); // schedule first-run fire

    // Drive consecutive nacks, each tick exactly at the scheduled fire, recording
    // the rescheduled delay (next_fire - now).
    std::vector<std::int64_t> delays;
    std::int64_t t = next_fire();
    for (int i = 0; i < 4; ++i) {
        sched.tick(t);
        std::int64_t nf = next_fire();
        delays.push_back(nf - t);
        t = nf;
    }
    // Strictly increasing: 30+J, 60+J, 120+J, 240+J (jitter J constant).
    REQUIRE(delays.size() == 4);
    CHECK(delays[0] < delays[1]);
    CHECK(delays[1] < delays[2]);
    CHECK(delays[2] < delays[3]);
    // Bounded: never exceeds kMaxTickSeconds.
    for (auto d : delays)
        CHECK(d <= SyncScheduler::kMaxTickSeconds.count());

    // A clean sync resets the ladder back to zero.
    nack = false;
    sched.tick(t); // clean → streak reset, next_fire jumps ~a day out
    CHECK(std::strtoll(kv["sync.installed_software.nf_streak"].c_str(), nullptr, 10) == 0);
    // The next nack restarts the ladder at the floor (streak 1), not where it left off.
    nack = true;
    std::int64_t after_reset = next_fire();
    sched.tick(after_reset);
    CHECK(std::strtoll(kv["sync.installed_software.nf_streak"].c_str(), nullptr, 10) == 1);
    CHECK((next_fire() - after_reset) == delays[0]); // same delay as the very first nack
}
