/**
 * test_dex_blast_radius.cpp — fleet-incident detector (dex_blast_radius, D3).
 *
 * The detector is pure in-memory state over (obs_type, subject, agent_id, t)
 * sightings, so every behaviour is testable without a store or clock: the
 * distinct-device threshold, window expiry, per-pair cooldown + re-arm,
 * pair independence, the new-pair-dropped-at-cap bound, callback re-entrancy,
 * and the subject extraction (uniform key, slice-1 fallback, sec-M1 clamp).
 */

#include "dex_blast_radius.hpp"

#include <catch2/catch_test_macros.hpp>

#include <stdexcept>
#include <string>
#include <vector>

using namespace yuzu::server;

namespace {

// The detector owns a mutex (immovable), so tests construct it in place and
// wire the capture sink with this helper.
struct Capture {
    std::vector<BlastRadiusIncident> incidents;
    void wire(BlastRadiusDetector& d) {
        d.set_on_incident(
            [this](const BlastRadiusIncident& i) { incidents.push_back(i); });
    }
};

} // namespace

TEST_CASE("blast: fires once at the distinct-device threshold", "[dex][blast]") {
    Capture cap;
    BlastRadiusConfig cfg;
    cfg.min_devices = 5;
    BlastRadiusDetector d(cfg);
    cap.wire(d);

    for (int i = 0; i < 4; ++i)
        d.observe("process.crashed", "chrome.exe", "agent-" + std::to_string(i), 1000);
    CHECK(cap.incidents.empty()); // 4 devices — below threshold

    d.observe("process.crashed", "chrome.exe", "agent-4", 1001);
    REQUIRE(cap.incidents.size() == 1);
    CHECK(cap.incidents[0].obs_type == "process.crashed");
    CHECK(cap.incidents[0].subject == "chrome.exe");
    CHECK(cap.incidents[0].device_count == 5);
    CHECK(cap.incidents[0].window_seconds == cfg.window_seconds);
}

TEST_CASE("blast: the same device repeating never counts twice", "[dex][blast]") {
    Capture cap;
    BlastRadiusConfig cfg;
    cfg.min_devices = 3;
    BlastRadiusDetector d(cfg);
    cap.wire(d);

    for (int i = 0; i < 20; ++i)
        d.observe("process.crashed", "chrome.exe", "agent-0", 1000 + i);
    d.observe("process.crashed", "chrome.exe", "agent-1", 1030);
    CHECK(cap.incidents.empty()); // 2 distinct devices, however noisy one is
}

TEST_CASE("blast: sightings age out of the window", "[dex][blast]") {
    Capture cap;
    BlastRadiusConfig cfg;
    cfg.min_devices = 3;
    cfg.window_seconds = 900;
    BlastRadiusDetector d(cfg);
    cap.wire(d);

    d.observe("process.crashed", "chrome.exe", "agent-0", 1000);
    d.observe("process.crashed", "chrome.exe", "agent-1", 1010);
    // agent-0 and agent-1 fall out of the window before the next sightings.
    d.observe("process.crashed", "chrome.exe", "agent-2", 2000);
    d.observe("process.crashed", "chrome.exe", "agent-3", 2010);
    CHECK(cap.incidents.empty()); // never 3 inside one window
}

TEST_CASE("blast: cooldown suppresses then re-arms with a fresh count", "[dex][blast]") {
    Capture cap;
    BlastRadiusConfig cfg;
    cfg.min_devices = 2;
    cfg.window_seconds = 900;
    cfg.cooldown_seconds = 3600;
    BlastRadiusDetector d(cfg);
    cap.wire(d);

    d.observe("service.crashed", "Spooler", "a", 1000);
    d.observe("service.crashed", "Spooler", "b", 1001);
    REQUIRE(cap.incidents.size() == 1);

    // Standing incident: more devices inside the cooldown stay silent.
    d.observe("service.crashed", "Spooler", "c", 1100);
    d.observe("service.crashed", "Spooler", "d", 1200);
    CHECK(cap.incidents.size() == 1);

    // After the cooldown, the (still-active) incident re-alerts with the
    // CURRENT windowed count — only the two fresh sightings are in-window.
    d.observe("service.crashed", "Spooler", "c", 1100 + 3600);
    d.observe("service.crashed", "Spooler", "d", 1101 + 3600);
    REQUIRE(cap.incidents.size() == 2);
    CHECK(cap.incidents[1].device_count == 2);
}

TEST_CASE("blast: pairs are independent (obs_type AND subject)", "[dex][blast]") {
    Capture cap;
    BlastRadiusConfig cfg;
    cfg.min_devices = 2;
    BlastRadiusDetector d(cfg);
    cap.wire(d);

    d.observe("process.crashed", "chrome.exe", "a", 1000);
    d.observe("process.crashed", "excel.exe", "b", 1000);
    d.observe("process.hung", "chrome.exe", "c", 1000);
    CHECK(cap.incidents.empty()); // three different pairs, one device each
}

TEST_CASE("blast: empty subject is a valid pair key", "[dex][blast]") {
    Capture cap;
    BlastRadiusConfig cfg;
    cfg.min_devices = 2;
    BlastRadiusDetector d(cfg);
    cap.wire(d);

    d.observe("os.bugcheck", "", "a", 1000);
    d.observe("os.bugcheck", "", "b", 1001);
    REQUIRE(cap.incidents.size() == 1);
    CHECK(cap.incidents[0].subject.empty());
}

TEST_CASE("blast: at the pair cap the LRU pair is evicted to admit a new one (gov UP-3)",
          "[dex][blast]") {
    // A saturated map must NOT silently suppress a fresh real incident. The
    // victim is the least-recently-touched pair; a live incident (touched on
    // every sighting) is never the victim.
    Capture cap;
    BlastRadiusConfig cfg;
    cfg.min_devices = 2;
    cfg.max_pairs = 2;
    cfg.window_seconds = 900;
    cfg.cooldown_seconds = 3600;
    BlastRadiusDetector d(cfg);
    cap.wire(d);

    // Live incident "real.exe" + a quiet pair fill the cap.
    d.observe("process.crashed", "real.exe", "a", 1000);
    d.observe("process.crashed", "real.exe", "b", 1001); // fires
    REQUIRE(cap.incidents.size() == 1);
    d.observe("process.crashed", "quiet.exe", "q", 1002);

    // Keep the incident hot so "quiet.exe" is the unambiguous LRU victim, then a
    // NEW pair arrives at the cap and is ADMITTED (not dropped — gov UP-3).
    d.observe("process.crashed", "real.exe", "c", 1100);
    d.observe("process.crashed", "fresh.exe", "x", 1101); // evicts quiet.exe
    d.observe("process.crashed", "fresh.exe", "y", 1102); // fresh.exe fires → it was admitted
    REQUIRE(cap.incidents.size() == 2);
    CHECK(cap.incidents[1].subject == "fresh.exe");

    // The live incident survived eviction: after the cooldown it re-fires.
    d.observe("process.crashed", "real.exe", "d", 1000 + 3600 + 10);
    d.observe("process.crashed", "real.exe", "e", 1000 + 3600 + 11);
    REQUIRE(cap.incidents.size() == 3);
    CHECK(cap.incidents[2].subject == "real.exe"); // never evicted
}

TEST_CASE("blast: the global entry budget bounds memory, frees as entries age out",
          "[dex][blast]") {
    Capture cap;
    BlastRadiusConfig cfg;
    cfg.min_devices = 2;
    cfg.window_seconds = 900;
    cfg.cooldown_seconds = 3600;
    cfg.max_total_entries = 4;
    BlastRadiusDetector d(cfg);
    cap.wire(d);

    // Budget fills: pair X takes 2 entries (fires), pair Y takes 2 (fires).
    d.observe("process.crashed", "x.exe", "a", 1000);
    d.observe("process.crashed", "x.exe", "b", 1001);
    d.observe("process.crashed", "y.exe", "c", 1002);
    d.observe("process.crashed", "y.exe", "d", 1003);
    REQUIRE(cap.incidents.size() == 2);

    // Budget exhausted: a NEW pair's sightings go untracked — no false fire,
    // no allocation growth.
    d.observe("process.crashed", "z.exe", "e", 1004);
    d.observe("process.crashed", "z.exe", "f", 1005);
    CHECK(cap.incidents.size() == 2);

    // Refreshing an EXISTING entry is never blocked by the budget.
    d.observe("process.crashed", "x.exe", "a", 1006);
    CHECK(cap.incidents.size() == 2); // still in cooldown, but tracked fine

    // Once stale entries prune (budget frees when a pair is TOUCHED past the
    // window — untouched stale pairs keep their slots until touched or
    // cap-swept), the budget recovers and new pairs track again.
    const std::int64_t later = 1000 + 3600 + 1000;
    d.observe("process.crashed", "x.exe", "a", later); // prunes X's 2 stale entries
    d.observe("process.crashed", "y.exe", "c", later); // prunes Y's 2 stale entries
    d.observe("process.crashed", "z.exe", "e", later + 1);
    d.observe("process.crashed", "z.exe", "f", later + 2);
    REQUIRE(cap.incidents.size() == 3);
    CHECK(cap.incidents[2].subject == "z.exe");
}

TEST_CASE("blast: a re-entrant observe from the callback does not deadlock", "[dex][blast]") {
    BlastRadiusConfig cfg;
    cfg.min_devices = 2;
    BlastRadiusDetector d(cfg);
    int fired = 0;
    d.set_on_incident([&](const BlastRadiusIncident&) {
        ++fired;
        // The callback runs OUTSIDE the detector lock by contract.
        d.observe("process.crashed", "other.exe", "z", 5000);
    });
    d.observe("process.crashed", "chrome.exe", "a", 1000);
    d.observe("process.crashed", "chrome.exe", "b", 1001);
    CHECK(fired == 1);
}

TEST_CASE("blast: a throwing sink never escapes observe", "[dex][blast]") {
    BlastRadiusConfig cfg;
    cfg.min_devices = 1;
    BlastRadiusDetector d(cfg);
    d.set_on_incident([](const BlastRadiusIncident&) { throw std::runtime_error("sink down"); });
    CHECK_NOTHROW(d.observe("process.crashed", "chrome.exe", "a", 1000));
}

// ── subject extraction (mirrors the projection's parse discipline) ───────────

TEST_CASE("blast subject: uniform key, slice-1 fallback, malformed JSON", "[dex][blast]") {
    CHECK(blast_subject_from_detail(R"({"subject":"chrome.exe"})") == "chrome.exe");
    // Slice-1 crash key fallback (PR #1311 transition).
    CHECK(blast_subject_from_detail(R"({"process":"old-agent.exe"})") == "old-agent.exe");
    CHECK(blast_subject_from_detail(R"({"subject":"s","process":"p"})") == "s");
    CHECK(blast_subject_from_detail("").empty());
    CHECK(blast_subject_from_detail("not json").empty());
    CHECK(blast_subject_from_detail(R"({"subject":42})").empty()); // wrong type
}

TEST_CASE("blast subject: sec-M1 clamp is UTF-8 safe", "[dex][blast]") {
    // 300 bytes of 'a' → clamped to 256.
    const std::string long_subject(300, 'a');
    const std::string json = R"({"subject":")" + long_subject + R"("})";
    CHECK(blast_subject_from_detail(json).size() == 256);

    // A 2-byte UTF-8 char straddling the cut is dropped whole, never torn:
    // 255 ASCII bytes + "é" (2 bytes) puts the cut mid-sequence.
    const std::string multi = std::string(255, 'a') + "\xC3\xA9";
    const std::string json2 = R"({"subject":")" + multi + R"(xyz"})";
    const std::string out = blast_subject_from_detail(json2);
    CHECK(out.size() == 255); // the é was dropped whole at the boundary
    CHECK(out == std::string(255, 'a'));
}

// ── Hardening-round additions (gov UP-1/UP-2) ───────────────────────────────

TEST_CASE("blast: global per-minute fan-out cap clips a correlated burst", "[dex][blast]") {
    Capture cap;
    BlastRadiusConfig cfg;
    cfg.min_devices = 2;
    cfg.max_fires_per_minute = 3;
    cfg.window_seconds = 900;
    BlastRadiusDetector d(cfg);
    cap.wire(d);

    // 5 distinct subjects each cross the threshold within the same minute (a bad
    // patch crashing many apps). Only 3 incidents fire; the rest are clipped.
    for (int s = 0; s < 5; ++s) {
        const std::string subj = "app" + std::to_string(s) + ".exe";
        d.observe("process.crashed", subj, "a", 2000);
        d.observe("process.crashed", subj, "b", 2001);
    }
    CHECK(cap.incidents.size() == 3);

    // Next minute, the budget resets — a fresh subject fires again.
    d.observe("process.crashed", "later.exe", "a", 2000 + 60);
    d.observe("process.crashed", "later.exe", "b", 2000 + 61);
    CHECK(cap.incidents.size() == 4);
}

TEST_CASE("blast: a budget-CLIPPED incident fires when the bucket frees, not after a cooldown",
          "[dex][blast]") {
    // gov Gate-8 sec MEDIUM: a pair clipped by the per-minute cap must NOT arm
    // the per-pair cooldown — it re-attempts and fires the moment the budget
    // frees, rather than going silent for a full cooldown on an unsent alert.
    Capture cap;
    BlastRadiusConfig cfg;
    cfg.min_devices = 2;
    cfg.max_fires_per_minute = 1;
    cfg.cooldown_seconds = 3600;
    cfg.window_seconds = 900;
    BlastRadiusDetector d(cfg);
    cap.wire(d);

    // Two subjects cross threshold in the same minute; only the first fires.
    d.observe("process.crashed", "first.exe", "a", 3000);
    d.observe("process.crashed", "first.exe", "b", 3001); // fires (budget 1/1)
    d.observe("process.crashed", "clipped.exe", "a", 3002);
    d.observe("process.crashed", "clipped.exe", "b", 3003); // clipped
    REQUIRE(cap.incidents.size() == 1);

    // Next minute, a fresh sighting of the clipped pair fires — proving its
    // cooldown was NOT armed by the clip (else it would stay silent ~1h).
    d.observe("process.crashed", "clipped.exe", "a", 3000 + 60);
    REQUIRE(cap.incidents.size() == 2);
    CHECK(cap.incidents[1].subject == "clipped.exe");
}

TEST_CASE("blast: prune throttle keeps a hot pair countable without per-call pruning",
          "[dex][blast]") {
    // The throttle (gov UP-1) must not change observable detection: a pair that
    // crosses the threshold still fires regardless of prune cadence.
    Capture cap;
    BlastRadiusConfig cfg;
    cfg.min_devices = 3;
    cfg.window_seconds = 900;
    cfg.prune_interval_seconds = 30;
    BlastRadiusDetector d(cfg);
    cap.wire(d);

    // Three distinct devices within a few seconds — inside the window, inside
    // one prune interval. Must fire on the 3rd.
    d.observe("process.crashed", "chrome.exe", "a", 5000);
    d.observe("process.crashed", "chrome.exe", "b", 5001);
    CHECK(cap.incidents.empty());
    d.observe("process.crashed", "chrome.exe", "c", 5002);
    REQUIRE(cap.incidents.size() == 1);
    CHECK(cap.incidents[0].device_count == 3);
}

TEST_CASE("blast: works with no metrics wired (metrics optional)", "[dex][blast]") {
    // set_metrics is never called — every inc_metric path must be a safe no-op.
    BlastRadiusConfig cfg;
    cfg.min_devices = 2;
    cfg.max_total_entries = 1; // force the entries_dropped metric path
    BlastRadiusDetector d(cfg);
    int fired = 0;
    d.set_on_incident([&](const BlastRadiusIncident&) { ++fired; });
    CHECK_NOTHROW(d.observe("process.crashed", "x.exe", "a", 1000));
    CHECK_NOTHROW(d.observe("process.crashed", "x.exe", "b", 1001)); // budget-dropped sighting
}
