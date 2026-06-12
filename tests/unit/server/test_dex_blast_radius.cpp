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

TEST_CASE("blast: at the pair cap a NEW pair is dropped, established pairs keep working",
          "[dex][blast]") {
    Capture cap;
    BlastRadiusConfig cfg;
    cfg.min_devices = 2;
    cfg.max_pairs = 2;
    BlastRadiusDetector d(cfg);
    cap.wire(d);

    d.observe("process.crashed", "real-incident.exe", "a", 1000);
    d.observe("process.crashed", "other.exe", "b", 1000);
    // Cap reached; a sprayed synthetic subject must not evict the live pairs.
    d.observe("process.crashed", "sprayed-1.exe", "x", 1001);
    d.observe("process.crashed", "sprayed-1.exe", "y", 1002);
    CHECK(cap.incidents.empty()); // the sprayed pair was never tracked

    d.observe("process.crashed", "real-incident.exe", "c", 1010);
    REQUIRE(cap.incidents.size() == 1); // the established pair still fires
    CHECK(cap.incidents[0].subject == "real-incident.exe");

    // Once the old pairs go stale (past window AND cooldown), the sweep frees
    // room and new pairs are tracked again.
    const std::int64_t later = 1000 + 3600 + 1000;
    d.observe("process.crashed", "fresh.exe", "x", later);
    d.observe("process.crashed", "fresh.exe", "y", later + 1);
    REQUIRE(cap.incidents.size() == 2);
    CHECK(cap.incidents[1].subject == "fresh.exe");
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
