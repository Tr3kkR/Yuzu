/**
 * test_guardian_journal_heartbeat.cpp -- the writer side of the durable lifecycle-journal
 * fleet telemetry (item 7 PR-Ag C7): the sparse-emit rule + the exact key names.
 */

#include "guardian_journal_heartbeat.hpp"

#include <catch2/catch_test_macros.hpp>

#include <map>
#include <string>

using namespace yuzu::agent;

TEST_CASE("journal heartbeat: a quiescent journal emits NO tags (sparse)",
          "[guardian][journal][heartbeat]") {
    std::map<std::string, std::string> tags;
    emit_guardian_journal_heartbeat_tags(tags, GuardianJournalStats{});
    CHECK(tags.empty()); // every field 0 → nothing to report
}

TEST_CASE("journal heartbeat: only non-zero counters are emitted, with the pinned keys",
          "[guardian][journal][heartbeat]") {
    std::map<std::string, std::string> tags;
    GuardianJournalStats s;
    s.stage_dropped = 3;
    s.clock_rejected = 1;
    s.pending_depth = 2;
    s.evicted_without_send_evidence = 7;
    emit_guardian_journal_heartbeat_tags(tags, s);

    CHECK(tags.size() == 4);
    CHECK(tags.at("yuzu.guardian_journal_stage_dropped") == "3");
    CHECK(tags.at("yuzu.guardian_journal_clock_rejected") == "1");
    CHECK(tags.at("yuzu.guardian_journal_pending") == "2");
    CHECK(tags.at("yuzu.guardian_journal_evicted_no_send_evidence") == "7");
    // A zero field is absent, not "0".
    CHECK(tags.find("yuzu.guardian_journal_batches_written") == tags.end());
    CHECK(tags.find("yuzu.guardian_journal_write_failures") == tags.end());
}

TEST_CASE("journal heartbeat: every field has a distinct key", "[guardian][journal][heartbeat]") {
    // Set all 18 fields to distinct non-zero values -> 18 distinct tags (no key collision).
    std::map<std::string, std::string> tags;
    GuardianJournalStats s{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18};
    emit_guardian_journal_heartbeat_tags(tags, s);
    CHECK(tags.size() == 18);
}
