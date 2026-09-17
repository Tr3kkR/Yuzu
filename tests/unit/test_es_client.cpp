// Tests for yuzu/agent/es_client.hpp -- pure Endpoint Security helpers
// relocated from tar_proc_es.cpp (A0, macOS Spark/Reflex/DEX programme).
// Every case is pure integer arithmetic, run on every host.

#include <yuzu/agent/es_client.hpp>

#include <catch2/catch_test_macros.hpp>

TEST_CASE("es_seq_gap counts only forward jumps and never underflows", "[agent][es_client]") {
    using yuzu::agent::es_seq_gap;
    // Consecutive seq → no gap.
    REQUIRE(es_seq_gap(10, 11) == 0);
    // A forward jump means the kernel dropped the messages in between.
    REQUIRE(es_seq_gap(10, 14) == 3); // 11,12,13 lost
    REQUIRE(es_seq_gap(0, 5) == 4);
    // Duplicate (equal) or a backward jump (a client re-create resets the per-type
    // counter) must yield 0 — never an unsigned underflow into a huge bogus count.
    REQUIRE(es_seq_gap(10, 10) == 0);
    REQUIRE(es_seq_gap(10, 2) == 0);
    REQUIRE(es_seq_gap(10, 0) == 0);
}
