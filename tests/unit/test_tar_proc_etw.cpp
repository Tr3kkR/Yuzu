// Tests for tar_proc_etw — the ETW process collector's deterministic parts.
// The live ETW session (start/decode/user-resolution) needs an elevated real
// session and is exercised by the standalone harness + agent UAT, not here; what
// IS unit-testable is the bounded ring buffer (the push→pull bridge) and the
// no-op contract before start / off-Windows.

#include "tar_proc_etw.hpp"

#include <catch2/catch_test_macros.hpp>

using yuzu::tar::ProcEtwCollector;
using yuzu::tar::ProcEvent;
using yuzu::tar::ProcEventRing;

TEST_CASE("ProcEventRing buffers and drains in order", "[tar][procetw]") {
    ProcEventRing ring(4);
    ProcEvent a;
    a.pid = 11;
    a.is_start = true;
    a.image_name = "a.exe";
    ProcEvent b;
    b.pid = 22;
    b.is_start = false;
    b.exit_code = 3;

    REQUIRE(ring.push(a));
    REQUIRE(ring.push(b));

    auto out = ring.drain();
    REQUIRE(out.size() == 2);
    REQUIRE(out[0].pid == 11);
    REQUIRE(out[0].is_start);
    REQUIRE(out[0].image_name == "a.exe");
    REQUIRE(out[1].pid == 22);
    REQUIRE_FALSE(out[1].is_start);
    REQUIRE(out[1].exit_code == 3);
    REQUIRE(ring.dropped() == 0);
}

TEST_CASE("ProcEventRing drain empties the buffer", "[tar][procetw]") {
    ProcEventRing ring(8);
    REQUIRE(ring.push(ProcEvent{}));
    REQUIRE(ring.drain().size() == 1);
    REQUIRE(ring.drain().empty()); // nothing left after the first drain
}

TEST_CASE("ProcEventRing drops on overflow and counts the drops", "[tar][procetw]") {
    ProcEventRing ring(2);
    REQUIRE(ring.push(ProcEvent{}));
    REQUIRE(ring.push(ProcEvent{}));
    REQUIRE_FALSE(ring.push(ProcEvent{})); // full → dropped
    REQUIRE_FALSE(ring.push(ProcEvent{})); // full → dropped
    REQUIRE(ring.dropped() == 2);

    auto out = ring.drain();
    REQUIRE(out.size() == 2); // only the first two were retained

    // Draining frees capacity; the drop counter persists across drains.
    REQUIRE(ring.push(ProcEvent{}));
    REQUIRE(ring.dropped() == 2);
}

TEST_CASE("ProcEtwCollector yields nothing before start", "[tar][procetw]") {
    ProcEtwCollector c(16);
    REQUIRE_FALSE(c.running());
    REQUIRE(c.drain().empty());
    REQUIRE(c.dropped() == 0);
    c.stop(); // safe to call when never started
}

#ifndef _WIN32
TEST_CASE("ProcEtwCollector is a clean no-op off-Windows", "[tar][procetw]") {
    ProcEtwCollector c;
    REQUIRE_FALSE(c.start()); // no ETW outside Windows
    REQUIRE_FALSE(c.running());
    REQUIRE(c.drain().empty());
    c.stop();
}
#endif
