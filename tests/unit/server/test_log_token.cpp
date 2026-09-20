/**
 * test_log_token.cpp -- the shared log-token neutraliser (common/include/yuzu/log_token.hpp).
 *
 * One mapping, used on BOTH sides of the Guardian T_wire/T_server id join and by the server's
 * audit-detail neutraliser (audit_token). The tests pin the mapping byte-for-byte because a
 * per-side difference would silently break the join for exactly the ids that need it.
 */

#include <yuzu/log_token.hpp>

#include "web_utils.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

using yuzu::kGuardianLogIdMaxBytes;
using yuzu::kLogTokenNoCap;
using yuzu::log_token;

TEST_CASE("log_token: ordinary identifiers pass through unchanged", "[log_token]") {
    CHECK(log_token("") == "");
    CHECK(log_token("rule-1") == "rule-1");
    CHECK(log_token("agent-2c82.evt_9:x/y") == "agent-2c82.evt_9:x/y");
    // Bytes >= 0x80 (UTF-8) are not structural and pass through untouched.
    CHECK(log_token("caf\xC3\xA9") == "caf\xC3\xA9");
}

TEST_CASE("log_token: every structural byte maps to '_'", "[log_token]") {
    CHECK(log_token("a b") == "a_b");
    CHECK(log_token("a=b") == "a_b");
    CHECK(log_token("a,b") == "a_b");
    CHECK(log_token(std::string("a\nb")) == "a_b");
    CHECK(log_token(std::string("a\rb")) == "a_b");
    CHECK(log_token(std::string("a\tb")) == "a_b");
    CHECK(log_token(std::string("a\x7F" "b")) == "a_b");
    CHECK(log_token(std::string("a\0b", 3)) == "a_b"); // embedded NUL
    // The exact forging shape: extra tokens AND a whole second line.
    CHECK(log_token("x agent=victim rule=r\nGuardian T_wire event_id=z") ==
          "x_agent_victim_rule_r_Guardian_T_wire_event_id_z");
    // Boundaries: 0x1F is a control byte, 0x20 is a space, 0x21 is not structural.
    CHECK(log_token(std::string(1, '\x1F')) == "_");
    CHECK(log_token(" ") == "_");
    CHECK(log_token("!") == "!");
}

TEST_CASE("log_token: the cap truncates by bytes and is applied before neutralising",
          "[log_token]") {
    const std::string s(kGuardianLogIdMaxBytes + 10, 'a');
    CHECK(log_token(s, kGuardianLogIdMaxBytes) == std::string(kGuardianLogIdMaxBytes, 'a'));
    // Exactly at the cap is untouched; no cap means no truncation at all.
    const std::string exact(kGuardianLogIdMaxBytes, 'b');
    CHECK(log_token(exact, kGuardianLogIdMaxBytes) == exact);
    CHECK(log_token(s).size() == s.size());
    CHECK(log_token(s, kLogTokenNoCap).size() == s.size());
    CHECK(log_token("abc", 0) == "");
    // The cap counts INPUT bytes, so a structural byte inside the cap still becomes one '_'.
    CHECK(log_token("a b c", 3) == "a_b");
    // The shared cap the Guardian T_* lines apply on both sides.
    CHECK(kGuardianLogIdMaxBytes == 256);
}

TEST_CASE("log_token: audit_token delegates to the same mapping", "[log_token]") {
    // audit_token predates log_token and is the audit-detail neutraliser; it now forwards, so
    // the two cannot drift. Cover every structural class plus a passthrough.
    for (const std::string s : {std::string("plain"), std::string("a b"), std::string("k=v,k2=v2"),
                                std::string("x\r\ny"), std::string("\x7F"), std::string("caf\xC3\xA9")}) {
        CHECK(yuzu::server::audit_token(s) == log_token(s));
    }
}
