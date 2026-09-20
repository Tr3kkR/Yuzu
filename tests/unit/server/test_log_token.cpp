/**
 * test_log_token.cpp -- the shared log-token neutralisers (common/include/yuzu/log_token.hpp).
 *
 * One mapping core, used on BOTH sides of the Guardian T_wire/T_server id join (log_id_token)
 * and by the server's audit-detail neutraliser (log_token, via audit_token). The tests pin the
 * mapping byte-for-byte because a per-side difference would silently break the join for exactly
 * the ids that need it.
 */

#include "web_utils.hpp"

#include <catch2/catch_test_macros.hpp>

#include <yuzu/log_token.hpp>

#include <string>

using yuzu::kGuardianLogIdMaxBytes;
using yuzu::kGuardianLogIdTailBytes;
using yuzu::log_id_token;
using yuzu::log_token;

TEST_CASE("log_token: ordinary identifiers pass through unchanged", "[log_token]") {
    CHECK(log_token("") == "");
    CHECK(log_token("rule-1") == "rule-1");
    CHECK(log_token("agent-2c82.evt_9:x/y") == "agent-2c82.evt_9:x/y");
    // Bytes >= 0x80 (UTF-8) are not structural for the audit-detail mapping and pass through.
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

TEST_CASE("log_id_token: printable ASCII passes, everything else becomes '_'", "[log_token]") {
    CHECK(log_id_token("") == "");
    CHECK(log_id_token("agent-1-r1-1789930557755-5") == "agent-1-r1-1789930557755-5");
    CHECK(log_id_token("rule-1.2:x/y_z~") == "rule-1.2:x/y_z~");
    CHECK(log_id_token("a b=c,d") == "a_b_c_d");
    CHECK(log_id_token(std::string("a\nb\rc\td")) == "a_b_c_d");
    CHECK(log_id_token(std::string("a\0b", 3)) == "a_b");
    CHECK(log_id_token(std::string("a\x7F" "b")) == "a_b");
    // Boundaries: 0x20 (space) maps, 0x21 ('!') and 0x7E ('~') pass, 0x7F maps.
    CHECK(log_id_token(" ") == "_");
    CHECK(log_id_token("!") == "!");
    CHECK(log_id_token("~") == "~");
    // Every byte >= 0x80 maps, so a multi-byte character can neither be cut into invalid UTF-8
    // nor smuggle a Unicode line separator into a line.
    CHECK(log_id_token("caf\xC3\xA9") == "caf__");
    CHECK(log_id_token("a\xE2\x80\xA8" "b") == "a___b"); // U+2028 LINE SEPARATOR
    CHECK(log_id_token("a\xC2\x85" "b") == "a__b");      // U+0085 NEXT LINE
    // The exact forging shape from a hostile rule id.
    CHECK(log_id_token("x agent=victim rule=r\nGuardian T_wire event_id=z") ==
          "x_agent_victim_rule_r_Guardian_T_wire_event_id_z");
}

TEST_CASE("log_id_token: an over-long id keeps its head, a marker and its tail", "[log_token]") {
    constexpr std::size_t kMax = kGuardianLogIdMaxBytes;
    constexpr std::size_t kTail = kGuardianLogIdTailBytes;

    // At or under the cap: untouched.
    const std::string exact(kMax, 'b');
    CHECK(log_id_token(exact) == exact);

    // One byte over: shortened to EXACTLY the cap as head + '~' + the last kTail bytes.
    std::string s;
    for (std::size_t i = 0; i < kMax + 1; ++i)
        s.push_back(static_cast<char>('a' + (i % 26)));
    const std::string t = log_id_token(s);
    REQUIRE(t.size() == kMax);
    CHECK(t.substr(0, kMax - kTail - 1) == s.substr(0, kMax - kTail - 1));
    CHECK(t[kMax - kTail - 1] == '~');
    CHECK(t.substr(kMax - kTail) == s.substr(s.size() - kTail));

    // The tail is what tells two events of one rule apart (`<wall_ms>-<seq>`): two over-long ids
    // that differ only there must NOT collapse onto one token (a plain prefix cut would).
    const std::string head(300, 'r');
    CHECK(log_id_token(head + "-1789930557755-101") != log_id_token(head + "-1789930557755-102"));

    // A multi-byte character straddling the cut cannot leave invalid UTF-8: the result is all ASCII.
    std::string mb(kMax - kTail - 2, 'a');
    mb += "\xC3\xA9"; // straddles the head boundary
    mb.append(200, 'z');
    const std::string m = log_id_token(mb);
    CHECK(m.size() == kMax);
    for (const char c : m)
        CHECK(static_cast<unsigned char>(c) < 0x80);

    // The shared constants themselves (agent and server both use these).
    CHECK(kGuardianLogIdMaxBytes == 256);
    CHECK(kGuardianLogIdTailBytes == 24);
}

TEST_CASE("log_token: audit_token delegates to the same mapping", "[log_token]") {
    // audit_token predates log_token and is the audit-detail neutraliser; it now forwards, so
    // the two cannot drift. Cover every structural class plus a passthrough.
    for (const std::string& s : {std::string("plain"), std::string("a b"), std::string("k=v,k2=v2"),
                                 std::string("x\r\ny"), std::string("\x7F"),
                                 std::string("caf\xC3\xA9")}) {
        CHECK(yuzu::server::audit_token(s) == log_token(s));
    }
}
