/**
 * test_discovery_parsers.cpp — parse_proc_net_arp (discovery_parsers.hpp)
 * (Wave-2 PR2.1, WP-C).
 *
 * Portable and unguarded — parse_proc_net_arp is pure header-only text
 * parsing (no ifstream, no platform dependency), so this TU carries no
 * platform guard and runs on every leg, macOS included.
 */
#include "discovery_parsers.hpp"

#include <catch2/catch_test_macros.hpp>

using yuzu::discovery::parse_proc_net_arp;

TEST_CASE("parse_proc_net_arp parses the real captured /proc/net/arp table",
         "[agent][discovery_parsers]") {
    // Real capture (captured 2026-08-14T20:07:03Z via docker — pre-migration
    // fixtures per ADR-3002:688-694): the two-line table section of
    // ~/.claude/wave2-prestage/fixtures/linux/proc_net_arp.out (manifest.txt
    // line "proc_net_arp.out|rc=0|cmd=docker debian:bookworm-slim ping
    // gateway then cat /proc/net/arp"); the file's leading "bash: line 5: ip:
    // command not found" and "=== ... ===" section banners are capture-
    // harness noise, not fixture data, and are excluded here.
    constexpr std::string_view kRealCapture = R"(IP address       HW type     Flags       HW address            Mask     Device
172.17.0.1       0x1         0x2         8e:2a:cd:00:41:28     *        eth0
)";

    const auto entries = parse_proc_net_arp(kRealCapture);
    REQUIRE(entries.size() == 1);
    CHECK(entries[0].ip == "172.17.0.1");
    CHECK(entries[0].mac == "8e:2a:cd:00:41:28");
}

TEST_CASE("parse_proc_net_arp returns empty on a header-only table",
         "[agent][discovery_parsers]") {
    constexpr std::string_view kHeaderOnly =
        "IP address       HW type     Flags       HW address            Mask     Device\n";
    CHECK(parse_proc_net_arp(kHeaderOnly).empty());
}

TEST_CASE("parse_proc_net_arp returns empty on blank input", "[agent][discovery_parsers]") {
    CHECK(parse_proc_net_arp("").empty());
    CHECK(parse_proc_net_arp("\n\n").empty());
}

TEST_CASE("parse_proc_net_arp drops an all-zero MAC", "[agent][discovery_parsers]") {
    constexpr std::string_view kAllZero =
        "IP address       HW type     Flags       HW address            Mask     Device\n"
        "192.168.1.50     0x1         0x2         00:00:00:00:00:00     *        eth0\n";
    CHECK(parse_proc_net_arp(kAllZero).empty());
}

TEST_CASE("parse_proc_net_arp drops an entry without the ATF_COM complete bit",
         "[agent][discovery_parsers]") {
    constexpr std::string_view kIncomplete =
        "IP address       HW type     Flags       HW address            Mask     Device\n"
        "192.168.1.51     0x1         0x0         00:00:00:00:00:00     *        eth0\n"
        "192.168.1.52     0x1         0x4         aa:bb:cc:dd:ee:ff     *        eth0\n";
    // Neither row has bit 0x2 set (0x0 and 0x4) — both dropped, even though
    // the second has a real-looking, non-zero MAC.
    CHECK(parse_proc_net_arp(kIncomplete).empty());
}

TEST_CASE("parse_proc_net_arp drops a non-Ethernet hardware type",
         "[agent][discovery_parsers]") {
    // hwtype 0x6 (IEEE 802 / token ring family) is complete and has a
    // real-looking MAC, but the old `arp -n` parser required hwtype
    // "ether" — preserve that selectivity: non-Ethernet rows are dropped
    // even when otherwise well-formed and "complete".
    constexpr std::string_view kNonEthernet =
        "IP address       HW type     Flags       HW address            Mask     Device\n"
        "192.168.1.90     0x6         0x2         aa:bb:cc:dd:ee:ff     *        eth0\n";
    CHECK(parse_proc_net_arp(kNonEthernet).empty());
}

TEST_CASE("parse_proc_net_arp drops a truncated row missing Mask/Device",
         "[agent][discovery_parsers]") {
    // Only 4 of the 6 kernel columns present — a truncated capture, not a
    // real /proc/net/arp row. Must be skipped, not misread as complete.
    constexpr std::string_view kTruncated =
        "IP address       HW type     Flags       HW address            Mask     Device\n"
        "192.168.1.91     0x1         0x2         aa:bb:cc:dd:ee:ff\n";
    CHECK(parse_proc_net_arp(kTruncated).empty());
}

TEST_CASE("parse_proc_net_arp tolerates ragged/collapsed whitespace",
         "[agent][discovery_parsers]") {
    constexpr std::string_view kRagged =
        "IP address       HW type     Flags       HW address            Mask     Device\n"
        "  192.168.1.60 \t 0x1  0x2 aa:bb:cc:dd:ee:ff\t*   eth0  \n";
    const auto entries = parse_proc_net_arp(kRagged);
    REQUIRE(entries.size() == 1);
    CHECK(entries[0].ip == "192.168.1.60");
    CHECK(entries[0].mac == "aa:bb:cc:dd:ee:ff");
}

TEST_CASE("parse_proc_net_arp tolerates short/malformed lines without crashing",
         "[agent][discovery_parsers]") {
    constexpr std::string_view kShortLines =
        "IP address       HW type     Flags       HW address            Mask     Device\n"
        "192.168.1.61\n"
        "192.168.1.62     0x1\n"
        "192.168.1.63     0x1         0x2         aa:bb:cc:dd:ee:00     *        eth0\n";
    const auto entries = parse_proc_net_arp(kShortLines);
    REQUIRE(entries.size() == 1);
    CHECK(entries[0].ip == "192.168.1.63");
}

TEST_CASE("parse_proc_net_arp tolerates CRLF line endings", "[agent][discovery_parsers]") {
    constexpr std::string_view kCrlf =
        "IP address       HW type     Flags       HW address            Mask     Device\r\n"
        "192.168.1.70     0x1         0x2         aa:bb:cc:11:22:33     *        eth0\r\n";
    const auto entries = parse_proc_net_arp(kCrlf);
    REQUIRE(entries.size() == 1);
    CHECK(entries[0].ip == "192.168.1.70");
    CHECK(entries[0].mac == "aa:bb:cc:11:22:33");
}

TEST_CASE("parse_proc_net_arp tolerates a missing header line",
         "[agent][discovery_parsers]") {
    // No "IP address ..." header row at all — the first line is real data
    // and must not be mistaken for (and dropped as) a header.
    constexpr std::string_view kNoHeader =
        "192.168.1.80     0x1         0x2         aa:bb:cc:44:55:66     *        eth0\n";
    const auto entries = parse_proc_net_arp(kNoHeader);
    REQUIRE(entries.size() == 1);
    CHECK(entries[0].ip == "192.168.1.80");
    CHECK(entries[0].mac == "aa:bb:cc:44:55:66");
}
