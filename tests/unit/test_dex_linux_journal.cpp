/**
 * test_dex_linux_journal.cpp — pure journald classification (dex_linux_journal).
 *
 * The sibling of test_dex_linux_proc / test_dex_macos: parsing a `journalctl -o
 * json` line into a SignalObservation is pure text handling, so it runs on EVERY
 * host against captured fixtures. The journalctl shell-out + cursor checkpoint
 * (dex_linux_collector) are exercised on a real Linux box via the live pipeline,
 * not here.
 */

#include "dex_linux_journal.hpp"

#include <catch2/catch_test_macros.hpp>

using namespace yuzu::agent::lnx;

TEST_CASE("journal: coredump → process.crashed", "[guardian][dex][linux][journal]") {
    const std::string line =
        R"({"__CURSOR":"s=ab;i=1;b=cd","MESSAGE_ID":"fc2e22bc6ee647b6b90729ab34a250b1",)"
        R"("COREDUMP_COMM":"nginx","COREDUMP_SIGNAL":"11","COREDUMP_EXE":"/usr/sbin/nginx"})";
    const JournalLine jl = parse_journal_line(line);
    CHECK(jl.cursor == "s=ab;i=1;b=cd");
    REQUIRE(jl.obs.has_value());
    CHECK(jl.obs->obs_type == "process.crashed");
    CHECK(jl.obs->subject == "nginx");
    CHECK(jl.obs->reason == "SIGSEGV");
    CHECK(jl.obs->kind == "signal");
    CHECK(jl.obs->platform.empty()); // collector stamps platform, not the parser
}

TEST_CASE("journal: coredump without a comm is dropped (no EXE path shipped)",
          "[guardian][dex][linux][journal]") {
    const std::string line =
        R"({"__CURSOR":"s=ab;i=2;b=cd","MESSAGE_ID":"fc2e22bc6ee647b6b90729ab34a250b1",)"
        R"("COREDUMP_EXE":"/opt/app/secret-path"})";
    const JournalLine jl = parse_journal_line(line);
    CHECK(jl.cursor == "s=ab;i=2;b=cd"); // cursor still advances
    CHECK_FALSE(jl.obs.has_value());
}

TEST_CASE("journal: unit failed → service.crashed", "[guardian][dex][linux][journal]") {
    const std::string line =
        R"({"__CURSOR":"s=ab;i=3;b=cd","MESSAGE_ID":"be02cf6855d2428ba40df7e9d022f03d",)"
        R"("UNIT":"postgresql.service","UNIT_RESULT":"exit-code"})";
    const JournalLine jl = parse_journal_line(line);
    REQUIRE(jl.obs.has_value());
    CHECK(jl.obs->obs_type == "service.crashed");
    CHECK(jl.obs->subject == "postgresql.service");
    CHECK(jl.obs->reason == "exit-code");
    CHECK(jl.obs->kind == "unit");
}

TEST_CASE("journal: unit failed without UNIT_RESULT still emits (empty reason)",
          "[guardian][dex][linux][journal]") {
    const std::string line =
        R"({"__CURSOR":"x","MESSAGE_ID":"be02cf6855d2428ba40df7e9d022f03d","UNIT":"sshd.service"})";
    const JournalLine jl = parse_journal_line(line);
    REQUIRE(jl.obs.has_value());
    CHECK(jl.obs->obs_type == "service.crashed");
    CHECK(jl.obs->subject == "sshd.service");
    CHECK(jl.obs->reason.empty());
}

TEST_CASE("journal: 'Failed with result' (the real failure message) → service.crashed",
          "[guardian][dex][linux][journal]") {
    // The MESSAGE_ID a simple service failure actually logs (confirmed against a live
    // specimen) — distinct from SD_MESSAGE_UNIT_FAILED, carries UNIT + UNIT_RESULT.
    const std::string line =
        R"({"__CURSOR":"s=ab;i=9;b=cd","MESSAGE_ID":"d9b373ed55a64feb8242e02dbe79a49c",)"
        R"("UNIT":"yuzu-smoke.service","UNIT_RESULT":"exit-code"})";
    const JournalLine jl = parse_journal_line(line);
    REQUIRE(jl.obs.has_value());
    CHECK(jl.obs->obs_type == "service.crashed");
    CHECK(jl.obs->subject == "yuzu-smoke.service");
    CHECK(jl.obs->reason == "exit-code");
}

TEST_CASE("journal: kernel OOM-kill → memory.exhausted", "[guardian][dex][linux][journal]") {
    const std::string line =
        R"({"__CURSOR":"s=ab;i=4;b=cd","_TRANSPORT":"kernel",)"
        R"("MESSAGE":"Out of memory: Killed process 4321 (mysqld) total-vm:9000000kB"})";
    const JournalLine jl = parse_journal_line(line);
    REQUIRE(jl.obs.has_value());
    CHECK(jl.obs->obs_type == "memory.exhausted");
    CHECK(jl.obs->subject == "mysqld");
    CHECK(jl.obs->reason == "oom-kill");
}

TEST_CASE("journal: non-OOM kernel line is dropped but advances the cursor",
          "[guardian][dex][linux][journal]") {
    const std::string line =
        R"({"__CURSOR":"s=ab;i=5;b=cd","_TRANSPORT":"kernel","MESSAGE":"usb 1-1: new device"})";
    const JournalLine jl = parse_journal_line(line);
    CHECK(jl.cursor == "s=ab;i=5;b=cd");
    CHECK_FALSE(jl.obs.has_value());
}

TEST_CASE("journal: unrelated MESSAGE_ID is dropped (cursor kept)",
          "[guardian][dex][linux][journal]") {
    const std::string line =
        R"({"__CURSOR":"s=ab;i=6;b=cd","MESSAGE_ID":"7d4958e842da4a758f6c1cdc7b36dcc5",)"
        R"("UNIT":"cron.service"})"; // unit STARTED, not failed
    const JournalLine jl = parse_journal_line(line);
    CHECK(jl.cursor == "s=ab;i=6;b=cd");
    CHECK_FALSE(jl.obs.has_value());
}

TEST_CASE("journal: malformed JSON yields no cursor, no obs (never throws)",
          "[guardian][dex][linux][journal]") {
    CHECK_FALSE(parse_journal_line("not json at all").obs.has_value());
    CHECK(parse_journal_line("not json at all").cursor.empty());
    CHECK_FALSE(parse_journal_line("").obs.has_value());
    // a JSON array (not an object) is also rejected
    CHECK_FALSE(parse_journal_line("[1,2,3]").obs.has_value());
}

TEST_CASE("crash_signal_name maps the core-generating signals",
          "[guardian][dex][linux][journal]") {
    CHECK(crash_signal_name(11) == "SIGSEGV");
    CHECK(crash_signal_name(6) == "SIGABRT");
    CHECK(crash_signal_name(7) == "SIGBUS");
    CHECK(crash_signal_name(8) == "SIGFPE");
    CHECK(crash_signal_name(99) == "signal 99"); // unmapped → numeric fallback
}
