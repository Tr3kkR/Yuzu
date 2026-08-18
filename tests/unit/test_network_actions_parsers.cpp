// network_actions_parsers.hpp's resolver_flush_flag() picks the correct
// flush-cache verb spelling for whichever Linux DNS resolver tool
// probe_tool_path found: resolvectl's modern CLI takes a bare subcommand,
// while the older systemd-resolve CLI takes a long option instead. Pure
// string-suffix logic — no subprocess, no filesystem probe.
#include <catch2/catch_test_macros.hpp>

#include "../../agents/plugins/network_actions/src/network_actions_parsers.hpp"

#include <string>

using yuzu::network_actions::resolver_flush_flag;

TEST_CASE("resolver_flush_flag: resolvectl takes the bare subcommand",
         "[agent][network_actions]") {
    CHECK(resolver_flush_flag("/usr/bin/resolvectl") == "flush-caches");
}

TEST_CASE("resolver_flush_flag: systemd-resolve takes the long option",
         "[agent][network_actions]") {
    CHECK(resolver_flush_flag("/usr/bin/systemd-resolve") == "--flush-caches");
}

TEST_CASE("resolver_flush_flag: matches on the tool basename, not just an exact path",
         "[agent][network_actions]") {
    // A distro that ships the older CLI at a different prefix still gets the
    // long-option form, because the match is a path suffix, not full equality.
    CHECK(resolver_flush_flag("/bin/systemd-resolve") == "--flush-caches");
}

TEST_CASE("resolver_flush_flag: empty / unrecognised path defaults to the bare subcommand",
         "[agent][network_actions]") {
    // probe_tool_path only ever returns an absolute resolvectl/systemd-resolve
    // path or empty; an empty path never reaches run_bounded_subprocess (the
    // caller leaves argv empty instead), but the pure function itself has no
    // way to signal "no tool" and must still return something well-defined.
    CHECK(resolver_flush_flag("") == "flush-caches");
    CHECK(resolver_flush_flag("/usr/bin/resolvectl-wrapper") == "flush-caches");
}
