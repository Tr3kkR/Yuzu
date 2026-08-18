/**
 * network_actions_parsers.hpp — pure, header-only helper(s) for
 * network_actions_plugin.cpp (ADR-3002 pure-core/thin-shell discipline:
 * testable decision logic lives here, free of I/O, subprocess spawning, or
 * any OS call, so it is fixture-testable without a runner/context).
 */
#pragma once

#include <string_view>

namespace yuzu::network_actions {

// Linux flush_dns resolves to whichever of resolvectl/systemd-resolve
// probe_tool_path actually found (see network_actions_plugin.cpp's
// flush_dns_linux site) and then must invoke it with the RIGHT verb spelling:
// resolvectl (systemd-resolved's modern CLI) takes a bare subcommand
// ("flush-caches"); the older systemd-resolve CLI predates that convention
// and takes a long option ("--flush-caches") instead. This picks the verb
// that matches whichever absolute tool path was resolved.
inline std::string_view resolver_flush_flag(std::string_view tool_path) {
    constexpr std::string_view kSystemdResolve = "systemd-resolve";
    if (tool_path.size() >= kSystemdResolve.size() &&
        tool_path.substr(tool_path.size() - kSystemdResolve.size()) == kSystemdResolve) {
        return "--flush-caches";
    }
    return "flush-caches";
}

} // namespace yuzu::network_actions
