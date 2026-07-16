#pragma once

/**
 * firewall_parsers.hpp — pure parse helpers for the firewall plugin's macOS
 * state leg: the Application Firewall global state (socketfilterfw) and the
 * pf packet-filter status (pfctl).
 *
 * Header-only and OS-free so the parsing is unit-tested on every host
 * (test_firewall_parsers.cpp — the netprobe_stats.hpp pattern); the popen
 * shell-outs in firewall_plugin.cpp are the impure shell.
 *
 * Honest-status invariant: empty, truncated, or unrecognised output parses
 * to `unknown` — never a false-safe enabled/disabled.
 */

#include <string_view>

namespace yuzu::firewall {

enum class FwState { enabled, disabled, unknown };

inline std::string_view to_string(FwState s) {
    switch (s) {
    case FwState::enabled:
        return "enabled";
    case FwState::disabled:
        return "disabled";
    default:
        return "unknown";
    }
}

/// Global state of the macOS Application Firewall as reported by
/// `socketfilterfw --getglobalstate`.
struct AlfGlobalState {
    FwState state{FwState::unknown};
    bool block_all{false}; // "(State = 2)" — enabled AND blocking all incoming
};

/// Parse `/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate`.
/// Primary signal is the "(State = N)" clause — 0 = disabled, 1 = enabled,
/// 2 = enabled + block-all — so prose rewording across macOS releases cannot
/// flip the verdict. The enabled/disabled prose is only a fallback, with
/// "disabled" checked first so ambiguous text biases toward the
/// attention-drawing answer rather than false assurance.
inline AlfGlobalState parse_alf_global_state(std::string_view out) {
    AlfGlobalState r;
    static constexpr std::string_view kClause = "(State = ";
    auto pos = out.find(kClause);
    if (pos != std::string_view::npos && pos + kClause.size() < out.size()) {
        switch (out[pos + kClause.size()]) {
        case '0':
            r.state = FwState::disabled;
            return r;
        case '1':
            r.state = FwState::enabled;
            return r;
        case '2':
            r.state = FwState::enabled;
            r.block_all = true;
            return r;
        default:
            break; // unrecognised state number — fall through to prose
        }
    }
    if (out.find("disabled") != std::string_view::npos)
        r.state = FwState::disabled;
    else if (out.find("enabled") != std::string_view::npos)
        r.state = FwState::enabled;
    return r;
}

/// Parse `pfctl -s info`. The first line reads "Status: Enabled for …" or
/// "Status: Disabled for …". Empty output (reading /dev/pf needs root and the
/// caller discards stderr) or anything unrecognised → unknown.
inline FwState parse_pf_status(std::string_view out) {
    if (out.find("Status: Enabled") != std::string_view::npos)
        return FwState::enabled;
    if (out.find("Status: Disabled") != std::string_view::npos)
        return FwState::disabled;
    return FwState::unknown;
}

} // namespace yuzu::firewall
