/**
 * windows_optional_features_parsers.hpp — pure state/row parsers and the
 * pure busy/timeout state machine for the windows_optional_features plugin.
 *
 * Deliberately free of <windows.h>: every function here is a plain string/
 * integer transform, testable on every OS via
 * tests/unit/test_windows_optional_features_parsers.cpp against P92-1's
 * real-capture fixtures — no DISM handle, no HRESULT, no wide string ever
 * crosses this header.
 *
 * `DismSlot` is the single owner of the busy/abandoned/timed-out state
 * machine windows_optional_features_plugin.cpp's Windows leg uses to keep
 * at most one DISM call in flight (DISM sessions are not documented as
 * safe for concurrent same-process use). It is pure — no thread, no clock,
 * no DISM call — so its acquired/busy/abandoned/release sequencing is
 * proven on every OS by the same test file that proves the row parsers.
 */
#pragma once

#include <yuzu/string_utils.hpp> // yuzu::util::safe_output_field

#include <atomic>
#include <charconv>
#include <format>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

namespace yuzu::wof {

// DismPackageFeatureState integer values (mingw dismapi.h:95-105, confirmed
// against the ADK header on the-rig — see
// tests/unit/fixtures/wave9/probes/the-rig-dism-findings.md).
enum class FeatureState {
    not_present,
    uninstall_pending,
    staged,
    removed,
    installed,
    install_pending,
    superseded,
    partially_installed,
    unknown,
};

/// Maps a raw DismPackageFeatureState int to a named state. Any value
/// outside the SDK's documented 0-7 range maps to `unknown` -- never
/// throws, since this is reached from a DISM enumeration loop that must
/// never abort a whole `list` over one unexpected int.
[[nodiscard]] inline FeatureState state_from_dism(int value) noexcept {
    switch (value) {
    case 0:
        return FeatureState::not_present;
    case 1:
        return FeatureState::uninstall_pending;
    case 2:
        return FeatureState::staged;
    case 3:
        return FeatureState::removed;
    case 4:
        return FeatureState::installed;
    case 5:
        return FeatureState::install_pending;
    case 6:
        return FeatureState::superseded;
    case 7:
        return FeatureState::partially_installed;
    default:
        return FeatureState::unknown;
    }
}

[[nodiscard]] inline std::string_view state_name(FeatureState state) noexcept {
    switch (state) {
    case FeatureState::installed:
        return "enabled";
    case FeatureState::not_present:
    case FeatureState::removed:
    case FeatureState::staged:
        return "disabled";
    case FeatureState::install_pending:
        return "pending_enable";
    case FeatureState::uninstall_pending:
        return "pending_disable";
    case FeatureState::superseded:
        return "superseded";
    case FeatureState::partially_installed:
        return "partially_installed";
    case FeatureState::unknown:
        break;
    }
    return "unknown";
}

/// True only for the two states DISM itself calls "pending" -- a reboot is
/// needed before the feature's enable/disable takes full effect.
[[nodiscard]] inline bool pending_restart(FeatureState state) noexcept {
    return state == FeatureState::install_pending || state == FeatureState::uninstall_pending;
}

/// DismRestartType: No=0, Possible=1, Required=2. Anything else (there is
/// no documented fourth value, but DismGetFeatureInfo's output is still
/// external data) maps to "unknown", matching state_from_dism's own
/// never-throw contract.
[[nodiscard]] inline std::string_view restart_type_name(int value) noexcept {
    switch (value) {
    case 0:
        return "no";
    case 1:
        return "possible";
    case 2:
        return "required";
    default:
        return "unknown";
    }
}

/// The `list`/`info` action decides which discriminator a row carries:
/// `feature` for list rows, `feature_info` for info rows -- also used for
/// the unsupported/unavailable sentinel rows so a positional parser can
/// still tell the two actions' output apart.
[[nodiscard]] inline std::string_view row_kind_for_action(std::string_view action) noexcept {
    return action == "info" ? "feature_info" : "feature";
}

[[nodiscard]] inline std::string format_feature_row(std::string_view name, FeatureState state,
                                                     bool restart_required) {
    return std::format("feature|{}|{}|{}", yuzu::util::safe_output_field(name), state_name(state),
                        restart_required ? "1" : "0");
}

[[nodiscard]] inline std::string format_feature_info_row(std::string_view name,
                                                          std::string_view display_name,
                                                          FeatureState state, int restart_type,
                                                          std::string_view description) {
    return std::format("feature_info|{}|{}|{}|{}|{}", yuzu::util::safe_output_field(name),
                        yuzu::util::safe_output_field(display_name), state_name(state),
                        restart_type_name(restart_type),
                        yuzu::util::safe_output_field(description));
}

[[nodiscard]] inline std::string format_unsupported_row(std::string_view action,
                                                         std::string_view token) {
    return std::format("{}|unsupported|{}", row_kind_for_action(action), token);
}

[[nodiscard]] inline std::string format_unavailable_row(std::string_view action,
                                                         std::string_view token) {
    return std::format("{}|unavailable|{}", row_kind_for_action(action), token);
}

/// `feature` is passed to DismGetFeatureInfo verbatim, so it is bounded and
/// character-restricted here rather than trusted through to the DISM call:
/// 1..256 chars of [A-Za-z0-9._-], nullopt otherwise (empty, too long, or
/// any other byte -- including '/', '\\', and whitespace). A literal `..`
/// anywhere in the value is also refused: '.' alone is a legal DISM feature
/// name character, but a `..` run is a path-traversal component with no
/// legitimate feature-name use, so it is rejected even though every
/// individual byte in it would otherwise pass.
[[nodiscard]] inline std::optional<std::string> validate_feature_name(std::string_view name) {
    if (name.empty() || name.size() > 256)
        return std::nullopt;
    if (name.find("..") != std::string_view::npos)
        return std::nullopt;
    for (char c : name) {
        const bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                        c == '.' || c == '_' || c == '-';
        if (!ok)
            return std::nullopt;
    }
    return std::string{name};
}

/// The optional `state` filter on `list`: enabled -> installed only;
/// disabled -> not_present/removed/staged; pending -> install_pending/
/// uninstall_pending. An unrecognized token returns nullopt -- the caller
/// treats that as "no filter" rather than failing the whole read, since
/// there is no closed failure token reserved for a bad filter value.
[[nodiscard]] inline std::optional<std::unordered_set<FeatureState>>
parse_state_filter(std::string_view token) {
    if (token == "enabled")
        return std::unordered_set<FeatureState>{FeatureState::installed};
    if (token == "disabled")
        return std::unordered_set<FeatureState>{FeatureState::not_present, FeatureState::removed,
                                                 FeatureState::staged};
    if (token == "pending")
        return std::unordered_set<FeatureState>{FeatureState::install_pending,
                                                 FeatureState::uninstall_pending};
    return std::nullopt;
}

/// One row of P92-1's probe dump between its "feature list" markers:
/// `<name>\t<state_int>`.
struct ProbeFeatureRow {
    std::string name;
    int state_int = 0;
};

/// Parses probe_wave9_dism.cpp's `features` dump (see
/// tests/unit/fixtures/wave9/windows_optional_features/dism_features_system.txt)
/// between its `--- feature list (name<TAB>state_int) ---` and
/// `--- end feature list ---` markers. Malformed/non-tab-delimited lines
/// inside the body are skipped rather than aborting the whole parse; a
/// missing start marker returns an empty vector.
[[nodiscard]] inline std::vector<ProbeFeatureRow> parse_probe_features_dump(std::string_view text) {
    std::vector<ProbeFeatureRow> out;

    constexpr std::string_view kStartMarker = "feature list (name<TAB>state_int)";
    constexpr std::string_view kEndMarker = "--- end feature list ---";

    const auto start = text.find(kStartMarker);
    if (start == std::string_view::npos)
        return out;
    auto body_start = text.find('\n', start);
    if (body_start == std::string_view::npos)
        return out;
    ++body_start;
    const auto end = text.find(kEndMarker, body_start);
    const std::string_view body =
        (end == std::string_view::npos) ? text.substr(body_start) : text.substr(body_start, end - body_start);

    std::size_t line_start = 0;
    while (line_start <= body.size()) {
        const auto nl = body.find('\n', line_start);
        std::string_view line =
            (nl == std::string_view::npos) ? body.substr(line_start) : body.substr(line_start, nl - line_start);
        if (!line.empty() && line.back() == '\r')
            line.remove_suffix(1);

        const auto tab = line.find('\t');
        if (tab != std::string_view::npos) {
            const std::string_view name = line.substr(0, tab);
            const std::string_view state_str = line.substr(tab + 1);
            int state_int = 0;
            const auto res =
                std::from_chars(state_str.data(), state_str.data() + state_str.size(), state_int);
            if (res.ec == std::errc{} && !name.empty())
                out.push_back(ProbeFeatureRow{std::string{name}, state_int});
        }

        if (nl == std::string_view::npos)
            break;
        line_start = nl + 1;
    }
    return out;
}

/// Single owner of the busy/abandoned/timed-out flag's lifecycle (peer H2).
/// `in_use` guards "a DISM call is in flight"; `timed_out` distinguishes a
/// merely-busy slot (a call is legitimately running, will finish soon) from
/// an abandoned one (the dispatching thread already gave up waiting on a
/// prior call, so the worker that eventually finishes it is the only thing
/// that can still release the slot). Every method is noexcept and touches
/// only these two atomics -- no thread, no clock, no DISM call -- so the
/// acquired/busy/abandoned/release sequencing is provable on every OS.
struct DismSlot {
    std::atomic<bool> in_use{false};
    std::atomic<bool> timed_out{false};

    enum class Acquire { acquired, busy, abandoned };

    /// Called by whichever thread is about to start (or refuse to start) a
    /// DISM call. CAS in_use false->true wins the slot (`acquired`);
    /// otherwise the slot is already held, and `timed_out` distinguishes
    /// `busy` (a call is genuinely still running) from `abandoned` (the
    /// dispatching thread already gave up on a prior call and the worker
    /// that eventually finishes it owns the only release).
    [[nodiscard]] Acquire try_acquire() noexcept {
        bool expected = false;
        if (in_use.compare_exchange_strong(expected, true, std::memory_order_acq_rel,
                                           std::memory_order_acquire)) {
            return Acquire::acquired;
        }
        return timed_out.load(std::memory_order_acquire) ? Acquire::abandoned : Acquire::busy;
    }

    /// Called ONLY by the DISPATCHING thread when its bounded wait on an
    /// in-flight call expires. Never touches `in_use` -- the worker thread
    /// that is still running the call is the only thing allowed to clear
    /// it, once DISM teardown actually completes.
    void mark_timed_out() noexcept { timed_out.store(true, std::memory_order_release); }

    /// Called ONLY by the WORKER thread once it has finished a DISM call it
    /// owns (or, on the Rejected bounded-call path, by the calling thread
    /// itself, since fn() there never ran and no worker exists). Clears
    /// `timed_out` before `in_use` so a racing try_acquire() never observes
    /// `in_use=false, timed_out=true` -- a state this slot's contract does
    /// not define.
    void release() noexcept {
        timed_out.store(false, std::memory_order_release);
        in_use.store(false, std::memory_order_release);
    }
};

} // namespace yuzu::wof
