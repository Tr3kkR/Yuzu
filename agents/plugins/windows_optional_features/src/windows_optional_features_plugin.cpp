/**
 * windows_optional_features_plugin.cpp — Windows optional OS feature
 * (DISM) state plugin for Yuzu.
 *
 * Actions:
 *   "list" — Lists every optional feature and its state (optional `state`
 *            filter: enabled|disabled|pending).
 *   "info" — Detail for one feature (required `feature`).
 *
 * Windows: DISM API, DISM_ONLINE_IMAGE session. Per Architect ruling
 *   2026-09-08 (specs/P92-2.respec.md — binding, read it before touching
 *   this file), DismApi.dll is runtime-bound at LOAD_LIBRARY_SEARCH_SYSTEM32
 *   and NEVER `#include <dismapi.h>`/`DismApi.lib`/`find_library`: that
 *   header/import-lib pair ships only with the Windows ADK's "Deployment
 *   Tools" feature, absent from every self-hosted Windows CI runner (P92-1,
 *   tests/unit/fixtures/wave9/probes/the-rig-dism-findings.md). The eight
 *   resolved exports are the WHOLE DISM surface this plugin uses — no
 *   enable/disable/add/commit export is ever resolved (read-only by
 *   construction).
 * macOS / Linux: DISM has no equivalent — an honest unsupported row on
 *   every action, never a fabricated read.
 *
 * Output is pipe-delimited via write_output():
 *   feature|<name>|<state>|<restart_required 1/0>
 *   feature_info|<name>|<display_name>|<state>|<restart_type>|<description>
 *   feature[_info]|unsupported|<os>:dism:unsupported
 *   feature[_info]|unavailable|<token>
 */

#include <yuzu/plugin.hpp>
#include <yuzu/string_utils.hpp>

#include <format>
#include <string>
#include <string_view>

#include "windows_optional_features_parsers.hpp"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <chrono>
#include <cstddef>
#include <cstdio>
#include <optional>
#include <thread>
#include <unordered_set>
#include <vector>

#include "bounded_wait.hpp" // yuzu::shared::bounded_call_ex -- agents/shared/bounded_wait.hpp:168
#include "win_str.hpp"       // yuzu::win::to_wide / from_wide -- agents/shared/win_str.hpp

// ── DISM API surface, declared locally -- no <dismapi.h>, no DismApi.lib ──
//
// dismapi.h/DismApi.lib are Windows-ADK-only (P92-1 proved it absent from
// the base SDK on the-rig and every self-hosted Windows CI runner). The
// enums/structs/function-pointer types below are the local declarations
// this plugin binds DismApi.dll's exports against at runtime; the
// __has_include cross-check further below proves them layout-identical to
// the real header wherever it happens to be present at compile time.
namespace dism {

enum class LogLevel : int { Errors = 0 };
enum class PackageIdentifier : int { None = 0 };

// DismPackageFeatureState (mingw dismapi.h:95-105 / ADK header, agreed
// byte-for-byte per the-rig-dism-findings.md's layout cross-check).
enum class FeatureState : int {
    NotPresent = 0,
    UninstallPending = 1,
    Staged = 2,
    Removed = 3,
    Installed = 4,
    InstallPending = 5,
    Superseded = 6,
    PartiallyInstalled = 7,
};

// DismRestartType.
enum class RestartType : int { No = 0, Possible = 1, Required = 2 };

using Session = UINT;

// DISM_ONLINE_IMAGE.
constexpr wchar_t kOnlineImage[] = L"DISM_{53BFAE52-B167-4E2F-A258-0A37B57FF845}";

// dismapi.h wraps these in #pragma pack(push, 1) (ADK header lines
// 201-375; mingw header lines 150-319 agree) -- a naturally-aligned local
// declaration would read garbage from features[1] onward. Measured
// byte-for-byte on the-rig: sizeof(Feature)=12, sizeof(FeatureInfo)=44,
// sizeof(String)=8 (x64, the only Windows target this project builds).
#pragma pack(push, 1)
struct String {
    PCWSTR Value;
};
struct CustomProperty {
    PCWSTR Name;
    PCWSTR Value;
    PCWSTR Path;
};
struct Feature {
    PCWSTR FeatureName;
    FeatureState State;
};
struct FeatureInfo {
    PCWSTR FeatureName;
    FeatureState State;
    PCWSTR DisplayName;
    PCWSTR Description;
    RestartType RestartRequired;
    CustomProperty* Custom;
    UINT CustomCount;
};
#pragma pack(pop)

static_assert(sizeof(Feature) == 12, "DismFeature is pack(1) on x64 -- see the-rig-dism-findings.md");
static_assert(sizeof(FeatureInfo) == 44,
             "DismFeatureInfo is pack(1) on x64 -- see the-rig-dism-findings.md");
static_assert(sizeof(String) == 8, "DismString is pack(1) on x64 -- see the-rig-dism-findings.md");

// Function-pointer types for exactly the eight exports this plugin resolves
// (signatures per the-rig-dism-findings.md / mingw dismapi.h:323-346). No
// other DismXxx export is ever GetProcAddress'd -- grep-provable, and the
// only surface a future enable/disable/add/commit call could use.
using DismInitializeFn = HRESULT(WINAPI*)(LogLevel, PCWSTR, PCWSTR);
using DismShutdownFn = HRESULT(WINAPI*)();
using DismOpenSessionFn = HRESULT(WINAPI*)(PCWSTR, PCWSTR, PCWSTR, Session*);
using DismCloseSessionFn = HRESULT(WINAPI*)(Session);
using DismGetFeaturesFn = HRESULT(WINAPI*)(Session, PCWSTR, PackageIdentifier, Feature**, UINT*);
using DismGetFeatureInfoFn =
    HRESULT(WINAPI*)(Session, PCWSTR, PCWSTR, PackageIdentifier, FeatureInfo**);
using DismGetLastErrorMessageFn = HRESULT(WINAPI*)(String**);
using DismDeleteFn = HRESULT(WINAPI*)(void*);

struct Api {
    DismInitializeFn Initialize = nullptr;
    DismShutdownFn Shutdown = nullptr;
    DismOpenSessionFn OpenSession = nullptr;
    DismCloseSessionFn CloseSession = nullptr;
    DismGetFeaturesFn GetFeatures = nullptr;
    DismGetFeatureInfoFn GetFeatureInfo = nullptr;
    DismGetLastErrorMessageFn GetLastErrorMessage = nullptr;
    DismDeleteFn Delete = nullptr;

    [[nodiscard]] bool complete() const noexcept {
        return Initialize && Shutdown && OpenSession && CloseSession && GetFeatures &&
               GetFeatureInfo && GetLastErrorMessage && Delete;
    }
};

/// Resolved once, for the process's lifetime (function-local static --
/// std::call_once is not needed, statics with dynamic init are themselves
/// thread-safe since C++11). LOAD_LIBRARY_SEARCH_SYSTEM32 pins resolution
/// to %SystemRoot%\System32: DismApi.dll is not a KnownDLL, so a bare
/// LoadLibraryW would resolve through the normal search order and is
/// hijackable by a same-named DLL earlier on PATH or in the current
/// directory. NEVER FreeLibrary'd: an abandoned/timed-out DISM worker may
/// still be executing inside the DLL when the caller gives up on it (the
/// slot protocol below), and unloading the module out from under a live
/// call would fault the process rather than just leaking a handle.
[[nodiscard]] inline const Api& api() noexcept {
    static const Api resolved = [] {
        Api a;
        HMODULE m = ::LoadLibraryExW(L"DismApi.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (!m)
            return a;
        a.Initialize = reinterpret_cast<DismInitializeFn>(::GetProcAddress(m, "DismInitialize"));
        a.Shutdown = reinterpret_cast<DismShutdownFn>(::GetProcAddress(m, "DismShutdown"));
        a.OpenSession = reinterpret_cast<DismOpenSessionFn>(::GetProcAddress(m, "DismOpenSession"));
        a.CloseSession =
            reinterpret_cast<DismCloseSessionFn>(::GetProcAddress(m, "DismCloseSession"));
        a.GetFeatures = reinterpret_cast<DismGetFeaturesFn>(::GetProcAddress(m, "DismGetFeatures"));
        a.GetFeatureInfo =
            reinterpret_cast<DismGetFeatureInfoFn>(::GetProcAddress(m, "DismGetFeatureInfo"));
        a.GetLastErrorMessage = reinterpret_cast<DismGetLastErrorMessageFn>(
            ::GetProcAddress(m, "DismGetLastErrorMessage"));
        a.Delete = reinterpret_cast<DismDeleteFn>(::GetProcAddress(m, "DismDelete"));
        return a;
    }();
    return resolved;
}

// The one DISMAPI_E_* value this plugin branches on by name (value per
// the-rig-dism-findings.md / mingw dismapi.h:359-375) -- every other
// failing HRESULT is reported generically via its stage. E_ACCESSDENIED
// itself comes from <winerror.h> via <windows.h>.
constexpr HRESULT kDismUnknownFeature = 0x800F080C; // DISMAPI_E_UNKNOWN_FEATURE

} // namespace dism

// Layout cross-check against the real header, wherever it happens to be
// present at compile time (mingw on the dev Mac; the ADK on the-rig; absent
// entirely on a contract-locked CI runner, where this whole block compiles
// out). Proves the local declarations above are not just size-correct in
// isolation but field-offset-identical to the header this DLL was actually
// built against.
#if defined(__has_include)
#if __has_include(<dismapi.h>)
#include <dismapi.h> // after <windows.h>; mingw on the dev Mac, ADK on the-rig
static_assert(sizeof(dism::Feature) == sizeof(::DismFeature));
static_assert(sizeof(dism::FeatureInfo) == sizeof(::DismFeatureInfo));
static_assert(offsetof(dism::FeatureInfo, CustomCount) ==
             offsetof(::DismFeatureInfo, CustomPropertyCount));
static_assert(offsetof(dism::FeatureInfo, RestartRequired) ==
             offsetof(::DismFeatureInfo, RestartRequired));
static_assert(static_cast<int>(dism::FeatureState::PartiallyInstalled) ==
             DismStatePartiallyInstalled);
#pragma message("windows_optional_features: dismapi.h layout cross-check compiled")
#endif
#endif

#endif // _WIN32

namespace {

#ifdef _WIN32

// Per-call timeout: P92-1 measured DismGetFeatures at ~4058.7ms for 137
// features on the-rig, two orders of magnitude slower than every other
// call in the session lifecycle. 4x that (~16.2s), rounded up, comfortably
// clears the 15s floor the findings recommend.
constexpr auto kDismTimeout = std::chrono::milliseconds{17000};

// Single owner of the busy/abandoned/timed-out slot (peer H2). Every DISM
// call in this plugin runs through it -- see try_acquire()'s three-way
// result and DismSlot's own doc comment in windows_optional_features_parsers.hpp.
yuzu::wof::DismSlot g_dism_slot;

// Constructed FIRST inside the bounded lambda, so it is destroyed LAST (C++
// destroys locals in reverse construction order) -- after DismSessionGuard
// has already run DismCloseSession/DismShutdown. release() therefore always
// runs on the WORKER thread, only after DISM teardown has actually
// completed, never before.
struct SlotRelease {
    ~SlotRelease() { g_dism_slot.release(); }
};

/// File-private RAII: DismInitialize -> DismOpenSession(DISM_ONLINE_IMAGE)
/// in the constructor, DismCloseSession (if opened) then DismShutdown (if
/// initialized) in the destructor -- every early return inside the bounded
/// lambda releases through this guard. Constructed only after api().
/// complete() is true (checked by the caller before this guard exists).
struct DismSessionGuard {
    bool initialized = false;
    bool opened = false;
    dism::Session session = 0;
    HRESULT first_failure = S_OK;
    std::string_view failed_stage;

    explicit DismSessionGuard(const dism::Api& api_table) noexcept : api_{api_table} {
        // DISM reference-counts Initialize/Shutdown pairs: a second
        // Initialize returns S_FALSE (not a hard error) per the-rig's
        // measured error-path capture, so FAILED() alone is the right test
        // -- S_OK and S_FALSE both mean the API is usable.
        HRESULT hr = api_.Initialize(dism::LogLevel::Errors, nullptr, nullptr);
        if (FAILED(hr)) {
            first_failure = hr;
            failed_stage = "initialize";
            return;
        }
        initialized = true;

        hr = api_.OpenSession(dism::kOnlineImage, nullptr, nullptr, &session);
        if (FAILED(hr)) {
            first_failure = hr;
            failed_stage = "open_session";
            return;
        }
        opened = true;
    }

    DismSessionGuard(const DismSessionGuard&) = delete;
    DismSessionGuard& operator=(const DismSessionGuard&) = delete;

    ~DismSessionGuard() {
        if (opened)
            api_.CloseSession(session);
        if (initialized)
            api_.Shutdown();
    }

private:
    const dism::Api& api_;
};

std::string dism_last_error_text(const dism::Api& api_table) {
    dism::String* msg = nullptr;
    if (FAILED(api_table.GetLastErrorMessage(&msg)) || !msg || !msg->Value)
        return {};
    std::string text = yuzu::win::from_wide(msg->Value);
    api_table.Delete(msg);
    return text;
}

std::string format_hr_reason(HRESULT hr, const dism::Api& api_table) {
    std::string reason = std::format("hr=0x{:08X}", static_cast<unsigned long>(hr));
    if (auto text = dism_last_error_text(api_table); !text.empty()) {
        reason += ' ';
        reason += text;
    }
    return reason;
}

struct DismOutcome {
    enum class Kind {
        Ok,
        ApiUnavailable,
        InitializeFailed,
        OpenSessionFailed,
        GetFeaturesFailed,
        GetFeatureInfoFailed,
        FeatureNotFound,
        AccessDenied,
        Exception,
    } kind = Kind::Ok;
    std::vector<std::string> rows;
    std::string reason;
};

/// Runs the whole init->enumerate->shutdown sequence for `list`. Executed
/// entirely inside ONE bounded_call_ex lambda by do_windows_list() below --
/// this function IS that lambda's body, factored out for readability.
DismOutcome run_dism_list(const std::optional<std::unordered_set<yuzu::wof::FeatureState>>& filter) {
    try {
        SlotRelease slot_release; // constructed FIRST -- destroyed LAST
        const auto& api_table = dism::api();
        DismSessionGuard guard(api_table); // constructed SECOND -- destroyed FIRST
        if (!guard.opened) {
            const auto reason = format_hr_reason(guard.first_failure, api_table);
            if (guard.first_failure == E_ACCESSDENIED)
                return {DismOutcome::Kind::AccessDenied, {}, reason};
            return {guard.failed_stage == "initialize" ? DismOutcome::Kind::InitializeFailed
                                                        : DismOutcome::Kind::OpenSessionFailed,
                    {},
                    reason};
        }

        dism::Feature* features = nullptr;
        UINT count = 0;
        const HRESULT hr =
            api_table.GetFeatures(guard.session, nullptr, dism::PackageIdentifier::None, &features, &count);
        if (FAILED(hr)) {
            const auto reason = format_hr_reason(hr, api_table);
            if (hr == E_ACCESSDENIED)
                return {DismOutcome::Kind::AccessDenied, {}, reason};
            return {DismOutcome::Kind::GetFeaturesFailed, {}, reason};
        }

        std::vector<std::string> rows;
        rows.reserve(count);
        for (UINT i = 0; i < count; ++i) {
            const auto state = yuzu::wof::state_from_dism(static_cast<int>(features[i].State));
            if (filter && !filter->contains(state))
                continue;
            std::string name =
                features[i].FeatureName ? yuzu::win::from_wide(features[i].FeatureName) : std::string{};
            rows.push_back(yuzu::wof::format_feature_row(name, state, yuzu::wof::pending_restart(state)));
        }
        api_table.Delete(features);
        return {DismOutcome::Kind::Ok, std::move(rows), {}};
    } catch (...) {
        return {DismOutcome::Kind::Exception, {}, "unhandled exception inside the bounded DISM call"};
    }
}

/// Same shape as run_dism_list() for `info`: init->OpenSession->
/// GetFeatureInfo->shutdown, entirely inside one bounded lambda. `name` is
/// already validated (validate_feature_name) by the caller.
DismOutcome run_dism_info(const std::string& name) {
    try {
        SlotRelease slot_release; // constructed FIRST -- destroyed LAST
        const auto& api_table = dism::api();
        DismSessionGuard guard(api_table); // constructed SECOND -- destroyed FIRST
        if (!guard.opened) {
            const auto reason = format_hr_reason(guard.first_failure, api_table);
            if (guard.first_failure == E_ACCESSDENIED)
                return {DismOutcome::Kind::AccessDenied, {}, reason};
            return {guard.failed_stage == "initialize" ? DismOutcome::Kind::InitializeFailed
                                                        : DismOutcome::Kind::OpenSessionFailed,
                    {},
                    reason};
        }

        const std::wstring wide_name = yuzu::win::to_wide(name);
        dism::FeatureInfo* info = nullptr;
        const HRESULT hr = api_table.GetFeatureInfo(guard.session, wide_name.c_str(), nullptr,
                                                     dism::PackageIdentifier::None, &info);
        if (FAILED(hr)) {
            const auto reason = format_hr_reason(hr, api_table);
            if (hr == dism::kDismUnknownFeature)
                return {DismOutcome::Kind::FeatureNotFound, {}, reason};
            if (hr == E_ACCESSDENIED)
                return {DismOutcome::Kind::AccessDenied, {}, reason};
            return {DismOutcome::Kind::GetFeatureInfoFailed, {}, reason};
        }

        const auto state = yuzu::wof::state_from_dism(static_cast<int>(info->State));
        std::string display_name =
            info->DisplayName ? yuzu::win::from_wide(info->DisplayName) : std::string{};
        std::string description =
            info->Description ? yuzu::win::from_wide(info->Description) : std::string{};
        std::string row = yuzu::wof::format_feature_info_row(
            name, display_name, state, static_cast<int>(info->RestartRequired), description);
        api_table.Delete(info);
        return {DismOutcome::Kind::Ok, {std::move(row)}, {}};
    } catch (...) {
        return {DismOutcome::Kind::Exception, {}, "unhandled exception inside the bounded DISM call"};
    }
}

int report_dism_outcome(yuzu::CommandContext& ctx, std::string_view action,
                        const DismOutcome& outcome) {
    switch (outcome.kind) {
    case DismOutcome::Kind::Ok:
        for (const auto& row : outcome.rows)
            ctx.write_output(row);
        return 0;
    case DismOutcome::Kind::ApiUnavailable:
        ctx.write_output(yuzu::wof::format_unavailable_row(action, "windows:dism:api_unavailable"));
        ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              outcome.reason);
        return 0;
    case DismOutcome::Kind::InitializeFailed:
        ctx.write_output(yuzu::wof::format_unavailable_row(action, "windows:dism:initialize_failed"));
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              outcome.reason);
        return 0;
    case DismOutcome::Kind::OpenSessionFailed:
        ctx.write_output(
            yuzu::wof::format_unavailable_row(action, "windows:dism:open_session_failed"));
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              outcome.reason);
        return 0;
    case DismOutcome::Kind::GetFeaturesFailed:
        ctx.write_output(
            yuzu::wof::format_unavailable_row(action, "windows:dism:get_features_failed"));
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              outcome.reason);
        return 0;
    case DismOutcome::Kind::GetFeatureInfoFailed:
        ctx.write_output(
            yuzu::wof::format_unavailable_row(action, "windows:dism:get_feature_info_failed"));
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              outcome.reason);
        return 0;
    case DismOutcome::Kind::FeatureNotFound:
        ctx.write_output(yuzu::wof::format_unavailable_row(action, "windows:dism:feature_not_found"));
        ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_FULL,
                              outcome.reason);
        return 0;
    case DismOutcome::Kind::AccessDenied:
        ctx.write_output(yuzu::wof::format_unavailable_row(action, "windows:dism:access_denied"));
        ctx.set_result_status(YUZU_RESULT_STATUS_PERMISSION_DENIED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              outcome.reason);
        return 0;
    case DismOutcome::Kind::Exception:
        ctx.write_output(yuzu::wof::format_unavailable_row(action, "windows:dism:exception"));
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              outcome.reason);
        return 0;
    }
    return 0;
}

/// SLOT PROTOCOL (peer H2, resolved): try_acquire() runs BEFORE the bounded
/// call, on the DISPATCHING thread. busy/abandoned report and return
/// without ever calling DismInitialize. On `acquired`, the whole DISM
/// sequence runs inside ONE bounded_call_ex -- Completed reports the
/// DismOutcome; TimedOut marks the slot timed-out (never clears in_use:
/// the worker thread that is still running fn() owns that); Rejected means
/// fn() never ran at all, so the calling thread performs the ONE
/// caller-side release the protocol allows.
int do_windows_list(yuzu::CommandContext& ctx, yuzu::Params params) {
    const auto& api_table = dism::api();
    if (!api_table.complete()) {
        ctx.write_output(yuzu::wof::format_unavailable_row("list", "windows:dism:api_unavailable"));
        ctx.set_result_status(
            YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
            "DismApi.dll or one of its eight required exports could not be resolved from System32");
        return 0;
    }

    const auto acquire = g_dism_slot.try_acquire();
    if (acquire == yuzu::wof::DismSlot::Acquire::busy) {
        ctx.write_output(yuzu::wof::format_unavailable_row("list", "windows:dism:busy"));
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              "a DISM call is already in progress on this agent");
        return 0;
    }
    if (acquire == yuzu::wof::DismSlot::Acquire::abandoned) {
        ctx.write_output(yuzu::wof::format_unavailable_row("list", "windows:dism:abandoned"));
        ctx.set_result_status(
            YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
            "a previous DISM call timed out and its worker has not returned; the DISM API is "
            "still held by that worker; recovers when it returns, otherwise a service restart "
            "clears it");
        return 0;
    }

    std::optional<std::unordered_set<yuzu::wof::FeatureState>> filter;
    if (const auto state_param = params.get("state"); !state_param.empty())
        filter = yuzu::wof::parse_state_filter(state_param);

    auto bounded =
        yuzu::shared::bounded_call_ex(kDismTimeout, [filter]() { return run_dism_list(filter); });

    if (bounded.status == yuzu::shared::BoundedCallStatus::TimedOut) {
        g_dism_slot.mark_timed_out(); // DISPATCHING thread; never clears in_use
        ctx.write_output(yuzu::wof::format_unavailable_row("list", "windows:dism:timeout"));
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              "DismGetFeatures did not return within the bounded timeout");
        return 0;
    }
    if (bounded.status == yuzu::shared::BoundedCallStatus::Rejected) {
        // fn() never ran -- no worker owns the slot. The ONE caller-side
        // release this protocol allows (see DismSlot's own doc comment).
        g_dism_slot.release();
        ctx.write_output(yuzu::wof::format_unavailable_row("list", "windows:dism:busy"));
        ctx.set_result_status(
            YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
            "the bounded-call outstanding-call ceiling rejected this DISM call before it started");
        return 0;
    }
    return report_dism_outcome(ctx, "list", *bounded.value);
}

int do_windows_info(yuzu::CommandContext& ctx, const std::string& name) {
    const auto& api_table = dism::api();
    if (!api_table.complete()) {
        ctx.write_output(yuzu::wof::format_unavailable_row("info", "windows:dism:api_unavailable"));
        ctx.set_result_status(
            YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
            "DismApi.dll or one of its eight required exports could not be resolved from System32");
        return 0;
    }

    const auto acquire = g_dism_slot.try_acquire();
    if (acquire == yuzu::wof::DismSlot::Acquire::busy) {
        ctx.write_output(yuzu::wof::format_unavailable_row("info", "windows:dism:busy"));
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              "a DISM call is already in progress on this agent");
        return 0;
    }
    if (acquire == yuzu::wof::DismSlot::Acquire::abandoned) {
        ctx.write_output(yuzu::wof::format_unavailable_row("info", "windows:dism:abandoned"));
        ctx.set_result_status(
            YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
            "a previous DISM call timed out and its worker has not returned; the DISM API is "
            "still held by that worker; recovers when it returns, otherwise a service restart "
            "clears it");
        return 0;
    }

    auto bounded =
        yuzu::shared::bounded_call_ex(kDismTimeout, [name]() { return run_dism_info(name); });

    if (bounded.status == yuzu::shared::BoundedCallStatus::TimedOut) {
        g_dism_slot.mark_timed_out(); // DISPATCHING thread; never clears in_use
        ctx.write_output(yuzu::wof::format_unavailable_row("info", "windows:dism:timeout"));
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              "DismGetFeatureInfo did not return within the bounded timeout");
        return 0;
    }
    if (bounded.status == yuzu::shared::BoundedCallStatus::Rejected) {
        g_dism_slot.release();
        ctx.write_output(yuzu::wof::format_unavailable_row("info", "windows:dism:busy"));
        ctx.set_result_status(
            YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
            "the bounded-call outstanding-call ceiling rejected this DISM call before it started");
        return 0;
    }
    return report_dism_outcome(ctx, "info", *bounded.value);
}

#else // !_WIN32

constexpr std::string_view kUnsupportedReason =
    "windows_optional_features is Windows-only (DISM); no Linux/macOS equivalent";

int mark_result_unsupported(yuzu::CommandContext& ctx, std::string_view action,
                            std::string_view token, std::string_view reason) {
    ctx.write_output(yuzu::wof::format_unsupported_row(action, token));
    ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL, reason);
    return 0;
}

#endif // _WIN32

int do_list(yuzu::CommandContext& ctx, yuzu::Params params) {
#ifdef _WIN32
    return do_windows_list(ctx, params);
#elif defined(__APPLE__)
    (void)params;
    return mark_result_unsupported(ctx, "list", "macos:dism:unsupported", kUnsupportedReason);
#else
    (void)params;
    return mark_result_unsupported(ctx, "list", "linux:dism:unsupported", kUnsupportedReason);
#endif
}

int do_info(yuzu::CommandContext& ctx, yuzu::Params params) {
    // Validated identically on every OS, BEFORE any platform branch: an
    // invalid feature parameter never reaches DISM (or the unsupported-row
    // path) and always costs rc 1 with no downstream call, regardless of
    // whether this OS could ever have serviced the request.
    const auto raw_feature = params.get("feature");
    auto valid = yuzu::wof::validate_feature_name(raw_feature);
    if (!valid) {
        ctx.write_output(std::format("feature_info|invalid|invalid 'feature' parameter: '{}'",
                                     yuzu::util::safe_output_field(raw_feature)));
        return 1;
    }

#ifdef _WIN32
    return do_windows_info(ctx, *valid);
#elif defined(__APPLE__)
    return mark_result_unsupported(ctx, "info", "macos:dism:unsupported", kUnsupportedReason);
#else
    return mark_result_unsupported(ctx, "info", "linux:dism:unsupported", kUnsupportedReason);
#endif
}

// ── ABI4 capability declarations (#2204) ────────────────────────────────
//
// windows: DISM API via DismOpenSession(DISM_ONLINE_IMAGE) + DismGetFeatures/
// DismGetFeatureInfo, runtime-bound (never linked against DismApi.lib) --
// rung 1, native OS interface.
// linux/macos: DISM has no equivalent on either platform.
const YuzuActionDescriptor kActionDescriptors[] = {
    {"list",
     /* linux_leg   = */
     {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr, "Windows-only: DISM has no Linux/macOS equivalent"},
     /* macos_leg   = */
     {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr, "Windows-only: DISM has no Linux/macOS equivalent"},
     /* windows_leg = */
     {YUZU_SUPPORT_SUPPORTED, 1,
      "DISM API DismOpenSession(DISM_ONLINE_IMAGE) + DismGetFeatures/DismGetFeatureInfo",
      "verified live on the-rig under NT AUTHORITY\\SYSTEM, 2026-09-08"}},
    {"info",
     /* linux_leg   = */
     {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr, "Windows-only: DISM has no Linux/macOS equivalent"},
     /* macos_leg   = */
     {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr, "Windows-only: DISM has no Linux/macOS equivalent"},
     /* windows_leg = */
     {YUZU_SUPPORT_SUPPORTED, 1,
      "DISM API DismOpenSession(DISM_ONLINE_IMAGE) + DismGetFeatures/DismGetFeatureInfo",
      "verified live on the-rig under NT AUTHORITY\\SYSTEM, 2026-09-08"}},
};

} // namespace

class WindowsOptionalFeaturesPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "windows_optional_features"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Windows optional OS feature state (enabled/disabled/pending) via the DISM API";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"list", "info", nullptr};
        return acts;
    }

    const YuzuActionDescriptor* action_descriptors() const noexcept override {
        return kActionDescriptors;
    }
    size_t action_descriptor_count() const noexcept override {
        return sizeof(kActionDescriptors) / sizeof(kActionDescriptors[0]);
    }

    yuzu::Result<void> init(yuzu::PluginContext& /*ctx*/) override { return {}; }

    /**
     * Short BOUNDED quiesce (plugin.hpp:245), mirroring power_health_plugin
     * .cpp's shutdown() pattern: wait up to 2x kDismTimeout for the DISM
     * slot to drain, then log the residue and return -- never an unbounded
     * join. On non-Windows the slot doesn't exist and there is nothing to
     * wait on.
     */
    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {
#ifdef _WIN32
        const auto deadline = std::chrono::steady_clock::now() + 2 * kDismTimeout;
        while (g_dism_slot.in_use.load(std::memory_order_relaxed) &&
               std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
        if (g_dism_slot.in_use.load(std::memory_order_relaxed)) {
            std::fprintf(stderr, "windows_optional_features: shutdown quiesce timed out with a "
                                 "DISM call still outstanding\n");
        }
#endif
    }

    int execute(yuzu::CommandContext& ctx, std::string_view action, yuzu::Params params) override {
        if (action == "list")
            return do_list(ctx, params);
        if (action == "info")
            return do_info(ctx, params);

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }
};

YUZU_PLUGIN_EXPORT(WindowsOptionalFeaturesPlugin)
