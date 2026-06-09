#pragma once

/**
 * crash_observer.hpp — fleet-wide process-crash observer (Guardian DEX, slice 1).
 *
 * Unlike an IGuard, a crash observer is NOT tied to a rule: it records ANY process
 * crashing on the host (a DEX "observation", no desired-state). It is idle-until-
 * crash — on Windows a push `EvtSubscribe` to the Application channel (Event ID
 * 1000, "Application Error"), NOT a process-exit firehose — so it costs ~nothing
 * until something actually crashes. See memory project-guardian-process-spark-slices
 * and docs/yuzu-guardian-dex-direction (the why) for the design.
 *
 * Proto-free and windows.h-free by design (mirrors guard.hpp): keeps protobuf's
 * headers and windows.h's ERROR/min/max macros out of the same TU. The
 * CrashObservation -> GuaranteedStateEvent mapping lives in the proto-aware
 * crash_event.{hpp,cpp}; the Windows EvtSubscribe collector lives in
 * crash_observer.cpp (winevt.h there, no proto).
 *
 * OS-agnostic in shape: the normalized CrashObservation + the ICrashObserver
 * interface are platform-neutral, with the collector behind make_crash_observer()
 * (Windows impl today; Linux/macOS collectors are deferred slices behind the
 * broader Guardian Linux/macOS work — off those platforms the factory returns a
 * no-op whose start() returns false, exactly like the guards).
 */

#include <yuzu/plugin.h> // YUZU_EXPORT

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace yuzu::agent {

/// How a process abnormally terminated. Normalized across OSes: on Windows `kind`
/// is "exception" and `code` the exception/exit code (e.g. 0xC0000005); on POSIX
/// (future slices) `kind` is "signal" and `code` the signal number. `symbolic` is
/// a best-effort human name ("ACCESS_VIOLATION" / "SIGSEGV"), "" when unknown.
struct CrashTermination {
    std::string kind;          ///< "exception" (Windows) | "signal" (POSIX, future)
    std::uint32_t code{0};     ///< exception/exit code or signal number
    std::string symbolic;      ///< best-effort name, or "" if not mapped
};

/// One observed process crash. OS-neutral; the platform collector fills it in.
/// `timestamp_unix` 0 = unknown (the server stamps ingest time, as for drift).
struct CrashObservation {
    std::string process_name;      ///< e.g. "notepad.exe" ("" if unparsed)
    std::uint32_t pid{0};          ///< faulting process id (0 if unknown)
    std::string image_path;        ///< full faulting-application path, or ""
    CrashTermination termination;
    std::string faulting_module;   ///< e.g. "ntdll.dll", or ""
    std::int64_t timestamp_unix{0};///< epoch seconds, 0 = unknown
    std::string platform;          ///< "windows" | "linux" | "macos"
};

/// Sink the observer calls on each observed crash. Invoked on an OS callback
/// thread (the EvtSubscribe delivery thread on Windows) — implementations must be
/// thread-safe and must not block it for long.
using CrashSink = std::function<void(const CrashObservation&)>;

/// A live fleet-wide crash subscription. start() arms the OS subscription and
/// returns true iff armed; stop() tears it down. Single-owner (non-copyable);
/// the agent owns one via unique_ptr. Virtual dtor makes that deletion correct.
class ICrashObserver {
public:
    virtual ~ICrashObserver() = default;
    /// Arm the OS subscription. `sink` is called on each observed crash (OS callback
    /// thread). `on_subscription_error` (optional) is called if the subscription fails
    /// at RUNTIME after a successful start (e.g. the EventLog channel becomes
    /// unreadable / the EventLog service restarts) — the owner uses it to mark the
    /// recorder no longer healthy, since start() returning true proves only that it
    /// armed, not that it stays live. It may fire on an OS thread and LATE (even during
    /// teardown), so it must be self-contained — capture owner-independent state (e.g.
    /// a shared atomic), never the owner by raw pointer.
    virtual bool start(CrashSink sink, std::function<void()> on_subscription_error = {}) = 0;
    virtual void stop() = 0;
};

/// Factory: the Windows EvtSubscribe collector on Windows, a no-op (start()==false)
/// elsewhere. Never null.
YUZU_EXPORT std::unique_ptr<ICrashObserver> make_crash_observer();

/// Best-effort symbolic name for a Windows NTSTATUS-shaped exception code
/// (0xC0000005 -> "ACCESS_VIOLATION", …); "" for codes not in the small map.
/// Pure + cross-platform so it is unit-testable off Windows.
YUZU_EXPORT std::string symbolic_exception_name(std::uint32_t code);

/// Parse the NAMED <EventData> fields of a Windows "Application Error" (Event ID
/// 1000) record into a normalized CrashObservation. Verified against real Win11
/// (10.0.26100) output: the manifest emits NAMED Data elements, so we look up by
/// name rather than position (robust to schema/version field reordering). Fields
/// used: AppName, ModuleName, ExceptionCode (hex), ProcessId (hex, e.g. "0x297c"),
/// AppPath. Missing names stay default. Pure + cross-platform by design so the
/// fiddly parsing is testable everywhere, even though it is only fed real data on
/// Windows.
YUZU_EXPORT CrashObservation
parse_application_error(const std::vector<std::pair<std::string, std::string>>& named_fields);

/// Extract each <Data Name='X'>value</Data> under <EventData> from a rendered
/// event XML as an ordered (name, value) list. Pure string scan (no Windows
/// types) so the whole XML -> fields -> CrashObservation chain is testable off
/// Windows against a real captured record. Handles ' and " attribute quoting and
/// self-closing/empty Data; XML entities in values are left undecoded (slice-1).
YUZU_EXPORT std::vector<std::pair<std::string, std::string>>
extract_named_data(const std::string& event_xml);

} // namespace yuzu::agent
