#pragma once

/**
 * dex_observer.hpp — fleet-wide DEX signal observer (Guardian DEX, multi-signal).
 *
 * Generalizes the slice-1 crash recorder: NOT tied to any rule, it records every
 * catalogued reliability/experience signal on the host (crash, hang, service
 * failure, bugcheck, boot duration, …) as a ruleless DEX "observation". On
 * Windows it arms one push `EvtSubscribe` per catalogue channel (Application,
 * System, Diagnostics-Performance, WLAN-AutoConfig, PrintService) with a
 * kernel-side filtered QueryList — idle-until-signal, never a firehose. The
 * signal set, field extraction, privacy minimisations, and per-type rate caps
 * all live in the catalogue (dex_signal_catalog.{hpp,cpp}); this engine is
 * generic over it.
 *
 * Proto-free and windows.h-free by design (mirrors guard.hpp): keeps protobuf's
 * headers and windows.h's ERROR/min/max macros out of the same TU. The
 * SignalObservation -> GuaranteedStateEvent mapping lives in the proto-aware
 * dex_event.{hpp,cpp}; the Windows EvtSubscribe engine lives in dex_observer.cpp
 * (winevt.h there, no proto).
 *
 * OS-agnostic in shape: SignalObservation + ISignalObserver are platform-
 * neutral, with the collector behind make_dex_observer() (Windows impl today;
 * Linux/macOS collectors are deferred slices — off those platforms the factory
 * returns a no-op whose start() returns false, exactly like the guards).
 */

#include <yuzu/plugin.h> // YUZU_EXPORT
#include <yuzu/agent/dex_signal_catalog.hpp> // SignalObservation, EventFields

#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace yuzu::agent {

/// Sink the observer calls on each observed signal. Invoked on an OS callback
/// thread (the EvtSubscribe delivery thread on Windows) — implementations must be
/// thread-safe and must not block it for long.
using SignalSink = std::function<void(const SignalObservation&)>;

/// A live fleet-wide signal subscription. start() arms the OS subscriptions and
/// returns true iff at least one channel armed; stop() tears them down.
/// Single-owner (non-copyable); the agent owns one via unique_ptr.
class ISignalObserver {
public:
    virtual ~ISignalObserver() = default;
    /// Arm the OS subscriptions. `sink` is called on each observed signal (OS
    /// callback thread). `on_subscription_error` (optional) is called if ANY
    /// channel subscription fails at RUNTIME after a successful start (EventLog
    /// service restart / channel ACL change) — the owner uses it to mark the
    /// recorder no longer fully healthy, since start() returning true proves only
    /// that it armed, not that it stays live. It may fire on an OS thread and
    /// LATE (even during teardown), so it must be self-contained — capture
    /// owner-independent state (e.g. a shared atomic), never the owner by raw
    /// pointer.
    virtual bool start(SignalSink sink, std::function<void()> on_subscription_error = {}) = 0;
    virtual void stop() = 0;
    /// Channels successfully armed by start() (0 before start / off-Windows).
    /// Diagnostic only — a partially-armed observer still collects from the
    /// channels that did arm.
    virtual int armed_channels() const = 0;
};

/// Factory: the Windows EvtSubscribe engine on Windows, a no-op (start()==false)
/// elsewhere. Never null.
YUZU_EXPORT std::unique_ptr<ISignalObserver> make_dex_observer();

/// Extract each <Data Name='X'>value</Data> under <EventData> from a rendered
/// event XML as an ordered (name, value) list. Pure string scan (no Windows
/// types) so the whole XML -> fields -> SignalObservation chain is testable off
/// Windows against real captured records. Handles ' and " attribute quoting and
/// self-closing/empty Data; XML entities in values are left undecoded (slice-1).
YUZU_EXPORT EventFields extract_named_data(const std::string& event_xml);

/// The <System> block facts the catalogue lookup keys on. Parsed by the same
/// defensive pure string scan as extract_named_data.
struct EventSystemFields {
    std::string provider; ///< <Provider Name='…'>
    int event_id{0};      ///< <EventID>n</EventID> (Qualifiers attr tolerated)
    int level{0};         ///< <Level>n</Level> (0 when absent)
    std::string channel;  ///< <Channel>…</Channel>
};

/// Parse provider/event-id/level/channel out of a rendered event XML. Pure +
/// cross-platform; missing elements stay default (never throws).
YUZU_EXPORT EventSystemFields extract_system_fields(const std::string& event_xml);

} // namespace yuzu::agent
