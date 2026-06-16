#pragma once

/**
 * dex_signal_catalog.hpp — the DEX signal catalogue (Guardian DEX, multi-signal).
 *
 * One static table drives the whole collection surface: each entry names an
 * obs_type, the Windows Event Log (channel, provider, event IDs) that produces
 * it, a per-type rate cap, and a PURE extractor that maps the event's
 * <EventData> fields onto the uniform SignalObservation shape. Adding signal
 * #21 is one catalogue entry + one extractor + fixtures — the observer engine,
 * wire mapping, server projection, and dashboard are all generic over this.
 *
 * Uniform observation shape (mirrored by detail_json on the wire and the
 * guardian_observations projection server-side):
 *   subject    — the failing entity (app, service, printer, update title, SSID…)
 *   reason     — machine-ish failure code ("0xC0000005", "0x80070643", "7031"…)
 *   symbolic   — best-effort human name for reason ("ACCESS_VIOLATION"…)
 *   component  — secondary entity (faulting module, NIC, conflicting MAC…)
 *   metric     — numeric payload where the signal IS a number (boot ms); 0 = none
 *
 * PRIVACY (works-council / co-determination — see docs/dex-signal-catalog.md):
 * extractors MUST drop user content at the edge, before anything leaves the
 * device: DNS queried names (browsing behavior), print document names (user
 * content), profile usernames. What is never extracted can never be exfiltrated,
 * subpoenaed, or mis-scoped.
 *
 * Proto-free AND windows.h-free by design (the crash_observer rationale): this
 * header is included by the winevt.h engine TU (dex_observer.cpp) and by the
 * proto TU (dex_event.cpp), so it must poison neither. Extractors are pure and
 * unit-tested off Windows against captured/synthetic rendered-XML fixtures.
 */

#include <yuzu/plugin.h> // YUZU_EXPORT

#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace yuzu::agent {

/// Ordered (name, value) list of <Data> elements under <EventData>. Classic
/// providers emit UNNAMED positional Data (name == ""); manifest providers emit
/// named Data. Extractors use named lookup with positional fallback so both
/// shapes parse.
using EventFields = std::vector<std::pair<std::string, std::string>>;

/// One observed DEX signal, normalized across signal types and (in shape) across
/// OSes. The platform collector + catalogue extractor fill it in; dex_event maps
/// it onto the GuaranteedStateEvent wire (rule_id = __observation__ sentinel).
struct SignalObservation {
    std::string obs_type;       ///< e.g. "process.crashed", "os.boot" — the taxonomy key
    std::string subject;        ///< the failing entity ("" if unparsed)
    std::string reason;         ///< failure code, or "" when the type has none
    std::string symbolic;       ///< human name for reason, "" if not mapped
    std::string component;      ///< secondary entity (module/NIC/MAC), or ""
    double metric{0.0};         ///< numeric payload (boot ms); 0 = none
    std::uint32_t pid{0};       ///< process id where meaningful (crash/hang), else 0
    std::string kind;           ///< "exception" | "hang" | "signal" | "unit" | "" — crash/failure-family detail
    std::string sentence;       ///< human-readable detected_value line
    std::int64_t timestamp_unix{0}; ///< epoch seconds, 0 = unknown (server stamps)
    std::string platform;       ///< "windows" | "linux" | "macos"
};

/// One catalogue entry. `event_ids` empty = any id from this provider (WHEA);
/// `max_level` 0 = any, else only Level 1..max_level (kernel-side filtered in the
/// subscription query AND re-checked in extract_signal so the filter is pure-
/// testable). `max_per_hour` is the per-type ingest cap the engine enforces —
/// storm types (WHEA corrected errors, failing-disk retries, Wi-Fi flaps) must
/// not flood the wire (be kind to the network).
struct SignalSpec {
    const char* obs_type;
    const char* channel;        ///< "Application" | "System" | "Microsoft-…/Operational"
    const char* provider;       ///< exact <Provider Name=…> match
    std::vector<int> event_ids; ///< empty = any
    int max_level{0};           ///< 0 = any; else Level must be 1..max_level
    int max_per_hour{60};
    SignalObservation (*extract)(const EventFields& fields, int event_id);
};

/// The catalogue — 103 obs_types (some backed by two provider spellings, so the
/// spec count is slightly higher). Static, immutable, no registration API:
/// signals are code, reviewed like code.
YUZU_EXPORT const std::vector<SignalSpec>& dex_signal_catalog();

/// Distinct channels the catalogue subscribes to (engine arms one EvtSubscribe
/// per channel for per-channel failure isolation).
YUZU_EXPORT std::vector<std::string> dex_channels();

/// The structured <QueryList> XML for one channel — one <Select> per spec, so no
/// single XPath approaches winevt's 32-expression limit. Pure + testable.
YUZU_EXPORT std::string dex_channel_query(const std::string& channel);

/// Catalogue lookup: (channel, provider, event_id) → spec, or nullptr when the
/// event matches no entry (defensive — the kernel-side query should pre-filter).
YUZU_EXPORT const SignalSpec* find_signal_spec(const std::string& channel,
                                               const std::string& provider, int event_id);

/// The single pure entry the engine calls per delivered event: look up the spec,
/// enforce the level filter, run the extractor, stamp obs_type/platform.
/// nullopt = not a catalogued signal (dropped silently).
YUZU_EXPORT std::optional<SignalObservation>
extract_signal(const std::string& channel, const std::string& provider, int event_id, int level,
               const EventFields& fields);

/// Best-effort symbolic name for a Windows NTSTATUS-shaped exception code
/// (0xC0000005 -> "ACCESS_VIOLATION", …); "" for codes not in the small map.
YUZU_EXPORT std::string symbolic_exception_name(std::uint32_t code);

} // namespace yuzu::agent
