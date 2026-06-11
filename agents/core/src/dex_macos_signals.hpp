#pragma once

/**
 * dex_macos_signals.hpp — pure macOS DEX signal extractors.
 *
 * The macOS analogue of the Windows catalogue's per-event extractors: pure
 * functions that map a macOS diagnostic artefact (a DiagnosticReports `.ips`
 * crash/jetsam/panic report, a `.diag` resource report, or a sysctl boot time)
 * onto the OS-neutral SignalObservation shape. They emit the SAME obs_type
 * strings as the Windows catalogue where a clean equivalent exists
 * (process.crashed, process.hung, os.bugcheck, memory.exhausted,
 * os.uptime_report), so the wire mapping, server projection, and `/dex`
 * dashboard render them with zero server change — the OS-neutral-by-design
 * promise (see docs/dex-signal-catalog.md "macOS mapping").
 *
 * Proto-free AND framework-free by design (mirrors dex_signal_catalog.hpp): a
 * `.ips` is just two concatenated JSON documents and a `.diag` is plain text, so
 * these parse with nlohmann/json + string scanning and NOTHING Apple-specific.
 * That is deliberate — it lets the fiddly field extraction be unit-tested on
 * every platform (incl. MSVC) against real captured records, exactly like the
 * Windows rendered-XML extractors. The impure collection mechanism (kqueue
 * folder-watch + sysctl) lives in dex_macos_collector.cpp behind `__APPLE__`.
 *
 * PRIVACY (works-council / co-determination — see docs/dex-signal-catalog.md):
 * extractors drop user content at the edge. A crash report's full procPath,
 * parentProc, thread register state, and image paths are NEVER read — only the
 * process BASENAME, the signal/exception name, and the faulting image BASENAME.
 * What is never extracted can never be exfiltrated or mis-scoped.
 */

#include <yuzu/agent/dex_signal_catalog.hpp> // SignalObservation

#include <cstdint>
#include <optional>
#include <string>

namespace yuzu::agent::macos {

/// Parse a DiagnosticReports `.ips` report (a JSON header line followed by a
/// separate JSON body document) into a normalized observation. Returns nullopt
/// when the report's `bug_type` is not one we map to a DEX signal. Defensive:
/// a malformed body still yields a counted occurrence from the header where the
/// type is recognised, never a throw (these run off an OS watcher thread).
YUZU_EXPORT std::optional<SignalObservation> parse_ips_report(const std::string& ips_content);

/// Parse a `.diag` resource report (plain-text `Key: value` blocks — a process
/// that exceeded a CPU / wakeups / disk-write budget). Maps to the macOS-specific
/// `process.resource_limit` obs_type. nullopt when the format is unrecognised.
YUZU_EXPORT std::optional<SignalObservation> parse_diag_report(const std::string& diag_content);

/// Build the `os.uptime_report` observation (metric = uptime seconds = now -
/// boot). The cross-platform cheap scalar (Windows EventLog 6013 equivalent);
/// unprivileged on both OSes. Returns nullopt when boot_unix is not positive.
YUZU_EXPORT std::optional<SignalObservation> uptime_observation(std::int64_t boot_unix,
                                                                std::int64_t now_unix);

} // namespace yuzu::agent::macos
