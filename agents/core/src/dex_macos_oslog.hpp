#pragma once

/**
 * dex_macos_oslog.hpp — pure macOS unified-log (OSLog) DEX signal extractors.
 *
 * The third macOS collection mechanism (after the DiagnosticReports folder-watch
 * and the sysctl scalar): the unified log. On macOS the "an event happened"
 * experience signals — a launchd service dying, Wi-Fi dropping, a software update
 * failing, a print job failing — land in the unified log, not in report files.
 * The collector polls `/usr/bin/log show --start <checkpoint> --predicate <p>
 * --style ndjson` on a timer (NOT a continuous `log stream` child, NOT the
 * Objective-C OSLogStore framework — keeps the agent pure C++ and NFR-friendly);
 * each output line is one JSON log event and this file maps it onto the
 * OS-neutral SignalObservation shape, reusing the SAME obs_type strings as the
 * Windows catalogue (`service.crashed`, …) → zero server/dashboard change.
 *
 * Pure + framework-free (mirrors dex_macos_signals.hpp): an ndjson log line is
 * just JSON, so the extraction is unit-tested on every host (incl. MSVC) against
 * REAL captured records. The impure mechanism (popen of `log show`, checkpoint
 * dedup) lives in dex_macos_collector.cpp behind `__APPLE__`.
 *
 * SEMANTIC NOTE (the honest fidelity gap vs Windows): launchd logs EVERY service
 * exit, not only unexpected ones (Windows SCM 7031/7034 fire only on unexpected
 * termination). So `parse_oslog_event` filters to ABNORMAL exits — non-zero exit
 * codes and crash signals (SIGSEGV/SIGABRT/…) — and drops clean exits (exit 0)
 * and intentional stops (SIGTERM/SIGKILL/SIGINT/SIGHUP). It is therefore broader
 * than the Windows equivalent (it also catches abnormal exits of on-demand jobs);
 * a crash-looping service still dominates and is the DEX-relevant fact.
 */

#include <yuzu/plugin.h>                     // YUZU_EXPORT
#include <yuzu/agent/dex_signal_catalog.hpp> // SignalObservation

#include <optional>
#include <string>

namespace yuzu::agent::macos {

/// Parse one ndjson line emitted by `log show/stream --style ndjson` into a
/// normalized observation. nullopt = not a DEX signal (an event we don't map, or
/// a benign one we deliberately drop — clean exit, intentional stop). Defensive:
/// malformed JSON / missing fields degrade to nullopt, never a throw.
YUZU_EXPORT std::optional<SignalObservation> parse_oslog_event(const std::string& ndjson_line);

/// The compound `--predicate` the collector polls the unified log with — the
/// union of every event class parse_oslog_event understands, kept in sync with it
/// so logd does the filtering server-side (the agent never sees the firehose).
YUZU_EXPORT std::string oslog_predicate();

} // namespace yuzu::agent::macos
