#pragma once

/**
 * dex_linux_journal.hpp — pure journald-record classification for Linux DEX.
 *
 * The Linux DEX collector (dex_linux_collector.cpp) reads the systemd journal via
 * a slow-cadence `journalctl --after-cursor … -o json` shell-out (the macOS
 * `log show` playbook — the DEX family reads logs via the OS log CLI), and feeds
 * each line through the PURE classifier here. journald reliability events map onto
 * EXISTING obs_types, so a Linux server lights up the same `/dex` buckets as
 * Windows/macOS with ZERO server change:
 *   - systemd unit entered failed state (MESSAGE_ID SD_MESSAGE_UNIT_FAILED) → service.crashed
 *   - systemd-coredump entry           (MESSAGE_ID SD_MESSAGE_COREDUMP)     → process.crashed
 *   - kernel OOM-killer                 (_TRANSPORT=kernel + the OOM text)  → memory.exhausted
 *
 * journalctl shell-out, not sd-journal, deliberately: no libsystemd build dep (the
 * collector stays buildable on musl/Alpine like the PR3 /proc source), no coupling
 * to the systemd_guard feature-gate, and `journalctl -o json` → a pure classifier
 * keeps the off-Linux-tested pattern (this file). MESSAGE_ID matching gives one
 * canonical entry per failure (so no multi-line de-dup needed); a flapping unit is
 * bounded by the collector's per-(type,subject) debounce, not here.
 *
 * PRIVACY (works-council / co-determination): only safe fields leave the device —
 * the killed/failed process comm, the unit name, and the signal/result code. The
 * raw MESSAGE is never shipped (the kernel OOM line is read only to extract the
 * killed comm). Never throws (the JSON parse is exception-free).
 */

#include <yuzu/plugin.h>                     // YUZU_EXPORT
#include <yuzu/agent/dex_signal_catalog.hpp> // SignalObservation

#include <optional>
#include <string>
#include <string_view>

namespace yuzu::agent::lnx {

// Stable systemd journal MESSAGE_IDs (from <systemd/sd-messages.h>) the collector
// filters the journal on and the classifier keys off.
inline constexpr std::string_view kMsgIdCoredump = "fc2e22bc6ee647b6b90729ab34a250b1"; // SD_MESSAGE_COREDUMP
inline constexpr std::string_view kMsgIdUnitFailed =
    "be02cf6855d2428ba40df7e9d022f03d"; // SD_MESSAGE_UNIT_FAILED (unit entered failed state)
// The "<unit>: Failed with result 'X'." message — what a simple service failure
// actually logs (carries UNIT + UNIT_RESULT); confirmed against a live specimen, and
// the case SD_MESSAGE_UNIT_FAILED alone misses. Both are matched for service.crashed.
inline constexpr std::string_view kMsgIdUnitResult = "d9b373ed55a64feb8242e02dbe79a49c";

/// One classified `journalctl -o json` line: its `__CURSOR` (the poll checkpoint —
/// always extracted, even when the line is not a catalogued signal, so the cursor
/// advances past noise) and the DEX observation it maps to (nullopt = not a
/// reliability signal we record).
struct JournalLine {
    std::string cursor;                   ///< __CURSOR, "" if absent/unparsable
    std::optional<SignalObservation> obs; ///< the mapped signal, or nullopt
};

/// PURE: parse + classify one `journalctl -o json` line. Extracts ONLY safe fields
/// (process comm / unit name / signal / result code); never ships the raw MESSAGE.
/// Never throws. Tested off-Linux against captured journalctl fixtures.
YUZU_EXPORT JournalLine parse_journal_line(std::string_view json_line);

/// PURE: best-effort signal name for a `COREDUMP_SIGNAL` number ("11" → "SIGSEGV");
/// "signal N" when unmapped. Exposed for tests.
YUZU_EXPORT std::string crash_signal_name(int signo);

} // namespace yuzu::agent::lnx
