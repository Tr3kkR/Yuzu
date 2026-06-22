#pragma once

/**
 * tar_aggregator.hpp -- Rollup aggregation and retention for TAR warehouse
 *
 * Aggregates live table data into hourly/daily/monthly summary tables.
 * Each rollup is idempotent: tracks last-processed timestamp in tar_config
 * and only processes new data on each invocation.
 */

#include "tar_db.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::tar {

// ── configure-time pattern-array validation caps (#541) ───────────────────────
//
// `redaction_patterns` and `process_stabilization_exclusions` feed should_redact,
// which is O(patterns × cmdline_length) per process per fast-collect cycle, so an
// unbounded array or pathologically-long element degrades the collector. The
// min-core-length floor guards a separate footgun: a 1–2 char bare substring
// (e.g. "a") matches almost every process name, silently dropping 70-90% of
// process events with no warning.
inline constexpr std::size_t kMaxPatternArrayElements = 256;
inline constexpr std::size_t kMaxPatternLength = 256;
inline constexpr std::size_t kMinExclusionCoreLength = 3;

// Validate a single configure pattern. Returns an error message (suitable for
// the `error|...` configure response) or std::nullopt if valid. Always enforces
// the per-element length cap. When `require_min_core_len` is set (process
// stabilization exclusions), a bare substring with no `*` wildcard shorter than
// kMinExclusionCoreLength is rejected — the operator must lengthen it or signal
// explicit wildcard intent with `*`. The empty/ is_string checks are done by the
// caller during JSON parsing.
[[nodiscard]] std::optional<std::string>
validate_config_pattern(std::string_view pattern, bool require_min_core_len);

// Parse a stored pattern-array config value (redaction_patterns /
// process_stabilization_exclusions) into a bounded, sanitised vector. This is
// the RUNTIME defence (#541): configure caps the array at write time, but the
// collect loop re-reads the stored value every fast cycle, so a value written
// before the cap existed — or mutated outside the plugin — must still be bounded
// here. Drops non-string, empty, and over-long (> kMaxPatternLength) elements and
// truncates to kMaxPatternArrayElements. Returns std::nullopt only when the
// stored text is not a JSON array (the caller then applies its own default);
// a valid-but-empty array yields an empty vector (explicit "no patterns").
//
// When `require_min_core_len` is set (the exclusions loader), an element whose
// effective match core — after stripping leading/trailing `*` — is shorter than
// kMinExclusionCoreLength is ALSO dropped, matching the configure-time floor in
// validate_config_pattern. This closes the load-path gap (#541): a sub-floor
// value persisted before the floor existed (a no-tamper upgrade) or written out
// of band would otherwise reach should_redact and silently suppress most process
// events. The redaction loader leaves it false — a short redaction core merely
// over-redacts a command line, it does not drop events.
[[nodiscard]] std::optional<std::vector<std::string>>
parse_pattern_config(std::string_view json_text, bool require_min_core_len = false);

/**
 * Run all pending aggregations for all sources.
 * Reads rollup marks from tar_config, processes new data, updates marks.
 * @param db        The TAR database.
 * @param now_epoch Current epoch seconds.
 * @return Total number of aggregation operations performed.
 */
int run_aggregation(TarDatabase& db, int64_t now_epoch);

/**
 * Run retention cleanup for all warehouse tables.
 * Enforces row-count limits on live tables and time-based retention on
 * aggregated tables.
 * @param db        The TAR database.
 * @param now_epoch Current epoch seconds.
 */
void run_retention(TarDatabase& db, int64_t now_epoch);

/**
 * Apply an enable/disable transition for a TAR capture source.
 *
 * Updates `<source>_enabled` to `new_value` and maintains the operator-facing
 * `<source>_paused_at` config row used by the TAR dashboard's
 * retention-paused list (PR-A / issue #547). The semantics are:
 *
 *   - enabled→disabled: writes `<source>_paused_at = now_epoch` AND clears the
 *     source's diff baseline (see #538 below).
 *   - disabled→enabled: writes `<source>_paused_at = "0"` (cleared, but kept
 *     present — a missing row would be ambiguous with "never paused").
 *   - no transition (idempotent set): leaves `<source>_paused_at` untouched.
 *
 * The default for `<source>_enabled` if not yet set comes from
 * `CaptureSourceDef::default_enabled` (`"true"` for always-on sources, `"false"`
 * for the opt-in module/procperf/netqual). So the first-ever set registers as a
 * transition only when it differs from that default — e.g. the first
 * `module_enabled=false` on a fresh DB is a no-op (module already defaults off)
 * and writes no spurious `paused_at`, whereas the first `process_enabled=false`
 * is a real enabled→disabled transition.
 *
 * #538: on the enabled→disabled transition the source's snapshot-diff baseline
 * (`diff_state_key(source)`) is cleared so a later re-enable starts from a clean
 * snapshot instead of diffing against the frozen pre-pause state — which would
 * emit ghost "stopped" events for every entity that exited during the pause.
 * No-op for sources without a diff baseline (perf/procperf/netqual). The CALLER
 * must serialise this against the collectors (they hold `collect_mu_` for their
 * whole enumerate→diff→set_state cycle); this function takes no lock itself.
 *
 * #538/UP-1 (fail-safe ordering): on enable→disable the baseline is cleared
 * BEFORE the `_enabled` flag is flipped, and the flag is flipped only if the
 * clear persisted. If the clear fails (e.g. SQLITE_BUSY), the source is left
 * ENABLED and this returns `false` — never a disabled source with a stale
 * baseline (which would reintroduce the ghost-event bug on re-enable).
 *
 * @param db        The TAR database.
 * @param source    Source name (e.g. "process", "tcp", "service", "user").
 * @param new_value Either `"true"` or `"false"`. Other values are rejected
 *                  upstream by the configure action.
 * @param now_epoch Current epoch seconds — used as the paused_at timestamp.
 * @return true on success; false ONLY when an enable→disable transition could
 *         not clear the baseline (the source is left enabled). Non-disabling
 *         transitions always return true.
 */
[[nodiscard]] bool apply_source_enabled_transition(TarDatabase& db,
                                                    std::string_view source,
                                                    std::string_view new_value,
                                                    int64_t now_epoch);

/**
 * Map a capture source to its snapshot-diff baseline key in the TAR state store
 * (the key passed to `TarDatabase::get_state`/`set_state`).
 *
 * The mapping is NOT 1:1 with the source name: `tcp`'s baseline lives under
 * `"network"`. Sources with no snapshot-diff baseline (`perf`/`procperf` keep an
 * in-memory previous reading; `netqual` is stateless) return an empty view.
 *
 * Single source of truth: both the collectors (`collect_fast`/`collect_slow`)
 * and the enable/disable transition above route through this so the on-disable
 * clear can never target the wrong key (a silent no-op).
 */
[[nodiscard]] std::string_view diff_state_key(std::string_view source);

} // namespace yuzu::tar
