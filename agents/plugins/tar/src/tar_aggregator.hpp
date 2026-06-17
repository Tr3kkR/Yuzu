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
 *   - enabled→disabled: writes `<source>_paused_at = now_epoch`.
 *   - disabled→enabled: writes `<source>_paused_at = "0"` (cleared, but kept
 *     present — a missing row would be ambiguous with "never paused").
 *   - no transition (idempotent set): leaves `<source>_paused_at` untouched.
 *
 * The default for `<source>_enabled` if not yet set is `"true"`, so the
 * first-ever set to `"false"` correctly registers as a transition.
 *
 * @param db        The TAR database.
 * @param source    Source name (e.g. "process", "tcp", "service", "user").
 * @param new_value Either `"true"` or `"false"`. Other values are rejected
 *                  upstream by the configure action.
 * @param now_epoch Current epoch seconds — used as the paused_at timestamp.
 */
void apply_source_enabled_transition(TarDatabase& db,
                                      std::string_view source,
                                      std::string_view new_value,
                                      int64_t now_epoch);

} // namespace yuzu::tar
