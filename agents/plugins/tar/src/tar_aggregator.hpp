#pragma once

/**
 * tar_aggregator.hpp -- Rollup aggregation and retention for TAR warehouse
 *
 * Aggregates live table data into hourly/daily/monthly summary tables.
 * Each rollup is idempotent: tracks last-processed timestamp in tar_config
 * and only processes new data on each invocation.
 */

#include "tar_db.hpp"

#include <cstdint>
#include <string_view>

namespace yuzu::tar {

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

/**
 * Map a capture-source name to the `set_state`/`get_state` collector key its
 * diff path uses, or "" for sources that keep no diff-state.
 *
 * NOTE the `tcp` source persists its snapshot under "network", NOT "tcp" — this
 * mapping MUST stay in sync with collect_fast_impl's set_state() calls. The
 * scalar samplers (`perf`, `procperf`, `netqual`) keep no snapshot diff and map
 * to "". Used when disabling a source to clear the right state row so a later
 * re-enable diffs against a clean baseline (#538).
 */
[[nodiscard]] std::string_view diff_state_key_for_source(std::string_view source);

/**
 * Canonicalise a stored `<source>_enabled` value to a strict tri-state for the
 * `status` surface (#560). do_configure only ever persists "true"/"false", so
 * any other stored value indicates the row was mutated outside the plugin
 * (corruption, disk tampering, downgrade/upgrade) and is reported as the
 * explicit "errored" sentinel — never coerced/guessed — so the dashboard can
 * render a value-error badge instead of silently omitting the source.
 */
[[nodiscard]] std::string_view canonical_source_enabled(std::string_view stored_value);

} // namespace yuzu::tar
