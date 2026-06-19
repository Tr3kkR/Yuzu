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
 * The default for `<source>_enabled` if not yet set comes from
 * `CaptureSourceDef::default_enabled` (`"true"` for always-on sources, `"false"`
 * for the opt-in module/procperf/netqual). So the first-ever set registers as a
 * transition only when it differs from that default — e.g. the first
 * `module_enabled=false` on a fresh DB is a no-op (module already defaults off)
 * and writes no spurious `paused_at`, whereas the first `process_enabled=false`
 * is a real enabled→disabled transition.
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
 * Canonicalise a stored `<source>_enabled` value to a strict tri-state for the
 * `status` surface (#560). do_configure only ever persists "true"/"false", so
 * any other stored value indicates the row was mutated outside the plugin
 * (corruption, disk tampering, downgrade/upgrade) and is reported as the
 * explicit "errored" sentinel — never coerced/guessed — so the dashboard can
 * render a value-error badge instead of silently omitting the source.
 *
 * Both the collect-time gate (`source_enabled`, tar_plugin.cpp) and
 * `run_retention` gate on this canonical value, so a non-canonical value fails
 * closed: collection stops AND the source's rows are preserved (not pruned).
 */
[[nodiscard]] std::string_view canonical_source_enabled(std::string_view stored_value);

} // namespace yuzu::tar
