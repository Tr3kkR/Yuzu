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
