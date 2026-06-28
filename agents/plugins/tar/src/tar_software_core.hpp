#pragma once

/**
 * tar_software_core.hpp -- Pure orchestration core for the `software` source.
 *
 * The platform shell (tar_software_collector.cpp) does the registry I/O and the
 * plugin (tar_plugin.cpp do_collect_software) does the lock / source-enabled gate
 * / DB read+write. Everything in between — classifying the prior state
 * (cold-start vs corrupt vs steady), gating machine-only vs per-user assembly, and
 * computing the diff — is the PURE logic here, so it is unit-testable off-Windows
 * where the registry collectors return empty (#1620).
 */

#include "tar_collectors.hpp" // SoftwareInfo, SoftwareEvent, compute/assemble

#include <cstdint>
#include <string>
#include <vector>

namespace yuzu::tar {

/// Serialise an installed-software snapshot to the JSON array persisted in the
/// `software` KV state. Shared by the collector orchestration and the tests.
std::string software_state_to_json(const std::vector<SoftwareInfo>& apps);

/// Parse a `software` KV-state blob back into entries (tolerant of missing
/// fields / non-object elements). Returns empty for an empty/blank or non-array
/// blob.
std::vector<SoftwareInfo> software_state_from_json(const std::string& s);

/// Outcome of one collect_software tick's PURE logic.
struct SoftwareCollectResult {
    enum class Kind : std::uint8_t {
        kColdStartSeed, // no prior state — seed the baseline, emit NO events
        kCorruptSkip,   // prior state is not a JSON array — skip, preserve baseline
        kSteady,        // diffed against the prior baseline
    };
    Kind kind{Kind::kSteady};
    std::vector<SoftwareEvent> events; // populated for Steady only
    std::string new_state_json;        // ColdStartSeed + Steady; empty on CorruptSkip
};

/**
 * Pure core of do_collect_software (#1620).
 *
 * @param prev_json      The prior `software` KV state ("" ⇒ cold start).
 * @param enumerated     What the caller read THIS tick: machine-only when
 *                       per-user scope is off; machine + currently-loaded user
 *                       hives when on; the full cold-start baseline on a first run.
 * @param scanned_users  Loaded-profile set for the steady-state carry-forward
 *                       (empty when per-user scope is off).
 * @param user_scope     Selects machine-only vs. per-user carry-forward assembly.
 */
SoftwareCollectResult software_collect_core(const std::string& prev_json,
                                            std::vector<SoftwareInfo> enumerated,
                                            const std::vector<std::string>& scanned_users,
                                            bool user_scope, int64_t timestamp,
                                            int64_t snapshot_id);

} // namespace yuzu::tar
