#pragma once

/// @file inventory_ingest_outcome.hpp
/// Shared outcome vocabulary for the daily-sync hash-skip ingest (ADR-0016 §4),
/// common to every typed inventory store (`SoftwareInventoryStore`,
/// `DeviceInventoryStore`, …). Extracted to a leaf header so a store needs only
/// this enum, not a sibling store's full interface (interface segregation).

namespace yuzu::server {

/// Outcome of a hash-skip ingest for one source (ADR-0016 §4).
enum class InventoryIngestOutcome {
    kStored,   ///< full payload accepted; the agent's rows were replaced
    kTouched,  ///< claimed hash matched the stored hash; last_seen bumped only
    kNeedFull, ///< cold cache / mismatch with no rows — server asks for a resend
    kError,    ///< pool/SQL failure (transient; the agent retries next cycle)
};

} // namespace yuzu::server
