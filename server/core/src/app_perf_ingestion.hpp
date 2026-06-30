#pragma once

/// @file app_perf_ingestion.hpp
/// Server ingest seam for the daily-sync `app_perf` source (DEX app-perf-over-time
/// B1). Deliberately SEPARATE from `inventory_ingestion` (the two sources share
/// nothing at the row level — installed_software is current-state entries,
/// app_perf is numeric time-series). BOTH server entry points call this one
/// function so the direct (`ReportInventory`) and gateway (`ProxyInventory`) paths
/// persist identically, right after `ingest_inventory_report`.
///
/// The report is **untrusted external input**: this seam caps the blob, the row
/// count, and each name/version field, and numeric-bounds every value before the
/// store. Unlike inventory it does NOT recompute/compare a content hash — B1 is
/// hash-less (the per-day window changes daily, so hash-skip is moot). A hash-only
/// `app_perf` report (no blob) is therefore answered with `need_full`.

#include "app_perf_daily_store.hpp" // AppPerfDailyRow

#include <string>
#include <vector>

namespace yuzu::agent::v1 {
class InventoryReport;
class InventoryAck;
} // namespace yuzu::agent::v1

namespace yuzu {
class MetricsRegistry;
}

namespace yuzu::server {

class AppPerfDailyStore;

/// Parse the `app_perf` canonical wire blob into daily rows: records are
/// 0x1E-separated, fields 0x1F-separated, 9 fields
/// `name, version, day, samples, instances_max, cpu_avg, cpu_max, ws_avg_bytes,
/// ws_max_bytes`. name/version are UTF-8-scrubbed + capped at 256 bytes (PK
/// safety); day must be a plausible epoch; numerics are bounded non-negative.
/// Empty-name rows are dropped. Lenient (a malformed numeric → 0) — the store
/// re-canons + re-clamps + merges. Exposed for unit testing.
[[nodiscard]] std::vector<AppPerfDailyRow> parse_app_perf_blob(const std::string& blob);

/// Ingest the `app_perf` source of `report` for `agent_id` into `store`. No-op when
/// `agent_id` is empty or the source is not present in this cycle. Appends
/// `app_perf` to `ack.need_full` on a hash-only report (no blob), an over-cap blob,
/// or a transient store error — so the agent re-sends. Does NOT set `ack.received`
/// (the caller owns that). `metrics` (nullable) receives
/// `yuzu_app_perf_ingest_total{outcome}` + `yuzu_app_perf_ingest_duration_seconds`.
void ingest_app_perf_report(AppPerfDailyStore& store, const std::string& agent_id,
                            const ::yuzu::agent::v1::InventoryReport& report,
                            ::yuzu::agent::v1::InventoryAck& ack,
                            ::yuzu::MetricsRegistry* metrics = nullptr);

} // namespace yuzu::server
