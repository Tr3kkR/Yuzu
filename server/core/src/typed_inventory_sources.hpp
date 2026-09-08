#pragma once

/// @file typed_inventory_sources.hpp
/// The set of TYPED daily-sync sources (ADR-0016). Each is persisted by its own
/// normalized store via a dedicated ingest seam — NOT the generic `InventoryStore`
/// blob store.
///
/// LOAD-BEARING: the gateway `ProxyInventory` generic-blob loop MUST skip these.
/// The direct `ReportInventory` path has **no** generic loop (the documented
/// "INTENTIONAL ASYMMETRY"), so a typed source that also lands in the generic store
/// (a) breaks direct/gateway parity (ADR-0016 §5), and (b) **leaks it past its own
/// securable** — the generic store is read by `query_inventory`/`get_agent_inventory`
/// on `Infrastructure:Read`, not the per-source gate (e.g. `Inventory:Read`), so the
/// device_ci serial/UUID/MAC would be readable without `Inventory:Read`.
///
/// ADDING A TYPED SOURCE = add its wire key here (one place), or it silently
/// double-stores into the generic store on the gateway path.

#include <string_view>

namespace yuzu::server {

[[nodiscard]] inline bool is_typed_inventory_source(std::string_view source) {
    // software_licensing (ADR-0024 Decision 5): registered in the SAME change
    // as its seam (software_licensing_ingestion) — omission would double-store
    // detected-licence rows (incl. `user_ref`) into the generic store on the
    // gateway path, readable under Infrastructure:Read, i.e. a leak past the
    // SoftwareLicensing securable.
    //
    // app_usage (Wave 7 PR7.2): same omission class, caught by
    // test_agent_service_impl.cpp's "ProxyInventory (gateway): an app_usage
    // payload reaches ingest_app_usage_report..." composition test — without
    // this entry, a gateway-proxied agent's app_usage blob double-stored into
    // the generic InventoryStore, readable under Infrastructure:Read rather
    // than the Forensics securable app_usage is gated on.
    return source == "installed_software" || source == "app_perf" || source == "device_ci" ||
           source == "software_licensing" || source == "app_usage";
}

} // namespace yuzu::server
