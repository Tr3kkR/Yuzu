#pragma once

/// @file server_ota_options.hpp
///
/// CLI/env registration for the OTA and gRPC bound knobs (#913, #911), split out
/// of `main.cpp` so it is reachable by a test.
///
/// WHY. These options are the ONLY way an operator tunes the OTA bounds, and
/// while the registration lived inline in `main.cpp` nothing exercised it: a
/// misspelled `envname()`, a default that drifted from the documented one, a
/// binding pointed at the wrong `Config` field, or a lost `CLI::PositiveNumber`
/// validator would all ship silently, with every service-level test still green
/// because those drive the setters directly. A gate-1 review flagged that gap.
///
/// The flag names, defaults and env spellings here are contract — they appear in
/// `docs/user-manual/server-admin.md` and the changelog. `test_server_ota_options.cpp`
/// pins them.

#include <CLI/CLI.hpp>

#include <yuzu/server/server.hpp>

namespace yuzu::server {

/// Register the OTA + gRPC bound options onto `app`, bound to `cfg`.
///
/// Every knob is `CLI::PositiveNumber`-validated for the same reason the
/// per-principal quota options are: a zero or negative value does not "disable"
/// these bounds, it configures a server that refuses every OTA pull (or accepts
/// no streams at all) with no clear signal why. Rejecting at parse time turns a
/// silent self-inflicted outage into a startup error.
inline void register_ota_options(CLI::App& app, Config& cfg) {
    app.add_option("--ota-max-concurrent-per-peer", cfg.ota_max_concurrent_per_peer,
                   "Max parallel DownloadUpdate streams per peer (default: 2)")
        ->default_val(2)
        ->check(CLI::PositiveNumber)
        ->envname("YUZU_OTA_MAX_CONCURRENT_PER_PEER");
    app.add_option("--ota-rate-capacity", cfg.ota_rate_capacity,
                   "Per-peer OTA token-bucket burst (default: 20)")
        ->default_val(20.0)
        ->check(CLI::PositiveNumber)
        ->envname("YUZU_OTA_RATE_CAPACITY");
    app.add_option("--ota-rate-refill-per-min", cfg.ota_rate_refill_per_min,
                   "Per-peer OTA tokens restored per minute (default: 1)")
        ->default_val(1.0)
        ->check(CLI::PositiveNumber)
        ->envname("YUZU_OTA_RATE_REFILL_PER_MIN");
    app.add_option("--ota-transfer-deadline-secs", cfg.ota_transfer_deadline_secs,
                   "Whole-transfer bound for one OTA download (default: 900)")
        ->default_val(900)
        ->check(CLI::PositiveNumber)
        ->envname("YUZU_OTA_TRANSFER_DEADLINE_SECS");
    app.add_option("--ota-chunk-write-deadline-secs", cfg.ota_chunk_write_deadline_secs,
                   "Single-chunk stall bound for an OTA download (default: 30). Raise "
                   "on fleets with genuinely slow links (satellite, congested WAN) — a "
                   "deadline-tripped transfer refunds its rate token, so raising this "
                   "trades a longer held thread for fewer aborted updates.")
        ->default_val(30)
        ->check(CLI::PositiveNumber)
        ->envname("YUZU_OTA_CHUNK_WRITE_DEADLINE_SECS");
    app.add_option("--ota-max-peers-tracked", cfg.ota_max_peers_tracked,
                   "Cardinality ceiling on the per-peer OTA admission map (default: 50000)")
        ->default_val(50000)
        ->check(CLI::PositiveNumber)
        ->envname("YUZU_OTA_MAX_PEERS_TRACKED");

    app.add_option("--grpc-max-concurrent-streams", cfg.grpc_max_concurrent_streams,
                   "Max concurrent HTTP/2 streams per gRPC connection (default: 128)")
        ->default_val(128)
        ->check(CLI::PositiveNumber)
        ->envname("YUZU_GRPC_MAX_CONCURRENT_STREAMS");
    app.add_option("--grpc-max-resource-memory-mb", cfg.grpc_max_resource_memory_mb,
                   "gRPC ResourceQuota memory ceiling in MiB (default: 512)")
        ->default_val(512)
        ->check(CLI::PositiveNumber)
        ->envname("YUZU_GRPC_MAX_RESOURCE_MEMORY_MB");
}

} // namespace yuzu::server
