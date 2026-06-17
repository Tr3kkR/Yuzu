#pragma once

/// @file offline_endpoint_store.hpp
/// First born-on-Postgres server store (ADR-0006/0009 greenfield, schema
/// `endpoint_state`). Persists per-agent last-known identity + last-seen so a
/// host that drops out of the in-memory FleetTopologyStore cache (60 s TTL)
/// renders **stale-flagged** on /viz/fleet instead of vanishing. Written on
/// every heartbeat ingest (direct + gateway, via HeartbeatIngestion), read by
/// the viz topology handler. No secrets — plain columns, no SecretCodec.
///
/// Substrate contract (ADR-0008): the store holds a `PgPool&` (not a
/// `sqlite3*`), runs its schema migration at construction on a pinned lease,
/// and schema-qualifies every runtime statement (`endpoint_state.endpoints`) —
/// pooled connections carry no per-store search_path. Mutate-and-return uses
/// `RETURNING` (the #1033-banning idiom), never `sqlite3_changes()`.

#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server::pg {
class PgPool;
}

namespace yuzu::server {

/// One persisted endpoint row — the last-known identity for an agent the
/// server has seen. Deliberately thin: enough to render a stale placeholder
/// cube, nothing that belongs to the live in-memory topology.
struct OfflineEndpoint {
    std::string agent_id;
    std::string hostname;
    std::string os;
    std::int64_t last_heartbeat_ms{0}; ///< Server wall-clock epoch ms at last ingest.
    std::int64_t agent_ts{0};          ///< Agent-emitted snapshot epoch seconds (0 if none).
};

class OfflineEndpointStore {
public:
    /// Borrows the shared pool and runs the `endpoint_state` schema migration
    /// on a pinned lease. `is_open()` is false if the lease was empty or the
    /// migration failed (the server fails closed before reaching here, so in
    /// production the migration runs against a proven-reachable database).
    explicit OfflineEndpointStore(pg::PgPool& pool);

    OfflineEndpointStore(const OfflineEndpointStore&) = delete;
    OfflineEndpointStore& operator=(const OfflineEndpointStore&) = delete;

    [[nodiscard]] bool is_open() const noexcept { return open_; }

    /// Upsert one agent's last-known identity + last-seen. Best-effort: returns
    /// false (logged at debug) on an empty lease or a query error so a slow or
    /// blipping database never fails the heartbeat path — the live in-memory
    /// stores remain the source of truth; this is durability on top. Single
    /// statement, autocommit, `INSERT ... ON CONFLICT ... RETURNING`.
    bool upsert(std::string_view agent_id, std::string_view hostname, std::string_view os,
                std::int64_t last_heartbeat_ms, std::int64_t agent_ts);

    /// Every endpoint whose last heartbeat is within `window` of now, newest
    /// first. The viz handler renders those NOT currently online as stale
    /// cubes; rows older than `window` are withheld so a long-departed host
    /// eventually stops cluttering the view. Empty on error (fail-soft: the
    /// page still renders the live fleet).
    [[nodiscard]] std::vector<OfflineEndpoint> query_stale_within(std::chrono::seconds window);

private:
    pg::PgPool& pool_;
    bool open_{false};
};

} // namespace yuzu::server
