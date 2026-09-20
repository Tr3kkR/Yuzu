#include "gateway_route_store.hpp"

#include "gateway_route_reap_rules.hpp" // PURE decide_reap + the two parsers (PR #4299 round-3 split)
#include "pg/pg_array.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include <spdlog/spdlog.h>

#include <charconv>
#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server {

namespace {

// Schema == snake_case(ClassName) with the Store suffix (ADR-0008 Update):
// GatewayRouteStore -> gateway_route_store. One schema, one table
// (`agent_routes`).
constexpr const char* kStoreName = "gateway_route_store";

// Lease-acquire deadlines (ADR-0012 §2). This store is written from the
// connect/disconnect notification path, not a synchronous operator request,
// so modest deadlines are fine; the caller has its own retry on the next
// notification.
//
// #9 (4.2a): kWriteTimeout deliberately DIFFERS from the 2s codebase norm
// (session_store.cpp:34, command_outbox_store.cpp:32) at 500ms. Every writer
// here (register_fresh/announce_connected/deregister/renew_leases) runs
// SYNCHRONOUSLY on a gRPC handler thread on the agent heartbeat/connect hot
// path (agent_service_impl.cpp's BatchHeartbeat, gateway_service_impl.cpp's
// ProxyRegister/ProxyStreamStatus) — a 2s stall under pool pressure pins that
// thread for 2s per call. Most of these writes are fail-open (a degraded write
// is logged and the RPC proceeds — see record_route_store_failure in
// gateway_service_impl.cpp; register_fresh is the one fail-CLOSED exception as
// of 4.2b Task B, returning UNAVAILABLE). A short bound fails fast back to "log and
// proceed" instead of holding the handler thread hostage; the expected
// consequence is that yuzu_server_gateway_route_write_failed_total rises
// under real pool pressure rather than every heartbeat blocking for 2s each.
// reap_stale_routes() is a background pass, not a handler-thread call, so it
// deliberately keeps the 2s norm (kReapWriteTimeout below) rather than this
// shortened one.
constexpr std::chrono::milliseconds kWriteTimeout{500};
constexpr std::chrono::milliseconds kReadTimeout{2000};

// reap_stale_routes() runs off a background timer (Task B's job wiring), not
// a gRPC handler thread, so it keeps the 2s codebase norm rather than the
// hot-path-motivated kWriteTimeout above.
constexpr std::chrono::milliseconds kReapWriteTimeout{2000};

// ---------------------------------------------------------------------------
// reap_stale_routes() constants (clock-guarded-retention, see this store's
// header + docs/clock-guarded-retention.md). Copy the SHAPE from
// SessionStore::reap_expired, never the numbers — every constant here is
// substrate/store-specific.
//
// The lease TTL agents/gateways renew against is
// gateway_service_impl.cpp::kGatewayRouteLeaseTtlSecs = 90s. That file is out
// of this task's scope (owned by Task C) and this store has no dependency on
// the gateway wiring layer, so the value is DELIBERATELY DUPLICATED — but as
// yuzu::server::kKnownLeaseTtlSecs, a plain namespace-scope constant declared
// in this store's OWN header (gateway_route_store.hpp), not a local literal —
// so gateway_service_impl.cpp (which already includes that header
// transitively via gateway_service_impl.hpp) can `static_assert` the two
// stay equal without either .cpp depending on the other (PR #4299 review;
// see that static_assert for the enforcement). A future TTL bump there must
// still be mirrored here (kStaleLeaseGraceSecs must stay >= 1x that TTL) or a
// merely-late heartbeat mid-renew starts getting reaped — the static_assert
// only catches the two constants disagreeing, not either one being wrong.

// kStaleLeaseGraceSecs (grace >= 1 lease TTL; 2x tolerates a FULL missed
// renewal cycle) was HOISTED into gateway_route_store.hpp (PR #4299 round 4) so
// the header can compute kMinReapRecoveryGapMs from it. The sweep-(a) cutoff
// below reads the header constant directly.

// Tombstone/never-announced purge age: deliberately SHORT (task spec) — a
// tombstone or a stuck mid-handshake row carries no state worth preserving
// beyond letting a genuine register_fresh find and reuse the primary-keyed
// row, which works whether the row exists or not (its higher minted epoch
// always wins). ~3.3x the TTL is comfortably longer than the lease-grace
// window (so this predicate never races predicate (a) over the same row)
// and short enough that dead rows do not linger in the directory.
constexpr int kTombstonePurgeAgeSecs = 300; // 5 minutes

// Unconditional per-predicate cap (part 5) — follows session_store.cpp's
// kReapCap shape (a hard ceiling that always applies, regardless of what the
// clock/anomaly guards decide).
constexpr int kReapCap = 5000;

// Part 1's implausibility bound, PER THIS STORE (never copied from another
// store's constant — docs/clock-guarded-retention.md part 1). This store's
// entire liveness horizon is under ten minutes (grace 180s + purge-age 300s
// == 480s); a `now()` reading more than a day ahead of the last accepted
// pass is already ~180x that horizon and cannot be legitimate operation,
// while staying far below SessionStore's 366-day bound (sized to a human
// session's plausible lifetime, not this store's sub-10-minute signal).
constexpr std::int64_t kMaxPlausibleSkewMs = 24LL * 3600 * 1000; // 1 day

// PR #4299 round 4: the recovery window (header constants) must be well-ordered
// AND its ceiling must not exceed the implausible-skew bound. Scope of the claim
// (PR #4299 round-5 review, Minor): this bounds the per-pass PERSISTENCE INTERVAL
// a recovery may credit (delta = now - first_now <= kMaxReapRecoveryGapMs), NOT
// the total forward jump a recovered pass then sweeps against — that jump is
// necessarily > kMaxPlausibleSkewMs by construction, since a jump that large is
// exactly what triggered the anomaly. The TERMINATING property is that the
// persistence evidence a recovery requires can never be widened past
// kMaxPlausibleSkewMs, the same horizon within which a clean pass already accepts
// a forward jump with no anomaly treatment at all — so recovery's evidence bar
// sits inside the clean path's plausibility envelope and the window cannot grow
// unbounded. kMaxPlausibleSkewMs stays store-local (this .cpp), so this assert
// lives here rather than in the header.
static_assert(kMinReapRecoveryGapMs < kMaxReapRecoveryGapMs &&
                  kMaxReapRecoveryGapMs <= kMaxPlausibleSkewMs,
              "reap recovery window must be well-ordered and its ceiling must not exceed the "
              "implausible-skew bound (else recovery would be weaker than a clean pass)");

std::optional<std::int64_t> parse_ms(const char* v) {
    if (v == nullptr || *v == '\0')
        return std::nullopt;
    // Postgres epoch-ms extraction below always yields an integral text value.
    // FULL-consumption check (ptr == end) added PR #4299 round-3 review: without
    // it "123abc" parses as 123 rather than being rejected (mirrors
    // leader_elector.cpp's parse_i64 and parse_reap_i64 in the reap-rules header).
    const char* end = v + std::char_traits<char>::length(v);
    std::int64_t n = 0;
    auto [ptr, ec] = std::from_chars(v, end, n);
    if (ec != std::errc{} || ptr != end)
        return std::nullopt;
    return n;
}

std::optional<std::string> col_opt(PGresult* r, int row, int col) {
    if (PQgetisnull(r, row, col))
        return std::nullopt;
    return std::string(PQgetvalue(r, row, col));
}

// Mirrors response_store.cpp/audit_store.cpp's local helper of the same name:
// Postgres boolean text output is 't'/'f'.
bool to_bool(const char* s) { return s != nullptr && s[0] == 't'; }

// parse_reap_i64 / parse_declined_marker moved to gateway_route_reap_rules.hpp
// (PR #4299 round-3 split): they are now shared by decide_reap (pure) AND this
// store's apply tail, and both are unit-tested without Postgres.

} // namespace

const std::vector<pg::PgMigration>& GatewayRouteStore::migrations() {
    // DDL is UNQUALIFIED — the runner sets search_path to this store's schema
    // for the migration transaction (playbook §2). `agent_id` is the PRIMARY
    // KEY: one live route per agent. `connection_epoch` is the anti-replay
    // fence (file header); `session_id`/`lease_until` guard the follow-up
    // announce/deregister/renew calls. cluster_id/gateway_node/session_id/
    // lease_until are nullable — unknown at register-time, filled in later by
    // announce_connected.
    //
    // The `session_id` index is load-bearing, not cosmetic: renew_leases() is
    // the highest-frequency op (once per BatchHeartbeat batch) and (#4246 #10)
    // joins against it via `r.session_id = t.session_id` (correlated with
    // `agent_id` too, but `agent_id` is already the primary key), and
    // deregister() filters on session_id too; without the index those are a
    // seq scan of agent_routes per heartbeat tick, which grows with fleet
    // size (governance perf/sre, WS-4 4.1). It ships in migration v1 because
    // adding it later costs a second migration version.
    static const std::vector<pg::PgMigration> kMigrations = {
        {1,
         R"(
CREATE SEQUENCE IF NOT EXISTS connection_epoch_seq AS bigint;
CREATE TABLE agent_routes (
    agent_id         TEXT        PRIMARY KEY,
    cluster_id       TEXT,
    gateway_node     TEXT,
    connection_epoch BIGINT      NOT NULL,
    session_id       TEXT,
    lease_until      TIMESTAMPTZ,
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX agent_routes_session_id_idx ON agent_routes (session_id);
)"},
        // v2 (4.2a): reap_stale_routes()'s persisted, sanitised clock anchor
        // (clock-guarded-retention parts 2/3), mirroring session_store's
        // session_meta / execution_tracker's reap_meta anchor tables. Plain
        // key/value, additive, no backfill (ADR-0009 — this store is
        // born-on-Postgres and route_meta never existed before this slice).
        {2, R"(
CREATE TABLE IF NOT EXISTS route_meta(key TEXT PRIMARY KEY, value TEXT);
)"},
        // v3 (#4324): the per-home generation fence. Nullable — a legacy
        // gateway build (or a row from before this slice) has no home id.
        // See the file header "SLICE #4324" for the asymmetric deregister
        // predicate this column enables.
        {3, R"(
ALTER TABLE agent_routes ADD COLUMN stream_home_id TEXT;
)"},
    };
    return kMigrations;
}

GatewayRouteStore::GatewayRouteStore(pg::PgPool& pool) : pool_(pool) {
    // Construction-only unbounded acquire (ADR-0012 §2); every runtime acquire
    // below is bounded.
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error("GatewayRouteStore: no database connection at construction ({}) — "
                      "gateway route directory disabled",
                      pool_.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error("GatewayRouteStore: schema migration failed — gateway route directory "
                      "disabled");
        return;
    }
    open_ = true;
    // ADR-0009 fresh-start-by-default: born on Postgres, no legacy SQLite
    // file, no backfill (this store never existed before WS-4).
    spdlog::info("GatewayRouteStore initialized (schema {}) — born on Postgres, no legacy "
                 "backfill",
                 kStoreName);
}

std::expected<RegisterFreshResult, GatewayRouteStoreError>
GatewayRouteStore::register_fresh(std::string_view agent_id, std::string_view session_id) {
    if (!open_)
        return std::unexpected(GatewayRouteStoreError::store_unavailable);
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease) {
        spdlog::warn("GatewayRouteStore::register_fresh: lease timeout — degraded");
        return std::unexpected(GatewayRouteStoreError::store_unavailable);
    }
    // The fresh epoch is minted INSIDE the same statement as the guarded
    // upsert (mirrors leader_elector.cpp's nextval-in-INSERT idiom) so the
    // mint and the CAS attempt are atomic — no window where a concurrent
    // caller could mint a higher epoch and win the row between this call's
    // mint and its own write.
    //
    // The `WHERE EXCLUDED.connection_epoch > agent_routes.connection_epoch`
    // guard is the anti-replay fence (file header): a delayed/out-of-order
    // register whose freshly-minted epoch happens to be LOWER than the
    // row's current epoch (impossible for THIS caller's own mint since the
    // sequence is monotonic, but the whole point is that a DIFFERENT,
    // concurrently-racing register may have already advanced the row to a
    // higher epoch by the time this statement runs) loses: zero rows
    // returned, existing row untouched. cluster_id/gateway_node are NULLed
    // (4.2b — see the file header "placement authority" note): a winning
    // register_fresh is a NEW connection attempt whose eventual placement is
    // not yet known, and announce_connected is the SOLE writer of placement
    // once the connection is fully established. Preserving the old values
    // here (the pre-4.2b COALESCE) let a stale placement survive a fresh
    // registration + a bare lease renewal with no intervening CONNECTED — a
    // trap for a dispatch reader that must never route on unconfirmed
    // placement.
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "INSERT INTO gateway_route_store.agent_routes "
        "  (agent_id, connection_epoch, session_id, updated_at) "
        "VALUES ($1, nextval('gateway_route_store.connection_epoch_seq'), $2, now()) "
        "ON CONFLICT (agent_id) DO UPDATE SET "
        "  connection_epoch = EXCLUDED.connection_epoch, "
        "  session_id = EXCLUDED.session_id, "
        "  cluster_id = NULL, "
        "  gateway_node = NULL, "
        "  stream_home_id = NULL, "
        // A winning re-register is a NEW connection — it must NOT inherit the
        // superseded session's lease. Reset to NULL here; the connection's own
        // announce_connected / first heartbeat renew establishes a fresh lease.
        // (cluster_id/gateway_node/stream_home_id are ALSO reset to NULL
        // above, for the same reason: all three are connection-specific until
        // announce_connected confirms them — stream_home_id IS placement,
        // #4324, same as cluster_id/gateway_node.)
        "  lease_until = NULL, "
        "  updated_at = now() "
        "WHERE EXCLUDED.connection_epoch > agent_routes.connection_epoch "
        "RETURNING connection_epoch",
        std::vector<std::optional<std::string>>{std::string(agent_id), std::string(session_id)});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::error("GatewayRouteStore::register_fresh: query failed: {}",
                      PQresultErrorMessage(res.get()));
        return std::unexpected(GatewayRouteStoreError::db_error);
    }
    if (PQntuples(res.get()) == 1) {
        RegisterFreshResult out;
        const char* v = PQgetvalue(res.get(), 0, 0);
        std::from_chars(v, v + std::char_traits<char>::length(v), out.epoch);
        out.won = true;
        return out;
    }
    // Zero rows: EITHER a brand-new INSERT with no conflict was somehow not
    // returned (impossible — a plain INSERT always returns its row) OR — the
    // real case — the ON CONFLICT branch's WHERE guard rejected the update
    // because a higher epoch already won. Either way the CAS did not apply;
    // the caller lost the race and must not proceed with this epoch. The
    // minted-but-discarded epoch value is not recoverable from the statement
    // (RETURNING produced no row), so report a zero epoch alongside won=false
    // — callers must check `won` before consulting `epoch`.
    return RegisterFreshResult{.epoch = 0, .won = false};
}

std::expected<AnnounceResult, GatewayRouteStoreError>
GatewayRouteStore::announce_connected(std::string_view agent_id, std::string_view session_id,
                                      std::string_view cluster_id, std::string_view gateway_node,
                                      int lease_ttl_secs, std::string_view stream_home_id) {
    if (!open_)
        return std::unexpected(GatewayRouteStoreError::store_unavailable);
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease) {
        spdlog::warn("GatewayRouteStore::announce_connected: lease timeout — degraded");
        return std::unexpected(GatewayRouteStoreError::store_unavailable);
    }
    // Session-guarded (file header): only touches a row that still belongs to
    // THIS session, so a stale CONNECTED from an already-superseded session
    // cannot overwrite a newer re-home's cluster/node.
    //
    // An EMPTY cluster_id is stored as NULL ("unknown"), never as ''. A gateway
    // build predating WS-4's field 7 sends no cluster_id (proto3 yields ""); a
    // future reader distinguishes "unknown" via IS NULL, and '' would be a third
    // state it would misclassify during a mixed-version rollout. `stream_home_id`
    // (#4324) follows the SAME convention, for the SAME reason (a gateway build
    // predating #4324, or a caller not yet threading it through, yields "").
    std::optional<std::string> cluster_arg =
        cluster_id.empty() ? std::nullopt : std::optional<std::string>{std::string(cluster_id)};
    std::optional<std::string> home_id_arg =
        stream_home_id.empty() ? std::nullopt
                                : std::optional<std::string>{std::string(stream_home_id)};
    pg::PgResult upd = pg::exec_params(
        lease.get(),
        "UPDATE gateway_route_store.agent_routes SET "
        "  cluster_id=$3, gateway_node=$4, stream_home_id=$6, "
        "  lease_until = now() + ($5 || ' seconds')::interval, updated_at = now() "
        "WHERE agent_id=$1 AND session_id=$2 RETURNING agent_id",
        std::vector<std::optional<std::string>>{
            std::string(agent_id), std::string(session_id), std::move(cluster_arg),
            std::string(gateway_node), std::to_string(lease_ttl_secs), home_id_arg});
    if (upd.status() != PGRES_TUPLES_OK) {
        spdlog::error("GatewayRouteStore::announce_connected: update failed: {}",
                      PQresultErrorMessage(upd.get()));
        return std::unexpected(GatewayRouteStoreError::db_error);
    }
    if (PQntuples(upd.get()) > 0)
        return AnnounceResult{.matched = true};

    // No existing row for this (agent_id, session_id) pair — insert one, but
    // NEVER overwrite a row a different session already holds (ON CONFLICT DO
    // NOTHING, not DO UPDATE): a stale/duplicate CONNECTED for a session that
    // lost the register_fresh race must not clobber the winner's row.
    pg::PgResult ins = pg::exec_params(
        lease.get(),
        "INSERT INTO gateway_route_store.agent_routes "
        "  (agent_id, cluster_id, gateway_node, connection_epoch, session_id, lease_until, "
        "   updated_at, stream_home_id) "
        "VALUES ($1, $2, $3, 0, $4, now() + ($5 || ' seconds')::interval, now(), $6) "
        "ON CONFLICT (agent_id) DO NOTHING",
        std::vector<std::optional<std::string>>{
            std::string(agent_id),
            cluster_id.empty() ? std::nullopt : std::optional<std::string>{std::string(cluster_id)},
            std::string(gateway_node), std::string(session_id), std::to_string(lease_ttl_secs),
            std::move(home_id_arg)});
    if (ins.status() != PGRES_COMMAND_OK) {
        spdlog::error("GatewayRouteStore::announce_connected: fallback insert failed: {}",
                      PQresultErrorMessage(ins.get()));
        return std::unexpected(GatewayRouteStoreError::db_error);
    }
    return AnnounceResult{.matched = false};
}

std::expected<bool, GatewayRouteStoreError>
GatewayRouteStore::reclaim_tombstoned_session(std::string_view agent_id,
                                              std::string_view session_id,
                                              int lease_ttl_secs) {
    if (!open_)
        return std::unexpected(GatewayRouteStoreError::store_unavailable);
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease) {
        spdlog::warn("GatewayRouteStore::reclaim_tombstoned_session: lease timeout — degraded");
        return std::unexpected(GatewayRouteStoreError::store_unavailable);
    }
    // Same ON-CONFLICT-DO-UPDATE-WHERE idiom as register_fresh's guarded
    // upsert, but the guard is `session_id IS NULL` (tombstoned or a fresh
    // The INSERT branch supplies the real session_id directly, so the
    // `session_id IS NULL` guard only ever matters on the UPDATE/conflict
    // branch — this is a resurrection of the SAME session, not a new one
    // racing for the row, so the guard is on session identity, not an
    // epoch comparison. connection_epoch is 0 on a brand-new row (INSERT)
    // and UNTOUCHED on a re-armed existing tombstone (UPDATE never sets
    // it) — either way a genuine concurrent or later register_fresh still
    // always wins regardless of commit order (file header "THE FENCE"):
    // its nextval mint exceeds a fresh row's 0, and a tombstone's retained
    // epoch is exactly what register_fresh already tolerated overwriting.
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "INSERT INTO gateway_route_store.agent_routes "
        "  (agent_id, connection_epoch, session_id, lease_until, updated_at) "
        "VALUES ($1, 0, $2, now() + ($3 || ' seconds')::interval, now()) "
        "ON CONFLICT (agent_id) DO UPDATE SET "
        "  session_id = EXCLUDED.session_id, "
        "  lease_until = EXCLUDED.lease_until, "
        "  updated_at = now() "
        "WHERE agent_routes.session_id IS NULL "
        "RETURNING agent_id",
        std::vector<std::optional<std::string>>{std::string(agent_id), std::string(session_id),
                                                 std::to_string(lease_ttl_secs)});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::error("GatewayRouteStore::reclaim_tombstoned_session: query failed: {}",
                      PQresultErrorMessage(res.get()));
        return std::unexpected(GatewayRouteStoreError::db_error);
    }
    // Zero rows: the ON CONFLICT branch's WHERE guard rejected the update
    // because the row belongs to a DIFFERENT, LIVE (non-NULL) session — a
    // genuine stale/zombie replay. The caller must refuse it outright.
    return PQntuples(res.get()) == 1;
}

std::expected<DeregisterResult, GatewayRouteStoreError>
GatewayRouteStore::deregister(std::string_view agent_id, std::string_view session_id,
                              std::string_view stream_home_id) {
    if (!open_)
        return std::unexpected(GatewayRouteStoreError::store_unavailable);
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease) {
        spdlog::warn("GatewayRouteStore::deregister: lease timeout — degraded");
        return std::unexpected(GatewayRouteStoreError::store_unavailable);
    }
    // Session-guarded: a stale DISCONNECTED from a DIFFERENT, superseded session
    // cannot tear down a newer re-home's row (its session_id will not match).
    // A SAME-session late DISCONNECTED is additionally fenced by `stream_home_id`
    // (file header SLICE #4324, #4246 #4): the re-announce path reuses the
    // session id, so session_id equality alone cannot tell an old home's
    // teardown from a newer re-home under the same id — the predicate below
    // closes that gap at the store layer. CLOSED end-to-end (task 3/3): the
    // RPC handler (`gateway_service_impl.cpp`'s `NotifyStreamStatus`) threads
    // the caller's REAL `stream_home_id` through on every call here.
    //
    // The predicate is deliberately NOT the naive symmetric form
    // (`$3 = '' OR stream_home_id = $3`): a STORED NULL admits ANY incoming
    // `$3` (stamped or not) — it does NOT additionally require `$3 = ''`
    // (PR #4492 review, HIGH, fixed from an earlier `stream_home_id IS NULL
    // AND $3 = ''` form). A stored NULL never represents a live placement
    // worth protecting from a stale teardown: under the single-producer
    // invariant it means ONLY "this session's own `announce_connected`
    // hasn't landed yet" (a `register_fresh`-only row — the gateway's two
    // independently-`spawn_monitor`'d RPC workers give no ordering guarantee
    // between a session's own CONNECTED and DISCONNECTED, so the latter can
    // reach the server first) or "already tombstoned" — both safe to admit.
    // A STAMPED stored value, by contrast, DOES require an EXACT match
    // against `$3` (a stale stamped DISCONNECTED from a superseded home
    // cannot tear down a different, newer stamped home). This is what
    // protects a rolling gateway upgrade (mixed old-build/new-build gateway
    // nodes is the NORMAL state of one): an old-build node's late unstamped
    // DISCONNECTED must not tombstone a new-build node's stamped re-home
    // reusing the same session id, while a legacy DISCONNECTED against a
    // legacy (never-stamped, stored-NULL) row still behaves exactly as
    // before (backward compatibility with a fleet that has no home-id-aware
    // gateways yet).
    //
    // TOMBSTONE, not DELETE (file header "SLICE 4.2a", closes 4.2 design-doc
    // obligation #5 — late-CONNECTED resurrection, NOT #4). A DELETE lets a late/reordered CONNECTED for this
    // same (now-gone) session resurrect the route via announce_connected's
    // fallback `ON CONFLICT DO NOTHING` INSERT, because that fallback only
    // refuses to clobber a row that EXISTS — against no row at all it just
    // recreates one. Tombstoning leaves the row in place with
    // `session_id IS NULL AND lease_until IS NULL` (the tombstone
    // definition): the late CONNECTED's session-guarded UPDATE still misses
    // (NULL never equals a bound `session_id` parameter) and its fallback
    // INSERT now hits `ON CONFLICT (agent_id) DO NOTHING` against the
    // EXISTING tombstoned row, so it no-ops instead of reviving a dead
    // route. `connection_epoch` is retained (NOT reset) — it is the
    // anti-replay fence's ratchet; a genuine later register_fresh mints a
    // strictly higher epoch and always wins the guarded UPSERT regardless of
    // what the tombstoned row's epoch is, so retaining it costs nothing and
    // avoids re-litigating fence state on every deregister/reconnect cycle.
    //
    // `home_id_arg` ALWAYS carries a value (never nullopt), even when empty —
    // unlike announce_connected's cluster/home-id args, which map an empty
    // input to a stored NULL.
    //
    // PREDICATE FIX (PR #4492 review, HIGH): a STORED NULL/empty
    // `stream_home_id` ADMITS ANY incoming value, stamped or not — it does
    // NOT additionally require `$3 = ''`. A stored NULL never represents a
    // live placement worth protecting from a stale teardown; under the
    // single-producer invariant (see gateway_route_store.hpp's SESSION
    // GUARDS LIMIT / SCOPE OF "CLOSED") it means ONLY "this session's own
    // `announce_connected` hasn't landed yet" (a `register_fresh`-only row)
    // or "already tombstoned" — both cases are safe to admit. The previous
    // `stream_home_id IS NULL AND $3 = ''` form rejected a STAMPED incoming
    // DISCONNECTED against a NULL stored value, misclassifying an ordinary
    // out-of-order CONNECTED/DISCONNECTED pair (no re-home involved — the
    // gateway's two independently-`spawn_monitor`'d RPC workers give no
    // ordering guarantee, so DISCONNECTED can reach the server before its
    // own paired CONNECTED) as a stale-home mismatch, skipping the tombstone
    // and letting the delayed CONNECTED publish a route for an already-dead
    // stream — a regression vs. the pre-#4324 unfenced behavior.
    std::optional<std::string> home_id_arg{std::string(stream_home_id)};
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE gateway_route_store.agent_routes SET "
        "  session_id=NULL, lease_until=NULL, cluster_id=NULL, gateway_node=NULL, "
        "  stream_home_id=NULL, updated_at=now() "
        "WHERE agent_id=$1 AND session_id=$2 "
        "  AND (stream_home_id IS NULL OR stream_home_id = $3) "
        "RETURNING agent_id",
        std::vector<std::optional<std::string>>{std::string(agent_id), std::string(session_id),
                                                 std::move(home_id_arg)});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::error("GatewayRouteStore::deregister: query failed: {}",
                      PQresultErrorMessage(res.get()));
        return std::unexpected(GatewayRouteStoreError::db_error);
    }
    return DeregisterResult{.removed = PQntuples(res.get()) > 0};
}

std::expected<int, GatewayRouteStoreError>
GatewayRouteStore::renew_leases(std::span<const std::string> agent_ids,
                                std::span<const std::string> session_ids, int lease_ttl_secs) {
    if (!open_)
        return std::unexpected(GatewayRouteStoreError::store_unavailable);
    // #4246 #10: agent_ids and session_ids are PARALLEL arrays (index i is one
    // (agent_id, session_id) pair) — a caller-side length mismatch would
    // silently misalign the correlation below, so refuse rather than guess
    // which element pairs with which.
    if (agent_ids.size() != session_ids.size()) {
        spdlog::error("GatewayRouteStore::renew_leases: agent_ids/session_ids length mismatch "
                      "({} vs {})",
                      agent_ids.size(), session_ids.size());
        return std::unexpected(GatewayRouteStoreError::db_error);
    }
    if (session_ids.empty())
        return 0;
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease) {
        spdlog::warn("GatewayRouteStore::renew_leases: lease timeout — degraded");
        return std::unexpected(GatewayRouteStoreError::store_unavailable);
    }
    // ONE batched statement, correlated on BOTH agent_id AND session_id via a
    // parallel-array unnest() join (#4246 #10) — a per-row renew would be one
    // write per agent every lease interval at fleet scale (file header), and
    // matching on session_id alone let a compromised/buggy gateway renew a
    // foreign agent's session merely by knowing its token, with no agent_id
    // correlation (defense-in-depth gap; see the retired trust-rationale
    // comment this replaces at the BatchHeartbeat call site). Both arrays go
    // through the shared pg::to_text_array helper (pg/pg_array.hpp) rather
    // than a hand-rolled literal, matching the established idiom
    // (app_perf_group_reader.cpp, deployment_run_store.cpp).
    std::vector<std::string_view> agent_views;
    agent_views.reserve(agent_ids.size());
    for (const std::string& a : agent_ids)
        agent_views.emplace_back(a);
    std::vector<std::string_view> session_views;
    session_views.reserve(session_ids.size());
    for (const std::string& s : session_ids)
        session_views.emplace_back(s);
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE gateway_route_store.agent_routes AS r SET "
        "  lease_until = now() + ($3 || ' seconds')::interval, updated_at = now() "
        "FROM unnest($1::text[], $2::text[]) AS t(agent_id, session_id) "
        "WHERE r.agent_id = t.agent_id AND r.session_id = t.session_id "
        "RETURNING r.agent_id",
        std::vector<std::string>{pg::to_text_array(agent_views), pg::to_text_array(session_views),
                                 std::to_string(lease_ttl_secs)});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::error("GatewayRouteStore::renew_leases: query failed: {}",
                      PQresultErrorMessage(res.get()));
        return std::unexpected(GatewayRouteStoreError::db_error);
    }
    return PQntuples(res.get());
}

std::expected<std::optional<RouteRow>, GatewayRouteStoreError>
GatewayRouteStore::lookup_route(std::string_view agent_id) {
    if (!open_)
        return std::unexpected(GatewayRouteStoreError::store_unavailable);
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        spdlog::warn("GatewayRouteStore::lookup_route: lease timeout — degraded");
        return std::unexpected(GatewayRouteStoreError::store_unavailable);
    }
    // is_stale computed IN-SQL against Postgres now() (DB-clock authority,
    // #3715 precedent) — never the process system_clock.
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT agent_id, cluster_id, gateway_node, connection_epoch, session_id, "
        "       (extract(epoch FROM lease_until) * 1000)::bigint AS lease_until_ms, "
        "       (lease_until IS NOT NULL AND lease_until < now()) AS is_stale "
        "FROM gateway_route_store.agent_routes WHERE agent_id=$1",
        std::vector<std::optional<std::string>>{std::string(agent_id)});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::error("GatewayRouteStore::lookup_route: query failed: {}",
                      PQresultErrorMessage(res.get()));
        return std::unexpected(GatewayRouteStoreError::db_error);
    }
    if (PQntuples(res.get()) == 0)
        return std::optional<RouteRow>(std::nullopt);

    RouteRow row;
    row.agent_id = PQgetvalue(res.get(), 0, 0);
    row.cluster_id = col_opt(res.get(), 0, 1);
    row.gateway_node = col_opt(res.get(), 0, 2);
    {
        const char* v = PQgetvalue(res.get(), 0, 3);
        std::from_chars(v, v + std::char_traits<char>::length(v), row.connection_epoch);
    }
    row.session_id = col_opt(res.get(), 0, 4);
    row.lease_until_ms = PQgetisnull(res.get(), 0, 5)
                              ? std::nullopt
                              : parse_ms(PQgetvalue(res.get(), 0, 5));
    row.is_stale = std::string_view(PQgetvalue(res.get(), 0, 6)) == "t";
    return std::optional<RouteRow>(std::move(row));
}

std::expected<std::vector<RoutableRoute>, GatewayRouteStoreError>
GatewayRouteStore::lookup_routes(std::span<const std::string> agent_ids) {
    if (!open_)
        return std::unexpected(GatewayRouteStoreError::store_unavailable);
    if (agent_ids.empty())
        return std::vector<RoutableRoute>{};
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        spdlog::warn("GatewayRouteStore::lookup_routes: lease timeout — degraded");
        return std::unexpected(GatewayRouteStoreError::store_unavailable);
    }
    // ONE batched statement over agent_id = ANY($1) — mirrors renew_leases'
    // array-param idiom (file header) so this read is bounded by a SINGLE
    // kReadTimeout regardless of how many agent_ids are requested, never
    // N-times that. `routable` is computed IN-SQL against Postgres now() —
    // the DB-clock authority (#3715 rule), never a replica clock — matching
    // is_stale's existing in-SQL computation above.
    std::vector<std::string_view> views;
    views.reserve(agent_ids.size());
    for (const std::string& s : agent_ids)
        views.emplace_back(s);
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT agent_id, cluster_id, gateway_node, connection_epoch, session_id, "
        "       (extract(epoch FROM lease_until) * 1000)::bigint AS lease_until_ms, "
        "       (lease_until IS NOT NULL AND lease_until < now()) AS is_stale, "
        "       (session_id IS NOT NULL AND lease_until >= now() AND cluster_id IS NOT NULL) "
        "         AS routable "
        "FROM gateway_route_store.agent_routes WHERE agent_id = ANY($1::text[])",
        std::vector<std::string>{pg::to_text_array(views)});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::error("GatewayRouteStore::lookup_routes: query failed: {}",
                      PQresultErrorMessage(res.get()));
        return std::unexpected(GatewayRouteStoreError::db_error);
    }
    const int n = PQntuples(res.get());
    std::vector<RoutableRoute> out;
    out.reserve(static_cast<std::size_t>(n));
    for (int i = 0; i < n; ++i) {
        RoutableRoute rr;
        rr.route.agent_id = PQgetvalue(res.get(), i, 0);
        rr.route.cluster_id = col_opt(res.get(), i, 1);
        rr.route.gateway_node = col_opt(res.get(), i, 2);
        {
            const char* v = PQgetvalue(res.get(), i, 3);
            std::from_chars(v, v + std::char_traits<char>::length(v), rr.route.connection_epoch);
        }
        rr.route.session_id = col_opt(res.get(), i, 4);
        rr.route.lease_until_ms = PQgetisnull(res.get(), i, 5)
                                       ? std::nullopt
                                       : parse_ms(PQgetvalue(res.get(), i, 5));
        rr.route.is_stale = std::string_view(PQgetvalue(res.get(), i, 6)) == "t";
        rr.routable = std::string_view(PQgetvalue(res.get(), i, 7)) == "t";
        out.push_back(std::move(rr));
    }
    return out;
}

std::expected<ReapRoutesResult, GatewayRouteStoreError> GatewayRouteStore::reap_stale_routes() {
    if (!open_)
        return std::unexpected(GatewayRouteStoreError::store_unavailable);

    // Clock-guarded, single-writer across replicas (SessionStore::reap_expired
    // shape — see the header comment on this method and
    // docs/clock-guarded-retention.md). The advisory lock is its OWN
    // statement, first, inside the txn (a CTE-embedded lock has the same
    // fixed-snapshot hazard session_store.cpp's comment describes). now_ms is
    // the DB clock (Postgres now(), read once in-SQL under the lock — the
    // SAME clock that authors lease_until/updated_at), sanitised against a
    // persisted route_meta anchor so a forward- or backward-skewed reading is
    // DECLINED, not acted on. Every accepted pass is unconditionally capped
    // per predicate.
    //
    // DECIDE/APPLY SPLIT (PR #4299 round-3 review): this method does I/O only —
    // the advisory lock, the three reads, and ONE apply tail. Every reap
    // decision (what to do to the sweeps, the anchor, and the decline marker)
    // is computed by the PURE `decide_reap` in gateway_route_reap_rules.hpp,
    // whose `ReapDecision::marker` has no default MarkerAction — so a future
    // reap branch that forgets the marker decision is a COMPILE error rather
    // than the three-rounds-running marker-obligation defect this split closes.
    int expired_leases_reaped = 0;
    int tombstones_reaped = 0;
    bool clock_anomaly = false;
    // Hoisted out of the lambda (was a lambda-local at the recovery-detection
    // site) so the recovery outcome survives past with_txn_for's return, into
    // ReapRoutesResult::recovered (PR #4299 round-2 review) — the caller
    // (server.cpp) needs it to emit a distinct `outcome="recovered"` metric,
    // separate from an ordinary `outcome="ok"` pass.
    bool recovered_from_prior_decline = false;
    // PR #4299 round 4 (observability-only): true iff an accepted sweep hit
    // kReapCap AND a same-txn EXISTS probe found a matching remainder. Surfaces
    // as outcome="ok_capped" — NOT a cadence/re-arm change (see the non-
    // acceleration rationale in docs/clock-guarded-retention.md).
    bool cap_bound_backlog = false;
    // PR #4299 round-2 external review (SHOULD): the ReplicaSafe contract for
    // this job (background_jobs.hpp) is "all but the advisory-lock holder
    // skip", matching every sibling single-sweeper store's
    // pg_try_advisory_xact_lock idiom (audit_store.cpp/response_store.cpp/
    // result_set_store.cpp/policy_store.cpp/guaranteed_state_store.cpp) — a
    // BLOCKING pg_advisory_xact_lock here instead pins a second replica's
    // maintenance-thread tick until the holder's transaction commits, which
    // the documented contract already claimed was not happening.
    bool skipped_lock = false;
    std::string err;
    const bool ok = pool_.with_txn_for(kReapWriteTimeout, [&](PGconn* c) -> bool {
        // Fixed key, deliberately NOT salted per-instance/per-test: Postgres advisory
        // locks are scoped per-DATABASE, and every [pg] test gets its own ephemeral
        // database, so a fixed key here cannot collide across tests. Across real
        // replicas sharing ONE production database, the fixed key IS the point — it is
        // the single-writer rendezvous every replica's reap tick must serialize
        // against (SINGLE-WRITER-today note above; becomes the PG-shared-state lock
        // when a 2nd replica lands).
        pg::PgResult lk = pg::exec_params(
            c, "SELECT pg_try_advisory_xact_lock(hashtext('gateway_route_store:reap'))",
            std::vector<std::string>{});
        if (lk.status() != PGRES_TUPLES_OK) {
            err = "reap advisory lock probe failed";
            return false;
        }
        if (!to_bool(PQgetvalue(lk.get(), 0, 0))) {
            skipped_lock = true;
            return true; // another replica is sweeping this tick; not a failure
        }
        // THREE reads, each `return false` (rollback) on statement failure.
        // decide_reap (gateway_route_reap_rules.hpp) is PURE — it is handed the
        // raw SELECTed text below and returns the full ReapDecision; this
        // method's ONE apply tail then executes it. Splitting decide from apply
        // is what closes the three-rounds-running marker-obligation class: a
        // decline is now a ReapDecision, never an early `return true`.

        // (1) DB now() — the SAME clock that authors lease_until/updated_at,
        // read once in-SQL under the lock so both sweep cutoffs, the anchor
        // compare, and the anchor advance stay in ONE clock domain.
        std::string now_raw;
        {
            pg::PgResult nr = pg::exec_params(
                c, "SELECT (extract(epoch FROM now()) * 1000)::bigint", std::vector<std::string>{});
            if (nr.status() != PGRES_TUPLES_OK || PQntuples(nr.get()) == 0) {
                err = "reap now() read failed";
                return false;
            }
            now_raw = PQgetvalue(nr.get(), 0, 0);
        }
        // (2) persisted anchor (0 rows -> nullopt -> first/no-anchor pass).
        std::optional<std::string> anchor_raw;
        {
            pg::PgResult ar = pg::exec_params(
                c, "SELECT value FROM gateway_route_store.route_meta WHERE key='reap_anchor_ms'",
                std::vector<std::string>{});
            if (ar.status() != PGRES_TUPLES_OK) {
                err = "reap anchor read failed";
                return false;
            }
            if (PQntuples(ar.get()) > 0)
                anchor_raw = PQgetvalue(ar.get(), 0, 0);
        }
        // (3) persisted decline marker (0 rows -> nullopt -> no prior decline).
        std::optional<std::string> marker_raw;
        {
            pg::PgResult mr = pg::exec_params(
                c,
                "SELECT value FROM gateway_route_store.route_meta WHERE "
                "key='reap_declined_anchor_ms'",
                std::vector<std::string>{});
            if (mr.status() != PGRES_TUPLES_OK) {
                err = "reap declined-anchor read failed";
                return false;
            }
            if (PQntuples(mr.get()) > 0)
                marker_raw = PQgetvalue(mr.get(), 0, 0);
        }

        const ReapDecision d = decide_reap(
            now_raw,
            anchor_raw ? std::optional<std::string_view>(*anchor_raw) : std::nullopt,
            marker_raw ? std::optional<std::string_view>(*marker_raw) : std::nullopt,
            kMaxPlausibleSkewMs, kMinReapRecoveryGapMs, kMaxReapRecoveryGapMs);
        clock_anomaly = d.clock_anomaly;
        recovered_from_prior_decline = d.recovered;
        if (d.clock_anomaly)
            spdlog::warn("GatewayRouteStore::reap_stale_routes declined (clock anomaly): "
                         "now='{}' anchor='{}' marker='{}'",
                         now_raw, anchor_raw.value_or("<none>"), marker_raw.value_or("<none>"));
        else if (d.recovered)
            spdlog::warn("GatewayRouteStore::reap_stale_routes recovering: a clock anomaly "
                         "persisted across a full decline pass (now='{}', anchor='{}') — treating "
                         "as genuine elapsed downtime and running the sweeps now",
                         now_raw, anchor_raw.value_or("<none>"));

        // ----- the ONE apply tail: the ONLY `return true` after the lock. A
        // decline is a ReapDecision (run_sweeps=false + marker Clear/Arm),
        // never an early return, so the marker obligation can never be skipped
        // by a new branch (PR #4299 round-3 split). -----

        // now_ms for the sweep cutoffs — re-parse the SAME now_raw decide_reap
        // used (one clock domain). run_sweeps is true only when now_raw parsed
        // OK, so this parse always engages; value_or(0) is dead defence.
        if (d.run_sweeps) {
            const std::int64_t now_ms = parse_reap_i64(now_raw).value_or(0);
            // Cutoffs hoisted (PR #4299 round 4) so the cap-backlog EXISTS probe
            // below can re-use the SAME cutoffs the two sweeps applied.
            const std::int64_t cutoff_a_ms =
                now_ms - static_cast<std::int64_t>(kStaleLeaseGraceSecs) * 1000;
            const std::int64_t cutoff_b_ms =
                now_ms - static_cast<std::int64_t>(kTombstonePurgeAgeSecs) * 1000;

            // (a) Expired-lease routes: lease_until past the grace window. Grace
        // (>= 1 lease TTL, task spec) means a merely-late heartbeat mid-renew
        // is never reaped here. ACTION is the same TOMBSTONE `deregister`
        // performs (retain connection_epoch, NULL the rest) rather than a
        // hard delete: the associated session may still be alive and simply
        // stopped renewing (network partition), and a late DISCONNECTED for
        // it arriving after this pass must still land as a no-op against a
        // tombstoned row rather than an error against a vanished one.
        //
        // The outer UPDATE's WHERE re-asserts the SAME expired predicate the
        // subquery already applied (governance fix #4, cpp-safety/UP-4): under
        // READ COMMITTED, the inner SELECT snapshots agent_id candidates, and
        // by the time the outer UPDATE takes each row's lock a concurrent
        // renew_leases()/announce_connected() could have pushed lease_until
        // back into the future for one of those rows. Without the re-check the
        // outer UPDATE only re-verifies `agent_id IN (...)` and would tombstone
        // an agent that renewed in that window anyway. Re-checking against
        // `$1` (the same cutoff the subquery used) closes that window: a
        // concurrently-renewed row now fails the outer predicate and drops
        // out, at the cost of nothing — a row that is still genuinely expired
        // passes both checks identically.
        {
            pg::PgResult dr = pg::exec_params(
                c,
                "UPDATE gateway_route_store.agent_routes SET "
                "  session_id=NULL, lease_until=NULL, cluster_id=NULL, gateway_node=NULL, "
                "  stream_home_id=NULL, updated_at=now() "
                "WHERE agent_id IN (SELECT agent_id FROM gateway_route_store.agent_routes "
                "  WHERE lease_until IS NOT NULL "
                "    AND (extract(epoch FROM lease_until) * 1000)::bigint < $1::bigint "
                "  LIMIT $2::bigint) "
                "  AND lease_until IS NOT NULL "
                "  AND (extract(epoch FROM lease_until) * 1000)::bigint < $1::bigint "
                "RETURNING agent_id",
                std::vector<std::string>{std::to_string(cutoff_a_ms), std::to_string(kReapCap)});
            if (dr.status() != PGRES_TUPLES_OK) {
                err = std::string("reap expired-lease sweep failed: ") + PQerrorMessage(c);
                return false;
            }
            expired_leases_reaped = PQntuples(dr.get());
        }

        // (b) Tombstoned / never-announced rows (lease_until IS NULL) whose
        // `updated_at` is older than the SHORT purge age (task spec) — this
        // catches both a real tombstone (session_id also NULL, left by
        // deregister or by sweep (a) above) and a row stuck since
        // register_fresh that never got an announce_connected. ACTION is a
        // hard DELETE, not a re-tombstone: by the purge age (well past any
        // plausible network-reordering window for a CONNECTED/DISCONNECTED
        // pair) a resurrection from a late notification is not a realistic
        // risk, and a genuine later register_fresh works identically whether
        // the row exists or not (INSERT with no conflict, always wins).
        //
        // The outer DELETE's WHERE re-asserts the SAME predicate the subquery
        // already applied (PR #4299 review, BLOCKER 2 — the same
        // EvalPlanQual hazard sweep (a) closed above, missed here on the
        // first pass): under READ COMMITTED the inner SELECT snapshots
        // agent_id candidates, and by the time the outer DELETE takes each
        // row's lock a concurrent `register_fresh`/`announce_connected` could
        // have revived that exact row (a fresh session_id/lease_until) in the
        // window between the snapshot and the lock. Without the re-check the
        // outer DELETE only re-verifies `agent_id IN (...)` and deletes the
        // just-revived row anyway — dropping a route a caller just believes
        // it (re-)established. Re-checking `lease_until IS NULL` and the SAME
        // `$1` cutoff the subquery used closes that window: a concurrently
        // revived row now fails the outer predicate and drops out, at the
        // cost of nothing — a row that is still genuinely a stale
        // tombstone/never-announced row passes both checks identically.
        {
            pg::PgResult dr = pg::exec_params(
                c,
                "DELETE FROM gateway_route_store.agent_routes WHERE agent_id IN "
                "  (SELECT agent_id FROM gateway_route_store.agent_routes "
                "     WHERE lease_until IS NULL "
                "       AND (extract(epoch FROM updated_at) * 1000)::bigint < $1::bigint "
                "     LIMIT $2::bigint) "
                "  AND lease_until IS NULL "
                "  AND (extract(epoch FROM updated_at) * 1000)::bigint < $1::bigint "
                "RETURNING agent_id",
                std::vector<std::string>{std::to_string(cutoff_b_ms), std::to_string(kReapCap)});
            if (dr.status() != PGRES_TUPLES_OK) {
                err = std::string("reap tombstone-purge sweep failed: ") + PQerrorMessage(c);
                return false;
            }
            tombstones_reaped = PQntuples(dr.get());
            }

            // Cap-backlog probe (PR #4299 round 4, SHOULD — observability only,
            // NOT acceleration). Hitting kReapCap does NOT prove a backlog
            // remains (an exact-boundary pass drained the last row), so probe
            // for a real remainder ONLY when a sweep hit its cap — the healthy
            // path pays nothing. Same txn, mirrors audit_store.cpp's shape.
            // Surfaces as outcome="ok_capped"; deliberately does NOT trigger a
            // faster re-arm (see docs/clock-guarded-retention.md — acceleration
            // would turn a mis-recovery into kReapCap tombstones every few
            // seconds, collapsing the operator reaction window).
            if (expired_leases_reaped >= kReapCap || tombstones_reaped >= kReapCap) {
                pg::PgResult more = pg::exec_params(
                    c,
                    "SELECT "
                    "EXISTS(SELECT 1 FROM gateway_route_store.agent_routes "
                    "  WHERE lease_until IS NOT NULL "
                    "    AND (extract(epoch FROM lease_until) * 1000)::bigint < $1::bigint), "
                    "EXISTS(SELECT 1 FROM gateway_route_store.agent_routes "
                    "  WHERE lease_until IS NULL "
                    "    AND (extract(epoch FROM updated_at) * 1000)::bigint < $2::bigint)",
                    std::vector<std::string>{std::to_string(cutoff_a_ms),
                                             std::to_string(cutoff_b_ms)});
                if (more.status() != PGRES_TUPLES_OK) {
                    err = std::string("reap cap-backlog probe failed: ") + PQerrorMessage(c);
                    return false;
                }
                const bool a_more = to_bool(PQgetvalue(more.get(), 0, 0));
                const bool b_more = to_bool(PQgetvalue(more.get(), 0, 1));
                // Only the predicate that actually hit its cap counts toward the
                // backlog signal — a below-cap sweep never leaves a hidden
                // remainder (it drained everything eligible this pass).
                cap_bound_backlog = (expired_leases_reaped >= kReapCap && a_more) ||
                                    (tombstones_reaped >= kReapCap && b_more);
            }
        } // end if (d.run_sweeps)

        // Advance the persisted anchor per the decision. nullopt = LEAVE it
        // untouched (a skew decline/arm never moves it, so the identical
        // repeat presents the same frozen pair). Otherwise upsert the chosen
        // value: decide_reap picks now_ms UNCONDITIONALLY for recovery /
        // first-pass / corrupt-anchor self-heal (moving decisively off a
        // stale/poisoned anchor — never max, which would leave a forward-skew
        // poison stuck forever), and max(anchor, now_ms) for a normal accepted
        // pass (see gateway_route_reap_rules.hpp's decide_reap).
        if (d.new_anchor) {
            pg::PgResult ur = pg::exec_params(
                c,
                "INSERT INTO gateway_route_store.route_meta (key, value) VALUES "
                "('reap_anchor_ms', $1) ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value",
                std::vector<std::string>{std::to_string(*d.new_anchor)});
            if (ur.status() != PGRES_COMMAND_OK) {
                err = "reap anchor update failed";
                return false;
            }
        }

        // Apply the marker decision. MANDATORY: MarkerAction has no default, so
        // decide_reap physically cannot return a ReapDecision that omits it —
        // this is the structural guarantee the decide/apply split buys (PR
        // #4299 round-3). CLEAR on every accepted / recovered / self-heal /
        // bad-now pass (a no-op DELETE when no marker is set costs one
        // statement); ARM "<anchor>:<direction>:<first_now_ms>" on a skew
        // decline (the 3-field format, PR #4299 round 4 — first_now_ms is the
        // reading the recovery persistence window is measured from).
        if (d.marker.kind() == MarkerAction::Kind::Clear) {
            pg::PgResult clr_declined = pg::exec_params(
                c,
                "DELETE FROM gateway_route_store.route_meta WHERE key='reap_declined_anchor_ms'",
                std::vector<std::string>{});
            if (clr_declined.status() != PGRES_COMMAND_OK) {
                err = "reap declined-anchor clear failed";
                return false;
            }
        } else {
            pg::PgResult set_declined = pg::exec_params(
                c,
                "INSERT INTO gateway_route_store.route_meta (key, value) VALUES "
                "('reap_declined_anchor_ms', $1) ON CONFLICT (key) DO UPDATE SET "
                "value=EXCLUDED.value",
                std::vector<std::string>{std::to_string(d.marker.anchor()) + ":" +
                                         d.marker.direction() + ":" +
                                         std::to_string(d.marker.first_now_ms())});
            if (set_declined.status() != PGRES_COMMAND_OK) {
                err = "reap declined-anchor persist failed";
                return false;
            }
        }
        return true;
    });
    if (!ok) {
        // `err` stays empty when with_txn_for itself failed before the lambda
        // ran a single statement (a try_acquire_for lease timeout, or BEGIN
        // failing on a broken connection) — that is the same "degraded, not a
        // query bug" case every other method here reports as
        // store_unavailable. `err` non-empty means the lambda's own guard set
        // it on a specific statement failure: a real db_error.
        if (err.empty()) {
            spdlog::warn("GatewayRouteStore::reap_stale_routes: lease timeout or txn-begin "
                         "failure — degraded");
            return std::unexpected(GatewayRouteStoreError::store_unavailable);
        }
        spdlog::error("GatewayRouteStore::reap_stale_routes: {}", err);
        return std::unexpected(GatewayRouteStoreError::db_error);
    }
    return ReapRoutesResult{.expired_leases_reaped = expired_leases_reaped,
                            .tombstones_reaped = tombstones_reaped,
                            .clock_anomaly = clock_anomaly,
                            .recovered = recovered_from_prior_decline,
                            .skipped = skipped_lock,
                            .cap_bound = cap_bound_backlog};
}

} // namespace yuzu::server
