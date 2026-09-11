// test_gateway_route_store.cpp — HA WS-4 slice 4.1: the fenced agent->cluster
// routing directory. These [pg] tests bind the two structural guarantees the
// architecture review made load-bearing (see gateway_route_store.hpp):
//   1. register_fresh mints a strictly-increasing epoch per connection
//      attempt, and the guarded UPSERT's CAS rejects a lower-epoch (stale/
//      out-of-order) register — the anti-replay fence.
//   2. announce_connected/deregister are SESSION-guarded: a stale
//      notification from a superseded session must not overwrite or tear
//      down a newer re-home's row.
// Plus renew_leases' batched update and lookup_route's in-SQL is_stale.
//
// This store is INERT in 4.1 (written, not yet read for dispatch) — these
// tests exercise the writer path in isolation, no dispatch surface involved.

#include "gateway_route_store.hpp"

#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <libpq-fe.h>

#include <cstdint>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

using namespace yuzu::server;

namespace {

// One migration run, cloned per fixture.
yuzu::test::PgTestTemplate gateway_route_tpl{"gatewayroute", [](const std::string& dsn) {
    yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
    yuzu::server::GatewayRouteStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("gateway_route template: store failed to migrate");
}};

// RAII bundle: ephemeral DB + pool + store.
class GatewayRoutePg {
public:
    GatewayRoutePg() {
        if (yuzu::test::pg_admin_dsn_env() == nullptr)
            SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
        db_.emplace(gateway_route_tpl);
        INFO("[GatewayRoutePg] fixture status (blank == OK): " << db_->error());
        REQUIRE(db_->available());
        pool_.emplace(yuzu::server::pg::PgPool::Options{.conninfo = db_->dsn(), .size = 4});
        REQUIRE(pool_->valid());
        store_ = std::make_unique<GatewayRouteStore>(*pool_);
        REQUIRE(store_->is_open());
    }

    GatewayRoutePg(const GatewayRoutePg&) = delete;
    GatewayRoutePg& operator=(const GatewayRoutePg&) = delete;

    GatewayRouteStore& store() noexcept { return *store_; }
    std::string dsn() const { return db_->dsn(); }

    // Directly overwrite a row's (connection_epoch, session_id) on a second
    // connection — for driving the anti-replay-fence scenario (a subsequent
    // register_fresh's freshly-minted epoch is LOWER than this artificially
    // bumped value) and for assertions the public API deliberately does not
    // expose.
    void raw_bump_epoch(const std::string& agent_id, std::int64_t epoch,
                        const std::string& session_id) {
        yuzu::server::pg::PgConn conn{PQconnectdb(dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        const std::string epoch_s = std::to_string(epoch);
        const char* p1 = agent_id.c_str();
        const char* p2 = epoch_s.c_str();
        const char* p3 = session_id.c_str();
        const char* params[3] = {p1, p2, p3};
        yuzu::server::pg::PgResult r{PQexecParams(
            conn.get(),
            "UPDATE gateway_route_store.agent_routes SET connection_epoch=$2::bigint, "
            "session_id=$3 WHERE agent_id=$1",
            3, nullptr, params, nullptr, nullptr, 0)};
        REQUIRE(r.status() == PGRES_COMMAND_OK);
    }

    // Directly rewrite a row's lease_until to `seconds_ago` seconds in the
    // past — for driving reap_stale_routes' grace-window scenarios without
    // waiting real wall-clock time.
    void raw_set_lease_until_ago(const std::string& agent_id, int seconds_ago) {
        yuzu::server::pg::PgConn conn{PQconnectdb(dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        const std::string secs_s = std::to_string(seconds_ago);
        const char* p1 = agent_id.c_str();
        const char* p2 = secs_s.c_str();
        const char* params[2] = {p1, p2};
        yuzu::server::pg::PgResult r{PQexecParams(
            conn.get(),
            "UPDATE gateway_route_store.agent_routes SET "
            "  lease_until = now() - ($2 || ' seconds')::interval "
            "WHERE agent_id=$1",
            2, nullptr, params, nullptr, nullptr, 0)};
        REQUIRE(r.status() == PGRES_COMMAND_OK);
    }

    // Directly rewrite a row's updated_at to `seconds_ago` seconds in the
    // past — for driving the tombstone-purge-age predicate.
    void raw_set_updated_at_ago(const std::string& agent_id, int seconds_ago) {
        yuzu::server::pg::PgConn conn{PQconnectdb(dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        const std::string secs_s = std::to_string(seconds_ago);
        const char* p1 = agent_id.c_str();
        const char* p2 = secs_s.c_str();
        const char* params[2] = {p1, p2};
        yuzu::server::pg::PgResult r{PQexecParams(
            conn.get(),
            "UPDATE gateway_route_store.agent_routes SET "
            "  updated_at = now() - ($2 || ' seconds')::interval "
            "WHERE agent_id=$1",
            2, nullptr, params, nullptr, nullptr, 0)};
        REQUIRE(r.status() == PGRES_COMMAND_OK);
    }

    // Row existence bypassing lookup_route (which reports a tombstone as a
    // present row) — for asserting a row was fully DELETED by the
    // tombstone-purge sweep.
    bool raw_row_exists(const std::string& agent_id) {
        yuzu::server::pg::PgConn conn{PQconnectdb(dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        const char* p1 = agent_id.c_str();
        const char* params[1] = {p1};
        yuzu::server::pg::PgResult r{PQexecParams(
            conn.get(), "SELECT 1 FROM gateway_route_store.agent_routes WHERE agent_id=$1", 1,
            nullptr, params, nullptr, nullptr, 0)};
        REQUIRE(r.status() == PGRES_TUPLES_OK);
        return PQntuples(r.get()) > 0;
    }

    // Bulk-insert `count` rows with lease_until well in the past, directly
    // via SQL — looping register_fresh/announce_connected `count` times would
    // make the cap test the slow part of the suite (mirrors
    // test_result_set_store.cpp's GC-sweep-cap idiom).
    void raw_bulk_insert_expired(int count, const std::string& agent_prefix) {
        yuzu::server::pg::PgConn conn{PQconnectdb(dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        const std::string count_s = std::to_string(count);
        const char* p1 = agent_prefix.c_str();
        const char* p2 = count_s.c_str();
        const char* params[2] = {p1, p2};
        yuzu::server::pg::PgResult r{PQexecParams(
            conn.get(),
            "INSERT INTO gateway_route_store.agent_routes "
            "  (agent_id, connection_epoch, session_id, lease_until, updated_at) "
            "SELECT $1 || lpad(g::text, 6, '0'), g, 'sess-capbulk', "
            "       now() - interval '1000 seconds', now() "
            "FROM generate_series(1, $2::int) AS g",
            2, nullptr, params, nullptr, nullptr, 0)};
        INFO(PQresultErrorMessage(r.get()));
        REQUIRE(r.status() == PGRES_COMMAND_OK);
    }

private:
    std::optional<yuzu::test::PostgresTestDb> db_;
    std::optional<yuzu::server::pg::PgPool> pool_;
    std::unique_ptr<GatewayRouteStore> store_;
};

} // namespace

TEST_CASE("GatewayRouteStore[pg]: opens and migrates", "[gateway_route][pg][store]") {
    GatewayRoutePg fx;
    CHECK(fx.store().is_open());
}

TEST_CASE("GatewayRouteStore[pg]: register_fresh mints strictly increasing epochs",
          "[gateway_route][pg][store]") {
    GatewayRoutePg fx;
    auto r1 = fx.store().register_fresh("agent-1", "session-1");
    REQUIRE(r1.has_value());
    CHECK(r1->won);
    CHECK(r1->epoch > 0);

    // A second connection attempt for the same agent (e.g. a reconnect) mints
    // a HIGHER epoch and wins.
    auto r2 = fx.store().register_fresh("agent-1", "session-2");
    REQUIRE(r2.has_value());
    CHECK(r2->won);
    CHECK(r2->epoch > r1->epoch);

    auto row = fx.store().lookup_route("agent-1");
    REQUIRE(row.has_value());
    REQUIRE(row->has_value());
    CHECK((*row)->connection_epoch == r2->epoch);
    CHECK((*row)->session_id == "session-2");
}

TEST_CASE("GatewayRouteStore[pg]: a lower-epoch register loses (anti-replay fence)",
          "[gateway_route][pg][store]") {
    GatewayRoutePg fx;
    auto r1 = fx.store().register_fresh("agent-2", "session-1");
    REQUIRE(r1.has_value());
    REQUIRE(r1->won);

    // Artificially advance the stored row's epoch far beyond anything the
    // sequence has minted yet (simulating a NEWER connection's register that
    // already won), then attempt a register_fresh whose freshly-minted epoch
    // is only r1->epoch+1 or so — well below the bumped value. The guarded
    // UPSERT's `WHERE EXCLUDED.connection_epoch > agent_routes.connection_epoch`
    // clause must reject it: won == false, and the row is left exactly as
    // bumped (this is the anti-replay fence a delayed/out-of-order gateway
    // notification relies on).
    const std::int64_t bumped_epoch = r1->epoch + 1'000'000;
    fx.raw_bump_epoch("agent-2", bumped_epoch, "session-winner");

    auto stale = fx.store().register_fresh("agent-2", "session-stale-replay");
    REQUIRE(stale.has_value());
    CHECK_FALSE(stale->won);

    auto row = fx.store().lookup_route("agent-2");
    REQUIRE(row.has_value());
    REQUIRE(row->has_value());
    CHECK((*row)->connection_epoch == bumped_epoch);
    CHECK((*row)->session_id == "session-winner");
}

TEST_CASE("GatewayRouteStore[pg]: announce_connected fills cluster/node when session matches",
          "[gateway_route][pg][store]") {
    GatewayRoutePg fx;
    auto r1 = fx.store().register_fresh("agent-3", "session-1");
    REQUIRE(r1.has_value());
    REQUIRE(r1->won);

    auto ann = fx.store().announce_connected("agent-3", "session-1", "cluster-a", "node-1", 30);
    REQUIRE(ann.has_value());
    CHECK(ann->matched);

    auto row = fx.store().lookup_route("agent-3");
    REQUIRE(row.has_value());
    REQUIRE(row->has_value());
    REQUIRE((*row)->cluster_id.has_value());
    CHECK(*(*row)->cluster_id == "cluster-a");
    REQUIRE((*row)->gateway_node.has_value());
    CHECK(*(*row)->gateway_node == "node-1");
    REQUIRE((*row)->lease_until_ms.has_value());
    CHECK_FALSE((*row)->is_stale);
}

TEST_CASE("GatewayRouteStore[pg]: announce_connected is a no-op against a different session",
          "[gateway_route][pg][store]") {
    GatewayRoutePg fx;
    auto r1 = fx.store().register_fresh("agent-4", "session-1");
    REQUIRE(r1.has_value());
    REQUIRE(r1->won);
    auto ann1 = fx.store().announce_connected("agent-4", "session-1", "cluster-a", "node-1", 30);
    REQUIRE(ann1.has_value());
    REQUIRE(ann1->matched);

    // A stale/duplicate CONNECTED for a DIFFERENT (losing or unrelated)
    // session must not overwrite the row the real winner holds.
    auto ann2 = fx.store().announce_connected("agent-4", "session-stale", "cluster-b", "node-2",
                                              30);
    REQUIRE(ann2.has_value());
    CHECK_FALSE(ann2->matched);

    auto row = fx.store().lookup_route("agent-4");
    REQUIRE(row.has_value());
    REQUIRE(row->has_value());
    CHECK((*row)->session_id == "session-1");
    REQUIRE((*row)->cluster_id.has_value());
    CHECK(*(*row)->cluster_id == "cluster-a");
}

TEST_CASE("GatewayRouteStore[pg]: deregister tombstones only when session matches",
          "[gateway_route][pg][store]") {
    GatewayRoutePg fx;
    auto r1 = fx.store().register_fresh("agent-5", "session-1");
    REQUIRE(r1.has_value());
    REQUIRE(r1->won);
    REQUIRE(fx.store().announce_connected("agent-5", "session-1", "c1", "n1", 30).value().matched);

    // Wrong session: row intact (session/lease/cluster/node untouched).
    auto wrong = fx.store().deregister("agent-5", "session-wrong");
    REQUIRE(wrong.has_value());
    CHECK_FALSE(wrong->removed);
    auto still = fx.store().lookup_route("agent-5");
    REQUIRE(still.has_value());
    REQUIRE(still->has_value());
    CHECK((*still)->session_id == "session-1");
    CHECK((*still)->cluster_id.has_value());

    // Correct session: TOMBSTONED, not deleted — the row still exists (#4/#5,
    // gateway_route_store.hpp "SLICE 4.2a"): session_id/lease_until/cluster_id/
    // gateway_node -> NULL, connection_epoch RETAINED.
    auto right = fx.store().deregister("agent-5", "session-1");
    REQUIRE(right.has_value());
    CHECK(right->removed);
    auto tombstoned = fx.store().lookup_route("agent-5");
    REQUIRE(tombstoned.has_value());
    REQUIRE(tombstoned->has_value()); // row still present — a tombstone, not gone
    CHECK_FALSE((*tombstoned)->session_id.has_value());
    CHECK_FALSE((*tombstoned)->lease_until_ms.has_value());
    CHECK_FALSE((*tombstoned)->cluster_id.has_value());
    CHECK_FALSE((*tombstoned)->gateway_node.has_value());
    CHECK((*tombstoned)->connection_epoch == r1->epoch);

    // A second deregister for the same (now stale) session is a no-op:
    // session_id is NULL, so `session_id=$2` never matches it again.
    auto again = fx.store().deregister("agent-5", "session-1");
    REQUIRE(again.has_value());
    CHECK_FALSE(again->removed);
}

TEST_CASE("GatewayRouteStore[pg]: a late announce_connected does not resurrect a tombstoned route",
          "[gateway_route][pg][store]") {
    GatewayRoutePg fx;
    auto r1 = fx.store().register_fresh("agent-tomb-1", "session-dead");
    REQUIRE(r1.has_value());
    REQUIRE(r1->won);
    REQUIRE(fx.store()
                .announce_connected("agent-tomb-1", "session-dead", "c1", "n1", 30)
                .value()
                .matched);
    REQUIRE(fx.store().deregister("agent-tomb-1", "session-dead").value().removed);

    // A reordered/late CONNECTED for the now-dead session arrives AFTER the
    // DISCONNECTED that tombstoned the row. Its session-guarded UPDATE misses
    // (NULL != 'session-dead'), and its fallback INSERT hits
    // `ON CONFLICT (agent_id) DO NOTHING` against the EXISTING tombstoned
    // row — it must NOT resurrect the route.
    auto late = fx.store().announce_connected("agent-tomb-1", "session-dead", "c-late", "n-late", 30);
    REQUIRE(late.has_value());
    CHECK_FALSE(late->matched);

    auto row = fx.store().lookup_route("agent-tomb-1");
    REQUIRE(row.has_value());
    REQUIRE(row->has_value()); // still a tombstone, not resurrected
    CHECK_FALSE((*row)->session_id.has_value());
    CHECK_FALSE((*row)->lease_until_ms.has_value());
    CHECK_FALSE((*row)->cluster_id.has_value());
}

TEST_CASE("GatewayRouteStore[pg]: register_fresh after a tombstone mints a higher epoch and "
          "reuses the row",
          "[gateway_route][pg][store]") {
    GatewayRoutePg fx;
    auto r1 = fx.store().register_fresh("agent-tomb-2", "session-old");
    REQUIRE(r1.has_value());
    REQUIRE(r1->won);
    REQUIRE(fx.store()
                .announce_connected("agent-tomb-2", "session-old", "c1", "n1", 30)
                .value()
                .matched);
    REQUIRE(fx.store().deregister("agent-tomb-2", "session-old").value().removed);

    auto tombstoned = fx.store().lookup_route("agent-tomb-2");
    REQUIRE(tombstoned.has_value());
    REQUIRE(tombstoned->has_value());
    CHECK((*tombstoned)->connection_epoch == r1->epoch);

    // A genuine reconnect: register_fresh mints a strictly higher epoch and
    // reuses the SAME primary-keyed row (not a fresh insert failure/conflict).
    auto r2 = fx.store().register_fresh("agent-tomb-2", "session-new");
    REQUIRE(r2.has_value());
    CHECK(r2->won);
    CHECK(r2->epoch > r1->epoch);

    auto row = fx.store().lookup_route("agent-tomb-2");
    REQUIRE(row.has_value());
    REQUIRE(row->has_value());
    CHECK((*row)->connection_epoch == r2->epoch);
    REQUIRE((*row)->session_id.has_value());
    CHECK(*(*row)->session_id == "session-new");
}

TEST_CASE("GatewayRouteStore[pg]: renew_leases bumps lease_until only for named sessions, batched",
          "[gateway_route][pg][store]") {
    GatewayRoutePg fx;
    REQUIRE(fx.store().register_fresh("agent-6", "session-a").value().won);
    REQUIRE(fx.store().register_fresh("agent-7", "session-b").value().won);
    REQUIRE(fx.store().register_fresh("agent-8", "session-c").value().won);
    REQUIRE(fx.store().announce_connected("agent-6", "session-a", "c1", "n1", 30).value().matched);
    REQUIRE(fx.store().announce_connected("agent-7", "session-b", "c1", "n1", 30).value().matched);
    REQUIRE(fx.store().announce_connected("agent-8", "session-c", "c1", "n1", 30).value().matched);

    // Renew only session-a and session-b, in ONE batched call.
    std::vector<std::string> ids{"session-a", "session-b"};
    auto renewed = fx.store().renew_leases(ids, 3600);
    REQUIRE(renewed.has_value());
    CHECK(*renewed == 2);

    auto ra = fx.store().lookup_route("agent-6");
    auto rb = fx.store().lookup_route("agent-7");
    auto rc = fx.store().lookup_route("agent-8");
    REQUIRE(ra.has_value());
    REQUIRE(rb.has_value());
    REQUIRE(rc.has_value());
    REQUIRE((*ra)->lease_until_ms.has_value());
    REQUIRE((*rb)->lease_until_ms.has_value());
    REQUIRE((*rc)->lease_until_ms.has_value());
    // session-c was NOT in the renewal batch, so its lease is still the
    // short 30s one from announce_connected — its expiry is well before
    // session-a/b's freshly-renewed 3600s expiry.
    CHECK(*(*rc)->lease_until_ms < *(*ra)->lease_until_ms);
    CHECK(*(*rc)->lease_until_ms < *(*rb)->lease_until_ms);
}

TEST_CASE("GatewayRouteStore[pg]: renew_leases renews a session id containing a comma and a "
          "double-quote (parameter binding, not string-splicing)",
          "[gateway_route][pg][store]") {
    GatewayRoutePg fx;
    // A hand-rolled `{"..",".."}` literal would misparse a comma as an
    // element separator and a bare `"` as a premature quote-close; a real
    // ANY($1::text[]) parameter binding does neither.
    const std::string tricky_session = R"(sess,"a")";
    REQUIRE(fx.store().register_fresh("agent-tricky", tricky_session).value().won);
    REQUIRE(fx.store()
                .announce_connected("agent-tricky", tricky_session, "c1", "n1", 30)
                .value()
                .matched);

    std::vector<std::string> ids{tricky_session};
    auto renewed = fx.store().renew_leases(ids, 3600);
    REQUIRE(renewed.has_value());
    CHECK(*renewed == 1);

    auto route = fx.store().lookup_route("agent-tricky");
    REQUIRE(route.has_value());
    REQUIRE((*route)->lease_until_ms.has_value());
}

TEST_CASE("GatewayRouteStore[pg]: lookup_route reports is_stale for an expired lease",
          "[gateway_route][pg][store]") {
    GatewayRoutePg fx;
    REQUIRE(fx.store().register_fresh("agent-9", "session-1").value().won);
    // A negative TTL lands lease_until in the past.
    auto ann = fx.store().announce_connected("agent-9", "session-1", "c1", "n1", -3600);
    REQUIRE(ann.has_value());
    REQUIRE(ann->matched);

    auto row = fx.store().lookup_route("agent-9");
    REQUIRE(row.has_value());
    REQUIRE(row->has_value());
    CHECK((*row)->is_stale);
}

TEST_CASE("GatewayRouteStore[pg]: lookup_route on an unknown agent returns nullopt",
          "[gateway_route][pg][store]") {
    GatewayRoutePg fx;
    auto row = fx.store().lookup_route("no-such-agent");
    REQUIRE(row.has_value());
    CHECK_FALSE(row->has_value());
}

// --- reap_stale_routes ------------------------------------------------------

TEST_CASE("GatewayRouteStore[pg]: reap_stale_routes tombstones an expired-lease row past grace",
          "[gateway_route][pg][store][reap]") {
    GatewayRoutePg fx;
    REQUIRE(fx.store().register_fresh("agent-reap-1", "session-1").value().won);
    REQUIRE(fx.store().announce_connected("agent-reap-1", "session-1", "c1", "n1", 30).value().matched);
    // kStaleLeaseGraceSecs is 180s (2x the 90s TTL) — push well past it.
    fx.raw_set_lease_until_ago("agent-reap-1", 200);

    auto out = fx.store().reap_stale_routes();
    REQUIRE(out.has_value());
    CHECK(out->expired_leases_reaped == 1);
    CHECK(out->tombstones_reaped == 0);
    CHECK_FALSE(out->clock_anomaly);

    // Reaped means TOMBSTONED (same shape as deregister), not deleted.
    auto row = fx.store().lookup_route("agent-reap-1");
    REQUIRE(row.has_value());
    REQUIRE(row->has_value());
    CHECK_FALSE((*row)->session_id.has_value());
    CHECK_FALSE((*row)->lease_until_ms.has_value());
    CHECK_FALSE((*row)->cluster_id.has_value());
}

TEST_CASE("GatewayRouteStore[pg]: reap_stale_routes leaves an expired lease alone within grace",
          "[gateway_route][pg][store][reap]") {
    GatewayRoutePg fx;
    REQUIRE(fx.store().register_fresh("agent-reap-2", "session-1").value().won);
    REQUIRE(fx.store().announce_connected("agent-reap-2", "session-1", "c1", "n1", 30).value().matched);
    // Lease is expired (30s TTL already elapsed logically, forced past via a
    // negative lookup below) but well WITHIN the 180s grace window.
    fx.raw_set_lease_until_ago("agent-reap-2", 60);

    auto out = fx.store().reap_stale_routes();
    REQUIRE(out.has_value());
    CHECK(out->expired_leases_reaped == 0);
    CHECK(out->tombstones_reaped == 0);

    // Untouched: still session-1, lease still set (though logically expired —
    // is_stale is a separate, always-live signal from the reap grace).
    auto row = fx.store().lookup_route("agent-reap-2");
    REQUIRE(row.has_value());
    REQUIRE(row->has_value());
    REQUIRE((*row)->session_id.has_value());
    CHECK(*(*row)->session_id == "session-1");
    CHECK((*row)->lease_until_ms.has_value());
    CHECK((*row)->is_stale); // lease_until < now() — is_stale fires independent of grace
}

TEST_CASE("GatewayRouteStore[pg]: reap_stale_routes purges a tombstone past the purge age",
          "[gateway_route][pg][store][reap]") {
    GatewayRoutePg fx;
    REQUIRE(fx.store().register_fresh("agent-reap-3", "session-1").value().won);
    REQUIRE(fx.store().announce_connected("agent-reap-3", "session-1", "c1", "n1", 30).value().matched);
    REQUIRE(fx.store().deregister("agent-reap-3", "session-1").value().removed); // tombstoned
    // kTombstonePurgeAgeSecs is 300s — push well past it.
    fx.raw_set_updated_at_ago("agent-reap-3", 400);

    auto out = fx.store().reap_stale_routes();
    REQUIRE(out.has_value());
    CHECK(out->tombstones_reaped == 1);
    CHECK(out->expired_leases_reaped == 0);

    // Purged means fully GONE — not merely re-tombstoned.
    CHECK_FALSE(fx.raw_row_exists("agent-reap-3"));
    auto row = fx.store().lookup_route("agent-reap-3");
    REQUIRE(row.has_value());
    CHECK_FALSE(row->has_value());
}

TEST_CASE("GatewayRouteStore[pg]: reap_stale_routes leaves a live lease untouched",
          "[gateway_route][pg][store][reap]") {
    GatewayRoutePg fx;
    REQUIRE(fx.store().register_fresh("agent-reap-4", "session-1").value().won);
    // A generous future TTL: lease_until is well ahead of now(), so neither
    // predicate (a) (needs lease_until IS NOT NULL and past grace) nor (b)
    // (needs lease_until IS NULL) applies.
    REQUIRE(
        fx.store().announce_connected("agent-reap-4", "session-1", "c1", "n1", 3600).value().matched);

    auto out = fx.store().reap_stale_routes();
    REQUIRE(out.has_value());
    CHECK(out->expired_leases_reaped == 0);
    CHECK(out->tombstones_reaped == 0);
    CHECK_FALSE(out->clock_anomaly);

    auto row = fx.store().lookup_route("agent-reap-4");
    REQUIRE(row.has_value());
    REQUIRE(row->has_value());
    REQUIRE((*row)->session_id.has_value());
    CHECK(*(*row)->session_id == "session-1");
    CHECK_FALSE((*row)->is_stale);
}

// Bulk-insert kReapCap(5000)+1 expired-lease rows directly via SQL — looping
// register_fresh/announce_connected 5001 times would make this test the slow
// part of the suite (test_result_set_store.cpp's GC-sweep-cap idiom, part 5
// of the clock-guarded-retention rule: the cap is the half that ALWAYS
// applies).
TEST_CASE("GatewayRouteStore[pg]: reap_stale_routes caps the expired-lease sweep at kReapCap",
          "[gateway_route][pg][store][reap]") {
    GatewayRoutePg fx;
    fx.raw_bulk_insert_expired(5001, "agent-reapcap");

    auto first = fx.store().reap_stale_routes();
    REQUIRE(first.has_value());
    CHECK(first->expired_leases_reaped == 5000); // capped exactly at kReapCap
    CHECK_FALSE(first->clock_anomaly);

    auto second = fx.store().reap_stale_routes();
    REQUIRE(second.has_value());
    CHECK(second->expired_leases_reaped == 1); // second pass drains the remainder
}

TEST_CASE("GatewayRouteStore[pg]: migrates from an empty database",
          "[gateway_route][pg][store][migration]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    GatewayRouteStore store{pool};
    REQUIRE(store.is_open());
    auto row = store.lookup_route("nonexistent");
    REQUIRE(row.has_value());
    CHECK_FALSE(row->has_value());

    // v2's route_meta anchor table applied too (not just v1's agent_routes).
    yuzu::server::pg::PgConn conn{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    yuzu::server::pg::PgResult r{
        PQexec(conn.get(), "SELECT 1 FROM gateway_route_store.route_meta LIMIT 1")};
    CHECK(r.status() == PGRES_TUPLES_OK); // table exists and is queryable (empty is fine)
}

TEST_CASE("GatewayRouteStore: fail-closed construction against a closed pool",
          "[gateway_route][pg]") {
    if (yuzu::test::pg_admin_dsn_env() == nullptr)
        SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
    // An unreachable conninfo (bogus port) never connects, so acquire() at
    // construction returns an empty lease and the store must report closed
    // rather than crash or silently pretend to be open (ADR-0012 fail-closed).
    yuzu::server::pg::PgPool pool{
        {.conninfo = "host=127.0.0.1 port=1 dbname=nonexistent connect_timeout=1", .size = 1}};
    GatewayRouteStore store{pool};
    CHECK_FALSE(store.is_open());
}
