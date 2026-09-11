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

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
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

    // The DB clock in wall-clock epoch-millis (the same expression
    // reap_stale_routes reads) — mirrors test_session_store.cpp's db_now_ms.
    std::int64_t raw_db_now_ms() {
        yuzu::server::pg::PgConn conn{PQconnectdb(dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        yuzu::server::pg::PgResult r{
            PQexec(conn.get(), "SELECT (extract(epoch FROM now()) * 1000)::bigint")};
        REQUIRE(r.status() == PGRES_TUPLES_OK);
        return std::strtoll(PQgetvalue(r.get(), 0, 0), nullptr, 10);
    }

    // Write a RAW (un-sanitised) string into route_meta's reap_anchor_ms key —
    // models a hand-edited row / storage corruption / a poisoned anchor from a
    // prior forward-skewed pass. Mirrors test_session_store.cpp's
    // set_meta_raw (#3785) — the typed reap path cannot express these values.
    void raw_set_reap_anchor(const std::string& raw_value) {
        yuzu::server::pg::PgConn conn{PQconnectdb(dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        const char* p1 = raw_value.c_str();
        const char* params[1] = {p1};
        yuzu::server::pg::PgResult r{PQexecParams(
            conn.get(),
            "INSERT INTO gateway_route_store.route_meta (key, value) VALUES "
            "('reap_anchor_ms', $1) ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value",
            1, nullptr, params, nullptr, nullptr, 0)};
        REQUIRE(r.status() == PGRES_COMMAND_OK);
    }

    // Write a RAW value into route_meta's reap_declined_anchor_ms key —
    // mirrors raw_set_reap_anchor above. Used to directly CONSTRUCT the
    // "declined_anchor == anchor" recovery precondition for a chosen anchor
    // value without depending on real wall-clock time to naturally produce
    // it (PR #4299 round-2 review, FIX C cross-type recovery test): a single
    // anchor scalar cannot naturally present as forward-skewed (anchor far
    // BEHIND now) on one pass and backward-skewed (anchor AHEAD of now) on a
    // later pass, since real time only advances between passes — so the
    // cross-type scenario is constructed directly via this helper plus
    // raw_set_reap_anchor, rather than waited-for.
    void raw_set_reap_declined_anchor(const std::string& raw_value) {
        yuzu::server::pg::PgConn conn{PQconnectdb(dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        const char* p1 = raw_value.c_str();
        const char* params[1] = {p1};
        yuzu::server::pg::PgResult r{PQexecParams(
            conn.get(),
            "INSERT INTO gateway_route_store.route_meta (key, value) VALUES "
            "('reap_declined_anchor_ms', $1) ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value",
            1, nullptr, params, nullptr, nullptr, 0)};
        REQUIRE(r.status() == PGRES_COMMAND_OK);
    }

    // The persisted declined-anchor marker's raw string value, or nullopt if
    // not set — for asserting a recovered/accepted pass CLEARS it.
    std::optional<std::string> raw_get_reap_declined_anchor() {
        yuzu::server::pg::PgConn conn{PQconnectdb(dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        yuzu::server::pg::PgResult r{PQexec(
            conn.get(),
            "SELECT value FROM gateway_route_store.route_meta WHERE "
            "key='reap_declined_anchor_ms'")};
        REQUIRE(r.status() == PGRES_TUPLES_OK);
        if (PQntuples(r.get()) == 0)
            return std::nullopt;
        return std::string(PQgetvalue(r.get(), 0, 0));
    }

    // The persisted anchor's raw string value, or nullopt if never set — for
    // asserting a DECLINED pass leaves it byte-for-byte unchanged.
    std::optional<std::string> raw_get_reap_anchor() {
        yuzu::server::pg::PgConn conn{PQconnectdb(dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        yuzu::server::pg::PgResult r{PQexec(
            conn.get(),
            "SELECT value FROM gateway_route_store.route_meta WHERE key='reap_anchor_ms'")};
        REQUIRE(r.status() == PGRES_TUPLES_OK);
        if (PQntuples(r.get()) == 0)
            return std::nullopt;
        return std::string(PQgetvalue(r.get(), 0, 0));
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

// Block until a backend OTHER than this polling connection is waiting on a
// lock, or give up. Mirrors test_settings_routes_ota_audit.cpp's
// wait_for_lock_waiter and the #4213 UP-3 self-heal side-lock rendezvous:
// polling pg_stat_activity for genuinely-observed lock contention, rather
// than sleeping a fixed duration, is what makes the rendezvous deterministic
// instead of a timing assumption. A bounded ceiling exists so a genuine
// absence of blocking FAILS the caller's REQUIRE rather than hanging.
[[nodiscard]] bool wait_for_lock_waiter(PGconn* conn) {
    for (int i = 0; i < 400; ++i) { // ~10s ceiling, far above any real wait
        yuzu::server::pg::PgResult r{
            PQexec(conn, "SELECT count(*) FROM pg_stat_activity "
                         "WHERE datname = current_database() "
                         "AND wait_event_type = 'Lock' "
                         "AND pid <> pg_backend_pid()")};
        if (r.status() == PGRES_TUPLES_OK && PQntuples(r.get()) == 1 &&
            std::string(PQgetvalue(r.get(), 0, 0)) != "0")
            return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }
    return false;
}

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

// ---------------------------------------------------------------------------
// Governance fix #2 (cpp-safety/quality-engineer/unhappy-path): drive
// clock_anomaly == true via all four seeded-anchor scenarios the reviewers
// named. Every case first runs ONE clean pass to establish a real persisted
// anchor (part 6 PROCEEDs on the first/no-anchor pass, so the anomaly guards
// below need a pre-existing anchor to compare against), seeds a LIVE row
// (future lease) and a genuinely-STALE row (past grace) so a declined pass's
// "touches nothing" guarantee is checked against both shapes, then asserts:
// clock_anomaly, zero reaps, the anchor byte-for-byte unchanged, and both
// rows untouched.

TEST_CASE("GatewayRouteStore[pg]: reap declines a forward-skew anomaly ONCE, then RECOVERS "
          "and drains on an identical repeat (decline-once/drain-on-repeat, PR #4299 review "
          "BLOCKER 1)",
          "[gateway_route][pg][store][reap]") {
    GatewayRoutePg fx;
    auto baseline = fx.store().reap_stale_routes(); // establishes a real anchor
    REQUIRE(baseline.has_value());
    CHECK_FALSE(baseline->clock_anomaly);

    REQUIRE(fx.store().register_fresh("agent-fwd-live", "s-live").value().won);
    REQUIRE(fx.store()
                .announce_connected("agent-fwd-live", "s-live", "c1", "n1", 3600)
                .value()
                .matched);
    REQUIRE(fx.store().register_fresh("agent-fwd-stale", "s-stale").value().won);
    REQUIRE(fx.store()
                .announce_connected("agent-fwd-stale", "s-stale", "c1", "n1", 30)
                .value()
                .matched);
    fx.raw_set_lease_until_ago("agent-fwd-stale", 200); // past the 180s grace

    // now_ms - anchor > kMaxPlausibleSkewMs (1 day): poison the anchor 2 days
    // behind the current DB clock.
    const std::string poisoned = std::to_string(fx.raw_db_now_ms() - 2LL * 24 * 3600 * 1000);
    fx.raw_set_reap_anchor(poisoned);

    // Pass 1: DECLINES — identical to the pre-fix behaviour. The anchor is
    // frozen and nothing is reaped.
    auto out1 = fx.store().reap_stale_routes();
    REQUIRE(out1.has_value());
    CHECK(out1->clock_anomaly);
    CHECK(out1->expired_leases_reaped == 0);
    CHECK(out1->tombstones_reaped == 0);

    auto anchor_after1 = fx.raw_get_reap_anchor();
    REQUIRE(anchor_after1.has_value());
    CHECK(*anchor_after1 == poisoned); // a declined pass never advances the anchor

    auto live1 = fx.store().lookup_route("agent-fwd-live");
    REQUIRE(live1.has_value());
    REQUIRE(live1->has_value());
    REQUIRE((*live1)->session_id.has_value());
    CHECK(*(*live1)->session_id == "s-live");
    auto stale1 = fx.store().lookup_route("agent-fwd-stale");
    REQUIRE(stale1.has_value());
    REQUIRE(stale1->has_value());
    REQUIRE((*stale1)->session_id.has_value());
    CHECK(*(*stale1)->session_id == "s-stale"); // NOT tombstoned by the declined pass

    // Pass 2: the anchor is STILL the same poisoned value (pass 1 never
    // advanced it), so the identical anomaly persisting across a FULL
    // decline pass is exactly what BLOCKER 1's fix treats as genuine
    // elapsed downtime — this is the recovery this fix exists to provide;
    // without it, this pass would decline forever (the pre-fix wedge).
    auto out2 = fx.store().reap_stale_routes();
    REQUIRE(out2.has_value());
    CHECK_FALSE(out2->clock_anomaly); // recovered, not a further decline
    CHECK(out2->expired_leases_reaped == 1); // agent-fwd-stale, past grace
    CHECK(out2->tombstones_reaped == 0);

    auto live2 = fx.store().lookup_route("agent-fwd-live");
    REQUIRE(live2.has_value());
    REQUIRE(live2->has_value());
    REQUIRE((*live2)->session_id.has_value());
    CHECK(*(*live2)->session_id == "s-live"); // untouched — its lease is not expired

    auto stale2 = fx.store().lookup_route("agent-fwd-stale");
    REQUIRE(stale2.has_value());
    REQUIRE(stale2->has_value());
    CHECK_FALSE((*stale2)->session_id.has_value()); // tombstoned by the recovered pass

    // The anchor re-anchored to (approximately) the current DB clock —
    // UNCONDITIONALLY, not max(anchor, now_ms), which would have left it
    // stuck at the poisoned value forever.
    auto anchor_after2 = fx.raw_get_reap_anchor();
    REQUIRE(anchor_after2.has_value());
    const std::int64_t anchor2 = std::strtoll(anchor_after2->c_str(), nullptr, 10);
    const std::int64_t poisoned_val = std::strtoll(poisoned.c_str(), nullptr, 10);
    CHECK(anchor2 > poisoned_val + 1LL * 24 * 3600 * 1000); // re-anchored, not stuck
}

TEST_CASE("GatewayRouteStore[pg]: a routine >24h gap between accepted passes (weekend "
          "shutdown / DR failover / extended maintenance) declines once then recovers, "
          "draining ONLY the genuinely-expired row (PR #4299 review BLOCKER 1)",
          "[gateway_route][pg][store][reap]") {
    GatewayRoutePg fx;
    auto baseline = fx.store().reap_stale_routes(); // establishes a real anchor
    REQUIRE(baseline.has_value());
    CHECK_FALSE(baseline->clock_anomaly);

    REQUIRE(fx.store().register_fresh("agent-gap-live", "s-live").value().won);
    REQUIRE(fx.store()
                .announce_connected("agent-gap-live", "s-live", "c1", "n1", 3600)
                .value()
                .matched);
    REQUIRE(fx.store().register_fresh("agent-gap-expired", "s-expired").value().won);
    REQUIRE(fx.store()
                .announce_connected("agent-gap-expired", "s-expired", "c1", "n1", 30)
                .value()
                .matched);
    fx.raw_set_lease_until_ago("agent-gap-expired", 200); // past the 180s grace

    // Simulate a routine >24h gap between accepted passes — NOT clock
    // corruption, just a server that was down/idle for a bit over a day, so
    // the last accepted anchor is now stale relative to the real DB clock.
    const std::int64_t now_before = fx.raw_db_now_ms();
    const std::string stale_anchor = std::to_string(now_before - 25LL * 3600 * 1000);
    fx.raw_set_reap_anchor(stale_anchor);

    // Pass 1: declines — the forward-skew guard cannot yet distinguish a
    // real gap from a clock glitch on the first observation.
    auto out1 = fx.store().reap_stale_routes();
    REQUIRE(out1.has_value());
    CHECK(out1->clock_anomaly);
    CHECK(out1->expired_leases_reaped == 0);
    CHECK(out1->tombstones_reaped == 0);
    auto anchor_after1 = fx.raw_get_reap_anchor();
    REQUIRE(anchor_after1.has_value());
    CHECK(*anchor_after1 == stale_anchor);

    // Pass 2: the identical anomaly persisted across a full pass — RECOVERS,
    // draining only the row that is genuinely past its grace window.
    auto out2 = fx.store().reap_stale_routes();
    REQUIRE(out2.has_value());
    CHECK_FALSE(out2->clock_anomaly);
    CHECK(out2->expired_leases_reaped == 1);
    CHECK(out2->tombstones_reaped == 0);

    auto live = fx.store().lookup_route("agent-gap-live");
    REQUIRE(live.has_value());
    REQUIRE(live->has_value());
    REQUIRE((*live)->session_id.has_value());
    CHECK(*(*live)->session_id == "s-live"); // untouched

    auto expired = fx.store().lookup_route("agent-gap-expired");
    REQUIRE(expired.has_value());
    REQUIRE(expired->has_value());
    CHECK_FALSE((*expired)->session_id.has_value()); // tombstoned

    auto anchor_after2 = fx.raw_get_reap_anchor();
    REQUIRE(anchor_after2.has_value());
    const std::int64_t anchor2 = std::strtoll(anchor_after2->c_str(), nullptr, 10);
    CHECK(anchor2 >= now_before); // re-anchored to ~now, not stuck at the stale value
}

TEST_CASE("GatewayRouteStore[pg]: a single glitched forward-skew pass reaps NOTHING at all, "
          "even with many genuinely-expired rows present — the guard still prevents a "
          "mass-reap on the one declined pass (PR #4299 review BLOCKER 1)",
          "[gateway_route][pg][store][reap]") {
    GatewayRoutePg fx;
    auto baseline = fx.store().reap_stale_routes();
    REQUIRE(baseline.has_value());
    CHECK_FALSE(baseline->clock_anomaly);

    // Bulk-seed a pile of genuinely sweep-(a)-eligible rows — if the
    // decline-once/drain-on-repeat fix regressed into "decline only holds
    // back the first row" or some other partial-suppression bug, this shape
    // catches it: every one of these rows is a legitimate reap candidate.
    fx.raw_bulk_insert_expired(50, "agent-glitch-bulk-");
    REQUIRE(fx.store().register_fresh("agent-glitch-live", "s-live").value().won);
    REQUIRE(fx.store()
                .announce_connected("agent-glitch-live", "s-live", "c1", "n1", 3600)
                .value()
                .matched);

    // A single forward-skew glitch (mirrors the existing forward-skew
    // poisoning shape): this ONE pass must decline outright and touch
    // nothing, regardless of how much genuinely-reapable data exists.
    const std::string poisoned = std::to_string(fx.raw_db_now_ms() - 2LL * 24 * 3600 * 1000);
    fx.raw_set_reap_anchor(poisoned);

    auto out = fx.store().reap_stale_routes();
    REQUIRE(out.has_value());
    CHECK(out->clock_anomaly);
    CHECK(out->expired_leases_reaped == 0);
    CHECK(out->tombstones_reaped == 0);

    // Every one of the 50 genuinely-expired rows survives the single
    // declined pass untouched — the guard does not "let a few through".
    for (int i = 1; i <= 50; ++i) {
        char buf[16];
        std::snprintf(buf, sizeof buf, "%06d", i);
        CHECK(fx.raw_row_exists(std::string("agent-glitch-bulk-") + buf));
    }
    auto live = fx.store().lookup_route("agent-glitch-live");
    REQUIRE(live.has_value());
    REQUIRE(live->has_value());
    REQUIRE((*live)->session_id.has_value());
    CHECK(*(*live)->session_id == "s-live");
}

TEST_CASE("GatewayRouteStore[pg]: reap declines when the anchor is AHEAD of the DB clock "
          "(backward/poisoned)",
          "[gateway_route][pg][store][reap]") {
    GatewayRoutePg fx;
    auto baseline = fx.store().reap_stale_routes();
    REQUIRE(baseline.has_value());
    CHECK_FALSE(baseline->clock_anomaly);

    REQUIRE(fx.store().register_fresh("agent-bwd-live", "s-live").value().won);
    REQUIRE(fx.store()
                .announce_connected("agent-bwd-live", "s-live", "c1", "n1", 3600)
                .value()
                .matched);
    REQUIRE(fx.store().register_fresh("agent-bwd-stale", "s-stale").value().won);
    REQUIRE(fx.store()
                .announce_connected("agent-bwd-stale", "s-stale", "c1", "n1", 30)
                .value()
                .matched);
    fx.raw_set_lease_until_ago("agent-bwd-stale", 200);

    // Anchor 1h AHEAD of the DB clock -> now_ms < anchor -> backward decline.
    const std::string poisoned = std::to_string(fx.raw_db_now_ms() + 3600LL * 1000);
    fx.raw_set_reap_anchor(poisoned);

    auto out = fx.store().reap_stale_routes();
    REQUIRE(out.has_value());
    CHECK(out->clock_anomaly);
    CHECK(out->expired_leases_reaped == 0);
    CHECK(out->tombstones_reaped == 0);

    auto anchor_after = fx.raw_get_reap_anchor();
    REQUIRE(anchor_after.has_value());
    CHECK(*anchor_after == poisoned);

    auto live = fx.store().lookup_route("agent-bwd-live");
    REQUIRE(live.has_value());
    REQUIRE(live->has_value());
    REQUIRE((*live)->session_id.has_value());
    CHECK(*(*live)->session_id == "s-live");
    auto stale = fx.store().lookup_route("agent-bwd-stale");
    REQUIRE(stale.has_value());
    REQUIRE(stale->has_value());
    REQUIRE((*stale)->session_id.has_value());
    CHECK(*(*stale)->session_id == "s-stale");
}

// PR #4299 round-2 review, FIX C: recovery is keyed on the ANCHOR VALUE only
// (`declined_anchor == anchor`), never on which direction (forward vs.
// backward) triggered either this pass's own anomaly or the anomaly that
// froze `declined_anchor` in the first place. This test proves the
// cross-type case: pass 1 is a genuine, real FORWARD-skew decline (anchor
// implausibly BEHIND the DB clock; identical mechanism to the "declines a
// forward-skew anomaly ONCE" test above), demonstrating the decline
// mechanism persists `reap_declined_anchor_ms` exactly as documented. A real
// anchor scalar cannot then naturally flip to presenting as BACKWARD-skewed
// (anchor AHEAD of the clock) on a very-shortly-after pass 2, since real
// wall-clock time only advances between passes — so pass 2's precondition
// (current anchor == persisted declined_anchor, with the CURRENT anchor
// positioned ahead of "now") is constructed directly via
// raw_set_reap_anchor + raw_set_reap_declined_anchor, both set to the SAME
// new value. This is the same test technique every other decline/recover
// case in this file already uses (a raw-seeded anchor standing in for
// "whatever a prior pass would have left behind") — here applied to BOTH
// meta keys so pass 2 is unambiguously classified as a BACKWARD-skew
// recovery against a declined_anchor that (by construction) could only
// really have been frozen by a backward decline, while pass 1 above
// independently proves the freezing mechanism works for the FORWARD
// direction too. Together they demonstrate the match is anchor-value-keyed,
// not direction-keyed: recovery does not care, and must not care, which
// direction produced either side of the comparison.
TEST_CASE("GatewayRouteStore[pg]: a forward-skew decline followed by a backward-skew repeat "
          "at the SAME (re-seeded) declined anchor RECOVERS, UNDER-reaps (the live row "
          "survives), and reports recovered=true, not just clock_anomaly=false (PR #4299 "
          "round-2 review, FIX C cross-type recovery)",
          "[gateway_route][pg][store][reap]") {
    GatewayRoutePg fx;
    auto baseline = fx.store().reap_stale_routes(); // establishes a real anchor
    REQUIRE(baseline.has_value());
    CHECK_FALSE(baseline->clock_anomaly);
    CHECK_FALSE(baseline->recovered);

    REQUIRE(fx.store().register_fresh("agent-mix-live", "s-live").value().won);
    REQUIRE(fx.store()
                .announce_connected("agent-mix-live", "s-live", "c1", "n1", 3600)
                .value()
                .matched);
    REQUIRE(fx.store().register_fresh("agent-mix-expired", "s-expired").value().won);
    REQUIRE(fx.store()
                .announce_connected("agent-mix-expired", "s-expired", "c1", "n1", 30)
                .value()
                .matched);
    fx.raw_set_lease_until_ago("agent-mix-expired", 200); // past the 180s grace

    // Pass 1 (REAL forward-skew decline): anchor implausibly BEHIND the DB
    // clock. Identical to the standalone forward-decline test above — this
    // is not manufactured, it is the store's genuine decline behaviour.
    const std::string forward_poisoned =
        std::to_string(fx.raw_db_now_ms() - 2LL * 24 * 3600 * 1000);
    fx.raw_set_reap_anchor(forward_poisoned);

    auto out1 = fx.store().reap_stale_routes();
    REQUIRE(out1.has_value());
    CHECK(out1->clock_anomaly);
    CHECK_FALSE(out1->recovered);
    CHECK(out1->expired_leases_reaped == 0);
    CHECK(out1->tombstones_reaped == 0);
    // The real decline persisted declined_anchor == forward_poisoned, and
    // left reap_anchor_ms unchanged at forward_poisoned too.
    auto declined_after1 = fx.raw_get_reap_declined_anchor();
    REQUIRE(declined_after1.has_value());
    CHECK(*declined_after1 == forward_poisoned);
    auto anchor_after1 = fx.raw_get_reap_anchor();
    REQUIRE(anchor_after1.has_value());
    CHECK(*anchor_after1 == forward_poisoned);

    // Construct pass 2's precondition directly: re-seed BOTH meta keys to
    // the SAME new value, positioned AHEAD of the current DB clock, so this
    // pass classifies as BACKWARD-skew (now_ms < anchor) against a
    // declined_anchor that matches the current anchor exactly ->
    // declined_anchor == anchor -> RECOVERS, via the opposite direction from
    // pass 1's own decline.
    const std::string backward_anchor =
        std::to_string(fx.raw_db_now_ms() + 2LL * 24 * 3600 * 1000);
    fx.raw_set_reap_anchor(backward_anchor);
    fx.raw_set_reap_declined_anchor(backward_anchor);

    auto out2 = fx.store().reap_stale_routes();
    REQUIRE(out2.has_value());
    CHECK_FALSE(out2->clock_anomaly); // recovered, not declined again
    CHECK(out2->recovered);           // distinct signal from an ordinary "ok" pass
    // UNDER-reaps: the recovery branch computes its cutoffs from THIS pass's
    // own (real, current, correct) now_ms -- never from the artificially
    // future anchor -- so it reaps exactly what a normal pass would: the
    // genuinely-expired row, and nothing more.
    CHECK(out2->expired_leases_reaped == 1);
    CHECK(out2->tombstones_reaped == 0);

    auto live = fx.store().lookup_route("agent-mix-live");
    REQUIRE(live.has_value());
    REQUIRE(live->has_value());
    REQUIRE((*live)->session_id.has_value());
    CHECK(*(*live)->session_id == "s-live"); // SURVIVES: backward under-reaps, never mass-reaps

    auto expired = fx.store().lookup_route("agent-mix-expired");
    REQUIRE(expired.has_value());
    REQUIRE(expired->has_value());
    CHECK_FALSE((*expired)->session_id.has_value()); // tombstoned by the recovered pass

    // Recovery re-anchors UNCONDITIONALLY to this pass's real now_ms, moving
    // decisively off the artificially-future backward_anchor, and clears the
    // declined marker.
    auto anchor_after2 = fx.raw_get_reap_anchor();
    REQUIRE(anchor_after2.has_value());
    const std::int64_t anchor2 = std::strtoll(anchor_after2->c_str(), nullptr, 10);
    const std::int64_t backward_anchor_val = std::strtoll(backward_anchor.c_str(), nullptr, 10);
    CHECK(anchor2 < backward_anchor_val); // NOT max(anchor, now_ms) -- moved decisively off it
    CHECK_FALSE(fx.raw_get_reap_declined_anchor().has_value());
}

TEST_CASE("GatewayRouteStore[pg]: reap declines a non-numeric (junk) persisted anchor",
          "[gateway_route][pg][store][reap]") {
    GatewayRoutePg fx;
    auto baseline = fx.store().reap_stale_routes();
    REQUIRE(baseline.has_value());
    CHECK_FALSE(baseline->clock_anomaly);

    REQUIRE(fx.store().register_fresh("agent-junk-live", "s-live").value().won);
    REQUIRE(fx.store()
                .announce_connected("agent-junk-live", "s-live", "c1", "n1", 3600)
                .value()
                .matched);
    REQUIRE(fx.store().register_fresh("agent-junk-stale", "s-stale").value().won);
    REQUIRE(fx.store()
                .announce_connected("agent-junk-stale", "s-stale", "c1", "n1", 30)
                .value()
                .matched);
    fx.raw_set_lease_until_ago("agent-junk-stale", 200);

    fx.raw_set_reap_anchor("not-a-number");

    auto out = fx.store().reap_stale_routes();
    REQUIRE(out.has_value());
    CHECK(out->clock_anomaly);
    CHECK(out->expired_leases_reaped == 0);
    CHECK(out->tombstones_reaped == 0);

    auto anchor_after = fx.raw_get_reap_anchor();
    REQUIRE(anchor_after.has_value());
    CHECK(*anchor_after == "not-a-number");

    auto live = fx.store().lookup_route("agent-junk-live");
    REQUIRE(live.has_value());
    REQUIRE(live->has_value());
    REQUIRE((*live)->session_id.has_value());
    CHECK(*(*live)->session_id == "s-live");
    auto stale = fx.store().lookup_route("agent-junk-stale");
    REQUIRE(stale.has_value());
    REQUIRE(stale->has_value());
    REQUIRE((*stale)->session_id.has_value());
    CHECK(*(*stale)->session_id == "s-stale");
}

TEST_CASE("GatewayRouteStore[pg]: reap declines a negative persisted anchor",
          "[gateway_route][pg][store][reap]") {
    GatewayRoutePg fx;
    auto baseline = fx.store().reap_stale_routes();
    REQUIRE(baseline.has_value());
    CHECK_FALSE(baseline->clock_anomaly);

    REQUIRE(fx.store().register_fresh("agent-neg-live", "s-live").value().won);
    REQUIRE(fx.store()
                .announce_connected("agent-neg-live", "s-live", "c1", "n1", 3600)
                .value()
                .matched);
    REQUIRE(fx.store().register_fresh("agent-neg-stale", "s-stale").value().won);
    REQUIRE(fx.store()
                .announce_connected("agent-neg-stale", "s-stale", "c1", "n1", 30)
                .value()
                .matched);
    fx.raw_set_lease_until_ago("agent-neg-stale", 200);

    fx.raw_set_reap_anchor("-5");

    auto out = fx.store().reap_stale_routes();
    REQUIRE(out.has_value());
    CHECK(out->clock_anomaly);
    CHECK(out->expired_leases_reaped == 0);
    CHECK(out->tombstones_reaped == 0);

    auto anchor_after = fx.raw_get_reap_anchor();
    REQUIRE(anchor_after.has_value());
    CHECK(*anchor_after == "-5");

    auto live = fx.store().lookup_route("agent-neg-live");
    REQUIRE(live.has_value());
    REQUIRE(live->has_value());
    REQUIRE((*live)->session_id.has_value());
    CHECK(*(*live)->session_id == "s-live");
    auto stale = fx.store().lookup_route("agent-neg-stale");
    REQUIRE(stale.has_value());
    REQUIRE(stale->has_value());
    REQUIRE((*stale)->session_id.has_value());
    CHECK(*(*stale)->session_id == "s-stale");
}

// ---------------------------------------------------------------------------
// Governance fix #4 (cpp-safety + unhappy-path UP-4): the outer UPDATE in
// sweep (a) re-asserts the expired predicate, not just `agent_id IN (...)` —
// a row renewed to a future lease must never be tombstoned. A prior version
// of this case renewed and COMMITTED before calling reap_stale_routes(),
// which never exercises the re-assert at all: the inner subquery's own
// snapshot already excludes a row that was renewed and committed first, so
// the outer re-check is redundant with the subquery and the case passes
// identically with FIX 4 present or reverted (a false green).
//
// The genuine race needs the renew to land INSIDE the reaper's
// snapshot-to-row-lock window: a concurrent transaction commits a
// future-lease UPDATE only AFTER the reaper's row-lock attempt blocks on it,
// forcing PostgreSQL's EvalPlanQual to re-check the outer UPDATE's WHERE
// against the freshly-committed row version. Deterministic via the #4213
// UP-3 self-heal side-lock pattern: hold the row lock in an open
// transaction, launch the reaper on its own thread, poll pg_stat_activity
// until it is observed genuinely blocked, THEN commit.
TEST_CASE("GatewayRouteStore[pg]: reap does not tombstone a row renewed to a future lease "
          "(outer-UPDATE re-assert, governance fix #4)",
          "[gateway_route][pg][store][reap]") {
    GatewayRoutePg fx;
    REQUIRE(fx.store().register_fresh("agent-reap-epq", "session-1").value().won);
    REQUIRE(fx.store()
                .announce_connected("agent-reap-epq", "session-1", "c1", "n1", 30)
                .value()
                .matched);
    fx.raw_set_lease_until_ago("agent-reap-epq", 200); // past the 180s grace, committed

    // Holder: BEGINs a future-lease UPDATE on the row and does NOT commit —
    // this takes the row lock while leaving the OLD (expired, committed)
    // lease_until the only version any OTHER transaction can see under READ
    // COMMITTED. The reaper's inner subquery therefore still legitimately
    // selects this agent_id as a candidate.
    yuzu::server::pg::PgConn holder{PQconnectdb(fx.dsn().c_str())};
    REQUIRE(PQstatus(holder.get()) == CONNECTION_OK);
    {
        yuzu::server::pg::PgResult begin{PQexec(holder.get(), "BEGIN")};
        REQUIRE(begin.status() == PGRES_COMMAND_OK);
        yuzu::server::pg::PgResult upd{PQexec(
            holder.get(), "UPDATE gateway_route_store.agent_routes SET "
                          "  lease_until = now() + interval '1 hour', updated_at = now() "
                          "WHERE agent_id = 'agent-reap-epq'")};
        REQUIRE(upd.status() == PGRES_COMMAND_OK);
    }

    // Run the reaper on its own thread, against the SAME store (its pool has
    // spare connections beyond the one the holder above uses directly). Its
    // sweep-(a) outer UPDATE selects agent-reap-epq via the subquery, then
    // blocks taking the row lock the holder connection is sitting on.
    std::expected<ReapRoutesResult, GatewayRouteStoreError> out;
    std::thread reaper([&] { out = fx.store().reap_stale_routes(); });

    // Side connection used ONLY to observe pg_stat_activity — never touches
    // the row itself, so its own presence cannot perturb the race.
    yuzu::server::pg::PgConn watcher{PQconnectdb(fx.dsn().c_str())};
    REQUIRE(PQstatus(watcher.get()) == CONNECTION_OK);
    const bool blocked = wait_for_lock_waiter(watcher.get());
    REQUIRE(blocked); // if nothing ever blocks, nothing locked the row, and
                       // the race this test exists to force never happened.

    // Only now does the future-lease version become visible to the blocked
    // reaper — exactly the window governance fix #4's outer-WHERE re-assert
    // defends via EvalPlanQual.
    {
        yuzu::server::pg::PgResult commit{PQexec(holder.get(), "COMMIT")};
        REQUIRE(commit.status() == PGRES_COMMAND_OK);
    }

    reaper.join();

    REQUIRE(out.has_value());
    CHECK_FALSE(out->clock_anomaly);
    // The renewed-under-EPQ row must not be counted as reaped.
    CHECK(out->expired_leases_reaped == 0);

    auto row = fx.store().lookup_route("agent-reap-epq");
    REQUIRE(row.has_value());
    REQUIRE(row->has_value());
    REQUIRE((*row)->session_id.has_value());
    CHECK(*(*row)->session_id == "session-1");
    CHECK_FALSE((*row)->is_stale);
}

// ---------------------------------------------------------------------------
// PR #4299 review, BLOCKER 2 (mechanical): sweep (b) (the NULL-lease/
// tombstone-purge DELETE) was missing the outer-WHERE re-assert sweep (a)
// got from governance fix #4 above — its outer DELETE checked only
// `agent_id IN (...)`, so a route a concurrent register_fresh/
// announce_connected just revived (setting a fresh session_id/updated_at
// while the DELETE was blocked on the row lock) would still be deleted once
// the lock released. Same #4213 UP-3 self-heal side-lock rendezvous pattern
// as the sweep-(a) case above, driving the exact EvalPlanQual window: the
// holder's UPDATE mirrors register_fresh's real re-registration UPSERT
// shape (fresh session_id, lease_until reset to NULL, updated_at = now()) so
// the inner subquery's stale-snapshot candidate becomes, by the time the
// outer DELETE takes the row lock, a row that no longer matches either the
// `lease_until IS NULL`-past-purge-age shape's cutoff (updated_at is now
// fresh) — exactly the case the outer re-assert exists to catch.
TEST_CASE("GatewayRouteStore[pg]: reap does not purge a tombstoned row concurrently revived "
          "by a fresh register_fresh (outer-DELETE re-assert, PR #4299 review BLOCKER 2)",
          "[gateway_route][pg][store][reap]") {
    GatewayRoutePg fx;
    REQUIRE(fx.store().register_fresh("agent-reap-epq-b", "session-b1").value().won);
    REQUIRE(fx.store()
                .announce_connected("agent-reap-epq-b", "session-b1", "c1", "n1", 30)
                .value()
                .matched);
    REQUIRE(fx.store().deregister("agent-reap-epq-b", "session-b1").value().removed);
    // Past the 300s tombstone purge age, committed — a genuine sweep-(b)
    // candidate as far as any snapshot taken before the revive below is
    // concerned.
    fx.raw_set_updated_at_ago("agent-reap-epq-b", 400);

    // Holder: BEGINs a revive UPDATE on the row and does NOT commit — this
    // takes the row lock while leaving the OLD (tombstoned, committed)
    // updated_at the only version any OTHER transaction can see under READ
    // COMMITTED. The reaper's inner subquery therefore still legitimately
    // selects this agent_id as a sweep-(b) candidate.
    yuzu::server::pg::PgConn holder{PQconnectdb(fx.dsn().c_str())};
    REQUIRE(PQstatus(holder.get()) == CONNECTION_OK);
    {
        yuzu::server::pg::PgResult begin{PQexec(holder.get(), "BEGIN")};
        REQUIRE(begin.status() == PGRES_COMMAND_OK);
        // Mirrors register_fresh's real re-registration UPSERT shape: a
        // fresh session_id, lease_until reset to NULL (register_fresh always
        // resets it — the winning connection's own announce_connected/renew
        // sets it later), updated_at = now().
        yuzu::server::pg::PgResult upd{PQexec(
            holder.get(), "UPDATE gateway_route_store.agent_routes SET "
                          "  connection_epoch = connection_epoch + 1, "
                          "  session_id = 'session-b2', lease_until = NULL, updated_at = now() "
                          "WHERE agent_id = 'agent-reap-epq-b'")};
        REQUIRE(upd.status() == PGRES_COMMAND_OK);
    }

    // Run the reaper on its own thread, against the SAME store. Its
    // sweep-(b) outer DELETE selects agent-reap-epq-b via the subquery, then
    // blocks taking the row lock the holder connection is sitting on.
    std::expected<ReapRoutesResult, GatewayRouteStoreError> out;
    std::thread reaper([&] { out = fx.store().reap_stale_routes(); });

    yuzu::server::pg::PgConn watcher{PQconnectdb(fx.dsn().c_str())};
    REQUIRE(PQstatus(watcher.get()) == CONNECTION_OK);
    const bool blocked = wait_for_lock_waiter(watcher.get());
    REQUIRE(blocked); // if nothing ever blocks, the race this test exists to
                       // force never happened.

    // Only now does the revived version become visible to the blocked
    // reaper — exactly the window BLOCKER 2's outer-WHERE re-assert defends
    // via EvalPlanQual.
    {
        yuzu::server::pg::PgResult commit{PQexec(holder.get(), "COMMIT")};
        REQUIRE(commit.status() == PGRES_COMMAND_OK);
    }

    reaper.join();

    REQUIRE(out.has_value());
    CHECK_FALSE(out->clock_anomaly);
    // The concurrently-revived row must not be counted as purged. THIS IS
    // THE DISCRIMINATING ASSERTION: revert the outer-WHERE re-assert (drop
    // the trailing `AND lease_until IS NULL AND (...) < $1::bigint` from
    // sweep (b)'s DELETE) and this goes to 1 with the row deleted — the test
    // fails without the fix and passes with it.
    CHECK(out->tombstones_reaped == 0);

    REQUIRE(fx.raw_row_exists("agent-reap-epq-b")); // NOT deleted
    auto row = fx.store().lookup_route("agent-reap-epq-b");
    REQUIRE(row.has_value());
    REQUIRE(row->has_value());
    REQUIRE((*row)->session_id.has_value());
    CHECK(*(*row)->session_id == "session-b2"); // the revived session, untouched
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

// Governance fix #5 (quality-engineer QE-5): reap_stale_routes() itself must
// report the same fail-closed store_unavailable a closed/unreachable pool
// gives every other method — mirrors the construction test directly above.
TEST_CASE("GatewayRouteStore: reap_stale_routes fails closed against a closed pool",
          "[gateway_route][pg]") {
    if (yuzu::test::pg_admin_dsn_env() == nullptr)
        SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
    yuzu::server::pg::PgPool pool{
        {.conninfo = "host=127.0.0.1 port=1 dbname=nonexistent connect_timeout=1", .size = 1}};
    GatewayRouteStore store{pool};
    REQUIRE_FALSE(store.is_open());
    auto out = store.reap_stale_routes();
    REQUIRE_FALSE(out.has_value());
    CHECK(out.error() == GatewayRouteStoreError::store_unavailable);
}
