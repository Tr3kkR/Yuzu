// test_gateway_route_wiring.cpp — HA WS-4 slice 4.1 SERVER WIRING coverage.
//
// GatewayRouteStore's own methods are already pinned in isolation
// (test_gateway_route_store.cpp, [gateway_route]). What that file does NOT
// cover is GatewayUpstreamServiceImpl (gateway_service_impl.cpp) actually
// DRIVING the store — in particular the one genuinely NEW decision branch
// this slice introduced:
//
//   ProxyRegister re-announce vs fresh. When the caller presents a
//   x-yuzu-session-id metadata value AND that session is still known
//   server-side (gateway_sessions_), ProxyRegister must REUSE it (renew_leases)
//   rather than mint a fresh session+epoch (register_fresh) — the latter would
//   let a delayed circuit-recovery replay clobber a route a newer connection
//   already won.
//
// Plus the CONNECTED -> announce_connected, DISCONNECTED -> deregister, and
// BatchHeartbeat -> renew_leases call sites, and the fail-OPEN posture (a
// degraded directory write never fails the RPC).
//
// Every assertion below is against the store's OBSERVABLE row state
// (lookup_route), not just "the RPC returned OK" — an RPC returning OK proves
// nothing about which store call actually fired.
//
// The re-announce / unknown-session cases need a REAL grpc::ServerContext
// carrying client_metadata() — that cannot be constructed outside an actual
// RPC (see test_grpc_on_behalf_enforce.cpp's note to the same effect), so
// this file spins a real grpc::Server + stub for those two cases only. Every
// other case drives the handler directly with context=nullptr, exactly like
// the existing ProxyRegister suite in test_agent_service_impl.cpp.

#include "gateway_service_impl.hpp"

#include <catch2/catch_test_macros.hpp>

#include <grpcpp/grpcpp.h>

#include "agent_registry.hpp"
#include "agent_service_impl.hpp"
#include "event_bus.hpp"
#include "gateway_route_store.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>
#include <yuzu/server/auto_approve.hpp>

#include "../test_helpers.hpp"

#include <libpq-fe.h>

#include <chrono>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>

using yuzu::server::detail::AgentRegistry;
using yuzu::server::detail::AgentServiceImpl;
using yuzu::server::detail::EventBus;
using yuzu::server::detail::GatewayUpstreamServiceImpl;
using yuzu::server::GatewayRouteStore;
using yuzu::server::pg::PgPool;
namespace pg = yuzu::server::pg;
namespace apb = ::yuzu::agent::v1;
namespace gw = ::yuzu::gateway::v1;

namespace {

// Template-cloned per fixture, mirroring test_gateway_route_store.cpp's own
// template (kept as a separate key — "gwroutewiring" vs "gatewayroute" — so
// the two files' fixtures never share a clone lineage).
yuzu::test::PgTestTemplate gwroutewiring_tpl{"gwroutewiring", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    GatewayRouteStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("gwroutewiring template: store failed to migrate");
}};

// A minimal-but-valid gateway-proxied RegisterRequest, carrying a fresh
// unlimited-use enrollment token so ProxyRegister accepts it outright. Mirrors
// make_gw_register in test_agent_service_impl.cpp (PR5d).
apb::RegisterRequest make_gw_register(yuzu::server::auth::AuthManager& auth_mgr,
                                      const std::string& agent_id) {
    apb::RegisterRequest req;
    req.mutable_info()->set_agent_id(agent_id);
    req.mutable_info()->set_hostname("gw-wiring-host");
    req.mutable_info()->mutable_platform()->set_os("linux");
    req.mutable_info()->mutable_platform()->set_arch("x86_64");
    req.set_enrollment_token(auth_mgr.create_enrollment_token("test", 0, std::chrono::hours(1)));
    return req;
}

// Directly overwrite a row's (connection_epoch, session_id) on a second
// connection — mirrors test_gateway_route_store.cpp's own `raw_bump_epoch`
// helper (kept as a separate copy: that file's fixture is a class member
// function, this file's tests construct the store inline per-case). Used to
// deterministically force a SUBSEQUENT register_fresh call to LOSE its epoch
// race (its freshly-minted epoch, drawn from the store's own sequence, ends
// up lower than this artificially-bumped value) — the 4.2a #8
// lost_race_sessions_ scenario, which single-threaded/in-order test calls
// cannot otherwise reach (each real register_fresh call naturally mints a
// strictly higher epoch than the last).
void raw_bump_epoch(const std::string& dsn, const std::string& agent_id, std::int64_t epoch,
                    const std::string& session_id) {
    pg::PgConn conn{PQconnectdb(dsn.c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    const std::string epoch_s = std::to_string(epoch);
    const char* p1 = agent_id.c_str();
    const char* p2 = epoch_s.c_str();
    const char* p3 = session_id.c_str();
    const char* params[3] = {p1, p2, p3};
    pg::PgResult r{PQexecParams(conn.get(),
                                "UPDATE gateway_route_store.agent_routes SET "
                                "connection_epoch=$2::bigint, session_id=$3 WHERE agent_id=$1",
                                3, nullptr, params, nullptr, nullptr, 0)};
    REQUIRE(r.status() == PGRES_COMMAND_OK);
}

/// Real grpc::Server hosting a GatewayUpstreamServiceImpl wired to a
/// caller-supplied GatewayRouteStore. Needed ONLY for the two cases that
/// depend on a real x-yuzu-session-id client_metadata() value — every other
/// case in this file drives the handler directly.
struct LiveGatewayWiringHarness {
    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    yuzu::server::auth::AuthManager auth_mgr;
    yuzu::server::auth::AutoApproveEngine auto_approve;
    GatewayUpstreamServiceImpl svc{registry, bus, auth_mgr, auto_approve, &metrics};

    std::unique_ptr<grpc::Server> server_;
    int port_ = 0;
    std::unique_ptr<gw::GatewayUpstream::Stub> stub_;

    explicit LiveGatewayWiringHarness(GatewayRouteStore& store) {
        svc.set_gateway_route_store(&store);

        grpc::ServerBuilder builder;
        // Port 0 -> OS assigns an ephemeral free port (avoids fixed-port
        // flakiness under parallel tests, mirrors test_grpc_on_behalf_enforce.cpp).
        builder.AddListeningPort("127.0.0.1:0", grpc::InsecureServerCredentials(), &port_);
        builder.RegisterService(&svc);
        server_ = builder.BuildAndStart();
        REQUIRE(server_ != nullptr);
        REQUIRE(port_ != 0);

        auto channel = grpc::CreateChannel("127.0.0.1:" + std::to_string(port_),
                                           grpc::InsecureChannelCredentials());
        stub_ = gw::GatewayUpstream::NewStub(channel);
    }

    ~LiveGatewayWiringHarness() {
        if (server_) server_->Shutdown();
    }

    LiveGatewayWiringHarness(const LiveGatewayWiringHarness&) = delete;
    LiveGatewayWiringHarness& operator=(const LiveGatewayWiringHarness&) = delete;

    /// Drives a real ProxyRegister RPC, optionally carrying `presented_session`
    /// as the x-yuzu-session-id client metadata value (the only way to
    /// exercise the re-announce/unknown-session branches — see file header).
    apb::RegisterResponse register_agent(const std::string& agent_id,
                                         const std::string& presented_session = {}) {
        auto req = make_gw_register(auth_mgr, agent_id);
        grpc::ClientContext ctx;
        ctx.set_deadline(std::chrono::system_clock::now() + std::chrono::seconds(5));
        if (!presented_session.empty())
            ctx.AddMetadata(std::string(AgentServiceImpl::kSessionMetadataKey), presented_session);
        apb::RegisterResponse resp;
        auto status = stub_->ProxyRegister(&ctx, req, &resp);
        REQUIRE(status.ok());
        return resp;
    }
};

} // namespace

// ── ProxyRegister: fresh path (no live server needed — context=nullptr means
//    presented_session is always empty, i.e. always fresh) ──────────────────

TEST_CASE("ProxyRegister: fresh register mints a route row; a second fresh register "
          "mints a STRICTLY GREATER epoch (new connection wins)",
          "[pg][gateway_route_wiring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayRouteStore store{pool};
    REQUIRE(store.is_open());

    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    yuzu::server::auth::AuthManager auth_mgr;
    yuzu::server::auth::AutoApproveEngine auto_approve;
    GatewayUpstreamServiceImpl gateway_svc{registry, bus, auth_mgr, auto_approve, &metrics};
    gateway_svc.set_gateway_route_store(&store);

    auto req1 = make_gw_register(auth_mgr, "agent-fresh-1");
    apb::RegisterResponse resp1;
    REQUIRE(gateway_svc.ProxyRegister(/*context=*/nullptr, &req1, &resp1).ok());
    REQUIRE(resp1.accepted());
    const std::string session1 = resp1.session_id();
    REQUIRE_FALSE(session1.empty());

    auto row1 = store.lookup_route("agent-fresh-1");
    REQUIRE(row1.has_value());
    REQUIRE(row1->has_value());
    CHECK((*row1)->session_id == session1);
    const auto epoch1 = (*row1)->connection_epoch;
    CHECK(epoch1 > 0);

    // Second ProxyRegister, still no metadata (context=nullptr => presented
    // session always empty) — a client that never carries x-yuzu-session-id
    // takes the fresh path every time, exactly as before this slice.
    auto req2 = make_gw_register(auth_mgr, "agent-fresh-1");
    apb::RegisterResponse resp2;
    REQUIRE(gateway_svc.ProxyRegister(/*context=*/nullptr, &req2, &resp2).ok());
    REQUIRE(resp2.accepted());
    const std::string session2 = resp2.session_id();
    CHECK(session2 != session1); // a NEW session was minted, not reused

    auto row2 = store.lookup_route("agent-fresh-1");
    REQUIRE(row2.has_value());
    REQUIRE(row2->has_value());
    CHECK((*row2)->session_id == session2);
    CHECK((*row2)->connection_epoch > epoch1); // strictly greater: new connection wins
}

// ── ProxyRegister: the NEW re-announce-vs-fresh decision branch ─────────────

TEST_CASE("ProxyRegister: presenting a KNOWN x-yuzu-session-id re-announces (renew_leases) "
          "instead of minting a fresh session+epoch — the anti-replay guarantee",
          "[pg][gateway_route_wiring][grpc]") {
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayRouteStore store{pool};
    REQUIRE(store.is_open());
    LiveGatewayWiringHarness h(store);

    auto resp1 = h.register_agent("agent-reannounce-1");
    REQUIRE(resp1.accepted());
    const std::string session1 = resp1.session_id();
    REQUIRE_FALSE(session1.empty());

    auto row1 = store.lookup_route("agent-reannounce-1");
    REQUIRE(row1.has_value());
    REQUIRE(row1->has_value());
    const auto epoch1 = (*row1)->connection_epoch;
    // register_fresh never sets a lease (only announce_connected/renew_leases do).
    CHECK_FALSE((*row1)->lease_until_ms.has_value());

    // Re-announce: present the SAME session id via x-yuzu-session-id metadata.
    auto resp2 = h.register_agent("agent-reannounce-1", session1);
    REQUIRE(resp2.accepted());
    CHECK(resp2.session_id() == session1); // REUSED, not a fresh mint

    auto row2 = store.lookup_route("agent-reannounce-1");
    REQUIRE(row2.has_value());
    REQUIRE(row2->has_value());
    // The core anti-replay guarantee: no new epoch, no session clobber.
    CHECK((*row2)->connection_epoch == epoch1);
    CHECK((*row2)->session_id == session1);
    // renew_leases fired instead of register_fresh.
    REQUIRE((*row2)->lease_until_ms.has_value());
}

TEST_CASE("ProxyRegister: an UNKNOWN presented x-yuzu-session-id renews the PRESENTED session "
          "in the directory — NEVER register_fresh — so no row is minted for a first-ever "
          "registration",
          "[pg][gateway_route_wiring][grpc]") {
    // 4.2a #2 (mechanism c): before this slice, an unknown-locally presented
    // session fell through to the SAME "fresh" branch as no-metadata-at-all,
    // which would mint a fresh epoch via register_fresh and unconditionally
    // win — able to clobber a live newer connection's route on a stale
    // replay. Now it renews the PRESENTED session only; since this agent has
    // never registered before, that presented session matches no row, so the
    // directory gets NO row at all (register_fresh never runs on this
    // branch) and the shortfall is counted as a desync signal.
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayRouteStore store{pool};
    REQUIRE(store.is_open());
    LiveGatewayWiringHarness h(store);

    // First call for this agent ever, so this session id is (and can only be)
    // unknown server-side — precisely the "presented but not in
    // gateway_sessions_" case, distinct from the no-metadata-at-all case
    // above.
    auto resp = h.register_agent("agent-unknown-session", "gw-session-forged-not-real");
    REQUIRE(resp.accepted());
    // Deferred S'-vs-S in-memory desync (#6/4.4, explicitly out of scope for
    // this slice): the response still mints a fresh session_id, unchanged
    // from the pre-4.2a behavior — only the DIRECTORY write changed.
    CHECK(resp.session_id() != "gw-session-forged-not-real");

    auto row = store.lookup_route("agent-unknown-session");
    REQUIRE(row.has_value());
    CHECK_FALSE(row->has_value()); // NO row minted — register_fresh never ran

    CHECK(h.metrics
              .counter("yuzu_server_gateway_route_desync_total",
                       {{"op", "renew_leases"}, {"outcome", "shortfall"}})
              .value() == 1);
}

TEST_CASE("ProxyRegister: a ZOMBIE unknown presented session (the agent's row belongs to a "
          "DIFFERENT, current session) renews zero rows and leaves the live row untouched",
          "[pg][gateway_route_wiring][grpc]") {
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayRouteStore store{pool};
    REQUIRE(store.is_open());
    LiveGatewayWiringHarness h(store);

    // Establish a real, current route via a genuine (no-metadata) fresh
    // registration.
    auto resp1 = h.register_agent("agent-zombie-1");
    REQUIRE(resp1.accepted());
    const std::string current_session = resp1.session_id();

    auto row_before = store.lookup_route("agent-zombie-1");
    REQUIRE(row_before.has_value());
    REQUIRE(row_before->has_value());
    CHECK((*row_before)->session_id == current_session);
    const auto epoch_before = (*row_before)->connection_epoch;

    // Present a DIFFERENT, forged session — never seen by this replica's
    // gateway_sessions_ (case 3: unknown locally) AND not the row's current
    // session either (the "zombie" shape) — renew_leases({forged}) must
    // match zero rows and leave the live row alone.
    auto resp2 = h.register_agent("agent-zombie-1", "gw-session-zombie-not-current");
    REQUIRE(resp2.accepted());

    auto row_after = store.lookup_route("agent-zombie-1");
    REQUIRE(row_after.has_value());
    REQUIRE(row_after->has_value());
    CHECK((*row_after)->session_id == current_session); // untouched
    CHECK((*row_after)->connection_epoch == epoch_before); // untouched

    CHECK(h.metrics
              .counter("yuzu_server_gateway_route_desync_total",
                       {{"op", "renew_leases"}, {"outcome", "shortfall"}})
              .value() == 1);
}

// ── #8 desync counters: announce_connected / deregister mismatch ───────────

TEST_CASE("NotifyStreamStatus: a STALE CONNECTED for a session already superseded by a genuine "
          "newer registration reports matched=false and bumps the desync counter",
          "[pg][gateway_route_wiring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayRouteStore store{pool};
    REQUIRE(store.is_open());

    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    yuzu::server::auth::AuthManager auth_mgr;
    yuzu::server::auth::AutoApproveEngine auto_approve;
    GatewayUpstreamServiceImpl gateway_svc{registry, bus, auth_mgr, auto_approve, &metrics};
    gateway_svc.set_gateway_route_store(&store);

    // session1 legitimately WINS its own register_fresh epoch race (this is
    // NOT the lost_race_sessions_ scenario) — it is only superseded LATER by
    // session2's own genuine fresh registration.
    auto req1 = make_gw_register(auth_mgr, "agent-mismatch-1");
    apb::RegisterResponse resp1;
    REQUIRE(gateway_svc.ProxyRegister(/*context=*/nullptr, &req1, &resp1).ok());
    const std::string session1 = resp1.session_id();

    auto req2 = make_gw_register(auth_mgr, "agent-mismatch-1");
    apb::RegisterResponse resp2;
    REQUIRE(gateway_svc.ProxyRegister(/*context=*/nullptr, &req2, &resp2).ok());
    const std::string session2 = resp2.session_id();
    REQUIRE(session2 != session1);

    // A stale CONNECTED for the now-superseded session1.
    gw::StreamStatusNotification notif;
    notif.set_agent_id("agent-mismatch-1");
    notif.set_session_id(session1);
    notif.set_event(gw::StreamStatusNotification::CONNECTED);
    notif.set_cluster_id("cluster-stale");
    notif.set_gateway_node("node-stale");
    gw::StreamStatusAck ack;
    REQUIRE(gateway_svc.NotifyStreamStatus(/*context=*/nullptr, &notif, &ack).ok());
    CHECK(ack.acknowledged()); // the in-memory gateway_sessions_ guard still passes

    // The store's session-guarded UPDATE did NOT match — session2 owns the row.
    auto row = store.lookup_route("agent-mismatch-1");
    REQUIRE(row.has_value());
    REQUIRE(row->has_value());
    CHECK((*row)->session_id == session2);
    CHECK_FALSE((*row)->cluster_id.has_value()); // stale CONNECTED did not write through

    CHECK(metrics
              .counter("yuzu_server_gateway_route_desync_total",
                       {{"op", "announce_connected"}, {"outcome", "session_mismatch"}})
              .value() == 1);
}

TEST_CASE("ProxyRegister: a session that LOSES its register_fresh epoch race does NOT bump the "
          "desync counter when its follow-up CONNECTED arrives (benign race loss, not a desync)",
          "[pg][gateway_route_wiring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayRouteStore store{pool};
    REQUIRE(store.is_open());

    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    yuzu::server::auth::AuthManager auth_mgr;
    yuzu::server::auth::AutoApproveEngine auto_approve;
    GatewayUpstreamServiceImpl gateway_svc{registry, bus, auth_mgr, auto_approve, &metrics};
    gateway_svc.set_gateway_route_store(&store);

    auto req1 = make_gw_register(auth_mgr, "agent-race-1");
    apb::RegisterResponse resp1;
    REQUIRE(gateway_svc.ProxyRegister(/*context=*/nullptr, &req1, &resp1).ok());
    auto row1 = store.lookup_route("agent-race-1");
    REQUIRE(row1.has_value());
    REQUIRE(row1->has_value());

    // Artificially bump the row's epoch far above whatever the store's own
    // sequence will mint next, simulating a newer connection that already
    // won — deterministic single-threaded stand-in for the real concurrent
    // race (see raw_bump_epoch's header comment).
    raw_bump_epoch(db.dsn(), "agent-race-1", (*row1)->connection_epoch + 1000,
                  "gw-session-already-won");

    // A SECOND fresh registration (no metadata — same "fresh" branch) now
    // mints a lower epoch than the artificially-bumped row and LOSES the
    // race.
    auto req2 = make_gw_register(auth_mgr, "agent-race-1");
    apb::RegisterResponse resp2;
    REQUIRE(gateway_svc.ProxyRegister(/*context=*/nullptr, &req2, &resp2).ok());
    const std::string losing_session = resp2.session_id();

    auto row2 = store.lookup_route("agent-race-1");
    REQUIRE(row2.has_value());
    REQUIRE(row2->has_value());
    CHECK((*row2)->session_id == "gw-session-already-won"); // the losing register_fresh did NOT win

    // The losing session's own follow-up CONNECTED must skip
    // announce_connected entirely (lost_race_sessions_) rather than call it
    // and observe matched=false.
    gw::StreamStatusNotification notif;
    notif.set_agent_id("agent-race-1");
    notif.set_session_id(losing_session);
    notif.set_event(gw::StreamStatusNotification::CONNECTED);
    notif.set_cluster_id("cluster-loser");
    notif.set_gateway_node("node-loser");
    gw::StreamStatusAck ack;
    REQUIRE(gateway_svc.NotifyStreamStatus(/*context=*/nullptr, &notif, &ack).ok());
    CHECK(ack.acknowledged());

    // The winning row is completely untouched by the loser's CONNECTED.
    auto row3 = store.lookup_route("agent-race-1");
    REQUIRE(row3.has_value());
    REQUIRE(row3->has_value());
    CHECK((*row3)->session_id == "gw-session-already-won");
    CHECK_FALSE((*row3)->cluster_id.has_value());

    // The core assertion: no desync counter increment for this benign race loss.
    CHECK(metrics
              .counter("yuzu_server_gateway_route_desync_total",
                       {{"op", "announce_connected"}, {"outcome", "session_mismatch"}})
              .value() == 0);
}

// ── NotifyStreamStatus: unknown-session reject counter ──────────────────────

TEST_CASE("NotifyStreamStatus: an unknown session (never registered on this replica) is "
          "rejected and bumps the desync counter",
          "[gateway_route_wiring]") {
    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    yuzu::server::auth::AuthManager auth_mgr;
    yuzu::server::auth::AutoApproveEngine auto_approve;
    GatewayUpstreamServiceImpl gateway_svc{registry, bus, auth_mgr, auto_approve, &metrics};
    // No gateway_route_store wired at all — this case exercises the
    // in-memory gateway_sessions_ guard purely, unrelated to the store.

    gw::StreamStatusNotification notif;
    notif.set_agent_id("agent-never-registered");
    notif.set_session_id("gw-session-never-seen");
    notif.set_event(gw::StreamStatusNotification::CONNECTED);
    gw::StreamStatusAck ack;
    REQUIRE(gateway_svc.NotifyStreamStatus(/*context=*/nullptr, &notif, &ack).ok());
    CHECK_FALSE(ack.acknowledged());

    CHECK(metrics
              .counter("yuzu_server_gateway_route_desync_total",
                       {{"op", "notify_stream_status"}, {"outcome", "unknown_session"}})
              .value() == 1);
}

// ── NotifyStreamStatus: CONNECTED / DISCONNECTED ────────────────────────────

TEST_CASE("NotifyStreamStatus: CONNECTED fills cluster_id/gateway_node for the matching session",
          "[pg][gateway_route_wiring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayRouteStore store{pool};
    REQUIRE(store.is_open());

    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    yuzu::server::auth::AuthManager auth_mgr;
    yuzu::server::auth::AutoApproveEngine auto_approve;
    GatewayUpstreamServiceImpl gateway_svc{registry, bus, auth_mgr, auto_approve, &metrics};
    gateway_svc.set_gateway_route_store(&store);

    auto req = make_gw_register(auth_mgr, "agent-connect-1");
    apb::RegisterResponse resp;
    REQUIRE(gateway_svc.ProxyRegister(/*context=*/nullptr, &req, &resp).ok());
    const std::string session_id = resp.session_id();

    gw::StreamStatusNotification notif;
    notif.set_agent_id("agent-connect-1");
    notif.set_session_id(session_id);
    notif.set_event(gw::StreamStatusNotification::CONNECTED);
    notif.set_cluster_id("cluster-a");
    notif.set_gateway_node("node-a");
    gw::StreamStatusAck ack;
    REQUIRE(gateway_svc.NotifyStreamStatus(/*context=*/nullptr, &notif, &ack).ok());
    CHECK(ack.acknowledged());

    auto row = store.lookup_route("agent-connect-1");
    REQUIRE(row.has_value());
    REQUIRE(row->has_value());
    CHECK((*row)->cluster_id == "cluster-a");
    CHECK((*row)->gateway_node == "node-a");
    CHECK((*row)->lease_until_ms.has_value()); // announce_connected sets the lease
}

TEST_CASE("NotifyStreamStatus: DISCONNECTED tombstones the route only for the matching "
          "session — a stale/superseded session does not tear it down",
          "[pg][gateway_route_wiring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayRouteStore store{pool};
    REQUIRE(store.is_open());

    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    yuzu::server::auth::AuthManager auth_mgr;
    yuzu::server::auth::AutoApproveEngine auto_approve;
    GatewayUpstreamServiceImpl gateway_svc{registry, bus, auth_mgr, auto_approve, &metrics};
    gateway_svc.set_gateway_route_store(&store);

    auto req1 = make_gw_register(auth_mgr, "agent-disconnect-1");
    apb::RegisterResponse resp1;
    REQUIRE(gateway_svc.ProxyRegister(/*context=*/nullptr, &req1, &resp1).ok());
    const std::string session1 = resp1.session_id();

    // A second (context-less, hence still "fresh path") ProxyRegister mints a
    // NEWER session that wins the epoch race and overwrites the row's
    // session_id — simulating a reconnect that has already superseded
    // session1's route.
    auto req2 = make_gw_register(auth_mgr, "agent-disconnect-1");
    apb::RegisterResponse resp2;
    REQUIRE(gateway_svc.ProxyRegister(/*context=*/nullptr, &req2, &resp2).ok());
    const std::string session2 = resp2.session_id();
    REQUIRE(session2 != session1);

    // A stale DISCONNECTED for the now-superseded session1 must NOT tear down
    // session2's row (session-guarded deregister in gateway_route_store.cpp).
    gw::StreamStatusNotification stale;
    stale.set_agent_id("agent-disconnect-1");
    stale.set_session_id(session1);
    stale.set_event(gw::StreamStatusNotification::DISCONNECTED);
    gw::StreamStatusAck stale_ack;
    REQUIRE(gateway_svc.NotifyStreamStatus(/*context=*/nullptr, &stale, &stale_ack).ok());

    auto row_after_stale = store.lookup_route("agent-disconnect-1");
    REQUIRE(row_after_stale.has_value());
    REQUIRE(row_after_stale->has_value());              // still present
    CHECK((*row_after_stale)->session_id == session2);  // untouched — still session2

    // 4.2a #8: the store's session-guarded UPDATE matched zero rows
    // (removed=false) — the stale session1 no-op is exactly the guard
    // rejection this counter exists to make visible.
    CHECK(metrics
              .counter("yuzu_server_gateway_route_desync_total",
                       {{"op", "deregister"}, {"outcome", "session_mismatch"}})
              .value() == 1);

    // The matching DISCONNECTED for session2 DOES tombstone it (4.2a:
    // deregister is a session-guarded UPDATE-to-tombstone, not a DELETE — see
    // gateway_route_store.hpp "SLICE 4.2a" — so the row stays present with
    // session_id/lease_until/cluster_id/gateway_node nulled, not gone).
    gw::StreamStatusNotification real;
    real.set_agent_id("agent-disconnect-1");
    real.set_session_id(session2);
    real.set_event(gw::StreamStatusNotification::DISCONNECTED);
    gw::StreamStatusAck real_ack;
    REQUIRE(gateway_svc.NotifyStreamStatus(/*context=*/nullptr, &real, &real_ack).ok());

    auto row_after_real = store.lookup_route("agent-disconnect-1");
    REQUIRE(row_after_real.has_value());
    REQUIRE(row_after_real->has_value()); // tombstoned, not removed
    CHECK_FALSE((*row_after_real)->session_id.has_value());
    CHECK_FALSE((*row_after_real)->lease_until_ms.has_value());

    // The matching (removed=true) deregister must NOT bump the desync
    // counter — still exactly the one count from the stale attempt above.
    CHECK(metrics
              .counter("yuzu_server_gateway_route_desync_total",
                       {{"op", "deregister"}, {"outcome", "session_mismatch"}})
              .value() == 1);
}

// ── BatchHeartbeat: renew_leases ────────────────────────────────────────────

TEST_CASE("BatchHeartbeat: renews the route lease for the carried session ids in one call",
          "[pg][gateway_route_wiring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayRouteStore store{pool};
    REQUIRE(store.is_open());

    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    yuzu::server::auth::AuthManager auth_mgr;
    yuzu::server::auth::AutoApproveEngine auto_approve;
    GatewayUpstreamServiceImpl gateway_svc{registry, bus, auth_mgr, auto_approve, &metrics};
    gateway_svc.set_gateway_route_store(&store);

    auto req = make_gw_register(auth_mgr, "agent-hb-1");
    apb::RegisterResponse resp;
    REQUIRE(gateway_svc.ProxyRegister(/*context=*/nullptr, &req, &resp).ok());
    const std::string session_id = resp.session_id();

    auto row_before = store.lookup_route("agent-hb-1");
    REQUIRE(row_before.has_value());
    REQUIRE(row_before->has_value());
    CHECK_FALSE((*row_before)->lease_until_ms.has_value()); // register_fresh sets no lease
    const auto epoch_before = (*row_before)->connection_epoch;

    gw::BatchHeartbeatRequest batch;
    batch.set_gateway_node("node-hb");
    auto* hb = batch.add_heartbeats();
    hb->set_session_id(session_id);
    gw::BatchHeartbeatResponse batch_resp;
    REQUIRE(gateway_svc.BatchHeartbeat(/*context=*/nullptr, &batch, &batch_resp).ok());

    auto row_after = store.lookup_route("agent-hb-1");
    REQUIRE(row_after.has_value());
    REQUIRE(row_after->has_value());
    CHECK((*row_after)->lease_until_ms.has_value());       // renewed by BatchHeartbeat
    CHECK((*row_after)->connection_epoch == epoch_before); // unaffected
    CHECK((*row_after)->session_id == session_id);
}

TEST_CASE("BatchHeartbeat: a duplicate session id in one batch and a lost-epoch-race session "
          "do NOT inflate the shortfall desync counter (PR #4299 review SHOULD 2)",
          "[pg][gateway_route_wiring]") {
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayRouteStore store{pool};
    REQUIRE(store.is_open());

    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    yuzu::server::auth::AuthManager auth_mgr;
    yuzu::server::auth::AutoApproveEngine auto_approve;
    GatewayUpstreamServiceImpl gateway_svc{registry, bus, auth_mgr, auto_approve, &metrics};
    gateway_svc.set_gateway_route_store(&store);

    // A genuinely live session — its row is real, so renewing it matches
    // exactly one row no matter how many times its id appears in the batch.
    auto req_live = make_gw_register(auth_mgr, "agent-hb-dup-1");
    apb::RegisterResponse resp_live;
    REQUIRE(gateway_svc.ProxyRegister(/*context=*/nullptr, &req_live, &resp_live).ok());
    const std::string live_session = resp_live.session_id();

    // A session that LOSES its register_fresh epoch race — deterministic
    // single-threaded stand-in via raw_bump_epoch, mirrors the existing
    // "does NOT bump the desync counter" NotifyStreamStatus case above.
    auto req_race1 = make_gw_register(auth_mgr, "agent-hb-race-1");
    apb::RegisterResponse resp_race1;
    REQUIRE(gateway_svc.ProxyRegister(/*context=*/nullptr, &req_race1, &resp_race1).ok());
    auto row_race = store.lookup_route("agent-hb-race-1");
    REQUIRE(row_race.has_value());
    REQUIRE(row_race->has_value());
    raw_bump_epoch(db.dsn(), "agent-hb-race-1", (*row_race)->connection_epoch + 1000,
                  "gw-session-already-won");
    auto req_race2 = make_gw_register(auth_mgr, "agent-hb-race-1");
    apb::RegisterResponse resp_race2;
    REQUIRE(gateway_svc.ProxyRegister(/*context=*/nullptr, &req_race2, &resp_race2).ok());
    const std::string losing_session = resp_race2.session_id();
    auto row_after_race = store.lookup_route("agent-hb-race-1");
    REQUIRE(row_after_race.has_value());
    REQUIRE(row_after_race->has_value());
    CHECK((*row_after_race)->session_id == "gw-session-already-won"); // the loser did NOT win

    // A batch carrying the live session TWICE (a retried-batch duplicate,
    // per the Erlang heartbeat buffer's no-dedup prepend) plus the losing
    // session once. renew_leases matches exactly ONE row (the live session
    // — the losing session's row belongs to a DIFFERENT session and matches
    // zero). Pre-fix, the raw comparison (3 requested vs 1 matched) would
    // report a shortfall of 2; post-fix, deduping to {live, losing} and
    // dropping the known race-loser leaves only {live}, matching 1-for-1.
    gw::BatchHeartbeatRequest batch;
    batch.set_gateway_node("node-hb-dup");
    batch.add_heartbeats()->set_session_id(live_session);
    batch.add_heartbeats()->set_session_id(live_session); // duplicate
    batch.add_heartbeats()->set_session_id(losing_session);
    gw::BatchHeartbeatResponse batch_resp;
    REQUIRE(gateway_svc.BatchHeartbeat(/*context=*/nullptr, &batch, &batch_resp).ok());

    auto row_live_after = store.lookup_route("agent-hb-dup-1");
    REQUIRE(row_live_after.has_value());
    REQUIRE(row_live_after->has_value());
    CHECK((*row_live_after)->lease_until_ms.has_value()); // genuinely renewed

    CHECK(metrics
              .counter("yuzu_server_gateway_route_desync_total",
                       {{"op", "renew_leases"}, {"outcome", "shortfall"}})
              .value() == 0);
}

// ── Fail-open posture ────────────────────────────────────────────────────────

TEST_CASE("ProxyRegister/NotifyStreamStatus: a degraded GatewayRouteStore write does NOT "
          "fail the RPC (fail-open) and is counted",
          "[gateway_route_wiring]") {
    // A deliberately unparseable conninfo makes PgPool::valid() false, so
    // GatewayRouteStore's construction-time acquire() fails FAST — no network
    // I/O at all (pg_pool.cpp: `if (!valid_) return {};`) — and the store
    // stays permanently open_==false. Every write below therefore degrades
    // with store_unavailable without touching a real Postgres instance, so
    // this case runs even when YUZU_TEST_POSTGRES_DSN is unset.
    PgPool broken_pool{{.conninfo = "not a valid conninfo string ===", .size = 1}};
    GatewayRouteStore broken_store{broken_pool};
    REQUIRE_FALSE(broken_store.is_open());

    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    yuzu::server::auth::AuthManager auth_mgr;
    yuzu::server::auth::AutoApproveEngine auto_approve;
    GatewayUpstreamServiceImpl gateway_svc{registry, bus, auth_mgr, auto_approve, &metrics};
    gateway_svc.set_gateway_route_store(&broken_store);

    auto req = make_gw_register(auth_mgr, "agent-failopen-1");
    apb::RegisterResponse resp;
    auto status = gateway_svc.ProxyRegister(/*context=*/nullptr, &req, &resp);
    CHECK(status.ok()); // fail-open: register_fresh degraded, RPC still succeeds
    CHECK(resp.accepted());
    CHECK(metrics
              .counter("yuzu_server_gateway_route_write_failed_total",
                       {{"op", "register_fresh"}, {"reason", "store_unavailable"}})
              .value() == 1);

    gw::StreamStatusNotification notif;
    notif.set_agent_id("agent-failopen-1");
    notif.set_session_id(resp.session_id());
    notif.set_event(gw::StreamStatusNotification::CONNECTED);
    gw::StreamStatusAck ack;
    auto notif_status = gateway_svc.NotifyStreamStatus(/*context=*/nullptr, &notif, &ack);
    CHECK(notif_status.ok());
    CHECK(ack.acknowledged());
    CHECK(metrics
              .counter("yuzu_server_gateway_route_write_failed_total",
                       {{"op", "announce_connected"}, {"reason", "store_unavailable"}})
              .value() == 1);
}
