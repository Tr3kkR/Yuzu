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

// ── #4324: the per-home stream-generation fence ─────────────────────────────
//
// The scenario #4324 exists to prevent: a session is CONNECTED under home A,
// then RE-HOMED to home B while REUSING the same session_id (a live
// circuit-recovery reconnect), and a stale DISCONNECTED from the now-torn-down
// home A arrives afterward. Constructed here via the REAL production call
// sequence — ProxyRegister's re-announce mechanism (needs a live grpc
// context to carry x-yuzu-session-id metadata, hence LiveGatewayWiringHarness)
// followed by a second CONNECTED for the reused session — rather than poking
// registry/store internals directly: ProxyRegister always calls
// register_agent() unconditionally (gateway_service_impl.cpp), even on the
// re-announce branch, so the re-announce INSTALLS A NEW AgentSession object
// that happens to be re-mapped onto the SAME session_id string — exactly the
// "new home, reused session id" shape, and the one thing the shipped gateway
// cannot produce today (at most one CONNECTED(S)/one DISCONNECTED(S) per
// session — see gateway_route_store.hpp's SESSION GUARDS LIMIT note).

TEST_CASE("NotifyStreamStatus #4324: a stale DISCONNECTED from a torn-down home does NOT tear "
          "down a session re-homed under the SAME session id (registry, store, AND the "
          "session map all survive)",
          "[pg][gateway_route_wiring][grpc]") {
    YUZU_REQUIRE_PG_DB_TPL(db, gwroutewiring_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayRouteStore store{pool};
    REQUIRE(store.is_open());
    LiveGatewayWiringHarness h(store);

    const std::string agent_id = "agent-stale-home-1";

    // 1. Fresh registration — mints session1.
    auto resp1 = h.register_agent(agent_id);
    REQUIRE(resp1.accepted());
    const std::string session1 = resp1.session_id();
    REQUIRE_FALSE(session1.empty());

    // 2. CONNECTED under home1 — the FIRST home.
    gw::StreamStatusNotification connected1;
    connected1.set_agent_id(agent_id);
    connected1.set_session_id(session1);
    connected1.set_event(gw::StreamStatusNotification::CONNECTED);
    connected1.set_cluster_id("cluster-a");
    connected1.set_gateway_node("node-a");
    connected1.set_stream_home_id("home-1");
    gw::StreamStatusAck ack1;
    REQUIRE(h.svc.NotifyStreamStatus(/*context=*/nullptr, &connected1, &ack1).ok());
    CHECK(ack1.acknowledged());
    CHECK(h.registry.gateway_stream_home_id(agent_id, session1) == "home-1");

    // 3. Re-announce: present the SAME session1 via x-yuzu-session-id metadata
    // (a live circuit-recovery reconnect). ProxyRegister's re-announce branch
    // reuses session1 in the RESPONSE, but register_agent() unconditionally
    // installs a NEW AgentSession object underneath — that new object's own
    // gateway_stream_home_id starts back at empty until its own CONNECTED
    // arrives, below.
    auto resp2 = h.register_agent(agent_id, session1);
    REQUIRE(resp2.accepted());
    REQUIRE(resp2.session_id() == session1); // reused, not a fresh mint

    // 4. CONNECTED under home2 — the SAME session_id, a NEW home. This is the
    // real re-home: same session, new stream_home_id.
    gw::StreamStatusNotification connected2;
    connected2.set_agent_id(agent_id);
    connected2.set_session_id(session1);
    connected2.set_event(gw::StreamStatusNotification::CONNECTED);
    connected2.set_cluster_id("cluster-b");
    connected2.set_gateway_node("node-b");
    connected2.set_stream_home_id("home-2");
    gw::StreamStatusAck ack2;
    REQUIRE(h.svc.NotifyStreamStatus(/*context=*/nullptr, &connected2, &ack2).ok());
    CHECK(ack2.acknowledged());
    CHECK(h.registry.gateway_stream_home_id(agent_id, session1) == "home-2");

    auto row_after_rehome = store.lookup_route(agent_id);
    REQUIRE(row_after_rehome.has_value());
    REQUIRE(row_after_rehome->has_value());
    CHECK((*row_after_rehome)->gateway_node == "node-b");
    CHECK((*row_after_rehome)->session_id == session1);

    // 5. A STALE DISCONNECTED from the now-torn-down home1 arrives (delayed
    // delivery from the old gateway process instance).
    gw::StreamStatusNotification stale_disc;
    stale_disc.set_agent_id(agent_id);
    stale_disc.set_session_id(session1); // SAME session_id — reused
    stale_disc.set_event(gw::StreamStatusNotification::DISCONNECTED);
    stale_disc.set_gateway_node("node-a");
    stale_disc.set_stream_home_id("home-1"); // STALE — the torn-down home
    gw::StreamStatusAck stale_ack;
    REQUIRE(h.svc.NotifyStreamStatus(/*context=*/nullptr, &stale_disc, &stale_ack).ok());
    // Acked exactly as a successful DISCONNECTED would be — the fence is a
    // silent no-op from the gateway's point of view, not an error.
    CHECK(stale_ack.acknowledged());

    // Assertion 1: the durable directory route is UNCHANGED — home2's
    // placement survives (not tombstoned, still session1/node-b).
    auto row_after_stale = store.lookup_route(agent_id);
    REQUIRE(row_after_stale.has_value());
    REQUIRE(row_after_stale->has_value());
    CHECK((*row_after_stale)->session_id == session1);
    CHECK((*row_after_stale)->gateway_node == "node-b");
    REQUIRE((*row_after_stale)->lease_until_ms.has_value()); // NOT tombstoned

    // Assertion 2: the registry's in-memory session state ALSO survives — the
    // naive "fence the registry/store writes but still erase the session map"
    // shape the design review flagged would fail THIS check even though
    // assertion 1 above would pass. Prove it by sending the SUBSEQUENT
    // genuine DISCONNECTED for the live re-homed session and confirming it is
    // NOT rejected as unknown_session.
    CHECK(h.registry.gateway_stream_home_id(agent_id, session1) == "home-2");
    gw::StreamStatusNotification real_disc;
    real_disc.set_agent_id(agent_id);
    real_disc.set_session_id(session1);
    real_disc.set_event(gw::StreamStatusNotification::DISCONNECTED);
    real_disc.set_gateway_node("node-b");
    real_disc.set_stream_home_id("home-2"); // matches the CURRENT home
    gw::StreamStatusAck real_ack;
    REQUIRE(h.svc.NotifyStreamStatus(/*context=*/nullptr, &real_disc, &real_ack).ok());
    CHECK(real_ack.acknowledged());
    // Not rejected as unknown_session — the fix this scenario exists to prove.
    CHECK(h.metrics
              .counter("yuzu_server_gateway_route_desync_total",
                       {{"op", "notify_stream_status"}, {"outcome", "unknown_session"}})
              .value() == 0);
    auto row_after_real = store.lookup_route(agent_id);
    REQUIRE(row_after_real.has_value());
    REQUIRE(row_after_real->has_value());
    CHECK_FALSE((*row_after_real)->session_id.has_value()); // now genuinely tombstoned

    // Assertion 3: the desync counter recorded exactly the one stale-home
    // rejection above (not the genuine, matching teardown).
    CHECK(h.metrics
              .counter("yuzu_server_gateway_route_desync_total",
                       {{"op", "deregister"}, {"outcome", "stale_home"}})
              .value() == 1);
}

TEST_CASE("NotifyStreamStatus #4324: a legacy (empty stream_home_id) DISCONNECTED for a legacy "
          "(empty stream_home_id) CONNECTED still tombstones normally — backward compatibility "
          "for a gateway build predating #4324",
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

    const std::string agent_id = "agent-legacy-home-1";
    auto req = make_gw_register(auth_mgr, agent_id);
    apb::RegisterResponse resp;
    REQUIRE(gateway_svc.ProxyRegister(/*context=*/nullptr, &req, &resp).ok());
    const std::string session_id = resp.session_id();

    // Legacy CONNECTED — stream_home_id left unset (defaults to empty, the
    // pre-#4324 wire shape).
    gw::StreamStatusNotification connected;
    connected.set_agent_id(agent_id);
    connected.set_session_id(session_id);
    connected.set_event(gw::StreamStatusNotification::CONNECTED);
    connected.set_gateway_node("node-legacy");
    gw::StreamStatusAck connected_ack;
    REQUIRE(gateway_svc.NotifyStreamStatus(/*context=*/nullptr, &connected, &connected_ack).ok());
    CHECK(connected_ack.acknowledged());
    CHECK(registry.gateway_stream_home_id(agent_id, session_id) == "");

    // Legacy DISCONNECTED — also unset. Both empty ⇒ the fence's "both are
    // legacy" clause admits it, exactly as if #4324 never shipped.
    gw::StreamStatusNotification disconnected;
    disconnected.set_agent_id(agent_id);
    disconnected.set_session_id(session_id);
    disconnected.set_event(gw::StreamStatusNotification::DISCONNECTED);
    disconnected.set_gateway_node("node-legacy");
    gw::StreamStatusAck disconnected_ack;
    REQUIRE(
        gateway_svc.NotifyStreamStatus(/*context=*/nullptr, &disconnected, &disconnected_ack)
            .ok());
    CHECK(disconnected_ack.acknowledged());

    auto row = store.lookup_route(agent_id);
    REQUIRE(row.has_value());
    REQUIRE(row->has_value());
    CHECK_FALSE((*row)->session_id.has_value());     // tombstoned
    CHECK_FALSE((*row)->lease_until_ms.has_value());  // tombstoned

    // No stale-home rejection — legacy-vs-legacy is not a mismatch.
    CHECK(metrics
              .counter("yuzu_server_gateway_route_desync_total",
                       {{"op", "deregister"}, {"outcome", "stale_home"}})
              .value() == 0);
}

TEST_CASE("NotifyStreamStatus #4324: an oversized stream_home_id is treated as malformed and "
          "clamped to empty, not used unbounded or rejecting the RPC",
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

    const std::string agent_id = "agent-oversized-home-1";
    auto req = make_gw_register(auth_mgr, agent_id);
    apb::RegisterResponse resp;
    REQUIRE(gateway_svc.ProxyRegister(/*context=*/nullptr, &req, &resp).ok());
    const std::string session_id = resp.session_id();

    gw::StreamStatusNotification connected;
    connected.set_agent_id(agent_id);
    connected.set_session_id(session_id);
    connected.set_event(gw::StreamStatusNotification::CONNECTED);
    connected.set_gateway_node("node-oversized");
    connected.set_stream_home_id(std::string(65, 'x')); // 1 over the 64-byte bound
    gw::StreamStatusAck ack;
    REQUIRE(gateway_svc.NotifyStreamStatus(/*context=*/nullptr, &connected, &ack).ok());
    CHECK(ack.acknowledged()); // malformed input degrades to legacy, never rejects the RPC

    // Clamped to empty, not stored unbounded.
    CHECK(registry.gateway_stream_home_id(agent_id, session_id) == "");
    CHECK(metrics
              .counter("yuzu_server_gateway_route_desync_total",
                       {{"op", "announce_connected"}, {"outcome", "malformed_home_id"}})
              .value() == 1);

    // A subsequent legacy-shaped (empty) DISCONNECTED still tears it down
    // normally — the clamp behaves exactly like an honestly-empty value.
    gw::StreamStatusNotification disconnected;
    disconnected.set_agent_id(agent_id);
    disconnected.set_session_id(session_id);
    disconnected.set_event(gw::StreamStatusNotification::DISCONNECTED);
    disconnected.set_gateway_node("node-oversized");
    gw::StreamStatusAck disc_ack;
    REQUIRE(
        gateway_svc.NotifyStreamStatus(/*context=*/nullptr, &disconnected, &disc_ack).ok());
    CHECK(disc_ack.acknowledged());
    auto row = store.lookup_route(agent_id);
    REQUIRE(row.has_value());
    REQUIRE(row->has_value());
    CHECK_FALSE((*row)->session_id.has_value()); // tombstoned normally
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

TEST_CASE("BatchHeartbeat: a session this replica's gateway_sessions_ doesn't recognize is "
          "excluded from the renew batch but counted as unknown_session, not silently dropped "
          "(#4246 #3/#10)",
          "[pg][gateway_route_wiring]") {
    // #4246 #10's renew correlation resolves agent_id from the per-replica
    // gateway_sessions_ map (the wire carries no agent_id) — a session this
    // replica never registered has nothing to correlate against, so it's
    // excluded from renew_leases entirely. That must still be OBSERVABLE via
    // the desync counter (op="renew_leases", outcome="unknown_session"),
    // never a silent drop — the exact regression this test pins.
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

    // A genuinely live, locally-known session, to prove the unknown one
    // doesn't disturb its renewal.
    auto req_live = make_gw_register(auth_mgr, "agent-hb-unknown-1");
    apb::RegisterResponse resp_live;
    REQUIRE(gateway_svc.ProxyRegister(/*context=*/nullptr, &req_live, &resp_live).ok());
    const std::string live_session = resp_live.session_id();

    gw::BatchHeartbeatRequest batch;
    batch.set_gateway_node("node-hb-unknown");
    batch.add_heartbeats()->set_session_id(live_session);
    // Never registered on this replica — this session_id is in no
    // gateway_sessions_ entry at all.
    batch.add_heartbeats()->set_session_id("gw-session-never-registered-here");
    gw::BatchHeartbeatResponse batch_resp;
    REQUIRE(gateway_svc.BatchHeartbeat(/*context=*/nullptr, &batch, &batch_resp).ok());

    // The known session still renews normally.
    auto row_live_after = store.lookup_route("agent-hb-unknown-1");
    REQUIRE(row_live_after.has_value());
    REQUIRE(row_live_after->has_value());
    CHECK((*row_live_after)->lease_until_ms.has_value());

    // No shortfall — the unknown session was never added to the renew batch
    // in the first place, so it can't manifest as a SQL-level mismatch.
    CHECK(metrics
              .counter("yuzu_server_gateway_route_desync_total",
                       {{"op", "renew_leases"}, {"outcome", "shortfall"}})
              .value() == 0);
    // But it IS surfaced, distinctly, as unknown_session.
    CHECK(metrics
              .counter("yuzu_server_gateway_route_desync_total",
                       {{"op", "renew_leases"}, {"outcome", "unknown_session"}})
              .value() == 1);
}

// ── Fail-open posture ────────────────────────────────────────────────────────

TEST_CASE("ProxyRegister: a degraded GatewayRouteStore register_fresh write FAILS the RPC "
          "(fail-CLOSED — Task B, 4.2b)",
          "[gateway_route_wiring]") {
    // register_fresh is the ONE fail-CLOSED record_route_store_failure call
    // site (Task B, 4.2b): it CREATES the row, so a missed create must refuse
    // the registration rather than let the agent connect unrouteable.
    //
    // A deliberately unparseable conninfo makes PgPool::valid() false, so
    // GatewayRouteStore's construction-time acquire() fails FAST — no network
    // I/O at all (pg_pool.cpp: `if (!valid_) return {};`) — and the store
    // stays permanently open_==false. The write below therefore degrades
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

    // Post-merge review #4344 follow-up (MEDIUM finding 1): before this fix, register_agent's
    // side effects (connected gauge, agent-online publish, root-group membership) survived a
    // failed register_fresh with no rollback — a contextless "ghost" AgentSession
    // (reap_stale_sessions can never TryCancel it: a gateway-proxied session carries no
    // server_context). Collect the bus events this call publishes to assert BOTH agent-online
    // (register_agent installing) AND agent-offline (the rollback tearing it back down) fire, in
    // that order.
    std::vector<std::string> events;
    auto sub = bus.subscribe([&events](const yuzu::server::detail::SseEvent& ev) {
        events.push_back(ev.event_type + ":" + ev.data);
    });

    auto req = make_gw_register(auth_mgr, "agent-failclosed-1");
    apb::RegisterResponse resp;
    auto status = gateway_svc.ProxyRegister(/*context=*/nullptr, &req, &resp);
    CHECK_FALSE(status.ok()); // fail-CLOSED: register_fresh degraded, RPC refused
    CHECK(status.error_code() == grpc::StatusCode::UNAVAILABLE);
    CHECK(metrics
              .counter("yuzu_server_gateway_route_write_failed_total",
                       {{"op", "register_fresh"}, {"reason", "store_unavailable"}})
              .value() == 1);

    // The ghost-session rollback: no session left on record, the connected gauge back at 0, and
    // an agent-offline event published for the rollback (following register_agent's own
    // agent-online publish). Pre-fix, `get_session` here returned a live (if useless — no stream,
    // no session_id) AgentSession forever, and the gauge stayed at 1.
    CHECK(registry.get_session("agent-failclosed-1") == nullptr);
    CHECK(metrics.gauge("yuzu_agents_connected").value() == 0);
    REQUIRE(events.size() == 2);
    CHECK(events[0] == "agent-online:agent-failclosed-1");
    CHECK(events[1] == "agent-offline:agent-failclosed-1");

    bus.unsubscribe(sub);
}

TEST_CASE("AgentRegistry::remove_agent_if_same: pointer identity, not session_id, is the "
          "rollback key — a concurrent registration that already superseded the rolled-back "
          "session survives untouched (HA WS-4 4.2b follow-up, #4344 MEDIUM finding 1)",
          "[gateway_route_wiring]") {
    // Both sessions installed below have an EMPTY session_id (map_session, which only runs on a
    // live Subscribe stream, never fires here) — the exact state ProxyRegister's own `installed`
    // capture is in when a rollback would fire (register_fresh runs long before any stream is
    // established). A session_id-STRING-keyed rollback ("" == "") could not tell these two
    // sessions apart and would delete whichever is current regardless of which one the caller
    // actually meant to undo — this test's second SECTION is the case that would fail under that
    // (hypothetical, pre-fix-shaped) implementation.
    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};

    apb::AgentInfo info;
    info.set_agent_id("agent-rollback-identity");
    info.set_hostname("host-1");
    info.mutable_platform()->set_os("linux");
    info.mutable_platform()->set_arch("x86_64");

    auto first = registry.register_agent(info);
    REQUIRE(first.has_value());
    auto installed_first = *first;
    REQUIRE(installed_first->session_id.empty());

    SECTION("no concurrent registration: rollback removes the session it installed") {
        registry.remove_agent_if_same("agent-rollback-identity", installed_first);
        CHECK(registry.get_session("agent-rollback-identity") == nullptr);
        CHECK(metrics.gauge("yuzu_agents_connected").value() == 0);
    }

    SECTION("a concurrent registration already superseded it: rollback is a NO-OP, the newer "
            "session survives") {
        info.set_hostname("host-2"); // distinguishes the second session for the assertion below
        auto second = registry.register_agent(info);
        REQUIRE(second.has_value());
        auto installed_second = *second;
        REQUIRE(installed_second != installed_first); // genuinely a different object
        REQUIRE(installed_second->session_id.empty()); // same empty-session_id shape as the first

        // Roll back using the FIRST call's captured pointer, exactly as ProxyRegister's
        // register_fresh-failure branch would (it only ever holds the pointer from its OWN
        // register_agent call, never a later caller's).
        registry.remove_agent_if_same("agent-rollback-identity", installed_first);

        auto current = registry.get_session("agent-rollback-identity");
        REQUIRE(current != nullptr); // NOT removed — the no-op case
        CHECK(current == installed_second); // the SECOND (still-current) session, untouched
        CHECK(current->hostname == "host-2");
        CHECK(metrics.gauge("yuzu_agents_connected").value() == 1); // still 1, not decremented
    }
}

TEST_CASE("ProxyRegister: a session that LOSES its register_fresh epoch race still leaves its "
          "OWN session installed on the registry (only the DIRECTORY row is lost, never the "
          "in-memory session — the epoch-race branch is NOT the register_fresh-FAILURE branch "
          "and must not roll anything back)",
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

    auto req1 = make_gw_register(auth_mgr, "agent-race-noop-rollback");
    apb::RegisterResponse resp1;
    REQUIRE(gateway_svc.ProxyRegister(/*context=*/nullptr, &req1, &resp1).ok());
    auto row1 = store.lookup_route("agent-race-noop-rollback");
    REQUIRE(row1.has_value());
    REQUIRE(row1->has_value());

    // Force the SECOND ProxyRegister's register_fresh to lose its epoch race (see
    // raw_bump_epoch's header comment above).
    raw_bump_epoch(db.dsn(), "agent-race-noop-rollback", (*row1)->connection_epoch + 1000,
                  "gw-session-already-won");

    auto req2 = make_gw_register(auth_mgr, "agent-race-noop-rollback");
    apb::RegisterResponse resp2;
    auto status = gateway_svc.ProxyRegister(/*context=*/nullptr, &req2, &resp2);
    CHECK(status.ok()); // still OK — losing the epoch race is NOT a register_fresh failure
    CHECK(resp2.accepted());

    // The losing call's OWN session is still on the registry — `!res->won` never calls
    // remove_agent_if_same. (This is a DIFFERENT agent_id from the desync-counter race test
    // above, so this registry entry is exclusively this call's.)
    CHECK(registry.get_session("agent-race-noop-rollback") != nullptr);
    CHECK(metrics.gauge("yuzu_agents_connected").value() == 1);
}

TEST_CASE("NotifyStreamStatus: a degraded GatewayRouteStore announce_connected write does NOT "
          "fail the RPC (fail-OPEN — Task B, 4.2b) and is counted",
          "[pg][gateway_route_wiring]") {
    // announce_connected stays fail-OPEN (Task B, 4.2b): the CONNECTED notify
    // is a droppable gen_server:cast and registry_.set_gateway_route has
    // already published the in-memory route by the time this write runs. A
    // REAL store is needed first so ProxyRegister (now fail-CLOSED on
    // register_fresh) succeeds and mints a session; the store is then SWAPPED
    // for a broken one so only the FOLLOW-UP announce_connected write
    // degrades.
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

    auto req = make_gw_register(auth_mgr, "agent-failopen-1");
    apb::RegisterResponse resp;
    REQUIRE(gateway_svc.ProxyRegister(/*context=*/nullptr, &req, &resp).ok());

    PgPool broken_pool{{.conninfo = "not a valid conninfo string ===", .size = 1}};
    GatewayRouteStore broken_store{broken_pool};
    REQUIRE_FALSE(broken_store.is_open());
    gateway_svc.set_gateway_route_store(&broken_store);

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
