// SPDX-License-Identifier: Apache-2.0
//
// tests/unit/server/test_gateway_service_impl.cpp
//
// #376 PR 1c-5 — register_with() coverage for
// `GatewayUpstreamServiceImpl`. The 4 unary handlers (ProxyRegister,
// BatchHeartbeat, ProxyInventory, NotifyStreamStatus) were lifted off
// `gw::GatewayUpstream::Service` and onto `transport::ServerListener`
// via `register_unary_pb<>`. These tests pin the contract that:
//
//   1. All 4 RPCs register successfully against a real transport
//      listener (no method-name typos, no factory mismatches).
//
//   2. An in-proc round-trip via `transport::Channel::unary` dispatches
//      to the typed handler bodies and returns the expected response
//      messages.
//
//   3. BatchHeartbeat with no known sessions returns acked_count == 0
//      (the canonical "gateway just spun up, no sessions yet" smoke).
//
// Full enrollment / approval branches are covered by
// `test_auto_approve.cpp` and friends — these tests focus on the lift
// boundary, not on the auth-engine paths.

#include "gateway_service_impl.hpp"

#include <yuzu/transport/proto_adapter.hpp>
#include <yuzu/transport/transport.hpp>

#include "agent_registry.hpp"
#include "event_bus.hpp"
#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>
#include <yuzu/server/auto_approve.hpp>

#include "agent.pb.h"
#include "gateway.pb.h"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <memory>

namespace agent_pb = ::yuzu::agent::v1;
namespace gw_pb = ::yuzu::gateway::v1;
using ::yuzu::transport::Backend;
using ::yuzu::transport::CallContext;
using ::yuzu::transport::ClientCertMode;
using ::yuzu::transport::Credentials;
using ::yuzu::transport::Endpoint;
using ::yuzu::transport::make_channel;
using ::yuzu::transport::make_server_listener;
using ::yuzu::transport::ServerListener;
using ::yuzu::transport::StatusCode;
using yuzu::server::detail::AgentRegistry;
using yuzu::server::detail::EventBus;
using yuzu::server::detail::GatewayUpstreamServiceImpl;

namespace {

struct GwServiceFixture {
    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    yuzu::server::auth::AuthManager auth_mgr;
    yuzu::server::auth::AutoApproveEngine auto_approve;
    GatewayUpstreamServiceImpl svc{registry, bus, auth_mgr, auto_approve, &metrics, nullptr};

    std::unique_ptr<ServerListener> listener;
    std::unique_ptr<::yuzu::transport::Channel> channel;

    GwServiceFixture() {
        listener = make_server_listener(Backend::Grpc);
        REQUIRE(listener != nullptr);
        svc.register_with(*listener);  // All 4 unary registrations happen here.

        Credentials creds{};
        creds.verify_peer = false;
        creds.client_cert_mode = ClientCertMode::None;

        Endpoint bind{"127.0.0.1", 0};
        REQUIRE(listener->start(bind, creds).has_value());
        REQUIRE(listener->is_serving());

        channel = make_channel(Backend::Grpc, listener->bound_endpoint(), creds);
        REQUIRE(channel != nullptr);
        REQUIRE(channel->wait_for_connected(std::chrono::seconds(2)));
    }

    GwServiceFixture(const GwServiceFixture&) = delete;
    GwServiceFixture& operator=(const GwServiceFixture&) = delete;
    GwServiceFixture(GwServiceFixture&&) = delete;
    GwServiceFixture& operator=(GwServiceFixture&&) = delete;

    ~GwServiceFixture() {
        if (channel) channel->close();
        if (listener) listener->shutdown();
    }
};

} // namespace

TEST_CASE("GatewayUpstream::BatchHeartbeat round-trips via transport with zero sessions",
          "[gateway][lift][unary][heartbeat]") {
    GwServiceFixture f;

    gw_pb::BatchHeartbeatRequest req;
    req.set_gateway_node("test-gw-node");
    auto* hb = req.add_heartbeats();
    hb->set_session_id("gw-session-unknown");  // unknown session → silently skipped

    gw_pb::BatchHeartbeatResponse resp;
    CallContext ctx;
    auto req_adapter = ::yuzu::transport::as_proto(req);
    auto resp_adapter = ::yuzu::transport::as_proto(resp);
    auto result = f.channel->unary(
        "yuzu.gateway.v1.GatewayUpstream/BatchHeartbeat", ctx, req_adapter, resp_adapter);
    REQUIRE(result.status.code == StatusCode::Ok);
    REQUIRE(resp.acknowledged_count() == 0);
}

TEST_CASE("GatewayUpstream::ProxyInventory round-trips via transport with unknown session",
          "[gateway][lift][unary][inventory]") {
    GwServiceFixture f;

    agent_pb::InventoryReport req;
    req.set_session_id("gw-session-unknown");

    agent_pb::InventoryAck resp;
    CallContext ctx;
    auto req_adapter = ::yuzu::transport::as_proto(req);
    auto resp_adapter = ::yuzu::transport::as_proto(resp);
    auto result = f.channel->unary(
        "yuzu.gateway.v1.GatewayUpstream/ProxyInventory", ctx, req_adapter, resp_adapter);
    REQUIRE(result.status.code == StatusCode::Ok);
    REQUIRE_FALSE(resp.received());  // session not known
}

TEST_CASE("GatewayUpstream::NotifyStreamStatus round-trips via transport with unknown session",
          "[gateway][lift][unary][stream-status]") {
    GwServiceFixture f;

    gw_pb::StreamStatusNotification req;
    req.set_session_id("gw-session-unknown");
    req.set_agent_id("agent-X");
    req.set_event(gw_pb::StreamStatusNotification::CONNECTED);
    req.set_gateway_node("test-gw-node");

    gw_pb::StreamStatusAck resp;
    CallContext ctx;
    auto req_adapter = ::yuzu::transport::as_proto(req);
    auto resp_adapter = ::yuzu::transport::as_proto(resp);
    auto result = f.channel->unary(
        "yuzu.gateway.v1.GatewayUpstream/NotifyStreamStatus", ctx, req_adapter, resp_adapter);
    REQUIRE(result.status.code == StatusCode::Ok);
    REQUIRE_FALSE(resp.acknowledged());  // session not known
}

TEST_CASE("GatewayUpstream::ProxyRegister round-trips via transport without enrollment token",
          "[gateway][lift][unary][register]") {
    GwServiceFixture f;

    agent_pb::RegisterRequest req;
    auto* info = req.mutable_info();
    info->set_agent_id("agent-pluto");
    info->set_hostname("pluto.local");
    // No enrollment_token, no auto-approve rules — falls through to Tier 1
    // (pending queue). Handler returns Ok with accepted=false +
    // enrollment_status=pending.

    agent_pb::RegisterResponse resp;
    CallContext ctx;
    auto req_adapter = ::yuzu::transport::as_proto(req);
    auto resp_adapter = ::yuzu::transport::as_proto(resp);
    auto result = f.channel->unary(
        "yuzu.gateway.v1.GatewayUpstream/ProxyRegister", ctx, req_adapter, resp_adapter);
    REQUIRE(result.status.code == StatusCode::Ok);
    REQUIRE_FALSE(resp.accepted());
    REQUIRE(resp.enrollment_status() == "pending");
}
