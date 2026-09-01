/**
 * test_ota_download_bound.cpp — the OTA pull bounds, exercised over a REAL
 * gRPC wire (issues #913 per-peer admission, #416 positive identity).
 *
 * WHY A LIVE SERVER. `grpc::ServerWriter` is a `final` class with a non-public
 * constructor, so a server-streaming handler cannot be driven by constructing a
 * writer the way a unary handler can be driven with a stack `ServerContext`.
 * There is no mock. The only way to execute `DownloadUpdate` at all is an
 * in-process server and a real client stub, which is the pattern
 * test_grpc_on_behalf_enforce.cpp established.
 *
 * WHY NO POSTGRES. `UpdateRegistry` needs a `pg::PgPool`, which would put this
 * file in the `[pg]` shard and make it need a claim in the shard partition. It
 * does not need one: both gates under test run BEFORE the handler consults
 * `update_registry_`, so leaving the registry unwired (the default) lets an
 * admitted call fall through to `UNAVAILABLE` — which is itself the useful
 * signal that admission PASSED. Every case here is therefore non-`[pg]`.
 *
 * WHAT THIS FILE DOES NOT COVER, honestly: the chunk-streaming body — the
 * per-chunk stall budget and the watchdog's TryCancel unblocking a stalled
 * Write — is not reachable without a real package on disk and a peer that can
 * be made to stall. That deadline logic is covered deterministically in
 * test_ota_transfer_watchdog.cpp; what is proven HERE is that the gates are
 * actually wired into the handler and are reached over the real wire, in the
 * right order, with the right status codes.
 */

#include "agent_service_impl.hpp"

#include <catch2/catch_test_macros.hpp>

#include <grpcpp/grpcpp.h>

#include <chrono>
#include <memory>
#include <string>

#include "agent.grpc.pb.h"
#include "agent_registry.hpp"
#include "event_bus.hpp"

using yuzu::server::detail::AgentRegistry;
using yuzu::server::detail::AgentServiceImpl;
using yuzu::server::detail::EventBus;

namespace {

namespace apb = ::yuzu::agent::v1;

// Real grpc::Server on an ephemeral loopback port, insecure creds (test-only).
// MEMBER ORDER IS LOAD-BEARING, mirroring LiveInterceptorHarness: `svc` borrows
// references into the members declared above it, and `server_` is stopped
// explicitly in the destructor because grpc::Server's own dtor knows nothing
// about `svc`'s lifetime.
struct OtaHarness {
    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    yuzu::server::auth::AuthManager auth_mgr;
    yuzu::server::auth::AutoApproveEngine auto_approve;
    AgentServiceImpl svc{registry,
                         bus,
                         /*require_client_identity=*/false,
                         auth_mgr,
                         auto_approve,
                         metrics,
                         /*gateway_mode=*/false};

    std::unique_ptr<grpc::Server> server_;
    int port_ = 0;
    std::unique_ptr<apb::AgentService::Stub> stub_;

    void start() {
        grpc::ServerBuilder builder;
        builder.AddListeningPort("127.0.0.1:0", grpc::InsecureServerCredentials(), &port_);
        builder.RegisterService(&svc);
        server_ = builder.BuildAndStart();
        REQUIRE(server_ != nullptr);
        REQUIRE(port_ != 0);
        auto channel = grpc::CreateChannel("127.0.0.1:" + std::to_string(port_),
                                           grpc::InsecureChannelCredentials());
        stub_ = apb::AgentService::NewStub(channel);
    }

    ~OtaHarness() {
        if (server_) server_->Shutdown();
    }

    // Drives one DownloadUpdate to completion and returns its terminal status.
    // A deadline is set for the same reason test_grpc_on_behalf_enforce.cpp sets
    // one: a regression that hangs must fail this case attributably rather than
    // time out the whole suite.
    grpc::Status download(const std::string& agent_id = "agent-1") {
        apb::DownloadUpdateRequest req;
        req.set_agent_id(agent_id);
        req.set_version("9.9.9");
        req.mutable_platform()->set_os("linux");
        req.mutable_platform()->set_arch("x86_64");

        grpc::ClientContext ctx;
        ctx.set_deadline(std::chrono::system_clock::now() + std::chrono::seconds(5));
        auto reader = stub_->DownloadUpdate(&ctx, req);
        apb::DownloadUpdateChunk chunk;
        while (reader->Read(&chunk)) {
        }
        return reader->Finish();
    }

    grpc::Status check_for_update(const std::string& agent_id = "agent-1") {
        apb::CheckForUpdateRequest req;
        req.set_agent_id(agent_id);
        req.set_current_version("0.0.1");
        req.mutable_platform()->set_os("linux");
        req.mutable_platform()->set_arch("x86_64");

        apb::CheckForUpdateResponse resp;
        grpc::ClientContext ctx;
        ctx.set_deadline(std::chrono::system_clock::now() + std::chrono::seconds(5));
        return stub_->CheckForUpdate(&ctx, req, &resp);
    }
};

} // namespace

TEST_CASE("DownloadUpdate: the default configuration admits and reaches the handler body",
          "[ota][bound][grpc]") {
    OtaHarness h;
    h.start();

    // No UpdateRegistry is wired, so an ADMITTED call falls through to
    // UNAVAILABLE. That code is the proof admission passed: a rejection would
    // have returned RESOURCE_EXHAUSTED before the registry was consulted.
    // This is the case that would catch a gate accidentally shipped
    // default-deny.
    auto st = h.download();
    CHECK(st.error_code() == grpc::StatusCode::UNAVAILABLE);
}

TEST_CASE("DownloadUpdate: the per-peer concurrency bound rejects with RESOURCE_EXHAUSTED",
          "[ota][bound][grpc]") {
    OtaHarness h;
    // max_concurrent_per_peer = 0 makes the concurrency dimension reject every
    // call deterministically. Holding two real streams open to exhaust a cap of
    // 2 would need a peer that stops reading mid-stream, which is precisely the
    // stall this suite cannot manufacture without a package on disk; forcing the
    // bound instead proves the same wiring — that the concurrency dimension is
    // consulted on the real handler and maps to RESOURCE_EXHAUSTED.
    AgentServiceImpl::OtaBoundConfig cfg;
    cfg.max_concurrent_per_peer = 0;
    h.svc.set_ota_bound_config(cfg);
    h.start();

    auto st = h.download();
    CHECK(st.error_code() == grpc::StatusCode::RESOURCE_EXHAUSTED);
    // Rejected BEFORE the registry: a rejection that fell through would have
    // surfaced as UNAVAILABLE instead.
    CHECK(st.error_message().find("per-peer") != std::string::npos);
}

TEST_CASE("DownloadUpdate: the per-peer rate bound rejects with RESOURCE_EXHAUSTED",
          "[ota][bound][grpc]") {
    OtaHarness h;
    // Concurrency wide open, bucket empty from the start: isolates the RATE
    // dimension, and proves both dimensions independently reach the same wire
    // status (the documented contract — one status, reject rather than queue).
    AgentServiceImpl::OtaBoundConfig cfg;
    cfg.max_concurrent_per_peer = 64;
    cfg.rate_capacity = 0.0;
    cfg.rate_refill_per_min = 0.0;
    h.svc.set_ota_bound_config(cfg);
    h.start();

    auto st = h.download();
    CHECK(st.error_code() == grpc::StatusCode::RESOURCE_EXHAUSTED);
}

TEST_CASE("OTA identity gate: inert by default so an unenrolled agent can still pull",
          "[ota][identity][grpc]") {
    OtaHarness h;
    h.start();

    // The gate defaults OFF. This is the non-breaking property the default-cert
    // bootstrap path depends on: the agent listener does not require a client
    // certificate there, so requiring a positive identity unconditionally would
    // reject every bootstrapping agent's OTA pull.
    CHECK(h.download().error_code() == grpc::StatusCode::UNAVAILABLE);
    CHECK(h.check_for_update().error_code() == grpc::StatusCode::OK);
}

TEST_CASE("OTA identity gate: a peer with no client certificate is rejected when armed",
          "[ota][identity][grpc]") {
    OtaHarness h;
    h.svc.set_require_positive_ota_identity(true);
    h.start();

    // This client connects over an insecure channel and so presents no identity.
    // Both agent-initiated OTA RPCs must refuse it once the gate is armed —
    // CheckForUpdate included, because its unverified agent_id selects rollout
    // eligibility even though it streams nothing.
    auto dl = h.download();
    CHECK(dl.error_code() == grpc::StatusCode::UNAUTHENTICATED);

    auto cfu = h.check_for_update();
    CHECK(cfu.error_code() == grpc::StatusCode::UNAUTHENTICATED);
}

TEST_CASE("OTA identity gate: identity is checked BEFORE admission", "[ota][identity][grpc]") {
    OtaHarness h;
    // Arm both gates. An unauthenticated peer must be refused on IDENTITY, not
    // spend an admission token first — ordering matters because admission state
    // is keyed on the very identity that has not been established yet.
    AgentServiceImpl::OtaBoundConfig cfg;
    cfg.max_concurrent_per_peer = 0; // would reject everything if reached
    h.svc.set_ota_bound_config(cfg);
    h.svc.set_require_positive_ota_identity(true);
    h.start();

    auto st = h.download();
    CHECK(st.error_code() == grpc::StatusCode::UNAUTHENTICATED);
    CHECK(st.error_code() != grpc::StatusCode::RESOURCE_EXHAUSTED);
}
