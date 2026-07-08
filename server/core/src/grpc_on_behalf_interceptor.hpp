// gRPC server interceptor rejecting on-behalf-of assertions at agent-service
// ingress (ADR-0022 Interim rules, execution-plan PR 1.1).
//
// A single interceptor — NOT a per-RPC-method check — so a future new RPC
// method cannot be added without this guard, silently reopening the gap
// (execution-plan PR 1.1 rationale). Registered on the one ServerBuilder in
// server.cpp, so it covers the agent, management, and gateway-upstream
// services alike.
//
// Rejection mechanics: gRPC server interceptors cannot synthesize a status of
// their own mid-stream, so the guard cancels the RPC via
// ServerContext::TryCancel() — a fast, transport-level abort the client
// observes as CANCELLED. TryCancel does NOT prevent the application handler
// from running: for a sync unary RPC the payload arrives with the call, the
// handler may execute fully, and its side effects would commit before the
// client-visible status changes. This interceptor is therefore a wire-level
// tripwire, not by itself an enforcement seam.
//
// The enforcement seam is grpc_on_behalf_enforce.hpp's `enforce()`, called
// as the first statement of every RPC handler reachable through the
// ServerBuilder this interceptor is registered on (AgentServiceImpl,
// GatewayUpstreamServiceImpl). It deliberately does NOT read
// ServerContext::IsCancelled() — TryCancel()'s effect on that flag is not
// synchronously visible to the handler thread (it propagates through
// gRPC-core's internal call machinery on its own schedule, racing the
// sync-server thread pool's handler dispatch; caught empirically by
// test_grpc_on_behalf_enforce.cpp). Instead it independently re-derives the
// same fact this interceptor computed, from the same ground truth
// (`context->client_metadata()`, already complete and immutable by the time
// any handler statement runs) — no shared mutable state, no race.
//
// The interceptor's own no-per-RPC-method-gap property (a single
// registration, not a per-method check) is what makes the pairing sound: a
// future new RPC method gets the TryCancel() half automatically by virtue of
// being on the same ServerBuilder, and the enforcement half by convention
// (call `if (auto s = onbehalf::enforce(context); !s.ok()) return s;` first,
// matching every existing handler).
// Defensive no-op today in effect (no engine-principal traffic crosses the
// agent gRPC channel under the plan's Decision 3, so no handler currently
// reads these metadata keys) but now actually enforced, not merely inert;
// ships now because the ADR rule binds on any surface from acceptance.

#pragma once

#include <grpcpp/support/server_interceptor.h>

#include <spdlog/spdlog.h>

#include "on_behalf_guard.hpp"
#include "yuzu/metrics.hpp"

namespace yuzu::server {

class OnBehalfRejectInterceptor final : public grpc::experimental::Interceptor {
public:
    OnBehalfRejectInterceptor(grpc::experimental::ServerRpcInfo* info,
                              yuzu::MetricsRegistry* metrics)
        : info_(info), metrics_(metrics) {}

    void Intercept(grpc::experimental::InterceptorBatchMethods* methods) override {
        if (methods->QueryInterceptionHookPoint(
                grpc::experimental::InterceptionHookPoints::POST_RECV_INITIAL_METADATA)) {
            auto* ctx = info_->server_context();
            if (ctx != nullptr) {
                auto hit = onbehalf::find_reserved_key(ctx->client_metadata());
                if (hit) {
                    bool log = metrics_ != nullptr &&
                               onbehalf::note_rejection(*metrics_, "grpc");
                    if (log) {
                        spdlog::warn(
                            "[ADR-0022] rejected gRPC call carrying reserved "
                            "on-behalf-of metadata key '{}' (method={}, peer={}); "
                            "on-behalf-of assertions are not accepted on any surface "
                            "(1 log per {} rejections; counter records all)",
                            *hit,
                            onbehalf::sanitize_for_log(
                                info_->method() ? info_->method() : "?"),
                            onbehalf::sanitize_for_log(ctx->peer()),
                            onbehalf::kLogEvery);
                    }
                    ctx->TryCancel();
                }
            }
        }
        methods->Proceed();
    }

private:
    grpc::experimental::ServerRpcInfo* info_;
    yuzu::MetricsRegistry* metrics_;
};

class OnBehalfRejectInterceptorFactory final
    : public grpc::experimental::ServerInterceptorFactoryInterface {
public:
    explicit OnBehalfRejectInterceptorFactory(yuzu::MetricsRegistry* metrics)
        : metrics_(metrics) {}

    grpc::experimental::Interceptor* CreateServerInterceptor(
        grpc::experimental::ServerRpcInfo* info) override {
        // Raw `new` is the documented gRPC interceptor-factory contract: the
        // framework takes ownership of the returned pointer and deletes it
        // when the call completes. The repo-wide no-raw-new rule is
        // deliberately excepted at this C-style framework boundary.
        return new OnBehalfRejectInterceptor(info, metrics_);
    }

private:
    yuzu::MetricsRegistry* metrics_;
};

}  // namespace yuzu::server
