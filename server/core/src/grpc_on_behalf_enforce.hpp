// Enforces the on-behalf-of rejection OnBehalfRejectInterceptor already
// signaled (ADR-1005 Interim rules, execution-plan PR 1.1).
//
// The interceptor's own doc comment names the limit: ServerContext::TryCancel()
// cancels the client-visible RPC but does NOT stop a sync unary/streaming
// handler from running — the payload already arrived with the call, so the
// handler may execute fully and its side effects commit before the client
// observes CANCELLED.
//
// EARLIER VERSION OF THIS HEADER read `context->IsCancelled()` as the
// enforcement check — WRONG, discovered by the end-to-end test in
// test_grpc_on_behalf_enforce.cpp: TryCancel()'s effect on IsCancelled() is
// NOT synchronously visible to the handler thread — it propagates through
// gRPC-core's internal call machinery on its own schedule, which races
// against the sync-server thread pool picking up and invoking the handler.
// Empirically ~1-in-5 runs under test load, IsCancelled() was still false
// when the handler's first statement ran, and the handler proceeded past
// the guard. A security enforcement check that is merely usually-correct is
// wrong by definition.
//
// This version reads the ground truth directly instead: it re-runs
// onbehalf::find_reserved_key() over context->client_metadata() — the SAME
// parsed headers the interceptor itself inspected. client_metadata() carries
// no such race: gRPC cannot invoke a unary/streaming handler before all
// initial metadata for the call has been received and parsed, so the map is
// already complete and immutable by the time any handler statement runs, on
// every call, deterministically. The interceptor's TryCancel() is still
// useful (fast transport-level abort, especially for a long-lived stream)
// and stays in place unchanged; this header no longer depends on it.
//
// Call `if (auto s = onbehalf::enforce(context); !s.ok()) return s;` as the
// FIRST statement of every RPC handler reachable through the ServerBuilder
// the interceptor is registered on — before any work that could commit a
// side effect (registry mutation, DB write, audit row) — so a
// reserved-header call is a true no-op, not merely a wrong status code on an
// already-committed action. Mirrors the exact idiom
// `AgentServiceImpl::reject_revoked_peer` already established in this
// codebase for a structurally identical guard.
//
// Deliberately a free function, not a per-class method: it needs no
// instance state, and a free function keeps the same one-line guard usable
// identically from every service impl class the interceptor covers
// (AgentServiceImpl, GatewayUpstreamServiceImpl, and any future one) — the
// same "no per-RPC-method gap by construction" property the interceptor
// itself has, now extended to enforcement. This guard's own coverage is
// still a manual per-handler convention, not itself mechanically enforced
// like the interceptor's single registration — a future RPC method (on any
// service registered on the same ServerBuilder, including a future
// ManagementServiceImpl handler) must remember to call this first; nothing
// currently fails CI if it doesn't (tracked as issue #2005: a per-handler
// zero-side-effect test or a static CI lint). test_grpc_on_behalf_enforce.cpp
// covers Register (unary), Subscribe (streaming — the "command-result
// handler"), and iterates every kReservedKeys entry over the real wire; it
// does not yet cover all 11 sites individually.
//
// `context == nullptr` returns OK (not rejected) rather than failing closed.
// This is NOT a production fail-open path — gRPC always supplies a real
// ServerContext per call; a null context only ever occurs in this
// codebase's OWN established unit-test convention of calling a handler
// method directly (bypassing gRPC transport entirely) to exercise its
// business logic without a live call — see e.g. the ~20 `nullptr`-context
// call sites already in test_agent_service_impl.cpp, several asserting
// `.ok()`. Failing closed here would break that established convention
// wholesale for a state gRPC itself never produces.
//
// Relies on the interceptor (grpc_on_behalf_interceptor.hpp) for the
// rejection metric/log — this function only enforces, it does not itself
// call `note_rejection`. Do not call it on a context that did not traverse
// the registered ServerBuilder's interceptor chain.

#pragma once

#include <grpcpp/server_context.h>

#include "on_behalf_guard.hpp"

namespace yuzu::server::onbehalf {

[[nodiscard]] inline grpc::Status enforce(grpc::ServerContext* context) {
    if (context == nullptr) return grpc::Status::OK;
    if (find_reserved_key(context->client_metadata())) {
        return grpc::Status(grpc::StatusCode::CANCELLED,
                            "on-behalf-of assertions are not accepted on any surface (ADR-1005)");
    }
    return grpc::Status::OK;
}

}  // namespace yuzu::server::onbehalf
