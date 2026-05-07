// SPDX-License-Identifier: Apache-2.0

#include "grpc_listener.hpp"

#include <grpcpp/grpcpp.h>

#include <stdexcept>
#include <string>
#include <utility>

#include "grpc_channel.hpp"           // for make_grpc_server_credentials
#include "grpc_method_validator.hpp"  // method_name_well_formed

namespace yuzu::transport::grpc_backend {

GrpcServerListener::GrpcServerListener() = default;

GrpcServerListener::~GrpcServerListener() {
    if (started_.load(std::memory_order_acquire) &&
        !shutting_down_.load(std::memory_order_acquire)) {
        // Sink any throws — destructors must not propagate (governance
        // UP-10 sibling). Shutdown itself doesn't throw, but the
        // metric-sink callback is user-supplied.
        try {
            shutdown();
        } catch (...) {
            // Documented as noexcept; swallow defensively.
        }
    }
}

void GrpcServerListener::enforce_method_or_die(const std::string& method) {
    if (!method_name_well_formed(method)) {
        // Per transport.hpp register_unary contract: registering a
        // malformed method is a programmer error. Throwing here is
        // appropriate because register_* runs at process startup,
        // not in production hot paths.
        throw std::invalid_argument(
            "yuzu::transport: method name fails validation contract: " +
            method);
    }
    if (started_.load(std::memory_order_acquire)) {
        throw std::logic_error(
            "yuzu::transport: register_* after start() is not permitted");
    }
}

void GrpcServerListener::register_unary(
    std::string method,
    std::function<std::unique_ptr<SerializableMessage>()> request_factory,
    std::function<std::unique_ptr<SerializableMessage>()> response_factory,
    UnaryHandler handler) {
    enforce_method_or_die(method);
    std::lock_guard<std::mutex> lock(mtx_);
    // Reject duplicate registration: silent first-wins is a debugging
    // foot-gun (governance UP-7). The contract is now "throw on
    // collision" — operators see a clear error instead of mysterious
    // dispatch behaviour.
    if (unary_handlers_.contains(method) || bidi_handlers_.contains(method)) {
        throw std::invalid_argument(
            "yuzu::transport: method already registered: " + method);
    }
    unary_handlers_.emplace(
        std::move(method),
        UnaryRegistration{std::move(request_factory),
                          std::move(response_factory), std::move(handler)});
}

void GrpcServerListener::register_bidi_stream(std::string method,
                                              BidiStreamHandler handler) {
    enforce_method_or_die(method);
    std::lock_guard<std::mutex> lock(mtx_);
    if (unary_handlers_.contains(method) || bidi_handlers_.contains(method)) {
        throw std::invalid_argument(
            "yuzu::transport: method already registered: " + method);
    }
    bidi_handlers_.emplace(std::move(method), std::move(handler));
}

std::expected<void, Status> GrpcServerListener::start(
    const Endpoint& bind, const Credentials& creds,
    const ListenerOptions& opts) {
    // Frame-size validation BEFORE the started_ exchange so a bad opts
    // does not flip is_serving() momentarily. (governance UP-18)
    const std::size_t frame_cap =
        opts.max_frame_size > 0 ? opts.max_frame_size : kDefaultMaxFrameSize;
    if (frame_cap > kAbsoluteMaxFrameSize) {
        return std::unexpected(Status{
            StatusCode::InvalidArgument,
            "ListenerOptions::max_frame_size exceeds kAbsoluteMaxFrameSize"});
    }

    if (started_.exchange(true, std::memory_order_acq_rel)) {
        return std::unexpected(Status{StatusCode::FailedPrecondition,
                                      "ServerListener::start called twice"});
    }

    std::string detail;
    auto server_creds = make_grpc_server_credentials(creds, detail);
    if (!server_creds) {
        started_.store(false, std::memory_order_release);
        return std::unexpected(Status{StatusCode::Unauthenticated, detail});
    }

    {
        std::lock_guard<std::mutex> lock(mtx_);
        opts_ = opts;
    }

    const std::string addr = bind.host + ":" + std::to_string(bind.port);
    ::grpc::ServerBuilder builder;
    builder.AddListeningPort(addr, server_creds);

    if (opts.max_concurrent_streams_per_connection > 0) {
        builder.AddChannelArgument(
            GRPC_ARG_MAX_CONCURRENT_STREAMS,
            static_cast<int>(opts.max_concurrent_streams_per_connection));
    }
    builder.SetMaxReceiveMessageSize(static_cast<int>(frame_cap));
    builder.SetMaxSendMessageSize(static_cast<int>(frame_cap));

    // PR 1b: register a grpc::AsyncGenericService here and route
    // incoming calls through it to unary_handlers_/bidi_handlers_.
    // PR 1a builds with no service registered, so the listener accepts
    // connections but every RPC returns Unimplemented (which is the
    // documented contract for an unregistered method).

    server_ = builder.BuildAndStart();
    if (!server_) {
        started_.store(false, std::memory_order_release);
        return std::unexpected(
            Status{StatusCode::Unavailable,
                   "gRPC ServerBuilder::BuildAndStart returned null"});
    }
    if (opts.metric_sink) {
        opts.metric_sink->on_connection_opened("grpc");
    }
    return {};
}

void GrpcServerListener::wait_for_shutdown() {
    std::unique_lock<std::mutex> lock(mtx_);
    shutdown_cv_.wait(
        lock,
        [this] { return shutting_down_.load(std::memory_order_acquire); });
}

void GrpcServerListener::shutdown() {
    if (shutting_down_.exchange(true, std::memory_order_acq_rel)) {
        return;  // idempotent
    }
    if (server_) {
        // Per the shutdown trailing-status guarantee in transport.hpp:
        // active server-streaming and bidi-streaming handlers receive
        // StatusCode::Unavailable so agents reconnect immediately. PR 1b
        // wires this through the AsyncGenericService dispatcher; in PR
        // 1a there is no live RPC dispatch path so the guarantee is
        // structurally vacuous.
        //
        // PR 1b should also pass a deadline to Shutdown() so a wedged
        // handler does not block forever (governance UP-13). PR 1a has
        // no live handlers so the no-deadline form is safe.
        server_->Shutdown();
    }
    {
        std::lock_guard<std::mutex> lock(mtx_);
        shutdown_cv_.notify_all();
    }
}

bool GrpcServerListener::is_serving() const noexcept {
    return started_.load(std::memory_order_acquire) &&
           !shutting_down_.load(std::memory_order_acquire);
}

}  // namespace yuzu::transport::grpc_backend
