// SPDX-License-Identifier: Apache-2.0

#include "grpc_listener.hpp"

#include <grpcpp/grpcpp.h>

#include <regex>
#include <stdexcept>
#include <string>
#include <utility>

#include "grpc_channel.hpp"  // for make_grpc_server_credentials

namespace yuzu::transport::grpc_backend {

namespace {

bool method_name_well_formed(std::string_view method) {
    if (method.empty() || method.size() > kMaxMethodSize) return false;
    static const std::regex re{
        R"(^[A-Za-z][A-Za-z0-9_.]*\/[A-Za-z][A-Za-z0-9_]*$)"};
    return std::regex_match(method.begin(), method.end(), re);
}

}  // namespace

GrpcServerListener::GrpcServerListener() = default;

GrpcServerListener::~GrpcServerListener() {
    if (started_.load(std::memory_order_acquire) &&
        !shutting_down_.load(std::memory_order_acquire)) {
        shutdown();
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
    std::lock_guard<std::mutex> lock(mu_);
    unary_handlers_.emplace(
        std::move(method),
        UnaryRegistration{std::move(request_factory),
                          std::move(response_factory),
                          std::move(handler)});
}

void GrpcServerListener::register_bidi_stream(std::string method,
                                              BidiStreamHandler handler) {
    enforce_method_or_die(method);
    std::lock_guard<std::mutex> lock(mu_);
    bidi_handlers_.emplace(std::move(method), std::move(handler));
}

std::expected<void, Status> GrpcServerListener::start(
    const Endpoint& bind, const Credentials& creds,
    const ListenerOptions& opts) {
    if (started_.exchange(true, std::memory_order_acq_rel)) {
        return std::unexpected(
            Status{StatusCode::FailedPrecondition,
                   "ServerListener::start called twice"});
    }

    std::string detail;
    auto server_creds = make_grpc_server_credentials(creds, detail);
    if (!server_creds) {
        started_.store(false, std::memory_order_release);
        return std::unexpected(Status{StatusCode::Unauthenticated, detail});
    }

    {
        std::lock_guard<std::mutex> lock(mu_);
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
    const std::size_t frame_cap =
        opts.max_frame_size > 0 ? opts.max_frame_size : kDefaultMaxFrameSize;
    if (frame_cap > kAbsoluteMaxFrameSize) {
        started_.store(false, std::memory_order_release);
        return std::unexpected(Status{
            StatusCode::InvalidArgument,
            "ListenerOptions::max_frame_size exceeds kAbsoluteMaxFrameSize"});
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
    std::unique_lock<std::mutex> lock(mu_);
    shutdown_cv_.wait(
        lock, [this] { return shutting_down_.load(std::memory_order_acquire); });
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
        server_->Shutdown();
    }
    {
        std::lock_guard<std::mutex> lock(mu_);
        shutdown_cv_.notify_all();
    }
}

bool GrpcServerListener::is_serving() const noexcept {
    return started_.load(std::memory_order_acquire) &&
           !shutting_down_.load(std::memory_order_acquire);
}

}  // namespace yuzu::transport::grpc_backend
