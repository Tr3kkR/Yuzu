// SPDX-License-Identifier: Apache-2.0
// Implements the public factories declared in
// <yuzu/transport/transport.hpp> for the gRPC backend.

#include "grpc_channel.hpp"
#include "grpc_listener.hpp"

#include <memory>
#include <string_view>

#include "yuzu/transport/transport.hpp"

namespace yuzu::transport {

std::unique_ptr<Channel> make_channel(
    Backend backend, const Endpoint& target, const Credentials& creds,
    BackoffPolicy backoff, std::shared_ptr<TransportMetricSink> metric_sink) {
    switch (backend) {
        case Backend::Grpc:
            return std::make_unique<grpc_backend::GrpcChannel>(
                target, creds, backoff, std::move(metric_sink));
        case Backend::Msquic:
            // PR 3 lands msquic backend; for now signal "backend not
            // linked" by returning nullptr.
            return nullptr;
    }
    return nullptr;
}

std::unique_ptr<ServerListener> make_server_listener(Backend backend) {
    switch (backend) {
        case Backend::Grpc:
            return std::make_unique<grpc_backend::GrpcServerListener>();
        case Backend::Msquic:
            return nullptr;
    }
    return nullptr;
}

std::string_view backend_name(Backend b) noexcept {
    switch (b) {
        case Backend::Grpc:   return "grpc";
        case Backend::Msquic: return "msquic";
    }
    return "unknown";
}

std::expected<Backend, Status> parse_backend(std::string_view name) noexcept {
    if (name == "grpc")   return Backend::Grpc;
    if (name == "msquic") return Backend::Msquic;
    if (name == "quic")   return Backend::Msquic;  // PR 5 --transport=quic alias
    return std::unexpected(
        Status{StatusCode::InvalidArgument,
               std::string{"unknown transport backend: "} + std::string{name}});
}

}  // namespace yuzu::transport
