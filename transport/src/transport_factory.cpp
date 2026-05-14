// SPDX-License-Identifier: Apache-2.0
// Implements the public factories declared in
// <yuzu/transport/transport.hpp>. Always compiled into yuzu_transport,
// regardless of which backend(s) the `transport` meson option selects.
//
// Backend selection is by compile define: meson sets YUZU_TRANSPORT_HAVE_GRPC
// and/or YUZU_TRANSPORT_HAVE_MSQUIC from the `transport` option. A Backend
// value whose backend is not compiled in returns nullptr — the documented
// "backend not linked" signal (transport.hpp make_channel contract).

#include <memory>
#include <string>
#include <string_view>
#include <utility>

#include "transport_backend_impl.hpp"
#include "yuzu/transport/transport.hpp"

namespace yuzu::transport {

std::unique_ptr<Channel> make_channel(
    Backend backend, const Endpoint& target, const Credentials& creds,
    BackoffPolicy backoff, std::shared_ptr<TransportMetricSink> metric_sink) {
    switch (backend) {
        case Backend::Grpc:
#ifdef YUZU_TRANSPORT_HAVE_GRPC
            return grpc_backend::make_channel_impl(target, creds, backoff,
                                                   std::move(metric_sink));
#else
            return nullptr;
#endif
        case Backend::Msquic:
#ifdef YUZU_TRANSPORT_HAVE_MSQUIC
            return msquic_backend::make_channel_impl(target, creds, backoff,
                                                     std::move(metric_sink));
#else
            return nullptr;
#endif
    }
    return nullptr;
}

std::unique_ptr<ServerListener> make_server_listener(Backend backend) {
    switch (backend) {
        case Backend::Grpc:
#ifdef YUZU_TRANSPORT_HAVE_GRPC
            return grpc_backend::make_server_listener_impl();
#else
            return nullptr;
#endif
        case Backend::Msquic:
#ifdef YUZU_TRANSPORT_HAVE_MSQUIC
            return msquic_backend::make_server_listener_impl();
#else
            return nullptr;
#endif
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
