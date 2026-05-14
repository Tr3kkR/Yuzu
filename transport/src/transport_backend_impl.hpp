// SPDX-License-Identifier: Apache-2.0
// Internal per-backend factory hooks.
//
// The public factories (make_channel / make_server_listener) live in
// transport_factory.cpp, which is always compiled. Each backend TU
// (grpc_transport.cpp, msquic_transport.cpp) provides the matching
// make_*_impl definitions, guarded by the YUZU_TRANSPORT_HAVE_* compile
// define meson sets from the `transport` option. A backend that is not
// compiled in contributes neither the define nor the symbols, and
// transport_factory.cpp returns nullptr for that Backend value.

#pragma once

#include <memory>

#include "yuzu/transport/transport.hpp"

namespace yuzu::transport {

#ifdef YUZU_TRANSPORT_HAVE_GRPC
namespace grpc_backend {
std::unique_ptr<Channel> make_channel_impl(
    const Endpoint& target, const Credentials& creds, BackoffPolicy backoff,
    std::shared_ptr<TransportMetricSink> metric_sink);
std::unique_ptr<ServerListener> make_server_listener_impl();
}  // namespace grpc_backend
#endif

#ifdef YUZU_TRANSPORT_HAVE_MSQUIC
namespace msquic_backend {
std::unique_ptr<Channel> make_channel_impl(
    const Endpoint& target, const Credentials& creds, BackoffPolicy backoff,
    std::shared_ptr<TransportMetricSink> metric_sink);
std::unique_ptr<ServerListener> make_server_listener_impl();
}  // namespace msquic_backend
#endif

}  // namespace yuzu::transport
