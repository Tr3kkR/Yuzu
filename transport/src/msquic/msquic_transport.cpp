// SPDX-License-Identifier: Apache-2.0
// msquic backend factory hooks. The public factories live in
// transport/src/transport_factory.cpp; this TU provides only the
// msquic_backend::make_*_impl definitions it dispatches to. Compiled into
// yuzu_transport when the `transport` meson option includes msquic.

#include <memory>
#include <utility>

#include "../transport_backend_impl.hpp"
#include "msquic_channel.hpp"
#include "msquic_listener.hpp"
#include "yuzu/transport/transport.hpp"

namespace yuzu::transport::msquic_backend {

std::unique_ptr<Channel> make_channel_impl(
    const Endpoint& target, const Credentials& creds, BackoffPolicy backoff,
    std::shared_ptr<TransportMetricSink> metric_sink) {
    return std::make_unique<MsquicChannel>(target, creds, backoff,
                                           std::move(metric_sink));
}

std::unique_ptr<ServerListener> make_server_listener_impl() {
    return std::make_unique<MsquicServerListener>();
}

}  // namespace yuzu::transport::msquic_backend
