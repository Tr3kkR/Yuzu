// SPDX-License-Identifier: Apache-2.0
//
// agents/core/include/yuzu/agent/detail/parse_target_address.hpp
//
// Internal helper exposed in a header so unit tests can exercise the
// rejection-path matrix in isolation. NOT public API; the `detail` path
// signals that consumers outside agent_core / its test suite must not
// include this header.
//
// Symmetric sibling: server.cpp's parse_listen_address (server-side
// bind parser, strips IPv6 brackets). Both will collapse into a single
// transport-library helper in #376 PR 1c-6.

#pragma once

#include <yuzu/transport/transport.hpp>

#include <charconv>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>

namespace yuzu::agent::detail {

// Parse "host:port" / "[ipv6]:port" into the transport's Endpoint.
// Returns nullopt on malformed input. Brackets are RETAINED in the host
// field for IPv6 forms because the gRPC backend constructs targets as
// `host + ":" + port` and needs `[::1]:50051` as a valid literal.
[[nodiscard]] inline std::optional<::yuzu::transport::Endpoint>
parse_target_address(std::string_view addr) noexcept {
    ::yuzu::transport::Endpoint e{};
    if (addr.empty())
        return std::nullopt;
    std::string_view port_sv;
    if (addr.front() == '[') {
        auto close = addr.find(']');
        if (close == std::string_view::npos)
            return std::nullopt;
        e.host = std::string{addr.substr(0, close + 1)};
        if (close + 1 == addr.size())
            return std::nullopt;
        if (addr[close + 1] != ':')
            return std::nullopt;
        port_sv = addr.substr(close + 2);
    } else {
        auto colon = addr.rfind(':');
        if (colon == std::string_view::npos)
            return std::nullopt;
        e.host = std::string{addr.substr(0, colon)};
        port_sv = addr.substr(colon + 1);
    }
    if (e.host.empty() || port_sv.empty())
        return std::nullopt;
    uint32_t port_raw = 0;
    auto* first = port_sv.data();
    auto* last = port_sv.data() + port_sv.size();
    auto [ptr, ec] = std::from_chars(first, last, port_raw);
    if (ec != std::errc{} || ptr != last)
        return std::nullopt;
    if (port_raw == 0 || port_raw > 0xFFFFu)
        return std::nullopt;
    e.port = static_cast<uint16_t>(port_raw);
    return e;
}

} // namespace yuzu::agent::detail
