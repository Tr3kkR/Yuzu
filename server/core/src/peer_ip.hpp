#pragma once

/// @file peer_ip.hpp
/// Shared gRPC peer-string → bare-IP parser.
///
/// Hoisted (W1.3 R2 / consistency MEDIUM-1) after a third caller appeared:
///   1. AgentServiceImpl::Subscribe (peer-mismatch check, #826)
///   2. GatewayUpstreamServiceImpl::ProxyRegister (trusted-gateway noting, #826)
///   3. test_agent_service_impl.cpp (extract_peer_ip unit tests)
///
/// The previous deferred comment on each of the two original copies promised
/// to fold into a shared header "when a third caller appears." The tests file
/// is that third caller — both production sites called the same logic, and
/// drift between them would silently regress the #826 IP-binding fix.

#include <string>
#include <string_view>

namespace yuzu::server::detail {

/// Extract the bare IP from a gRPC peer string.
///
/// gRPC peer encoding (per src/core/lib/iomgr/parse_address.cc):
///   ipv4:1.2.3.4:5678
///   ipv6:[::1]:5678        — brackets always present for v6
///   ipv6:[2001:db8::1]:443
///   unix:/tmp/sock         — no IP, returns empty (caller treats as mismatch)
///
/// Examples:
///   "ipv4:1.2.3.4:5678"      -> "1.2.3.4"
///   "ipv6:[::1]:5678"        -> "::1"
///   "ipv6:[2001:db8::1]:443" -> "2001:db8::1"
///   "unix:/tmp/sock"         -> ""
///   ""                       -> ""
///
/// **#826 invariant.** Callers MUST treat empty as a mismatch (never as a
/// wild match). Empty bypasses the peer-binding check the entire vulnerability
/// turns on. `AgentRegistry::is_trusted_gateway_peer` and
/// `AgentRegistry::note_trusted_gateway_peer` both refuse empty as
/// defence-in-depth, but the contract starts here.
inline std::string extract_peer_ip(std::string_view peer) {
    auto colon = peer.find(':');
    if (colon == std::string_view::npos)
        return {};
    auto scheme = peer.substr(0, colon);
    auto rest = peer.substr(colon + 1);
    if (scheme == "ipv6") {
        // [addr]:port  — strip brackets, drop trailing :port
        if (rest.empty() || rest.front() != '[')
            return {}; // malformed
        auto close = rest.find(']');
        if (close == std::string_view::npos)
            return {};
        return std::string(rest.substr(1, close - 1));
    }
    if (scheme == "ipv4") {
        // addr:port
        auto port_colon = rest.rfind(':');
        if (port_colon == std::string_view::npos)
            return std::string(rest);
        return std::string(rest.substr(0, port_colon));
    }
    // unix / other — no IP to extract
    return {};
}

} // namespace yuzu::server::detail
