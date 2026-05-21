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

#include <cstddef>
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
///
/// **#1058 strict-mode + canonicalization (W1.3 R2).** The extracted address
/// is validated against the shape it claims to be — a malformed `ipv4:`/`ipv6:`
/// body returns empty (→ mismatch) rather than a half-parsed substring, so a
/// crafted peer string can't smuggle a value past the binding check. IPv6 is
/// lowercased so the register-side and subscribe-side comparison is
/// case-insensitive on hex digits and zone ids (gRPC emits canonical form
/// today, but the comparison must not depend on that). Both comparison sides
/// go through this one function, so canonicalization is symmetric by
/// construction.
inline bool is_valid_ipv4(std::string_view s) {
    int octets = 0;
    std::size_t i = 0;
    while (i < s.size()) {
        std::size_t start = i;
        unsigned val = 0;
        while (i < s.size() && s[i] >= '0' && s[i] <= '9') {
            val = val * 10u + static_cast<unsigned>(s[i] - '0');
            ++i;
            if (i - start > 3) // > 3 digits in an octet
                return false;
        }
        if (i == start) // no digit consumed
            return false;
        if (i - start > 1 && s[start] == '0') // leading-zero octet (non-canonical)
            return false;
        if (val > 255)
            return false;
        ++octets;
        if (i == s.size())
            break;
        if (s[i] != '.') // octets separated only by '.'
            return false;
        ++i;
        if (i == s.size()) // trailing dot
            return false;
    }
    return octets == 4;
}

/// Plausible IPv6 literal. The address part is hex digits, ':' (required, at
/// least one) and '.' (v4-mapped tail); an optional `%zone` suffix (link-local
/// scope / interface name) may follow and is validated as an interface-name
/// token (alnum / '.' / '-' / '_'), since zone ids legitimately contain
/// non-hex letters like `eth0`. Deliberately not a full RFC 4291 parser — it
/// rejects clearly-malformed bodies (the strict-mode goal) without
/// re-implementing inet_pton, which gRPC already ran when it produced the peer
/// string.
inline bool is_plausible_ipv6(std::string_view s) {
    if (s.empty())
        return false;
    auto pct = s.find('%');
    std::string_view addr = (pct == std::string_view::npos) ? s : s.substr(0, pct);
    if (addr.empty())
        return false;
    bool has_colon = false;
    for (char c : addr) {
        const bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
        if (c == ':')
            has_colon = true;
        else if (!(hex || c == '.'))
            return false;
    }
    if (!has_colon)
        return false;
    if (pct != std::string_view::npos) {
        std::string_view zone = s.substr(pct + 1);
        if (zone.empty())
            return false;
        for (char c : zone) {
            const bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') ||
                            (c >= 'A' && c <= 'Z') || c == '.' || c == '-' || c == '_';
            if (!ok)
                return false;
        }
    }
    return true;
}

inline std::string to_lower_ascii(std::string_view s) {
    std::string out(s);
    for (char& c : out)
        if (c >= 'A' && c <= 'Z')
            c = static_cast<char>(c - 'A' + 'a');
    return out;
}

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
        auto addr = rest.substr(1, close - 1);
        if (!is_plausible_ipv6(addr))
            return {};
        return to_lower_ascii(addr); // canonicalize hex + zone id
    }
    if (scheme == "ipv4") {
        // addr:port (port optional in some encodings)
        auto port_colon = rest.rfind(':');
        auto addr = (port_colon == std::string_view::npos) ? rest : rest.substr(0, port_colon);
        if (!is_valid_ipv4(addr))
            return {};
        return std::string(addr);
    }
    // unix / other — no IP to extract
    return {};
}

} // namespace yuzu::server::detail
