/**
 * server_address_resolver.cpp -- see server_address_resolver.hpp for the
 * contract.
 */

#include <yuzu/agent/server_address_resolver.hpp>

#include <yuzu/agent/server_address_parsers.hpp>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h> // getaddrinfo/inet_ntop
#pragma comment(lib, "ws2_32.lib")
#else
#include <arpa/inet.h> // inet_ntop
#include <netdb.h>     // getaddrinfo
#include <sys/socket.h>
#endif

#include <icmp_probe.hpp> // yuzu::shared::AddrInfoGuard (agents/shared)

#include <chrono>
#include <future>
#include <vector>

namespace yuzu::agent {

namespace {

#ifdef _WIN32
// Idempotent Winsock init (getaddrinfo requires it) -- same RAII-static
// pattern as agents/core/src/cloud_identity.cpp's ensure_wsa(), duplicated
// locally rather than shared for the same reason that file's own comment
// gives: this call is self-contained and has no cross-module reason to
// route through it.
void ensure_wsa_init() {
    struct WsaInit {
        WsaInit() {
            WSADATA wsa;
            WSAStartup(MAKEWORD(2, 2), &wsa);
        }
        ~WsaInit() { WSACleanup(); }
    };
    static WsaInit init;
    (void)init;
}
#endif

// Blocking getaddrinfo() call -- run only on the std::async task below,
// never directly on the caller's thread. Adopts the result into
// yuzu::shared::AddrInfoGuard IMMEDIATELY on success, before any
// allocating operation (std::string construction, vector growth) that
// could throw and leak the chain.
std::vector<std::string> getaddrinfo_literals(std::string host) {
    std::vector<std::string> out;
#ifdef _WIN32
    ensure_wsa_init();
#endif
    struct addrinfo hints {};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* raw = nullptr;
    if (::getaddrinfo(host.c_str(), nullptr, &hints, &raw) != 0 || !raw)
        return out;
    yuzu::shared::AddrInfoGuard guard{raw};
    for (auto* p = guard.p; p != nullptr; p = p->ai_next) {
        char buf[INET6_ADDRSTRLEN] = {};
        const void* addr = nullptr;
        if (p->ai_family == AF_INET)
            addr = &reinterpret_cast<struct sockaddr_in*>(p->ai_addr)->sin_addr;
        else if (p->ai_family == AF_INET6)
            addr = &reinterpret_cast<struct sockaddr_in6*>(p->ai_addr)->sin6_addr;
        else
            continue;
        if (::inet_ntop(p->ai_family, addr, buf, sizeof(buf))) {
            std::string lit{buf};
            bool dup = false;
            for (const auto& existing : out) {
                if (existing == lit) {
                    dup = true;
                    break;
                }
            }
            if (!dup)
                out.push_back(std::move(lit));
        }
    }
    return out;
}

} // namespace

std::string resolve_server_address_literals(std::string_view target) {
    const std::string host = extract_server_host(target);
    if (host.empty())
        return {};
    if (looks_like_ip_literal(host))
        return host;

    // Bounded: agent startup must never hang indefinitely on a wedged
    // resolver (an NSS module against a degraded domain controller has no
    // reliable timeout of its own to fall back on). The std::async task
    // keeps running to completion even past the wait_for deadline below --
    // safe here specifically because this whole translation unit lives in
    // agent-core, never dlclose()'d, so a late-arriving result is simply
    // discarded rather than racing an unload (the risk this exact shape
    // would carry inside a PLUGIN).
    auto fut = std::async(std::launch::async, getaddrinfo_literals, host);
    constexpr auto kResolveDeadline = std::chrono::seconds(5);
    if (fut.wait_for(kResolveDeadline) != std::future_status::ready)
        return {};

    const std::vector<std::string> literals = fut.get();
    std::string joined;
    for (size_t i = 0; i < literals.size(); ++i) {
        if (i)
            joined += ",";
        joined += literals[i];
    }
    return joined;
}

} // namespace yuzu::agent
