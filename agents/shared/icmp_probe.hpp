/**
 * icmp_probe.hpp — shared unprivileged reachability probes
 * (ADR-3002, Decision 5: deepest-interpreter-invoked rung classification
 * applies to consumers; this header itself is rung 1, native, no interpreter).
 * Consumers: discovery's ping sweep, wol's check action.
 *
 * Hoisted VERBATIM from netprobe_plugin.cpp (behaviour identical; netprobe's
 * in-plugin copy is converged onto this header as a tracked follow-up) so
 * discovery's ping sweep and wol's `check` action can probe a host natively
 * (rung 1) instead of spawning `ping`:
 *
 *   IcmpSession — ICMP echo RTT. Windows: IcmpSendEcho (iphlpapi,
 *       unprivileged; whole-millisecond granularity by API design). POSIX:
 *       unprivileged SOCK_DGRAM ICMP "ping socket" (works out of the box on
 *       macOS; on Linux gated by net.ipv4.ping_group_range — a refused socket
 *       sets `permitted=false` so callers report an honest `not-permitted` /
 *       CONSTRAINED status, never a fake 100% loss).
 *   tcp_sample — TCP connect-time RTT for targets that drop ICMP (the
 *       pragmatic fallback; unprivileged everywhere).
 *   resolve_first / set_port — getaddrinfo helpers shared by both.
 *
 * IPv4-focused like the netprobe original (IPv6 is a tracked follow-up).
 * Header-only; no spawn, no interpreter — rung 1 by construction.
 */
#pragma once

#include <chrono>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
// clang-format off
#include <iphlpapi.h>
#include <icmpapi.h> // after iphlpapi.h
// clang-format on
#else
#include <arpa/inet.h>
#include <cerrno>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace yuzu::shared {

// Move-only RAII owner for a getaddrinfo() result list -- zero-dependency
// (agents/shared leaf rule: no core/plugin type, just the platform socket
// headers this file already includes).
struct AddrInfoGuard {
    addrinfo* p{nullptr};
    AddrInfoGuard() = default;
    explicit AddrInfoGuard(addrinfo* ptr) : p(ptr) {}
    ~AddrInfoGuard() {
        if (p)
            ::freeaddrinfo(p);
    }
    AddrInfoGuard(const AddrInfoGuard&) = delete;
    AddrInfoGuard& operator=(const AddrInfoGuard&) = delete;
    AddrInfoGuard(AddrInfoGuard&& other) noexcept : p(other.p) { other.p = nullptr; }
    AddrInfoGuard& operator=(AddrInfoGuard&& other) noexcept {
        if (this != &other) {
            if (p)
                ::freeaddrinfo(p);
            p = other.p;
            other.p = nullptr;
        }
        return *this;
    }
};

#ifdef _WIN32
using SocketHandle = SOCKET;
constexpr SocketHandle kInvalidSocket = INVALID_SOCKET;
inline void close_socket(SocketHandle s) { ::closesocket(s); }
#else
using SocketHandle = int;
constexpr SocketHandle kInvalidSocket = -1;
inline void close_socket(SocketHandle s) { ::close(s); }
#endif

// Move-only RAII owner for a socket fd/SOCKET, same shape as wol_plugin.cpp's
// SocketGuard (that copy is plugin-local; this is the shared-leaf twin so
// icmp_probe.hpp's own socket acquisitions don't manually close).
struct SocketGuard {
    SocketHandle s{kInvalidSocket};
    SocketGuard() = default;
    explicit SocketGuard(SocketHandle sock) : s(sock) {}
    ~SocketGuard() {
        if (s != kInvalidSocket)
            close_socket(s);
    }
    SocketGuard(const SocketGuard&) = delete;
    SocketGuard& operator=(const SocketGuard&) = delete;
    SocketGuard(SocketGuard&& other) noexcept : s(other.s) { other.s = kInvalidSocket; }
    SocketGuard& operator=(SocketGuard&& other) noexcept {
        if (this != &other) {
            if (s != kInvalidSocket)
                close_socket(s);
            s = other.s;
            other.s = kInvalidSocket;
        }
        return *this;
    }
    bool ok() const { return s != kInvalidSocket; }
};

inline double probe_elapsed_ms(std::chrono::steady_clock::time_point t0) {
    return std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0)
        .count();
}

// One resolved address (first result of the requested family).
struct Resolved {
    sockaddr_storage addr{};
    int addr_len{0};
    int family{0};
};

// getaddrinfo wrapper: first result for `family` (AF_UNSPEC = first of any).
// nullopt on failure. The numeric-friendly hints make IP literals resolve
// without a DNS round-trip.
inline std::optional<Resolved> resolve_first(const std::string& target, int family) {
    addrinfo hints{};
    hints.ai_family = family;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* raw_res = nullptr;
    if (getaddrinfo(target.c_str(), nullptr, &hints, &raw_res) != 0 || !raw_res)
        return std::nullopt;
    AddrInfoGuard res{raw_res};
    Resolved r;
    std::memcpy(&r.addr, res.p->ai_addr, res.p->ai_addrlen);
    r.addr_len = static_cast<int>(res.p->ai_addrlen);
    r.family = res.p->ai_family;
    return r;
}

inline void set_port(Resolved& r, int port) {
    if (r.family == AF_INET)
        reinterpret_cast<sockaddr_in*>(&r.addr)->sin_port =
            htons(static_cast<std::uint16_t>(port));
    else if (r.family == AF_INET6)
        reinterpret_cast<sockaddr_in6*>(&r.addr)->sin6_port =
            htons(static_cast<std::uint16_t>(port));
}

// ── TCP connect-time sample ──────────────────────────────────────────────────

// A TCP connect attempt can end three genuinely different ways, and
// collapsing them onto one std::optional<double> lost a distinction that
// matters: `rtt_ms` set means a real connect succeeded; `refused` means the
// destination's network stack actively answered with an RST (ECONNREFUSED /
// WSAECONNREFUSED) -- POSITIVE evidence the host is up and reachable, just
// with nothing listening on this port (common for a woken desktop with no
// service on kFallbackTcpPort, especially when ICMP is also blocked);
// neither set means a genuine timeout/no-response -- no evidence either way.
// A caller that only checks `rtt_ms` (the old contract) still gets identical
// behaviour for the connected case; `refused` is new information, not a
// behaviour change for existing has_value()-style checks.
struct TcpSampleResult {
    std::optional<double> rtt_ms;
    bool refused{false};
};

#ifdef _WIN32
inline TcpSampleResult tcp_sample(const Resolved& dst, int timeout_ms) {
    TcpSampleResult result;
    SocketGuard sock{::socket(dst.family, SOCK_STREAM, IPPROTO_TCP)};
    if (!sock.ok())
        return result;
    const SOCKET s = sock.s;
    u_long nonblock = 1;
    ::ioctlsocket(s, FIONBIO, &nonblock);
    const auto t0 = std::chrono::steady_clock::now();
    int rc = ::connect(s, reinterpret_cast<const sockaddr*>(&dst.addr), dst.addr_len);
    if (rc == 0) {
        result.rtt_ms = probe_elapsed_ms(t0);
        return result;
    }
    const int err = ::WSAGetLastError();
    if (err == WSAECONNREFUSED) {
        // Rare but possible: a synchronous refusal (e.g. loopback) with no
        // async wait needed at all.
        result.refused = true;
        return result;
    }
    if (err != WSAEWOULDBLOCK)
        return result;
    fd_set wfds, efds;
    FD_ZERO(&wfds);
    FD_ZERO(&efds);
    FD_SET(s, &wfds);
    FD_SET(s, &efds);
    timeval tv{timeout_ms / 1000, (timeout_ms % 1000) * 1000};
    if (::select(0, nullptr, &wfds, &efds, &tv) <= 0)
        return result;
    // Windows signals an async connect failure (e.g. RST/refused) via the
    // EXCEPT set, not the WRITE set -- the write set alone (the old check)
    // never observed a refusal at all, so it read identically to a timeout.
    if (FD_ISSET(s, &wfds)) {
        int soerr = 0;
        int len = sizeof(soerr);
        if (::getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&soerr), &len) == 0 &&
            soerr == 0)
            result.rtt_ms = probe_elapsed_ms(t0);
        return result;
    }
    if (FD_ISSET(s, &efds)) {
        int soerr = 0;
        int len = sizeof(soerr);
        if (::getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&soerr), &len) == 0 &&
            soerr == WSAECONNREFUSED)
            result.refused = true;
    }
    return result;
}
#else
inline TcpSampleResult tcp_sample(const Resolved& dst, int timeout_ms) {
    TcpSampleResult result;
    SocketGuard sock{::socket(dst.family, SOCK_STREAM, IPPROTO_TCP)};
    if (!sock.ok())
        return result;
    const int s = sock.s;
    ::fcntl(s, F_SETFL, ::fcntl(s, F_GETFL, 0) | O_NONBLOCK);
    const auto t0 = std::chrono::steady_clock::now();
    int rc = ::connect(s, reinterpret_cast<const sockaddr*>(&dst.addr),
                       static_cast<socklen_t>(dst.addr_len));
    if (rc == 0) {
        result.rtt_ms = probe_elapsed_ms(t0);
        return result;
    }
    if (errno == ECONNREFUSED) {
        // Rare but possible: a synchronous refusal (e.g. loopback) with no
        // async wait needed at all.
        result.refused = true;
        return result;
    }
    if (errno != EINPROGRESS)
        return result;
    // Poll for the connect to settle -- do not gate on `revents & POLLOUT`:
    // a failed async connect (e.g. RST/refused) is reported on some POSIX
    // implementations via POLLERR/POLLHUP rather than POLLOUT, and the old
    // POLLOUT-only gate silently treated that identically to a timeout
    // (never reaching the getsockopt below at all). Any wakeup here means
    // the connect settled one way or another; SO_ERROR tells us which.
    pollfd pfd{s, POLLOUT, 0};
    if (::poll(&pfd, 1, timeout_ms) <= 0)
        return result;
    int soerr = 0;
    socklen_t len = sizeof(soerr);
    if (::getsockopt(s, SOL_SOCKET, SO_ERROR, &soerr, &len) == 0) {
        if (soerr == 0)
            result.rtt_ms = probe_elapsed_ms(t0);
        else if (soerr == ECONNREFUSED)
            result.refused = true;
    }
    return result;
}
#endif

// ── ICMP echo sample ─────────────────────────────────────────────────────────

#ifdef _WIN32
// IcmpSendEcho reports RoundTripTime in WHOLE milliseconds (a sub-ms LAN hop
// reads 0 — kept raw, never fudged; TCP sampling gives sub-ms fidelity).
struct IcmpSession {
    HANDLE h{INVALID_HANDLE_VALUE};
    IcmpSession() : h(::IcmpCreateFile()) {}
    ~IcmpSession() {
        if (h != INVALID_HANDLE_VALUE)
            ::IcmpCloseHandle(h);
    }
    IcmpSession(const IcmpSession&) = delete;
    IcmpSession& operator=(const IcmpSession&) = delete;
    bool ok() const { return h != INVALID_HANDLE_VALUE; }
    bool permitted{true}; // Windows ICMP is unprivileged; parity with POSIX

    std::optional<double> sample(ULONG ipv4, int timeout_ms) {
        static const char payload[24] = "yuzu-netprobe-e1-sample";
        std::vector<unsigned char> reply(sizeof(ICMP_ECHO_REPLY) + sizeof(payload) + 8);
        DWORD n = ::IcmpSendEcho(h, ipv4, const_cast<char*>(payload), sizeof(payload), nullptr,
                                 reply.data(), static_cast<DWORD>(reply.size()),
                                 static_cast<DWORD>(timeout_ms));
        if (n == 0)
            return std::nullopt;
        const auto* r = reinterpret_cast<const ICMP_ECHO_REPLY*>(reply.data());
        if (r->Status != IP_SUCCESS)
            return std::nullopt;
        return static_cast<double>(r->RoundTripTime);
    }
};
#else
// RFC 1071 internet checksum.
inline std::uint16_t icmp_checksum(const unsigned char* data, std::size_t len) {
    std::uint32_t sum = 0;
    for (std::size_t i = 0; i + 1 < len; i += 2)
        sum += static_cast<std::uint32_t>(data[i]) << 8 | data[i + 1];
    if (len & 1)
        sum += static_cast<std::uint32_t>(data[len - 1]) << 8;
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return static_cast<std::uint16_t>(~sum);
}

struct IcmpSession {
    int fd{-1};
    bool permitted{true};
    std::uint16_t seq{0};

    IcmpSession() {
        fd = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
        if (fd < 0)
            permitted = !(errno == EACCES || errno == EPERM || errno == EPROTONOSUPPORT);
        // Randomize the starting sequence: on macOS concurrent ICMP dgram
        // sockets can see each other's echo replies, and two sessions both
        // counting from 0 could cross-match a reply (and record a bogus RTT).
        seq = static_cast<std::uint16_t>(
            std::chrono::steady_clock::now().time_since_epoch().count() & 0xFFFF);
    }
    ~IcmpSession() {
        if (fd >= 0)
            ::close(fd);
    }
    IcmpSession(const IcmpSession&) = delete;
    IcmpSession& operator=(const IcmpSession&) = delete;
    bool ok() const { return fd >= 0; }

    std::optional<double> sample(const sockaddr_in& dst, int timeout_ms) {
        // Echo request: type 8 / code 0 / checksum / id / seq + 24-byte
        // payload. Linux ping sockets rewrite the id, so replies are matched
        // on SEQUENCE only.
        unsigned char pkt[32] = {8, 0, 0, 0, 0, 0, 0, 0, 'y', 'u', 'z', 'u', '-', 'n', 'e', 't'};
        const std::uint16_t this_seq = ++seq;
        pkt[6] = static_cast<unsigned char>(this_seq >> 8);
        pkt[7] = static_cast<unsigned char>(this_seq & 0xFF);
        const std::uint16_t ck = icmp_checksum(pkt, sizeof(pkt));
        pkt[2] = static_cast<unsigned char>(ck >> 8);
        pkt[3] = static_cast<unsigned char>(ck & 0xFF);

        const auto t0 = std::chrono::steady_clock::now();
        if (::sendto(fd, pkt, sizeof(pkt), 0, reinterpret_cast<const sockaddr*>(&dst),
                     sizeof(dst)) < 0)
            return std::nullopt;

        // Drain until OUR echo reply (other ICMP traffic can share the
        // socket) or the timeout budget is spent.
        for (;;) {
            const int remaining = timeout_ms - static_cast<int>(probe_elapsed_ms(t0));
            if (remaining <= 0)
                return std::nullopt;
            pollfd pfd{fd, POLLIN, 0};
            if (::poll(&pfd, 1, remaining) <= 0)
                return std::nullopt;
            unsigned char buf[512];
            const auto n = ::recv(fd, buf, sizeof(buf), 0);
            if (n <= 0)
                return std::nullopt;
            // macOS delivers IP header + ICMP; Linux ping sockets deliver
            // ICMP only. Skip the IP header when one is present.
            std::size_t off = 0;
            if (n >= 20 && (buf[0] & 0xF0) == 0x40)
                off = static_cast<std::size_t>(buf[0] & 0x0F) * 4;
            if (static_cast<std::size_t>(n) < off + 8)
                continue;
            const bool is_reply = buf[off] == 0; // echo reply
            const std::uint16_t got_seq =
                static_cast<std::uint16_t>(buf[off + 6] << 8 | buf[off + 7]);
            if (is_reply && got_seq == this_seq)
                return probe_elapsed_ms(t0);
            // Someone else's reply / other ICMP — keep draining.
        }
    }
};
#endif

} // namespace yuzu::shared
