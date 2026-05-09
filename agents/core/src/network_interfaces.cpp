/**
 * network_interfaces.cpp -- Cross-platform local-IP enumeration
 *
 * Linux/macOS: getifaddrs(3)
 * Windows:     GetAdaptersAddresses (iphlpapi)
 */

#include <yuzu/agent/network_interfaces.hpp>

#include <set>
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
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#elif defined(__linux__) || defined(__APPLE__)
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace yuzu::agent {

namespace {

#if defined(_WIN32) || defined(__linux__) || defined(__APPLE__)

bool is_ipv4_loopback(const in_addr& addr) {
    // 127.0.0.0/8
    return (ntohl(addr.s_addr) & 0xff000000u) == 0x7f000000u;
}

bool is_ipv4_link_local(const in_addr& addr) {
    // 169.254.0.0/16
    return (ntohl(addr.s_addr) & 0xffff0000u) == 0xa9fe0000u;
}

bool is_ipv6_loopback(const in6_addr& addr) {
    return IN6_IS_ADDR_LOOPBACK(&addr) != 0;
}

bool is_ipv6_link_local(const in6_addr& addr) {
    return IN6_IS_ADDR_LINKLOCAL(&addr) != 0;
}

#endif

} // namespace

#ifdef _WIN32

std::vector<std::string> enumerate_local_ips() {
    constexpr ULONG kFlags =
        GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_ANYCAST;

    ULONG bufsize = 16 * 1024;
    std::vector<unsigned char> buf(bufsize);
    ULONG rc = GetAdaptersAddresses(AF_UNSPEC, kFlags, nullptr,
                                    reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data()), &bufsize);
    if (rc == ERROR_BUFFER_OVERFLOW) {
        buf.resize(bufsize);
        rc = GetAdaptersAddresses(AF_UNSPEC, kFlags, nullptr,
                                  reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data()), &bufsize);
    }
    if (rc != ERROR_SUCCESS)
        return {};

    std::set<std::string> uniq;
    char text_buf[INET6_ADDRSTRLEN];

    for (auto* adapter = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data()); adapter != nullptr;
         adapter = adapter->Next) {
        if (adapter->OperStatus != IfOperStatusUp)
            continue;
        if (adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK)
            continue;

        for (auto* unicast = adapter->FirstUnicastAddress; unicast != nullptr;
             unicast = unicast->Next) {
            const auto* sa = unicast->Address.lpSockaddr;
            if (!sa)
                continue;
            if (sa->sa_family == AF_INET) {
                const auto* sin = reinterpret_cast<const sockaddr_in*>(sa);
                if (is_ipv4_loopback(sin->sin_addr) || is_ipv4_link_local(sin->sin_addr))
                    continue;
                if (inet_ntop(AF_INET, &sin->sin_addr, text_buf, sizeof(text_buf)))
                    uniq.emplace(text_buf);
            } else if (sa->sa_family == AF_INET6) {
                const auto* sin6 = reinterpret_cast<const sockaddr_in6*>(sa);
                if (is_ipv6_loopback(sin6->sin6_addr) || is_ipv6_link_local(sin6->sin6_addr))
                    continue;
                if (inet_ntop(AF_INET6, &sin6->sin6_addr, text_buf, sizeof(text_buf)))
                    uniq.emplace(text_buf);
            }
        }
    }
    return std::vector<std::string>(uniq.begin(), uniq.end());
}

#elif defined(__linux__) || defined(__APPLE__)

std::vector<std::string> enumerate_local_ips() {
    ifaddrs* head = nullptr;
    if (getifaddrs(&head) != 0)
        return {};

    std::set<std::string> uniq;
    char text_buf[INET6_ADDRSTRLEN];

    for (ifaddrs* p = head; p != nullptr; p = p->ifa_next) {
        if (!p->ifa_addr)
            continue;
        if (p->ifa_addr->sa_family == AF_INET) {
            const auto* sin = reinterpret_cast<const sockaddr_in*>(p->ifa_addr);
            if (is_ipv4_loopback(sin->sin_addr) || is_ipv4_link_local(sin->sin_addr))
                continue;
            if (inet_ntop(AF_INET, &sin->sin_addr, text_buf, sizeof(text_buf)))
                uniq.emplace(text_buf);
        } else if (p->ifa_addr->sa_family == AF_INET6) {
            const auto* sin6 = reinterpret_cast<const sockaddr_in6*>(p->ifa_addr);
            if (is_ipv6_loopback(sin6->sin6_addr) || is_ipv6_link_local(sin6->sin6_addr))
                continue;
            if (inet_ntop(AF_INET6, &sin6->sin6_addr, text_buf, sizeof(text_buf)))
                uniq.emplace(text_buf);
        }
    }

    freeifaddrs(head);
    return std::vector<std::string>(uniq.begin(), uniq.end());
}

#else

std::vector<std::string> enumerate_local_ips() {
    return {};
}

#endif

#if defined(_WIN32) || defined(__linux__) || defined(__APPLE__)

std::string get_hostname() {
    char buf[256] = {};
    if (::gethostname(buf, sizeof(buf) - 1) != 0)
        return {};
    return std::string(buf);
}

#else

std::string get_hostname() {
    return {};
}

#endif

} // namespace yuzu::agent
