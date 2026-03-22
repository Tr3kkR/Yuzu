/**
 * tar_network_collector.cpp -- Network connection enumeration for TAR plugin
 *
 * Enumerates active TCP/UDP connections and returns them as structured
 * NetConnection records for diff-based change detection.
 *
 * Platform support:
 *   Windows -- GetExtendedTcpTable + GetExtendedUdpTable (IP Helper API)
 *   Linux   -- /proc/net/{tcp,tcp6,udp,udp6} + /proc/[pid]/fd inode mapping
 *   macOS   -- proc_listallpids + proc_pidfdinfo (libproc)
 */

#include "tar_collectors.hpp"

#include <spdlog/spdlog.h>

#include <charconv>
#include <cstdint>
#include <format>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#ifdef __linux__
#include <arpa/inet.h>
#include <cstring>
#include <dirent.h>
#include <fstream>
#include <sstream>
#include <unistd.h>
#elif defined(__APPLE__)
#include <arpa/inet.h>
#include <libproc.h>
#include <sys/proc_info.h>
#elif defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#endif

namespace yuzu::tar {

// -- Linux implementation -----------------------------------------------------
#ifdef __linux__

namespace {

constexpr std::string_view tcp_state_str(int st) noexcept {
    switch (st) {
    case 0x01: return "ESTABLISHED";
    case 0x02: return "SYN_SENT";
    case 0x03: return "SYN_RECV";
    case 0x04: return "FIN_WAIT1";
    case 0x05: return "FIN_WAIT2";
    case 0x06: return "TIME_WAIT";
    case 0x07: return "CLOSE";
    case 0x08: return "CLOSE_WAIT";
    case 0x09: return "LAST_ACK";
    case 0x0A: return "LISTEN";
    case 0x0B: return "CLOSING";
    default:   return "UNKNOWN";
    }
}

std::string parse_ipv4(std::string_view hex_addr) {
    uint32_t addr = 0;
    std::from_chars(hex_addr.data(), hex_addr.data() + hex_addr.size(), addr, 16);
    struct in_addr in{};
    std::memcpy(&in, &addr, sizeof(addr));
    char buf[INET_ADDRSTRLEN]{};
    inet_ntop(AF_INET, &in, buf, sizeof(buf));
    return buf;
}

std::string parse_ipv6(std::string_view hex_addr) {
    struct in6_addr in6{};
    for (int i = 0; i < 4; ++i) {
        auto chunk = hex_addr.substr(static_cast<size_t>(i) * 8, 8);
        uint32_t word = 0;
        std::from_chars(chunk.data(), chunk.data() + chunk.size(), word, 16);
        std::memcpy(&in6.s6_addr[i * 4], &word, sizeof(word));
    }
    char buf[INET6_ADDRSTRLEN]{};
    inet_ntop(AF_INET6, &in6, buf, sizeof(buf));
    return buf;
}

uint16_t parse_hex_port(std::string_view hex) {
    unsigned int port = 0;
    std::from_chars(hex.data(), hex.data() + hex.size(), port, 16);
    return static_cast<uint16_t>(port);
}

std::unordered_map<uint64_t, uint32_t> build_inode_to_pid_map() {
    std::unordered_map<uint64_t, uint32_t> map;

    DIR* proc_dir = opendir("/proc");
    if (!proc_dir)
        return map;

    struct dirent* proc_entry = nullptr;
    while ((proc_entry = readdir(proc_dir)) != nullptr) {
        int pid = 0;
        auto [ptr, ec] = std::from_chars(
            proc_entry->d_name,
            proc_entry->d_name + std::strlen(proc_entry->d_name), pid);
        if (ec != std::errc{} || pid <= 0)
            continue;

        std::string fd_path = std::format("/proc/{}/fd", pid);
        DIR* fd_dir = opendir(fd_path.c_str());
        if (!fd_dir)
            continue;

        char link_buf[128];
        struct dirent* fd_entry = nullptr;
        while ((fd_entry = readdir(fd_dir)) != nullptr) {
            if (fd_entry->d_name[0] == '.')
                continue;

            std::string link_path = std::format("{}/{}", fd_path, fd_entry->d_name);
            ssize_t len = readlink(link_path.c_str(), link_buf, sizeof(link_buf) - 1);
            if (len <= 0)
                continue;
            link_buf[len] = '\0';

            std::string_view sv(link_buf, static_cast<size_t>(len));
            if (!sv.starts_with("socket:["))
                continue;
            auto inode_sv = sv.substr(8, sv.size() - 9);
            uint64_t inode = 0;
            std::from_chars(inode_sv.data(), inode_sv.data() + inode_sv.size(), inode);
            if (inode > 0)
                map.emplace(inode, static_cast<uint32_t>(pid));
        }
        closedir(fd_dir);
    }
    closedir(proc_dir);
    return map;
}

void parse_proc_net_file(const char* path, std::string_view proto,
                         const std::unordered_map<uint64_t, uint32_t>& inode_map,
                         std::vector<NetConnection>& out, bool is_tcp, bool is_ipv6) {
    std::ifstream f(path);
    if (!f)
        return;

    std::string line;
    std::getline(f, line); // skip header

    while (std::getline(f, line)) {
        std::istringstream iss(line);
        std::string sl, local, remote, state_hex;
        if (!(iss >> sl >> local >> remote >> state_hex))
            continue;

        auto colon = local.rfind(':');
        if (colon == std::string::npos)
            continue;
        std::string local_addr = is_ipv6
            ? parse_ipv6(std::string_view(local).substr(0, colon))
            : parse_ipv4(std::string_view(local).substr(0, colon));
        uint16_t local_port = parse_hex_port(std::string_view(local).substr(colon + 1));

        auto rcolon = remote.rfind(':');
        if (rcolon == std::string::npos)
            continue;
        std::string remote_addr = is_ipv6
            ? parse_ipv6(std::string_view(remote).substr(0, rcolon))
            : parse_ipv4(std::string_view(remote).substr(0, rcolon));
        uint16_t remote_port = parse_hex_port(std::string_view(remote).substr(rcolon + 1));

        int state_val = 0;
        std::from_chars(state_hex.data(), state_hex.data() + state_hex.size(), state_val, 16);
        std::string state = is_tcp ? std::string{tcp_state_str(state_val)} : std::string{};

        // Skip remaining columns to get to inode (column index 9)
        std::string tok;
        for (int i = 0; i < 5 && (iss >> tok); ++i) {}
        uint64_t inode = 0;
        iss >> inode;

        uint32_t pid = 0;
        if (inode > 0) {
            auto it = inode_map.find(inode);
            if (it != inode_map.end())
                pid = it->second;
        }

        NetConnection nc;
        nc.proto = proto;
        nc.local_addr = std::move(local_addr);
        nc.local_port = local_port;
        nc.remote_addr = std::move(remote_addr);
        nc.remote_port = remote_port;
        nc.state = std::move(state);
        nc.pid = pid;
        out.push_back(std::move(nc));
    }
}

} // namespace

std::vector<NetConnection> enumerate_connections() {
    std::vector<NetConnection> result;
    auto inode_map = build_inode_to_pid_map();

    parse_proc_net_file("/proc/net/tcp",  "tcp",  inode_map, result, true,  false);
    parse_proc_net_file("/proc/net/tcp6", "tcp6", inode_map, result, true,  true);
    parse_proc_net_file("/proc/net/udp",  "udp",  inode_map, result, false, false);
    parse_proc_net_file("/proc/net/udp6", "udp6", inode_map, result, false, true);
    return result;
}

// -- macOS implementation -----------------------------------------------------
#elif defined(__APPLE__)

namespace {

constexpr std::string_view tcp_state_str_mac(int st) noexcept {
    switch (st) {
    case 0:  return "CLOSED";
    case 1:  return "LISTEN";
    case 2:  return "SYN_SENT";
    case 3:  return "SYN_RECV";
    case 4:  return "ESTABLISHED";
    case 5:  return "CLOSE_WAIT";
    case 6:  return "FIN_WAIT1";
    case 7:  return "CLOSING";
    case 8:  return "LAST_ACK";
    case 9:  return "FIN_WAIT2";
    case 10: return "TIME_WAIT";
    default: return "UNKNOWN";
    }
}

std::string format_addr4(const struct in_addr& addr) {
    char buf[INET_ADDRSTRLEN]{};
    inet_ntop(AF_INET, &addr, buf, sizeof(buf));
    return buf;
}

std::string format_addr6(const struct in6_addr& addr) {
    char buf[INET6_ADDRSTRLEN]{};
    inet_ntop(AF_INET6, &addr, buf, sizeof(buf));
    return buf;
}

} // namespace

std::vector<NetConnection> enumerate_connections() {
    std::vector<NetConnection> result;
    std::unordered_map<std::string, bool> seen;

    int pid_count = proc_listallpids(nullptr, 0);
    if (pid_count <= 0)
        return result;

    std::vector<pid_t> pids(static_cast<size_t>(pid_count) * 2);
    pid_count = proc_listallpids(pids.data(), static_cast<int>(pids.size() * sizeof(pid_t)));
    if (pid_count <= 0)
        return result;
    pids.resize(static_cast<size_t>(pid_count));

    // NOTE: TOCTOU race is inherent to the proc_listallpids + proc_pidinfo
    // approach on macOS. A process can exit between the listing and the FD
    // enumeration. The `continue` on error is the correct mitigation -- we
    // simply skip PIDs that have disappeared and log at debug level.
    for (pid_t pid : pids) {
        int buf_size = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nullptr, 0);
        if (buf_size <= 0) {
            spdlog::debug("TAR: PID {} disappeared before FD enumeration (TOCTOU)", pid);
            continue;
        }

        auto fd_count = static_cast<size_t>(buf_size) / sizeof(struct proc_fdinfo);
        std::vector<struct proc_fdinfo> fds(fd_count);
        int actual = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds.data(),
                                  static_cast<int>(fds.size() * sizeof(struct proc_fdinfo)));
        if (actual <= 0) {
            spdlog::debug("TAR: PID {} disappeared during FD read (TOCTOU)", pid);
            continue;
        }
        fd_count = static_cast<size_t>(actual) / sizeof(struct proc_fdinfo);

        for (size_t i = 0; i < fd_count; ++i) {
            if (fds[i].proc_fdtype != PROX_FDTYPE_SOCKET)
                continue;

            struct socket_fdinfo si{};
            int si_size = proc_pidfdinfo(pid, fds[i].proc_fd,
                                         PROC_PIDFDSOCKETINFO, &si, sizeof(si));
            if (si_size < static_cast<int>(sizeof(si)))
                continue;

            int family = si.psi.soi_family;
            if (family != AF_INET && family != AF_INET6)
                continue;

            int kind = si.psi.soi_kind;
            bool is_tcp = (kind == SOCKINFO_TCP);
            bool is_udp = (kind == SOCKINFO_IN);
            if (!is_tcp && !is_udp)
                continue;

            NetConnection nc;
            nc.pid = static_cast<uint32_t>(pid);

            if (is_tcp) {
                auto& tcp = si.psi.soi_proto.pri_tcp;
                nc.state = tcp_state_str_mac(tcp.tcpsi_state);

                if (family == AF_INET) {
                    nc.proto = "tcp";
                    nc.local_addr = format_addr4(tcp.tcpsi_ini.insi_laddr.ina_46.i46a_addr4);
                    nc.remote_addr = format_addr4(tcp.tcpsi_ini.insi_faddr.ina_46.i46a_addr4);
                } else {
                    nc.proto = "tcp6";
                    nc.local_addr = format_addr6(tcp.tcpsi_ini.insi_laddr.ina_6);
                    nc.remote_addr = format_addr6(tcp.tcpsi_ini.insi_faddr.ina_6);
                }
                nc.local_port = ntohs(static_cast<uint16_t>(tcp.tcpsi_ini.insi_lport));
                nc.remote_port = ntohs(static_cast<uint16_t>(tcp.tcpsi_ini.insi_fport));
            } else {
                auto& inp = si.psi.soi_proto.pri_in;

                if (family == AF_INET) {
                    nc.proto = "udp";
                    nc.local_addr = format_addr4(inp.insi_laddr.ina_46.i46a_addr4);
                    nc.remote_addr = "*";
                } else {
                    nc.proto = "udp6";
                    nc.local_addr = format_addr6(inp.insi_laddr.ina_6);
                    nc.remote_addr = "*";
                }
                nc.local_port = ntohs(static_cast<uint16_t>(inp.insi_lport));
                nc.remote_port = 0;
            }

            // Deduplicate -- same socket may appear in multiple PIDs (fork)
            auto key = std::format("{}:{}:{}:{}:{}", nc.proto, nc.local_addr,
                                   nc.local_port, nc.remote_addr, nc.remote_port);
            if (seen.contains(key))
                continue;
            seen.emplace(std::move(key), true);

            result.push_back(std::move(nc));
        }
    }
    return result;
}

// -- Windows implementation ---------------------------------------------------
#elif defined(_WIN32)

namespace {

constexpr std::string_view tcp_state_str_win(DWORD st) noexcept {
    switch (st) {
    case 1:  return "CLOSED";
    case 2:  return "LISTEN";
    case 3:  return "SYN_SENT";
    case 4:  return "SYN_RECV";
    case 5:  return "ESTABLISHED";
    case 6:  return "FIN_WAIT1";
    case 7:  return "FIN_WAIT2";
    case 8:  return "CLOSE_WAIT";
    case 9:  return "CLOSING";
    case 10: return "LAST_ACK";
    case 11: return "TIME_WAIT";
    case 12: return "DELETE_TCB";
    default: return "UNKNOWN";
    }
}

std::string format_win_addr4(DWORD addr) {
    struct in_addr in{};
    in.s_addr = addr;
    char buf[INET_ADDRSTRLEN]{};
    inet_ntop(AF_INET, &in, buf, sizeof(buf));
    return buf;
}

std::string format_win_addr6(const void* addr) {
    char buf[INET6_ADDRSTRLEN]{};
    inet_ntop(AF_INET6, addr, buf, sizeof(buf));
    return buf;
}

void collect_tcp4(std::vector<NetConnection>& out) {
    DWORD size = 0;
    GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (size == 0)
        return;

    std::vector<BYTE> buf(size);
    for (int attempt = 0; attempt < 3; ++attempt) {
        DWORD ret = GetExtendedTcpTable(buf.data(), &size, FALSE,
                                         AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        if (ret == NO_ERROR)
            break;
        if (ret == ERROR_INSUFFICIENT_BUFFER) {
            buf.resize(size);
            continue;
        }
        return;
    }

    auto* table = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(buf.data());
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        auto& row = table->table[i];
        NetConnection nc;
        nc.proto = "tcp";
        nc.local_addr = format_win_addr4(row.dwLocalAddr);
        nc.local_port = ntohs(static_cast<u_short>(row.dwLocalPort));
        nc.remote_addr = format_win_addr4(row.dwRemoteAddr);
        nc.remote_port = ntohs(static_cast<u_short>(row.dwRemotePort));
        nc.state = tcp_state_str_win(row.dwState);
        nc.pid = static_cast<uint32_t>(row.dwOwningPid);
        out.push_back(std::move(nc));
    }
}

void collect_tcp6(std::vector<NetConnection>& out) {
    DWORD size = 0;
    GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
    if (size == 0)
        return;

    std::vector<BYTE> buf(size);
    for (int attempt = 0; attempt < 3; ++attempt) {
        DWORD ret = GetExtendedTcpTable(buf.data(), &size, FALSE,
                                         AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
        if (ret == NO_ERROR)
            break;
        if (ret == ERROR_INSUFFICIENT_BUFFER) {
            buf.resize(size);
            continue;
        }
        return;
    }

    auto* table = reinterpret_cast<MIB_TCP6TABLE_OWNER_PID*>(buf.data());
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        auto& row = table->table[i];
        NetConnection nc;
        nc.proto = "tcp6";
        nc.local_addr = format_win_addr6(row.ucLocalAddr);
        nc.local_port = ntohs(static_cast<u_short>(row.dwLocalPort));
        nc.remote_addr = format_win_addr6(row.ucRemoteAddr);
        nc.remote_port = ntohs(static_cast<u_short>(row.dwRemotePort));
        nc.state = tcp_state_str_win(row.dwState);
        nc.pid = static_cast<uint32_t>(row.dwOwningPid);
        out.push_back(std::move(nc));
    }
}

void collect_udp4(std::vector<NetConnection>& out) {
    DWORD size = 0;
    GetExtendedUdpTable(nullptr, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    if (size == 0)
        return;

    std::vector<BYTE> buf(size);
    for (int attempt = 0; attempt < 3; ++attempt) {
        DWORD ret = GetExtendedUdpTable(buf.data(), &size, FALSE,
                                         AF_INET, UDP_TABLE_OWNER_PID, 0);
        if (ret == NO_ERROR)
            break;
        if (ret == ERROR_INSUFFICIENT_BUFFER) {
            buf.resize(size);
            continue;
        }
        return;
    }

    auto* table = reinterpret_cast<MIB_UDPTABLE_OWNER_PID*>(buf.data());
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        auto& row = table->table[i];
        NetConnection nc;
        nc.proto = "udp";
        nc.local_addr = format_win_addr4(row.dwLocalAddr);
        nc.local_port = ntohs(static_cast<u_short>(row.dwLocalPort));
        nc.remote_addr = "*";
        nc.remote_port = 0;
        nc.pid = static_cast<uint32_t>(row.dwOwningPid);
        out.push_back(std::move(nc));
    }
}

void collect_udp6(std::vector<NetConnection>& out) {
    DWORD size = 0;
    GetExtendedUdpTable(nullptr, &size, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0);
    if (size == 0)
        return;

    std::vector<BYTE> buf(size);
    for (int attempt = 0; attempt < 3; ++attempt) {
        DWORD ret = GetExtendedUdpTable(buf.data(), &size, FALSE,
                                         AF_INET6, UDP_TABLE_OWNER_PID, 0);
        if (ret == NO_ERROR)
            break;
        if (ret == ERROR_INSUFFICIENT_BUFFER) {
            buf.resize(size);
            continue;
        }
        return;
    }

    auto* table = reinterpret_cast<MIB_UDP6TABLE_OWNER_PID*>(buf.data());
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        auto& row = table->table[i];
        NetConnection nc;
        nc.proto = "udp6";
        nc.local_addr = format_win_addr6(row.ucLocalAddr);
        nc.local_port = ntohs(static_cast<u_short>(row.dwLocalPort));
        nc.remote_addr = "*";
        nc.remote_port = 0;
        nc.pid = static_cast<uint32_t>(row.dwOwningPid);
        out.push_back(std::move(nc));
    }
}

} // namespace

std::vector<NetConnection> enumerate_connections() {
    std::vector<NetConnection> result;
    collect_tcp4(result);
    collect_tcp6(result);
    collect_udp4(result);
    collect_udp6(result);
    return result;
}

#else
// Unsupported platform
std::vector<NetConnection> enumerate_connections() {
    return {};
}
#endif

} // namespace yuzu::tar
