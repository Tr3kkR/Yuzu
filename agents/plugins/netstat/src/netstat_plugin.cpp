/**
 * netstat_plugin.cpp — Network connection enumeration plugin for Yuzu
 *
 * Actions:
 *   "netstat_list" — Enumerates active TCP/UDP connections and listening
 *                    sockets on the host, returning protocol, addresses,
 *                    ports, state, and owning PID.
 *
 * Output is pipe-delimited, one connection per line via write_output():
 *   proto|local_addr|local_port|remote_addr|remote_port|state|pid
 *
 * Platform support:
 *   Linux   — /proc/net/{tcp,tcp6,udp,udp6} + /proc/[pid]/fd inode mapping
 *   macOS   — libproc (proc_listallpids, proc_pidinfo, proc_pidfdinfo)
 *   Windows — IP Helper API (GetExtendedTcpTable, GetExtendedUdpTable)
 */

#include <yuzu/plugin.hpp>

#include <array>
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
#endif

namespace {

// -- Linux implementation -----------------------------------------------------
#ifdef __linux__

constexpr std::string_view tcp_state_str(int st) noexcept {
    switch (st) {
    case 0x01:
        return "ESTABLISHED";
    case 0x02:
        return "SYN_SENT";
    case 0x03:
        return "SYN_RECV";
    case 0x04:
        return "FIN_WAIT1";
    case 0x05:
        return "FIN_WAIT2";
    case 0x06:
        return "TIME_WAIT";
    case 0x07:
        return "CLOSE";
    case 0x08:
        return "CLOSE_WAIT";
    case 0x09:
        return "LAST_ACK";
    case 0x0A:
        return "LISTEN";
    case 0x0B:
        return "CLOSING";
    default:
        return "UNKNOWN";
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
    // Kernel prints four 32-bit words in host byte order, 8 hex chars each
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

// Scan /proc/[pid]/fd/ symlinks to build inode → PID mapping.
std::unordered_map<uint64_t, int> build_inode_to_pid_map() {
    std::unordered_map<uint64_t, int> map;

    DIR* proc_dir = opendir("/proc");
    if (!proc_dir)
        return map;

    struct dirent* proc_entry = nullptr;
    while ((proc_entry = readdir(proc_dir)) != nullptr) {
        int pid = 0;
        [[maybe_unused]] auto [ptr, ec] = std::from_chars(proc_entry->d_name,
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

            // Match "socket:[12345]"
            std::string_view sv(link_buf, static_cast<size_t>(len));
            if (!sv.starts_with("socket:["))
                continue;
            auto inode_sv = sv.substr(8, sv.size() - 9); // strip "socket:[" and "]"
            uint64_t inode = 0;
            std::from_chars(inode_sv.data(), inode_sv.data() + inode_sv.size(), inode);
            if (inode > 0)
                map.emplace(inode, pid);
        }
        closedir(fd_dir);
    }
    closedir(proc_dir);
    return map;
}

void parse_proc_net_file(const char* path, std::string_view proto,
                         const std::unordered_map<uint64_t, int>& inode_map,
                         yuzu::CommandContext& ctx, bool is_tcp, bool is_ipv6) {
    std::ifstream f(path);
    if (!f)
        return;

    std::string line;
    std::getline(f, line); // skip header

    while (std::getline(f, line)) {
        std::istringstream iss(line);
        std::string sl, local, remote, state_hex;
        // Columns: sl local_address rem_address st ...
        if (!(iss >> sl >> local >> remote >> state_hex))
            continue;

        // Parse local address:port
        auto colon = local.rfind(':');
        if (colon == std::string::npos)
            continue;
        std::string local_addr = is_ipv6 ? parse_ipv6(std::string_view(local).substr(0, colon))
                                         : parse_ipv4(std::string_view(local).substr(0, colon));
        uint16_t local_port = parse_hex_port(std::string_view(local).substr(colon + 1));

        // Parse remote address:port
        auto rcolon = remote.rfind(':');
        if (rcolon == std::string::npos)
            continue;
        std::string remote_addr = is_ipv6 ? parse_ipv6(std::string_view(remote).substr(0, rcolon))
                                          : parse_ipv4(std::string_view(remote).substr(0, rcolon));
        uint16_t remote_port = parse_hex_port(std::string_view(remote).substr(rcolon + 1));

        // Parse state
        int state_val = 0;
        std::from_chars(state_hex.data(), state_hex.data() + state_hex.size(), state_val, 16);
        std::string_view state = is_tcp ? tcp_state_str(state_val) : std::string_view{};

        // Skip remaining columns to get to inode (column index 9, 0-based)
        std::string tok;
        // Already consumed 4 tokens (sl, local, remote, state).
        // Need to skip 5 more: tx_queue:rx_queue, tr:tm->when, retrnsmt, uid, timeout
        for (int i = 0; i < 5 && (iss >> tok); ++i) {}
        uint64_t inode = 0;
        if (iss >> inode) { /* got inode */
        }

        int pid = -1;
        if (inode > 0) {
            auto it = inode_map.find(inode);
            if (it != inode_map.end())
                pid = it->second;
        }

        ctx.write_output(std::format("{}|{}|{}|{}|{}|{}|{}", proto, local_addr, local_port,
                                     remote_addr, remote_port, state, pid));
    }
}

void enumerate_and_stream(yuzu::CommandContext& ctx) {
    auto inode_map = build_inode_to_pid_map();

    parse_proc_net_file("/proc/net/tcp", "tcp", inode_map, ctx, true, false);
    parse_proc_net_file("/proc/net/tcp6", "tcp6", inode_map, ctx, true, true);
    parse_proc_net_file("/proc/net/udp", "udp", inode_map, ctx, false, false);
    parse_proc_net_file("/proc/net/udp6", "udp6", inode_map, ctx, false, true);
}

// -- macOS implementation -----------------------------------------------------
#elif defined(__APPLE__)

constexpr std::string_view tcp_state_str_mac(int st) noexcept {
    // TSI_S_* constants from <netinet/tcp_fsm.h> (included via sys/proc_info.h)
    switch (st) {
    case 0:
        return "CLOSED";
    case 1:
        return "LISTEN";
    case 2:
        return "SYN_SENT";
    case 3:
        return "SYN_RECV";
    case 4:
        return "ESTABLISHED";
    case 5:
        return "CLOSE_WAIT";
    case 6:
        return "FIN_WAIT1";
    case 7:
        return "CLOSING";
    case 8:
        return "LAST_ACK";
    case 9:
        return "FIN_WAIT2";
    case 10:
        return "TIME_WAIT";
    default:
        return "UNKNOWN";
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

void enumerate_and_stream(yuzu::CommandContext& ctx) {
    // Get list of all PIDs
    int pid_count = proc_listallpids(nullptr, 0);
    if (pid_count <= 0)
        return;

    std::vector<pid_t> pids(static_cast<size_t>(pid_count) * 2); // over-allocate
    pid_count = proc_listallpids(pids.data(), static_cast<int>(pids.size() * sizeof(pid_t)));
    if (pid_count <= 0)
        return;
    pids.resize(static_cast<size_t>(pid_count));

    // Track seen connections to avoid duplicates (key: proto+local+remote)
    std::unordered_map<std::string, bool> seen;

    for (pid_t pid : pids) {
        // Get file descriptor list for this process
        int buf_size = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nullptr, 0);
        if (buf_size <= 0)
            continue;

        auto fd_count = static_cast<size_t>(buf_size) / sizeof(struct proc_fdinfo);
        std::vector<struct proc_fdinfo> fds(fd_count);
        int actual = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds.data(),
                                  static_cast<int>(fds.size() * sizeof(struct proc_fdinfo)));
        if (actual <= 0)
            continue;
        fd_count = static_cast<size_t>(actual) / sizeof(struct proc_fdinfo);

        for (size_t i = 0; i < fd_count; ++i) {
            if (fds[i].proc_fdtype != PROX_FDTYPE_SOCKET)
                continue;

            struct socket_fdinfo si{};
            int si_size =
                proc_pidfdinfo(pid, fds[i].proc_fd, PROC_PIDFDSOCKETINFO, &si, sizeof(si));
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

            std::string proto;
            std::string local_addr, remote_addr;
            uint16_t local_port = 0, remote_port = 0;
            std::string_view state;

            if (is_tcp) {
                auto& tcp = si.psi.soi_proto.pri_tcp;
                state = tcp_state_str_mac(tcp.tcpsi_state);

                if (family == AF_INET) {
                    proto = "tcp";
                    local_addr = format_addr4(tcp.tcpsi_ini.insi_laddr.ina_46.i46a_addr4);
                    remote_addr = format_addr4(tcp.tcpsi_ini.insi_faddr.ina_46.i46a_addr4);
                } else {
                    proto = "tcp6";
                    local_addr = format_addr6(tcp.tcpsi_ini.insi_laddr.ina_6);
                    remote_addr = format_addr6(tcp.tcpsi_ini.insi_faddr.ina_6);
                }
                local_port = ntohs(static_cast<uint16_t>(tcp.tcpsi_ini.insi_lport));
                remote_port = ntohs(static_cast<uint16_t>(tcp.tcpsi_ini.insi_fport));
            } else {
                auto& inp = si.psi.soi_proto.pri_in;

                if (family == AF_INET) {
                    proto = "udp";
                    local_addr = format_addr4(inp.insi_laddr.ina_46.i46a_addr4);
                    remote_addr = "*";
                } else {
                    proto = "udp6";
                    local_addr = format_addr6(inp.insi_laddr.ina_6);
                    remote_addr = "*";
                }
                local_port = ntohs(static_cast<uint16_t>(inp.insi_lport));
                remote_port = 0;
            }

            // Deduplicate — same socket may appear in multiple PIDs (fork)
            auto key = std::format("{}:{}:{}:{}:{}", proto, local_addr, local_port, remote_addr,
                                   remote_port);
            if (seen.contains(key))
                continue;
            seen.emplace(std::move(key), true);

            ctx.write_output(std::format("{}|{}|{}|{}|{}|{}|{}", proto, local_addr, local_port,
                                         remote_addr, remote_port, state, static_cast<int>(pid)));
        }
    }
}

// -- Windows implementation ---------------------------------------------------
#elif defined(_WIN32)

constexpr std::string_view tcp_state_str_win(DWORD st) noexcept {
    switch (st) {
    case 1:
        return "CLOSED";
    case 2:
        return "LISTEN";
    case 3:
        return "SYN_SENT";
    case 4:
        return "SYN_RECV";
    case 5:
        return "ESTABLISHED";
    case 6:
        return "FIN_WAIT1";
    case 7:
        return "FIN_WAIT2";
    case 8:
        return "CLOSE_WAIT";
    case 9:
        return "CLOSING";
    case 10:
        return "LAST_ACK";
    case 11:
        return "TIME_WAIT";
    case 12:
        return "DELETE_TCB";
    default:
        return "UNKNOWN";
    }
}

std::string format_addr4(DWORD addr) {
    struct in_addr in{};
    in.s_addr = addr; // already in network byte order
    char buf[INET_ADDRSTRLEN]{};
    inet_ntop(AF_INET, &in, buf, sizeof(buf));
    return buf;
}

std::string format_addr6(const void* addr) {
    char buf[INET6_ADDRSTRLEN]{};
    inet_ntop(AF_INET6, addr, buf, sizeof(buf));
    return buf;
}

void emit_tcp4(yuzu::CommandContext& ctx) {
    DWORD size = 0;
    GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (size == 0)
        return;

    std::vector<BYTE> buf(size);
    for (int attempt = 0; attempt < 3; ++attempt) {
        DWORD ret =
            GetExtendedTcpTable(buf.data(), &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
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
        ctx.write_output(std::format(
            "tcp|{}|{}|{}|{}|{}|{}", format_addr4(row.dwLocalAddr),
            ntohs(static_cast<u_short>(row.dwLocalPort)), format_addr4(row.dwRemoteAddr),
            ntohs(static_cast<u_short>(row.dwRemotePort)), tcp_state_str_win(row.dwState),
            static_cast<int>(row.dwOwningPid)));
    }
}

void emit_tcp6(yuzu::CommandContext& ctx) {
    DWORD size = 0;
    GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
    if (size == 0)
        return;

    std::vector<BYTE> buf(size);
    for (int attempt = 0; attempt < 3; ++attempt) {
        DWORD ret =
            GetExtendedTcpTable(buf.data(), &size, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
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
        ctx.write_output(std::format(
            "tcp6|{}|{}|{}|{}|{}|{}", format_addr6(row.ucLocalAddr),
            ntohs(static_cast<u_short>(row.dwLocalPort)), format_addr6(row.ucRemoteAddr),
            ntohs(static_cast<u_short>(row.dwRemotePort)), tcp_state_str_win(row.dwState),
            static_cast<int>(row.dwOwningPid)));
    }
}

void emit_udp4(yuzu::CommandContext& ctx) {
    DWORD size = 0;
    GetExtendedUdpTable(nullptr, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    if (size == 0)
        return;

    std::vector<BYTE> buf(size);
    for (int attempt = 0; attempt < 3; ++attempt) {
        DWORD ret = GetExtendedUdpTable(buf.data(), &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
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
        ctx.write_output(std::format("udp|{}|{}|*|0||{}", format_addr4(row.dwLocalAddr),
                                     ntohs(static_cast<u_short>(row.dwLocalPort)),
                                     static_cast<int>(row.dwOwningPid)));
    }
}

void emit_udp6(yuzu::CommandContext& ctx) {
    DWORD size = 0;
    GetExtendedUdpTable(nullptr, &size, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0);
    if (size == 0)
        return;

    std::vector<BYTE> buf(size);
    for (int attempt = 0; attempt < 3; ++attempt) {
        DWORD ret = GetExtendedUdpTable(buf.data(), &size, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0);
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
        ctx.write_output(std::format("udp6|{}|{}|*|0||{}", format_addr6(row.ucLocalAddr),
                                     ntohs(static_cast<u_short>(row.dwLocalPort)),
                                     static_cast<int>(row.dwOwningPid)));
    }
}

void enumerate_and_stream(yuzu::CommandContext& ctx) {
    emit_tcp4(ctx);
    emit_tcp6(ctx);
    emit_udp4(ctx);
    emit_udp6(ctx);
}

#endif // platform

} // namespace

class NetstatPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "netstat"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Enumerates active network connections and listening sockets";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"netstat_list", nullptr};
        return acts;
    }

    yuzu::Result<void> init(yuzu::PluginContext& /*ctx*/) override { return {}; }
    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {}

    int execute(yuzu::CommandContext& ctx, std::string_view action,
                yuzu::Params /*params*/) override {
        if (action == "netstat_list") {
            return do_list(ctx);
        }
        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }

private:
    int do_list(yuzu::CommandContext& ctx) {
#if defined(__linux__) || defined(__APPLE__) || defined(_WIN32)
        enumerate_and_stream(ctx);
        return 0;
#else
        ctx.write_output("error: network enumeration not supported on this platform");
        return 1;
#endif
    }
};

YUZU_PLUGIN_EXPORT(NetstatPlugin)
