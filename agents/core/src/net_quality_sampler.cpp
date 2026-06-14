/// @file net_quality_sampler.cpp
/// See net_quality_sampler.hpp. Linux implementation reads per-connection
/// TCP_INFO via netlink SOCK_DIAG/INET_DIAG (proven to match `ss -ti`) and
/// device throughput from /proc/net/dev; other platforms return all-invalid.

#include "net_quality_sampler.hpp"

// Pure helpers (median / throughput_bps / is_degraded) are header-inline.

// ── Linux implementation ─────────────────────────────────────────────────────
#if defined(__linux__)

#include <linux/inet_diag.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sock_diag.h>
#include <netinet/in.h>
#include <netinet/tcp.h> // struct tcp_info
#include <sys/socket.h>
#include <unistd.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

#ifndef NETLINK_SOCK_DIAG
#define NETLINK_SOCK_DIAG 4
#endif

namespace yuzu::agent::netq {

namespace {

/// RAII owner for the netlink socket fd (cpp-safety: no leak on any return).
struct FdGuard {
    int fd{-1};
    explicit FdGuard(int f) : fd(f) {}
    ~FdGuard() {
        if (fd >= 0)
            ::close(fd);
    }
    FdGuard(const FdGuard&) = delete;
    FdGuard& operator=(const FdGuard&) = delete;
};

bool send_dump(int fd, uint8_t family) {
    struct {
        struct nlmsghdr nlh;
        struct inet_diag_req_v2 req;
    } msg{};
    msg.nlh.nlmsg_len = sizeof(msg);
    msg.nlh.nlmsg_type = SOCK_DIAG_BY_FAMILY;
    msg.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    msg.nlh.nlmsg_seq = family;
    msg.req.sdiag_family = family;
    msg.req.sdiag_protocol = IPPROTO_TCP;
    msg.req.idiag_states = (1u << TCP_ESTABLISHED); // only conns with a live RTT
    msg.req.idiag_ext = (1u << (INET_DIAG_INFO - 1));
    struct sockaddr_nl sa{};
    sa.nl_family = AF_NETLINK;
    struct iovec iov{&msg, sizeof(msg)};
    struct msghdr m{};
    m.msg_name = &sa;
    m.msg_namelen = sizeof(sa);
    m.msg_iov = &iov;
    m.msg_iovlen = 1;
    return ::sendmsg(fd, &m, 0) > 0;
}

// Accumulate per-connection RTT (ms) + retransmit/segment totals from one dump.
void collect(int fd, std::vector<double>& rtts_ms, uint64_t& retrans, uint64_t& segs) {
    char buf[16384];
    for (;;) {
        struct sockaddr_nl sa{};
        struct iovec iov{buf, sizeof(buf)};
        struct msghdr m{};
        m.msg_name = &sa;
        m.msg_namelen = sizeof(sa);
        m.msg_iov = &iov;
        m.msg_iovlen = 1;
        ssize_t n = ::recvmsg(fd, &m, 0);
        if (n <= 0)
            return;
        for (auto* h = reinterpret_cast<struct nlmsghdr*>(buf); NLMSG_OK(h, n);
             h = NLMSG_NEXT(h, n)) {
            if (h->nlmsg_type == NLMSG_DONE || h->nlmsg_type == NLMSG_ERROR)
                return;
            if (h->nlmsg_type != SOCK_DIAG_BY_FAMILY)
                continue;
            auto* diag = reinterpret_cast<struct inet_diag_msg*>(NLMSG_DATA(h));
            int rtalen = static_cast<int>(h->nlmsg_len) -
                         static_cast<int>(NLMSG_LENGTH(sizeof(*diag)));
            auto* attr = reinterpret_cast<struct rtattr*>(diag + 1);
            for (; RTA_OK(attr, rtalen); attr = RTA_NEXT(attr, rtalen)) {
                if (attr->rta_type != INET_DIAG_INFO)
                    continue;
                // Defensive: the kernel's tcp_info may be shorter/longer than
                // our headers'; only read the fields we need if they're present.
                if (RTA_PAYLOAD(attr) < offsetof(struct tcp_info, tcpi_segs_out) +
                                            sizeof(uint32_t))
                    continue;
                const auto* ti = reinterpret_cast<const struct tcp_info*>(RTA_DATA(attr));
                if (ti->tcpi_rtt > 0)
                    rtts_ms.push_back(ti->tcpi_rtt / 1000.0); // tcpi_rtt is microseconds
                retrans += ti->tcpi_total_retrans;
                segs += ti->tcpi_segs_out;
            }
        }
    }
}

} // namespace

NetCounters read_net_counters() {
    NetCounters c;
    std::FILE* f = std::fopen("/proc/net/dev", "re");
    if (!f)
        return c; // invalid
    char line[512];
    // Skip the two header lines.
    if (!std::fgets(line, sizeof(line), f) || !std::fgets(line, sizeof(line), f)) {
        std::fclose(f);
        return c;
    }
    uint64_t rx_total = 0, tx_total = 0;
    while (std::fgets(line, sizeof(line), f)) {
        char* colon = std::strchr(line, ':');
        if (!colon)
            continue;
        // Interface name is before the colon (may be space-padded).
        char* name = line;
        while (*name == ' ')
            ++name;
        *colon = '\0';
        // Skip the loopback — it is not "the network", and dwarfs real traffic.
        if (std::strcmp(name, "lo") == 0)
            continue;
        // rx: bytes packets errs drop fifo frame compressed multicast | tx: bytes ...
        unsigned long long rxb = 0, txb = 0, junk = 0;
        // 8 rx fields then tx bytes is field 9 overall.
        if (std::sscanf(colon + 1, "%llu %llu %llu %llu %llu %llu %llu %llu %llu", &rxb, &junk,
                        &junk, &junk, &junk, &junk, &junk, &junk, &txb) >= 9) {
            rx_total += rxb;
            tx_total += txb;
        }
    }
    std::fclose(f);
    c.valid = true;
    c.rx_bytes = rx_total;
    c.tx_bytes = tx_total;
    c.at = std::chrono::steady_clock::now();
    return c;
}

NetQualitySample sample_net_quality(const NetCounters& prev, const NetCounters& cur) {
    NetQualitySample s;

    // RTT + retransmit via netlink INET_DIAG (no delta needed).
    int raw = ::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_SOCK_DIAG);
    if (raw >= 0) {
        FdGuard guard(raw);
        std::vector<double> rtts;
        uint64_t retrans = 0, segs = 0;
        for (uint8_t fam : {AF_INET, AF_INET6})
            if (send_dump(raw, fam))
                collect(raw, rtts, retrans, segs);
        if (auto p50 = median(std::move(rtts))) {
            s.rtt_valid = true;
            s.rtt_p50_ms = *p50;
        }
        if (segs > 0) {
            s.retrans_valid = true;
            s.retrans_pct = 100.0 * static_cast<double>(retrans) / static_cast<double>(segs);
        }
    }

    // Throughput from the interface-counter delta.
    if (auto bps = throughput_bps(prev, cur)) {
        s.throughput_valid = true;
        s.throughput_bps = *bps;
    }

    s.degraded = is_degraded(s.rtt_valid, s.rtt_p50_ms, s.retrans_valid, s.retrans_pct);
    return s;
}

} // namespace yuzu::agent::netq

#else // ── non-Linux: all-invalid (Windows spike / macOS later) ───────────────

namespace yuzu::agent::netq {

NetCounters read_net_counters() { return {}; }

NetQualitySample sample_net_quality(const NetCounters&, const NetCounters&) { return {}; }

} // namespace yuzu::agent::netq

#endif
