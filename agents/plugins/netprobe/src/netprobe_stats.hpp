#pragma once

/**
 * netprobe_stats.hpp — pure helpers for the netprobe plugin (BRD E1,
 * docs/dex-brd-coverage.md): sample statistics (min/avg/max/jitter/loss),
 * parameter clamping, and probe-target validation.
 *
 * Header-only and OS-free so the fiddly parts (stddev arithmetic, the
 * target charset gate, CSV splitting) are unit-tested on every host
 * (test_netprobe_stats.cpp — the cve_rules.hpp pattern); the socket work in
 * netprobe_plugin.cpp is the impure shell.
 */

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstddef>
#include <string>
#include <vector>

namespace yuzu::netprobe {

/// One probe run's aggregate. Jitter is the POPULATION standard deviation of
/// the successful samples (the BRD's "variation in latency over time"), 0
/// when fewer than two samples succeeded.
struct ProbeStats {
    int sent{0};
    int ok{0};
    double min_ms{0.0};
    double avg_ms{0.0};
    double max_ms{0.0};
    double jitter_ms{0.0};
    double loss_pct{100.0};
};

inline ProbeStats compute_stats(int sent, const std::vector<double>& ok_ms) {
    ProbeStats s;
    s.sent = sent;
    s.ok = static_cast<int>(ok_ms.size());
    if (sent <= 0) {
        s.sent = 0;
        s.loss_pct = s.ok > 0 ? 0.0 : 100.0; // defensive — caller always sends > 0
        return s;
    }
    s.loss_pct = 100.0 * static_cast<double>(sent - s.ok) / static_cast<double>(sent);
    if (s.ok == 0)
        return s;
    s.min_ms = *std::min_element(ok_ms.begin(), ok_ms.end());
    s.max_ms = *std::max_element(ok_ms.begin(), ok_ms.end());
    double sum = 0.0;
    for (double v : ok_ms)
        sum += v;
    s.avg_ms = sum / static_cast<double>(s.ok);
    if (s.ok >= 2) {
        double var = 0.0;
        for (double v : ok_ms)
            var += (v - s.avg_ms) * (v - s.avg_ms);
        s.jitter_ms = std::sqrt(var / static_cast<double>(s.ok));
    }
    return s;
}

/// Parse an integer parameter with a default and inclusive clamp. Junk,
/// empty, or out-of-int values fall back to `def` (never throw — parameters
/// arrive from the wire).
inline int clamp_param(const std::string& raw, int def, int lo, int hi) {
    int v = def;
    if (!raw.empty()) {
        try {
            v = std::stoi(raw);
        } catch (...) {
            v = def;
        }
    }
    return std::clamp(v, lo, hi);
}

/// Hostname / IPv4-literal gate for probe targets: 1..253 chars drawn from
/// [A-Za-z0-9._-], starting and ending alphanumeric. Deliberately strict —
/// these strings reach getaddrinfo and operator-facing output, and there is
/// no legitimate probe target outside this set (IPv6 literals are a tracked
/// E1 follow-up; ':' stays rejected until then).
inline bool valid_probe_target(const std::string& t) {
    if (t.empty() || t.size() > 253)
        return false;
    auto alnum = [](char c) { return std::isalnum(static_cast<unsigned char>(c)) != 0; };
    if (!alnum(t.front()) || !alnum(t.back()))
        return false;
    for (char c : t)
        if (!alnum(c) && c != '.' && c != '-' && c != '_')
            return false;
    return true;
}

/// Split a comma-separated target list: trims ASCII whitespace, drops
/// empties, caps at `max_n` (silently — the cap is a fan-out bound, not an
/// error). Validation is per-target via valid_probe_target at the call site
/// so each invalid entry gets its own operator-visible row.
inline std::vector<std::string> split_targets(const std::string& csv, std::size_t max_n) {
    std::vector<std::string> out;
    std::size_t pos = 0;
    while (pos <= csv.size() && out.size() < max_n) {
        std::size_t comma = csv.find(',', pos);
        const std::size_t end = (comma == std::string::npos) ? csv.size() : comma;
        std::size_t b = pos, e = end;
        while (b < e && std::isspace(static_cast<unsigned char>(csv[b])))
            ++b;
        while (e > b && std::isspace(static_cast<unsigned char>(csv[e - 1])))
            --e;
        if (e > b)
            out.emplace_back(csv.substr(b, e - b));
        if (comma == std::string::npos)
            break;
        pos = comma + 1;
    }
    return out;
}

} // namespace yuzu::netprobe
