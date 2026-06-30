#include "sync_source_device_ci.hpp"

#include "local_dispatcher.hpp"
#include "sync_source_installed_software.hpp" // reuse yuzu::agent::sha256_hex

#include <spdlog/spdlog.h>

#include <algorithm>
#include <charconv>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::agent {

namespace {

// Caps — MUST match the server seam (device_ci_ingestion.cpp) so the server's
// parse never truncates/drops differently from what this source hashed.
constexpr std::size_t kMaxFieldLen = 1024;
// The device-CI canonical blob is a single small record (~22 short fields); 64 KiB
// is far above any real machine and well below the gRPC 4 MiB receive ceiling.
constexpr std::size_t kMaxBlobBytes = 64u * 1024;

// ── UTF-8 scrub + field clamp ───────────────────────────────────────────────
//
// VERBATIM copy of sync_source_installed_software.cpp's sanitize_utf8_strict +
// clamp_field. The bytes MUST be identical here, in sync_source_installed_software,
// AND in the server's device_ci_ingestion.cpp (parse), or the agent- and
// server-recomputed canonical hashes diverge → permanent need_full. Scrub BEFORE
// clamp (U+FFFD is 3 bytes, so scrubbing can grow a field; clamping first would
// apply a different budget on each side). Replaces every byte not part of a valid
// PostgreSQL-UTF8 sequence (no overlong, no surrogates, nothing > U+10FFFF) with
// U+FFFD — an invalid byte reaching PG is SQLSTATE 22021, which rolls back the
// full-replace txn and makes the agent resend the identical poison forever.
std::string sanitize_utf8_strict(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    const std::size_t n = s.size();
    const auto cont = [&](std::size_t j) -> bool {
        return j < n && (static_cast<unsigned char>(s[j]) & 0xC0) == 0x80;
    };
    std::size_t i = 0;
    while (i < n) {
        const unsigned char c = static_cast<unsigned char>(s[i]);
        const unsigned char c1 = i + 1 < n ? static_cast<unsigned char>(s[i + 1]) : 0;
        std::size_t len = 0;
        bool ok = false;
        if (c < 0x80) {
            ok = true;
            len = 1;
        } else if (c >= 0xC2 && c <= 0xDF) {
            ok = cont(i + 1);
            len = 2;
        } else if (c == 0xE0) {
            ok = c1 >= 0xA0 && c1 <= 0xBF && cont(i + 2); // reject overlong 80..9F
            len = 3;
        } else if (c >= 0xE1 && c <= 0xEC) {
            ok = cont(i + 1) && cont(i + 2);
            len = 3;
        } else if (c == 0xED) {
            ok = c1 >= 0x80 && c1 <= 0x9F && cont(i + 2); // reject surrogates A0..BF
            len = 3;
        } else if (c >= 0xEE && c <= 0xEF) {
            ok = cont(i + 1) && cont(i + 2);
            len = 3;
        } else if (c == 0xF0) {
            ok = c1 >= 0x90 && c1 <= 0xBF && cont(i + 2) && cont(i + 3); // reject overlong 80..8F
            len = 4;
        } else if (c >= 0xF1 && c <= 0xF3) {
            ok = cont(i + 1) && cont(i + 2) && cont(i + 3);
            len = 4;
        } else if (c == 0xF4) {
            ok = c1 >= 0x80 && c1 <= 0x8F && cont(i + 2) && cont(i + 3); // reject > U+10FFFF
            len = 4;
        }
        if (ok) {
            out.append(s.data() + i, len);
            i += len;
        } else {
            out.append("\xEF\xBF\xBD", 3); // U+FFFD, advance one byte
            i += 1;
        }
    }
    return out;
}

std::string clamp_field(std::string_view raw) {
    std::string f = sanitize_utf8_strict(raw);
    if (f.size() > kMaxFieldLen) {
        std::size_t end = kMaxFieldLen;
        while (end > 0 && (static_cast<unsigned char>(f[end]) & 0xC0) == 0x80)
            --end;
        f.resize(end);
    }
    // Strip the canonical framing separators (and NUL) so a value can never corrupt
    // the wire blob's structure (0x1F field / 0x1E record separators).
    std::string out;
    out.reserve(f.size());
    for (char c : f) {
        if (c == '\x1f' || c == '\x1e' || c == '\0')
            continue;
        out.push_back(c);
    }
    return out;
}

// ── plugin-output parsing ───────────────────────────────────────────────────
// Each plugin action writes pipe-delimited lines: `key|f1|f2|...`.

std::vector<std::string_view> split_lines(std::string_view out) {
    std::vector<std::string_view> lines;
    std::size_t pos = 0;
    while (pos < out.size()) {
        std::size_t eol = out.find('\n', pos);
        if (eol == std::string_view::npos)
            eol = out.size();
        std::string_view line = out.substr(pos, eol - pos);
        while (!line.empty() && line.back() == '\r')
            line.remove_suffix(1);
        if (!line.empty())
            lines.push_back(line);
        pos = eol + 1;
    }
    return lines;
}

std::vector<std::string_view> split_pipe(std::string_view line) {
    std::vector<std::string_view> tok;
    std::size_t fp = 0;
    while (true) {
        std::size_t bar = line.find('|', fp);
        if (bar == std::string_view::npos) {
            tok.push_back(line.substr(fp));
            break;
        }
        tok.push_back(line.substr(fp, bar - fp));
        fp = bar + 1;
    }
    return tok;
}

// First `key|value` line's value column ("" if absent). For scalar actions.
std::string scalar(std::string_view out, std::string_view key) {
    for (auto line : split_lines(out)) {
        auto t = split_pipe(line);
        if (t.size() >= 2 && t[0] == key)
            return std::string(t[1]);
    }
    return {};
}

long long to_ll(std::string_view s) {
    long long v = 0;
    auto [p, ec] = std::from_chars(s.data(), s.data() + s.size(), v);
    (void)p;
    return ec == std::errc{} ? v : 0;
}

// A MAC that carries no information (all-zero or empty) — excluded so it can't
// inflate nic_count or pin primary_mac.
bool meaningful_mac(std::string_view mac) {
    if (mac.empty())
        return false;
    for (char c : mac)
        if (c != '0' && c != ':' && c != '-')
            return true;
    return false;
}

} // namespace

std::string device_ci_canonical_blob(const CiRecord& rec) {
    // POSITIONAL — field order is the contract (see CiRecord). Each field is
    // scrub+clamp'd here; the server re-clamps on parse (idempotent) and rejoins.
    const std::string fields[] = {
        rec.manufacturer, rec.model,       rec.serial,        rec.system_uuid,
        rec.hostname,     rec.domain,      rec.ou,            rec.bios_vendor,
        rec.bios_version, rec.bios_date,   rec.cpu_model,     rec.cpu_cores,
        rec.cpu_threads,  rec.ram_bytes,   rec.disks_summary, rec.primary_mac,
        rec.macs_summary, rec.nic_count,   rec.os_name,       rec.os_version,
        rec.os_build,     rec.arch,
    };
    std::string canon;
    bool first = true;
    for (const auto& f : fields) {
        if (!first)
            canon += '\x1f';
        canon += clamp_field(f);
        first = false;
    }
    canon += '\x1e';
    return canon;
}

SyncSource make_device_ci_source(const YuzuPluginDescriptor* hardware,
                                 const YuzuPluginDescriptor* device_identity,
                                 const YuzuPluginDescriptor* os_info,
                                 const YuzuPluginDescriptor* network_config) {
    SyncSource src;
    src.name = "device_ci";
    src.interval = std::chrono::hours{24};
    src.collect = [hardware, device_identity, os_info,
                   network_config]() -> std::optional<std::pair<std::string, std::string>> {
        if (hardware == nullptr || device_identity == nullptr || os_info == nullptr ||
            network_config == nullptr) {
            spdlog::debug("sync: a device_ci source plugin is not loaded — source idle "
                          "(hardware={}, device_identity={}, os_info={}, network_config={})",
                          static_cast<const void*>(hardware),
                          static_cast<const void*>(device_identity),
                          static_cast<const void*>(os_info),
                          static_cast<const void*>(network_config));
            return std::nullopt;
        }

        LocalDispatcher dispatcher;
        // Run one action, returning its captured stdout. Any rc!=0 or a truncated
        // capture aborts the whole cycle (skip — never sync a partial CI record,
        // which would flap the hash). nullopt propagates the abort.
        auto run = [&](const YuzuPluginDescriptor* d,
                       const char* action) -> std::optional<std::string> {
            LocalDispatcher::Result r = dispatcher.run(d, action);
            if (r.rc != 0) {
                spdlog::warn("sync: device_ci action '{}' rc={} — skipping this cycle", action,
                             r.rc);
                return std::nullopt;
            }
            if (r.truncated) {
                spdlog::warn("sync: device_ci action '{}' output truncated — skipping this cycle",
                             action);
                return std::nullopt;
            }
            return std::move(r.captured);
        };

        auto manufacturer = run(hardware, "manufacturer");
        auto model = run(hardware, "model");
        auto system = run(hardware, "system");
        auto bios = run(hardware, "bios");
        auto processors = run(hardware, "processors");
        auto memory = run(hardware, "memory");
        auto disks = run(hardware, "disks");
        auto device_name = run(device_identity, "device_name");
        auto domain = run(device_identity, "domain");
        auto ou = run(device_identity, "ou");
        auto os_name = run(os_info, "os_name");
        auto os_version = run(os_info, "os_version");
        auto os_build = run(os_info, "os_build");
        auto os_arch = run(os_info, "os_arch");
        auto adapters = run(network_config, "adapters");
        if (!manufacturer || !model || !system || !bios || !processors || !memory || !disks ||
            !device_name || !domain || !ou || !os_name || !os_version || !os_build || !os_arch ||
            !adapters)
            return std::nullopt; // a required action failed → skip the cycle

        CiRecord rec;
        rec.manufacturer = scalar(*manufacturer, "manufacturer");
        rec.model = scalar(*model, "model");
        rec.serial = scalar(*system, "serial");
        rec.system_uuid = scalar(*system, "system_uuid");
        rec.hostname = scalar(*device_name, "device_name");
        rec.domain = scalar(*domain, "domain");
        rec.ou = scalar(*ou, "ou");
        rec.bios_vendor = scalar(*bios, "bios_vendor");
        rec.bios_version = scalar(*bios, "bios_version");
        rec.bios_date = scalar(*bios, "bios_date");
        rec.os_name = scalar(*os_name, "os_name");
        rec.os_version = scalar(*os_version, "os_version");
        rec.os_build = scalar(*os_build, "os_build");
        rec.arch = scalar(*os_arch, "os_arch");

        // processors: `cpu|<id>|<model>|<cores>|<threads>|<mhz>` — model from the
        // first CPU, cores/threads summed across sockets.
        long long cores = 0;
        long long threads = 0;
        for (auto line : split_lines(*processors)) {
            auto t = split_pipe(line);
            if (t.size() >= 5 && t[0] == "cpu") {
                if (rec.cpu_model.empty() && !t[2].empty())
                    rec.cpu_model = std::string(t[2]);
                cores += to_ll(t[3]);
                threads += to_ll(t[4]);
            }
        }
        rec.cpu_cores = std::to_string(cores);
        rec.cpu_threads = std::to_string(threads);

        // memory: `dimm|<slot>|<size_mb>|<type>|<speed_mhz>` — sum size_mb → bytes.
        long long total_mb = 0;
        for (auto line : split_lines(*memory)) {
            auto t = split_pipe(line);
            if (t.size() >= 3 && t[0] == "dimm")
                total_mb += to_ll(t[2]);
        }
        rec.ram_bytes = std::to_string(total_mb * 1024 * 1024);

        // disks: `disk|<idx>|<model>|<size>|<type>|<interface>` — sorted human
        // summary "<model> <size> <type>". (No numeric total: the size unit is not
        // portable — GB int on Windows, "476.9G" on Linux.) Skip the empty sentinel.
        std::vector<std::string> disk_strs;
        for (auto line : split_lines(*disks)) {
            auto t = split_pipe(line);
            if (t.size() >= 5 && t[0] == "disk") {
                if (t[2] == "unknown" && t[3] == "0")
                    continue;
                std::string s = std::string(t[2]) + " " + std::string(t[3]) + " " + std::string(t[4]);
                disk_strs.push_back(std::move(s));
            }
        }
        std::sort(disk_strs.begin(), disk_strs.end());
        for (std::size_t i = 0; i < disk_strs.size(); ++i) {
            if (i)
                rec.disks_summary += "; ";
            rec.disks_summary += disk_strs[i];
        }

        // adapters: `adapter|<name>|<mac>|<speed>|<status>` — collect meaningful
        // MACs, dedup + sort (deterministic). primary = first sorted.
        std::vector<std::string> macs;
        for (auto line : split_lines(*adapters)) {
            auto t = split_pipe(line);
            if (t.size() >= 3 && t[0] == "adapter" && meaningful_mac(t[2]))
                macs.emplace_back(t[2]);
        }
        std::sort(macs.begin(), macs.end());
        macs.erase(std::unique(macs.begin(), macs.end()), macs.end());
        rec.nic_count = std::to_string(macs.size());
        if (!macs.empty())
            rec.primary_mac = macs.front();
        for (std::size_t i = 0; i < macs.size(); ++i) {
            if (i)
                rec.macs_summary += ",";
            rec.macs_summary += macs[i];
        }

        std::string blob = device_ci_canonical_blob(rec);
        if (blob.size() > kMaxBlobBytes) {
            spdlog::warn("sync: device_ci blob {} B exceeds {} B cap — skipping this cycle",
                         blob.size(), kMaxBlobBytes);
            return std::nullopt;
        }
        std::string hash = sha256_hex(blob);
        return std::make_pair(std::move(blob), std::move(hash));
    };
    return src;
}

} // namespace yuzu::agent
