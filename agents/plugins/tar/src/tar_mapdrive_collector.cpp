// tar_mapdrive_collector.cpp — mapped-drive enumeration for the TAR `mapdrive`
// capture source (capability-map §3.8). Impure platform shell; the snapshot is
// diffed in tar_diff.cpp (compute_mapdrive_events) and persisted in tar_db.cpp
// (insert_mapdrive_events). Core capture-source pattern — types/decls in
// tar_collectors.hpp. See docs/tar-implementer.md "Adding a capture source".
//
// Two directions, both in scope (Windows + Linux; macOS kPlanned):
//   outbound = drives THIS host maps to remote shares
//   inbound  = remote hosts mapping THIS host's shares (the §3.8 lateral-movement signal)
// and two modes:
//   live     = current state, snapshot-diffed each collect_slow tick (enumerate_mapdrive)
//   historic = a one-time init backfill from persistent OS artifacts (enumerate_mapdrive_history)
//
// The raw text parsers (parse_proc_mounts / parse_fstab / parse_smbstatus /
// parse_win_security_logons / parse_samba_logs) are PURE and compiled on every
// platform so each leg is unit-tested off its native OS from captured samples.
// Only the I/O (WNet / NetApi / registry hive loads / subprocess / file reads)
// is #ifdef-guarded.
//
// PII: mapped-drive rows expose usernames + share paths. Per the works-council
// posture the source is opt-in (default_enabled=false); rows are NOT run through
// redact_cmdline (cmdline-only; it would mangle UNC paths) — opt-in + audit is
// the protection, exactly as dns_live does for visited domains.

#include "tar_collectors.hpp"

#include <spdlog/spdlog.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <winnetwk.h> // WNetOpenEnumW / WNetEnumResourceW / WNetGetUserW (mpr)
#include <lm.h>       // NetSessionEnum / NetApiBufferFree (netapi32)
#include <win_str.hpp> // shared yuzu::win wide<->UTF-8 helpers (#1681)
#include <cwchar>      // wcslen
#endif

namespace yuzu::tar {

// ── Pure helpers (cross-platform) ─────────────────────────────────────────────
namespace {

std::string trim(const std::string& s) {
    auto b = s.find_first_not_of(" \t\r\n");
    if (b == std::string::npos)
        return {};
    auto e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
}

std::vector<std::string> split_ws(const std::string& s) {
    std::vector<std::string> out;
    std::size_t i = 0;
    while (i < s.size()) {
        while (i < s.size() && std::isspace(static_cast<unsigned char>(s[i])))
            ++i;
        std::size_t start = i;
        while (i < s.size() && !std::isspace(static_cast<unsigned char>(s[i])))
            ++i;
        if (i > start)
            out.push_back(s.substr(start, i - start));
    }
    return out;
}

bool icontains(const std::string& hay, const std::string& needle) {
    if (needle.empty())
        return true;
    if (needle.size() > hay.size())
        return false;
    auto lower = [](char c) { return static_cast<char>(std::tolower(static_cast<unsigned char>(c))); };
    for (std::size_t i = 0; i + needle.size() <= hay.size(); ++i) {
        std::size_t j = 0;
        for (; j < needle.size(); ++j)
            if (lower(hay[i + j]) != lower(needle[j]))
                break;
        if (j == needle.size())
            return true;
    }
    return false;
}

// Civil-days epoch (Howard Hinnant) — portable + deterministic (unit-testable),
// no timegm/_mkgmtime portability split. Local-time log stamps are recorded
// as-is (interpreted as UTC); a small tz skew on historical rows is acceptable
// for forensic ordering and keeps the parsers pure.
int64_t days_from_civil(int y, unsigned m, unsigned d) {
    y -= m <= 2;
    const int64_t era = (y >= 0 ? y : y - 399) / 400;
    const unsigned yoe = static_cast<unsigned>(y - era * 400);
    const unsigned doy = (153u * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + static_cast<int64_t>(doe) - 719468;
}

int64_t ymd_hms_to_epoch(int y, int mo, int d, int h, int mi, int s) {
    if (mo < 1 || mo > 12 || d < 1 || d > 31)
        return 0;
    return days_from_civil(y, static_cast<unsigned>(mo), static_cast<unsigned>(d)) * 86400 +
           h * 3600 + mi * 60 + s;
}

// Parse a flexible timestamp starting at `pos`: "YYYY-MM-DD[T| ]HH:MM:SS" or the
// Samba "YYYY/MM/DD HH:MM:SS" form. Returns epoch seconds or 0 if not matched.
int64_t parse_flexible_ts(const std::string& s, std::size_t pos = 0) {
    int y = 0, mo = 0, d = 0, h = 0, mi = 0, se = 0;
    // Accept '-' or '/' date separators and 'T' or ' ' between date and time.
    if (std::sscanf(s.c_str() + pos, "%4d-%2d-%2dT%2d:%2d:%2d", &y, &mo, &d, &h, &mi, &se) == 6 ||
        std::sscanf(s.c_str() + pos, "%4d-%2d-%2d %2d:%2d:%2d", &y, &mo, &d, &h, &mi, &se) == 6 ||
        std::sscanf(s.c_str() + pos, "%4d/%2d/%2d %2d:%2d:%2d", &y, &mo, &d, &h, &mi, &se) == 6)
        return ymd_hms_to_epoch(y, mo, d, h, mi, se);
    return 0;
}

// Decode the kernel's octal escapes in /proc/mounts and /etc/fstab fields
// (space=\040, tab=\011, newline=\012, backslash=\134).
std::string decode_mount_escapes(const std::string& in) {
    std::string out;
    out.reserve(in.size());
    for (std::size_t i = 0; i < in.size(); ++i) {
        if (in[i] == '\\' && i + 3 < in.size() && std::isdigit(static_cast<unsigned char>(in[i + 1])) &&
            std::isdigit(static_cast<unsigned char>(in[i + 2])) &&
            std::isdigit(static_cast<unsigned char>(in[i + 3]))) {
            int v = (in[i + 1] - '0') * 64 + (in[i + 2] - '0') * 8 + (in[i + 3] - '0');
            out.push_back(static_cast<char>(v));
            i += 3;
        } else {
            out.push_back(in[i]);
        }
    }
    return out;
}

bool is_network_fstype(const std::string& fs) {
    static const char* kNet[] = {"cifs",       "smb3",  "smb2", "smbfs",    "nfs",
                                 "nfs4",       "ncpfs", "afs",  "glusterfs", "fuse.sshfs",
                                 "fuse.davfs", "davfs", "fuse.cifs"};
    for (const auto* n : kNet)
        if (fs == n)
            return true;
    return false;
}

// Best-effort host extraction from a share/device string across the forms:
//   \\server\share  //server/share  server:/export  user@host:/path
std::string remote_host_of(const std::string& path) {
    std::string p = path;
    // UNC: leading \\ or //
    if (p.size() >= 2 && (p[0] == '\\' || p[0] == '/') && (p[1] == '\\' || p[1] == '/')) {
        std::size_t start = 2;
        std::size_t end = p.find_first_of("\\/", start);
        return p.substr(start, end == std::string::npos ? std::string::npos : end - start);
    }
    // user@host:/path — strip the user@ prefix first
    auto at = p.find('@');
    auto colon = p.find(':');
    if (colon != std::string::npos && (at == std::string::npos || at < colon)) {
        std::size_t start = (at != std::string::npos) ? at + 1 : 0;
        return p.substr(start, colon - start);
    }
    return {};
}

// Extract the address from a Samba "(ipv4:1.2.3.4:445)" / "(ipv6:::1:...)" token.
std::string extract_paren_ip(const std::string& line) {
    for (const char* tag : {"(ipv4:", "(ipv6:"}) {
        auto pos = line.find(tag);
        if (pos == std::string::npos)
            continue;
        pos += std::string(tag).size();
        auto end = line.find(')', pos);
        if (end == std::string::npos)
            continue;
        std::string inside = line.substr(pos, end - pos);
        // ipv4:1.2.3.4:445 -> drop the trailing :port. IPv6 addresses contain
        // colons, so strip only a final :digits suffix AND only when it is not
        // itself part of the address — i.e. the char before the last ':' is not
        // another ':' (which would make it the "::" of a portless address like
        // 2001:db8::1). Without that guard the last hextet of a portless IPv6
        // address is lopped off.
        auto last = inside.find_last_of(':');
        if (last != std::string::npos && last > 0 && last + 1 < inside.size() &&
            inside[last - 1] != ':' &&
            std::isdigit(static_cast<unsigned char>(inside[last + 1])))
            inside = inside.substr(0, last);
        return inside;
    }
    return {};
}

// Word following `marker` in `line` (whitespace-delimited); "" if absent.
std::string word_after(const std::string& line, const std::string& marker) {
    auto pos = line.find(marker);
    if (pos == std::string::npos)
        return {};
    pos += marker.size();
    while (pos < line.size() && std::isspace(static_cast<unsigned char>(line[pos])))
        ++pos;
    std::size_t start = pos;
    while (pos < line.size() && !std::isspace(static_cast<unsigned char>(line[pos])))
        ++pos;
    return line.substr(start, pos - start);
}

// cpp-conventions.md §Shell/process boundaries: this is a popen/_popen shell
// site. DOCUMENTED EXCEPTION (a shell is used rather than argv-style
// CreateProcess/posix_spawn):
//   1. Every command passed here is a COMPILE-TIME CONSTANT literal — no value
//      from the network, registry, filesystem, or operator is ever interpolated,
//      so there is no command-injection surface.
//   2. The Linux tools (smbstatus/journalctl) live at distro-varying paths and we
//      parse their line-oriented text output; an argv helper would still need a
//      PATH lookup. The one Windows tool (wevtutil) is invoked by its ABSOLUTE
//      System32 path (see system32_path) so PATH resolution cannot be hijacked on
//      the privileged agent.
//   3. Output is byte-capped (max_bytes) so a runaway tool cannot exhaust memory;
//      the pipe is fully drained so the child never blocks on a full pipe.
// [[maybe_unused]]: unused on the macOS stub build.
[[maybe_unused]] std::string run_command(const std::string& cmd,
                                         std::size_t max_bytes = 8u * 1024 * 1024) {
    std::string out;
#ifdef _WIN32
    FILE* pipe = _popen(cmd.c_str(), "r");
#else
    FILE* pipe = popen(cmd.c_str(), "r");
#endif
    if (!pipe)
        return out;
    std::array<char, 4096> buf{};
    std::size_t n;
    bool capped = false;
    while ((n = std::fread(buf.data(), 1, buf.size(), pipe)) > 0) {
        if (out.size() < max_bytes) {
            std::size_t take = std::min(n, max_bytes - out.size());
            out.append(buf.data(), take);
            if (out.size() >= max_bytes)
                capped = true;
        }
        // Past the cap: keep reading (discarding) so the child can finish writing
        // rather than blocking on a full pipe — memory stays bounded by max_bytes.
    }
#ifdef _WIN32
    _pclose(pipe);
#else
    pclose(pipe);
#endif
    if (capped)
        spdlog::warn("TAR mapdrive: command output capped at {} bytes (tail discarded)", max_bytes);
    return out;
}

[[maybe_unused]] std::string read_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f)
        return {};
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

// Read at most the LAST max_bytes of a file. Samba's log.smbd on a busy file
// server can be hundreds of MB (or unbounded with `max log size = 0`); slurping
// it whole on the init-critical backfill path is a memory/latency hazard. The
// most recent connects are at the tail, which is what the backfill wants anyway.
// Starts at a line boundary so parse_samba_logs never sees a half-truncated line.
[[maybe_unused]] std::string read_file_tail(const std::string& path, std::size_t max_bytes) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f)
        return {};
    std::streamoff size = f.tellg();
    if (size <= 0)
        return {};
    std::size_t want = static_cast<std::size_t>(size);
    bool truncated = want > max_bytes;
    if (truncated)
        want = max_bytes;
    f.seekg(static_cast<std::streamoff>(static_cast<std::size_t>(size) - want), std::ios::beg);
    std::string buf(want, '\0');
    f.read(buf.data(), static_cast<std::streamsize>(want));
    buf.resize(static_cast<std::size_t>(f.gcount()));
    // Drop a leading partial line if we started mid-file.
    if (truncated) {
        if (auto nl = buf.find('\n'); nl != std::string::npos)
            buf.erase(0, nl + 1);
    }
    return buf;
}

} // namespace

// Collapse duplicate history rows by mapping identity, preferring the smallest
// non-zero timestamp (the earliest known sighting). Applies the cap. Defined at
// yuzu::tar scope (not the anonymous namespace) so it is unit-testable.
std::vector<MapDriveHistoryRow> dedup_history(std::vector<MapDriveHistoryRow> rows) {
    std::unordered_map<std::string, std::size_t> seen;
    std::vector<MapDriveHistoryRow> out;
    out.reserve(rows.size());
    for (auto& r : rows) {
        std::string key = r.entry.direction + "\x1f" + r.entry.local_mount + "\x1f" +
                          r.entry.remote_path + "\x1f" + r.entry.remote_host + "\x1f" +
                          r.entry.username;
        auto it = seen.find(key);
        if (it == seen.end()) {
            seen.emplace(std::move(key), out.size());
            out.push_back(std::move(r));
        } else {
            auto& kept = out[it->second];
            if (r.ts != 0 && (kept.ts == 0 || r.ts < kept.ts))
                kept.ts = r.ts;
        }
        if (out.size() >= kMapDriveHistoryCap)
            break;
    }
    return out;
}

// ── Pure parsers (compiled everywhere; unit-tested off-OS) ────────────────────

std::vector<MapDriveEntry> parse_proc_mounts(const std::string& text) {
    std::vector<MapDriveEntry> out;
    std::istringstream in(text);
    std::string line;
    while (std::getline(in, line)) {
        auto tok = split_ws(line);
        if (tok.size() < 3)
            continue;
        std::string fstype = tok[2];
        if (!is_network_fstype(fstype))
            continue;
        std::string device = decode_mount_escapes(tok[0]);
        std::string mountpoint = decode_mount_escapes(tok[1]);
        MapDriveEntry e;
        e.direction = "outbound";
        e.local_mount = mountpoint;
        e.remote_path = device;
        e.remote_host = remote_host_of(device);
        e.provider = fstype;
        out.push_back(std::move(e));
    }
    return out;
}

std::vector<MapDriveHistoryRow> parse_fstab(const std::string& text) {
    std::vector<MapDriveHistoryRow> out;
    std::istringstream in(text);
    std::string line;
    while (std::getline(in, line)) {
        std::string t = trim(line);
        if (t.empty() || t[0] == '#')
            continue;
        auto tok = split_ws(t);
        if (tok.size() < 3)
            continue;
        std::string fstype = tok[2];
        if (!is_network_fstype(fstype))
            continue;
        std::string spec = decode_mount_escapes(tok[0]);
        std::string mountpoint = decode_mount_escapes(tok[1]);
        MapDriveHistoryRow r;
        r.ts = 0; // fstab carries no timestamp
        r.entry.direction = "outbound";
        r.entry.local_mount = mountpoint;
        r.entry.remote_path = spec;
        r.entry.remote_host = remote_host_of(spec);
        r.entry.provider = fstype;
        out.push_back(std::move(r));
    }
    return out;
}

std::vector<MapDriveEntry> parse_smbstatus(const std::string& text) {
    // `smbstatus -b` sessions table:
    //   PID  Username  Group  Machine                       Protocol  ...
    //   1234 alice     alice  192.168.1.50 (ipv4:1.2.3.4:445) SMB3_11 ...
    // A data row starts with a numeric PID; the client is the parenthetical IP if
    // present, else the Machine token (index 3).
    std::vector<MapDriveEntry> out;
    std::istringstream in(text);
    std::string line;
    while (std::getline(in, line)) {
        auto tok = split_ws(line);
        if (tok.size() < 4)
            continue;
        bool pid = !tok[0].empty();
        for (char c : tok[0])
            if (!std::isdigit(static_cast<unsigned char>(c)))
                pid = false;
        if (!pid)
            continue;
        MapDriveEntry e;
        e.direction = "inbound";
        e.username = tok[1];
        std::string ip = extract_paren_ip(line);
        e.remote_host = !ip.empty() ? ip : tok[3];
        e.provider = "SMB";
        out.push_back(std::move(e));
    }
    return out;
}

std::vector<MapDriveHistoryRow> parse_win_security_logons(const std::string& text) {
    // wevtutil `/f:text` emits one block per event starting with "Event[N]:".
    // We keep 4624 (successful logon) with Logon Type 3 (network) that carry a
    // real Source Network Address — those are the inbound network connections
    // (over-captures beyond SMB; acceptable for lateral-movement history). The
    // real account is the 2nd "Account Name:" (the 1st is the requesting subject).
    std::vector<MapDriveHistoryRow> out;
    std::size_t pos = 0;
    while (pos < text.size()) {
        std::size_t next = text.find("Event[", pos + 1);
        std::string block = text.substr(pos, next == std::string::npos ? std::string::npos : next - pos);
        pos = (next == std::string::npos) ? text.size() : next;

        if (!icontains(block, "Event ID:"))
            continue;
        int event_id = 0;
        {
            auto p = block.find("Event ID:");
            if (p != std::string::npos)
                std::sscanf(block.c_str() + p + 9, "%d", &event_id);
        }
        if (event_id != 4624)
            continue;

        // Logon Type must be 3 (network).
        int logon_type = -1;
        {
            auto p = block.find("Logon Type:");
            if (p != std::string::npos)
                std::sscanf(block.c_str() + p + 11, "%d", &logon_type);
        }
        if (logon_type != 3)
            continue;

        std::string src = trim(word_after(block, "Source Network Address:"));
        if (src.empty() || src == "-" || src == "127.0.0.1" || src == "::1")
            continue; // no real remote peer -> not an inbound connection

        // The 2nd "Account Name:" is the logged-on account (the 1st is the
        // requesting subject / system account).
        std::string account;
        {
            auto p1 = block.find("Account Name:");
            auto p2 = (p1 == std::string::npos) ? std::string::npos
                                                : block.find("Account Name:", p1 + 1);
            std::size_t use = (p2 != std::string::npos) ? p2 : p1;
            if (use != std::string::npos)
                account = trim(word_after(block.substr(use), "Account Name:"));
        }
        if (account.empty() || account == "-")
            continue;
        // Skip machine accounts (name ends with '$') and well-known noise.
        if (account.back() == '$' || account == "ANONYMOUS")
            continue;

        std::string date = trim(word_after(block, "Date:"));
        MapDriveHistoryRow r;
        r.ts = parse_flexible_ts(date);
        r.entry.direction = "inbound";
        r.entry.remote_host = src;
        r.entry.username = account;
        r.entry.provider = "network"; // logon-audit heuristic (broader than SMB)
        out.push_back(std::move(r));
    }
    return out;
}

std::vector<MapDriveHistoryRow> parse_samba_logs(const std::string& text) {
    // Two shapes are handled:
    //   Samba log.smbd:  "[2026/07/01 10:20:30.123, 3] .../service.c(...)" header
    //                    lines set the timestamp; a later line contains
    //                    "... (ipv4:IP:445) connect to service SHARE initially as user USER".
    //   journalctl -o short-iso: the connect line itself is ISO-dated.
    std::vector<MapDriveHistoryRow> out;
    std::istringstream in(text);
    std::string line;
    int64_t last_ts = 0;
    while (std::getline(in, line)) {
        // Samba header timestamp: "[YYYY/MM/DD HH:MM:SS"
        if (!line.empty() && line[0] == '[' && line.size() > 20) {
            if (auto ts = parse_flexible_ts(line, 1); ts != 0)
                last_ts = ts;
        }
        if (!icontains(line, "connect to service"))
            continue;

        int64_t ts = last_ts;
        if (auto own = parse_flexible_ts(line); own != 0) // journalctl ISO-dated line
            ts = own;

        std::string service = word_after(line, "connect to service");
        std::string user = word_after(line, "as user");
        std::string ip = extract_paren_ip(line);
        if (ip.empty())
            ip = word_after(line, "client ["); // "client [1.2.3.4]"
        if (!ip.empty() && ip.back() == ']')
            ip.pop_back();

        if (service.empty() && user.empty() && ip.empty())
            continue;
        MapDriveHistoryRow r;
        r.ts = ts;
        r.entry.direction = "inbound";
        r.entry.local_mount = service;
        r.entry.remote_host = ip;
        r.entry.username = user;
        r.entry.provider = "SMB";
        out.push_back(std::move(r));
    }
    return out;
}

// ── Windows platform shell ────────────────────────────────────────────────────
#ifdef _WIN32

namespace {

void warn_capped(std::atomic<bool>& flag, const char* what, std::size_t cap) {
    if (!flag.exchange(true))
        spdlog::warn("TAR mapdrive: {} cap {} reached — truncating (repeats suppressed "
                     "until it clears)",
                     what, cap);
}

// RAII owners for the Win32 enumeration resources (cpp-conventions.md §Resource
// ownership: manual cleanup between a throwing acquire/use and release is a
// governance finding). from_wide / vector::push_back below can throw, so the
// handle/buffer must free on every exit including an exceptional unwind. Same
// shape as this file's RegKeyGuard/HiveUnloadGuard and the in-repo HandleGuard
// (processes_plugin.cpp) / MibTableGuard (network_config_plugin.cpp).
struct WNetEnumGuard {
    HANDLE h{nullptr};
    explicit WNetEnumGuard(HANDLE hh) noexcept : h(hh) {}
    ~WNetEnumGuard() {
        if (h)
            WNetCloseEnum(h);
    }
    WNetEnumGuard(const WNetEnumGuard&) = delete;
    WNetEnumGuard& operator=(const WNetEnumGuard&) = delete;
};
struct NetApiBufGuard {
    LPVOID p{nullptr};
    explicit NetApiBufGuard(LPVOID pp) noexcept : p(pp) {}
    ~NetApiBufGuard() {
        if (p)
            NetApiBufferFree(p);
    }
    NetApiBufGuard(const NetApiBufGuard&) = delete;
    NetApiBufGuard& operator=(const NetApiBufGuard&) = delete;
};

// Absolute path to a System32 tool, quoted for the shell (cpp-conventions §Shell:
// removes PATH-hijack exposure for wevtutil on the privileged agent). Falls back
// to the bare name if GetSystemDirectoryW fails (defensive; effectively never).
std::string system32_path(const char* exe) {
    wchar_t dir[MAX_PATH]{};
    UINT n = GetSystemDirectoryW(dir, MAX_PATH);
    if (n == 0 || n >= MAX_PATH)
        return exe; // fallback: bare name resolved via PATH
    return "\"" + yuzu::win::from_wide(dir) + "\\" + exe + "\"";
}

// --- outbound live: currently-connected network drives (WNet) ---
void enum_wnet_outbound(std::vector<MapDriveEntry>& out) {
    HANDLE hEnum = nullptr;
    DWORD rc = WNetOpenEnumW(RESOURCE_CONNECTED, RESOURCETYPE_DISK, 0, nullptr, &hEnum);
    if (rc != NO_ERROR)
        return; // no connected network resources (or provider unavailable)
    WNetEnumGuard eg{hEnum}; // closes on every exit (cap return / throw / normal)

    std::vector<char> buffer(16384);
    for (;;) {
        DWORD count = 0xFFFFFFFF; // as many as fit
        DWORD size = static_cast<DWORD>(buffer.size());
        rc = WNetEnumResourceW(hEnum, &count, buffer.data(), &size);
        if (rc == ERROR_MORE_DATA) {
            // Buffer too small for this page — grow and retry (distinct from
            // session pagination; WNet has no resume handle).
            buffer.resize(size);
            continue;
        }
        if (rc != NO_ERROR)
            break; // ERROR_NO_MORE_ITEMS or a failure — done
        auto* res = reinterpret_cast<NETRESOURCEW*>(buffer.data());
        for (DWORD i = 0; i < count; ++i) {
            MapDriveEntry e;
            e.direction = "outbound";
            if (res[i].lpLocalName)
                e.local_mount = yuzu::win::from_wide(res[i].lpLocalName);
            if (res[i].lpRemoteName)
                e.remote_path = yuzu::win::from_wide(res[i].lpRemoteName);
            if (res[i].lpProvider)
                e.provider = yuzu::win::from_wide(res[i].lpProvider);
            e.remote_host = remote_host_of(e.remote_path);
            wchar_t ubuf[256]{};
            DWORD ulen = 256;
            const wchar_t* key = res[i].lpLocalName ? res[i].lpLocalName : res[i].lpRemoteName;
            if (key && WNetGetUserW(key, ubuf, &ulen) == NO_ERROR)
                e.username = yuzu::win::from_wide(ubuf);
            out.push_back(std::move(e));
            if (out.size() >= kMapDriveEntryCap) {
                static std::atomic<bool> warned{false};
                warn_capped(warned, "live", kMapDriveEntryCap);
                return; // eg unwinds WNetCloseEnum
            }
        }
    }
}

// --- inbound live: remote sessions into our shares (NetSessionEnum) ---
template <typename INFO>
void collect_sessions(INFO* buf, DWORD n, std::vector<MapDriveEntry>& out,
                      LPWSTR INFO::*cname, LPWSTR INFO::*uname) {
    for (DWORD i = 0; i < n; ++i) {
        MapDriveEntry e;
        e.direction = "inbound";
        if (buf[i].*cname)
            e.remote_host = yuzu::win::from_wide(buf[i].*cname);
        if (buf[i].*uname)
            e.username = yuzu::win::from_wide(buf[i].*uname);
        e.provider = "SMB";
        if (e.remote_host.empty() && e.username.empty())
            continue;
        out.push_back(std::move(e));
        if (out.size() >= kMapDriveEntryCap)
            return;
    }
}

// Drain one NetSessionEnum level, paging on ERROR_MORE_DATA via the resume
// handle (MAX_PREFERRED_LENGTH usually returns everything in one call, but the
// API may still page — a single call silently drops sessions past page one on a
// busy file server). Stops at kMapDriveEntryCap with a truncation warn (§8
// cap-with-warn); each page's buffer is freed by NetApiBufGuard even on a throw.
// Returns the final NET_API_STATUS so the caller can branch on access-denied.
template <typename INFO>
NET_API_STATUS enum_sessions_level(DWORD level, LPWSTR INFO::*cname, LPWSTR INFO::*uname,
                                   std::vector<MapDriveEntry>& out) {
    DWORD resume = 0; // NetSessionEnum resume_handle is LPDWORD (DWORD), not DWORD_PTR
    NET_API_STATUS s;
    // Hard progress backstop: the cap check below only trips once `out` grows, so a
    // (pathological) provider returning ERROR_MORE_DATA without advancing `resume`
    // and yielding only skipped rows could otherwise spin. Real result sets need
    // far fewer than this many pages; exceeding it means no forward progress.
    constexpr unsigned kMaxPages = 4096;
    unsigned pages = 0;
    do {
        INFO* buf = nullptr;
        DWORD read = 0, total = 0;
        s = NetSessionEnum(nullptr, nullptr, nullptr, level, reinterpret_cast<LPBYTE*>(&buf),
                           MAX_PREFERRED_LENGTH, &read, &total, &resume);
        NetApiBufGuard g{buf};
        if (s == NERR_Success || s == ERROR_MORE_DATA)
            collect_sessions<INFO>(buf, read, out, cname, uname); // caps internally
        if (out.size() >= kMapDriveEntryCap) {
            static std::atomic<bool> warned{false};
            warn_capped(warned, "inbound", kMapDriveEntryCap);
            return s;
        }
        if (s == ERROR_MORE_DATA && (read == 0 || ++pages >= kMaxPages)) {
            spdlog::warn("TAR mapdrive: NetSessionEnum paging made no progress — stopping "
                         "(read={}, pages={})",
                         read, pages);
            break; // no forward progress — bail rather than spin
        }
    } while (s == ERROR_MORE_DATA);
    return s;
}

void enum_netsession_inbound(std::vector<MapDriveEntry>& out) {
    // Level 502 (rich) → fall back to level 10 → give up on access-denied.
    NET_API_STATUS s = enum_sessions_level<SESSION_INFO_502>(
        502, &SESSION_INFO_502::sesi502_cname, &SESSION_INFO_502::sesi502_username, out);
    // Access is checked up front, so a 502 denial leaves `out` empty — the level-10
    // fallback cannot double-collect.
    if (s == ERROR_ACCESS_DENIED)
        s = enum_sessions_level<SESSION_INFO_10>(
            10, &SESSION_INFO_10::sesi10_cname, &SESSION_INFO_10::sesi10_username, out);

    // Access denied at both levels (not local-admin / Server-Operator) — degrade
    // to empty, warned once.
    static std::atomic<bool> s_denied_warned{false};
    if (s == ERROR_ACCESS_DENIED && !s_denied_warned.exchange(true))
        spdlog::warn("TAR mapdrive: NetSessionEnum access denied — inbound sessions require "
                     "local-admin / Server-Operator; skipping (repeats suppressed)");
}

// --- registry helpers for outbound history ---
struct RegKeyGuard {
    HKEY h{nullptr};
    ~RegKeyGuard() {
        if (h)
            RegCloseKey(h);
    }
};

// RAII unload for a RegLoadKeyW-mounted offline hive. Construct it BEFORE the
// RegKeyGuard for the mounted root so destruction order (reverse of
// construction) closes the root key first, then unloads — and the unload runs on
// EVERY exit including an exception (e.g. std::bad_alloc from a string/vector
// grow while reading the hive). A leaked mount locks NTUSER.DAT until reboot.
struct HiveUnloadGuard {
    std::wstring mount;
    ~HiveUnloadGuard() {
        if (!mount.empty())
            RegUnLoadKeyW(HKEY_USERS, mount.c_str());
    }
};

int64_t filetime_to_epoch(const FILETIME& ft) {
    ULARGE_INTEGER u;
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    constexpr uint64_t kDelta = 116444736000000000ULL; // 1601→1970 in 100ns
    if (u.QuadPart < kDelta)
        return 0;
    return static_cast<int64_t>((u.QuadPart - kDelta) / 10000000ULL);
}

int64_t key_last_write_epoch(HKEY key) {
    FILETIME ft{};
    if (RegQueryInfoKeyW(key, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                         nullptr, nullptr, nullptr, &ft) != ERROR_SUCCESS)
        return 0;
    return filetime_to_epoch(ft);
}

std::string reg_read_sz(HKEY key, const wchar_t* name) {
    DWORD type = 0, cb = 0;
    if (RegQueryValueExW(key, name, nullptr, &type, nullptr, &cb) != ERROR_SUCCESS)
        return {};
    if ((type != REG_SZ && type != REG_EXPAND_SZ) || cb == 0)
        return {};
    std::wstring buf(cb / sizeof(wchar_t) + 1, L'\0');
    DWORD cb2 = static_cast<DWORD>(buf.size() * sizeof(wchar_t));
    if (RegQueryValueExW(key, name, nullptr, &type, reinterpret_cast<LPBYTE>(buf.data()), &cb2) !=
        ERROR_SUCCESS)
        return {};
    buf.resize(wcslen(buf.c_str()));
    return yuzu::win::from_wide(buf.c_str());
}

// MountPoints2 remote subkey names encode a UNC: "##server#share" -> "\\server\share".
std::string decode_mountpoints2(const std::wstring& name) {
    if (name.rfind(L"##", 0) != 0)
        return {}; // volume GUIDs / drive letters are not remote shares
    // Rebuild as wide (mapping '#' -> '\\') then convert once through the shared
    // UTF-16->UTF-8 helper — a raw static_cast<char> would mangle any non-ASCII
    // code unit in an internationalized server/share name.
    std::wstring w = L"\\\\";
    for (std::size_t i = 2; i < name.size(); ++i)
        w += (name[i] == L'#') ? L'\\' : name[i];
    return yuzu::win::from_wide(w.c_str());
}

// Read the three per-user outbound artifacts under an opened user-root hive key.
void read_user_outbound_history(HKEY user_root, const std::string& profile_user,
                                std::vector<MapDriveHistoryRow>& out) {
    // (a) HKCU\Network\<Drive> — persistent mapped drives.
    {
        RegKeyGuard net;
        if (RegOpenKeyExW(user_root, L"Network", 0, KEY_READ, &net.h) == ERROR_SUCCESS) {
            wchar_t sub[256];
            DWORD idx = 0, len = 256;
            while (RegEnumKeyExW(net.h, idx, sub, &len, nullptr, nullptr, nullptr, nullptr) ==
                   ERROR_SUCCESS) {
                if (out.size() >= kMapDriveHistoryCap)
                    return; // per-key cap (a corrupt/huge key must not run unbounded)
                RegKeyGuard drive;
                if (RegOpenKeyExW(net.h, sub, 0, KEY_READ, &drive.h) == ERROR_SUCCESS) {
                    MapDriveHistoryRow r;
                    r.ts = key_last_write_epoch(drive.h);
                    r.entry.direction = "outbound";
                    r.entry.local_mount = std::string(1, static_cast<char>(sub[0])) + ":";
                    r.entry.remote_path = reg_read_sz(drive.h, L"RemotePath");
                    r.entry.remote_host = remote_host_of(r.entry.remote_path);
                    std::string u = reg_read_sz(drive.h, L"UserName");
                    r.entry.username = u.empty() ? profile_user : u;
                    r.entry.provider = reg_read_sz(drive.h, L"ProviderName");
                    if (!r.entry.remote_path.empty())
                        out.push_back(std::move(r));
                }
                idx++;
                len = 256;
            }
        }
    }
    // (b) Map Network Drive MRU — recently mapped UNCs (may be since-removed).
    {
        RegKeyGuard mru;
        if (RegOpenKeyExW(user_root,
                          L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Map Network "
                          L"Drive MRU",
                          0, KEY_READ, &mru.h) == ERROR_SUCCESS) {
            int64_t ts = key_last_write_epoch(mru.h);
            wchar_t vname[128];
            DWORD vidx = 0, vlen = 128;
            for (;; vidx++, vlen = 128) {
                if (out.size() >= kMapDriveHistoryCap)
                    return; // per-key cap
                LONG er = RegEnumValueW(mru.h, vidx, vname, &vlen, nullptr, nullptr, nullptr, nullptr);
                if (er != ERROR_SUCCESS)
                    break;
                if (vname[0] == L'M' && std::wstring(vname) == L"MRUList")
                    continue;
                std::string unc = reg_read_sz(mru.h, vname);
                if (unc.empty())
                    continue;
                MapDriveHistoryRow r;
                r.ts = ts;
                r.entry.direction = "outbound";
                r.entry.remote_path = unc;
                r.entry.remote_host = remote_host_of(unc);
                r.entry.username = profile_user;
                r.entry.provider = "SMB";
                out.push_back(std::move(r));
            }
        }
    }
    // (c) MountPoints2 — every remote share the user touched.
    {
        RegKeyGuard mp;
        if (RegOpenKeyExW(user_root,
                          L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2", 0,
                          KEY_READ, &mp.h) == ERROR_SUCCESS) {
            wchar_t sub[256];
            DWORD idx = 0, len = 256;
            while (RegEnumKeyExW(mp.h, idx, sub, &len, nullptr, nullptr, nullptr, nullptr) ==
                   ERROR_SUCCESS) {
                if (out.size() >= kMapDriveHistoryCap)
                    return; // per-key cap
                std::string unc = decode_mountpoints2(sub);
                if (!unc.empty()) {
                    RegKeyGuard sk;
                    int64_t ts = 0;
                    if (RegOpenKeyExW(mp.h, sub, 0, KEY_READ, &sk.h) == ERROR_SUCCESS)
                        ts = key_last_write_epoch(sk.h);
                    MapDriveHistoryRow r;
                    r.ts = ts;
                    r.entry.direction = "outbound";
                    r.entry.remote_path = unc;
                    r.entry.remote_host = remote_host_of(unc);
                    r.entry.username = profile_user;
                    r.entry.provider = "SMB";
                    out.push_back(std::move(r));
                }
                idx++;
                len = 256;
            }
        }
    }
}

bool is_system_sid(const std::wstring& sid) {
    return sid == L"S-1-5-18" || sid == L"S-1-5-19" || sid == L"S-1-5-20";
}

// Walk every profile in ProfileList; read the outbound artifacts from the live
// HKU\<SID> hive, or load NTUSER.DAT for offline users (RAII-unloaded).
void enum_registry_outbound_history(std::vector<MapDriveHistoryRow>& out) {
    RegKeyGuard pl;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList", 0, KEY_READ,
                      &pl.h) != ERROR_SUCCESS)
        return;

    wchar_t sid[256];
    DWORD idx = 0, len = 256;
    while (RegEnumKeyExW(pl.h, idx, sid, &len, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
        idx++;
        std::wstring sid_str(sid);
        len = 256; // reset the name-length in/out param for the next enum call
        if (is_system_sid(sid_str))
            continue;

        RegKeyGuard prof;
        std::string profile_user;
        std::wstring ntuser;
        if (RegOpenKeyExW(pl.h, sid_str.c_str(), 0, KEY_READ, &prof.h) == ERROR_SUCCESS) {
            std::string img = reg_read_sz(prof.h, L"ProfileImagePath");
            if (!img.empty()) {
                auto slash = img.find_last_of("\\/");
                profile_user = (slash == std::string::npos) ? img : img.substr(slash + 1);
                // ProfileImagePath is REG_EXPAND_SZ and reg_read_sz does NOT expand
                // it; a literal token (e.g. %SystemDrive%\Users\name on some
                // provisioning setups) would make RegLoadKeyW fail and silently drop
                // that profile. Expand it, matching installed_apps::do_list_per_user.
                std::wstring imgw = yuzu::win::to_wide(img);
                wchar_t expanded[1024]{};
                DWORD en = ExpandEnvironmentStringsW(imgw.c_str(), expanded,
                                                     static_cast<DWORD>(std::size(expanded)));
                std::wstring base = (en > 0 && en <= std::size(expanded)) ? std::wstring(expanded)
                                                                          : imgw;
                ntuser = base + L"\\NTUSER.DAT";
            }
        }

        // Prefer the already-loaded hive.
        RegKeyGuard live;
        if (RegOpenKeyExW(HKEY_USERS, sid_str.c_str(), 0, KEY_READ, &live.h) == ERROR_SUCCESS) {
            read_user_outbound_history(live.h, profile_user, out);
        } else if (!ntuser.empty()) {
            std::wstring mount = L"YUZU_TAR_" + sid_str;
            LONG lr = RegLoadKeyW(HKEY_USERS, mount.c_str(), ntuser.c_str());
            if (lr == ERROR_SUCCESS) {
                // unload constructed FIRST so it destructs LAST (after `mounted`
                // closes the root key). Both run on an exceptional unwind too, so
                // the hive is always unloaded — no NTUSER.DAT lock-until-reboot.
                HiveUnloadGuard unload{mount};
                RegKeyGuard mounted;
                if (RegOpenKeyExW(HKEY_USERS, mount.c_str(), 0, KEY_READ, &mounted.h) ==
                    ERROR_SUCCESS)
                    read_user_outbound_history(mounted.h, profile_user, out);
            }
            // ERROR_PRIVILEGE_NOT_HELD / sharing violation -> skip this offline user.
        }
        if (out.size() >= kMapDriveHistoryCap)
            return;
    }
}

} // namespace

std::vector<MapDriveEntry> enumerate_mapdrive() {
    std::vector<MapDriveEntry> out;
    enum_wnet_outbound(out);
    if (out.size() < kMapDriveEntryCap)
        enum_netsession_inbound(out);
    return out;
}

std::vector<MapDriveHistoryRow> enumerate_mapdrive_history() {
    std::vector<MapDriveHistoryRow> rows;
    enum_registry_outbound_history(rows);
    // Inbound history: Security event log 4624 (successful logon), filtered to
    // logon_type=3 (network) by the parser. Query 4624 ONLY — 4634 (logoff) is
    // not parsed, so including it would waste up to half the newest-first /c:5000
    // budget on events we discard, halving the effective backfill depth. Bounded
    // read; constant query (no interpolation). Empty on access denial.
    const std::string cmd =
        system32_path("wevtutil.exe") +
        " qe Security /q:\"*[System[(EventID=4624)]]\" /c:5000 /f:text /rd:true 2>nul";
    auto inbound = parse_win_security_logons(run_command(cmd));
    rows.insert(rows.end(), inbound.begin(), inbound.end());
    return dedup_history(std::move(rows));
}

// ── Linux platform shell ──────────────────────────────────────────────────────
#elif defined(__linux__)

std::vector<MapDriveEntry> enumerate_mapdrive() {
    std::vector<MapDriveEntry> out = parse_proc_mounts(read_file("/proc/mounts"));
    // Inbound: current Samba sessions. Empty if Samba isn't installed / no perms.
    auto inbound = parse_smbstatus(run_command("timeout 10 smbstatus -b 2>/dev/null"));
    out.insert(out.end(), inbound.begin(), inbound.end());
    if (out.size() > kMapDriveEntryCap) {
        static std::atomic<bool> warned{false};
        if (!warned.exchange(true))
            spdlog::warn("TAR mapdrive: live cap {} reached — truncating (repeats suppressed)",
                         kMapDriveEntryCap);
        out.resize(kMapDriveEntryCap);
    }
    return out;
}

std::vector<MapDriveHistoryRow> enumerate_mapdrive_history() {
    std::vector<MapDriveHistoryRow> rows = parse_fstab(read_file("/etc/fstab"));
    // Inbound history: Samba connect events. Prefer the on-disk log; fall back to
    // journald. Best-effort (log verbosity varies) — empty where neither exists.
    // Bounded: read only the last 4 MiB (the recent tail — a busy server's
    // log.smbd is unbounded with `max log size = 0`) and cap the journalctl
    // fallback with a timeout so a hung journald can't stall the init backfill.
    constexpr std::size_t kSambaLogTailBytes = 4u * 1024 * 1024;
    std::string logs = read_file_tail("/var/log/samba/log.smbd", kSambaLogTailBytes);
    if (logs.empty())
        logs = run_command(
            "timeout 15 journalctl -u smbd --no-pager -o short-iso -n 5000 2>/dev/null");
    auto inbound = parse_samba_logs(logs);
    rows.insert(rows.end(), inbound.begin(), inbound.end());
    return dedup_history(std::move(rows));
}

// ── macOS / other: kPlanned ───────────────────────────────────────────────────
#else

std::vector<MapDriveEntry> enumerate_mapdrive() { return {}; }
std::vector<MapDriveHistoryRow> enumerate_mapdrive_history() { return {}; }

#endif

} // namespace yuzu::tar
