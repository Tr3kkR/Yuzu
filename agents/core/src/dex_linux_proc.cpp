#include "dex_linux_proc.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <cmath>
#include <cstdlib>
#include <utility>

namespace yuzu::agent::lnx {

namespace {

// Parse one whitespace-delimited token as an unsigned value. nullopt on anything
// malformed (extra chars, sign, overflow). from_chars never throws — a bad /proc
// line must not unwind out of the poll thread (the parse_int_field rationale).
std::optional<std::uint64_t> to_u64(std::string_view tok) {
    std::uint64_t v = 0;
    const char* const end = tok.data() + tok.size();
    const auto [ptr, ec] = std::from_chars(tok.data(), end, v);
    if (ec != std::errc{} || ptr != end)
        return std::nullopt;
    return v;
}

double clamp_pct(double v) { return std::clamp(v, 0.0, 100.0); }

// Invoke fn() for each space/tab-delimited token of `s` (runs collapse — no empty
// tokens). The classic /proc layout: a label then numbers.
template <class Fn>
void for_each_token(std::string_view s, Fn fn) {
    std::size_t i = 0;
    while (i < s.size()) {
        while (i < s.size() && (s[i] == ' ' || s[i] == '\t'))
            ++i;
        const std::size_t start = i;
        while (i < s.size() && s[i] != ' ' && s[i] != '\t')
            ++i;
        if (i > start)
            fn(s.substr(start, i - start));
    }
}

// Invoke fn() for each '\n'-delimited line of `s` (a trailing unterminated line
// is included). CR is left on the line — /proc never emits it, and to_u64 would
// reject a stray '\r' token anyway.
template <class Fn>
void for_each_line(std::string_view s, Fn fn) {
    std::size_t i = 0;
    while (i < s.size()) {
        const std::size_t nl = s.find('\n', i);
        if (nl == std::string_view::npos) {
            fn(s.substr(i));
            return;
        }
        fn(s.substr(i, nl - i));
        i = nl + 1;
    }
}

// The first whitespace-delimited token of `line` ("cpu0 1 2 3" -> "cpu0").
std::string_view first_token(std::string_view line) {
    std::size_t i = 0;
    while (i < line.size() && (line[i] == ' ' || line[i] == '\t'))
        ++i;
    const std::size_t start = i;
    while (i < line.size() && line[i] != ' ' && line[i] != '\t')
        ++i;
    return line.substr(start, i - start);
}

// The kB value of a `Key:` line in /proc/meminfo ("CommitLimit:  9711560 kB").
// nullopt when the key is absent or its value token is not numeric. Exact key
// match (so "CommitLimit" never matches "Committed_AS" and vice versa).
std::optional<std::uint64_t> meminfo_kb(std::string_view meminfo, std::string_view key) {
    std::optional<std::uint64_t> result;
    for_each_line(meminfo, [&](std::string_view line) {
        if (result || line.size() <= key.size())
            return;
        if (line.substr(0, key.size()) != key || line[key.size()] != ':')
            return;
        // First token after the colon is the number; the trailing "kB" fails
        // to_u64 and is ignored.
        bool taken = false;
        for_each_token(line.substr(key.size() + 1), [&](std::string_view tok) {
            if (taken)
                return;
            taken = true;
            result = to_u64(tok); // first token only — nullopt stays nullopt if non-numeric
        });
    });
    return result;
}

bool is_octal(char c) { return c >= '0' && c <= '7'; }

// Decode /proc/mounts octal escapes (\040 space, \011 tab, \012 newline, \134
// backslash). The kernel escapes exactly these in the device and mount-point
// fields, so without this a valid local mount whose path contains a space is
// statvfs'd on the wrong spelling and silently never checked. A backslash NOT
// followed by three octal digits is copied verbatim (defensive — never throws).
std::string decode_octal(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (std::size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '\\' && i + 3 < s.size() && is_octal(s[i + 1]) && is_octal(s[i + 2]) &&
            is_octal(s[i + 3])) {
            out.push_back(static_cast<char>((s[i + 1] - '0') * 64 + (s[i + 2] - '0') * 8 +
                                            (s[i + 3] - '0')));
            i += 3;
        } else {
            out.push_back(s[i]);
        }
    }
    return out;
}

// A mount option flag ("ro") present in a comma-separated options field.
bool has_opt(std::string_view opts, std::string_view flag) {
    std::size_t i = 0;
    while (i < opts.size()) {
        const std::size_t c = opts.find(',', i);
        const std::string_view t = (c == std::string_view::npos) ? opts.substr(i)
                                                                  : opts.substr(i, c - i);
        if (t == flag)
            return true;
        if (c == std::string_view::npos)
            break;
        i = c + 1;
    }
    return false;
}

} // namespace

CpuJiffies parse_proc_stat(std::string_view proc_stat) {
    CpuJiffies out;

    // The aggregate line's first token is exactly "cpu"; per-core lines are
    // "cpu0", "cpu1", … (first token "cpuN", not "cpu").
    std::string_view cpu_line;
    for_each_line(proc_stat, [&](std::string_view line) {
        if (cpu_line.empty() && first_token(line) == "cpu")
            cpu_line = line;
    });
    if (cpu_line.empty())
        return out;

    std::array<std::uint64_t, 8> f{}; // user,nice,system,idle,iowait,irq,softirq,steal
    int n = 0;
    bool malformed = false;
    bool first = true;
    for_each_token(cpu_line, [&](std::string_view tok) {
        if (first) { // skip the "cpu" label
            first = false;
            return;
        }
        if (n >= 8) // ignore guest / guest_nice — already folded into user / nice
            return;
        const auto v = to_u64(tok);
        if (!v) {
            malformed = true;
            return;
        }
        f[static_cast<std::size_t>(n++)] = *v;
    });
    if (malformed || n < 4) // need at least user, nice, system, idle
        return out;

    std::uint64_t total = 0;
    for (int k = 0; k < n; ++k)
        total += f[static_cast<std::size_t>(k)];
    out.total = total;
    out.idle = f[3] + (n > 4 ? f[4] : 0); // idle + iowait
    out.valid = true;
    return out;
}

std::optional<double> cpu_busy_pct(const CpuJiffies& prev, const CpuJiffies& cur) {
    if (!prev.valid || !cur.valid)
        return std::nullopt;
    if (cur.total < prev.total || cur.idle < prev.idle)
        return std::nullopt; // counter regression (reboot/reset) — re-baseline next tick
    const std::uint64_t dt = cur.total - prev.total;
    if (dt == 0)
        return std::nullopt; // no elapsed time
    std::uint64_t di = cur.idle - prev.idle;
    if (di > dt)
        di = dt; // non-busy time cannot exceed total within an interval
    return clamp_pct(100.0 * static_cast<double>(dt - di) / static_cast<double>(dt));
}

std::optional<double> parse_commit_pct(std::string_view proc_meminfo) {
    const auto limit = meminfo_kb(proc_meminfo, "CommitLimit");
    const auto committed = meminfo_kb(proc_meminfo, "Committed_AS");
    if (!limit || *limit == 0 || !committed)
        return std::nullopt;
    return clamp_pct(100.0 * static_cast<double>(*committed) / static_cast<double>(*limit));
}

std::vector<MountPoint> parse_storage_mounts(std::string_view proc_mounts) {
    static constexpr std::array<std::string_view, 7> kLocalFs{"ext2", "ext3",  "ext4", "xfs",
                                                              "btrfs", "f2fs", "zfs"};
    std::vector<MountPoint> out;
    std::vector<std::string> seen_devices;
    for_each_line(proc_mounts, [&](std::string_view line) {
        // /proc/mounts fields: device mountpoint fstype options dump pass
        std::array<std::string_view, 4> f{};
        int n = 0;
        for_each_token(line, [&](std::string_view tok) {
            if (n < 4)
                f[static_cast<std::size_t>(n)] = tok;
            ++n;
        });
        if (n < 4)
            return;
        const std::string_view fstype = f[2], opts = f[3];
        if (std::find(kLocalFs.begin(), kLocalFs.end(), fstype) == kLocalFs.end())
            return; // pseudo / network / squashfs etc. — never a server storage volume
        if (has_opt(opts, "ro"))
            return; // a read-only mount (snap, image) is "full" by design
        // Decode the kernel's octal escapes BEFORE dedup/use: the device is both the
        // dedup key and the source of device_label(); the path is what statvfs reads,
        // so an escaped space must be restored or the mount is silently never checked.
        std::string device = decode_octal(f[0]);
        if (std::find(seen_devices.begin(), seen_devices.end(), device) != seen_devices.end())
            return; // bind mount of an already-seen device
        seen_devices.push_back(device);
        out.push_back(MountPoint{std::move(device), decode_octal(f[1]), std::string(fstype)});
    });
    return out;
}

std::string device_label(std::string_view device) {
    // The mount PATH is never consulted here (it carries user content; see the header).
    // The label is derived from the backing DEVICE, but the safe reduction differs by
    // source kind:
    if (device.starts_with("/dev/")) {
        // Block device: the BASENAME is the stable non-PII identifier
        // ("/dev/sda1" -> "sda1", "/dev/mapper/vg0-root" -> "vg0-root"): infrastructure
        // config, the sibling of the hostname — the same subject class as the
        // drive-name / device-path / SSID subjects elsewhere in the catalogue.
        const auto slash = device.find_last_of('/'); // present — the device starts "/dev/"
        const std::string_view base = device.substr(slash + 1);
        return base.empty() ? "disk" : std::string(base);
    }
    // Non-/dev source — notably a ZFS dataset, whose /proc/mounts source is the dataset
    // PATH ("pool/parent/child") and whose canonical layout is per-user / per-tenant
    // LEAVES ("tank/home/alice", "rpool/USERDATA/alice_a1b2c3"). The basename would be
    // that leaf = user/tenant content — a forbidden edge-privacy egress (Gate-2). Use
    // the FIRST segment (the POOL), which is infrastructure config like a block-device
    // name, never the leaf.
    const auto slash = device.find_first_of('/');
    const std::string_view head =
        (slash == std::string_view::npos) ? device : device.substr(0, slash);
    return head.empty() ? "disk" : std::string(head);
}

bool overcommit_is_always(std::string_view s) {
    // The file holds a single integer with a trailing newline ("1\n"). Take the first
    // whitespace-delimited token (newline IS a delimiter here, unlike for_each_token)
    // and require it to be exactly "1" (mode 1, "always"); "10"/"12" must NOT match.
    const auto is_ws = [](char c) { return c == ' ' || c == '\t' || c == '\n' || c == '\r'; };
    std::size_t i = 0;
    while (i < s.size() && is_ws(s[i]))
        ++i;
    const std::size_t start = i;
    while (i < s.size() && !is_ws(s[i]))
        ++i;
    return s.substr(start, i - start) == "1";
}

bool is_whole_disk(std::string_view name) {
    // Pseudo / aggregate / removable-optical devices and software-RAID/LVM/crypt
    // mappers are never a real physical disk for a latency reading (md/dm/nbd roll
    // their members' I/O up → double-count; loop/ram/zram/sr/fd are not disks).
    for (const std::string_view pfx : {"loop", "ram", "zram", "sr", "fd", "dm-", "md", "nbd"})
        if (name.starts_with(pfx))
            return false;
    // nvme: whole disk is nvmeXnY; a partition is nvmeXnYpZ (has a 'p').
    if (name.starts_with("nvme"))
        return name.find('n') != std::string_view::npos && name.find('p') == std::string_view::npos;
    // mmcblk: whole disk mmcblkN; partition mmcblkNpM (has a 'p').
    if (name.starts_with("mmcblk"))
        return name.find('p') == std::string_view::npos;
    // sd/vd/xvd/hd: a whole disk ends in a LETTER ("sda"); a partition ends in a
    // DIGIT ("sda1").
    for (const std::string_view pfx : {"sd", "vd", "xvd", "hd"})
        if (name.starts_with(pfx))
            return !name.empty() && !(name.back() >= '0' && name.back() <= '9');
    return false; // unknown device kind — exclude, never count an unexpected source
}

DiskIoTotals parse_diskstats(std::string_view proc_diskstats) {
    DiskIoTotals out;
    for_each_line(proc_diskstats, [&](std::string_view line) {
        // Fields: major minor name reads_completed reads_merged sectors_read
        // ms_reading writes_completed writes_merged sectors_written ms_writing …
        std::array<std::string_view, 11> f{};
        int n = 0;
        for_each_token(line, [&](std::string_view tok) {
            if (n < 11)
                f[static_cast<std::size_t>(n)] = tok;
            ++n;
        });
        if (n < 11 || !is_whole_disk(f[2]))
            return;
        const auto reads = to_u64(f[3]), ms_read = to_u64(f[6]);
        const auto writes = to_u64(f[7]), ms_write = to_u64(f[10]);
        if (!reads || !ms_read || !writes || !ms_write)
            return; // a malformed row is skipped, never poisons the aggregate
        out.ios += *reads + *writes;
        out.time_ms += *ms_read + *ms_write;
        out.valid = true; // at least one whole disk parsed
    });
    return out;
}

std::optional<double> disk_await_ms(const DiskIoTotals& prev, const DiskIoTotals& cur) {
    if (!prev.valid || !cur.valid)
        return std::nullopt;
    if (cur.ios < prev.ios || cur.time_ms < prev.time_ms)
        return std::nullopt; // counter regression (reboot / hotplug) — re-baseline
    const std::uint64_t dios = cur.ios - prev.ios;
    if (dios == 0)
        return 0.0; // no I/O this interval — an idle disk is healthy, not slow
    return static_cast<double>(cur.time_ms - prev.time_ms) / static_cast<double>(dios);
}

std::optional<double> parse_proc_uptime(std::string_view proc_uptime) {
    // /proc/uptime: "<uptime_seconds> <idle_seconds>" — take the first token.
    // strtod needs a NUL-terminated buffer and is exception-free (unlike stod); a
    // non-finite/overflow value reads as inf → rejected, never poisons the metric.
    const std::string s(proc_uptime);
    const char* const begin = s.c_str();
    char* end = nullptr;
    const double v = std::strtod(begin, &end);
    // Reject non-finite, negative, AND implausibly huge. The caller casts to int64
    // (boot = now - uptime), so a finite-but-out-of-range value (a corrupt /proc/uptime
    // reading "1e300") would be undefined behaviour on the cast. 1e12 s ≈ 31,000 years
    // — far above any real uptime, far below the int64 range.
    if (end == begin || !std::isfinite(v) || v < 0.0 || v >= 1e12)
        return std::nullopt;
    return v;
}

} // namespace yuzu::agent::lnx
