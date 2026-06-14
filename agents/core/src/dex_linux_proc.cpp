#include "dex_linux_proc.hpp"

#include <algorithm>
#include <array>
#include <charconv>

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
    std::vector<std::string_view> seen_devices;
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
        const std::string_view device = f[0], path = f[1], fstype = f[2], opts = f[3];
        if (std::find(kLocalFs.begin(), kLocalFs.end(), fstype) == kLocalFs.end())
            return; // pseudo / network / squashfs etc. — never a server storage volume
        if (has_opt(opts, "ro"))
            return; // a read-only mount (snap, image) is "full" by design
        if (std::find(seen_devices.begin(), seen_devices.end(), device) != seen_devices.end())
            return; // bind mount of an already-seen device
        seen_devices.push_back(device);
        out.push_back(MountPoint{std::string(device), std::string(path), std::string(fstype)});
    });
    return out;
}

} // namespace yuzu::agent::lnx
