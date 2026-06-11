#include "dex_macos_iokit.hpp"

#include <cctype>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::agent::macos {

namespace {

std::string trim(std::string_view s) {
    std::size_t b = 0, e = s.size();
    while (b < e && std::isspace(static_cast<unsigned char>(s[b])))
        ++b;
    while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1])))
        --e;
    return std::string(s.substr(b, e - b));
}

// Value of the first line whose first non-space token is `key` ("Condition:" →
// "Normal"). "" when absent. Tolerates the leading indentation of both
// `diskutil info` and `system_profiler` output.
std::string field(const std::string& text, std::string_view key) {
    std::size_t pos = 0;
    while (pos <= text.size()) {
        const std::size_t eol = text.find('\n', pos);
        const std::string_view line(text.data() + pos,
                                    (eol == std::string::npos ? text.size() : eol) - pos);
        std::size_t s = 0;
        while (s < line.size() && std::isspace(static_cast<unsigned char>(line[s])))
            ++s;
        const std::string_view body = line.substr(s);
        if (body.size() >= key.size() && body.substr(0, key.size()) == key)
            return trim(body.substr(key.size()));
        if (eol == std::string::npos)
            break;
        pos = eol + 1;
    }
    return {};
}

// Leading integer of a value like "92%" / "1" → 92 / 1 (0 on failure).
int int_prefix(const std::string& s) {
    try {
        return std::stoi(s);
    } catch (...) {
        return 0;
    }
}

std::vector<std::string> tokens(std::string_view line) {
    std::vector<std::string> out;
    std::size_t i = 0;
    while (i < line.size()) {
        while (i < line.size() && std::isspace(static_cast<unsigned char>(line[i])))
            ++i;
        const std::size_t start = i;
        while (i < line.size() && !std::isspace(static_cast<unsigned char>(line[i])))
            ++i;
        if (i > start)
            out.emplace_back(line.substr(start, i - start));
    }
    return out;
}

bool is_percent_token(const std::string& t) {
    if (t.size() < 2 || t.back() != '%')
        return false;
    for (std::size_t i = 0; i + 1 < t.size(); ++i)
        if (!std::isdigit(static_cast<unsigned char>(t[i])))
            return false;
    return true;
}

// Last non-empty line of a multi-line string (the `df` data row).
std::string last_line(const std::string& text) {
    std::size_t end = text.size();
    while (end > 0 && (text[end - 1] == '\n' || text[end - 1] == '\r'))
        --end;
    std::size_t start = text.rfind('\n', end == 0 ? 0 : end - 1);
    start = (start == std::string::npos) ? 0 : start + 1;
    return text.substr(start, end - start);
}

} // namespace

std::string parse_smart_status(const std::string& diskutil_output) {
    return field(diskutil_output, "SMART Status:");
}

std::optional<SignalObservation> smart_observation(const std::string& status,
                                                   const std::string& disk) {
    if (status.empty())
        return std::nullopt;
    // "Verified" = healthy; "Not Supported"/"Not Mapped" = no SMART capability,
    // NOT a failure — a missing capability must never read as a failing disk.
    if (status == "Verified" || status.rfind("Not", 0) == 0)
        return std::nullopt;
    SignalObservation o;
    o.obs_type = "disk.smart_failure";
    o.subject = disk.empty() ? "disk0" : disk;
    o.reason = status; // "Failing"
    o.sentence = "Disk SMART status: " + status + " (" + o.subject + ")";
    return o;
}

BatteryHealth parse_battery_health(const std::string& sp_power_output) {
    BatteryHealth h;
    const std::string cond = field(sp_power_output, "Condition:");
    const std::string cap = field(sp_power_output, "Maximum Capacity:");
    const std::string cyc = field(sp_power_output, "Cycle Count:");
    if (cond.empty() && cap.empty())
        return h; // no battery (desktop) — valid stays false
    h.valid = true;
    h.condition = cond;
    h.max_capacity_pct = int_prefix(cap);
    h.cycle_count = int_prefix(cyc);
    return h;
}

std::optional<SignalObservation> battery_observation(const BatteryHealth& h) {
    if (!h.valid)
        return std::nullopt;
    const bool bad_condition = !h.condition.empty() && h.condition != "Normal";
    const bool low_capacity = h.max_capacity_pct > 0 && h.max_capacity_pct < 80;
    if (!bad_condition && !low_capacity)
        return std::nullopt; // healthy battery
    SignalObservation o;
    o.obs_type = "hw.error"; // generic Hardware obs_type (no Windows battery signal)
    o.subject = "battery";
    o.reason = bad_condition ? h.condition
                             : ("capacity " + std::to_string(h.max_capacity_pct) + "%");
    o.metric = static_cast<double>(h.max_capacity_pct);
    o.sentence = "Battery health degraded: " + o.reason +
                 (h.cycle_count > 0 ? " (" + std::to_string(h.cycle_count) + " cycles)" : "");
    return o;
}

DiskUsage parse_disk_usage(const std::string& df_output) {
    DiskUsage u;
    const auto toks = tokens(last_line(df_output));
    // Positional-robust: the first "<digits>%" token is Capacity; the token
    // immediately before it is Available (this holds whether or not `df` emitted
    // the inode columns).
    for (std::size_t i = 1; i < toks.size(); ++i) {
        if (is_percent_token(toks[i])) {
            u.capacity_pct = int_prefix(toks[i]);
            try {
                u.available_kb = std::stoll(toks[i - 1]);
                u.valid = true;
            } catch (...) {
                u.valid = false;
            }
            break;
        }
    }
    return u;
}

std::optional<SignalObservation> disk_observation(const DiskUsage& u, const std::string& volume) {
    if (!u.valid)
        return std::nullopt;
    constexpr long long kFiveGiBKb = 5LL * 1024 * 1024;
    const bool nearly_full = u.capacity_pct >= 90 || u.available_kb < kFiveGiBKb;
    if (!nearly_full)
        return std::nullopt;
    SignalObservation o;
    o.obs_type = "storage.low";
    o.subject = volume.empty() ? "disk" : volume;
    o.reason = std::to_string(u.capacity_pct) + "% full";
    o.metric = static_cast<double>(u.capacity_pct);
    o.sentence = "Disk nearly full: " + o.reason + " (" + std::to_string(u.available_kb / 1024) +
                 " MB free) on " + o.subject;
    return o;
}

std::optional<SignalObservation> thermal_observation(const std::string& pmset_therm_output) {
    const std::string limit = field(pmset_therm_output, "CPU_Speed_Limit");
    // pmset emits "CPU_Speed_Limit \t= 100"; field() returns "= 100" → number after '='.
    // int_prefix (std::stoi) skips the leading space.
    std::string num = limit;
    if (const std::size_t eq = num.find('='); eq != std::string::npos)
        num = num.substr(eq + 1);
    const int speed = int_prefix(num);
    if (limit.empty() || speed <= 0 || speed >= 100)
        return std::nullopt; // no cap recorded, or running at full speed
    SignalObservation o;
    o.obs_type = "hw.cpu_throttled";
    o.subject = "CPU";
    o.reason = "speed limited to " + std::to_string(speed) + "%";
    o.metric = static_cast<double>(speed);
    o.sentence = "CPU thermally throttled to " + std::to_string(speed) + "% of full speed";
    return o;
}

std::optional<SignalObservation> memory_pressure_observation(const std::string& mp_output) {
    // "System-wide memory free percentage: 54%"
    const std::string pct = field(mp_output, "System-wide memory free percentage:");
    if (pct.empty())
        return std::nullopt;
    const int free_pct = int_prefix(pct);
    if (free_pct <= 0 || free_pct >= 10)
        return std::nullopt; // healthy (or unparsed) — only warn under real pressure
    SignalObservation o;
    o.obs_type = "memory.exhausted"; // warning tier; jetsam .ips is the kill tier
    o.subject = "system";
    o.reason = "low_memory";
    o.metric = static_cast<double>(free_pct);
    o.sentence = "System memory pressure — only " + std::to_string(free_pct) + "% free";
    return o;
}

} // namespace yuzu::agent::macos
