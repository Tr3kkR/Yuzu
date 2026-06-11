#include "dex_macos_iokit.hpp"

#include <cctype>
#include <string>
#include <string_view>

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

} // namespace yuzu::agent::macos
