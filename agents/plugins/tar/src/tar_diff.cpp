/**
 * tar_diff.cpp -- Diff engine for TAR collectors
 *
 * Implements snapshot-based diff computation for processes, network connections,
 * services, and user sessions. Uses std::unordered_map with composite keys
 * to efficiently detect births, deaths, and state changes.
 *
 * Redaction: command-line strings matching sensitive patterns are replaced
 * with "[REDACTED by TAR]" before being stored in event detail JSON.
 */

#include "tar_collectors.hpp"

#include <algorithm>
#include <cctype>
#include <format>
#include <string>
#include <unordered_map>

namespace yuzu::tar {

namespace {

/// Escape a string for safe embedding in JSON values.
/// Handles backslash, double-quote, and control characters.
std::string json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
        case '"':
            out += "\\\"";
            break;
        case '\\':
            out += "\\\\";
            break;
        case '\n':
            out += "\\n";
            break;
        case '\r':
            out += "\\r";
            break;
        case '\t':
            out += "\\t";
            break;
        default:
            if (static_cast<unsigned char>(c) < 0x20) {
                // Control character -- emit \u00XX
                out += std::format("\\u{:04x}", static_cast<unsigned>(static_cast<unsigned char>(c)));
            } else {
                out += c;
            }
            break;
        }
    }
    return out;
}

/// Case-insensitive substring search.
bool icontains(const std::string& haystack, const std::string& needle) {
    if (needle.empty())
        return true;
    if (needle.size() > haystack.size())
        return false;

    auto to_lower = [](char c) -> char {
        return static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    };

    auto it = std::search(haystack.begin(), haystack.end(), needle.begin(), needle.end(),
                          [&](char a, char b) { return to_lower(a) == to_lower(b); });
    return it != haystack.end();
}

/// Strip leading/trailing '*' from a glob pattern to get the core substring.
std::string strip_stars(const std::string& pattern) {
    std::string result = pattern;
    while (!result.empty() && result.front() == '*')
        result.erase(result.begin());
    while (!result.empty() && result.back() == '*')
        result.pop_back();
    return result;
}

} // namespace

// ── Redaction ────────────────────────────────────────────────────────────────

bool should_redact(const std::string& cmdline, const std::vector<std::string>& patterns) {
    if (cmdline.empty())
        return false;
    for (const auto& pattern : patterns) {
        auto core = strip_stars(pattern);
        if (!core.empty() && icontains(cmdline, core))
            return true;
    }
    return false;
}

std::string redact_cmdline(const std::string& cmdline, const std::vector<std::string>& patterns) {
    if (should_redact(cmdline, patterns))
        return "[REDACTED by TAR]";
    return cmdline;
}

// ── Process diff ─────────────────────────────────────────────────────────────

std::vector<TarEvent> compute_process_diff(
    const std::vector<yuzu::agent::ProcessInfo>& previous,
    const std::vector<yuzu::agent::ProcessInfo>& current,
    int64_t timestamp, int64_t snapshot_id,
    const std::vector<std::string>& redaction_patterns) {

    std::vector<TarEvent> events;

    // Build map of previous processes: PID -> (name, cmdline, user)
    // Using PID as key. If PID is reused with a different name, we treat it
    // as a death of the old process + birth of the new one.
    struct ProcState {
        std::string name;
        std::string cmdline;
        std::string user;
        uint32_t ppid;
    };

    std::unordered_map<uint32_t, ProcState> prev_map;
    prev_map.reserve(previous.size());
    for (const auto& p : previous) {
        prev_map[p.pid] = {p.name, p.cmdline, p.user, p.ppid};
    }

    std::unordered_map<uint32_t, ProcState> curr_map;
    curr_map.reserve(current.size());
    for (const auto& p : current) {
        curr_map[p.pid] = {p.name, p.cmdline, p.user, p.ppid};
    }

    // Detect births and PID reuse (birth + death)
    for (const auto& p : current) {
        auto it = prev_map.find(p.pid);
        if (it == prev_map.end()) {
            // New process -- birth
            auto safe_cmd = redact_cmdline(p.cmdline, redaction_patterns);
            TarEvent ev;
            ev.timestamp = timestamp;
            ev.event_type = "process";
            ev.event_action = "started";
            ev.detail_json = std::format(
                R"({{"pid":{},"ppid":{},"name":"{}","cmdline":"{}","user":"{}"}})",
                p.pid, p.ppid, json_escape(p.name), json_escape(safe_cmd),
                json_escape(p.user));
            ev.snapshot_id = snapshot_id;
            events.push_back(std::move(ev));
        } else if (it->second.name != p.name) {
            // PID reused with different process -- old process died, new one started
            auto old_cmd = redact_cmdline(it->second.cmdline, redaction_patterns);
            TarEvent death;
            // Death gets timestamp-1 so death always sorts before birth for PID reuse
            death.timestamp = timestamp - 1;
            death.event_type = "process";
            death.event_action = "stopped";
            death.detail_json = std::format(
                R"({{"pid":{},"ppid":{},"name":"{}","cmdline":"{}","user":"{}"}})",
                p.pid, it->second.ppid, json_escape(it->second.name),
                json_escape(old_cmd), json_escape(it->second.user));
            death.snapshot_id = snapshot_id;
            events.push_back(std::move(death));

            auto new_cmd = redact_cmdline(p.cmdline, redaction_patterns);
            TarEvent birth;
            birth.timestamp = timestamp;
            birth.event_type = "process";
            birth.event_action = "started";
            birth.detail_json = std::format(
                R"({{"pid":{},"ppid":{},"name":"{}","cmdline":"{}","user":"{}"}})",
                p.pid, p.ppid, json_escape(p.name), json_escape(new_cmd),
                json_escape(p.user));
            birth.snapshot_id = snapshot_id;
            events.push_back(std::move(birth));
        }
        // If same PID + same name -> still running, no event
    }

    // Detect deaths (in previous, not in current)
    for (const auto& p : previous) {
        if (!curr_map.contains(p.pid)) {
            auto safe_cmd = redact_cmdline(p.cmdline, redaction_patterns);
            TarEvent ev;
            ev.timestamp = timestamp;
            ev.event_type = "process";
            ev.event_action = "stopped";
            ev.detail_json = std::format(
                R"({{"pid":{},"ppid":{},"name":"{}","cmdline":"{}","user":"{}"}})",
                p.pid, p.ppid, json_escape(p.name), json_escape(safe_cmd),
                json_escape(p.user));
            ev.snapshot_id = snapshot_id;
            events.push_back(std::move(ev));
        }
    }

    return events;
}

// ── Network diff ─────────────────────────────────────────────────────────────

std::vector<TarEvent> compute_network_diff(
    const std::vector<NetConnection>& previous,
    const std::vector<NetConnection>& current,
    int64_t timestamp, int64_t snapshot_id) {

    std::vector<TarEvent> events;

    // Composite key: proto + local_addr + local_port + remote_addr + remote_port
    auto make_key = [](const NetConnection& c) -> std::string {
        return std::format("{}:{}:{}:{}:{}", c.proto, c.local_addr, c.local_port, c.remote_addr,
                           c.remote_port);
    };

    std::unordered_map<std::string, const NetConnection*> prev_map;
    prev_map.reserve(previous.size());
    for (const auto& c : previous) {
        prev_map[make_key(c)] = &c;
    }

    std::unordered_map<std::string, const NetConnection*> curr_map;
    curr_map.reserve(current.size());
    for (const auto& c : current) {
        curr_map[make_key(c)] = &c;
    }

    // New connections (births)
    for (const auto& c : current) {
        auto key = make_key(c);
        if (!prev_map.contains(key)) {
            TarEvent ev;
            ev.timestamp = timestamp;
            ev.event_type = "network";
            ev.event_action = "connected";
            ev.detail_json = std::format(
                R"({{"proto":"{}","local_addr":"{}","local_port":{},"remote_addr":"{}","remote_port":{},"state":"{}","pid":{},"process_name":"{}"}})",
                json_escape(c.proto), json_escape(c.local_addr), c.local_port,
                json_escape(c.remote_addr), c.remote_port, json_escape(c.state), c.pid,
                json_escape(c.process_name));
            ev.snapshot_id = snapshot_id;
            events.push_back(std::move(ev));
        }
    }

    // Closed connections (deaths)
    for (const auto& c : previous) {
        auto key = make_key(c);
        if (!curr_map.contains(key)) {
            TarEvent ev;
            ev.timestamp = timestamp;
            ev.event_type = "network";
            ev.event_action = "disconnected";
            ev.detail_json = std::format(
                R"({{"proto":"{}","local_addr":"{}","local_port":{},"remote_addr":"{}","remote_port":{},"state":"{}","pid":{},"process_name":"{}"}})",
                json_escape(c.proto), json_escape(c.local_addr), c.local_port,
                json_escape(c.remote_addr), c.remote_port, json_escape(c.state), c.pid,
                json_escape(c.process_name));
            ev.snapshot_id = snapshot_id;
            events.push_back(std::move(ev));
        }
    }

    return events;
}

// ── Service diff ─────────────────────────────────────────────────────────────

std::vector<TarEvent> compute_service_diff(
    const std::vector<ServiceInfo>& previous,
    const std::vector<ServiceInfo>& current,
    int64_t timestamp, int64_t snapshot_id) {

    std::vector<TarEvent> events;

    // Key: service name
    std::unordered_map<std::string, const ServiceInfo*> prev_map;
    prev_map.reserve(previous.size());
    for (const auto& s : previous) {
        prev_map[s.name] = &s;
    }

    std::unordered_map<std::string, const ServiceInfo*> curr_map;
    curr_map.reserve(current.size());
    for (const auto& s : current) {
        curr_map[s.name] = &s;
    }

    // New services or state changes
    for (const auto& s : current) {
        auto it = prev_map.find(s.name);
        if (it == prev_map.end()) {
            // New service -- birth
            TarEvent ev;
            ev.timestamp = timestamp;
            ev.event_type = "service";
            ev.event_action = "started";
            ev.detail_json = std::format(
                R"({{"name":"{}","display_name":"{}","status":"{}","startup_type":"{}"}})",
                json_escape(s.name), json_escape(s.display_name), json_escape(s.status),
                json_escape(s.startup_type));
            ev.snapshot_id = snapshot_id;
            events.push_back(std::move(ev));
        } else {
            // Check for state change (status or startup_type changed)
            const auto* prev = it->second;
            if (prev->status != s.status || prev->startup_type != s.startup_type) {
                TarEvent ev;
                ev.timestamp = timestamp;
                ev.event_type = "service";
                ev.event_action = "state_changed";
                ev.detail_json = std::format(
                    R"({{"name":"{}","display_name":"{}","status":"{}","prev_status":"{}","startup_type":"{}","prev_startup_type":"{}"}})",
                    json_escape(s.name), json_escape(s.display_name), json_escape(s.status),
                    json_escape(prev->status), json_escape(s.startup_type),
                    json_escape(prev->startup_type));
                ev.snapshot_id = snapshot_id;
                events.push_back(std::move(ev));
            }
        }
    }

    // Removed services (deaths)
    for (const auto& s : previous) {
        if (!curr_map.contains(s.name)) {
            TarEvent ev;
            ev.timestamp = timestamp;
            ev.event_type = "service";
            ev.event_action = "stopped";
            ev.detail_json = std::format(
                R"({{"name":"{}","display_name":"{}","status":"{}","startup_type":"{}"}})",
                json_escape(s.name), json_escape(s.display_name), json_escape(s.status),
                json_escape(s.startup_type));
            ev.snapshot_id = snapshot_id;
            events.push_back(std::move(ev));
        }
    }

    return events;
}

// ── User session diff ────────────────────────────────────────────────────────

std::vector<TarEvent> compute_user_diff(
    const std::vector<UserSession>& previous,
    const std::vector<UserSession>& current,
    int64_t timestamp, int64_t snapshot_id) {

    std::vector<TarEvent> events;

    // Composite key: user + session_id
    auto make_key = [](const UserSession& u) -> std::string {
        return u.user + ":" + u.session_id;
    };

    std::unordered_map<std::string, const UserSession*> prev_map;
    prev_map.reserve(previous.size());
    for (const auto& u : previous) {
        prev_map[make_key(u)] = &u;
    }

    std::unordered_map<std::string, const UserSession*> curr_map;
    curr_map.reserve(current.size());
    for (const auto& u : current) {
        curr_map[make_key(u)] = &u;
    }

    // New sessions (logins)
    for (const auto& u : current) {
        auto key = make_key(u);
        if (!prev_map.contains(key)) {
            TarEvent ev;
            ev.timestamp = timestamp;
            ev.event_type = "user";
            ev.event_action = "login";
            ev.detail_json = std::format(
                R"({{"user":"{}","domain":"{}","logon_type":"{}","session_id":"{}"}})",
                json_escape(u.user), json_escape(u.domain), json_escape(u.logon_type),
                json_escape(u.session_id));
            ev.snapshot_id = snapshot_id;
            events.push_back(std::move(ev));
        }
    }

    // Ended sessions (logouts)
    for (const auto& u : previous) {
        auto key = make_key(u);
        if (!curr_map.contains(key)) {
            TarEvent ev;
            ev.timestamp = timestamp;
            ev.event_type = "user";
            ev.event_action = "logout";
            ev.detail_json = std::format(
                R"({{"user":"{}","domain":"{}","logon_type":"{}","session_id":"{}"}})",
                json_escape(u.user), json_escape(u.domain), json_escape(u.logon_type),
                json_escape(u.session_id));
            ev.snapshot_id = snapshot_id;
            events.push_back(std::move(ev));
        }
    }

    return events;
}

} // namespace yuzu::tar
