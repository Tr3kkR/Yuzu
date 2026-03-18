#pragma once

#include <nlohmann/json.hpp>

#include <chrono>
#include <cstdint>
#include <string>

namespace yuzu::server {

enum class Severity : int { kDebug = 0, kInfo = 1, kWarn = 2, kError = 3, kCritical = 4 };

inline std::string severity_to_string(Severity s) {
    switch (s) {
    case Severity::kDebug:
        return "debug";
    case Severity::kInfo:
        return "info";
    case Severity::kWarn:
        return "warn";
    case Severity::kError:
        return "error";
    case Severity::kCritical:
        return "critical";
    }
    return "info";
}

inline Severity severity_from_string(const std::string& s) {
    if (s == "debug")
        return Severity::kDebug;
    if (s == "warn")
        return Severity::kWarn;
    if (s == "error")
        return Severity::kError;
    if (s == "critical")
        return Severity::kCritical;
    return Severity::kInfo;
}

struct AnalyticsEvent {
    // Identity & routing
    std::string tenant_id{"default"};
    std::string agent_id;
    std::string session_id;
    std::string event_type; // dotted: "command.completed"

    // Timing (milliseconds since epoch)
    int64_t event_time{0};
    int64_t ingest_time{0}; // set by emit()

    // Context
    std::string plugin;
    std::string capability;     // action within plugin
    std::string correlation_id; // command_id, execution_id, etc.
    Severity severity{Severity::kInfo};

    // Source
    std::string source{"server"};
    std::string hostname;
    std::string os;
    std::string arch;
    std::string agent_version;

    // Principal (operator-initiated events)
    std::string principal;
    std::string principal_role;

    // Payload
    nlohmann::json attributes = nlohmann::json::object();
    nlohmann::json payload = nlohmann::json::object();

    int schema_version{1};
};

inline void to_json(nlohmann::json& j, const AnalyticsEvent& e) {
    j = nlohmann::json{{"tenant_id", e.tenant_id},
                       {"agent_id", e.agent_id},
                       {"session_id", e.session_id},
                       {"event_type", e.event_type},
                       {"event_time", e.event_time},
                       {"ingest_time", e.ingest_time},
                       {"plugin", e.plugin},
                       {"capability", e.capability},
                       {"correlation_id", e.correlation_id},
                       {"severity", severity_to_string(e.severity)},
                       {"source", e.source},
                       {"hostname", e.hostname},
                       {"os", e.os},
                       {"arch", e.arch},
                       {"agent_version", e.agent_version},
                       {"principal", e.principal},
                       {"principal_role", e.principal_role},
                       {"attributes", e.attributes},
                       {"payload", e.payload},
                       {"schema_version", e.schema_version}};
}

inline void from_json(const nlohmann::json& j, AnalyticsEvent& e) {
    e.tenant_id = j.value("tenant_id", "default");
    e.agent_id = j.value("agent_id", "");
    e.session_id = j.value("session_id", "");
    e.event_type = j.value("event_type", "");
    e.event_time = j.value("event_time", int64_t{0});
    e.ingest_time = j.value("ingest_time", int64_t{0});
    e.plugin = j.value("plugin", "");
    e.capability = j.value("capability", "");
    e.correlation_id = j.value("correlation_id", "");
    e.severity = severity_from_string(j.value("severity", "info"));
    e.source = j.value("source", "server");
    e.hostname = j.value("hostname", "");
    e.os = j.value("os", "");
    e.arch = j.value("arch", "");
    e.agent_version = j.value("agent_version", "");
    e.principal = j.value("principal", "");
    e.principal_role = j.value("principal_role", "");
    e.schema_version = j.value("schema_version", 1);

    if (j.contains("attributes") && j["attributes"].is_object()) {
        e.attributes = j["attributes"];
    }
    if (j.contains("payload") && j["payload"].is_object()) {
        e.payload = j["payload"];
    }
}

/// Convenience: current time in milliseconds since epoch.
inline int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

} // namespace yuzu::server
