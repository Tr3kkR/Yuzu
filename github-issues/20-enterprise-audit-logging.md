---
title: "[P2/ENT] Implement durable audit logging for commands and access"
labels: enhancement, enterprise, P2, compliance
assignees: ""
---

## Summary

Commands dispatched to agents are not logged in a durable, tamper-evident audit trail. Enterprise compliance (SOC2, ISO 27001, FedRAMP) requires audit logs of all administrative actions.

## Requirements

### Audit events to log

| Event | Data | Trigger |
|-------|------|---------|
| Agent registered | agent_id, hostname, IP, cert CN | `Register()` RPC |
| Agent disconnected | agent_id, reason, duration | Stream close |
| Command dispatched | command_id, plugin, action, target agents, requester | `/api/command` |
| Command completed | command_id, status, exit_code, duration | `CommandResponse` |
| Auth failure | IP, reason, endpoint | Failed auth check |
| Config change | parameter, old_value, new_value | SIGHUP reload |

### Audit log properties

- **Append-only**: Write to separate file, not mixed with application logs
- **Structured**: JSON format for ingestion by SIEM tools
- **Tamper-evident**: Include HMAC or hash chain (stretch goal)
- **Rotatable**: Support log rotation with configurable retention

### Example audit entry

```json
{
  "timestamp": "2026-03-08T10:00:00.123Z",
  "event": "command_dispatched",
  "command_id": "cmd-abc123",
  "plugin": "procfetch",
  "action": "fetch",
  "target_agents": ["agent-001", "agent-002"],
  "requester_ip": "10.0.1.50",
  "requester_role": "admin"
}
```

## Recommended Implementation

```cpp
// Separate spdlog logger for audit trail
auto audit_logger = spdlog::basic_logger_mt("audit", "/var/log/yuzu/audit.log");
audit_logger->set_pattern("%v");  // Raw JSON, no spdlog prefix

void audit_log(const nlohmann::json& event) {
    event["timestamp"] = current_iso8601();
    audit_logger->info(event.dump());
    audit_logger->flush();  // Ensure durability
}
```

## Acceptance Criteria

- [ ] All command dispatches logged to audit file
- [ ] All authentication events (success + failure) logged
- [ ] Agent registration/disconnection logged
- [ ] Audit log is separate from application log
- [ ] JSON format compatible with common SIEM tools
- [ ] `--audit-log` flag configures audit log path
- [ ] Log rotation supported via external tool (logrotate) or built-in
