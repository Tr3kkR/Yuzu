---
title: "[P2/ENT] Implement admin/read-only RBAC for HTTP and management APIs"
labels: enhancement, enterprise, P2, security
assignees: ""
---

## Summary

All authenticated users have identical permissions. Enterprise deployments need role-based access control to separate operators who can view dashboards from administrators who can execute commands.

## Roles

| Role | Permissions |
|------|------------|
| `readonly` | `GET /api/agents`, `GET /events`, `GET /` (dashboard), `ListAgents`, `GetAgent`, `QueryInventory` |
| `admin` | All readonly permissions + `POST /api/command`, `POST /api/chargen/*`, `POST /api/procfetch/*`, `SendCommand` |

## Recommended Implementation

### API key with embedded role

```cpp
struct ApiKeyEntry {
    std::string key_hash;  // SHA-256 hash of the API key
    std::string role;      // "admin" or "readonly"
    std::string label;     // Human-readable label for audit logs
    std::chrono::system_clock::time_point expires_at;
};
```

### Key management

Store API keys in a JSON file:
```json
{
  "keys": [
    {
      "key_hash": "sha256:abc123...",
      "role": "admin",
      "label": "ops-team",
      "expires": "2027-01-01T00:00:00Z"
    },
    {
      "key_hash": "sha256:def456...",
      "role": "readonly",
      "label": "monitoring",
      "expires": "2027-01-01T00:00:00Z"
    }
  ]
}
```

### Endpoint protection

```cpp
auto require_role = [&](const httplib::Request& req, const std::string& role) -> bool {
    auto key_entry = authenticate(req);
    if (!key_entry) return false;  // 401
    if (key_entry->role != role && key_entry->role != "admin") return false;  // 403
    return true;
};

web_server_->Post("/api/command", [&](auto& req, auto& res) {
    if (!require_role(req, "admin")) {
        res.status = 403;
        res.set_content(R"({"error":"admin role required"})", "application/json");
        return;
    }
    // ... dispatch command ...
});
```

### Key generation CLI

```bash
yuzu-server --generate-api-key --role admin --label "ops-team"
# Output: API key: yk_abc123... (save this, it cannot be retrieved later)
```

## Acceptance Criteria

- [ ] Two roles: `admin` and `readonly`
- [ ] Read-only keys cannot execute commands (403)
- [ ] Admin keys can perform all operations
- [ ] Keys stored as hashes (not plaintext)
- [ ] Key expiration supported
- [ ] CLI tool to generate and manage API keys
- [ ] Audit log includes requester role and key label
- [ ] ManagementService gRPC also enforces roles via metadata

## References

- CLAUDE.md Auth item #3
