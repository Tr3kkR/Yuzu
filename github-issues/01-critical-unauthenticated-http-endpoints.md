---
title: "[P0/CRITICAL] Add authentication to all HTTP API endpoints"
labels: security, P0, breaking-change
assignees: ""
---

## Summary

All HTTP endpoints (`/api/agents`, `/api/command`, `/events`, `/api/chargen/*`, `/api/procfetch/*`) are completely unauthenticated. Anyone with network access to the web server (default `0.0.0.0:8080`) can enumerate agents, execute arbitrary commands on any connected agent, and monitor all real-time events.

This is a **remote code execution surface** — the single most critical security gap in the codebase.

## Affected Files

- `server/core/src/server.cpp` (lines 752-900) — all HTTP route handlers
- `server/core/include/yuzu/server/server.hpp` — needs `http_api_key` config field

## Attack Scenario

```bash
# Enumerate all agents (agent IDs, hostnames, OS, arch)
curl http://target:8080/api/agents

# Execute arbitrary plugin commands on ALL agents
curl -X POST http://target:8080/api/command \
  -H "Content-Type: application/json" \
  -d '{"plugin":"chargen","action":"chargen_start","agent_ids":[]}'

# Monitor all agent events in real-time
curl http://target:8080/events
```

## Recommended Fix

### Phase 1: Static API Key (minimum viable)

1. Add config field and environment variable support:
```cpp
// server.hpp
struct Config {
    std::string http_api_key;  // from YUZU_HTTP_API_KEY env var or --api-key flag
};
```

2. Add middleware-style authentication check:
```cpp
auto require_auth = [&cfg](const httplib::Request& req, httplib::Response& res) -> bool {
    if (cfg.http_api_key.empty()) return true;  // No key configured = open (dev mode)
    auto auth = req.get_header_value("Authorization");
    if (!auth.starts_with("Bearer ") || auth.substr(7) != cfg.http_api_key) {
        res.status = 401;
        res.set_content(R"({"error":"unauthorized"})", "application/json");
        return false;
    }
    return true;
};
```

3. Apply to all `/api/*` and `/events` routes. Dashboard (`/`) can remain open but should embed the key via a login prompt.

### Phase 2: Role-Based API Keys (enterprise)

See issue: "Implement admin/read-only RBAC for HTTP and management APIs"

### Phase 3: OIDC/SSO Integration (enterprise)

Support external identity providers for dashboard authentication.

## Acceptance Criteria

- [ ] All `/api/*` endpoints return 401 without valid `Authorization: Bearer <key>` header
- [ ] `/events` SSE stream returns 401 without valid auth
- [ ] API key configurable via `--api-key` flag and `YUZU_HTTP_API_KEY` env var
- [ ] Dashboard prompts for API key or embeds it via login flow
- [ ] Existing gRPC endpoints are not affected
- [ ] Unit tests cover authenticated and unauthenticated access patterns

## References

- CLAUDE.md Auth item #2
- SECURITY_REVIEW.md Section 3
