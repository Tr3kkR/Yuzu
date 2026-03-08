---
title: "[P1/HIGH] Implement enrollment token validation for agent registration"
labels: security, enhancement, P1
assignees: ""
---

## Summary

Any entity with a valid client certificate signed by the CA can register as an agent with an arbitrary `agent_id`. There is no enrollment token or pre-shared secret to authorize new agent registrations. This means a compromised CA key enables unlimited agent impersonation with no secondary validation.

## Affected Files

- `proto/yuzu/agent/v1/agent.proto` (lines 40-42) — `RegisterRequest` message
- `server/core/src/server.cpp` — `Register()` RPC handler (line ~310)
- `server/core/include/yuzu/server/server.hpp` — Config struct
- `agents/core/src/agent.cpp` — Agent registration call
- `agents/core/src/main.cpp` — CLI flag for token
- `agents/core/include/yuzu/agent/agent.hpp` — Agent Config struct

## Current State

```protobuf
message RegisterRequest {
  AgentInfo info = 1;
  // TODO: add enrollment_token field, validated by server
}
```

## Recommended Implementation

### 1. Proto change

```protobuf
message RegisterRequest {
  AgentInfo info = 1;
  string enrollment_token = 2;
}
```

### 2. Server-side validation

```cpp
// Config
struct Config {
    std::string enrollment_token;  // from --enrollment-token or YUZU_ENROLLMENT_TOKEN
};

// In Register():
if (!cfg_.enrollment_token.empty()) {
    if (request->enrollment_token() != cfg_.enrollment_token) {
        spdlog::warn("Register rejected: invalid enrollment token from {}", context->peer());
        return grpc::Status(grpc::StatusCode::UNAUTHENTICATED, "invalid enrollment token");
    }
}
```

### 3. Agent-side

```cpp
// Config
struct Config {
    std::string enrollment_token;  // from --enrollment-token or YUZU_ENROLLMENT_TOKEN
};

// In register_with_server():
pb::RegisterRequest req;
req.mutable_info()->CopyFrom(build_agent_info());
req.set_enrollment_token(cfg_.enrollment_token);
```

### 4. CLI flags

```cpp
// Agent
app.add_option("--enrollment-token", cfg.enrollment_token,
    "Enrollment token for server authentication");

// Server
app.add_option("--enrollment-token", cfg.enrollment_token,
    "Required enrollment token for agent registration");
```

### Future: Per-agent tokens

For enterprise deployments, support a token store mapping tokens to allowed agent IDs:
```
token-abc123 -> agent-prod-01
token-def456 -> agent-staging-*
```

## Acceptance Criteria

- [ ] `RegisterRequest` proto includes `enrollment_token` field
- [ ] Server validates token when `--enrollment-token` is configured
- [ ] Server rejects registration with invalid/missing token (UNAUTHENTICATED)
- [ ] Server accepts all registrations when no token is configured (backward compat)
- [ ] Agent sends token from `--enrollment-token` flag or `YUZU_ENROLLMENT_TOKEN` env var
- [ ] Token is not logged in plaintext (mask in log output)
- [ ] Unit test covers valid token, invalid token, missing token, and unconfigured scenarios

## References

- CLAUDE.md Auth item #1
- SECURITY_REVIEW.md Section 2
