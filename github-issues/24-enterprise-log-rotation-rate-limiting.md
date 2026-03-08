---
title: "[P2/ENT] Add log rotation, rate limiting, and session timeout enforcement"
labels: enhancement, enterprise, P2
assignees: ""
---

## Summary

Three related operational gaps that need addressing for enterprise deployment:

1. **No log rotation** — File logger uses `basic_file_sink` with no size limits. Can exhaust disk.
2. **No rate limiting** — Unlimited agent registrations and command dispatch. DoS vector.
3. **Session timeout not enforced** — `session_timeout` exists in Config but is never checked.

## 1. Log Rotation

### Current (`server.cpp:601-621`)
```cpp
file_logger_ = spdlog::basic_logger_mt("server_file", log_path.string());
```

### Fix
```cpp
// Rotate at 50MB, keep 5 files
file_logger_ = spdlog::rotating_logger_mt("server_file", log_path.string(),
    50 * 1024 * 1024, 5);
```

Or use `spdlog::daily_logger_mt()` for daily rotation.

Add CLI flags:
- `--log-max-size` (default: 50MB)
- `--log-max-files` (default: 5)

## 2. Rate Limiting

### Agent registration
```cpp
// Limit to 10 registrations per IP per minute
struct RateLimiter {
    std::unordered_map<std::string, std::vector<time_point>> requests;
    bool allow(const std::string& key, int max_requests, std::chrono::seconds window);
};
```

### Command dispatch (HTTP)
```cpp
// Limit to 100 commands per minute per API key
web_server_->Post("/api/command", [&](auto& req, auto& res) {
    if (!rate_limiter.allow(api_key, 100, 60s)) {
        res.status = 429;
        res.set_content(R"({"error":"rate limit exceeded"})", "application/json");
        return;
    }
    // ...
});
```

### Max agents
`cfg_.max_agents` (default 10,000) exists but needs enforcement in `Register()`.

## 3. Session Timeout

### Current
`cfg_.session_timeout` (default 90s) is declared but never used for active session cleanup.

### Fix
Add a periodic cleanup thread that disconnects agents that haven't sent a heartbeat within `session_timeout`:

```cpp
void AgentRegistry::prune_stale_sessions() {
    auto now = std::chrono::steady_clock::now();
    std::lock_guard lock(mu_);
    for (auto it = agents_.begin(); it != agents_.end();) {
        if (now - it->second->last_heartbeat > cfg_.session_timeout) {
            spdlog::warn("Agent {} timed out (no heartbeat for {}s)",
                it->first, cfg_.session_timeout.count());
            it->second->context->TryCancel();
            it = agents_.erase(it);
        } else {
            ++it;
        }
    }
}
```

## Acceptance Criteria

- [ ] Log files rotate at configurable size/count
- [ ] Rate limiting on agent registration (per-IP)
- [ ] Rate limiting on command dispatch (per-API-key)
- [ ] `max_agents` enforced in `Register()` with RESOURCE_EXHAUSTED status
- [ ] Stale sessions cleaned up based on `session_timeout`
- [ ] HTTP 429 responses for rate-limited requests
