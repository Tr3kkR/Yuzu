---
title: "[P0/CRITICAL] Fix JSON injection in AgentRegistry::to_json()"
labels: security, bug, P0
assignees: ""
---

## Summary

`AgentRegistry::to_json()` concatenates agent metadata directly into JSON strings without escaping. A compromised agent registering with a hostname containing `"`, `\`, or control characters produces malformed/injectable JSON consumed by the dashboard JavaScript.

## Affected Files

- `server/core/src/server.cpp` (lines 209-225) — `to_json()` method

## Root Cause

```cpp
json += "{\"agent_id\":\"" + s->agent_id +
        "\",\"hostname\":\"" + s->hostname +
        "\",\"os\":\"" + s->os +
        "\",\"arch\":\"" + s->arch +
        "\",\"agent_version\":\"" + s->agent_version + "\"}";
```

No escaping of special JSON characters. A hostname like `prod-01","admin":true,"x":"` would inject arbitrary JSON keys.

## Recommended Fix

Replace hand-rolled JSON construction with `nlohmann/json`, which is **already declared as a dependency in `vcpkg.json`** but not used in the server:

```cpp
#include <nlohmann/json.hpp>

std::string to_json() const {
    std::lock_guard lock(mu_);
    nlohmann::json arr = nlohmann::json::array();
    for (const auto& [id, s] : agents_) {
        arr.push_back({
            {"agent_id", s->agent_id},
            {"hostname", s->hostname},
            {"os", s->os},
            {"arch", s->arch},
            {"agent_version", s->agent_version}
        });
    }
    return arr.dump();
}
```

This also fixes the hand-rolled JSON parser (see related issue).

## Acceptance Criteria

- [ ] `to_json()` uses nlohmann/json for safe serialization
- [ ] Agent metadata containing special characters (`"`, `\`, newlines, null bytes) is correctly escaped
- [ ] Dashboard correctly displays agents with unusual hostnames
- [ ] Unit test with hostile hostname values

## References

- SECURITY_REVIEW.md Section 3
- Related: Hand-rolled JSON parser issue
