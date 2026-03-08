---
title: "[P1/HIGH] Replace hand-rolled JSON parser with nlohmann/json"
labels: security, bug, P1
assignees: ""
---

## Summary

The server uses hand-rolled `extract_json_string()` and `extract_json_string_array()` functions for parsing HTTP request bodies. These functions use naive string searching that fails on escaped quotes, nested objects, whitespace variations, and unicode escapes. `nlohmann-json` is **already declared as a dependency in `vcpkg.json`** but is not used in the server code.

## Affected Files

- `server/core/src/server.cpp` (lines 931-966) — `extract_json_string()`, `extract_json_string_array()`
- `server/core/src/server.cpp` (lines 805-860) — `/api/command` endpoint
- `server/core/CMakeLists.txt` — needs `nlohmann_json::nlohmann_json` link

## Known Parsing Failures

1. **Escaped quotes**: `{"plugin": "test\"other"}` — extracts `test` instead of `test"other`
2. **Whitespace**: `{"plugin" : "test"}` — fails due to exact `":"` pattern matching
3. **Nested keys**: `{"nested":{"plugin":"inner"}, "plugin":"outer"}` — may extract wrong value
4. **Unicode**: `{"plugin": "\u0074est"}` — treats as literal string
5. **Type confusion**: `{"plugin": 123}` — silently extracts `123` as string

## Recommended Fix

```cpp
#include <nlohmann/json.hpp>

web_server_->Post("/api/command",
    [this](const httplib::Request& req, httplib::Response& res) {
        nlohmann::json body;
        try {
            body = nlohmann::json::parse(req.body);
        } catch (const nlohmann::json::parse_error&) {
            res.status = 400;
            res.set_content(R"({"error":"invalid JSON"})", "application/json");
            return;
        }

        if (!body.contains("plugin") || !body["plugin"].is_string() ||
            !body.contains("action") || !body["action"].is_string()) {
            res.status = 400;
            res.set_content(R"({"error":"plugin and action must be strings"})", "application/json");
            return;
        }

        auto plugin = body["plugin"].get<std::string>();
        auto action = body["action"].get<std::string>();

        std::vector<std::string> agent_ids;
        if (body.contains("agent_ids") && body["agent_ids"].is_array()) {
            agent_ids = body["agent_ids"].get<std::vector<std::string>>();
        }

        // ... rest of handler ...
    });
```

Add to `server/core/CMakeLists.txt`:
```cmake
find_package(nlohmann_json CONFIG REQUIRED)
target_link_libraries(yuzu-server PRIVATE nlohmann_json::nlohmann_json)
```

Delete `extract_json_string()` and `extract_json_string_array()` entirely.

## Acceptance Criteria

- [ ] All JSON parsing uses nlohmann/json
- [ ] `extract_json_string()` and `extract_json_string_array()` are removed
- [ ] Invalid JSON returns 400 with error message
- [ ] Type mismatches (number where string expected) return 400
- [ ] `to_json()` also uses nlohmann/json (see related issue)
- [ ] CMakeLists.txt links nlohmann_json target
- [ ] Unit tests with malformed JSON, escaped characters, nested objects

## References

- SECURITY_REVIEW.md Section 3
- Related: JSON injection in to_json() issue
