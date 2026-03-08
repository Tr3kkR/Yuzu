---
title: "[P2/MEDIUM] Default web server bind address to 127.0.0.1"
labels: security, enhancement, P2
assignees: ""
---

## Summary

The HTTP dashboard defaults to listening on `0.0.0.0:8080`, exposing the unauthenticated web UI and API to the entire network. Combined with the lack of HTTP authentication, this makes the command execution surface accessible to any host on the network.

## Affected Files

- `server/core/include/yuzu/server/server.hpp` (lines 13-14)
- `server/core/src/main.cpp` — CLI default value

## Current Default

```cpp
std::string web_address{"0.0.0.0"};  // Binds to ALL interfaces
int         web_port{8080};
```

## Recommended Fix

Change default to localhost:

```cpp
std::string web_address{"127.0.0.1"};  // Localhost only by default
int         web_port{8080};
```

Users who need network access can explicitly set `--web-address 0.0.0.0`. This follows the principle of least privilege — network binding should be opt-in, not opt-out.

## Acceptance Criteria

- [ ] Default web address is `127.0.0.1`
- [ ] `--web-address 0.0.0.0` explicitly enables network binding
- [ ] Startup log clearly shows which address the web server is bound to
- [ ] Documentation updated to reflect the change

## References

- SECURITY_REVIEW.md Section 3
