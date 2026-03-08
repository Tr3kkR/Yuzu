---
title: "[P0/CRITICAL] Replace predictable session IDs with cryptographically secure tokens"
labels: security, bug, P0
assignees: ""
---

## Summary

Session IDs returned by `Register()` are derived from a monotonic clock timestamp and are trivially predictable. An attacker who can observe one session ID can predict future ones, potentially enabling session hijacking.

## Affected Files

- `server/core/src/server.cpp` (lines 330-331)

## Root Cause

```cpp
auto session_id = "session-" + std::to_string(
    std::chrono::steady_clock::now().time_since_epoch().count());
```

Session IDs are sequential nanosecond timestamps. An attacker observing approximate registration time can brute-force the ~2000 candidate values in a ±1ms window.

## Mitigating Factors

The server does validate peer IP match and mTLS identity overlap on `Subscribe()`, which limits exploitation when mTLS is enabled. However, in shared-IP environments (NAT, cloud VPCs) or without mTLS, this is exploitable.

## Recommended Fix

Use `RAND_bytes()` from OpenSSL (already a transitive dependency via gRPC):

```cpp
#include <openssl/rand.h>

static std::string generate_secure_session_id() {
    unsigned char buf[32];
    if (RAND_bytes(buf, sizeof(buf)) != 1) {
        throw std::runtime_error("RAND_bytes failed");
    }
    std::string id;
    id.reserve(64);
    for (auto b : buf) {
        std::format_to(std::back_inserter(id), "{:02x}", b);
    }
    return id;
}
```

## Acceptance Criteria

- [ ] Session IDs use 256 bits of cryptographically secure randomness
- [ ] No dependency on clock values for session ID generation
- [ ] Session ID format is hex-encoded (64 characters)
- [ ] Collision probability is negligible (birthday bound at 2^128)
- [ ] Unit test verifies uniqueness across 10,000 generated IDs

## References

- SECURITY_REVIEW.md Section 2
