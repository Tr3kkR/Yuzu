---
title: "[P1/HIGH] Zero private key material after TLS setup"
labels: security, enhancement, P1
assignees: ""
---

## Summary

Private keys are read into `std::string` objects and passed to gRPC. These strings are not zeroed on deallocation — key material persists in freed heap memory and is recoverable from core dumps, memory forensics, or `/proc/[pid]/mem`.

## Affected Files

- `agents/core/src/agent.cpp` (lines 191-193) — client key loading
- `server/core/src/server.cpp` (lines 716-717) — server key loading
- `server/core/src/server.cpp` (lines 582-587) — `read_file_contents()` utility

## Root Cause

```cpp
auto key = detail::read_file_contents(key_path);
// key is std::string — no secure erasure on destruction
// After SSL context is initialized, key material persists in heap
```

## Recommended Fix

### Option A: Explicit cleanse after use (minimal change)

```cpp
#include <openssl/crypto.h>  // for OPENSSL_cleanse

auto key = detail::read_file_contents(key_path);
// ... pass to gRPC SSL options ...
OPENSSL_cleanse(key.data(), key.size());
key.clear();
key.shrink_to_fit();
```

### Option B: Secure string wrapper (robust)

```cpp
struct SecureString {
    std::string data;

    ~SecureString() {
        if (!data.empty()) {
            OPENSSL_cleanse(data.data(), data.size());
        }
    }

    SecureString(const SecureString&) = delete;
    SecureString& operator=(const SecureString&) = delete;
    SecureString(SecureString&& o) noexcept : data(std::move(o.data)) {}
};
```

### Additional hardening

- Disable core dumps for the process: `prctl(PR_SET_DUMPABLE, 0)` on Linux
- Lock key pages in memory: `mlock(key.data(), key.size())` to prevent swap

## Acceptance Criteria

- [ ] Private key material is zeroed immediately after TLS context initialization
- [ ] Both agent and server key paths are covered
- [ ] No key material visible in heap dumps after TLS setup
- [ ] Core dump generation disabled or restricted in production mode

## References

- SECURITY_REVIEW.md Section 2
