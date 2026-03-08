---
title: "[P1/HIGH] Replace mt19937 UUID generation with cryptographically secure PRNG"
labels: security, bug, P1
assignees: ""
---

## Summary

Agent UUID generation in `identity_store.cpp` uses `std::mt19937_64` (Mersenne Twister), a non-cryptographic PRNG. An attacker who observes an agent UUID (e.g., via the unauthenticated `/api/agents` endpoint) could theoretically recover the PRNG state and predict UUIDs generated on the same machine.

## Affected Files

- `agents/core/src/identity_store.cpp` (lines 14-39)

## Root Cause

```cpp
std::string generate_uuid_v4() {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dist;

    uint64_t hi = dist(gen);
    uint64_t lo = dist(gen);
    // ... UUID formatting ...
}
```

Mersenne Twister is deterministic — its full state can be recovered from 624 observed 32-bit outputs. While the function creates a new generator per call (seeded from `random_device`), on some platforms `random_device` itself may not be cryptographically secure.

## Recommended Fix

Use OpenSSL's `RAND_bytes()` (already a transitive dependency via gRPC):

```cpp
#include <openssl/rand.h>

std::string generate_uuid_v4() {
    unsigned char buf[16];
    if (RAND_bytes(buf, sizeof(buf)) != 1) {
        // Fallback or throw
        throw std::runtime_error("RAND_bytes failed — CSPRNG unavailable");
    }

    // Set UUID version 4 bits
    buf[6] = (buf[6] & 0x0f) | 0x40;  // version 4
    buf[8] = (buf[8] & 0x3f) | 0x80;  // variant 1

    return std::format(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        buf[0], buf[1], buf[2], buf[3],
        buf[4], buf[5],
        buf[6], buf[7],
        buf[8], buf[9],
        buf[10], buf[11], buf[12], buf[13], buf[14], buf[15]);
}
```

## Acceptance Criteria

- [ ] UUID generation uses `RAND_bytes()` or equivalent CSPRNG
- [ ] Generated UUIDs are valid UUID v4 format
- [ ] No dependency on `std::mt19937` or `std::mt19937_64` for security-sensitive values
- [ ] Unit test verifies UUID format and uniqueness

## References

- SECURITY_REVIEW.md Section 2
