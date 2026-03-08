---
title: "[P2/MEDIUM] Enable compiler hardening flags for release builds"
labels: enhancement, security, P2
assignees: ""
---

## Summary

The build does not enable standard enterprise hardening flags. These protect against buffer overflows, stack smashing, ROP/JOP attacks, and other memory corruption exploits.

## Affected Files

- `cmake/modules/CompilerFlags.cmake`

## Missing Flags

### Linux/macOS (GCC/Clang)

| Flag | Purpose |
|------|---------|
| `-D_FORTIFY_SOURCE=2` | Compile-time and runtime buffer overflow detection |
| `-fstack-protector-strong` | Stack canary on functions with local arrays/address-taken vars |
| `-fPIE` + `-pie` | Position-independent executable (enables full ASLR) |
| `-Wl,-z,relro,-z,now` | Full RELRO — makes GOT read-only after relocation |
| `-Wformat -Wformat-security` | Warn on insecure format strings |

### Windows (MSVC)

| Flag | Purpose |
|------|---------|
| `/DYNAMICBASE` | ASLR (usually on by default) |
| `/HIGHENTROPYVA` | High-entropy 64-bit ASLR |
| `/NXCOMPAT` | Data Execution Prevention |
| `/guard:cf` | Control Flow Guard |
| `/GS` | Buffer security check (usually on by default) |

## Recommended Implementation

```cmake
# In CompilerFlags.cmake, add to Release/RelWithDebInfo configurations:

if(NOT MSVC)
    add_compile_options(
        -D_FORTIFY_SOURCE=2
        -fstack-protector-strong
        -Wformat
        -Wformat-security
    )
    # PIE for executables
    set(CMAKE_POSITION_INDEPENDENT_CODE ON)
    add_link_options(
        -Wl,-z,relro
        -Wl,-z,now
    )
else()
    add_compile_options(
        /guard:cf
        /GS
    )
    add_link_options(
        /DYNAMICBASE
        /HIGHENTROPYVA
        /NXCOMPAT
        /guard:cf
    )
endif()
```

Note: `-D_FORTIFY_SOURCE=2` requires optimization (`-O1` or higher) to be effective, so guard with a generator expression or apply only to Release/RelWithDebInfo.

## Acceptance Criteria

- [ ] All hardening flags enabled in Release and RelWithDebInfo builds
- [ ] Debug builds optionally exclude `_FORTIFY_SOURCE` (conflicts with ASan)
- [ ] CI builds pass with new flags on all platforms
- [ ] `checksec` or equivalent verifies PIE, RELRO, stack canary, NX on built binaries

## References

- SECURITY_REVIEW.md Section 3
