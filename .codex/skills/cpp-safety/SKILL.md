---
name: cpp-safety
description: Review Yuzu C++ source changes for RAII ownership, borrowed lifetimes, C ABI contexts, casts, process/syscall boundaries, callbacks, threads, and proportionate sanitizer coverage. Use for every governance review that changes C++ files, paired with cpp-expert.
---

# C++ Safety

Pair with `cpp-expert`. Load `docs/cpp-conventions.md` and inspect existing owner types and shutdown patterns in the owning module.

## Review

- Require an ownership note only when the range adds an owning resource boundary or changes acquisition, transfer, release, callback, or thread lifetime. Name the owner, acquire/transfer/release points, and failure cleanup.
- Prefer an existing RAII owner. Otherwise use the smallest fitting mechanism: value ownership, `std::unique_ptr` with a deleter, a move-only wrapper, or a local scope guard.
- Treat manual cleanup as blocking when a concrete return, exception, transfer, retry, or concurrency path can leak or double-release. Its mere presence in untouched legacy code is not a finding.
- Prove borrowed `std::string_view`, `std::span`, raw pointers, C callback contexts, and returned C strings cannot outlive their owners.
- Prove threads and callbacks have explicit stop, join, unregister, and destruction ordering. Review shared-state synchronization and casts at ABI/syscall boundaries.
- Prefer argv-style process execution. Require validation and a documented constraint when a shell is genuinely necessary.
- Ask for the narrowest useful ASan/UBSan, TSan, or platform test only when the changed risk warrants it; do not demand every sanitizer mechanically.

## Output

Return only evidence-backed `BLOCKING` or `SHOULD` findings with `file:line`, consequence, and the smallest project-native fix. End with `Ownership note: complete`, `incomplete`, or `not required`, then `PASS` or `BLOCKED`.
