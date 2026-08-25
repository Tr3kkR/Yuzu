# Resource Ledger — Wave 5 PR5.1 runner convergence (`script_exec`/`content_dist` onto `run_bounded_subprocess`)

This ledger documents the new/modified owned C resource this branch's Windows leg
introduces. Reviewers must verify that every code path (normal fall-through,
early exit, and exception unwind) releases exactly the listed resource.

---

## Resources

### `LPWCH` — `GetEnvironmentStringsW()` parent-environment snapshot
- **Site:** `agents/core/src/subprocess_runner.cpp`, Windows `run_bounded_subprocess`
  (the `spec.inherit_parent_env` branch — script_exec's Windows-parity leg,
  `SubprocessOptions::inherit_parent_env`, A2-002).
- **Allocated by:** `GetEnvironmentStringsW()`.
- **Released by:** `std::unique_ptr<wchar_t, EnvironmentStringsDeleter>` (a
  local, file-scoped deleter struct calling `FreeEnvironmentStringsW`),
  constructed IMMEDIATELY on acquisition, before the parse loop that walks the
  returned block runs.
- **Scope:** local to the `inherit_parent_env` branch; the `unique_ptr` goes
  out of scope (and releases) at the end of that `if` block, whether the loop
  completes normally or an exception (allocation failure in `std::wstring`
  construction/append, or `parent_env.push_back()`) unwinds through it.
- **BR-004 (whole-branch review, fixed):** the original code held the raw
  `LPWCH` in a plain local and called `FreeEnvironmentStringsW` in a
  lexically-paired statement AFTER the parse loop. Lexical pairing is not an
  ownership proof — every operation between acquisition and that free
  (`std::wstring` construction/append, `push_back`) is NOT `noexcept`, so an
  exception thrown anywhere in the loop skipped the free and leaked the
  block; the agent's plugin exception firewall then let the process survive
  to leak it again on the next `inherit_parent_env` call. Fixed by wrapping
  the pointer in the RAII owner above at the point of acquisition.
- **All paths covered:** normal loop completion ✓ · null return from
  `GetEnvironmentStringsW` (BR3-005, whole-branch review round 3: BR-008
  is FIXED, not merely tracked-separately as an earlier version of this
  line said — a null return now fails the spawn closed,
  `result.termination_reason = TerminationReason::spawn_error`, before the
  parse loop or the RAII owner above is ever reached, so there is nothing
  for that owner to release on this path; the `unique_ptr` remains safely
  null-constructed and its destructor is a no-op) ✓ · exception unwinding
  through the parse loop ✓
- **Platform note:** this code path is Windows-only (`#else // _WIN32` block,
  `agents/core/src/subprocess_runner.cpp`); verified by compile only on this
  host (macOS) — no Windows runtime evidence was collected for this fix.
