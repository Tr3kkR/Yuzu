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

---

## Known limitations

### `no_window=true` makes `soft_terminate_grace` ineffective on Windows (BR-006)
- **Sites:** `content_dist_exec_parsers.hpp::build_execution_options` (30s
  grace) and `script_exec_plugin.cpp`'s Windows leg (10s grace), the only two
  callers that set both `no_window=true` and a nonzero
  `soft_terminate_grace`.
- **Cause:** `CREATE_NO_WINDOW` gives the child no console at all (not merely
  a hidden window) — Microsoft's own documented contract for
  `GenerateConsoleCtrlEvent` requires the target process group to share a
  console with the caller, which a `no_window=true` child never has. Every
  deadline/cancel against these two call sites therefore skips CTRL_BREAK
  delivery entirely and goes straight to `TerminateJobObject`, silently
  discarding the configured grace.
- **Status:** confirmed by the documented Win32 API contract (adversarial
  review, HIGH); not runtime-verified — no Windows host available to this
  branch's authoring session. No in-scope fix: a soft-unwind channel that
  works against a console-less child is a separate, larger design (a
  dedicated IPC/event mechanism), not an extension of CTRL_BREAK delivery.
  Documented at `SubprocessOptions::no_window`'s doc comment
  (`subprocess_runner.hpp`) and both call sites above.
