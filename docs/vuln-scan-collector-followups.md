# vuln_scan collector — deferred follow-ups

Local tracking note for governance findings deliberately deferred out of the
`feat/vuln-scan-collector` PR (the ADR-0018 collect-thin identity collector).
None block that PR; all are **owner (@lesault) responsibility** for a later stage.
Recorded here rather than filed on the GitHub tracker, per owner decision
(2026-07-02). Source: the `/governance` run on this branch.

## Deferred items

1. **Config-hardening checks retired without replacement** (compliance C4 — control-coverage gap).
   `config_checks.hpp` (UAC / SMBv1 / ASLR / FileVault / firewall / password-policy) was deleted
   with the plugin. Re-author these as question-type Instruction Engine `InstructionDefinition`s
   (the design-doc fallback path). Until then there is **no agent-side config-compliance coverage**;
   any customer evidence packet that cited `security.vuln_scan.config_scan` output has a gap.

2. **Shared pipe-encoding trailing-backslash column forgery** (security-guardian MEDIUM).
   A field value ending in `\` can merge columns in the server splitter
   (`result_parsing.hpp` `find_unescaped_pipe`/`unescape_pipes`). The `|`-escaping itself is sound;
   only trailing `\` is ambiguous. This is a **pre-existing shared-scheme limitation** affecting
   every producer (`ioc`, `sockwho`, `procfetch`, `vuln_scan`). Correct fix = escape-the-escape
   across ALL producers + the server decode together (a cross-cutting change; a one-sided fix would
   regress UNC/`\\` paths in the other plugins). A code comment marks the site in `vuln_identity.hpp`.

3. **No per-command subprocess timeout** (sre / UP-5 — pre-existing, agent-wide).
   A hung `dpkg-query`/`rpm -qa`/`system_profiler`/`brew list` parks one thread-pool worker
   indefinitely (bounded pool, so not a whole-agent stall). `inventory` now runs these on every
   call, widening a pre-existing exposure. Add a bounded timeout/cancellation to the dispatch path.

4. **No output-size / entry cap on `vuln_scan.inventory`** (sre / UP-6).
   A 10k–50k-package host emits an unbounded, ~5×-wider response into the response store; the
   daily-sync path caps at 20000 entries / 3 MiB, the command path has no cap. Add a row/byte cap
   (with a truncation marker so a cap can't silently hide packages) on this action.

5. **Windows registry enumeration robustness** (unhappy-path / UP-7, UP-8 — pre-existing).
   `enumerate_uninstall_key`'s `while (RegEnumKeyExW(...) == ERROR_SUCCESS)` terminates on
   `ERROR_MORE_DATA` (a >255-wchar Uninstall subkey name), dropping all remaining apps in that hive;
   a `REG_EXPAND_SZ` `DisplayName` (type ≠ `REG_SZ`) is silently skipped. Continue past a non-success
   enum result and handle `REG_EXPAND_SZ`.

6. **"Never live-verify signature" has no automated guard** (quality-engineer Q5).
   The invariant (no `rpm -K` / `gpg --verify` / `codesign` on a routine scan) is enforced only by
   review + a code comment. Add a CI grep-lint or a `[vuln]` source-scanning test.

## Minor / noted (not tracked as work)

- `collect_sorted` dedup key omits `epoch` — two rpm records differing only by epoch collapse
  (near-impossible under rpm NVRA semantics; happy-path NICE).
- An app present in both HKLM and HKCU is intentionally kept as two rows (`arch` differs) —
  arguably correct; a one-line inventory-count doc note if it ever surprises an operator.
