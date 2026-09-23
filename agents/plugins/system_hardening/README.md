# system_hardening

<!-- BEGIN GENERATED: plugin-doc-gen header -->
| | |
|---|---|
| **What it does** | Exploit-mitigation and kernel-hardening posture (read-only) |
| **Version** | 1.0.0 |
| **Kind** | Collector · read-only · gathered (crossplatform.system_hardening.posture) |
| **Platforms** | Windows ✅ · macOS ✅ · Linux ✅ |
| **Actions** | `posture` (definition `crossplatform.system_hardening.posture`) |
| **Security** | securable `Security` · operation Read · risk Low · dispatch ReadOnly · approval gate None |
| **Roles** | execute: endpoint-admin, endpoint-operator, security-admin · author: content-author |
<!-- END GENERATED -->

## How it works

One action, `posture` (`system_hardening_plugin.cpp`), reads a fixed allowlist of exploit-mitigation and kernel-hardening keys and writes one row per key: `posture|<os>|<key>|<raw>|<state>`. The action takes no parameters, so no request text ever reaches a path or a registry name. Every leg is rung 1 and never spawns a process. The allowlists are:

- **Linux** (`/proc/sys`, opened read-only with `open`/`read`, one table of key to path, no directory walk): `kernel.randomize_va_space`, `kernel.kptr_restrict`, `kernel.yama.ptrace_scope`, `kernel.dmesg_restrict`, `kernel.unprivileged_bpf_disabled`, `kernel.sysrq`, `fs.protected_hardlinks`, `fs.protected_symlinks`, `fs.protected_fifos`, `fs.protected_regular`, `fs.suid_dumpable`.
- **macOS** (`sysctlbyname`): `kern.securelevel`, `kern.coredump`, `kern.sugid_coredump`, `kern.bootargs`. `kern.nx` is deliberately not read: it is an unknown oid on Apple Silicon.
- **Windows** (registry plus one API): the `MitigationOptions` and `MitigationAuditOptions` values under `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel`, decoded per policy into `mitigation.<policy>` and `mitigation_audit.<policy>` rows (DEP, SEHOP, force-relocate, bottom-up and high-entropy ASLR, CFG and the other fields of the kernel's system-wide mitigation option map, one two-bit nibble per policy), and `GetProcessMitigationPolicy` on the agent's own process for the `self.*` rows (DEP, ASLR, CFG). Only the agent's own process is queried; no other process is enumerated.

Every key reads as exactly one of three things: a **value** (with a state), **`absent`** (the OS definitively reports the key is not there), or **`unreadable`** (the read failed). A failed read never reads as absent: the errno (Linux, macOS) or Win32 error (Windows) decides. A not-found only counts as absence where the surface being read is itself known to be present: on Linux an `ENOENT` is `absent` only when `statfs` confirms `/proc/sys` is a mounted procfs (otherwise the key reads `unreadable`, `<key>:errno_19`), and on Windows a not-found registry VALUE is `absent` but a not-found `Session Manager\kernel` KEY, which exists on every install, reads `unreadable` with `<name>:key_missing`. Absence is not a failure: an `absent` row adds no reason token and does not lower the result status, so a host that lacks an optional key (a default Windows install, which has no `MitigationOptions`, or a Linux kernel without Yama) reports `OK`. Only an `unreadable` row carries a reason token, one per cause. On Linux and macOS the state is `enabled`, `disabled` or `partial`, describing the hardening rather than the raw number (`kernel.sysrq=0` is `enabled`, `kern.coredump=1` is `disabled`); `unmodelled` means a value was read that the table has no interpretation for. Windows uses `on`, `off` and `default` instead, because a system-wide mitigation nibble is a tri-state override (not set, always on, always off) and not a hardening level. An empty macOS `kern.bootargs` is a successful read of an empty string, not a failure.

**Why this plugin exists (stated plainly, not inflated).** Zero documented driver: no capability-map *requirement*, enterprise-parity, SOC 2 or `docs/roadmap.md` entry names this plugin as a need (the capability-map plugin-inventory row is added by this change as a listing, not a driver); the nearest adjacent doc idea (`docs/roadmap.md` Issue 18.2 "Compliance Reporting Templates," CIS-benchmark-shaped) is a reporting/templating layer over rules that would already have to exist elsewhere, not a justification for this collection plugin itself, and is itself only "Proposed." This is pure capability-gap reasoning, not evidenced demand.

```mermaid
flowchart LR
  OP[Operator / workflow] --> SRV[Server<br/>authz: Security.Read]
  SRV -- gRPC mTLS --> HOST[Agent plugin host] --> EX[system_hardening.execute]
  EX --> WIN[Windows leg<br/>Session Manager kernel registry + GetProcessMitigationPolicy]
  EX --> MAC[macOS leg<br/>sysctlbyname allowlist]
  EX --> LIN[Linux leg<br/>/proc/sys allowlist]
  WIN & MAC & LIN --> ROWS[rows + typed result status] --> RS[(ResponseStore)] --> API[REST /api/responses]
```

## OS capability

<!-- BEGIN GENERATED: plugin-doc-gen capability -->
| Action | Windows | macOS | Linux |
|---|---|---|---|
| `posture` | ✅ supported · rung 1 · HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel mitigation registry + GetProcessMitigationPolicy (agent process) | ✅ supported · rung 1 · allowlisted sysctlbyname reads (kern.securelevel/coredump/sugid_coredump/bootargs) | ✅ supported · rung 1 · allowlisted /proc/sys reads (open/read, errno-classified absent/unreadable) |

**Declared limits per leg** (descriptor fallback text, verbatim):

- **`posture` / Windows** — Rig-verified 2026-09-21: MitigationOptions/MitigationAuditOptions are ABSENT on a default Windows 11 install (rows read `absent`, not a failure); a present value decodes as 16 two-bit nibbles (dep, sehop, aslr_bottom_up, aslr_high_entropy and cfg confirmed on hardware); GetProcessMitigationPolicy succeeds for DEP/ASLR/CFG on x64.
<!-- END GENERATED -->

## Privileges and prerequisites

| OS | Runs as | Extra grant needed | Measured | If the read is refused |
|---|---|---|---|---|
| Windows | agent service account (LocalSystem today, #1442) | None documented for this plugin (`docs/agent-privilege-model.md`) | 2026-09-21, bare-metal, the-rig (Windows 11 Pro 10.0.26200), `NT AUTHORITY\SYSTEM` — real capture (`docs/samples/windows.txt`); the mitigation probe summary is in the `system_hardening_win.cpp` banner | `ERROR_FILE_NOT_FOUND`/`ERROR_PATH_NOT_FOUND` on a registry value reports that row `absent` with no token (the default state of a fresh install), as do `ERROR_INVALID_PARAMETER`/`ERROR_NOT_SUPPORTED` from `GetProcessMitigationPolicy` for that `self.*` row; an `ERROR_ACCESS_DENIED` reports it `unreadable` with reason `<name>:access_denied` and the action reports `PERMISSION_DENIED`/`PARTIAL`; any other Win32 error reports `unreadable` with `<name>:win32_<n>`. A not-found on the `Session Manager\kernel` key itself (not a value inside it) reports both registry rows `unreadable` with `<name>:key_missing` and the action reports `CONSTRAINED`/`PARTIAL`: that key exists on every install, so its absence is never a clean answer |
| macOS | agent daemon, root today (LaunchDaemon carries no `UserName` key — `docs/agent-privilege-model.md` TL;DR); this plugin's reads need no elevation beyond that default | None — `sysctlbyname` reads of these keys are unprivileged | 2026-09-21, bare-metal, this Mac (`braga`), unprivileged (euid 501) — real capture (`docs/samples/macos.txt`); no root-privileged run has been captured, so the root identity above is the documented production default, not a measured one | `EPERM` reports the key `unreadable` with reason `<key>:eacces` and the action reports `PERMISSION_DENIED`/`PARTIAL`; an unknown oid (`ENOENT`) reports it `absent` with no token and leaves the result unchanged |
| Linux | agent daemon, default | None — the allowlisted `/proc/sys` files are world-readable by default | container (Docker VM on this Mac), root (`euid 0`) — a real live capture of the built `.so` (`docs/samples/linux.txt`) | `EACCES`/`EPERM` reports the key `unreadable` with reason `<key>:eacces` and the action reports `PERMISSION_DENIED`/`PARTIAL`; any other errno reports `unreadable` with `<key>:errno_<n>`; a missing file (`ENOENT`, for example `kernel.yama.ptrace_scope` with Yama not built in) reports it `absent` with no token and leaves the result unchanged, but only once `statfs("/proc/sys")` confirms a mounted procfs; if `/proc/sys` is not procfs (hidden by `ProcSubset=pid`, masked or unmounted in a container) the `ENOENT` is remapped to `ENODEV` and the key reads `unreadable` with `<key>:errno_19`. As a backstop, if ALL ELEVEN keys read `absent` on a confirmed procfs, one additional `proc_sys:not_visible` token downgrades the result to `CONSTRAINED` (each row still reads `absent`) |

Binaries/subprocesses: none — every leg is an in-process read (`/proc/sys`, `sysctlbyname`, the Windows registry API and `GetProcessMitigationPolicy`); no `sysctl`, `reg` or PowerShell binary is ever run. Network: none.

## Data contract

### Inputs

<!-- BEGIN GENERATED: plugin-doc-gen inputs -->
The action takes no parameters.
<!-- END GENERATED -->

### Outputs

Pipe-delimited rows, one per allowlisted key, in allowlist order, written via `write_output()`. The first field is the fixed literal `posture`, then `<os>`, `<key>`, `<raw>` and `<state>`. `<raw>` is `-` when nothing was read (`absent` or `unreadable`); a raw value that WAS read passes through the shared untrusted-output escaper. Windows rows can outnumber the allowlist: one registry value decodes into one row per policy field, and each trailing QWORD of a longer blob adds one raw-hex `ext_q<n>` row (`default` when zero, otherwise `unmodelled`) rather than being dropped. The action returns 0 for every data-level outcome (an unreadable key is a degraded result and an absent key is not a failure; neither is ever a failed command); only an internal exception returns 1 (any leg), adding a `constrained|<os>|internal_error|-|unreadable` row (the same five fields as every other row) after any rows already written. A value that was read but cannot be interpreted is `unmodelled` (Linux and macOS: non-numeric, empty or out-of-range text; Windows: a nibble with no modelled meaning), while a Windows blob whose structure cannot be decoded at all (empty, odd length, not QWORD-aligned, oversized) is `unreadable` with a reason token.

<!-- BEGIN GENERATED: plugin-doc-gen outputs -->
**`crossplatform.system_hardening.posture` — `row_kind|os|key|raw|state`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `row_kind` | string | `posture` `constrained` | Windows, Linux, macOS | `posture` | Row family: `posture` (one per allowlisted key) or `constrained` (an internal-error row: `os` is the host leg, `key` is `internal_error`, `state` is `unreadable`). |
| `os` | string | `linux` `macos` `windows` | Windows, Linux, macOS | `linux` | The leg that produced the row. |
| `key` | string | - | Windows, Linux, macOS | `kernel.randomize_va_space` | Allowlisted key: a sysctl name (Linux, macOS) or a policy name (Windows: mitigation.<policy> and mitigation_audit.<policy> from the registry, self.<policy> from the agent process, or the value name itself for a failed read; the trailing QWORDs of a longer registry blob appear as ext_q<n> rows). |
| `raw` | string | - | Windows, Linux, macOS | `2` | The raw value read (integer, string, or 0x-prefixed hex on Windows); "-" when nothing was read (absent or unreadable). An empty macOS kern.bootargs is a successful read and an empty column. |
| `state` | string | `enabled` `disabled` `partial` `on` `off` `default` `unmodelled` `absent` `unreadable` | Windows, Linux, macOS | `enabled` | Linux and macOS: enabled/disabled/partial describe the hardening (enabled = protection on, partial = on at a weaker level), not the sysctl value. Windows: on/off/default, because a system-wide mitigation nibble is a tri-state override (not set / always on / always off), not a hardening level. unmodelled = a value was read that this table has no interpretation for. absent = the key does not exist here. unreadable = the read failed. |
<!-- END GENERATED -->

### Result status

| Status | Completeness | Provenance | When |
|---|---|---|---|
| `OK` | `FULL` | — | No key was `unreadable`: every key was either read or `absent`. An absent key adds no reason token, so a host that lacks an optional key (Yama not built into the Linux kernel, `MitigationOptions` never written on a default Windows install) still reports `OK`. |
| `CONSTRAINED` | `PARTIAL` | `<key>:errno_<n>`, `<name>:win32_<n>`, `<name>:key_missing`, `<name>:type_<n>`, `<name>:oversized`, `proc_sys:not_visible` | At least one key was `unreadable` and none was refused; the status reason lists one `<key>:<cause>` token per unreadable key, and the matching row reads `unreadable`. An `absent` key never appears here. Windows decoder failures (`empty_blob`, `odd_length`, `not_qword_aligned`, `oversized`, `no_hex_digits`, `odd_hex_digits`, `bad_hex`) appear as `<name>:<token>`. |
| `CONSTRAINED` | `PARTIAL` | `internal_error` | Any leg: an unexpected exception escaped a leg and was contained in `execute()`; the action returns 1 with the row `constrained\|<os>\|internal_error\|-\|unreadable`. |
| `PERMISSION_DENIED` | `PARTIAL` | `<key>:eacces`, `<name>:access_denied` | Any leg: a read was refused — `EACCES`/`EPERM` on Linux and macOS (token `<key>:eacces`) or `ERROR_ACCESS_DENIED` on Windows (token `<name>:access_denied`). A refusal outranks every other unreadable cause in the same run; the reason still lists every unreadable key's token. |

### Where the data goes

- **Instruction result.** Rows travel over the agent's mTLS gRPC channel as the command response and land in the ResponseStore, queryable at `/api/responses/{id}`. `posture` is also a gathered definition (`crossplatform.system_hardening.posture`, 300s TTL).
- **Not consumed by** daily-sync, TAR, DEX, or metrics.
- **Sensitivity.** Rows carry kernel and mitigation settings only: no username, path, process name or installed-software name. The values are a security-posture baseline of the host (for example ASLR off, ptrace unrestricted, core dumps enabled), which is useful to an attacker choosing an exploit, so the rows warrant the same handling as other `Security` data. `kern.bootargs`, where non-empty, echoes the host's boot arguments verbatim.
- **Siblings:** `vuln_scan` (its configuration checks read two of the same Linux keys, `kernel.randomize_va_space` and `fs.suid_dumpable`, as pass/fail findings; this plugin reports the raw value and state) and `bitlocker` (disk encryption posture).

## Sample output

<!-- BEGIN GENERATED: plugin-doc-gen samples -->
**Windows** — captured: windows Windows 10.0.26200 x86_64 · bare-metal · 2026-09-21 · LocalSystem (elevated) · leg-hash 26c1ee54c2ae

```
== action=posture
posture|windows|mitigation_options|-|absent
posture|windows|mitigation_audit_options|-|absent
posture|windows|self.dep|3|on
posture|windows|self.aslr_bottom_up|5|on
posture|windows|self.aslr_force_relocate|5|off
posture|windows|self.aslr_high_entropy|5|on
posture|windows|self.cfg|0|off
posture|windows|self.cfg_export_suppression|0|off
posture|windows|self.cfg_strict_mode|0|off
[result_status] OK / FULL
```

**macOS** — captured: macos macOS 26.6.2 arm64 · bare-metal · 2026-09-21 · euid 501 · leg-hash 26c1ee54c2ae

```
== action=posture
posture|macos|kern.securelevel|0|disabled
posture|macos|kern.coredump|1|disabled
posture|macos|kern.sugid_coredump|0|enabled
posture|macos|kern.bootargs||enabled
[result_status] OK / FULL
```

**Linux** — captured: linux Debian GNU/Linux 13 (trixie) aarch64 · container · 2026-09-21 · euid 0 · leg-hash 26c1ee54c2ae

```
== action=posture
posture|linux|kernel.randomize_va_space|2|enabled
posture|linux|kernel.kptr_restrict|0|disabled
posture|linux|kernel.yama.ptrace_scope|-|absent
posture|linux|kernel.dmesg_restrict|1|enabled
posture|linux|kernel.unprivileged_bpf_disabled|0|disabled
posture|linux|kernel.sysrq|1|disabled
posture|linux|fs.protected_hardlinks|1|enabled
posture|linux|fs.protected_symlinks|1|enabled
posture|linux|fs.protected_fifos|0|disabled
posture|linux|fs.protected_regular|0|disabled
posture|linux|fs.suid_dumpable|0|enabled
[result_status] OK / FULL
```
<!-- END GENERATED -->

## Caveats and known gaps

1. **No documented business driver.** The priority for this plugin is asserted from a capability-gap reading, not evidenced by any tracked demand (see "How it works"); there is no capability-map requirement, named customer, SOC 2 control or CVE behind it (the capability-map row lists the plugin; it does not drive it).
2. **Two state vocabularies.** Linux and macOS report `enabled`/`disabled`/`partial`; Windows reports `on`/`off`/`default` because a system-wide mitigation nibble is a tri-state override, not a hardening level. Consumers key on the `<os>` column. The three non-value states (`unmodelled`, `absent`, `unreadable`) are the same on every OS.
3. **An absent key does not downgrade the run.** `absent` means the OS definitively reports the key is not there, which is the ordinary state of a host without an optional feature, so it adds no reason token: a host without Yama or without `kernel.unprivileged_bpf_disabled`, or a default Windows install with no `MitigationOptions`, reports `OK`. A consumer that needs to know a key is missing reads the `absent` row, not the status. Only an `unreadable` key (a refused or failed read) moves the status to `CONSTRAINED`/`PARTIAL`, or `PERMISSION_DENIED`/`PARTIAL` when the read was refused. A not-found is only treated as absence where the surface is confirmed present. On Linux the primary check is `statfs("/proc/sys")`: if it is not a mounted procfs (a `ProcSubset=pid` mount, a masked or unmounted `/proc/sys` in a container), every missing key reads `unreadable` with `<key>:errno_19` rather than `absent`. All eleven keys absent on a confirmed procfs is a backstop exception: it adds one `proc_sys:not_visible` token and the status reads `CONSTRAINED`, while each row still reads `absent`. On Windows a missing `MitigationOptions` value is `absent`, but a missing `Session Manager\kernel` key reads `unreadable` (`<name>:key_missing`), because that key exists on every install (compared on the-rig before and after a fresh install, 2026-09-21).
4. **The Windows self rows describe the agent process only.** The `self.*` rows come from `GetProcessMitigationPolicy`, called on the agent's own process, so those rows are the agent's effective DEP/ASLR/CFG policy, not a statement about other processes; the system-wide policy is the registry value (`mitigation.*`). A host where `MitigationOptions` has never been written (a default Windows install, measured on the-rig on 2026-09-21) reads `absent` for that value and still reports `OK`; only the `self.*` rows carry policy values there. Only part of the mitigation layout is confirmed on hardware: `MitigationOptions` was captured for real and five policies (`dep`, `sehop`, `aslr_bottom_up`, `aslr_high_entropy`, `cfg`) were confirmed against it; the other eleven two-bit positions follow the kernel's option order and are unverified. `MitigationAuditOptions` is decoded with the same layout, but no non-zero audit value was ever observed (it is absent on the measured host), so audit rows follow the documented structure and are not confirmed. The decoder reads QWORD 0 of any 8-byte-aligned value up to 256 bytes (only the 24-byte shape was captured) and reports trailing QWORDs raw as `ext_q<n>`, never mapped; of the nibble values only `1` (`on`) was observed, so `2` (`off`) and `3`-`15` (`unmodelled`) are reconstructed, not measured.
5. **Fixed allowlists, no discovery; a container reads the host kernel.** The plugin reads only the keys listed above; it does not walk `/proc/sys` or the registry, and it does not report Linux LSM state (SELinux, AppArmor) or macOS SIP and Gatekeeper posture. The eleven Linux keys are kernel-global, not namespaced, so an agent in a container (including the shipped `deploy/docker/Dockerfile.agent` image) reports the HOST kernel's settings, not anything the container configured. A runtime that masks or does not mount `/proc/sys` makes every key read `unreadable` (`<key>:errno_19`), not `absent` (measured 2026-09-23: a tmpfs mounted over `/proc/sys` in a privileged container gave eleven `unreadable` rows and `CONSTRAINED`/`PARTIAL`). The Linux sample above was captured in a container (Docker VM on this Mac), so it shows that VM's kernel.

## Source and tests

<!-- BEGIN GENERATED: plugin-doc-gen source -->
- Plugin: `agents/plugins/system_hardening/src/system_hardening_legs.hpp` · `agents/plugins/system_hardening/src/system_hardening_linux.cpp` · `agents/plugins/system_hardening/src/system_hardening_macos.cpp` · `agents/plugins/system_hardening/src/system_hardening_parsers.hpp` · `agents/plugins/system_hardening/src/system_hardening_plugin.cpp` · `agents/plugins/system_hardening/src/system_hardening_win.cpp` · `agents/plugins/system_hardening/src/system_hardening_win_parsers.hpp`
- Definitions: `content/definitions/system_hardening.yaml`
- Capability rows: `server/core/src/capability_decls/plugin_action_catalogue_system_hardening.hpp`
- Tests: `tests/unit/test_system_hardening_local_dispatcher.cpp` · `tests/unit/test_system_hardening_parsers.cpp` · `tests/unit/test_system_hardening_win_parsers.cpp`
- Privilege row: `docs/agent-privilege-model.md`
- Changelog: `changelog.d/wave8-pr81b-system_hardening.added.md`
<!-- END GENERATED -->
