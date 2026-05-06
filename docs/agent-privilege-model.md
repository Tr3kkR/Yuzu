# Yuzu Agent Privilege Model

**Status:** active reference doc
**Owners:** `security-guardian`, `cross-platform`, `plugin-developer`
**Implementation:** `scripts/install-agent-user.sh` (Linux/macOS), `scripts/install-agent-user.ps1` (Windows)
**First introduced:** 2026-05-06

---

## TL;DR

The Yuzu agent runs under a dedicated unprivileged account (`_yuzu` on macOS, `yuzu` on Linux, `YuzuAgent` or virtual `NT SERVICE\YuzuAgent` on Windows). Plugins that need privileged operations shell out via narrow `sudo NOPASSWD` entries (Linux/macOS) or rely on the service account's pre-granted LSA privileges (Windows). The agent's own process **never runs as root or LocalSystem**.

If the doc and an install script disagree, **the doc wins** — fix the script, then re-run.

---

## Why this model

Three options were considered:

1. **Run agent as root / LocalSystem.** Simple, works for every plugin. Disqualified: a single bug in any plugin or in the gRPC stack becomes a full system compromise. The audit surface is the entire kernel.

2. **Run agent unprivileged, escalate per-call via sudo / WTSQueryUserToken.** This is the pattern shipped here. The audit surface is **the explicit list of commands in `/etc/sudoers.d/yuzu-agent` plus the LSA privilege grants on Windows** — finite and reviewable.

3. **Run a privileged broker beside an unprivileged worker.** Cleanest from a compartmentalization standpoint but doubles the operational surface (two processes, two sets of metrics, IPC contract between them). Reserved for a future hardening pass; the per-call model gets us 95% of the value at 20% of the cost.

The chosen model also lets `script_exec.exec` / `script_exec.bash` / `script_exec.powershell` run **without** elevated privileges by default — the agent has no path to root for arbitrary scripts. To run a privileged script, an operator authors and approves a specific instruction whose YAML wraps the exact command, and the sudoers/LSA grants are extended for that one binary.

---

## Per-platform account specifications

### macOS

| Attribute | Value |
|---|---|
| Account name | `_yuzu` (leading underscore is the Apple convention for system daemons; matches `_postgres`, `_www`, `_unbound`) |
| UID / GID | First free integer ≥ 200 (system range), assigned by the install script via `dscl . -list /Users UniqueID` |
| Shell | `/usr/bin/false` (no interactive login) |
| Home | `/var/empty` (no profile) |
| Hidden from login window | yes (`IsHidden 1`) |
| Primary group | `_yuzu` (same name + GID) |
| Group memberships | none (macOS doesn't have systemd-journal / adm equivalents we need) |

### Linux

| Attribute | Value |
|---|---|
| Account name | `yuzu` |
| UID / GID | `useradd --system` picks from the distro's system range (typically 100–999) |
| Shell | `/usr/sbin/nologin` |
| Home | `/var/lib/yuzu-agent` (the state directory; not auto-created — install script creates it explicitly) |
| Group memberships | `systemd-journal` (read journal entries), `adm` (read `/var/log/*` files where applicable) |

### Windows

| Attribute | Value (production) | Value (dev) |
|---|---|---|
| Account | virtual service account `NT SERVICE\YuzuAgent` | local user `YuzuAgent` |
| Created by | `sc.exe create yuzu-agent obj= "NT SERVICE\..." ...` at MSI install time | `New-LocalUser` from `install-agent-user.ps1` |
| Password | managed by SCM (no plaintext password exists) | random 24-char, DPAPI-stashed at `C:\ProgramData\Yuzu\agent-credential.dpapi` (SYSTEM + Administrators only) |
| Interactive logon | denied implicitly (virtual service account can't log on) | denied via `SeDenyInteractiveLogonRight` + `SeDenyRemoteInteractiveLogonRight` (set by install script) |
| Group memberships | `Event Log Readers`, `Performance Monitor Users`, `Performance Log Users` |

The production virtual-service-account path is preferred wherever it can be used. The local-user path exists for dev environments where the service hasn't been registered yet (typically during `/test` runs that exercise the agent binary directly).

---

## Privilege matrix (all 217 instructions)

This table is the source of truth for what each plugin requires. When you add a new privileged plugin, add a row here AND a corresponding entry in `install-agent-user.{sh,ps1}` AND a sudoers entry / LSA privilege.

### Read-only (no privilege beyond default account)

| Plugin / Action | macOS | Linux | Windows |
|---|---|---|---|
| `processes.list`, `processes.query` | default | default | default |
| `processes.fetch`, `tar.process_tree` | default | `cap_sys_ptrace` (set on agent binary) | `SeDebugPrivilege` is **NOT** granted; a process can only inspect its own children. Operators that need this should run a one-off elevated dispatch. |
| `os_info.*` | default | default | default |
| `network_config.*` | default | default | default |
| `installed_apps.*`, `msi_packages.*` | default | default | default |
| `event_logs.*` | default | `systemd-journal` group | `Event Log Readers` group; `Security` log additionally needs `SeSecurityPrivilege` |
| `services.list`, `services.running` | default | default | default |
| `certificates.list`, `certificates.details` | default | default | default |
| `tar.*` (TAR snapshots) | default | `cap_dac_read_search` (read all `/proc/<pid>/*`) | `SeBackupPrivilege` (read regardless of DACL) |
| `netstat.*`, `sockwho.*` | default | default | default |
| `bitlocker.state` | n/a | n/a | `SeBackupPrivilege` (some BitLocker WMI properties require this on system drives) |

### Privileged actions (require sudoers entry / LSA privilege)

| Plugin / Action | macOS sudoers | Linux sudoers | Windows privilege |
|---|---|---|---|
| `quarantine.isolate`, `quarantine.release`, `quarantine.whitelist` | `/sbin/pfctl` | `/usr/sbin/iptables`, `/usr/sbin/ip6tables`, `/usr/sbin/nft` | service account is in `Administrators` group OR has `SeAssignPrimaryTokenPrivilege` + uses `Set-NetFirewallRule` cmdlet |
| `services.set_start_mode` | `/bin/launchctl bootstrap system *`, `/bin/launchctl bootout system *`, `/bin/launchctl enable system/*`, `/bin/launchctl disable system/*` | `/bin/systemctl enable *`, `/bin/systemctl disable *`, `/bin/systemctl mask *`, `/bin/systemctl unmask *` (also `/usr/bin/systemctl` on distros that mirror it) | `SeAssignPrimaryTokenPrivilege` (service control) |
| `network_actions.flush_dns` | `/usr/bin/dscacheutil -flushcache`, `/usr/bin/killall -HUP mDNSResponder` | `/usr/bin/systemd-resolve --flush-caches`, `/usr/bin/resolvectl flush-caches` | runs as service; uses `Clear-DnsClientCache` cmdlet (no extra privilege required when running as service) |
| `certificates.delete` (system store only) | `/usr/bin/security delete-certificate -t /Library/Keychains/System.keychain *` | (uses `update-ca-certificates` reading `/etc/ssl/certs/*` → no sudo needed for CA store; OpenSSL trust chain is filesystem-managed) | `SeBackupPrivilege` + `SeRestorePrivilege` to write the certificate store |
| `registry.set_value`, `registry.delete_value`, `registry.delete_key` | n/a | n/a | service account in `Administrators` group required for `HKLM\*`; user hives (`HKCU`) work without elevation |
| `filesystem.write_content`, `filesystem.replace`, `filesystem.append`, `filesystem.delete_lines` | depends on path; system paths (`/etc/*`, `/Library/*`) require operator-authored per-path sudo entry. Default install grants nothing. | depends on path; system paths require operator-authored per-path sudo entry. | depends on path; system paths require service account to be `Administrators` member |
| `script_exec.exec`, `script_exec.bash`, `script_exec.powershell` | runs as `_yuzu` (no sudo) | runs as `yuzu` (no sudo) | runs as `YuzuAgent` (no extra privilege) |
| `wol.wake` | runs as `_yuzu` with raw socket privileges from `cap_net_raw` | `cap_net_raw` set on agent binary | service account; uses `Send-MagicPacket` (PowerShell) or socket APIs |
| `content_dist.execute_staged` | runs as `_yuzu` (the staging area is `_yuzu`-owned) | runs as `yuzu` | runs as `YuzuAgent` |
| `bitlocker.state` | n/a | n/a | service account in `Administrators` group for system drive queries |
| `patches.deploy` | (calls Apple's `softwareupdate` — needs `/usr/sbin/softwareupdate` sudo entry; not in default sudoers — operator opts in) | (calls `apt-get` / `dnf upgrade` — needs `/usr/bin/apt-get`, `/usr/bin/dnf` sudo entries; not in default sudoers) | service account in `Administrators` (Windows Update API) |

---

## Deliberately NOT granted (negative space)

This section matters as much as the positive grants — it documents the privileges the agent could *plausibly* claim but explicitly does not, and the reasoning. When reviewing a PR that wants to add one of these, default to "no" and require an explicit threat-model justification.

| Privilege | Platform | Why NOT granted |
|---|---|---|
| Generic `ALL=(ALL)` sudo | macOS, Linux | Makes the audit surface infinite. Every privileged operation must be itemized. |
| `SeDebugPrivilege` | Windows | Effective full-system access via process token theft. Reserved for LocalSystem and a small set of debug tools. |
| `SeLoadDriverPrivilege` | Windows | Drivers run in kernel mode. The agent stays user-mode; if a plugin ever needs kernel-mode telemetry, it goes through ETW, not a custom driver. |
| `SeImpersonatePrivilege` | Windows | Lets the agent impersonate any logged-in user. Reserved for the future per-session interaction helper. |
| `SeTakeOwnershipPrivilege` | Windows | Agent should never seize files. If a plugin needs to write a file the agent doesn't own, that's a configuration problem, not a privilege problem. |
| Membership in `wheel` / `Administrators` | Linux / Windows (dev) | Same audit-surface argument as generic sudo. Only the production virtual service account has equivalent privileges, and those are bounded by what `Administrators` grants in the platform default. |
| `cap_sys_admin` | Linux | Grants too much (mount, swap, etc.). Plugins should never need this. |
| Write access to `/usr/local/lib/yuzu/plugins/` | all | A compromised plugin shouldn't be able to tamper with siblings. Plugin signing (future) will add a second layer. |
| GUI session access | all | Daemons can't reach a logged-in user's display server. The interaction plugin needs a separate per-session helper, not the daemon. |
| `chown` / `chmod` shell-outs | macOS, Linux | Agent should never rewrite ACLs. If a plugin needs to write a path the agent doesn't own, that's a configuration problem. |

---

## Filesystem hierarchy

| Path (Linux) | Path (macOS) | Path (Windows) | Owner | Mode | Purpose |
|---|---|---|---|---|---|
| `/var/lib/yuzu-agent/` | `/Library/Application Support/Yuzu/state/` | `C:\ProgramData\Yuzu\state\` | agent | 0750 | persistent state: `agent.db`, KV store, `cmd_execution_ids` cache |
| `/var/cache/yuzu-agent/` | `/Library/Caches/Yuzu/` | `C:\ProgramData\Yuzu\cache\` | agent | 0750 | regenerable cache; `content_dist.stage` writes downloads here |
| `/var/log/yuzu-agent/` | `/Library/Logs/Yuzu/` | `C:\ProgramData\Yuzu\logs\` | agent | 0750 | spdlog output (managed by logrotate / Apple ASL / Windows ETW) |
| `/usr/local/lib/yuzu/plugins/` | `/Library/Application Support/Yuzu/plugins/` | `C:\Program Files\Yuzu\plugins\` (or `C:\ProgramData\Yuzu\plugins\` for dev) | root | 0755 (read-only to agent) | plugin `.so` / `.dylib` / `.dll` loaded at agent startup. **Must NOT be writable by the agent account** |
| `/etc/yuzu-agent/agent.cfg` | `/Library/Application Support/Yuzu/config/agent.cfg` | `C:\ProgramData\Yuzu\config\agent.cfg` | root | 0640 (root:agent) | agent config; root-owned, agent-readable |
| `/etc/yuzu-agent/cert/` | `/Library/Application Support/Yuzu/config/cert/` | `C:\ProgramData\Yuzu\config\cert\` | root | 0640 (root:agent) | mTLS cert+key for gRPC; root-owned, agent-readable |

The plugins directory specifically being root-owned and read-only-to-agent is a hardening invariant: a compromised plugin should not be able to drop a sibling .so that gets loaded on next agent restart. Plugin code-signing (a future feature) will be a defence-in-depth alongside this.

---

## How sudoers entries are constructed

Every line in `/etc/sudoers.d/yuzu-agent` follows this exact shape:

```
yuzu ALL=(root) NOPASSWD: /absolute/path/to/binary [arg-template-with-globs]
```

**Why each piece matters:**

- **`yuzu`** — the agent's account name. The default install uses `yuzu` (Linux) / `_yuzu` (macOS), but the sudoers file is regenerated by the install script and reflects whatever `--account-name` was passed.
- **`ALL=`** — the host pattern. `ALL` is correct here because we're not using sudo's host-restriction feature; the file is host-local.
- **`(root)`** — the target user. Always `root` for our entries; the privileged commands operate on system-level resources only the kernel has authority over.
- **`NOPASSWD:`** — required because the agent runs non-interactively. Without this, every privileged plugin call would block on a password prompt the daemon can't answer.
- **`/absolute/path/to/binary`** — required to prevent PATH-injection attacks. If we wrote `iptables` instead of `/usr/sbin/iptables`, an attacker who got code execution as the agent could prepend a directory to `PATH` containing a malicious `iptables` binary, and the sudoers entry would helpfully run that as root.
- **`arg-template-with-globs`** — bounds the argument shape. `pfctl *` allows any pfctl subcommand; `systemctl enable *` only allows enable, not start/stop. We err on the side of broader globs (`pfctl *` rather than enumerating every subcommand) because `pfctl` is single-purpose; for `systemctl` we narrow to specific subcommands because the agent should never `systemctl reboot`.

The install script always validates the generated file with `visudo -cf <tempfile>` before atomic move into place. A syntactically invalid sudoers file would brick every sudo call on the host, so this validation is non-optional.

---

## How LSA privileges are granted (Windows)

Windows has no built-in cmdlet to grant `SeXxxPrivilege` rights to an account. The two real options:

1. **`secedit /export` → edit → `secedit /configure`.** Clunky, race-prone if multiple admins are configuring policy at the same time, and the edit-the-INI step is fragile under encoding (UTF-16 LE BOM is required).
2. **P/Invoke `advapi32!LsaAddAccountRights`.** Atomic, no temp files, no encoding gotchas. This is what `install-agent-user.ps1` uses.

The PowerShell script defines the LSA structures + function imports inline (in a `$lsaSource` C# string), loads them via `Add-Type`, and calls `LsaAddAccountRights` per privilege. The complement function `LsaRemoveAccountRights` is used by `-Uninstall`.

We deliberately keep the C# definitions in the script rather than a separate module so the script is self-contained — operators can read it end-to-end without chasing imports.

The deny-interactive logon rights (`SeDenyInteractiveLogonRight`, `SeDenyRemoteInteractiveLogonRight`) are an exception: they're set via `secedit` because LsaAddAccountRights doesn't include the deny-rights LSA functions in its public surface (those go through the user-rights-assignment policy, which is what `secedit` exports/imports).

---

## How to add a new privileged plugin

Procedure for any change that introduces a new privileged shell-out:

1. **Read this doc end-to-end.** If your plugin's privilege isn't listed, it isn't granted.
2. **Choose the narrowest grant that works.** If your plugin only needs to run `mount /dev/sdX /mnt`, the sudoers entry is `/usr/bin/mount /dev/sd* /mnt/*` — not `/usr/bin/mount`.
3. **Update the privilege matrix above.** Add a row with the platform-specific grants.
4. **Update `install-agent-user.{sh,ps1}` `generate_sudoers_content` / `RequiredPrivileges`.** Both scripts. If the change is platform-specific, only the platform-specific script needs changing, but document that in the matrix.
5. **Update the plugin's source to use `sudo -n` (Unix) or run inside the elevated service token (Windows).** Code-review for argument quoting: every argv passed to `sudo -n` must come from a trusted source (a YAML-declared parameter that's been validated against its schema), not from raw operator input.
6. **Add a regression test under `tests/instructions/` (PR C surface) that exercises the new privilege grant on a UAT stack** with the install script's `--check` as a precondition.
7. **File a security-guardian review** referencing this doc. The reviewer's job: confirm the grant is the narrowest that works and the argv-validation in step 5 is sound.

---

## Production vs dev install paths

|  | Production (MSI / `.deb` / `.pkg`) | Dev (`scripts/install-agent-user.{sh,ps1}` directly) |
|---|---|---|
| Account creation | by the package's pre-install hook (`postinst` on `.deb`, `RunAfterInstall` MSI custom action) | by the script invoked manually as root/admin |
| Sudoers / LSA grants | dropped by the package's pre-install hook (Linux/macOS); `Microsoft.Windows.LsaAddAccountRights` MSI custom action (Windows) | by the script |
| State dir creation | as part of package extraction, with correct ACLs already set | by the script |
| Service registration | as part of package install (`systemctl enable`, `launchctl bootstrap`, `sc.exe create`) | the dev operator runs `scripts/start-UAT.sh` which doesn't register a service — the agent runs as a foreground process |
| Account password (Windows) | virtual service account; SCM manages credentials | random password stashed in DPAPI blob; only relevant if the operator wants to log in as the account for debugging |

The dev path produces an account-and-grants combination that is **functionally equivalent** to the production virtual-service-account path for everything except service registration. This means `/test --instructions-quarantine` produces the same firewall behaviour as a production deployment would when the operator runs the same instruction.

---

## Audit and review

`/etc/sudoers.d/yuzu-agent` is regenerated by `install-agent-user.sh` on every run. Treat the file as build artifact, not source — its source is the `generate_sudoers_content` function. The file's git history is in this repo, in the install script's commits.

Windows LSA grants leave no on-disk artifact equivalent to a sudoers file. The `install-agent-user.ps1` script writes an install marker at `C:\ProgramData\Yuzu\install-marker.json` listing the account name, granted privileges, and groups. `secedit /export` against the live policy is the authoritative source on a running box.

For a periodic audit, a `security-guardian` agent should:
- Diff `/etc/sudoers.d/yuzu-agent` against the install script's `generate_sudoers_content` output. Any drift means an operator hand-edited the file (a violation of the model).
- Diff the live policy's USER_RIGHTS section against this doc's matrix. Any privilege not listed here means an operator hand-granted via `secedit` or the Group Policy Editor.
- Confirm the agent process is not running as root / LocalSystem (unless it's a deliberate development override; production images should refuse to start as root, see future hardening).

---

## Troubleshooting

### `sudo: a password is required`

The agent shelled out to `sudo /sbin/pfctl` (or similar) and sudo asked for a password. Either:
- The sudoers file isn't installed → run `install-agent-user.sh --check`.
- The sudoers file is wrong → re-run `install-agent-user.sh` (it regenerates the file).
- The agent is running as a different account than the one in sudoers → check `ps -o user= -p $(pgrep yuzu-agent)`.

### `pfctl: Operation not permitted` (macOS) or `iptables: Permission denied` (Linux)

The shell-out used the bare command instead of `sudo -n /sbin/pfctl`. The plugin source needs updating — see "How to add a new privileged plugin" step 5. This was the state of the world up to and including the v0.10.x line; PR after this doc lands is what flips it.

### Windows `Set-NetFirewallRule: Access denied`

The service account is missing `SeAssignPrimaryTokenPrivilege` or isn't in `Administrators`. Run `install-agent-user.ps1 -Check` to see which.

### `_yuzu` user gets created but agent still runs as `nathan`

The agent process started before the install script ran, OR the launch path (e.g., `start-UAT.sh`) isn't using `sudo -u _yuzu` to launch the agent. Update the launch path. Production deployments via launchd/systemd/SCM don't have this issue because the unit/plist specifies the account.

---

## Routing for the agent team

| If you're touching... | Read this section |
|---|---|
| `agents/plugins/quarantine/src/quarantine_plugin.cpp` | "How sudoers entries are constructed", privilege matrix row for `quarantine.*` |
| `agents/plugins/services/src/services_plugin.cpp` | privilege matrix row for `services.set_start_mode` |
| Any new plugin that runs OS-level commands | "How to add a new privileged plugin" — full procedure |
| `scripts/install-agent-user.{sh,ps1}` | the whole doc; the scripts implement what's specified here |
| `scripts/start-UAT.sh` | "Production vs dev install paths" — UAT is a dev path |
| `docs/yuzu-guardian-design-v1.1.md` (Guardian guards) | each Guardian guard's enforcement action follows this same model: agent shells out via narrow sudo entries, never as root |
