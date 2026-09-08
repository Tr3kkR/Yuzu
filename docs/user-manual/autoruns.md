# Autoruns

The `autoruns` plugin enumerates **persistence sources** -- everything an
endpoint's OS will start automatically -- across Windows, Linux and macOS.
It is read-only: no action mutates host state, spawns a mutating process, or
writes to the registry/filesystem/launchd.

## Actions

| Action | What it does | OS call |
|---|---|---|
| `catalog` | Lists every `SourceId` this build knows about, with the support level THIS build declares for it (`kSourceCatalog`, versioned by `kAutorunSourceCatalogVersion`). | None -- a pure reflection of static data. |
| `list` | Runs every per-OS leg and emits a `source|` status line per catalog source, plus zero or more `autorun|` rows for sources that produced data. `sources=` filters to a comma-separated `SourceId` allow-list. | Yes -- see the per-source table below. |

Both actions run unconditionally on every build: the two legs that are not
the build's own OS resolve to `autoruns_legs.hpp`'s foreign-OS stub
(`unsupported|0|foreign_os`), so a `list` capture always names every source
in the catalog on every OS, and the capability matrix generator always sees
a complete three-OS shape.

## Row format

Two row shapes share one stream, discriminated by field 0:

```
source|<id>|<support>|<row_count>|<reason>
autorun|<source_id>|<catalog_version>|<location>|<entry>|<target>|<args>|<enabled>|<scope>|<user>|<signed>|<mtime>
```

A literal `|` inside any text field is folded to U+2502 (`│`), never
backslash-escaped, so every row has a fixed field count under a plain
`split('|')`. `catalog_version` lets a consumer that stored an `autorun|` row
tell "this row predates a `SourceId` rename/add/remove" from "this is simply
new data" -- always cross-check it against the catalog version `catalog`
reports before comparing row shapes across a fleet's mixed agent versions.

### `source|` status semantics -- "nothing there" vs "could not read"

The fifth field (`reason`; the fourth payload field after the `source`
discriminator) always distinguishes a source that was read and had nothing
versus one that could not be read at all:

- **`supported|0|absent`** -- the mechanism ran and genuinely found nothing
  (e.g. an XDG autostart dir that doesn't exist, `/etc/rc.local` absent).
  This is a complete, honest read, not a failure.
- **`constrained|0|absent`** -- the same ENOENT, but for a source the
  catalog treats as required (`/etc/crontab`, `/etc/anacrontab` on Linux):
  its absence is itself unusual enough to flag, not silently folded into
  "supported, nothing there".
- **`constrained|<n>|permission_denied`** / any other errno token -- a real
  read failure. Never conflated with `absent`: a caller that only checks
  `row_count == 0` cannot distinguish "empty" from "denied" without reading
  `reason`.
- **`unsupported|0|foreign_os`** -- this source belongs to an OS this build
  isn't running on (autoruns_legs.hpp's stub).
- **`constrained|0|btm_private_database_no_public_api`** (`mac_login_items`)
  -- the mechanism exists but this leg deliberately does not exercise it: no
  public read API for the private BTM database.
- **`constrained|<n>|<sid>:<reason>`** (`win_*_hku` sources, per profile) --
  the hive couldn't be reached for that SID, with the specific constraint
  named rather than folded into one bucket: `not_found` (no such profile
  hive), `privilege_missing` (`SeBackupPrivilege`/`SeRestorePrivilege`
  couldn't be enabled on the process token), or `mount_failed`
  (`RegLoadKeyW` itself failed for the offline arm). A separate
  `warning|hive_unload_failed|...` line is emitted if the trailing
  `RegUnLoadKeyW` fails on the way out -- this is orthogonal to the
  per-source `source|` line and never folded into it.
- **`constrained|<n>|malformed`** (launchd plist walk, `mac_emond`) -- the
  file was read but its plist could not be parsed (corrupt, or a valid
  plist truncated by `kMaxPlistBytes`); never silently folded into a
  `supported` status. `mac_emond` combines this with any directory-level
  constraint via a comma-joined reason.

## Versioned source catalog

Support: **S**upported (rung 1, direct read), **C**onstrained (reads, but
with a documented gap), **U**nsupported (foreign OS). Every source carries
all three OS columns even when native to one OS, so `catalog`/foreign-OS
stubs never special-case per-OS.

| SourceId | Name | W | L | M | Why |
|---|---|---|---|---|---|
| `win_run_hklm` | HKLM Run | S | U | U | Reg\*W, native + WOW6432Node views |
| `win_runonce_hklm` | HKLM RunOnce | S | U | U | Reg\*W, native + WOW6432Node views |
| `win_runonceex_hklm` | HKLM RunOnceEx | S | U | U | Reg\*W, native + WOW6432Node views |
| `win_run_hku` | HKU Run (every loaded/mountable hive) | S | U | U | per-profile `with_user_hive` ladder |
| `win_runonce_hku` | HKU RunOnce (every loaded/mountable hive) | S | U | U | per-profile `with_user_hive` ladder |
| `win_startup_approved` | Explorer StartupApproved\Run | S | U | U | Reg\*W, system + per-user |
| `win_winlogon_shell` | Winlogon Shell | S | U | U | Reg\*W |
| `win_winlogon_userinit` | Winlogon Userinit | S | U | U | Reg\*W |
| `win_appinit_dlls` | AppInit_DLLs | S | U | U | Reg\*W |
| `win_ifeo_debugger` | Image File Execution Options Debugger | S | U | U | Reg\*W |
| `win_startup_folder_common` | Startup folder (All Users) | S | U | U | file listing |
| `win_startup_folder_user` | Startup folder (current user) | S | U | U | file listing, per profile |
| `win_scheduled_tasks` | Scheduled Tasks | S | U | U | ITaskService COM |
| `win_wmi_subscriptions` | WMI permanent event subscriptions | S | U | U | bounded `root\subscription` query |
| `lnx_etc_crontab` | `/etc/crontab` | U | S | U | file read; absent is CONSTRAINED (required) |
| `lnx_cron_d` | `/etc/cron.d/*` | U | S | U | dir listing + file reads |
| `lnx_cron_periodic` | `/etc/cron.{hourly,daily,weekly,monthly}` | U | S | U | dir listing |
| `lnx_user_crontabs` | per-user crontabs | U | S | U | `/var/spool/cron{,/crontabs}` reads |
| `lnx_anacrontab` | `/etc/anacrontab` | U | S | U | file read; absent is CONSTRAINED (required) |
| `lnx_at_spool` | `/var/spool/at` (`at(1)` jobs) | U | S | U | dir listing |
| `lnx_systemd_timers_system` | systemd system timer units | U | S | U | tri-state; see below |
| `lnx_systemd_timers_user` | systemd user timer units | U | S | U | tri-state; see below |
| `lnx_xdg_autostart_system` | XDG autostart (`/etc/xdg/autostart`) | U | S | U | dir listing |
| `lnx_xdg_autostart_user` | XDG autostart (`~/.config/autostart`) | U | S | U | dir listing, per user |
| `lnx_rc_local` | `/etc/rc.local` | U | S | U | file read |
| `lnx_init_d` | `/etc/init.d/*` (SysV, listing only) | U | **C** | U | script names only -- no runlevel/`systemctl` wiring cross-check |
| `mac_launchdaemons` | `/Library/LaunchDaemons` | U | U | S | plist walk |
| `mac_launchagents` | `/Library/LaunchAgents` | U | U | S | plist walk |
| `mac_system_launchdaemons` | `/System/Library/LaunchDaemons` | U | U | S | plist walk |
| `mac_system_launchagents` | `/System/Library/LaunchAgents` | U | U | S | plist walk |
| `mac_user_launchagents` | `~/Library/LaunchAgents` | U | U | S | plist walk, per real home |
| `mac_login_items` | Login Items | U | U | **C** | private BTM database, no public read API |
| `mac_periodic` | `/etc/periodic` | U | U | S | dir listing (no content read) |
| `mac_emond` | `/etc/emond.d/rules` | U | U | S | plist walk |

## Real `source|` captures

Pasted verbatim from real runs, 2026-09-07 -- not constructed fixtures. The
macOS capture is against the actual built plugin (`autoruns.dylib` via
`LocalDispatcher`); the Linux capture is a standalone harness linking the
real `collect_linux` against the container's real filesystem, NOT the
shipped artifact dispatched end-to-end (this build's `.dylib` cannot run on
Linux -- see the container section below for the caveat). Windows values are
A1's the-rig probe results (quoted in the descriptor notes and
`docs/wave7/rig-checklist-autoruns-win.md`); no macOS-host or container-host
Windows run exists, and no real end-to-end Linux `list` dispatch (real
plugin, real dispatcher, real runner) has been performed yet -- tracked as a
gap in the checklist below.

**This Mac (macOS, `autoruns.dylib`, LocalDispatcher `list`):**

```
source|mac_launchdaemons|supported|2|launchd_plist_walk
source|mac_launchagents|supported|0|launchd_plist_walk
source|mac_system_launchdaemons|supported|422|launchd_plist_walk
source|mac_system_launchagents|supported|456|launchd_plist_walk
source|mac_user_launchagents|supported|1|launchd_plist_walk
source|mac_login_items|constrained|0|btm_private_database_no_public_api
source|mac_periodic|supported|0|periodic_dir_walk
source|mac_emond|supported|0|emond_rule_plist_walk
```

(every `win_*`/`lnx_*` source reads `unsupported|0|foreign_os` on this
build, as expected.)

**Real `ubuntu:24.04` Docker container (a standalone harness compiled against
the real `collect_linux`, run against the container's actual filesystem --
this build's plugin `.dylib` cannot run on Linux, so this is the leg's real
code against a real host, not the shipped artifact):**

```
source|lnx_etc_crontab|constrained|0|absent
source|lnx_cron_d|supported|2|-
source|lnx_cron_periodic|supported|2|-
source|lnx_user_crontabs|supported|0|absent
source|lnx_anacrontab|constrained|0|absent
source|lnx_at_spool|supported|0|absent
source|lnx_systemd_timers_system|unsupported|0|no_systemd
source|lnx_systemd_timers_user|unsupported|0|no_systemd
source|lnx_xdg_autostart_system|supported|0|absent
source|lnx_xdg_autostart_user|supported|0|-
source|lnx_rc_local|supported|0|absent
source|lnx_init_d|constrained|1|listing_only
```

This container has no init system, so it exercises the tri-state's `absent`
branch (`no_systemd`) for both systemd sources, not the rung-2
`systemctl list-timers` fallback -- that path needs a host with systemd
present but every one of its three unit dirs unreadable, which no available
host provided. It also confirms the `absent`-vs-required distinction:
`/etc/crontab` and `/etc/anacrontab` (required by the catalog) read
CONSTRAINED, while every other genuinely-empty source reads SUPPORTED.

## Windows: the per-profile HKU ladder

`win_run_hku`, `win_runonce_hku` and `win_startup_approved` each need to read
every reachable user's hive, not just HKLM. Per profile
(`win_profiles.hpp::with_user_hive`):

1. **Live hive first.** If the user is logged in, its hive is already
   mounted under `HKEY_USERS\<sid>` -- read it directly, no privilege
   elevation, no mount/unmount.
2. **Offline `RegLoadKeyW` fallback.** If not, the profile's
   `NTUSER.DAT` is mounted at a private mount point under
   `SeBackupPrivilege` + `SeRestorePrivilege`, enabled on the *process*
   token only for the duration of the offline arm, and serialised
   process-wide by `offline_hive_mutex()` so two offline reads never race
   the same mount point or contend the privilege-enable/mount/read/
   unmount/restore sequence against each other.
3. **`unload_failed` is surfaced, never dropped.** If the trailing
   `RegUnLoadKeyW` fails, a `warning|hive_unload_failed|...` line is
   emitted for that SID/mount name -- this is a real host-state leak (a
   stray mounted hive) an operator needs to know about, not swallowed
   into a generic "read OK" result.

A1's the-rig probe found `RegLoadAppKeyW` (a *different* API, used
elsewhere for Amcache) does not require `SeBackupPrivilege` at all; that
finding does not apply to this leg's `RegLoadKeyW`, which does.

## The one rung-2 fallback: `systemctl list-timers`

`lnx_systemd_timers_system`/`_user` are a **tri-state on
`/run/systemd/system`**, not a plain present/absent check:

- **absent** (`stat` returns `ENOENT`) -- reports `unsupported|0|no_systemd`.
  No systemd, nothing to enumerate.
- **undetermined** (`stat` fails some other way) -- reports
  `constrained|0|systemd_state_undetermined`. The host's systemd state
  itself couldn't be determined; this is not the same fact as "no systemd".
- **present** -- reads `/etc/systemd/system`, `/usr/lib/systemd/system` and
  `/lib/systemd/system` directly (rung 1). **Only when systemd is present
  but all three are unreadable** does the leg fall back to
  `systemctl list-timers --all --no-pager --no-legend` (rung 2,
  sink-manifest site `autoruns/collect_linux#1`) -- the single spawn in this
  entire leg. Rows from that fallback carry `enabled=unknown`: the text
  output carries no wants-symlink evidence, so enablement cannot be
  determined the same way the rung-1 directory read determines it.

## macOS: Login Items is constrained, `osascript` is rejected

`mac_login_items` always emits one constrained status line
(`constrained|0|btm_private_database_no_public_api`) and zero rows, never a
real read attempt. The list lives in a private per-user BTM (Background Task
Management) database with no public read API. The only route that exists at
all is `osascript` driving System Events -- a rung-3 governed-shell
acquisition under ADR-3002 Decision 5 -- and this leg does not perform it:
file truth only, zero process spawns anywhere in the macOS leg.

## `signed` column, macOS rows only

`apple_system` means the row's `location` falls under `/System/Library/` --
a **path judgement only**, matching a literal path prefix. It is **not** a
code-signature verification: this plugin never calls
`SecStaticCodeCheckValidity` or any other Security.framework API, so
`apple_system` means "Apple ships this location", not "this file's
signature was checked and is valid." Every other macOS row -- everything
under `/Library/`, a user's `~/Library/LaunchAgents`, `/etc/periodic`, and
`/etc/emond.d` -- is `not_checked`. Windows and Linux rows are always
`not_checked`; neither leg reads a signature. A future PR wiring a real
`SecStaticCodeCheckValidity` call adds new `signed` values -- it does not
repurpose `apple_system`/`not_checked` to mean something different than they
do today.

## Security, permissions, and approval

Both actions are classified `Security` / `ReadOnly` / `Mutability::None` /
`RiskTier::Low` / `ExecuteGate::None` (`plugin_action_catalogue_autoruns.hpp`)
-- no approval gate, matching the read-only fact-collection precedent
`vuln_scan.*` uses. `catalog` performs no OS call at all; `list` reads
registry values, files, and plist/task/WMI metadata -- nothing in either
action opens a write handle, spawns a mutating process, or changes any
persistence entry it reports on. This classification is pinned exactly by
`test_capability_catalogue.cpp`'s "autoruns.list and autoruns.catalog pin
their exact classification" case -- a drift from `Security` to a broader
securable, or from `ReadOnly`/`None`/`None`, fails that test.

## Real-hardware verification checklist

**Windows (the-rig, desktop-04dnsig)** -- full 10-step checklist lives in
`docs/wave7/rig-checklist-autoruns-win.md`; summarised here, numbered to
match that file:

1. Build the plugin under MSVC 2022 BuildTools and confirm it links against
   `advapi32`/`ole32`/`oleaut32`/`wbemuuid`/`taskschd` with no unresolved
   externals.
2. Run `catalog` via the local dispatcher test: one `source|` line per
   catalog entry, all Windows entries `windows: SUPPORTED`.
3. Run `list` unfiltered: all 14 `win_*` SourceIds each emit exactly one
   `source|` line, none `unsupported` (that value only comes from the
   foreign-OS stub on a non-Windows build).
4. HKLM Run/RunOnce/RunOnceEx: confirm both native-view and WOW6432Node row
   sets, cross-checked against a manual `reg query`.
5. Per-user Run/RunOnce/StartupApproved: confirm at least one logged-in
   profile reads via the live-hive path (no `warning|hive_unload_failed`),
   and a logged-out profile goes through the offline `RegLoadKeyW` arm and
   still unloads cleanly.
6. StartupApproved join: a scratch Run entry plus its StartupApproved blob
   reports `disabled` correctly, and a truncated (non-12-byte) blob reports
   `enabled=unmodelled` with a `constrained` status, never a dropped row.
7. Startup folders: a dropped `.lnk` in both the common and per-user
   Startup folders surfaces as its own row with unresolved target/args and
   a real `mtime`.
8. Scheduled Tasks: `win_scheduled_tasks` row count matches the
   ITaskService session's own recursive enumeration (A1's probe: 321-322
   tasks), hidden tasks included, never cross-checked against `schtasks.exe`
   (must never be spawned).
9. WMI subscriptions: exactly one `win_wmi_subscriptions` row per
   `__FilterToConsumerBinding` (A1's probe: one stock binding, `Next()`
   `WBEM_S_FALSE` after exactly 1).
10. Cleanup verification: every scratch registry key/task/binding/file
    created for steps 4-9 is removed and a follow-up `list` run confirms no
    stray rows remain.

**Linux container (`ubuntu:24.04`) and this Mac, both run 2026-09-07:**

1. Linux container: `lnx_systemd_timers_{system,user}` both read
   `no_systemd` (no init system present -- the tri-state's absent branch,
   not rung-2); `lnx_cron_d` and `lnx_cron_periodic` both produced real
   `autorun|` rows from the image's stock `e2scrub_all`/`dpkg`/`apt-compat`
   cron entries; `lnx_etc_crontab`/`lnx_anacrontab` correctly read
   `constrained|absent` (required sources, genuinely missing in this
   minimal image); `lnx_init_d` listed the stock `procps` SysV script,
   correctly `constrained|listing_only`. This ran through a standalone
   harness linking the real `collect_linux`, not the built `.dylib`
   dispatched end-to-end (that artifact cannot run on Linux at all).
2. This Mac (macOS, native `autoruns.dylib`, `LocalDispatcher`): all five
   launchd-plist sources supported with real row counts (422/456 system
   daemons/agents, 2/0/1 user-scope), `mac_login_items` constrained with
   zero rows, `mac_periodic`/`mac_emond` supported with zero rows (neither
   directory populated on this host) -- the "supported, nothing there" vs
   "constrained, no API" distinction holds for real; every `win_*`/`lnx_*`
   source correctly reads `unsupported|0|foreign_os` through the foreign-OS
   stub.
3. **Not yet run for real, tracked as a gap:** an end-to-end Linux `list`
   dispatch (real `autoruns.so`, real dispatcher, real
   `run_bounded_subprocess`) -- everything above for Linux is the leg's
   real code compiled standalone, not the shipped artifact; the rung-2
   `systemctl list-timers` fallback (needs a host with systemd present but
   every unit dir unreadable -- no available host provided this state); a
   Linux host with a populated `/etc/anacrontab`/per-user crontab/`at(1)`
   spool/systemd timer unit to confirm those `autorun|` row shapes for real
   (only the container's stock cron/init.d entries were exercised here);
   the-rig's own `meson compile`/link (tracked separately, concurrent with
   this package per the run context).
