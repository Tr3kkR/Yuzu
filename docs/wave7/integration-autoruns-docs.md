# autoruns docs finalization (P15)

P15 owns `agents/plugins/autoruns/src/autoruns_plugin.cpp` (descriptor notes
only, no logic), `content/definitions/autoruns.yaml`,
`docs/user-manual/autoruns.md`, `changelog.d/7.1-autoruns.added.md`, and this
doc. No hotspot file, no leg/parser edit. This is the wave's own docs-and-
descriptors closer for the plugin P11/P12/P13/P14 built; every row below is
for the integrator to apply to a shared file this package does not own.

## Routed-concerns row

For whichever doc tracks routed cross-cutting concerns by plugin:

| Plugin | Concern | Detail |
|---|---|---|
| `autoruns` | Catalogue version bump rules | `kAutorunSourceCatalogVersion` (`autoruns_catalog.hpp`) is bumped whenever a `SourceId` is added, renamed, or removed — never for a support-level or mechanism change to an existing id. A consumer keys `autorun|`/`source|` rows on `catalog_version` to tell "this row predates a shape I don't recognise" from "this row is simply new data"; a bump with no shape change would make every stored row look stale for nothing, and skipping a bump on a real rename would make an old and new id collide under one version. |
| `autoruns` | Unmodelled vs unknown | `Enabled::unmodelled` is reserved for undecoded input shapes (currently: a Windows StartupApproved blob that fails its expected 12-byte shape). It is NOT what a launchd plist with no `Disabled` key produces — `launchd_row_from_fields` (`autoruns_parsers.hpp`) currently resolves that case to `Enabled::enabled` (the key's absence means "not disabled"), not to `unmodelled` or `unknown`; do not route a future review of this leg to expect `unmodelled` there. `Enabled::unknown` is reserved for genuinely indeterminate cases (Linux `systemctl list-timers` fallback rows: no wants-symlink evidence in that text). Linux init.d listing rows carry no `enabled` value at all (the source is a plain directory listing, not a per-entry row). A future leg fix must not repurpose `unmodelled`/`unknown` to mean each other, and any change to the launchd no-`Disabled` default must update this row and its test (`test_autoruns_macos_local.cpp`, "enabled, not unmodelled") together. |
| `autoruns` | Per-profile hive `unload_failed` must be surfaced | `win_profiles.hpp::with_user_hive`'s offline arm never silently drops a trailing `RegUnLoadKeyW` failure — `HiveAccessReport::unload_failed` is rendered as a `warning|hive_unload_failed|...` line for that SID/mount name by every one of `win_run_hku`/`win_runonce_hku`/`win_startup_approved`'s per-user pass (`autoruns_win.cpp`'s `render_hive_access_lines` call), even though the source's own `source|`/`autorun|` rows may otherwise report a clean read. A future edit to this leg must keep emitting that line — a stray mounted hive left behind on a target endpoint is real host state an operator needs to know about, not a detail this plugin is allowed to swallow. **Known gap:** this contract is exercised only by `render_hive_access_lines`'s own unit coverage; no reviewed test forces `HiveAccessReport::unload_failed=true` through an actual `win_run_hku`/`win_runonce_hku`/`win_startup_approved` call site and asserts the warning line survives. A follow-up test package should add an injectable hive-access seam at that call site. |
| `autoruns` | The one argv fallback | `collect_linux`'s only spawn, `systemctl list-timers --all --no-pager --no-legend` (sink-manifest `autoruns/collect_linux#1`), fires only when `/run/systemd/system` presence-checks `present` AND all three system unit directories (`/etc/systemd/system`, `/usr/lib/systemd/system`, `/lib/systemd/system`) fail to open. Every other acquisition across all three legs is a direct file/registry/COM/WMI read — zero spawns on Windows or macOS, and this one Linux exception is conditional, not unconditional. **Known gap:** no injected-runner test pins argv literally, pins the two-directory-state trigger, or structurally asserts this is the only spawn site across all three legs; a refactor could invoke `systemctl` unconditionally, or add a spawn on macOS/Windows, and the current host-tolerant tests would not catch it. |

## README index row

For `docs/user-manual/README.md`'s Table of Contents (alongside `[Agent
Plugins](agent-plugins.md)`):

```
| [Autoruns](autoruns.md) | Persistence-source enumeration ("what starts automatically") across Windows (Run keys, Scheduled Tasks, WMI subscriptions), Linux (cron/systemd timers, XDG autostart), and macOS (launchd, Login Items) — the versioned 34-source catalog, row/status semantics, and real-hardware verification |
```

## Sink-manifest row (re-verified against `docs/agent-spawn-sink-manifest.md`'s current schema, unchanged since P13)

| Site ID | Location | Mechanism | Platform | Provenance | Mutating | Shell features | Privilege | Ladder review | Rung + evidence | Registration |
|---|---|---|---|---|---|---|---|---|---|---|
| `autoruns/collect_linux#1` | `agents/plugins/autoruns/src/autoruns_linux.cpp:collect_linux` | runner argv | Linux | compile-time literal argv | read-only | none — no pipeline/redirection; `--all`/`--no-pager`/`--no-legend` are direct argv flags, not shell syntax | none | no rung-1 API for this data on this OS in this plugin; the rung-1 path (reading the systemd unit directories directly) is attempted first and only falls back here when all three are unreadable | 2 — direct argv via yuzu::agent::run_bounded_subprocess; rung 1 passed over: no rung-1 API for systemd timer enumeration in this plugin, and the rung-1 directory-read path is unavailable on this host; rung 3 avoided: no shell hop, argv resolved via probe_tool_path | n/a |

## SOC2 data-inventory row

For whichever "Agent-side, transient" data-inventory table exists or is
added alongside the server-side SQLite/PostgreSQL tables
(`docs/enterprise-readiness-soc2-first-customer.md`):

| Source | Data class | Where it lives | Retention | Deletion mechanism |
|---|---|---|---|---|
| `autoruns.list` (agent-side, transient) | Persistence-source metadata: file paths, registry key names/values, task/service names, command lines and arguments; user-scope rows (`win_run_hku`/`win_runonce_hku`/`win_startup_approved`, Linux per-user crontabs/systemd-user/XDG-user, macOS `~/Library/LaunchAgents`) carry the profile/user name in the `user` field | Not stored on the agent between runs — computed fresh per invocation, streamed to the caller | None on the agent (nothing persisted). If the result transits the **response store** (an operator running this via the instruction engine), it is retained under the standard response retention (`response_retention_days`, default 90 d) — the same annotation pattern as the per-application-image-names row (`docs/enterprise-readiness-soc2-first-customer.md:469`) — because a `list` row can name a specific user's autorun entries, not just machine-wide facts. | Response-store rows follow that store's existing erasure path; no agent-side erasure needed since nothing is retained there. |

## Expected capmatrix rows (for the integrator's Linux-regen diff)

`tools/capmatrix-gen` reads `YuzuActionDescriptor` capability declarations
directly — never this doc — but these are the exact markdown table rows
(`capmatrix_gen.cpp`'s own `escape_cell`/`support_name` output: lowercase
support, `\|`-escaped pipes, `\\`-escaped backslashes, generator's own
linux/macos/windows leg order) the regenerated block should produce once
all three legs (P12/P13/P14) plus this package's descriptor notes are
wired in and the generator runs on the canonical Linux host. `mechanism`
is column 6, the full descriptor `notes`/fallback text is column 7 —
both copied verbatim from `kActionDescriptors` after this package's edit:

| autoruns | list | linux | supported | 1 | file reads of cron/anacron/at/systemd unit dirs/XDG autostart; systemctl list-timers argv fallback only when no unit dir is readable | Every acquisition is a bounded local file read or directory listing (read_file_bounded, O_NOFOLLOW on the leaf) except one declared exception: systemd timer enumeration is a tri-state on /run/systemd/system -- absent reports UNSUPPORTED (no_systemd), a stat() error other than ENOENT reports CONSTRAINED (systemd_state_undetermined), and present reads /etc/systemd/system, /usr/lib/systemd/system and /lib/systemd/system directly. Only when systemd is present but all three dirs are unreadable does it fall back to `systemctl list-timers --all --no-pager --no-legend` (rung 2, autoruns/collect_linux#1, docs/agent-spawn-sink-manifest.md), whose rows carry enabled=unknown -- that text has no wants-symlink evidence. Real captures (2026-09-07): this Mac reports the Linux source through the foreign-OS stub as lnx_systemd_timers_system\|unsupported\|0\|foreign_os (this build cannot exercise the leg at all); a real ubuntu:24.04 Docker container read lnx_systemd_timers_system\|unsupported\|0\|no_systemd -- the container has no init system at all, so this confirms the absent branch; the rung-2 fallback itself needs a host with systemd present but its unit dirs unreadable, not exercised here. `absent` (ENOENT) on /etc/crontab and /etc/anacrontab reports CONSTRAINED (their absence is itself a real constraint, classify_read_error's required_by_catalog=true); the same ENOENT on every other file/dir source reports SUPPORTED (nothing there is a valid, fully-read answer) -- a genuine read failure (permission_denied or any other errno) always reports CONSTRAINED with that token, never folded into `absent`. lnx_init_d lists /etc/init.d script names only (no runlevel/systemctl wiring cross-check) -- CONSTRAINED by design, per-user reads report owning uid numerically (no NSS/getpwuid_r lookup, no directory-service deadline risk on this read-only path). |

| autoruns | list | macos | supported | 1 | CFPropertyListCreateWithData over launchd plists; file reads of /etc/periodic, /etc/emond.d | File-truth only, rung 1: CFPropertyListCreateWithData over launchd plists (system + per-user LaunchDaemons/LaunchAgents), /etc/periodic directory listings, and /etc/emond.d/rules plists. Login Items is CONSTRAINED -- the list lives in a private per-user BTM database with no public read API; this leg never shells out to osascript, launchctl, or sfltool. A plist's own Disabled key is read, but launchctl print-disabled's separate override database is NOT consulted -- this is file truth, not launchd's live runtime state, a deliberate divergence from a services-style plugin that does read launchctl state. Real capture on this Mac (2026-09-07): mac_system_launchdaemons\|supported\|422, mac_system_launchagents\|supported\|456, mac_launchdaemons\|supported\|2, mac_user_launchagents\|supported\|1, mac_launchagents\|supported\|0, mac_periodic\|supported\|0, mac_emond\|supported\|0, mac_login_items\|constrained\|0\|btm_private_database_no_public_api -- login items always emits that one constrained status line and zero rows, never a real read attempt (docs/user-manual/autoruns.md has the full `source\|` capture). |

| autoruns | list | windows | supported | 1 | Reg*W over HKLM + every HKU via win_profiles with_user_hive; ITaskService COM; WMI root\\subscription bounded query | Reg*W over HKLM plus every reachable HKU hive via win_profiles.hpp's with_user_hive ladder (live hive first; offline RegLoadKeyW under SeBackup/SeRestore -- enabled on the process token for the offline arm only, serialised process-wide by offline_hive_mutex() -- when the profile is not logged in; unload_failed is surfaced as a warning line, never dropped, when RegUnLoadKeyW fails on the way out). ITaskService COM (yuzu::shared::win::ComInit, COINIT_MULTITHREADED, no dedicated STA thread) and a bounded WMI root\\subscription query, one row per __FilterToConsumerBinding joined on the ref Name -- a dangling ref still emits its row, tagged constrained\|unresolved_ref, never dropped or collapsed into another binding's row. A1's the-rig probe (tests/unit/fixtures/wave7/probes/the-rig-probe-findings.md, 2026-09-06), Probe 3, quoted verbatim for the LocalSystem session: CoInitializeEx/Connect/GetFolder HRESULT 0x00000000, 322 tasks recursively enumerated (COINIT_MULTITHREADED and COINIT_APARTMENTTHREADED gave identical HRESULTs and counts -- MTA is not a problem for ITaskService here, including as LocalSystem); WMI root\\subscription ConnectServer/ExecQuery HRESULT 0x00000000, Next() 0x00000001 (WBEM_S_FALSE) after exactly 1 binding -- the same stock 'SCM Event Log Filter'/'SCM Event Log Consumer' binding the admin session saw, confirming LocalSystem reaches both APIs with no apartment-model or session-identity gap. CoInitializeEx itself failing is the one COM failure this leg cannot render as a real hr_<hex> token (ComInit::ok() exposes no HRESULT) -- reported as the fixed sentinel hr_cominit_failed; every other COM/WMI failure carries the real HRESULT or wmi_bounded.hpp's error token. Zero spawn primitives: schtasks.exe, wmic.exe and PowerShell are never invoked. Real-hardware verification: docs/wave7/rig-checklist-autoruns-win.md's 10-step checklist. |

| autoruns | catalog | linux | supported | 1 | file reads of cron/anacron/at/systemd unit dirs/XDG autostart; systemctl list-timers argv fallback only when no unit dir is readable | Pure reflection of this build's static kSourceCatalog declarations for the Linux sources above -- no OS call. See the `list` descriptor's note for what those declarations mean once `list` actually runs each mechanism. |

| autoruns | catalog | macos | supported | 1 | CFPropertyListCreateWithData over launchd plists; file reads of /etc/periodic, /etc/emond.d | Pure reflection of this build's static kSourceCatalog declarations for the macOS sources above -- no OS call. See the `list` descriptor's note for what those declarations mean once `list` actually runs each mechanism. |

| autoruns | catalog | windows | supported | 1 | Reg*W over HKLM + every HKU via win_profiles with_user_hive; ITaskService COM; WMI root\\subscription bounded query | Pure reflection of this build's static kSourceCatalog declarations for the Windows sources above -- no OS call itself, but the same LocalSystem session this build's ITaskService/WMI mechanism relies on is A1's the-rig probe (tests/unit/fixtures/wave7/probes/the-rig-probe-findings.md, 2026-09-06), Probe 3, quoted verbatim: CoInitializeEx/Connect/GetFolder HRESULT 0x00000000, 322 tasks recursively enumerated (COINIT_MULTITHREADED and COINIT_APARTMENTTHREADED gave identical HRESULTs and counts); WMI root\\subscription ConnectServer/ExecQuery HRESULT 0x00000000, Next() 0x00000001 (WBEM_S_FALSE) after exactly 1 binding. See the `list` descriptor's note for the full per-source `list` behaviour this catalog entry declares support for. |

These are leg-level (per `YuzuActionDescriptor`) rows — `supported` at
rung 1 on every OS for both actions, matching `kActionDescriptors` in
`autoruns_plugin.cpp` after this package's edit. The PER-SOURCE picture
(`mac_login_items` constrained, `lnx_init_d` constrained, etc.) lives in
`kSourceCatalog` (`autoruns_catalog.hpp`, unowned by this package, already
correct) and in `docs/user-manual/autoruns.md`'s source table — it is a
finer grain than capmatrix's per-action cells and is not expected to change
those six `supported`/rung-1 leg-level rows.

## Real capture evidence this package's descriptor text and manual are grounded on

- **This Mac (macOS, real `autoruns.dylib` via `LocalDispatcher`, 2026-09-07):**
  `mac_system_launchdaemons|supported|422`, `mac_system_launchagents|supported|456`,
  `mac_launchdaemons|supported|2`, `mac_user_launchagents|supported|1`,
  `mac_launchagents|supported|0`, `mac_periodic|supported|0`,
  `mac_emond|supported|0`, `mac_login_items|constrained|0|btm_private_database_no_public_api`.
- **Real `ubuntu:24.04` Docker container (a standalone harness linking the
  real `collect_linux` plus a minimal, non-shipped subprocess-runner stub,
  run against the container's actual filesystem, 2026-09-07):**
  `lnx_etc_crontab|constrained|0|absent`, `lnx_cron_d|supported|2|-`,
  `lnx_cron_periodic|supported|2|-`, `lnx_user_crontabs|supported|0|absent`,
  `lnx_anacrontab|constrained|0|absent`, `lnx_at_spool|supported|0|absent`,
  `lnx_systemd_timers_system|unsupported|0|no_systemd`,
  `lnx_systemd_timers_user|unsupported|0|no_systemd`,
  `lnx_xdg_autostart_system|supported|0|absent`,
  `lnx_xdg_autostart_user|supported|0|-`, `lnx_rc_local|unsupported|0|absent`,
  `lnx_init_d|constrained|1|listing_only`. This container has no init
  system, so it confirms the tri-state's `absent` branch, not the rung-2
  `systemctl list-timers` fallback — that needs a host with systemd present
  but every unit dir unreadable, which was not available.
- **Windows:** A1's the-rig probe (`tests/unit/fixtures/wave7/probes/
  the-rig-probe-findings.md`), Probe 3, under LocalSystem — quoted verbatim
  in the plugin's own Windows descriptor note. No live `list` run against
  the real `autoruns.dll` on the-rig exists yet (a concurrent verification
  agent is building it this run); `docs/wave7/rig-checklist-autoruns-win.md`
  is the 10-step real-hardware checklist for whoever runs that build.

## Projected PR7.1 LOC

```
git diff --stat origin/dev -- agents/plugins/autoruns server/core/src/capability_decls/plugin_action_catalogue_autoruns.hpp content/definitions/autoruns.yaml tests/unit/test_autoruns* docs/user-manual/autoruns.md
```

run against this package's own worktree (P11-P14's files already integrated
there, per this package's `depends_on`): **6,675 lines added, 0 deleted, 18
files** — slightly over the ~6.5k target (by ~175 lines, ~2.7%). Largest
files: `tests/unit/test_autoruns_parsers.cpp` (633), `test_autoruns_win_local.cpp`
(334), `test_autoruns_macos_local.cpp` (314), `test_autoruns_local_dispatcher.cpp`
(202) — the test surface, not this package's docs (`autoruns.md` is ~290
lines after this fix round, the changelog one line). The integrator should
re-run the exact command above once all four packages are actually merged
(this number is from the worktree, not the merged branch) and decide
whether the ~1.6% overage needs trimming before raising PR7.1 or is within
the "~" ceiling's own tolerance.
