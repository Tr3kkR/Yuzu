# Wave 2 handoff — WP-A (users plugin: zero raw spawn)

WP-A takes `agents/plugins/users/src/users_plugin.cpp` to zero raw spawn
sites: Windows `primary_user`/`session_history` now read the Security
channel natively via wevtapi (`EvtQuery`/`EvtNext`/`EvtRender`), the Windows
`primary_user` fallback reads `ProfileList` via `agents/shared/win_profiles.hpp`,
and every POSIX site runs through a new `run_tool()` direct-argv helper
(`yuzu::agent::run_bounded_subprocess`, no shell). `run_command()` — including
its `#ifdef _WIN32` `_popen` branch — is deleted entirely.

New files: `agents/plugins/users/src/users_win_events.hpp` (pure Security-
channel XML parsers, no Windows headers, no I/O) and
`tests/unit/test_users_win_events.cpp`. WP-A does not own `tests/meson.build`
— the integrator wires the new test TU in, per below.

## tests/meson.build

Append this line to `agent_test_exe`'s `files(...)` source list (the
`agents/plugins/users/src` include path is already on that target from the
`qe-M1` `users_macos_last.hpp` entry, so no new `include_directories` is
needed):

```
'unit/test_users_win_events.cpp',      # Wave-2 WP-A: pure wevtapi Security-channel XML parsers
```

## Session-history timestamp correction (behaviour change, not a silent one)

`session_history`'s `time` field's **value** changes on Windows, though the
row **shape** stays byte-identical. The pre-migration text-mode parser
(`wevtutil qe ... /f:text`) read the `Date:` line, which is local time with a
`Z` suffix stamped on it regardless — a pre-existing correctness defect —
and a rounded fractional second. The new wevtapi path reads
`<TimeCreated SystemTime='...'/>` from `/f:xml`-shaped `EvtRender` output,
which is true UTC at full precision. Verified on the same underlying event
across the prestage captures
(`~/.claude/wave2-prestage/fixtures/windows/fx_wevtutil_4624_text.txt` vs.
`fx_wevtutil_4624_xml.xml`, same `EventRecordID`):

```
text mode (old): Date: 2026-08-14T21:10:49.4170000Z   (local time, mislabelled Z, rounded)
xml mode (new):  SystemTime='2026-08-14T20:10:49.4173297Z'  (true UTC, full precision)
```

Suggested `changelog.d/` entry (WP-A does not own `changelog.d/**`):

`changelog.d/wave2-wpa-users-runner-migration.changed.md`:
```
- **`users` plugin: zero raw process spawns.** Windows `primary_user`/
  `session_history` now read the Security event log natively via wevtapi
  (`EvtQuery`/`EvtRender`) instead of shelling out to `wevtutil`; the
  `primary_user` ProfileList fallback reads the registry natively via
  `agents/shared/win_profiles.hpp` instead of `reg query`. Every POSIX call
  site (`dscl`/`last`/`lastlog`/`who`/`w`) now runs through a bounded
  direct-argv runner instead of a `/bin/sh -c` shell hop — no shell-quoting
  surface, ADR-3002 rung 2. **Behaviour change:** `session_history`'s `time`
  field on Windows now carries the Security event's true UTC timestamp at
  full precision, instead of the old text-parser's local time mis-stamped
  with a trailing `Z` and rounded to the nearest 100us. The row shape is
  unchanged.
```

## Spawn-site manifest

Rows below are transcribed to the canonical schema of
`docs/agent-spawn-sink-manifest.md` (see its "Row schema" section) for the
integrator to paste into that file's "Registered sites" table — WP-A does
not own `docs/**`. All 14 sites are read-only, with no deadline/grace
escalation.

| Site ID | Location | Mechanism | Platform | Provenance | Mutating | Shell features | Privilege | Ladder review | Rung + evidence | Registration |
|---|---|---|---|---|---|---|---|---|---|---|
| `users/do_logged_on#1` | `agents/plugins/users/src/users_plugin.cpp:do_logged_on` | runner argv | macOS | compile-time literal argv | read-only | none — redirection eliminated (2>/dev/null -> merge_stderr=false) | none | no rung-1 API for this data on this OS in this plugin | 2 — direct argv via yuzu::agent::run_bounded_subprocess; rung 1 passed over: no rung-1 API for this data on this OS in this plugin | n/a |
| `users/do_sessions#1` | `agents/plugins/users/src/users_plugin.cpp:do_sessions` | runner argv | Linux | compile-time literal argv | read-only | none — redirection eliminated (2>/dev/null -> merge_stderr=false) | none | no rung-1 API for this data on this OS in this plugin | 2 — direct argv via yuzu::agent::run_bounded_subprocess; rung 1 passed over: no rung-1 API for this data on this OS in this plugin | n/a |
| `users/do_sessions#2` | `agents/plugins/users/src/users_plugin.cpp:do_sessions` | runner argv | macOS | compile-time literal argv | read-only | none — redirection eliminated (2>/dev/null -> merge_stderr=false) | none | no rung-1 API for this data on this OS in this plugin | 2 — direct argv via yuzu::agent::run_bounded_subprocess; rung 1 passed over: no rung-1 API for this data on this OS in this plugin | n/a |
| `users/do_local_users#1` | `agents/plugins/users/src/users_plugin.cpp:do_local_users` | runner argv | Linux | compile-time literal + account name derived from a local-system enumeration (dscl -list / getpwent) | read-only | none — pipeline eliminated (tail -1 replicated in-process, last non-empty line; max_lines caps the FIRST N and would invert the selection) | none | no rung-1 API for this data on this OS in this plugin | 2 — direct argv via yuzu::agent::run_bounded_subprocess; rung 1 passed over: no rung-1 API for this data on this OS in this plugin | n/a |
| `users/do_local_users#2` | `agents/plugins/users/src/users_plugin.cpp:do_local_users` | runner argv | macOS | compile-time literal argv | read-only | none — redirection eliminated (2>/dev/null -> merge_stderr=false) | none | no public OpenDirectory C API in-tree; .mm ruled out of this run by the architect | 2 — direct argv via yuzu::agent::run_bounded_subprocess; rung 1 passed over: no public OpenDirectory C API in-tree, .mm ruled out this run | n/a |
| `users/do_local_users#3` | `agents/plugins/users/src/users_plugin.cpp:do_local_users` | runner argv | macOS | compile-time literal + account name derived from a local-system enumeration (dscl -list / getpwent) | read-only | none — redirection eliminated (2>/dev/null -> merge_stderr=false) | none | no public OpenDirectory C API in-tree; .mm ruled out of this run by the architect | 2 — direct argv via yuzu::agent::run_bounded_subprocess; rung 1 passed over: no public OpenDirectory C API in-tree, .mm ruled out this run | n/a |
| `users/do_local_users#4` | `agents/plugins/users/src/users_plugin.cpp:do_local_users` | runner argv | macOS | compile-time literal + account name derived from a local-system enumeration (dscl -list / getpwent) | read-only | none — redirection eliminated (2>/dev/null -> merge_stderr=false) | none | no public OpenDirectory C API in-tree; .mm ruled out of this run by the architect | 2 — direct argv via yuzu::agent::run_bounded_subprocess; rung 1 passed over: no public OpenDirectory C API in-tree, .mm ruled out this run | n/a |
| `users/do_local_users#5` | `agents/plugins/users/src/users_plugin.cpp:do_local_users` | runner argv | macOS | compile-time literal + account name derived from a local-system enumeration (dscl -list / getpwent) | read-only | none — env-var prefix carried by /usr/bin/env LC_ALL=C, an exec wrapper not an interpreter | none | no rung-1 API for this data on this OS in this plugin | 2 — direct argv via yuzu::agent::run_bounded_subprocess; rung 1 passed over: no rung-1 API for this data on this OS in this plugin; rung stays 2: /usr/bin/env is an exec wrapper, not an interpreter | n/a |
| `users/do_local_admins#1` | `agents/plugins/users/src/users_plugin.cpp:do_local_admins` | runner argv | macOS | compile-time literal argv | read-only | none — redirection eliminated (2>/dev/null -> merge_stderr=false) | none | no public OpenDirectory C API in-tree; .mm ruled out of this run by the architect | 2 — direct argv via yuzu::agent::run_bounded_subprocess; rung 1 passed over: no public OpenDirectory C API in-tree, .mm ruled out this run | n/a |
| `users/do_group_members#1` | `agents/plugins/users/src/users_plugin.cpp:do_group_members` | runner argv | macOS | operator param (group), gated by is_safe_identifier | read-only | none — redirection eliminated (2>/dev/null -> merge_stderr=false) | none | no public OpenDirectory C API in-tree; .mm ruled out of this run by the architect | 2 — direct argv via yuzu::agent::run_bounded_subprocess; rung 1 passed over: no public OpenDirectory C API in-tree, .mm ruled out this run | n/a |
| `users/do_primary_user#1` | `agents/plugins/users/src/users_plugin.cpp:do_primary_user` | runner argv | Linux | compile-time literal argv | read-only | none — pipeline eliminated (head -200 -> max_lines=200, stop_after_max_lines=true) | none | no rung-1 API for this data on this OS in this plugin | 2 — direct argv via yuzu::agent::run_bounded_subprocess; rung 1 passed over: no rung-1 API for this data on this OS in this plugin | n/a |
| `users/do_primary_user#2` | `agents/plugins/users/src/users_plugin.cpp:do_primary_user` | runner argv | macOS | compile-time literal argv | read-only | none — pipeline eliminated (head -200 -> max_lines=200, stop_after_max_lines=true) | none | no rung-1 API for this data on this OS in this plugin | 2 — direct argv via yuzu::agent::run_bounded_subprocess; rung 1 passed over: no rung-1 API for this data on this OS in this plugin | n/a |
| `users/do_session_history#1` | `agents/plugins/users/src/users_plugin.cpp:do_session_history` | runner argv | Linux | operator param (count), numeric | read-only | none — redirection eliminated (2>/dev/null -> merge_stderr=false) | none | no rung-1 API for this data on this OS in this plugin | 2 — direct argv via yuzu::agent::run_bounded_subprocess; rung 1 passed over: no rung-1 API for this data on this OS in this plugin | n/a |
| `users/do_session_history#2` | `agents/plugins/users/src/users_plugin.cpp:do_session_history` | runner argv | macOS | operator param (count), numeric | read-only | none — redirection eliminated (2>/dev/null -> merge_stderr=false) | none | no rung-1 API for this data on this OS in this plugin | 2 — direct argv via yuzu::agent::run_bounded_subprocess; rung 1 passed over: no rung-1 API for this data on this OS in this plugin | n/a |

### Appendix — migration detail (not part of the canonical schema)

Carried forward unchanged from the pre-canonical-schema manifest: pre-
migration base-commit line number, old shell string, new argv, argv[0] kind
(fixed vs. `probe_tool_path`), and max_lines/stop_after_max_lines.

| # | sink id | orig line | action | platform | old mechanism | new argv | argv\[0] kind | max_lines/stop | rung | notes |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | `do_logged_on#1` | :185 | logged_on | macOS | `who 2>/dev/null` | `{who} ` | probed (`/usr/bin/who`,`/bin/who`) | 0 / false | 2 | no native macOS enumeration API in this plugin |
| 2 | `do_sessions#1` | :261 | sessions | Linux | `w -h 2>/dev/null` | `{w} -h` | probed (`/usr/bin/w`,`/bin/w`) | 0 / false | 2 | |
| 3 | `do_sessions#2` | :279 | sessions | macOS | `w -h 2>/dev/null` | `{w} -h` | probed (`/usr/bin/w`,`/bin/w`) | 0 / false | 2 | |
| 4 | `do_local_users#1` | :415 | local_users | Linux | `lastlog -u {user} 2>/dev/null \| tail -1` | `{lastlog} -u {user}` | probed (`/usr/bin/lastlog`,`/bin/lastlog`) | 0 / false | 2 | `\| tail -1` replicated in-process (last non-empty line), NOT max_lines — max_lines caps the FIRST N, which would invert the selection |
| 5 | `do_local_users#2` | :439 | local_users | macOS | `dscl . -list /Users UniqueID 2>/dev/null` | `{dscl} . -list /Users UniqueID` | fixed (`/usr/bin/dscl`) | 0 / false | 2 | |
| 6 | `do_local_users#3` | :467 | local_users | macOS | `dscl . -read /Users/{user} UserShell 2>/dev/null` | `{dscl} . -read /Users/{user} UserShell` | fixed (`/usr/bin/dscl`) | 0 / false | 2 | per-account, inside the dscl-list loop |
| 7 | `do_local_users#4` | :482 | local_users | macOS | `dscl . -read /Users/{user} RealName 2>/dev/null` | `{dscl} . -read /Users/{user} RealName` | fixed (`/usr/bin/dscl`) | 0 / false | 2 | per-account |
| 8 | `do_local_users#5` | :517 | local_users | macOS | `LC_ALL=C last -y -1 {user} 2>/dev/null` | `{env} LC_ALL=C {last} -y -1 {user}` | fixed (`/usr/bin/env`) + probed last | 0 / false | 2 | `/usr/bin/env` carries `LC_ALL=C` — `SubprocessOptions` has no env field and `LC_ALL=C` is load-bearing for `users_macos_last.hpp`'s English-locale weekday match; `env` is an exec wrapper, not an interpreter, so this stays rung 2 |
| 9 | `do_local_admins#1` | :642 | local_admins | macOS | `dscl . -read /Groups/admin GroupMembership 2>/dev/null` | `{dscl} . -read /Groups/admin GroupMembership` | fixed (`/usr/bin/dscl`) | 0 / false | 2 | |
| 10 | `do_group_members#1` | :764 | group_members | macOS | `dscl . -read /Groups/{name} GroupMembership 2>/dev/null` | `{dscl} . -read /Groups/{name} GroupMembership` | fixed (`/usr/bin/dscl`) | 0 / false | 2 | `{name}` is the operator-supplied `group` param, gated by `is_safe_identifier` before this call (unchanged) |
| 11 | `do_primary_user#1` | :844 | primary_user | Linux | `last -F 2>/dev/null \| head -200` | `{last} -F` | probed (`/usr/bin/last`,`/bin/last`) | 200 / true | 2 | `\| head -200` -> `max_lines=200, stop_after_max_lines=true` |
| 12 | `do_primary_user#2` | :881 | primary_user | macOS | `last 2>/dev/null \| head -200` | `{last}` | probed (`/usr/bin/last`,`/bin/last`) | 200 / true | 2 | same |
| 13 | `do_session_history#1` | :1009 | session_history | Linux | `last -F -n {count} 2>/dev/null` | `{last} -F -n {count}` | probed (`/usr/bin/last`,`/bin/last`) | 0 / false | 2 | `-n {count}` already bounds the tool's own output |
| 14 | `do_session_history#2` | :1051 | session_history | macOS | `last -n {count} 2>/dev/null` | `{last} -n {count}` | probed (`/usr/bin/last`,`/bin/last`) | 0 / false | 2 | same |

Note on count: the spec's prose lists these as "thirteen" call sites because
it groups rows 2 and 3 (`:261 and :279 w -h`) together as one bullet; the
code has 14 distinct call sites (14 `// sink:` comments, 14 rows above) since
`:261` and `:279` are two separate `#ifdef` branches. No functional
ambiguity — every acceptance criterion ("each surviving spawn site carries a
comment") is satisfied per physical site.

Windows sites eliminated (native replacement, not a runner argv site, so not
in the table above): `wevtutil qe Security .../EventID=4624` (`primary_user`,
orig `:919`) and `.../EventID=4624 or EventID=4634` (`session_history`, orig
`:1091`) -> `EvtQuery`/`EvtNext`/`EvtRender` against the `Security` channel
(`query_logon_events` in `users_plugin.cpp`, feeding
`yuzu::users_win::parse_logon_events`/`primary_user_from_events`/
`session_history_rows`); `reg query ".../ProfileList" /s` (`primary_user`
fallback, orig `:960`) -> `yuzu::win::enumerate_profile_records`
(`agents/shared/win_profiles.hpp`).
