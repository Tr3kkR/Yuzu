# Agent spawn sink manifest

Owner: @Doomgoose. Population tracked in #2380. Governed by ADR-3002
(`docs/adr/3002-acquisition-ladder.md`) — read that first; this file is the
standing evidence ledger it mandates, a **governance artifact, not a plan**
(sequencing lives with the migration roadmap, not here).

Every spawn call site in `agents/plugins/*` and the covered agent-core paths
gets a row. The row — not the call site — is the single authority for the
site's evidence: the call site carries only its **site ID** and a one-line
rationale in a comment. Site IDs are stable and follow
`<plugin-or-component>/<function>#<n>` (`#<n>` disambiguates multiple sites
in one function; IDs are never reused after a site is deleted).

## Row schema

| Column | Meaning |
|---|---|
| Site ID | `<plugin-or-component>/<function>#<n>` — stable, never reused |
| Location | `path/to/file.cpp:function` (line numbers drift; function names anchor) |
| Mechanism | current spawn mechanism (`popen` helper, `system()`, direct `fork/exec`, runner argv, runner Decision-5 shape) |
| Platform | which OS paths reach this site |
| Provenance | where the interpolated values come from (operator/server params, derived, local-system, compile-time literal) |
| Mutating | mutating vs read-only — drives deadline/grace policy and migration gating (ADR-3002 runner contract) |
| Shell features | which shell capabilities the site actually uses (pipeline, redirection, glob, `~user` expansion, none) |
| Privilege | sudoers grant relied on, if any (exact grant form from `scripts/install-agent-user.sh`) |
| Ladder review | does this subprocess need to exist, or does a rung-1 interface answer the same question? |
| Rung + evidence | the rung the site sits at and the ADR-3002 Decision-1 evidence for every rung passed over |
| Registration | Decision-5 interpreter registration / Decision-7 shell exception, where applicable |

## Registered sites

Populated as the migration reaches each site (and immediately for any new or
interim site — ADR-3002 Decisions 1 and 2).

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

## Seed inventory — known spawn surfaces awaiting transcription

Plugin-granularity seed from the ADR-3002 review inventory (dev @ 2026-07-23,
27 raw-spawning plugins of 49; three further plugins exec directly through
private helpers). Site-level transcription is #2380's first work item —
these rows are pointers, not evidence.

**Raw `popen`/`system` helpers:** antivirus, bitlocker, certificates,
device_identity, event_logs, firewall, hardware, installed_apps,
interaction, ioc, license_scan, network_actions, network_config,
network_diag, os_info, processes, quarantine, sccm, services,
software_actions, tar, vuln_scan, wifi, windows_updates, wol.
(`vuln_scan` carries code slated for retirement per ADR-0028/ADR-0018 —
sequence that cleanup against migrating it, tracked in #2380.)

**Migrated off raw spawn (Wave 2, PR2.1a):** `users` (Windows session
history moved to wevtapi/EvtQuery, ProfileList to native enumeration; POSIX
sites moved to direct runner argv — see Registered sites above).

**Migrated off raw spawn (Wave 2, PR2.1c):** `discovery` (0 spawn sites, was
5 — GetIpNetTable2/`/proc/net/arp`/sysctl ARP + a shared `IcmpSession`
sweep; no manifest rows since none survive).

**Direct exec via private helpers:** script_exec, content_dist, filesystem
(filesystem is fully migrated onto the runner on the #2321 branch).

**Agent-core sites:** trigger_engine (2 sites), dex_linux_collector,
dex_macos_collector.
