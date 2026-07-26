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
interim site — ADR-3002 Decisions 1 and 2). No site-level rows yet.

| Site ID | Location | Mechanism | Platform | Provenance | Mutating | Shell features | Privilege | Ladder review | Rung + evidence | Registration |
|---|---|---|---|---|---|---|---|---|---|---|

## Seed inventory — known spawn surfaces awaiting transcription

Plugin-granularity seed from the ADR-3002 review inventory (dev @ 2026-07-23,
27 raw-spawning plugins of 49; three further plugins exec directly through
private helpers). Site-level transcription is #2380's first work item —
these rows are pointers, not evidence.

**Raw `popen`/`system` helpers:** antivirus, bitlocker, certificates,
device_identity, discovery, event_logs, firewall, hardware, installed_apps,
interaction, ioc, license_scan, network_actions, network_config,
network_diag, os_info, processes, quarantine, sccm, services,
software_actions, tar, users, vuln_scan, wifi, windows_updates, wol.
(`vuln_scan` carries code slated for retirement per ADR-0028/ADR-0018 —
sequence that cleanup against migrating it, tracked in #2380.)

**Direct exec via private helpers:** script_exec, content_dist, filesystem
(filesystem is fully migrated onto the runner on the #2321 branch).

**Agent-core sites:** trigger_engine (2 sites), dex_linux_collector,
dex_macos_collector.
