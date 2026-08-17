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
| `certificates/list_certs_macos#1` | `certificates_plugin.cpp:list_certs_macos` | runner argv, single element = trusted shell script string | macOS | `cmd` built by `build_login_keychain_read_command()` from an already-allowlist-validated uid/username (local-system, not operator input) | read-only | `~user` home-directory expansion (the one feature `/bin/sh -c` is retained for) | none beyond the LaunchDaemon's existing root context (ships with no `UserName` key — runs as root today; no sudoers grant needed) | Reviewed — no rung-1/2 API reaches a per-console-user login keychain without a session hop; `security find-certificate` under `launchctl asuser`/`sudo -u` needs the shell for `~user` expansion | Rung 3 — Decision-7 governed-shell exception (ADR-3002); Decision-1 evidence: `cert_store.cpp`'s macOS post-mortem documents a prior clean-argv attempt failing to reach the per-user keychain session | Decision-7 shell exception |
| `certificates/details_cert_macos#1` | `certificates_plugin.cpp:details_cert_macos` | runner argv, single element = trusted shell script string | macOS | same as above | read-only | same as above | same as above | same as above | same as above | Decision-7 shell exception |
| `certificates/keychain_contains_thumbprint#1` | `certificates_plugin.cpp:keychain_contains_thumbprint` | runner argv (`/usr/bin/security find-certificate -a -p <path>`) | macOS | `keychain_path` is one of two fixed literal paths (`resolve_delete_keychain_path()`); no operator-controlled text reaches this argv | read-only (used for both the pre-delete presence check and the post-delete verify re-enumeration in `delete_cert_macos`) | none | none beyond the LaunchDaemon's existing root context | Reviewed — plain argv, no shell needed; already rung 2 | Rung 2 — clean multi-element argv through the bounded subprocess runner (Decision-5 registered mechanism) | Decision-5 interpreter registration (bounded runner) |
| `certificates/delete_cert_macos#1` | `certificates_plugin.cpp:delete_cert_macos` | runner argv (`/usr/bin/security delete-certificate -Z <thumbprint> <path>`) | macOS | `<thumbprint>` is hex-validated (`is_valid_thumbprint`) + canonicalized operator input; `<path>` is one of two fixed literal paths | **mutating** | none | `$ACCOUNT_NAME ALL=(root) NOPASSWD: /usr/bin/security delete-certificate -t /Library/Keychains/System.keychain *` (`scripts/install-agent-user.sh:467`) — scoped to System.keychain only; root-context LaunchDaemon needs no sudo hop today | Reviewed — plain argv, no shell needed; already rung 2 | Rung 2 — clean multi-element argv through the bounded subprocess runner | Decision-5 interpreter registration (bounded runner) |
| `certificates/parse_pem_block_macos#1` | `certificates_plugin.cpp:parse_pem_block_macos` | runner argv (`/usr/bin/openssl x509 -noout -in <tmpfile> -subject -issuer -startdate -enddate -serial -fingerprint -sha1 -text`) | macOS | `<tmpfile>` is a `yuzu::TempFile`-owned path (mkstemps/O_EXCL, mode 0600) holding one PEM block read from the login keychain — no operator text | read-only | none | none beyond the LaunchDaemon's existing root context | Reviewed — LibreSSL (the host `/usr/bin/openssl`) rejects `-ext keyUsage`, so this parses via `-text` + the shared line-selection helpers instead of certificates_x509.hpp; migrating this specific site to certificates_x509.hpp (feed it the PEM block directly, in-process) is a natural rung-1 follow-up but is OUT of this package's scope (the spec's part 6 froze the login-keychain path byte-identical) | Rung 2 — clean multi-element argv through the bounded subprocess runner | Decision-5 interpreter registration (bounded runner) |
| `certificates/resolve_console_user#1` | `certificates_plugin.cpp:resolve_console_user` | runner argv (`/usr/bin/stat -f%Su /dev/console`) | macOS | none — fixed literal argv | read-only | none | none beyond the LaunchDaemon's existing root context | Reviewed — the LaunchDaemon has no SystemConfiguration framework access (unlike `agents/plugins/users`'s `SCDynamicStoreCopyConsoleUser`), so this is the only console-user resolution mechanism available here | Rung 2 — clean multi-element argv through the bounded subprocess runner | Decision-5 interpreter registration (bounded runner) |
| `certificates/resolve_console_user#2` | `certificates_plugin.cpp:resolve_console_user` | runner argv (`/usr/bin/id -u <username>`) | macOS | `<username>` is the output of site `#1` above, allowlist-validated (`is_valid_username`) before use | read-only | none | none beyond the LaunchDaemon's existing root context | Reviewed — same constraint as `#1` | Rung 2 — clean multi-element argv through the bounded subprocess runner | Decision-5 interpreter registration (bounded runner) |

## Seed inventory — known spawn surfaces awaiting transcription

Plugin-granularity seed from the ADR-3002 review inventory (dev @ 2026-07-23,
27 raw-spawning plugins of 49; three further plugins exec directly through
private helpers). Site-level transcription is #2380's first work item —
these rows are pointers, not evidence.

**Raw `popen`/`system` helpers:** antivirus, bitlocker,
device_identity, discovery, event_logs, firewall, hardware, installed_apps,
interaction, ioc, license_scan, network_actions, network_config,
network_diag, os_info, processes, quarantine, sccm, services,
software_actions, tar, users, vuln_scan, wifi, windows_updates, wol.
(`vuln_scan` carries code slated for retirement per ADR-0028/ADR-0018 —
sequence that cleanup against migrating it, tracked in #2380.)

**Migrated off raw spawn (Wave 2, PR2.1b):** `certificates` (Linux/macOS
System+SystemRoot promoted to rung-1 libcrypto/SecItem; the login-keychain
hop stays a registered Decision-7 exception — see Registered sites above).

**Direct exec via private helpers:** script_exec, content_dist, filesystem
(filesystem is fully migrated onto the runner on the #2321 branch).

**Agent-core sites:** trigger_engine (2 sites), dex_linux_collector,
dex_macos_collector.
