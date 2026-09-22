# browser_inventory

<!-- BEGIN GENERATED: plugin-doc-gen header -->
| | |
|---|---|
| **What it does** | Chromium-family browser and profile inventory |
| **Version** | 1.0.0 |
| **Kind** | Collector · read-only · gathered (crossplatform.browser_inventory.browsers, crossplatform.browser_inventory.profiles) |
| **Platforms** | Windows 🟡 planned · macOS 🟡 planned · Linux ✅ |
| **Actions** | `browsers` (definition `crossplatform.browser_inventory.browsers`) · `profiles` (definition `crossplatform.browser_inventory.profiles`) |
| **Security** | securable `Forensics` · operation Read · risk High · dispatch ReadOnly · approval gate AdminOrApproval |
| **Roles** | execute: admin · author: content-author |
<!-- END GENERATED -->

## How it works

`browsers` and `profiles` are two independent reads, dispatched and gated separately — a failure in one never blocks the other. On Linux this wave, `browsers` checks presence of the known Chromium-family system-wide binaries (`google-chrome`, `microsoft-edge`, `chromium`) and emits one row per candidate, present or not, with version always `-` (no version/channel probe in this package). `profiles` walks every discoverable OS user's `~/.config/{google-chrome,chromium,microsoft-edge}` directory and reads that browser's `Local State` JSON, emitting one row per profile directory listed in `profile.info_cache`; no profile directory is opened and no file inside one is read. Every action's wire stream leads with a `status|<action>|<supported|constrained>|<reason>` row before any data row (the same CC-07 typed-status pairing `peripherals`/`autoruns` use), so a consumer never reads silence and infers "nothing checked." macOS and Windows legs — including Safari on macOS — are PLANNED and follow as their own PR; Firefox follows separately on every OS. Every row is Forensics-gated, single-target, and DEFAULT-OFF behind the server-side plugin-config kill switch until an operator explicitly enables it.

**PRIVACY CONTRACT.** No row this plugin emits, on any action or any OS leg, ever carries an account identifier, browsing history, cookies or bookmarks — no `user_name`, no `gaia_id`, no e-mail address. This is enforced structurally in `browser_inventory_parsers.hpp`: `BrowserProfileRow` simply has no such field, so there is no code path that could put one on the wire. No leg opens any file inside a profile directory (`Preferences`, `Secure Preferences`, `History`, `Cookies`, ...) — see caveat 3.

**WHY Forensics, not Inventory.** Unlike a plain installed-software inventory, this plugin reads per-user browser profile state for a SINGLE named machine — the kind of evidence a rogue or compromised operator identity could otherwise use to fingerprint a target's activity undetected (which browsers and browser profiles exist on a specific user's account). That is the same operator-triage rationale `execution_artifacts` and `app_usage` already carry, and this plugin shares their exact `Forensics:Read`/`AdminOrApproval` boundary — see `server/core/src/capability_decls/plugin_action_catalogue_browser_inventory.hpp` for the fuller rationale, copied field-for-field from `execution_artifacts`'.

```mermaid
flowchart LR
  OP[Operator / workflow<br/>dispatches definition] --> SRV[Server<br/>authz: Forensics.Read<br/>AdminOrApproval · single-target only<br/>kill switch must be enabled]
  SRV -- gRPC mTLS --> HOST[Agent plugin host]
  HOST --> EX[browser_inventory.execute]
  EX --> BR[browsers leg<br/>binary presence check]
  EX --> PR[profiles leg<br/>Local State JSON read]
  BR & PR --> ROWS[rows + typed result status] --> RS[(ResponseStore)] --> API[REST /api/responses]
```

## OS capability

<!-- BEGIN GENERATED: plugin-doc-gen capability -->
| Action | Windows | macOS | Linux |
|---|---|---|---|
| `browsers` | 🟡 planned · rung 1 · ProfileList walk + %LOCALAPPDATA% User Data; Program Files Application\\<semver> dirs | 🟡 planned · rung 1 · /Applications/{Google Chrome,Microsoft Edge}.app Info.plist + ~/Library/Application Support/{Google/Chrome,Microsoft Edge} walk; Safari bundle + .appex containers | 🟡 constrained · rung 1 · ~/.config/{google-chrome,microsoft-edge} directory presence |
| `profiles` | 🟡 planned · rung 1 · ProfileList walk + %LOCALAPPDATA% User Data; Program Files Application\\<semver> dirs | 🟡 planned · rung 1 · /Applications/{Google Chrome,Microsoft Edge}.app Info.plist + ~/Library/Application Support/{Google/Chrome,Microsoft Edge} walk; Safari bundle + .appex containers | ✅ supported · rung 1 · ~/.config/{google-chrome,microsoft-edge}/Local State JSON read |

**Declared limits per leg** (descriptor fallback text, verbatim):

- **`browsers` / Windows** — follows as its own PR
- **`browsers` / macOS** — follows as its own PR
- **`browsers` / Linux** — presence-only; no version/channel detection in this package
- **`profiles` / Windows** — follows as its own PR
- **`profiles` / macOS** — follows as its own PR
<!-- END GENERATED -->

## Privileges and prerequisites

| OS | Runs as | Extra grant needed | Measured | If the read is refused |
|---|---|---|---|---|
| Windows | agent service account (LocalSystem today, #1442) | n/a this wave — the Windows leg is a FINAL placeholder; real implementation and its own privilege measurement follow as its own PR | not measured (no mechanism exists yet) | always the PLANNED sentinel row, `UNAVAILABLE`/`PARTIAL` |
| macOS | agent service account | n/a this wave — the macOS leg (including Safari) is a FINAL placeholder; real implementation and its own privilege measurement follow as its own PR | not measured (no mechanism exists yet) | always the PLANNED sentinel row, `UNAVAILABLE`/`PARTIAL` |
| Linux | agent service account | None — every read is an unprivileged filesystem read under a discoverable OS user's own home directory (`~/.config/{google-chrome,microsoft-edge}`); no elevation, no subprocess | not yet measured on real hardware this wave (Chrome fixtures are SYNTHETIC, sign-off 2026-09-21 — neither browser is installed on the build host; see Caveats) | `constrained` with a named reason (`ConstraintAccumulator`-sourced, e.g. a directory-open or file-read failure token) — a genuinely absent browser or user reports absent/zero rows, distinct from `constrained` |

No external binaries, no subprocesses, no network access on the Linux leg — every call is an in-process filesystem read and JSON parse. This plugin performs no authorization of its own: `Forensics:Read`/`AdminOrApproval`/single-target enforcement lives at the server dispatch layer (`server/core/src/dispatch_destructive_gate.hpp`), and every read is additionally gated behind the server-side plugin-config kill switch (`PluginConfigStore::seed_kill_switch_default_off`), which is OFF until an operator explicitly enables it.

## Data contract

### Inputs

<!-- BEGIN GENERATED: plugin-doc-gen inputs -->
Neither action takes parameters.
<!-- END GENERATED -->

### Outputs

Pipe-delimited rows. Every action's stream leads with a `status|<action>|<supported|constrained>|<reason>` row (CC-07 typed-status pairing), followed by zero or more data rows discriminated by their own leading tag (`browser|...`, `profile|...`); every untrusted string field (usernames, profile directory and display names) is escaped through `safe_output_field`. A directory or file that cannot be opened or read anywhere in the walk (`ConstraintAccumulator`) sets the action's `status` row to `constrained` with the accumulated reason — a genuinely absent browser install or user directory is never treated as a failure, only as fewer rows.

<!-- BEGIN GENERATED: plugin-doc-gen outputs -->
**`crossplatform.browser_inventory.browsers` — `row_kind|field_1|field_2|field_3`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `row_kind` | string | - | all | `browser` | Discriminates the row shape - "status" or "browser". |
| `field_1` | string | - | all | `google-chrome` | status row: the action name ("browsers"). browser row: the browser identifier. |
| `field_2` | string | - | all | `1` | status row: "supported" or "constrained". browser row: "1" if the binary is present, "0" otherwise. |
| `field_3` | string | - | all | `-` | status row: the constraint reason, "-" when supported. browser row: version, always "-" this wave (no version/channel probe). |

**`crossplatform.browser_inventory.profiles` — `row_kind|field_1|field_2|field_3|field_4`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `row_kind` | string | - | all | `profile` | Discriminates the row shape - "status" or "profile". |
| `field_1` | string | - | all | `jdoe` | status row: the action name ("profiles"). profile row: the owning OS user, redacted per the sample-capture convention in non-sample contexts this is the real local username. |
| `field_2` | string | - | all | `google-chrome` | status row: "supported" or "constrained". profile row: the browser identifier. |
| `field_3` | string | - | all | `Default` | status row: the constraint reason, "-" when supported. profile row: the profile directory name (the Local State info_cache key), e.g. "Default", "Profile 1". |
| `field_4` | string | - | all | `Work` | status row: empty. profile row: the profile's user-editable display name. |
<!-- END GENERATED -->

### Result status

| Status | Completeness | Provenance | When |
|---|---|---|---|
| `OK` | full | *(empty)* | The leg's walk completed with no unreadable directory or malformed file anywhere along the way (`status\|supported\|-`). |
| `CONSTRAINED` | partial | `linux:browser_inventory:local_state_malformed` · `linux:browser_inventory:busy` · `linux:browser_inventory:not_a_directory` · `linux:browser_inventory:not_regular` · `linux:browser_inventory:open_failed` · `linux:browser_inventory:permission_denied` · `linux:browser_inventory:readdir_error:home` · `linux:browser_inventory:row_cap:home` · `linux:browser_inventory:symlink_refused` | A `Local State` file existed but failed to parse as valid JSON, or a directory in the walk (a user's config directory, a browser's data directory) could not be opened, read, or safely followed (symlink refusal, non-directory, non-regular file, busy/locked, permission denied, a `readdir` failure, or the per-user row cap) for a reason other than benign absence. |
| `UNAVAILABLE` | partial | `macos:planned` · `windows:planned` | macOS and Windows, every action, this wave — both legs are FINAL placeholders; the real implementation (including Safari on macOS) follows as its own PR. The row itself is `status\|<action>\|unsupported\|<os_tag>:planned`. |

### Where the data goes

- **Instruction result only.** Rows travel over the agent's mTLS gRPC channel as the command response, land in the ResponseStore, and are queryable at `/api/responses/{id}` — single-target only; fleet or scope targeting is refused at the server dispatch layer before this plugin ever runs.
- **Not consumed by** daily-sync inventory, the TAR warehouse, DEX, or metrics. Nothing here runs on a schedule; each action dispatches only when an operator or workflow explicitly requests it, and only once the plugin-config kill switch is enabled.
- **Sensitivity.** `profiles` rows name a real local OS username and real browser profile identity for a single named machine — they let a reader reconstruct which browsers and profiles a specific person on that machine uses, which is exactly the kind of per-user fingerprint an unauthorized reader could misuse, even though no account identifier, browsing history or cookie is ever included (see the PRIVACY CONTRACT above).
- **Siblings:** `execution_artifacts` and `app_usage` are the other Forensics-gated, default-off evidence sources in the catalogue; none share a store or a format with this plugin.
- **MCP / REST.** Discover: `discover_plugins` (summary) → `yuzu://plugin-docs` (this page as data) → `discover_instructions` / `get_definition("crossplatform.browser_inventory.profiles")`. Run: `execute_instruction {definition_id, parameters}` (single explicit `agent_id` required). Read: `/api/responses/{id}`.

## Sample output

<!-- BEGIN GENERATED: plugin-doc-gen samples -->
**Linux** — captured: linux Debian GNU/Linux 13 (trixie) aarch64 · container · 2026-09-22 · euid 0 · leg-hash 4bbe3a481e62

```
== action=browsers
status|browsers|supported|-
browser|chrome|0|-
browser|edge|0|-
browser|chromium|0|-
[result_status] OK / FULL

== action=profiles
status|profiles|supported|-
[result_status] OK / FULL
```
<!-- END GENERATED -->

## Caveats and known gaps

1. **macOS and Windows legs — including Safari on macOS — are PLANNED, not implemented, this wave.** Every action on those two OSes returns the fixed `status|<action>|unsupported|<os_tag>:planned` sentinel and `UNAVAILABLE`/`PARTIAL`; the real per-OS reads (macOS: `/Applications/{Google Chrome,Microsoft Edge}.app` Info.plist + `~/Library/Application Support/{Google/Chrome,Microsoft Edge}` walk, plus the Safari bundle/`.appex` containers; Windows: `ProfileList` walk + `%LOCALAPPDATA%` User Data, plus `Program Files\Application\<semver>` dirs) each follow as their own PR. Firefox is out of scope for every leg in this package and follows separately.
2. **Chrome fixtures are SYNTHETIC; Microsoft Edge fixtures are a REAL CAPTURE (the-rig, reduced and redacted).** Neither Chrome nor Firefox is installed on the build host this wave, so Alex explicitly signed off SYNTHETIC Chrome fixtures on 2026-09-21 (run-context.md Phase-0 item 2) on condition they mirror the real Edge capture's on-disk shape (`tests/unit/fixtures/wave10/browser_inventory/chrome/`, every file's `_provenance` key states SYNTHETIC or RECONSTRUCTION). The Edge fixtures (`tests/unit/fixtures/wave10/browser_inventory/edge/`) are a real the-rig capture of `Local State`, reduced (subtrees dropped) and redacted (account/host values replaced) before being committed — see that directory's `provenance.txt` for the full capture log and hash chain.
3. **The `extensions` action is deferred and follows as its own PR.** This release reads no file inside any profile directory — only each browser's `Local State` at the browser root — so no extension id, name, version or enable state is emitted anywhere. The per-profile `Secure Preferences`/`Preferences` read, its parser, fixtures and tests land together with that action; the real Edge capture behind it showed `extensions.settings` lives in `Secure Preferences` only, which is what that parser will prefer.
4. **DEFAULT-OFF behind the server-side plugin-config kill switch.** Neither action dispatches until an operator explicitly `PUT`s `/api/v1/plugin-config/browser_inventory/kill-switch {"enabled":true}` — on a fresh install or an unconfigured fleet, every dispatch attempt is refused at the server layer, not reported as a plugin-level failure.
5. **Linux `browsers` is presence-only this wave.** It detects whether the known system-wide binary paths exist; it does not probe the installed version or release channel (descriptor rung 1) — a distinct value-add over `installed_apps`' broader inventory that this plugin does not yet close.

## Source and tests

<!-- BEGIN GENERATED: plugin-doc-gen source -->
- Plugin: `agents/plugins/browser_inventory/src/browser_inventory_legs.hpp` · `agents/plugins/browser_inventory/src/browser_inventory_linux.cpp` · `agents/plugins/browser_inventory/src/browser_inventory_linux_parsers.hpp` · `agents/plugins/browser_inventory/src/browser_inventory_macos.cpp` · `agents/plugins/browser_inventory/src/browser_inventory_parsers.hpp` · `agents/plugins/browser_inventory/src/browser_inventory_plugin.cpp` · `agents/plugins/browser_inventory/src/browser_inventory_win.cpp`
- Definitions: `content/definitions/browser_inventory.yaml`
- Capability rows: `server/core/src/capability_decls/plugin_action_catalogue_browser_inventory.hpp`
- Tests: `tests/unit/test_browser_inventory_linux_parsers.cpp` · `tests/unit/test_browser_inventory_local_dispatcher.cpp` · `tests/unit/test_browser_inventory_parsers.cpp`
- Privilege row: `docs/agent-privilege-model.md`
<!-- END GENERATED -->
