# browser_policy

<!-- BEGIN GENERATED: plugin-doc-gen header -->
| | |
|---|---|
| **What it does** | Enterprise-managed Chrome and Edge browser policy inventory |
| **Version** | 1.0.0 |
| **Kind** | Collector · read-only · gathered (crossplatform.browser_policy.policies) |
| **Platforms** | Windows 🟡 planned · macOS 🟡 planned · Linux ✅ |
| **Actions** | `policies` (definition `crossplatform.browser_policy.policies`) |
| **Security** | securable `Inventory` · operation Read · risk Low · dispatch ReadOnly · approval gate None |
| **Roles** | execute: endpoint-admin, endpoint-operator · author: content-author |
<!-- END GENERATED -->

## How it works

`policies` reports which enterprise-managed browser policies an administrator has configured on the device, as facts only. One `policy` row is written per configured policy: the browser (Chrome, Chromium or Edge), whether the policy is mandatory or recommended, its scope, its name, its typed value and the file it was read from. On Linux the rows come from the JSON policy files under `/etc/opt/chrome/policies`, `/etc/chromium/policies` and `/etc/opt/edge/policies`, in their `managed` and `recommended` subdirectories. Every directory below the root is opened without following symlinks, every file is read with a 1 MiB cap, and the parse is done with the vendored `nlohmann` JSON library. The plugin reads local configuration and nothing else: no subprocess, no network, no write. It enforces nothing and judges nothing; a policy is a row, not a verdict. The Windows and macOS legs are placeholders (see Caveats).

The plugin carries no default-off kill switch, on purpose: it reads operator/IT-authored config, not personal data, and carries neither gate.

```mermaid
flowchart LR
  OP[Operator / workflow] --> SRV[Server<br/>authz: Inventory.Read]
  SRV -- gRPC mTLS --> HOST[Agent plugin host] --> EX[browser_policy.execute]
  EX --> WIN[Windows leg<br/>placeholder: zero rows, UNAVAILABLE windows:planned]
  EX --> MAC[macOS leg<br/>placeholder: zero rows, UNAVAILABLE macos:planned]
  EX --> LIN[Linux leg<br/>/etc/opt/chrome, /etc/chromium, /etc/opt/edge policy JSON reads]
  WIN & MAC & LIN --> ROWS[rows + typed result status] --> RS[(ResponseStore)] --> API[REST /api/responses]
```

## OS capability

<!-- BEGIN GENERATED: plugin-doc-gen capability -->
| Action | Windows | macOS | Linux |
|---|---|---|---|
| `policies` | 🟡 planned · rung 1 · HKLM\\SOFTWARE\\Policies\\{Google\\Chrome,Microsoft\\Edge} registry reads (RegKey enumerate_value_names) | 🟡 planned · rung 1 · /Library/Managed Preferences/{,<user>/}{com.google.Chrome,com.microsoft.Edge}.plist (CFPropertyListCreateWithData) | ✅ supported · rung 1 · /etc/opt/{chrome,edge} and /etc/chromium policies/{managed,recommended}/*.json (nlohmann) |

**Declared limits per leg** (descriptor fallback text, verbatim):

- **`policies` / Windows** — follows as its own PR
- **`policies` / macOS** — follows as its own PR
<!-- END GENERATED -->

## Privileges and prerequisites

| OS | Runs as | Extra grant needed | Measured | If the read is refused |
|---|---|---|---|---|
| Windows | n/a - planned placeholder | n/a - planned placeholder | n/a - planned placeholder (the registry probe below is evidence, not a measurement of this plugin) | n/a - the placeholder reports `UNAVAILABLE` with `windows:planned` and reads nothing |
| macOS | n/a - planned placeholder | n/a - planned placeholder | n/a - planned placeholder | n/a - the placeholder reports `UNAVAILABLE` with `macos:planned` and reads nothing |
| Linux | agent daemon, dedicated unprivileged account (`yuzu`), never root by design (`docs/agent-privilege-model.md`) | None to read - the policy directories are root-owned but must be world-readable for the browser itself to load them | Measured 2026-09-22 in a Debian 13 container as euid 0 (`docs/samples/linux.txt`: the seeded policy files read with no extra grant); the refusal path (`permission_denied`) is proven by the unit suite as euid 501, not by a service-account run on a real host | `CONSTRAINED` / partial with a `linux:<detail>` token (for example `linux:permission_denied` or `linux:symlink_refused`); the unreadable directory or file contributes no rows, and the result never reads as "no policy configured" |

No external binaries, no subprocesses, no shell-out and no network use: the Linux leg is an in-process, bounded read of local files.

**Windows LocalSystem probe (evidence, not a measured outcome of this plugin).** The Windows leg is a planned placeholder that reads nothing, so the plugin has no LocalSystem outcome of its own yet. Separately, a registry probe on the-rig (2026-09-21) of `HKLM\SOFTWARE\Policies\Google\Chrome` and `HKLM\SOFTWARE\Policies\Microsoft\Edge` returned byte-identical output whether run as the interactive user or as SYSTEM: both roots were present with no values at the root and one subkey, `LocalNetworkAccessAllowedForUrls`, holding a value named `1` (`REG_SZ`), and the `Recommended` subkeys were absent (a real `reg query` exit 1).

## Data contract

### Inputs

<!-- BEGIN GENERATED: plugin-doc-gen inputs -->
The action takes no parameters.
<!-- END GENERATED -->

### Outputs

Every row is pipe-delimited and has nine fields; field 0 is always the literal `policy`. There is no status row kind: the result status carries the outcome, and a host with no managed policy returns zero rows. Free text is escaped for the server's pipe grammar (`safe_output_field`, lossy on backslash by design), a field with an embedded NUL byte has it replaced by U+FFFD and is flagged in `detail`, and a value that cannot be represented is typed `unmodelled` (`detail` `json_type`) instead of being dropped. `browser_policy` is not in the server's key/value plugin set, so rows are decoded as pipe-separated fields, not as `key|rest`.

<!-- BEGIN GENERATED: plugin-doc-gen outputs -->
**`crossplatform.browser_policy.policies` — `row_kind|browser|level|scope|name|value_type|value|source|detail`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `row_kind` | string | `policy` | Windows, Linux, macOS | `policy` | Row shape discriminator (field 0). Always the literal policy: this plugin has no status row kind, the result status carries the outcome. |
| `browser` | string | `chrome` `chromium` `edge` | Windows, Linux, macOS | `chrome` | Browser the policy applies to. Values: chrome (Google Chrome), chromium (Chromium), edge (Microsoft Edge). |
| `level` | string | `mandatory` `recommended` | Windows, Linux, macOS | `mandatory` | Policy level. Values: mandatory (the user cannot override it), recommended (a default the user may change). |
| `scope` | string | - | Windows, Linux, macOS | `machine` | Where the policy applies. Values: machine, or user:<name> where a leg reads per-user policy (the Linux leg reads machine policy only, so it always reports machine). The user name is untrusted text. |
| `name` | string | - | Windows, Linux, macOS | `HomepageLocation` | Policy name exactly as the browser documents it. |
| `value_type` | string | `bool` `int` `real` `string` `list` `dict` `null` `unmodelled` | Windows, Linux, macOS | `string` | Type of the value. Values: bool, int, real, string, list, dict, null, unmodelled (the policy is present but its value could not be represented; see detail). |
| `value` | string | - | Windows, Linux, macOS | `https://intranet.example.com` | The policy value as text: true or false for a bool, decimal text for int and real, the string verbatim, compact JSON text for a list or dict, the literal null for null, and "-" for unmodelled. |
| `source` | string | - | Windows, Linux, macOS | `/etc/opt/chrome/policies/managed/corp.json` | The logical file the policy was read from, never an injected test root (Linux). The Windows and macOS legs will report the registry key or plist path. |
| `detail` | string | - | Windows, Linux, macOS | `-` | A short qualifier, or "-" when there is none. json_type marks an unmodelled value; nul_replaced (appended, comma-joined) marks a free-text field that held an embedded NUL byte, replaced by U+FFFD. |
<!-- END GENERATED -->

### Result status

`policies` sets `OK`/`FULL` when the Linux read completed, including a host with no policy files at all: an absent policy set is a complete answer, not a degradation. Any directory, file or value that exists but could not be read or decoded makes the result `CONSTRAINED`/`PARTIAL` with the failure tokens as the reason; the rows that were read are still emitted. The Windows and macOS placeholders report `UNAVAILABLE`/`PARTIAL`: that host was not inspected, which is never the same as "no policy configured". No exception crosses the plugin boundary: a leg that throws is reported as `UNAVAILABLE`/`PARTIAL` with an exception token.

| Status | Completeness | Provenance | When |
|---|---|---|---|
| `OK` | `FULL` | (empty) | Linux: every read completed, populated or genuinely empty |
| `CONSTRAINED` | `PARTIAL` | `linux:<detail>` with `<detail>` one of `permission_denied`, `symlink_refused`, `not_a_directory`, `open_failed`, `stat_failed`, `not_regular`, `oversized`, `read_failed`, `readdir_error`; also `linux:row_cap` (more than 8192 rows in one run), `linux:entry_cap` (one policy directory holds more than 4096 entries), `linux:json_unparseable`, `linux:json_not_object` and `linux:json_too_deep` (several tokens are comma-joined) | Linux: a policy directory or file exists but could not be read completely or decoded, or a bound (row cap, directory entry cap, 1 MiB file cap, nesting depth) was hit |
| `UNAVAILABLE` | `PARTIAL` | `windows:planned` | Windows: the leg is a placeholder; zero rows |
| `UNAVAILABLE` | `PARTIAL` | `macos:planned` | macOS: the leg is a placeholder; zero rows |
| `UNAVAILABLE` | `PARTIAL` | `windows:leg:exception` / `macos:leg:exception` / `linux:leg:exception` | a leg threw; reported instead of unwinding across the plugin boundary |

### Where the data goes

- **Instruction result.** Rows travel over the agent's mTLS gRPC channel as the command response and land in the ResponseStore, queryable at `/api/responses/{id}`. `policies` is also a gathered definition (`crossplatform.browser_policy.policies`, 300s TTL).
- **Not consumed by** daily-sync, TAR, DEX, or metrics.
- **Sensitivity.** Rows are operator/IT-authored configuration: policy names and values such as homepage URLs, allowed or blocked extension ids and proxy settings can disclose part of an organisation's browser-management posture and internal hostnames. They carry no browsing history, bookmarks, cookies or user credentials, and no row names a user account on the Linux leg.
- **Siblings:** `installed_apps` (which browsers are installed, not how they are managed) and `update_source_trust` (package-source trust posture, a different attack-surface fact).

## Sample output

<!-- BEGIN GENERATED: plugin-doc-gen samples -->
**macOS** — captured: macos macOS 26.6.2 arm64 · bare-metal · 2026-09-21 · euid 501 · leg-hash 3349c5d2765b

```
== action=policies
[result_status] UNAVAILABLE / PARTIAL / macos:planned
```

**Linux** — captured: linux Debian GNU/Linux 13 (trixie) aarch64 · container · 2026-09-21 · euid 0 · leg-hash 3349c5d2765b

```
== action=policies
[result_status] OK / FULL
```
<!-- END GENERATED -->

The Linux capture is taken from a real Debian container that was seeded, for the capture only, with two SYNTHETIC Chrome policy files (Alex sign-off 2026-09-21; the image ships no browser): `/etc/opt/chrome/policies/managed/seeded.json` holding `ExtensionInstallForcelist`, `HomepageLocation` and `RestoreOnStartup`, and `/etc/opt/chrome/policies/recommended/seeded.json` holding `BookmarkBarEnabled`, so the sample shows the shipping leg reading real files through the production root. The same container with no policy files reports zero rows with `OK`/`FULL`. Every failure token and the caps are covered by the fixture-driven unit tests over `tests/unit/fixtures/wave10/browser_policy/linux`. The planned legs are status-only: the macOS capture shows the placeholder status alone (`UNAVAILABLE`/`PARTIAL`, `macos:planned`, zero rows), and there is no Windows capture.

## Caveats and known gaps

1. **No documented customer driver.** Zero documented driver anywhere - a full sweep of all four planning docs (capability-map, enterprise-parity-plan, the SOC 2 doc, roadmap.md) found not one mention of "browser," a browser name, or "extension"/"shadow IT" in any browser-security sense. Pure capability-gap reasoning, identical caveat to PR8.1 through PR8.5.
2. **No kill switch, by design.** `browser_policy` reads operator/IT-authored config, not personal data, and carries neither gate: the action is an ordinary `Inventory` read (`Inventory:Read`, no execute gate), unlike `browser_inventory`, whose installed-extension data can reveal user identity and behaviour.
3. **Windows and macOS legs planned.** Each follows as its own PR; until then `policies` on those hosts returns zero rows with result status `UNAVAILABLE` and provenance `windows:planned` or `macos:planned`, so a host that was not inspected never reads as having no policy.
4. **Linux reads machine-level JSON policy files only.** Only the `managed` and `recommended` `*.json` files under `/etc/opt/chrome`, `/etc/chromium` and `/etc/opt/edge` are read; per-user policy, snap and flatpak Chromium paths and Firefox `policies.json` are not, and every row reports scope `machine`.
5. **Values are reported, not validated.** A policy name is emitted as written and is not checked against the browser's policy schema, so a misspelt or unsupported policy still appears as a row; lists and dicts are emitted as compact JSON text, and an embedded backslash in a value is folded to `/` by the escaper.

## Source and tests

<!-- BEGIN GENERATED: plugin-doc-gen source -->
- Plugin: `agents/plugins/browser_policy/src/browser_policy_legs.hpp` · `agents/plugins/browser_policy/src/browser_policy_linux.cpp` · `agents/plugins/browser_policy/src/browser_policy_linux_parsers.hpp` · `agents/plugins/browser_policy/src/browser_policy_macos.cpp` · `agents/plugins/browser_policy/src/browser_policy_parsers.hpp` · `agents/plugins/browser_policy/src/browser_policy_plugin.cpp` · `agents/plugins/browser_policy/src/browser_policy_win.cpp`
- Definitions: `content/definitions/browser_policy.yaml`
- Capability rows: `server/core/src/capability_decls/plugin_action_catalogue_browser_policy.hpp`
- Tests: `tests/unit/test_browser_policy_local_dispatcher.cpp` · `tests/unit/test_browser_policy_parsers.cpp`
- Privilege row: `docs/agent-privilege-model.md`
<!-- END GENERATED -->
