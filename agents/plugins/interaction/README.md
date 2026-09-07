# interaction

<!-- BEGIN GENERATED: plugin-doc-gen header -->
| | |
|---|---|
| **What it does** | Desktop user interaction — notifications, message boxes, input dialogs, surveys, DND |
| **Version** | 0.3.0 |
| **Kind** | Action · mutating · on-demand (no scheduled gather) |
| **Platforms** | Windows ✅ · macOS 🟡 constrained · Linux ✅ |
| **Actions** | `notify` (definition `device.interaction.notify`) · `message_box` (`device.interaction.message_box`) · `input` (`device.interaction.input`) · `survey` (`device.interaction.survey`) · `set_dnd` (`device.interaction.set_dnd`) |
| **Security** | securable `Infrastructure` · operation Write · risk Medium · dispatch Mutating · approval gate AdminOrApproval |
| **Roles** | execute: endpoint-admin (all actions) + endpoint-operator (`notify`, `set_dnd` only) · author: content-author |
<!-- END GENERATED -->

## How it works

Four of the five actions dispatch a platform-native dialog or notification mechanism and report what happened; the fifth, `set_dnd`, is a pure local KV-store flag with no OS call. `notify` and `survey` first check whether Do Not Disturb is active and, if so, short-circuit to `status|suppressed` without ever spawning anything. Every dialog action validates its required parameters in the OS-agnostic dispatch layer before reaching a platform leg — a missing `title` never spawns a subprocess, on any OS. Text fields are then sanitized (metacharacters and quotes stripped) before being interpolated into an osascript/PowerShell script fragment; every spawn itself goes through the bounded argv runner with no shell involved end to end. The plugin never fabricates a dialog outcome: a non-zero exit, a runner-level failure, or an unreachable GUI session is always reported as an honest `status|unavailable`/`status|not_reachable`/`status|error` line rather than a guessed button or cancellation. It is deliberately not a general scripting surface — the only mechanisms it invokes are ShellNotifyIcon/MessageBoxW/PowerShell (Windows), notify-send/zenity (Linux), and osascript (macOS).

```mermaid
flowchart LR
  OP[Operator / workflow] --> SRV[Server<br/>authz: Infrastructure.Write]
  SRV -- gRPC mTLS --> HOST[Agent plugin host] --> EX[interaction.execute]
  EX --> DND{DND active?<br/>notify/survey only}
  DND -- yes --> SUP[status suppressed]
  DND -- no / n-a --> VAL{required params present?}
  VAL -- no --> ERR[status error]
  VAL -- yes --> WIN[Windows leg<br/>Shell_NotifyIconW / MessageBoxW /<br/>PowerShell InputBox / WinForms]
  VAL -- yes --> MAC[macOS leg<br/>osascript display notification / dialog]
  VAL -- yes --> LIN[Linux leg<br/>notify-send / zenity]
  SUP & ERR & WIN & MAC & LIN --> ROWS[key|value rows] --> RS[(ResponseStore)] --> API[REST /api/responses]
```

## OS capability

<!-- BEGIN GENERATED: plugin-doc-gen capability -->
| Action | Windows | macOS | Linux |
|---|---|---|---|
| `notify` | ✅ supported · rung 1 · `shell_notifyicon` | 🟡 constrained · rung 3 · `osascript` | ✅ supported · rung 2 · `notify_send` |
| `message_box` | ✅ supported · rung 1 · `messageboxw` | 🟡 constrained · rung 3 · `osascript` | ✅ supported · rung 2 · `zenity` |
| `input` | ✅ supported · rung 3 · `powershell_inputbox` | 🟡 constrained · rung 3 · `osascript` | ✅ supported · rung 2 · `zenity` |
| `survey` | ✅ supported · rung 3 · `powershell_winforms` | 🟡 constrained · rung 3 · `osascript` | ✅ supported · rung 2 · `zenity` |
| `set_dnd` | ✅ supported · rung 1 · `local_kv_store` | ✅ supported · rung 1 · `local_kv_store` | ✅ supported · rung 1 · `local_kv_store` |

**Declared limits per leg** (the descriptor's fallback text, verbatim):

- **`notify` / macOS** — no reachable GUI session under a headless/root LaunchDaemon
- **`message_box` / macOS** — no reachable GUI session under a headless/root LaunchDaemon
- **`input` / macOS** — no reachable GUI session under a headless/root LaunchDaemon
- **`survey` / macOS** — no reachable GUI session under a headless/root LaunchDaemon
<!-- END GENERATED -->

## Privileges and prerequisites

| OS | Runs as | Extra grant needed | Measured | If the read is refused |
|---|---|---|---|---|
| Windows | agent service account; registers and runs as LocalSystem today (#1442, not yet the intended virtual service account) | None — `Shell_NotifyIconW`/`MessageBoxW` are unprivileged, and PowerShell needs no elevation to run `InputBox`/`WinForms` | 2026-09-07, bare-metal, as `SYSTEM` | PowerShell dialogs (`input`/`survey`) report `status|unavailable|PowerShell dialog exited with an error` or `...timed out`; native `notify`/`message_box` have no refusal path — `MessageBoxW` always returns a button |
| macOS | root (shipped LaunchDaemon has no `UserName` key) | None — but no LaunchDaemon has a reachable Aqua/GUI session by design | 2026-09-07, bare-metal, as euid 501 (alex) — an interactive logged-in user, **not** the production root-daemon posture | `status|unavailable|no reachable GUI session` (`notify`) or `status|not_reachable` (`message_box`/`input`/`survey`) |
| Linux | agent unprivileged account (`yuzu`) | None — the plugin checks `DISPLAY`/`WAYLAND_DISPLAY` before ever spawning | 2026-09-06, container, as euid 0 | `status|unavailable|no reachable GUI session`, checked upfront before spawning zenity/notify-send |

Binaries/subprocesses: PowerShell (`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, Windows `input`/`survey`) · osascript (`/usr/bin/osascript`, macOS all four dialog actions) · zenity and notify-send (`/usr/bin/zenity`, `/usr/local/bin/zenity`, `/usr/bin/notify-send`, `/usr/local/bin/notify-send`, Linux). No network access. `set_dnd` and Windows `notify`/`message_box` spawn nothing.

## Data contract

### Inputs

<!-- BEGIN GENERATED: plugin-doc-gen inputs -->
| Action | Parameter | Type | Required | Default | Description |
|---|---|---|---|---|---|
| `notify` (`device.interaction.notify`) | `title` | string | yes | — | Notification title text |
| `notify` (`device.interaction.notify`) | `message` | string | yes | — | Notification body text |
| `notify` (`device.interaction.notify`) | `type` | string | no | `info` | Notification severity: info, warning, or error |
| `message_box` (`device.interaction.message_box`) | `title` | string | yes | — | Dialog title text |
| `message_box` (`device.interaction.message_box`) | `message` | string | yes | — | Dialog body text |
| `message_box` (`device.interaction.message_box`) | `buttons` | string | no | `ok` | Button configuration: ok, okcancel, or yesno |
| `input` (`device.interaction.input`) | `title` | string | yes | — | Dialog title text |
| `input` (`device.interaction.input`) | `prompt` | string | yes | — | Prompt text shown above the input field |
| `input` (`device.interaction.input`) | `default_value` | string | no | `""` | Pre-filled default text in the input field |
| `survey` (`device.interaction.survey`) | `title` | string | yes | — | Survey window title |
| `survey` (`device.interaction.survey`) | `questions` | string | yes | — | JSON array of question objects: `{prompt, type: text\|yesno\|choice, choices}` |
| `set_dnd` (`device.interaction.set_dnd`) | `enabled` | string | yes | — | Set to 'true' to enable DND, 'false' to disable |
| `set_dnd` (`device.interaction.set_dnd`) | `duration_minutes` | int32 | no | `0` | Optional duration in minutes; 0 or omitted means indefinite |
<!-- END GENERATED -->

### Outputs

Each action writes one or more `key|value` lines via `write_output()`. The dashboard/REST layer treats `interaction` as a key/value plugin and splits each line into exactly a key and the remainder of the line as its value — so a value can itself contain literal `|` characters, e.g. `status|error|missing required parameter: title` has key `status` and value `error|missing required parameter: title`. Not every declared column is written on every invocation: `response`/`cancelled` are mutually exclusive per action, and `status` appears only on a validation failure, a suppressed DND, or an undeliverable/failed dialog — a clean button press or clean survey completion never emits a `status` line at all.

<!-- BEGIN GENERATED: plugin-doc-gen outputs -->
**`notify` — one `key|value` line: `status`**

| Field | Type | Values | Available | Example |
|---|---|---|---|---|
| `status` | string | `ok`, `suppressed\|<reason>`, `error\|<reason>`, `unavailable\|<reason>` (reason is free text) | W, M, L | `error\|missing required parameter: title` |

**`message_box` — one `key|value` line, `response` OR `status`**

| Field | Type | Values | Available | Example |
|---|---|---|---|---|
| `response` | string | `ok`, `cancel`, `yes`, `no` | W, M, L | `ok` |
| `status` | string | `not_reachable`, `error\|<reason>`, `unavailable\|<reason>` | W, M, L | `error\|missing required parameter: title` |

**`input` — one or two `key|value` lines: `response` OR `cancelled`, plus `status` on failure**

| Field | Type | Values | Available | Example |
|---|---|---|---|---|
| `response` | string | free text | W, M, L | `-` |
| `cancelled` | bool | `true` | W, M, L | `true` |
| `status` | string | `error\|<reason>`, `unavailable\|<reason>` | W, M, L | `error\|missing required parameter: title` |

**`survey` — `cancelled` OR (`question_count` + `answer_0`…`answer_4`) OR `status`**

| Field | Type | Values | Available | Example |
|---|---|---|---|---|
| `cancelled` | bool | `true` | W, M, L | `true` |
| `question_count` | int32 | integer | W, M, L | `-` |
| `answer_0` | string | free text, or yes/no for a yesno question | W, M, L | `-` |
| `answer_1` | string | free text, or yes/no for a yesno question | W, M, L | `-` |
| `answer_2` | string | free text, or yes/no for a yesno question | W, M, L | `-` |
| `answer_3` | string | free text, or yes/no for a yesno question | W, M, L | `-` |
| `answer_4` | string | free text, or yes/no for a yesno question | W, M, L | `-` |
| `status` | string | `suppressed\|<reason>`, `error\|<reason>`, `unavailable\|<reason>` | W, M, L | `error\|missing required parameter: title` |

**`set_dnd` — `dnd_enabled` + `status`, plus `dnd_duration_minutes`/`dnd_expires_at` when a duration is set**

| Field | Type | Values | Available | Example |
|---|---|---|---|---|
| `dnd_enabled` | bool | `true`, `false` | W, M, L | `true` |
| `dnd_duration_minutes` | int32 | integer | W, M, L | `-` |
| `dnd_expires_at` | int64 | epoch seconds, or omitted | W, M, L | `-` |
| `status` | string | `ok` | W, M, L | `ok` |
<!-- END GENERATED -->

### Result status

This plugin does not set a typed result status; the agent records `UNDECLARED` and the sample shows `UNDECLARED / UNKNOWN /`.

### Where the data goes

- **Instruction result only.** Rows travel over the agent's mTLS gRPC channel as the command response and land in the ResponseStore (90-day default retention), queryable at `/api/responses/{id}`.
- **Not consumed by** daily-sync inventory, TAR, DEX, or metrics. Nothing runs on a schedule; the plugin executes only when an operator or workflow dispatches one of its five definitions. The dashboard's generic key/value renderer is the only non-ResponseStore consumer of these rows.
- **Siblings:** none — no other plugin performs desktop notification/dialog interaction.
- **MCP / REST.** Discover: `discover_plugins` (summary) → `yuzu://plugin-docs` (this page as data) → `discover_instructions` / `get_definition("device.interaction.notify")`. Run: `execute_instruction {definition_id, parameters}`. Read: `/api/responses/{id}`.

## Sample output

<!-- BEGIN GENERATED: plugin-doc-gen samples -->
**Windows** — captured: windows Microsoft Windows NT 10.0.26200.0 x64 · bare-metal · 2026-09-07 · SYSTEM · leg-hash pending

```
== action=notify
status|error|missing required parameter: title
[result_status] UNDECLARED / UNKNOWN / 
[rc] 1

== action=message_box
status|error|missing required parameter: title
[result_status] UNDECLARED / UNKNOWN / 
[rc] 1

== action=input
status|error|missing required parameter: title
[result_status] UNDECLARED / UNKNOWN / 
[rc] 1

== action=survey
status|error|missing required parameter: title
[result_status] UNDECLARED / UNKNOWN / 
[rc] 1

== action=set_dnd
dnd_enabled|true
status|ok
[result_status] UNDECLARED / UNKNOWN / 
```

**macOS** — captured: macos macOS 26.6.2 arm64 · bare-metal · 2026-09-07 · euid 501 (alex) · leg-hash pending

```
== action=notify
status|error|missing required parameter: title
[result_status] UNDECLARED / UNKNOWN / 
[rc] 1

== action=message_box
status|error|missing required parameter: title
[result_status] UNDECLARED / UNKNOWN / 
[rc] 1

== action=input
status|error|missing required parameter: title
[result_status] UNDECLARED / UNKNOWN / 
[rc] 1

== action=survey
status|error|missing required parameter: title
[result_status] UNDECLARED / UNKNOWN / 
[rc] 1

== action=set_dnd
dnd_enabled|true
status|ok
[result_status] UNDECLARED / UNKNOWN / 
```

**Linux** — captured: linux Debian GNU/Linux 13 (trixie) aarch64 · container · 2026-09-06 · euid 0 · leg-hash pending

```
== action=notify
status|error|missing required parameter: title
[result_status] UNDECLARED / UNKNOWN / 
[rc] 1

== action=message_box
status|error|missing required parameter: title
[result_status] UNDECLARED / UNKNOWN / 
[rc] 1

== action=input
status|error|missing required parameter: title
[result_status] UNDECLARED / UNKNOWN / 
[rc] 1

== action=survey
status|error|missing required parameter: title
[result_status] UNDECLARED / UNKNOWN / 
[rc] 1

== action=set_dnd
dnd_enabled|true
status|ok
[result_status] UNDECLARED / UNKNOWN / 
```

No sample on any of the three platforms shows a dialog actually being displayed — every capture ran each action with zero parameters, so `notify`/`message_box`/`input`/`survey` all reject at the `require_param` check before ever reaching a platform leg. `set_dnd` (no required parameter beyond `enabled`, which defaults to `true`) is the only action shown succeeding.
<!-- END GENERATED -->

## Caveats and known gaps

1. **No sample shows a real dialog.** All three captures ran with zero parameters, so every dialog action failed validation before reaching a platform leg. `response`, `cancelled`, `answer_0`–`answer_4`, `question_count`, `dnd_duration_minutes`, and `dnd_expires_at` have no observed real value anywhere in this repo — see the code paths in Data contract → Outputs for what would populate them.
2. **The macOS capture ran as an interactive user, not the production posture.** It was taken at euid 501 (a logged-in human), not as the root LaunchDaemon the plugin actually ships under, so it cannot demonstrate the constrained "no reachable GUI session" path even though the descriptor declares macOS `CONSTRAINED` for all four dialog actions.
3. **Honest-status is a hard invariant, not a bug to "fix."** Every dialog leg treats a non-zero exit, a runner failure, or an unreachable session as `status|unavailable`/`status|not_reachable`, never a fabricated button. A pre-0.3.0 version wrongly reported `response|ok` for an undelivered macOS dialog; do not reintroduce a catch-all "unrecognized output → ok" branch on any platform.
4. **`message_box`'s `status` fires on every OS, not only macOS.** It is set on a validation failure (missing title/message or a bad `buttons` value — all three OSes, confirmed by every sample), the macOS `not_reachable` sentinel, or a Linux zenity delivery failure — never only the macOS undeliverable path.
5. **`executeRoles` differs per action.** `notify`/`set_dnd` allow `endpoint-operator`; `message_box`/`input`/`survey` are `endpoint-admin`-only. Do not assume one roles line covers every action of this plugin.

## Source and tests

<!-- BEGIN GENERATED: plugin-doc-gen source -->
- Plugin: `agents/plugins/interaction/src/interaction_plugin.cpp` (descriptor, all 5 actions) · `interaction_parsers.hpp` (pure osascript/zenity/PowerShell capture classifiers)
- Definitions: `content/definitions/interaction.yaml`
- Capability rows: `server/core/src/capability_decls/plugin_action_catalogue_d.hpp`
- Tests: `tests/unit/test_interaction_parsers.cpp`
- Privilege row: no row in `docs/agent-privilege-model.md` (the doc's general GUI-session note names this plugin)
- Changelog: `changelog.d/20260716-macos-interaction-not-reachable.fixed.md` · `changelog.d/20260818-wave2-interaction-native-argv.changed.md` · `changelog.d/2204-declarations-group-d.added.md` · `changelog.d/2243-os-capability-matrix-sections.changed.md` · `changelog.d/2277-macos-plugin-parity.added.md`
<!-- END GENERATED -->
