---
title: User-session helper subsystem
status: proposed
date: 2026-07-30
owner: "@Doomgoose (Alex Young)"
deciders: "requires at least one non-author approval per dev-branch protection"
scope: agent runtime, per-user session capabilities, agent packaging
depends-on: ["3002-acquisition-ladder", "0028-agent-component-inventory-collection", "0033-access-control-spine", "0017-management-group-confinement-list-reads", "0032-use-case-admission-protocol", "0010-secrets-at-rest-envelope-encryption"]
related: ["0021-spark-reflex-architecture", "0031-engine-principal-store"]
context-refs: ["#1442", "#1455"]
---

# ADR-3003: User-session helper subsystem

## Context

The Yuzu agent runs as a system-context daemon on every OS, at a privilege level that **varies by platform**: **root** (macOS LaunchDaemon — no `UserName` key in `com.yuzu.agent.plist`), **LocalSystem** (Windows service *today* — the intended unprivileged virtual service account is a tracked deviation, #1442), and a **dedicated unprivileged account** (Linux — `User=yuzu-agent`, `NoNewPrivileges=true`, `ProtectSystem=strict`; the process never runs as root). What is uniform is not the privilege level but the *context*: on every OS it runs outside any interactive login session, so — regardless of privilege — it is, by construction, unable to reach a logged-in user's session: session-0 isolation (Windows), no Aqua/GUI session or login keychain (macOS), no user D-Bus / `DISPLAY` / `XDG_RUNTIME_DIR` (Linux). A recurring class of capability is dead-ended on this and today fails *honestly* rather than working:

- `interaction` message-box/input/survey/notify return `status|not_reachable` on macOS/Linux — the dialog is never delivered to the user.
- `wifi` SSID/BSSID scan on macOS is gated by per-user Location Services, which the daemon cannot hold.
- `app_usage`, `geo_presence` coordinates, and per-user software estate (npm/brew/pip config, per-user dependency stores) all require per-user session context.

Three existing decisions already name this subsystem as the sanctioned future shape and set its burden:

- **`docs/agent-privilege-model.md`** — *"The interaction plugin needs a separate per-session helper, not the daemon"*; reserves Windows `SeImpersonatePrivilege` *"for the future per-session interaction helper"*; frames a privileged broker beside the worker as a deferred hardening pass.
- **ADR-0028** rejected daemon reads of per-user files and punted the fix to *"a session-scoped helper running as the interactive user … not a service-account privilege grant."*
- **ADR-3002 Decision 8** does not foreclose *"a future brokered-elevation design that clears its own threat-model review."*

The only per-user reach in-tree today is the `certificates` plugin's root-gated, read-only `launchctl asuser <uid> sudo -n -u <user> security …` hop (`agents/shared/macos_console_user.hpp`) — a narrow stopgap, not a general capability.

**Why now — the parity effort.** Yuzu is driving every existing and new agent plugin up the ADR-3002 acquisition ladder to full Windows/Linux/macOS parity, priority **Windows > Linux > macOS**. That effort rests on a small set of foundational capabilities the agent does not have today; a review of the plugin surface found several capabilities silently assume infrastructure that is absent, and the per-user session gap is one of them — repeatedly deferred (privilege-model doc, ADR-0028, ADR-3002 Decision 8) rather than designed. This ADR is one of those foundations: it exists so that the plugins which need to reach a user's session (enumerated in *Relationship to the plugin-parity effort* below) are unblocked from a single, reviewed mechanism rather than each re-inventing session reach with its own trust boundary.

A platform investigation established the load-bearing constraint that shapes the architecture. macOS **Location Services is administered by `locationd`, outside TCC**, and delivering Wi-Fi/Location capability requires all three of: a real `Info.plist` `CFBundleIdentifier` (CoreWLAN rejects the path-synthesised `locationd` identity a bare CLI receives); a continuously running run loop (a one-shot exec returns `nil` SSID); and an interactive per-user consent grant that **cannot be MDM/PPPC pre-granted** (Location is not a TCC service). TCC-gated capabilities (dialogs, per-user file reads, Full Disk Access) are *not* subject to this — a signed CLI Mach-O is a legal PPPC target. This cleanly partitions the subsystem: only the macOS Location leg forces a net-new signed component; everything else can be delivered by extending existing primitives or reusing the existing binary.

## Decision

### Architecture at a glance

```
                    PRIVILEGED SYSTEM CONTEXT                    │        INTERACTIVE USER SESSION
     (root LaunchDaemon / LocalSystem svc / system daemon)      │      (per logged-in user, user privilege)
 ───────────────────────────────────────────────────────────── │ ──────────────────────────────────────────────
                                                                │
   ┌───────────────────────────┐                                │
   │      Yuzu agent daemon     │                               │
   │  (plugins, gRPC to server) │                               │
   └───────────┬───────────────┘                                │
               │                                                 │
   Tier A ─────┤  run_in_session_as_user  ───(transient exec, drops to user)──▶  dialog / per-user file read
   (no new     │  (subprocess_runner mode)      argv rung-2 · osascript/pwsh rung-3
    component) │                                                 │
               │                                                 │
   Tier B ─────┤  local authenticated IPC   ═══(peer-cred · per-boot bind · replay-safe · versioned)═══╗
   (resident,  │  ‖ NEVER an arbitrary-exec op — fixed typed vocabulary only ‖                          ║
    reuse      │                                                 │                                      ▼
    binary)    │                                                 │        ┌──────────────────────────────────────┐
               │                                                 │        │ agents/core --session-helper (resident) │
               │                                                 │        │  · app_usage sampler                    │
               │                                                 │        └──────────────────────────────────────┘
               │                                                 │                      │  macOS only
               │                                                 │                      ▼
               │                                                 │        ┌──────────────────────────────────────┐
   Tier B-Loc ─┘                                                 │        │  signed .app LaunchAgent (run loop)     │
   (macOS only,                                                  │        │  · CoreLocation → wifi scan / geo coords│
    signed .app)                                                 │        └──────────────────────────────────────┘
                                                                 │
   Windows/Linux wifi + geo = daemon-native rung-1 (no helper)   │
   Per-OS launch: WTSQueryUserToken+CreateProcessAsUser · systemd --user · macOS LaunchAgent
```

1. **Adopt a per-user session helper as a foundation of the plugin-parity effort, layered in three tiers by the minimum runtime shape each capability actually requires.** The subsystem exists to *de-escalate* privileged intent from the daemon into the user's session — never to elevate.

   - **Tier A — transient session-exec (no new component).** GUI dialogs (`interaction` on Linux/macOS) and per-user file reads fold into a `run_in_session_as_user` mode on the shared `subprocess_runner`, dropping a short-lived child into the target user's session at the user's privilege. This discharges ADR-0028 directly: it runs *as the interactive user*, not as a service-account grant.
   - **Tier B — resident helper (reuse the agent binary).** Capabilities needing a process resident in the session (`app_usage` sampling) run the existing `agents/core` binary in a `--session-helper` mode launched per-user, loading only the typed session op-vocabulary — no privileged plugins. Reuses the OTA updater and packaging pipeline; introduces no new build artifact.
   - **Tier B-Location — signed macOS `.app` (the one net-new component).** macOS Wi-Fi scan and geo coordinates require the resident helper to be wrapped in a **persistent, signed, notarized, bundle-identified `.app` LaunchAgent with a CoreLocation run loop** — the only Apple-permitted path. Compiled from the same source as the agent; distinct only as an on-disk signed bundle. Windows (native WLAN) and Linux (NetworkManager D-Bus) reach Wi-Fi/geo via daemon-native interfaces and need no helper.

2. **The daemon↔helper contract is a strict, typed operation vocabulary with no arbitrary-execution primitive.** The daemon may invoke only a fixed set of high-level operations (e.g. show-dialog, notify, scan-wifi, read-named-user-store, get-location, sample-usage). There is never a "run this command as the user" op. This is the subsystem's paramount security invariant.

3. **The IPC channel between daemon and helper is local, off-wire, and mutually authenticated.** It does not use the server→agent gRPC path and adds no `CommandRequest` proto field (the Erlang gpb gateway strips unknown wire fields). It provides peer-credential verification in both directions, per-boot channel binding, message authentication with replay protection, and version negotiation modelled on the plugin-ABI min/max handshake. Per-OS transport: Windows named pipe (user-SID-scoped ACL) with `WTSQueryUserToken`/`CreateProcessAsUser` launch; macOS XPC/UNIX socket from the signed LaunchAgent; Linux `AF_UNIX` under `XDG_RUNTIME_DIR` with `SO_PEERCRED`, launched by the user's own `systemd --user` instance / D-Bus activation. **The launch mechanism is privilege-dependent:** where the daemon is root/LocalSystem it can impersonate the user to start the helper (`launchctl asuser`, `CreateProcessAsUser`); the unprivileged Linux daemon cannot `setuid` into the user, so it does **not** impersonate — the helper runs in the user's own login session, started by the per-user session manager.

4. **Authority rides the existing access-control spine.** Each helper operation is a capability declared as a `securable × operation` on the ADR-0033 spine (a C++ edit plus four-eyes manifest — there is no runtime registry yet), bound to the access-control authz model. Sensitive/consent-class operations are additionally default-off, dedicated-securable, single-target, value-minimised; any list/fan-out read of per-user data routes the ADR-0017 `authorize_list_read` chokepoint. Read-only is a mutability class, not a privacy control.

5. **Per-user consent, revocation, kill switches, and audit are first-class.** The helper obtains and can revoke per-user consent; twinned REST+MCP kill switches disable it; every operation emits its own audit verb through the behavioural-PII fail-closed wrapper, and a mutation that cannot be audited does not proceed. Any secret the helper persists (consent tokens, per-user credentials) is a verify-only hash or a `SecretCodec` envelope, never a plaintext column.

6. **Every session-exec and the helper launch itself obey the acquisition ladder (ADR-3002).** They route through the single argv runner, pass the Decision-10a lexical spawn gate, and record sink-manifest + call-identity ledger rows. Session-hop argv (`launchctl asuser`/`sudo -u`/`CreateProcessAsUser`) is rung 2; interpreter payloads (`osascript -e`, `powershell -Command`) are rung 3 by Decision 5.

## Relationship to the plugin-parity effort

This foundation is a hard dependency for a specific, bounded set of plugins. It ships no capability of its own; its value is that each affected plugin dedupes onto it instead of building its own session-reach. Naming them here makes the forward relevance explicit and prevents divergent one-off mechanisms.

**Affected plugins and what changes for each:**

| Plugin | Affected action(s) | Tier that serves it | What it gains |
|---|---|---|---|
| `interaction` | `notify`, `message_box`, `input`, `survey` (Linux + macOS legs) | A — session-exec | dialogs actually delivered to the logged-in user instead of today's `status\|not_reachable` |
| `installed_apps` / per-user package inventory | per-user npm/brew/pip config reads | A — session-exec | reads run *as the interactive user* (the ADR-0028-sanctioned shape), not a daemon cross-user read |
| `app_usage` (new) | per-session usage sampling | B — resident helper | a process resident in the session, which a transient exec cannot provide |
| `wifi` | `list_networks` (SSID/BSSID scan), **macOS leg only** | B-Location — signed `.app` | CoreLocation authorization + run loop → real scan results instead of the `airport removed` constrained row |
| `geo_presence` (new) | coordinate acquisition, **macOS leg only** | B-Location — signed `.app` | CoreLocation authorization + per-user consent |

Two plugins are affected on **macOS only** — `wifi` and `geo_presence` — because their Windows (native WLAN) and Linux (NetworkManager D-Bus) legs are daemon-native rung-1 and do **not** wait on this helper; the **Windows > Linux > macOS** priority therefore lands their non-macOS legs first, independent of this ADR. Not affected but worth noting: the `certificates` macOS login-keychain read currently uses the ad-hoc `launchctl asuser` hop and *may* later migrate onto Tier A for uniformity, but that is not required by this ADR.

Each affected plugin remains responsible for its own ADR-3002 descriptor, machine-readable per-OS capability declaration, authz registration, and audit surface; this ADR governs only the session boundary those actions cross. On sequencing: the session-exec tier can land ahead of the access-control authz model (a dialog needs no securable to render); the resident and Location tiers depend on that authz model (each helper op is a securable) and on the default-off / kill-switch config plane, and are co-designed with the in-flight ADR-0031/0032/0033 decomposition work.

## Consequences

- **Unblocks the parity cells that are otherwise permanently constrained:** `interaction` on Linux/macOS, `wifi` macOS scan, `app_usage`, per-user package stores, `geo_presence` coordinates. The subsystem ships no parity itself; it is leverage for those consumer plugins.
- **Minimises net-new surface:** Tier A extends one primitive; Tier B reuses the agent binary and its updater/packaging; a net-new signed component exists only where Apple's platform forces it (macOS Location).
- **Discharges the standing burdens:** ADR-0028 (runs as the user), ADR-3002 Decision 8 (this ADR is the required threat-model review), and the privilege-model doc's deferred per-session helper.
- **Introduces a new, security-critical trust boundary** (privileged daemon ↔ user-privilege helper) whose properties must be designed before code — the reason this ADR precedes any implementation.
- **New operator obligations:** macOS Location consent cannot be MDM-silenced (an interactive per-user approval is required on every managed Mac for Wi-Fi/geo); the macOS `.app` adds a second notarization submission to the release pipeline; Windows `SeImpersonatePrivilege` must be held by the service account (available under today's LocalSystem; lands with the least-privilege account fix, #1442).
- **The design does not assume the daemon stays root/LocalSystem.** The privilege model is deliberately narrowing (#1442 → an unprivileged Windows virtual service account; #1455 → macOS off root), which removes the daemon's ability to impersonate a user. The durable launch model is therefore each platform's per-user session manager (LaunchAgent / `systemd --user` / the user's Windows session); daemon-side `CreateProcessAsUser` / `launchctl asuser` impersonation is used only where privilege permits and is not the foundation.
- **Sequencing:** the session-exec tier can precede the access-control authz model (dialogs need no securable to render); the resident and Location tiers depend on that authz model (securables) and on the default-off / kill-switch config plane, and must be co-designed with the in-flight ADR-0031/0032/0033 decomposition work.

## Alternatives considered

- **Fold every capability into the daemon (no helper).** Rejected — impossible by construction for GUI/Location/per-user context, and ADR-0028 already rejected a service-account cross-user read grant on memory-safety-blast-radius grounds.
- **Deliver all capabilities via transient session-exec only (no resident process).** Rejected — a sampler (`app_usage`) needs residence, and macOS Location needs a persistent bundle-identified run loop; three independent OS walls make transient exec insufficient for Wi-Fi/Location.
- **Ship a dedicated minimal helper binary rather than a mode of the agent.** Rejected for now — the smaller attack surface does not justify a net-new build target, update-ownership, and packaging surface; reusing the binary in a restricted `--session-helper` mode (privileged plugins not loaded) captures most of the isolation benefit.
- **Defer the macOS `.app` and keep Wi-Fi/geo constrained.** Rejected — accepted the one Apple-mandated signed `.app` now so macOS reaches parity with the Windows/Linux Wi-Fi/geo legs; deferral would leave macOS permanently behind for no design gain.
- **Extend `CommandRequest` with a session/mutability field.** Rejected — the gpb gateway strips unknown wire fields, and the daemon↔helper channel is local; adding a wire field would be inert end-to-end and is unnecessary.
