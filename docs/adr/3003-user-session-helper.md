---
status: proposed
date: 2026-07-30
owner: "@Doomgoose (Alex Young)"
deciders: >-
  @Doomgoose (author). Ratified by PR approval under the dev-branch protection rule
  (at least one non-author approval). An independent two-reviewer adversarial review
  (2026-07-31, verdict REQUEST-CHANGES) was adjudicated against the code; every accepted
  finding is folded in, together with three further errors the re-verification surfaced.
effective: >-
  Binding on merge (ratification) for the three-tier partition, the no-arbitrary-exec
  invariant (Decision 2), the de-escalation-only principle, and the Decision-3 requirement
  that the daemon never impersonates a user. Three items are deliberately NOT settled by
  this ADR and do not bind on merge: (a) the governed contract for OS-managed activation of
  a resident helper, which ADR-3002 places out of the bounded runner's scope and which
  nobody has yet written; (b) the Windows `ImpersonateNamedPipeClient` privilege dependency,
  which must be re-verified against the actual `NT SERVICE\YuzuAgent` account once #1442
  lands rather than assumed from a LocalSystem run; (c) coordinate acquisition on Windows
  and Linux, for which no provider exists in-tree and which is out of scope here.
scope: agent runtime, per-user session capabilities, agent packaging
depends-on: ["3002-acquisition-ladder", "0028-agent-component-inventory-collection", "0033-access-control-spine", "0017-management-group-confinement-list-reads", "0032-use-case-admission-protocol"]
related: ["0021-spark-reflex-architecture", "0031-engine-principal-store"]
context-refs: ["#1442", "#1455", "docs/spark-rebuild-baselines/stage0-windows-spikes.md"]
---

# ADR-3003: User-session helper subsystem

## Context

The Yuzu agent runs as a system-context daemon on every OS, at a privilege level that **varies by platform**: **root** (macOS LaunchDaemon — no `UserName` key in `com.yuzu.agent.plist`), **LocalSystem** (Windows service *today* — the intended unprivileged virtual service account is a tracked deviation, #1442), and a **dedicated unprivileged account** (Linux — `User=yuzu-agent`, `NoNewPrivileges=true`, `ProtectSystem=strict`; the process never runs as root). What is uniform is not the privilege level but the *context*: on every OS it runs outside any interactive login session, so — regardless of privilege — it is, by construction, unable to reach a logged-in user's session: session-0 isolation (Windows), no Aqua/GUI session or login keychain (macOS), no user D-Bus / `DISPLAY` / `XDG_RUNTIME_DIR` (Linux). A recurring class of capability is dead-ended on this and today fails *honestly* rather than working:

- `interaction` message-box/input/survey/notify never reach the user on macOS or Linux, though the two fail differently: the macOS `osascript` leg is honest by design (`status|not_reachable`, the plugin's only such site, never a fabricated button), while the Linux `notify-send`/`zenity` legs simply fail against a daemon with no session bus or `DISPLAY` and surface a generic error. Undeliverable either way; only one of them says so.
- `wifi` SSID/BSSID scan on macOS is gated by per-user Location Services, which the daemon cannot hold.
- `app_usage`, `geo_presence` coordinates, and per-user software estate (npm/brew/pip config, per-user dependency stores) all require per-user session context.

Three existing decisions already name this subsystem as the sanctioned future shape and set its burden:

- **`docs/agent-privilege-model.md`** — *"The interaction plugin needs a separate per-session helper, not the daemon"*; reserves Windows `SeImpersonatePrivilege` *"for the future per-session interaction helper"*; frames a privileged broker beside the worker as a deferred hardening pass.
- **ADR-0028** rejected daemon reads of per-user files and punted the fix to *"a session-scoped helper running as the interactive user … not a service-account privilege grant."*
- **ADR-3002 Decision 8** does not foreclose *"a future brokered-elevation design that clears its own threat-model review."*

The only per-user reach in-tree today is the `certificates` plugin's root-gated, read-only `launchctl asuser <uid> sudo -n -u <user> security …` hop (`agents/shared/macos_console_user.hpp`) — a narrow stopgap, not a general capability. Note its shape: the whole hop is assembled as a single `/bin/sh -c` **shell string**, so it is a rung-3 site under ADR-3002 Decision 5, not the rung-2 argv hop Tier A prescribes below. The stopgap and the sanctioned shape are not the same thing.

**Prior art on the hardest platform.** Windows is the one OS where the mechanism has already been prototyped and decided, and that work is load-bearing here. `docs/spark-rebuild-baselines/stage0-windows-spikes.md` records two spikes and a decision. The service-side cross-session launch (`WTSQueryUserToken` + `CreateProcessAsUser`) was built and **failed** — `ERROR_PRIVILEGE_NOT_HELD` — because it needs `SeTcbPrivilege`, which the agent does not hold and which #1442's least-privilege account will not hold either. The recorded resolution (2026-07-06) chose instead a **persistent per-user helper launched by a logon-triggered Scheduled Task**: Task Scheduler already runs as SYSTEM and performs the session placement, so the agent never calls `WTSQueryUserToken`/`CreateProcessAsUser` and never needs a new privilege. A second spike then validated that shape end to end — an Interactive-principal task landing the helper in the user's session as the user, round-tripping over an authenticated named pipe with peer verification in both directions. This ADR adopts that decision as its Windows leg rather than re-litigating it, and Tier B below is that shape generalised to the other two platforms.

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
   Tier B ─────┤  local authenticated IPC   ◀══(helper dials the daemon · peer-cred · session-bound)══╗
   (resident,  │  ‖ NEVER an arbitrary-exec op — fixed typed vocabulary only ‖   replay-safe · versioned ║
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
   Windows wifi = native WLAN rung-1 · Linux wifi = nmcli/iw     │  NO coordinate provider
   rung-3 today (D-Bus descent is separate ADR-3002 work);       │  exists on ANY platform
   neither leg waits on this helper                              │  in-tree today
                                                                 │
   Per-OS launch — the OS session manager, never impersonation:  │
     logon Scheduled Task · systemd --user · LaunchAgent         │
```

1. **Adopt a per-user session helper as a foundation of the plugin-parity effort, layered in three tiers by the minimum runtime shape each capability actually requires.** The subsystem exists to *de-escalate* privileged intent from the daemon into the user's session — never to elevate.

   - **Tier A — transient session-exec (no new component).** GUI dialogs (`interaction` on Linux/macOS) and per-user file reads fold into a `run_in_session_as_user` mode on the shared `subprocess_runner`, dropping a short-lived child into the target user's session at the user's privilege. This discharges ADR-0028 directly: it runs *as the interactive user*, not as a service-account grant. Tier A is deliberately a **POSIX-only mode** — `run_bounded_subprocess` is a stub on Windows (`agents/core/include/yuzu/agent/subprocess_runner.hpp`) — and that is sufficient for its scope, because the dialog and per-user-read gaps this tier closes are Linux and macOS gaps. Windows session reach is not served by Tier A at all; it follows the separately-decided resident-helper path recorded in the Context above.
   - **Tier B — resident helper (reuse the agent binary).** Capabilities needing a process resident in the session (`app_usage` sampling) run the existing `agents/core` binary in a `--session-helper` mode launched per-user, loading only the typed session op-vocabulary — no privileged plugins. Reuses the OTA updater and packaging pipeline; introduces no new build artifact. This is the shape the Windows spike already validated end to end (Context above) — a resident per-user helper reached over an authenticated local channel — generalised from Windows to all three platforms.
   - **Tier B-Location — signed macOS `.app` (the one net-new component).** macOS Wi-Fi scan and geo coordinates require the resident helper to be wrapped in a **persistent, signed, notarized, bundle-identified `.app` LaunchAgent with a CoreLocation run loop** — the only Apple-permitted path. Compiled from the same source as the agent; distinct only as an on-disk signed bundle. Wi-Fi on the other two platforms needs no helper and does not wait on this ADR: Windows is already daemon-native rung 1 (`WlanEnumInterfaces`/`WlanGetAvailableNetworkList`), and Linux ships today at rung 3 (`nmcli`/`iw` through `/bin/sh -c`, `agents/plugins/wifi/`), whose descent toward a NetworkManager D-Bus rung-1 leg is ordinary ADR-3002 ladder work owned by that plugin, not by this subsystem.

2. **The daemon↔helper contract is a strict, typed operation vocabulary with no arbitrary-execution primitive.** The daemon may invoke only a fixed set of high-level operations (e.g. show-dialog, notify, scan-wifi, read-named-user-store, get-location, sample-usage). There is never a "run this command as the user" op. This is the subsystem's paramount security invariant.

3. **The IPC channel between daemon and helper is local, off-wire, mutually authenticated, and dialled by the helper.** It does not use the server→agent gRPC path and adds no `CommandRequest` proto field (the Erlang gpb gateway strips unknown wire fields). It provides peer-credential verification in both directions, per-boot channel binding, message authentication with replay protection, and version negotiation modelled on the plugin-ABI min/max handshake.

   **The helper connects out to a daemon-owned rendezvous; the daemon never reaches into a user's session to establish the channel.** This direction is not a preference — it is what the shipped privilege model permits. The Linux daemon runs as an unprivileged `yuzu-agent` account under `NoNewPrivileges=true` and `ProtectSystem=strict` (`deploy/systemd/yuzu-agent.service`): it cannot traverse into `/run/user/<uid>` (mode 0700, owned by the login user) to reach a helper-owned socket, and `SO_PEERCRED` would not help — that authenticates an already-connected peer, it does not grant connect access. Reversing the direction removes the need for any capability grant on the platform whose privilege model is narrowest, and gives the same shape on all three.

   Per-OS transport:

   - **Linux** — the daemon `bind`/`listen`s on an `AF_UNIX` socket it owns and authenticates each connection with `SO_PEERCRED` on `accept`. `ProtectSystem=strict` also makes `/run` read-only to the daemon, so the rendezvous directory is a packaging obligation, not an assumption: `deploy/systemd/yuzu-agent.service` gains `RuntimeDirectory=yuzu-agent` and `RuntimeDirectoryMode=0755`, giving a daemon-writable, world-traversable `/run/yuzu-agent/`. Authority is the verified peer credential, never the socket's DAC bits.
   - **Windows** — a named pipe served by the daemon, per the mechanism the Stage-0 spike validated. Two of that spike's findings are contract, not trivia: the server must `ReadFile` at least once **before** `ImpersonateNamedPipeClient` (it fails `ERROR_CANNOT_IMPERSONATE` otherwise), and the pipe's DACL must *restrict* which principals may connect — the spike identified its peer but ran a NULL DACL, so restriction is unbuilt and is part of this subsystem's work. The `ImpersonateNamedPipeClient` path depends on the server holding `SeImpersonatePrivilege`, which LocalSystem has today and which `NT SERVICE\YuzuAgent` is expected to hold by service-logon grant — **expected is not verified, and this must be re-tested against the real account when #1442 lands.** Client-side verification of the server is the pipe's owner SID via `GetSecurityInfo`, not `OpenProcess` (which a filtered user token is denied).
   - **macOS** — XPC or a UNIX socket, dialled by the signed LaunchAgent.

   **Every operation is bound to a named session identity, not merely to a valid local peer.** A peer credential proves that *some* legitimate local process is on the other end; it does not prove it is *the* session an operator targeted. On a host with fast user switching, multiple RDS sessions, or concurrent logins that gap is exploitable and, worse, silently mis-attributes audit. So each request names its target session — Windows logon session plus user SID, macOS uid plus audit session id, Linux uid plus the `systemd` session id — the verified peer credential is checked *against* that identity rather than merely for validity, a mismatch fails the operation closed, and the identity is carried onto the audit row. Multi-session targeting is one of the items the Windows spike explicitly recorded as unproven; naming it here is what keeps it from being assumed.

   **The daemon does not impersonate a user, on any platform.** The durable launch model is each OS's own per-user session manager — a logon-triggered Scheduled Task (Windows), `systemd --user` or D-Bus activation (Linux), a LaunchAgent (macOS). This is a deliberate reversal of the impersonation-where-privilege-permits shape: that shape is unavailable on Linux by construction, was proven unavailable on Windows by the Stage-0 spike, and would be lost on macOS the moment #1455 takes the daemon off root. A design that depends on privilege the platform is actively removing is not a foundation.

4. **Authority rides the existing access-control spine.** Each helper operation is a capability declared as a `securable × operation` on the ADR-0033 spine (a C++ edit plus four-eyes manifest — there is no runtime registry yet), bound to the access-control authz model. Sensitive/consent-class operations are additionally default-off, dedicated-securable, single-target, value-minimised; any list/fan-out read of per-user data routes the ADR-0017 `authorize_list_read` chokepoint. Read-only is a mutability class, not a privacy control.

5. **Per-user consent, revocation, kill switches, and audit are first-class — and the helper holds no recoverable secret.** The helper obtains and can revoke per-user consent; twinned REST+MCP kill switches disable it; every operation emits its own audit verb through the behavioural-PII fail-closed wrapper, and a mutation that cannot be audited does not proceed. Consent is recorded as verify-only state — a hash or a boolean in the agent's SQLite store — never as a recoverable token, and the helper is designed so that no per-user credential needs to live on disk at all. Where state must persist it inherits the discipline the agent already applies to the one durable secret it owns, its mTLS client key: atomic stage-and-rename at mode 0600 inside a 0700 directory (`agents/core/src/agent_csr.cpp`).

   This deliberately does **not** cite `SecretCodec`/ADR-0010. That primitive is bound to the server's Postgres substrate — it includes `libpq-fe.h` and every entry point takes a live `PGconn*` — and the agent links no libpq at all (ADR-0035; ADR-0006 keeps the agent SQLite-only). Naming it here would have promised a no-plaintext-secrets guarantee with no implementable owner on the endpoint. There is no agent-side envelope/KEK primitive today; committing the helper to hold nothing recoverable is what makes that absence acceptable rather than papered over. One asymmetry is worth recording for later: a helper running inside the user's login session can reach the macOS login keychain that the daemon provably cannot (`agents/core/src/cert_store.cpp`), and the platform credential stores (Windows CredMan/DPAPI, libsecret) are likewise reachable only from the session side. That is a future upgrade path this ADR opens, not a commitment it makes.

6. **Every Tier A session-exec obeys the acquisition ladder (ADR-3002); resident-helper activation is a different contract, and that contract does not yet exist.** Tier A hops are bounded, transient child processes and sit squarely on the ladder: they route through the single argv runner, pass the Decision-10a lexical spawn gate, and record sink-manifest + call-identity ledger rows. Session-hop argv (`launchctl asuser`, `sudo -u`) is rung 2; interpreter payloads (`osascript -e`, `powershell -Command`) are rung 3 by Decision 5.

   Tier B and Tier B-Location activation is **not** in that scope, and this ADR does not claim it is. ADR-3002's own scope section carves out "long-lived / ownership-transferring process launch" as "a separate governed contract, out of scope for the bounded runner", on the grounds that a process meant to outlive the initiating call cannot ride a contract built on deadline-kill-reap. A resident helper is exactly that class. The point is sharper still under Decision 3 above: the durable activation path is the OS session manager, so on the foundation path the daemon performs no spawn at all — there is no argv for the runner to own, no token for the lexical gate to match, and no call site for the sink manifest to key. Routing claims that presuppose a spawn are therefore not merely over-broad here, they are inapplicable.

   ADR-3002 says such launches "get their own governed contract (exec-success acknowledgement, explicit ownership transfer, no shell)". No such contract has been written, and no artifact in-tree can currently represent an OS-manager activation for manifest or audit purposes. Defining it is a prerequisite of the Tier B implementation, not of this ADR; it is recorded as an open item in `effective:` and tracked as a follow-up. What this ADR does fix is the boundary: the unit, plist, or task definition that activates a helper is the reviewable artefact, and helper activation must be as accountable as a spawn even though it is not one.

## Relationship to the plugin-parity effort

This foundation is a hard dependency for a specific, bounded set of plugins. It ships no capability of its own; its value is that each affected plugin dedupes onto it instead of building its own session-reach. Naming them here makes the forward relevance explicit and prevents divergent one-off mechanisms.

**Affected plugins and what changes for each:**

| Plugin | Affected action(s) | Tier that serves it | What it gains |
|---|---|---|---|
| `interaction` | `notify`, `message_box`, `input`, `survey` (Linux + macOS legs) | A — session-exec | dialogs actually delivered to the logged-in user, instead of today's honest `status\|not_reachable` (macOS) or generic `notify-send`/`zenity` failure (Linux) |
| `installed_apps` / per-user package inventory | per-user npm/brew/pip config reads | A — session-exec | reads run *as the interactive user* (the ADR-0028-sanctioned shape), not a daemon cross-user read |
| `app_usage` (new) | per-session usage sampling | B — resident helper | a process resident in the session, which a transient exec cannot provide |
| `wifi` | `list_networks` (SSID/BSSID scan), **macOS leg only** | B-Location — signed `.app` | CoreLocation authorization + run loop → real scan results instead of the `airport removed` constrained row |
| `geo_presence` (new) | coordinate acquisition, **macOS leg only** | B-Location — signed `.app` | CoreLocation authorization + per-user consent |

Two plugins are affected on **macOS only** — `wifi` and `geo_presence` — but for different reasons, and the distinction matters.

`wifi`'s non-macOS legs are shipped and do not wait on this helper: Windows is daemon-native rung 1 via the native WLAN API, and Linux ships today at rung 3 (`nmcli`/`iw` through `/bin/sh -c`), whose descent to a NetworkManager D-Bus rung-1 leg is ordinary ADR-3002 ladder work for that plugin. Only the macOS scan is blocked here, by CoreLocation.

`geo_presence` is different, and this ADR should not be read as implying otherwise: **no coordinate provider exists in-tree on any platform.** Neither the native WLAN API nor NetworkManager yields latitude and longitude — they return network state, and conflating the two would make the Windows and Linux legs look solved when nothing has been built. Only the macOS leg is designed here, because only the macOS leg has a forced architectural shape (a bundle-identified run loop). Windows and Linux coordinate acquisition — plausibly `Windows.Devices.Geolocation` and GeoClue, neither evaluated — is **out of scope for this ADR** and needs its own decision before `geo_presence` can claim cross-platform parity.

Not affected but worth noting: the `certificates` macOS login-keychain read currently uses the ad-hoc `launchctl asuser` shell hop and *may* later migrate onto Tier A for uniformity — which would also move it from rung 3 to rung 2 — but that is not required by this ADR.

Each affected plugin remains responsible for its own ADR-3002 descriptor, machine-readable per-OS capability declaration, authz registration, and audit surface; this ADR governs only the session boundary those actions cross. On sequencing: the session-exec tier can land ahead of the access-control authz model (a dialog needs no securable to render); the resident and Location tiers depend on that authz model (each helper op is a securable) and on the default-off / kill-switch config plane, and are co-designed with the in-flight ADR-0031/0032/0033 decomposition work.

## Consequences

- **Unblocks the parity cells that are otherwise permanently constrained:** `interaction` on Linux/macOS, `wifi` macOS scan, `app_usage`, per-user package stores, and `geo_presence` coordinates **on macOS** (the only platform for which this ADR designs a coordinate path). The subsystem ships no parity itself; it is leverage for those consumer plugins.
- **Minimises net-new surface:** Tier A extends one primitive; Tier B reuses the agent binary and its updater/packaging; a net-new signed component exists only where Apple's platform forces it (macOS Location).
- **Discharges the standing burdens:** ADR-0028 (reads run as the interactive user, not under a service-account grant) and the privilege-model doc's deferred per-session helper. On ADR-3002 Decision 8, this ADR is the reviewed design that decision left the door open for — though it is worth being precise that the door Decision 8 held open was for *brokered elevation*, and this subsystem walks through a different one: it only ever de-escalates, and Decision 8's sudo boundary is untouched.
- **Introduces a new, security-critical trust boundary** (privileged daemon ↔ user-privilege helper) whose properties must be designed before code — the reason this ADR precedes any implementation.
- **The design needs no new privilege on any platform — that is the point.** Windows activation is performed by Task Scheduler, which already runs as SYSTEM, so the agent never acquires `SeTcbPrivilege`; Linux reverses the channel direction rather than asking for `CAP_DAC_OVERRIDE` or a supplementary group; macOS uses a LaunchAgent rather than depending on the daemon still being root. The one open privilege dependency is `SeImpersonatePrivilege` for `ImpersonateNamedPipeClient` on the Windows pipe — held today, expected to survive #1442 by service-logon grant, and required to be re-verified against the real account rather than assumed.
- **New operator obligations:** macOS Location consent cannot be MDM-silenced (an interactive per-user approval is required on every managed Mac for Wi-Fi/geo); the macOS `.app` adds a second notarization submission to the release pipeline; the Windows installer must register a logon-triggered Scheduled Task with an Interactive principal; and the Linux package must add `RuntimeDirectory=yuzu-agent` / `RuntimeDirectoryMode=0755` to `deploy/systemd/yuzu-agent.service`, without which the daemon cannot create its rendezvous socket under `ProtectSystem=strict`.
- **The design does not assume the daemon stays root/LocalSystem.** The privilege model is deliberately narrowing (#1442 → an unprivileged Windows virtual service account; #1455 → macOS off root), which removes the daemon's ability to impersonate a user. The durable launch model is therefore each platform's per-user session manager (logon Scheduled Task / `systemd --user` / LaunchAgent), and there is no impersonation fallback anywhere in the design — a fallback that only works while privilege lasts would decay into the primary path and then fail on the accounts the platform is moving to.
- **One prerequisite is unowned:** the governed contract for OS-managed activation that ADR-3002 carves out of the bounded runner's scope has not been written, and no in-tree artefact can represent a non-spawn activation for manifest or audit purposes. Tier B cannot land accountably until it exists. This is called out rather than absorbed, because absorbing it is how a subsystem acquires an unreviewed launch path.
- **Sequencing:** the session-exec tier can precede the access-control authz model (dialogs need no securable to render); the resident and Location tiers depend on that authz model (securables) and on the default-off / kill-switch config plane, and must be co-designed with the in-flight ADR-0031/0032/0033 decomposition work.

## Alternatives considered

- **Fold every capability into the daemon (no helper).** Rejected — impossible by construction for GUI/Location/per-user context, and ADR-0028 already rejected a service-account cross-user read grant on memory-safety-blast-radius grounds.
- **Deliver all capabilities via transient session-exec only (no resident process).** Rejected — a sampler (`app_usage`) needs residence, and macOS Location needs a persistent bundle-identified run loop; three independent OS walls make transient exec insufficient for Wi-Fi/Location.
- **Ship a dedicated minimal helper binary rather than a mode of the agent.** Rejected for now — the smaller attack surface does not justify a net-new build target, update-ownership, and packaging surface; reusing the binary in a restricted `--session-helper` mode (privileged plugins not loaded) captures most of the isolation benefit.
- **Defer the macOS `.app` and keep Wi-Fi/geo constrained.** Rejected — accepted the one Apple-mandated signed `.app` now so the macOS Wi-Fi scan reaches parity with the shipped Windows and Linux Wi-Fi legs; deferral would leave macOS permanently behind for no design gain. Note this argument is about Wi-Fi only: there are no Windows/Linux geo legs to reach parity *with*.
- **Service-side cross-session launch (`WTSQueryUserToken` + `CreateProcessAsUser`) on Windows.** Rejected on evidence and by prior decision. The Stage-0 spike built it and it failed with `ERROR_PRIVILEGE_NOT_HELD`: the call needs `SeTcbPrivilege`, which the agent does not hold. Granting it was considered and rejected in its own right — it re-opens a session-impersonation hole that partially defeats the least-privilege account #1442 exists to deliver. Moving the privileged session placement into Task Scheduler dissolves the conflict instead of working around it.
- **Daemon dials into the user's session on Linux (`AF_UNIX` under `XDG_RUNTIME_DIR`).** Rejected — unreachable as specified. `/run/user/<uid>` is mode 0700 and owned by the login user; the unprivileged `yuzu-agent` account cannot traverse it, and `ProtectSystem=strict` additionally leaves it no writable path outside its state directory. Making it work would require `CAP_DAC_OVERRIDE` or per-user group membership — a privilege grant on the very platform whose model is narrowest. Reversing the direction costs nothing and needs no grant.
- **Extend `CommandRequest` with a session/mutability field.** Rejected — the gpb gateway strips unknown wire fields, and the daemon↔helper channel is local; adding a wire field would be inert end-to-end and is unnecessary.
