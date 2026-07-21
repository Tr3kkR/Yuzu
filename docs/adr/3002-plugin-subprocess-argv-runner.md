---
status: proposed
date: 2026-07-21
owner: "@Doomgoose (Alex Young)"
deciders: >-
  Proposed. To be ratified by the engineering colleagues. Grounded in the standing rule at
  docs/cpp-conventions.md §Shell/process boundaries and the plugin CodeQL queries that
  already police non-literal spawn arguments. An independent external pre-PR review
  (2026-07-21, verdict REQUEST-CHANGES) was adjudicated against the code; every accepted
  blocking finding is folded into this revision.
depends-on: >-
  The shared argv runner (agents/core subprocess_runner, work item BR-001) currently on
  feat/macos-subproc-runner-certs (#2273/#2274, PR #2321 stacked on #2277). This ADR sets
  the target state; the runner landing on dev is the prerequisite for the migration waves.
related: >-
  docs/agent-privilege-model.md (macOS agent is root, Windows LocalSystem today — the
  privilege context; and the Linux sudo-boundary rules Decision 7 preserves).
  fork_lock.hpp / BR-001 (the macOS pipe()+fork() race whose residual gap is the
  uncovered popen sites). .github/codeql/queries/cpp/plugin-command-exec-non-literal.ql
  and plugin-windows-process-spawn-non-literal.ql (existing detection — see Decision 9
  on making them a failing gate). agents/plugins/tar/src/tar_mapdrive_collector.cpp
  (the documented shell exception this ADR re-homes onto the runner).
  docs/yuzu-guardian-design-v1.1.md §restart-process (already mandates posix_spawn —
  the spawn mechanism Decision 8 adopts as the runner's evolution path).
---

# ADR-3002 — Plugins execute subprocesses through the argv runner, never a raw shell

## The two models, in plain terms

Every external command a plugin runs ends up as an `exec` of some binary. The question
this ADR settles is what stands between the plugin and that binary.

### Model 1 — the shell (what ~26 plugins do today)

`popen("...")` does not run your command. It runs a **shell** — `/bin/sh -c` on
POSIX, `cmd.exe /c` on Windows — and hands it your command **as a string to interpret**:

```
run_command("ping -c 3 " + host)
        │
        ▼
  /bin/sh -c "ping -c 3 8.8.8.8"      ← EXTRA PROCESS, EXTRA STEP: the shell
        │                                parses the string — splits words, expands
        │                                | ; && > * $VAR — and decides what to run
        ▼
  /sbin/ping -c 3 8.8.8.8             ← the command we actually wanted
```

The shell is an interpreter inserted between us and the tool. Everything in the string
is *code* to it. That is the feature — and the flaw:

- **Feature:** `"system_profiler ... | grep 'Boot ROM' | awk '{print $2}'"` is one
  line; the shell wires up the pipeline (four processes) for us.
- **Flaw:** if `host` above arrives as `8.8.8.8; rm -rf /`, the shell faithfully
  executes **both** commands. Data got promoted to code, because to a shell the whole
  string is code. Every hand-rolled allowlist in the plugins today
  (`is_safe_host()`, `shell_single_quote()`) exists only to fight this one property.

### Model 2 — the argv runner (the target state)

An argv runner skips the interpreter. The plugin hands the kernel a **pre-split
argument array** and the runner execs the binary directly:

```
run_subprocess({"/sbin/ping", "-c", "3", host}, deadline_ms)
        │
        ▼
  /sbin/ping -c 3 8.8.8.8             ← direct exec; arguments passed through as-is
```

There is **no string-parsing step between us and the tool**. Consequences:

- **Shell-metacharacter injection is eliminated structurally, not mitigated.**
  `host` = `8.8.8.8; rm -rf /` reaches ping as one inert argument; ping fails to
  resolve it. Argument boundaries are fixed by the array, never discovered by parsing.
  **Scope this claim precisely**: what argv removes is the *outer shell's* parsing.
  It does not remove **option injection** (a value starting with `-` can still be
  read as a flag by the tool — see Decision 5), and it does not remove
  **interpreter-payload injection** where a script string is itself the argument
  (PowerShell, bash, AppleScript — see Decision 4). Per-tool validation remains
  mandatory; it just stops being the only line of defense against arbitrary
  command execution.
- **No quoting problem** — a filename with spaces or quotes is just one element.
- **No PATH search for the launched tool** — the runner requires absolute paths
  (`execv`, not `execvp`), so a planted binary can never shadow the tool we launch.
  (This protects the *initially launched* executable only: interpreters, scripts
  using `/usr/bin/env`, and tools that spawn their own helpers can still PATH-search
  internally.) This matters because the agent is root/LocalSystem on two of three
  platforms.
- **Usually one process, not two** — we stop paying for a shell on every command.
  (For a simple command some shells `exec` the tool in place; the real waste is the
  pipeline helpers — `grep`, `awk`, `head` — which our shell strings use pervasively.)
- **The runner owns the child**: hard wall-clock deadline, process-group kill, output
  caps, cooperative cancel, and a result that distinguishes "tool missing" from
  "tool ran and failed" from "killed at deadline". `popen` as used in this codebase
  provides none of that — the ~26 helper copies have no timeout, mostly drop exit
  codes, and lose stderr.

What the shell's interpreter did for us, we do explicitly — and each piece has a
natural home we already use:

| Shell feature | Argv-world replacement |
|---|---|
| `\| grep \| awk '{print $2}'` | run the base tool, extract in C++ (`*_parsers.hpp` — already our test discipline) |
| `\| head -100` | the runner's `max_lines` output cap |
| `2>/dev/null`, `2>&1` | runner wires the child's stderr itself — capture or discard |
| `ls /boot/vmlinuz-*` | `std::filesystem` directory iteration |
| `cmd1 \|\| cmd2` | check exit code, run the second argv |
| `command -v tool` probes | stat an absolute-path probe list |
| PATH lookup | first-existing-path-wins probe helper |

## Context

- **Current state is split and skewed.** ~26 of 49 plugins spawn commands through
  per-plugin shell helpers of varying shapes — `run_command`, `run_command_rc`,
  `run_command_lines`, bare `system()` probes, and bespoke helpers in `tar` and
  `interaction` — all wrapping `popen()`/`system()`. Exactly three plugins exec
  directly today (`script_exec`, `content_dist`, `filesystem`), each with its own
  private helper. The helper divergence is itself the disease: timeouts, exit-code
  handling, and stderr behaviour differ per copy.
- **The standard already points one way.** `docs/cpp-conventions.md` §Shell/process
  boundaries mandates argv-style execution, with shell sites requiring a documented
  exception; two custom CodeQL queries detect non-literal arguments to
  `system`/`popen`/`exec*`/`CreateProcess`/`ShellExecute` in plugin sources. The
  fleet has never been migrated to match the rule — and the queries upload SARIF
  without failing CI (see Decision 9).
- **The risk is not hypothetical.** Governance history records 4 CRITICAL
  command-injection vulnerabilities shipped in waves 1–4. The surviving shell sites
  interpolate values that are untrusted or attacker-influenceable — operator/server
  params (ping hosts in `network_actions`/`wol`), values derived from validated
  input (`discovery` IPs), and local-system-sourced strings (`users` usernames from
  `/etc/passwd`, `license_scan` filenames, `certificates` filesystem paths) — each
  guarded only by a per-site allowlist or hand-rolled quoting.
- **The `popen` helpers are operationally weak**: no timeout at all (a hung
  `system_profiler` blocks a plugin thread forever — flagged in-code in
  `windows_updates`), exit codes mostly dropped, stderr silently lost.
- **macOS fork-safety (BR-001).** macOS has no `pipe2()`; the global fork lock
  serialises the `[pipe()..fork()]` window in the launcher implementations that take
  it today (the runner, `script_exec`, `content_dist`, and `trigger_engine`'s macOS
  `popen`). The ~26 scattered plugin `popen` calls are explicitly **not** covered —
  each is an unserialised `fork()` that can leak fds. The residual closes only if
  **every** spawn, including approved shell use, routes through covered code — which
  is what Decisions 1 and 6 require.
- **A shared runner now exists** (`agents/core` `subprocess_runner`, on
  `feat/macos-subproc-runner-certs`): fixed argv, absolute-path `execv`, own process
  group, deadline + SIGKILL + reap, line caps, exec-error pipe, cooperative cancel;
  it lives in agent-core deliberately so its reaper thread survives plugin
  `dlclose()`. On that branch `filesystem` is fully migrated; `certificates` and
  `event_logs` are migrated on their macOS paths (their generic paths still carry
  `popen` helpers — in scope for the waves below). The branch also already
  establishes the governed-shell shape this ADR adopts: `certificates` routes one
  validated `{"/bin/sh", "-c", cmd}` call *through the runner* where the outer
  shell's `~username` expansion is genuinely needed.

## Concurrency and centralisation — why one runner is not a chokepoint

A reasonable objection to a single hardened runner in agent-core: doesn't that
concentrate all subprocess work behind one component and create a concurrency
bottleneck / single point of failure? It does not, and the distinction matters enough
to record.

**The runner is shared *code*, not a shared *service*.**
`run_bounded_subprocess()` is a stateless, reentrant free function. There is no
singleton, no dispatcher thread, no work queue, no pool. When N plugins call it
concurrently, each call runs on its own caller's thread, forks its own child, and
drains its own pipe. Runtime execution is already per-call and ephemeral; only the
implementation is centralised. There is no serialised dispatch path to back up, and
no runner "process" whose death is a distinct failure mode — the code fails or
succeeds on the caller's thread exactly as plugin-local code would.

Three things *are* shared across concurrent calls, each bounded:

1. **The fork lock** (`global_fork_lock()`, BR-001) — held from the first `pipe()`
   through `fork()` only, released in the parent the instant `fork()` returns.
2. **The cooperative cancel flag** — a single `std::atomic<bool>`; contention-free.
3. **Detached reaper threads** — spawned only on the rare path where a SIGKILLed
   child cannot be confirmed-reaped within a short bound; normally none exist.

**The lock must be process-global; the single runner is the engineering choice that
makes its coverage auditable.** All plugins load into the one agent process, and
`fork()` clones that entire process — every fd open anywhere in it. The BR-001 race
is cross-plugin by nature: plugin A opens a pipe, and before A can set `FD_CLOEXEC`
(macOS has no `pipe2()`), plugin B forks on another thread and inherits A's
half-configured pipe. So *whatever* the architecture, one process-global lock must
exist and every spawn site must take it. In principle N separate implementations
could all share that one lock; in practice that is exactly today's failure mode —
`fork_lock.hpp` itself warns that any site which forgets the lock silently reopens
the race, and ~26 scattered helpers is how sites get forgotten. One runner makes
"every spawn takes the lock" a property of the architecture instead of a per-site
discipline, and makes a future spawn-mechanism swap (Decision 8) a one-file change.

**Contention is expected to be negligible at our workload — and is verified, not
assumed.** The lock's critical section is two `pipe()` calls, four
`fcntl(F_SETFD)` calls, and one `fork()` — tens to a few hundred microseconds,
dominated by fork's page-table copy. Everything expensive (the child tool's actual
runtime — a `system_profiler` call takes seconds) executes fully in parallel,
outside the lock. Interval triggers have a 30 s floor and the heaviest sweep is ~10
commands; bursts can also arrive from operator/API commands and agent-startup
triggers independent of that floor, so the Verification section includes a
representative-load latency measurement rather than resting on this arithmetic.
The genuinely scarce resource in a burst is plugin-host *threads* (each call blocks
its caller up to the deadline) — a property of synchronous spawning that is
identical under `popen` today and identical under any per-plugin runner; an async
variant on the same runner is the fix if it ever matters, not decentralisation.

**Scaling levers, should spawn rate ever grow orders of magnitude** (e.g. a future
per-event spawner): both work *through* the single API and neither is reachable from
26 plugin-local copies —

- **`posix_spawn` + `POSIX_SPAWN_CLOEXEC_DEFAULT` (Darwin)** — a documented,
  public Apple extension (non-POSIX, non-portable): every fd not explicitly mapped
  via file actions is closed in the child, eliminating the pipe/CLOEXEC race with
  *no lock at all*; spawns become fully concurrent and the fork lock retires on
  macOS. Linux needs no equivalent (`pipe2(O_CLOEXEC)` exists). Guardian's
  restart-process already mandates `posix_spawn`. Adopted, with hedges, as the
  runner's evolution path (Decision 8).
- **Fork-broker helper process** (zygote pattern) — a tiny single-threaded process
  spawned at agent boot that receives argv over a socket and fork/execs from a
  thread-free context, passing output fds back. Removes forking-from-a-threaded-
  process entirely. Recorded as the contingency; unjustified at current cadence.

## Decision

1. **Plugins never spawn a process through a raw API.** No `popen()`, `_popen()`,
   `system()`, raw `fork()`/`exec*`, or raw `CreateProcess`/`ShellExecute` in
   `agents/plugins/*`. **Every** subprocess — including the narrow governed shell
   use of Decisions 4 and 6 — goes through the shared agent-core argv runner
   (`subprocess_runner`) once it lands on `dev`, so every spawn gets the fork lock,
   a deadline, output caps, and cancel support with no per-site discipline required.
2. **The runner is the single spawn path**: absolute-path argv exec by default, no
   PATH search, deadline mandatory, output capped, fork-lock covered. Per-plugin
   spawn helpers are deleted as their plugins migrate — no new private
   `run_command` copies.
3. **The runner stays a stateless library seam, never a service** — reentrant free
   function on the caller's thread; no queue, no dispatcher, no shared pool; any
   future throughput work (async variant, `posix_spawn`, broker) preserves this
   contract behind the same API. It is an **internal seam for bundled in-tree
   plugins** (built with the repo toolchain, linking `yuzu_agent_core_dep`) and is
   **not part of the stable C plugin ABI** — its C++ signature must never be
   presented to third-party plugin authors; if it is ever exposed beyond the
   bundled set, a C-compatible wrapper (argv pointer/count, POD options,
   host-owned result + destroy) is required first.
4. **Interpreters are argv'd, not shelled.** Where an interpreter is genuinely the
   tool (`powershell -NoProfile -Command …`, `bash` in `script_exec`, or `/bin/sh`
   itself when a shell capability like `~username` expansion is truly required),
   it is exec'd **through the runner** with the script/expression as a single argv
   element built from validated or compile-time-constant parts — the shape
   `certificates` already uses on the branch. The outer spawn is thereby safe and
   bounded; the embedded script content remains code and stays a per-site security
   review concern.
5. **Argument hygiene remains mandatory — argv is not a licence to skip validation.**
   Argv eliminates shell-metacharacter injection only. Every migrated site must:
   handle option injection (pass `--` before positional values where the tool
   supports it, or reject leading-`-` values — today's `is_safe_host()` permits a
   leading `-`); keep numeric parameters bounds-checked; keep per-tool allowlists
   as defense-in-depth; and treat any interpreter payload under Decision 4 as code.
6. **Documented exceptions are registered call identities, narrowly.** An exception
   names the exact function/call site (never a whole file), uses only compile-time
   constant or allowlist-validated strings, carries an in-code comment stating why
   the shell capability is unavoidable, and **executes via the runner's Decision-4
   shell shape — never raw `popen()`**. The `tar` collectors' current `popen` calls
   migrate onto that shape (their commands stay shell strings; the spawn becomes
   runner-owned), which is what actually closes the BR-001 residual — a retained
   raw `popen` exception would sit outside the fork lock and keep the race alive.
7. **Privileged execution on Linux keeps the sudo boundary intact.** Linux runs the
   agent unprivileged with narrow `sudo NOPASSWD` grants matched against specific
   command forms (`docs/agent-privilege-model.md`). The canonical privileged argv is
   `{"/usr/bin/sudo", "-n", "--", "/abs/path/tool", args…}`; every migrated
   privileged site must be checked against the sudoers grant it relies on — a
   shell-string-to-argv rewrite must neither bypass `sudo -n` nor change the
   command/argument form the grant matches.
8. **Spawn-mechanism evolution: `posix_spawn` + `POSIX_SPAWN_CLOEXEC_DEFAULT` on
   macOS**, retiring the fork lock there, behind the unchanged
   `run_bounded_subprocess` API. Hedged: the flag is a public but Darwin-only,
   non-POSIX extension — adoption is gated on compile-time availability and
   minimum-supported-macOS tests, with the current fork-lock design (correct today)
   as the standing fallback. Not a migration blocker; recorded as direction, and a
   reason the single-runner decision is load-bearing — a spawn-mechanism swap is
   only feasible through one implementation.
9. **Enforcement becomes a failing CI gate, not a convention.** The plugin CodeQL
   queries are extended to flag **any** raw spawn call — `popen`/`system`,
   `fork`/`exec*`, `CreateProcess*`/`ShellExecute*` — outside the runner
   implementation, plus shell-interpreter argv patterns (`"/bin/sh", "-c"`) that
   bypass the Decision-4/6 governed shapes, across `agents/plugins/*` **and** the
   agent-core collector/trigger paths. Exceptions are allowlisted by call identity
   (Decision 6), never by file. And because today's `codeql.yml` uploads SARIF
   without failing the build, the gate is completed by either a failing SARIF-count
   step or a required GitHub code-scanning branch-protection check — verified, not
   assumed. Query unit tests pin the intended matches.

## Considered alternatives

- **Per-plugin ephemeral argv runners** (each plugin instantiates its own runner, or
  a header-only helper compiled into each plugin). Rejected:
  - *No isolation gained* — plugins are `.so`/`.dll` images in the same agent
    process; same address space, same fate-sharing as core code.
  - *Fork-lock coverage becomes per-site discipline again* — the race is
    cross-plugin, so every copy must remember the process-global lock; scattered
    copies forgetting it is precisely BR-001's residual today. (A plugin-local
    wrapper *could* share core's lock and reaper — but then the hard parts live in
    core anyway, and only the drift-prone parts are duplicated.)
  - *Cannot own the reaper* — the agent `dlclose()`s plugins on reconnect/shutdown;
    a detached thread whose code lives in a plugin image gets unmapped from under
    it. A plugin-local runner must therefore block its thread in `waitpid` on an
    unkillable child (reintroducing the indefinite hang that is a headline reason
    to leave `popen`) or leak zombies.
  - *Regenerates copy drift* — divergent per-plugin helpers are precisely why
    timeouts, exit codes, and stderr handling are inconsistent today.
- **A serialised spawn service** (single dispatcher thread/queue owning all spawns).
  Never proposed, rejected pre-emptively: it is the strawman the "centralisation"
  worry correctly fears. Decision 3 forbids it.
- **Fork-broker helper process** (zygote pattern). Deferred, not rejected — the
  contingency if spawn rates ever grow orders of magnitude (see Concurrency
  section). Unjustified complexity at a 30 s trigger floor.
- **Status quo** (per-plugin `popen` + allowlists). Rejected on the Context
  evidence: 4 shipped CRITICAL injections, no timeouts, uncovered fork race,
  root/LocalSystem privilege.

## What we must refactor

### Step 0 — the sink manifest (first migration artifact)

Before wave work starts, generate a complete manifest of every spawn call site —
one row each: plugin/file/line, mechanism (`popen`/`system`/raw exec), platform,
**data provenance** (operator/server param, derived, filesystem, constant),
mutating vs read-only, shell features used, environment/cwd/stdin needs, output
semantics, **privilege path (sudoers grant, if any)**, target wave, and the test
that covers the migration. The wave lists below are the starting inventory, not the
authority — the manifest is, and it is how "no site missed" is proven at the end.

### Runner API work to close first (prerequisites, in agent-core; feed back to #2321 follow-ups)

- **Windows implementation** — currently a stub. The contract must specify:
  explicit absolute `lpApplicationName`; a documented UTF-8→UTF-16, CRT-compatible
  argv→command-line serialization; `STARTUPINFOEXW` with an explicit
  inherited-handle list; the child created suspended and assigned to a
  kill-on-close Job Object *before* resume (avoiding the child-before-job race);
  RAII on all handles; and quoting edge-case tests (empty args, spaces, embedded
  quotes, trailing backslashes, Unicode, embedded-NUL rejection) plus
  integration tests for non-CRT parsers (`cmd.exe`, PowerShell).
- **Honest termination reporting** — add an explicit termination reason
  (`exited` / `signaled` / `deadline` / `cancelled` / `line_limit` /
  `spawn_error`) so the current `stop_after_max_lines` success-sentinel
  (`exit_code = 0` after a deliberate SIGKILL) becomes an explicit reason instead
  of a fabricated exit status, matching the header's "never fabricate" contract.
- **Contract enforcement at the boundary** — reject relative `argv[0]` and
  embedded NULs at runtime (today absolute-path is caller-discipline only); make
  the output byte cap caller-configurable (the 1 MB sanity cap is fixed;
  `script_exec` needs 16 MiB).
- **Environment / locale / stdio policy** — explicit child environment control
  (sanitized env, `LC_ALL=C` option so wave-3 C++ parsers never meet localized
  tool output), stdin → `/dev/null` by default, intentional signal defaults.
- **stderr policy** — `merge_stderr` exists (capture or `/dev/null`); confirm it
  covers all `2>&1`/`2>/dev/null` call-site patterns during wave 2.
- **Tool path probing** — a "first existing absolute path wins" helper (e.g. `ip`
  differs across distros). Note honestly: stat-then-exec is still a filesystem
  TOCTOU if an attacker can replace the probed binary — root-owned tool
  directories are the mitigation, not the probe itself.
- **Streaming output** — wave 4 (`script_exec`) needs incremental line delivery to
  the command context, not just collect-at-end.

### Wave 1 — sites executing untrusted or attacker-influenceable values (highest priority)

Values interpolated into shell strings today, behind per-site allowlists/quoting
(provenance per site recorded honestly in the manifest — not all are
operator-supplied, all are influenceable):

- `network_actions` — ping host/count (operator/server params)
- `wol` — ping host (operator/server param)
- `discovery` — target IPs derived from validated CIDR
- `users` — usernames read from `/etc/passwd` into `lastlog -u …`
- `license_scan` — filesystem filenames via hand-rolled `shell_single_quote()`
- `certificates` — filesystem paths and thumbprints interpolated into
  OpenSSL/security commands on `dev` (moved here from the "mechanical" wave —
  it is not literal-only)
- `quarantine` — destructive file operations (mutating; high blast radius)
- `services` — service mutation commands (mutating)
- `interaction` — scripts built from operator-supplied content (interpreter
  payload; pairs with Decision 4 review)

The allowlists stay (defense-in-depth per Decision 5) but stop being the only line
of defense.

### Wave 2 — literal single-command sites (mechanical swaps)

Straight `run_command("tool args")` with no shell features: swap to a runner call
with a probed absolute path. Representative set (the pattern repeats): `hardware`,
`os_info`, `device_identity`, `antivirus`, `bitlocker`, `sccm`, `network_diag`,
`processes` (`ps -axo …`), `firewall`. Sites whose only shell feature is
`2>/dev/null`/`2>&1`/`2>nul` also land here via `merge_stderr`. Branch note: the
`certificates`/`event_logs` migrations on `feat/macos-subproc-runner-certs` cover
their **macOS paths only** — their generic-path `popen` helpers are wave 2/3 work
like everyone else's.

### Wave 3 — shell-feature restructures (pipelines, globs, fallbacks)

Each replaces in-shell text processing with the base tool + C++ filtering — the
same code the `*_parsers.hpp` test discipline wants anyway. Run with `LC_ALL=C`
so parsers never meet localized output:

- **Pipelines** (`… | grep | awk | head | wc`): `wifi` (`iw`/`iwlist`/`iwconfig`),
  `hardware` (`system_profiler`/`ioreg` on macOS), `network_config`
  (`route`/`scutil`), `software_actions` (`yum`/`dpkg` counting),
  `windows_updates` (`rpm`/`apt` listings), `users` (`last | head`),
  `installed_apps` + `vuln_scan` (`system_profiler SPApplicationsDataType`),
  `event_logs` (`log show … | head`), `services` (`launchctl list`). Truncation
  moves to the runner's `max_lines` (+ `stop_after_max_lines` where "first N
  lines" is the whole ask).
- **Glob:** `windows_updates` `ls -t /boot/vmlinuz-* | head -1` →
  `std::filesystem` iteration + mtime sort.
- **Fallback chain:** `network_actions` `systemd-resolve … || true` → run first
  argv, check exit code, run alternate.
- **`system()` capability probes** (`command -v tool`): `vuln_scan`, `discovery`,
  `installed_apps`, `license_scan` → stat against the probe list.

### Wave 4 — converge the argv islands, agent-core sites, and the tar exception

- `script_exec` and `content_dist` keep their specialised behaviours (env
  whitelist, staged-binary execution, streaming, 16 MiB cap) and converge onto the
  shared runner **only after** the prerequisite runner features above exist — a
  premature convergence would regress behaviour.
- Agent-core shell-outs migrate under the same rule: `dex_macos_collector.cpp`,
  `dex_linux_collector.cpp`, and the `trigger_engine.cpp` `popen` sites (the Linux
  branch of which is also outside the fork lock today).
- `tar` mapdrive/service collectors: re-homed as Decision-6 registered exceptions
  executing via the runner's shell shape — commands stay literal shell strings,
  the raw `popen` spawns go away, and the sites gain the lock/deadline/caps.

### Explicit non-goals

- Windows WMI/Win32-API collection paths are untouched — they never spawn a shell
  and are the preferred mechanism where they exist.
- The Erlang gateway spawns no plugin subprocesses and is out of scope; the only
  interaction is budget arithmetic (an agent-side subprocess deadline must fit
  inside the command/gateway response budget — recorded in the manifest per site).

## Consequences

- **Positive:** arbitrary-command injection via shell metacharacters is eliminated
  structurally in plugins; every spawn — including the surviving shell-string
  exceptions — gains a deadline, output caps, group kill, honest termination
  reporting, and fork-lock coverage; per-command process count drops (no pipeline
  helper processes); ~26 divergent helper copies collapse into one tested seam; the
  standard, the CodeQL gates, and the code finally agree; a future spawn-mechanism
  swap (`posix_spawn`, broker) becomes a one-file change instead of a fleet
  migration.
- **Negative / accepted:** migration effort across ~26 plugins (staged in waves,
  each independently shippable and testable); pipeline sites gain C++ parsing code
  (offset: it lands in `*_parsers.hpp` where it is unit-testable on every host,
  which the shell strings never were); absolute-path probing must track distro
  drift; intermediate output that `| head` used to truncate in-pipeline is now
  produced by the child before the runner's cap truncates it (bounded by the
  runner's caps); spawn bursts still consume one plugin-host thread per in-flight
  call — unchanged from today, revisit with an async runner variant only if
  measured; the runner seam couples bundled plugins to agent-core's C++ API
  (accepted per Decision 3's internal-seam boundary — never for third parties).
- **Risk:** behaviour drift during restructures (a C++ filter subtly unlike the
  `grep`/`awk` it replaces; an argv rewrite subtly unlike the sudoers grant it must
  match). Controlled by fixture-driven parser tests per site — capture real command
  output as the fixture before migrating, assert identical extraction after — and
  by the per-site sudoers verification of Decision 7.

## Verification

- Per-wave: fixture tests in `tests/unit/` for each new/extended `*_parsers.hpp`
  (canned real-output fixtures captured pre-migration, `LC_ALL=C`); plugin suite
  green (`meson test -C build-<os> --suite agent`); on macOS additionally the
  migrated plugins' actions exercised against the live host tools.
- Privilege: for every migrated privileged site, a test that the emitted argv
  matches the sudoers grant form (`sudo -n -- /abs/tool …`) from
  `scripts/install-agent-user.sh` — quarantine, services, network actions,
  certificates, patching.
- Fleet-wide: the extended CodeQL queries (with their own query unit tests) prove
  zero un-excepted raw spawn sites in `agents/plugins/*` and the covered
  agent-core paths; the SARIF gate (or documented branch-protection check) is
  demonstrated to actually fail a PR that adds one; `grep -rn "popen\|system("
  agents/plugins/` matches only Decision-6 registered call sites.
- Runner: `test_subprocess_runner.cpp` extended for the termination-reason enum,
  argv[0]/NUL enforcement, byte-cap configurability, env/locale policy, the probe
  helper, and the Windows quoting edge cases, before the wave that depends on each
  starts.
- Concurrency: a deterministic fork-lock coverage test — a test hook/barrier
  around pipe creation plus direct inspection of child fd state (not just N
  threads racing) — pinning the "library seam, not chokepoint" contract
  (Decision 3); plus a representative-load latency measurement of the fork-lock
  critical section to replace the arithmetic estimate in the Concurrency section.
