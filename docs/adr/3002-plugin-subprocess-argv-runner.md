---
status: proposed
date: 2026-07-21
owner: "@Doomgoose (Alex Young)"
deciders: >-
  Proposed. To be ratified by the engineering colleagues. Grounded in the standing rule at
  docs/cpp-conventions.md §Shell/process boundaries and the plugin CodeQL queries that
  already police non-literal spawn arguments. An independent external pre-PR review
  (2026-07-21, verdict REQUEST-CHANGES) was adjudicated against the code; every accepted
  blocking finding is folded in. Reframed 2026-07-21 from an argv-vs-shell decision into
  the acquisition-ladder standard it enforces. A colleague review on the PR (advisory
  COMMENT, 2026-07-21, findings F1–F10) is folded in this revision: two-tier enforcement
  (per-PR lexical gate + scheduled CodeQL), the out-of-tree spawn-path gap stated, batch
  files banned on Windows, termination honesty elevated to an automation-correctness
  prerequisite gating mutating waves, interpreter sites registered, and the descent rule
  set to evidence-backed justification. The syscall/native-API split was subsequently
  collapsed into a single native-interface rung: every in-process route bottoms out in
  the same syscall layer, and the load-bearing boundaries are the process and the
  interpreter, not wrapper depth.
depends-on: >-
  The shared argv runner (agents/core subprocess_runner, work item BR-001) currently on
  feat/macos-subproc-runner-certs (#2273/#2274, PR #2321 stacked on #2277). This ADR sets
  the target state; the runner landing on dev is the prerequisite for the rung-2/3
  migration waves.
related: >-
  docs/agent-privilege-model.md (macOS agent is root, Windows LocalSystem today — the
  privilege context; and the Linux sudo-boundary rules Decision 8 preserves).
  fork_lock.hpp / BR-001 (the macOS pipe()+fork() race whose residual gap is the
  uncovered popen sites). .github/codeql/queries/cpp/plugin-command-exec-non-literal.ql
  and plugin-windows-process-spawn-non-literal.ql (existing detection — see Decision 10
  on making them a failing gate). agents/plugins/tar/src/tar_mapdrive_collector.cpp
  (the documented shell exception this ADR re-homes onto the runner).
  docs/yuzu-guardian-design-v1.1.md §restart-process (posix_spawn mandate — Decision 9's
  evolution path). docs/tar-implementer.md (capture sources — already built at rung 1:
  Endpoint Security, ETW).
---

# ADR-3002 — The acquisition ladder: how plugins and capture sources get data and act on endpoints

## The ladder

Every plugin action and capture source ultimately asks the operating system a
question ("what model is this machine?", "which TCP connections exist?") or tells
it to do something ("quarantine this file"). There are three ways to ask, and this
ADR fixes their priority order — and the order is **mandatory and sequential**.
Development starts at rung 1, and moves down **one rung at a time, only on
recorded evidence** that the rung above cannot reasonably serve the site: the
native OS interface is considered and ruled out on evidence before spawning a
process, the argv runner before any shell. A
bare assertion ("the API route looked painful") never justifies a descent; a
cited, checkable justification from the categories below does.

```
Rung 1  NATIVE OS INTERFACE  agent ──syscall / kernel surface / OS API──▶ OS  (0 processes, typed data)
Rung 2  ARGV RUNNER          agent ──fork/exec──▶ tool ──▶ text ──▶ C++ parse (1 process)
Rung 3  GOVERNED SHELL       agent ──runner──▶ /bin/sh ──parse──▶ tool ──▶ …  (2+ processes, string = code)
```

Each rung down inserts another layer between the agent and the answer — another
process, another parser, another thing to trust, another way to hang or fail.
The order is therefore also the order of our core principles: lightweight
footprint (a syscall is microseconds; a shell pipeline is 2–4 processes),
security surface (a syscall has no command to inject; a shell string is all
code), and reliability (typed structs don't drift with tool output formats or
locales).

### The rungs, concretely

**Rung 1 — the native OS interface.** Everything in-process: syscalls and
kernel-published surfaces (`sysctlbyname()`, `/proc` and `/sys` reads,
`getifaddrs()`, `statvfs()`, netlink, kernel control sockets) and the OS APIs
and frameworks layered over them (WMI, Win32 APIs such as
`GetExtendedTcpTable` and `Reg*W`, IOKit, Security.framework, Endpoint
Security, ETW, `sd_journal`). Zero processes, near-zero cost, data arrives as
structs or stable kernel text — and there is no meaningful mechanism split
inside this rung: every in-process route bottoms out in the same syscall
layer, differing only in how thick the supported wrapper is. Within the rung,
ordinary engineering judgment prefers the lowest-dependency surface available
(a kernel-published surface over a daemon-mediated framework call that can
block on a wedged service) — a preference, not an evidence-gated step.
Already ours in places: Windows plugins live here
(`hardware`/`bitlocker`/`license_scan` via WMI), the TAR capture sources were
built here from day one (ES on macOS, ETW on Windows — `ProcStreamCollector`
implementations, never spawned tools), `network_diag` reads `/proc/net/tcp`
directly, and the netqual nstat spike replaced a would-be `nettop` spawn with
one kernel-control socket. Platform honesty: "native interface" means the
lowest *supported* surface — on Linux the kernel ABI is the contract; on
macOS and Windows you reach it through libSystem/Win32 wrappers, never raw
syscall numbers (those are unstable there by design).

**Rung 2 — the argv runner.** A subprocess, exec'd directly from a pre-split
argument array through the shared agent-core `subprocess_runner`: absolute
path, no PATH search, no interpreter, hard deadline, output caps,
process-group kill, fork-lock covered. The right rung when the capability
only exists as a CLI, or when a subprocess is *desirable* (see "Justifying a
descent" below).

**Rung 3 — the governed shell.** A shell string — but executed *through the
runner* (`{"/bin/sh", "-c", <validated literal>}`), as a registered exception
only. The shell is an interpreter: everything in the string is code to it,
which is why it sits last and why raw `popen()`/`system()` are banned
outright (Decision 2).

### Same question, three rungs

Reading the hardware model on macOS today: `run_command("sysctl -n hw.model")`
— a shell parses the string, forks, execs `sysctl`, which calls…
`sysctlbyname("hw.model")`. Two processes and a text pipe to reach a one-line
rung-1 call the agent could make itself. The migration's first question per
site is therefore not "how do we argv this?" but **"does this subprocess need
to exist at all?"**

### Justifying a descent — evidence, not assertion

A lower rung is not a failure; an **unevidenced** lower rung is. Every descent
records its justification — in the code and in the sink manifest — drawn from
the recognised categories below, each carrying the evidence named. The
recognised categories:

- **No interface exists at the rung.** The data or action is simply not
  exposed there — no syscall/kernel surface publishes it, or the only
  programmatic surface is a CLI (`softwareupdate`, `launchctl` operations,
  apt/yum/dpkg — no stable library contract, chunks of `system_profiler`).
  Evidence: what was searched and found absent.
- **The rung's only interface is unsupported by platform contract.** A
  private/undocumented ABI is not a shippable interface. Evidence: the
  documented status of the interface (the nstat spike's `ntstat.h` layout
  risk is the canonical example — and also the proof this is judged per site,
  since the kctl route was accepted there with the risk recorded). "Unstable
  by contract" is evidence; "harder to write" is not.
- **The rung cannot satisfy a hard requirement of the site.** Three recognised
  hard requirements: *per-call privilege elevation* on Linux — the agent must
  not hold the privilege in-process, and `sudo` exists only at a process
  boundary, so rung 1 is ruled out for privileged Linux operations
  (Decision 8); *bounded cancellation* — a daemon-backed in-process call with
  a demonstrated wedge history cannot be killed without killing the agent,
  where a child is SIGKILLed at the runner's deadline; *crash isolation* — an
  interface with a demonstrated in-process crash history takes the agent down
  with it, where a child crashes alone. Evidence: the demonstrated behaviour,
  cited — not a hypothetical.
- **Disproportionate cost — the weakest category, reviewed the hardest.** A
  large, risky implementation at the higher rung against a small, reliable
  one below can justify a descent — but only with a **written comparison**
  (what the higher rung demands versus what it buys, e.g. a COM traversal
  sized against a reliable read-only CLI) recorded in the manifest and
  accepted in review. "It was quicker" is an assertion, not a comparison.

## Context

- **The fleet is split by platform and by history.** Windows plugins largely
  live at rung 1 already (WMI/Win32, registry via `Reg*W`); TAR capture
  sources were built at rung 1 (ES/ETW). But 27 of 49 plugins — heavily
  concentrated on macOS and Linux — sit at an *ungoverned* rung 3: per-plugin
  shell helpers of varying shapes (`run_command`, `run_command_rc`,
  `run_command_lines`, bare `system()` probes, bespoke `tar`/`interaction`
  helpers) wrapping `popen()`/`system()`. Exactly three plugins exec directly
  today (`script_exec`, `content_dist`, `filesystem`), each with a private
  helper. The divergence is itself the disease: timeouts, exit-code handling,
  and stderr behaviour differ per copy.
- **The standard already points up-ladder.** `docs/cpp-conventions.md`
  §Shell/process boundaries mandates argv-style execution with documented
  exceptions for shells; two custom CodeQL queries detect non-literal spawn
  arguments in plugin sources — but they upload SARIF without failing CI
  (Decision 10), and nothing records why a site is at the rung it's at.
- **The risk is not hypothetical.** Governance history records 4 CRITICAL
  command-injection vulnerabilities. Surviving rung-3 sites interpolate
  values that are untrusted or attacker-influenceable — operator/server
  params (`network_actions`/`wol` ping hosts), derived values (`discovery`
  IPs), local-system strings (`users` usernames, `license_scan` filenames,
  `certificates` paths) — each guarded only by a per-site allowlist or
  hand-rolled quoting, in an agent that runs root on macOS and LocalSystem on
  Windows.
- **The `popen` helpers are operationally weak**: no timeout (a hung
  `system_profiler` blocks a plugin thread forever — flagged in-code in
  `windows_updates`; the one exception is `tar`, whose literal commands wrap
  coreutils `timeout 10`/`15` — bounds the migration carries into runner
  deadlines), exit codes mostly dropped, stderr lost.
- **macOS fork-safety (BR-001).** macOS has no `pipe2()`. On `dev` today the
  race is wholly unmitigated — `fork_lock.hpp` does not exist there and every
  spawn site runs bare. Once #2321 lands, the global fork lock serialises the
  `[pipe()..fork()]` window in the launchers that take it (the runner,
  `script_exec`, `content_dist`, `trigger_engine`'s macOS `popen`) — but the
  27 spawning plugins' scattered `popen` calls remain **not** covered; each
  is an unserialised `fork()` that can leak fds. The residual closes only if
  every spawn, including approved shell use, routes through covered code
  (Decisions 2 and 7). Rung-1 promotions close it harder still — a spawn
  that no longer exists cannot race.
- **A shared runner now exists** (`agents/core` `subprocess_runner`, on
  `feat/macos-subproc-runner-certs`): fixed argv, absolute-path `execv`, own
  process group, deadline + SIGKILL + reap, line caps, exec-error pipe,
  cooperative cancel; in agent-core deliberately so its reaper thread
  survives plugin `dlclose()`. On that branch `filesystem` is fully migrated;
  `certificates`/`event_logs` are migrated on their macOS paths only. The
  branch also establishes the governed rung-3 shape: `certificates` routes
  one validated `{"/bin/sh", "-c", cmd}` call *through the runner* where the
  outer shell's `~username` expansion is genuinely needed.

## The subprocess rungs in plain terms — shell vs argv

For readers new to the distinction the bottom two rungs turn on: `popen("...")`
does not run your command. It runs a **shell** — `/bin/sh -c` on POSIX,
`cmd.exe /c` on Windows — and hands it your command **as a string to
interpret**:

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

Everything in the string is *code* to the shell. That is the feature — one line
buys pipelines like `system_profiler … | grep 'Boot ROM' | awk '{print $2}'` —
and the flaw: if `host` arrives as `8.8.8.8; rm -rf /`, the shell faithfully
executes **both** commands. Every hand-rolled allowlist in the plugins today
(`is_safe_host()`, `shell_single_quote()`) exists only to fight this property.

The argv runner skips the interpreter — a pre-split array, exec'd directly:

```
run_bounded_subprocess({"/sbin/ping", "-c", "3", host}, opts)
        │
        ▼
  /sbin/ping -c 3 8.8.8.8             ← direct exec; arguments passed through as-is
```

No string-parsing step exists between us and the tool, so:

- **Shell-metacharacter injection is eliminated structurally, not mitigated** —
  `8.8.8.8; rm -rf /` reaches ping as one inert argument. Scope the claim
  precisely: argv removes the *outer shell's* parsing. It does not remove
  **option injection** (a leading-`-` value read as a flag — Decision 6) or
  **interpreter-payload injection** (a script string is still code —
  Decision 5). Per-tool validation stays mandatory; it stops being the only
  line of defense.
- **No quoting problem** — a filename with spaces is one element.
- **No PATH search for the launched tool** (`execv`, absolute paths) — though
  this protects the initially launched executable only; interpreters and
  `/usr/bin/env` scripts can still PATH-search internally.
- **Usually one process, not two** — and none of the pipeline helpers
  (`grep`/`awk`/`head`), whose work moves into unit-testable C++.
- **The runner owns the child** — deadline, group kill, caps, cancel, and a
  result distinguishing "tool missing" from "ran and failed" from "killed".
  `popen` as used here provides none of that.

What the shell's interpreter did, we do explicitly — each piece has a home we
already use:

| Shell feature | Replacement |
|---|---|
| `\| grep \| awk '{print $2}'` | run the base tool, extract in C++ (`*_parsers.hpp` — the test discipline) |
| `\| head -100` | the runner's `max_lines` cap |
| `2>/dev/null`, `2>&1` | runner wires child stderr — capture or discard |
| `ls /boot/vmlinuz-*` | `std::filesystem` iteration |
| `cmd1 \|\| cmd2` | check exit code, run second argv |
| `command -v tool` probes | stat an absolute-path probe list |
| PATH lookup | first-existing-path-wins probe helper |

## Concurrency and centralisation — why one runner is not a chokepoint

A reasonable objection to a single hardened runner in agent-core: doesn't that
concentrate all subprocess work behind one component and create a concurrency
bottleneck / single point of failure? It does not, and the distinction matters
enough to record.

**The runner is shared *code*, not a shared *service*.**
`run_bounded_subprocess()` is a stateless, reentrant free function. There is no
singleton, no dispatcher thread, no work queue, no pool. When N plugins call it
concurrently, each call runs on its own caller's thread, forks its own child,
and drains its own pipe. Runtime execution is already per-call and ephemeral;
only the implementation is centralised. There is no serialised dispatch path to
back up, and no runner "process" whose death is a distinct failure mode.

Three things *are* shared across concurrent calls, each bounded: the fork lock
(held from the first `pipe()` through `fork()` only), the cooperative cancel
flag (one contention-free atomic), and detached reaper threads (rare path only;
normally none exist).

**The lock must be process-global; the single runner is the engineering choice
that makes its coverage auditable.** All plugins load into the one agent
process, and `fork()` clones that entire process — every fd open anywhere in
it. The BR-001 race is cross-plugin by nature: plugin A opens a pipe, and
before A can set `FD_CLOEXEC` (no `pipe2()` on macOS), plugin B forks on
another thread and inherits A's half-configured pipe. So whatever the
architecture, one process-global lock must exist and every spawn site must take
it. In principle N implementations could share that lock; in practice that is
today's failure mode — `fork_lock.hpp` warns that any site which forgets it
silently reopens the race, and 27 scattered helpers is how sites get
forgotten. One runner makes "every spawn takes the lock" a property of the
architecture instead of a per-site discipline, and makes a spawn-mechanism swap
(Decision 9) a one-file change.

**Contention is expected to be negligible at our workload — and is verified,
not assumed.** The critical section is two `pipe()` calls, four
`fcntl(F_SETFD)` calls, and one `fork()` — tens to a few hundred microseconds,
dominated by fork's page-table copy. The child tool's actual runtime (seconds,
for `system_profiler`) executes fully in parallel outside the lock. Interval
triggers floor at 30 s and the heaviest sweep is ~10 commands; bursts can also
arrive from operator/API commands and startup triggers, so Verification
includes a representative-load latency measurement rather than resting on this
arithmetic. The genuinely scarce resource in a burst is plugin-host *threads*
(each call blocks its caller up to the deadline) — identical under `popen`
today and under any per-plugin runner; an async variant on the same runner is
the fix if ever measured, not decentralisation. And every rung-1 promotion
removes its spawn from the picture entirely.

**Scaling levers, should spawn rate ever grow orders of magnitude** — both work
*through* the single API and neither is reachable from 27 plugin-local copies:

- **`posix_spawn` + `POSIX_SPAWN_CLOEXEC_DEFAULT` (Darwin)** — a documented,
  public Apple extension (non-POSIX, non-portable): every fd not explicitly
  mapped via file actions is closed in the child, eliminating the pipe/CLOEXEC
  race with *no lock at all*. Linux needs no equivalent (`pipe2(O_CLOEXEC)`).
  Guardian's restart-process already mandates `posix_spawn`. Adopted, hedged,
  as the runner's evolution path (Decision 9).
- **Fork-broker helper process** (zygote pattern) — a single-threaded
  boot-time process receiving argv over a socket, fork/exec'ing from a
  thread-free context. Removes forking-from-a-threaded-process entirely.
  Contingency only; unjustified at current cadence.

## Decision

1. **The ladder is mandatory and sequential, and every descent is
   evidence-backed.** Every new data-acquisition or action path in plugins
   and capture sources starts at rung 1 — the native OS interface is
   considered first — and moves down **one rung at a time, only on recorded
   evidence** from the recognised categories above (no interface exists; only
   interface unsupported by platform contract; a hard requirement —
   privilege elevation, bounded cancellation, crash isolation — demonstrably
   unmeetable; a written disproportionate-cost comparison). The native
   interface is ruled out on evidence before spawning a process, the argv
   runner before any shell. Each descent's **rung evidence** is recorded in
   the code and in the sink manifest; a bare assertion is not evidence;
   reviewers reject any descent without it. Existing sites acquire their
   evidence chain as the migration reaches them.
2. **Plugins never spawn a process through a raw API.** No `popen()`,
   `_popen()`, `system()`, raw `fork()`/`exec*`, or raw
   `CreateProcess`/`ShellExecute` in `agents/plugins/*`. Every subprocess —
   including the governed shell of Decisions 5 and 7 — goes through the shared
   agent-core argv runner once it lands on `dev`, so every spawn gets the fork
   lock, a deadline, output caps, and cancel support with no per-site
   discipline required.
3. **The runner is the single spawn path**: absolute-path argv exec by
   default, no PATH search, deadline mandatory, output capped, fork-lock
   covered. Per-plugin spawn helpers are deleted as their plugins migrate — no
   new private `run_command` copies.
4. **The runner stays a stateless library seam, never a service** — reentrant
   free function on the caller's thread; no queue, no dispatcher, no shared
   pool; any future throughput work preserves this contract behind the same
   API. It is an **internal seam for bundled in-tree plugins** and **not part
   of the stable C plugin ABI** — its C++ signature must never be presented to
   third-party plugin authors; if ever exposed beyond the bundled set, a
   C-compatible wrapper (argv pointer/count, POD options, host-owned result +
   destroy) comes first. Until that wrapper ships, out-of-tree plugin authors
   have **no sanctioned spawn path** — a deliberate, stated gap: this ADR's
   structural guarantees cover bundled plugins, and the C wrapper is
   scheduled as a named follow-up work item rather than implied.
5. **Interpreters are argv'd, not shelled.** Where an interpreter is genuinely
   the tool (`powershell -NoProfile -Command …`, `bash` in `script_exec`, or
   `/bin/sh` itself when a shell capability like `~username` expansion is
   truly required), it is exec'd **through the runner** with the
   script/expression as a single argv element built from validated or
   compile-time-constant parts — the shape `certificates` already uses on the
   branch. The outer spawn is safe and bounded; the embedded script content
   remains code and stays a per-site security review concern. Decision-5
   interpreter sites are **registered in the same call-identity ledger as
   Decision-7 exceptions**, so the "argv'd interpreter" population is
   enumerable and audited — at least eight plugins build PowerShell command
   strings today, several from runtime values, and each is a payload CodeQL
   cannot inspect. The ladder shrinks this set too: PowerShell query sites
   with native WMI/COM equivalents should cease to exist rather than be
   migrated.
6. **Argument hygiene remains mandatory — argv is not a licence to skip
   validation.** Every migrated site must handle option injection (pass `--`
   before positional values where supported, or reject leading-`-` values —
   today's `is_safe_host()` permits a leading `-`), keep numeric parameters
   bounds-checked, keep per-tool allowlists as defense-in-depth, and treat any
   interpreter payload under Decision 5 as code.
7. **Documented rung-3 exceptions are registered call identities, narrowly.**
   An exception names the exact function/call site (never a whole file), uses
   only compile-time constant or allowlist-validated strings, carries an
   in-code comment stating why the shell capability is unavoidable, and
   **executes via the runner's Decision-5 shape — never raw `popen()`**. The
   `tar` collectors' `popen` calls migrate onto that shape (commands stay
   shell strings; the spawn becomes runner-owned) — which is what actually
   closes the BR-001 residual; a retained raw `popen` would sit outside the
   fork lock and keep the race alive.
8. **Privileged execution on Linux keeps the sudo boundary intact — and stays
   rung 2 by design.** Linux runs the agent unprivileged with narrow
   `sudo NOPASSWD` grants matched against specific command forms
   (`docs/agent-privilege-model.md`); per-call elevation exists only at a
   process boundary, so rung-1 promotion is out of scope for privileged
   Linux operations. The canonical privileged argv is
   `{"/usr/bin/sudo", "-n", "--", "/abs/path/tool", args…}`; every migrated
   privileged site is checked against the sudoers grant it relies on — a
   rewrite must neither bypass `sudo -n` nor change the form the grant
   matches. The per-site verification also (a) preserves the existing
   run-as-root conditional (sites skip `sudo` when `geteuid() == 0`), and
   (b) runs against a **live sudoers install** from
   `scripts/install-agent-user.sh`, not just a string comparison against the
   grant text.
9. **Spawn-mechanism evolution: `posix_spawn` + `POSIX_SPAWN_CLOEXEC_DEFAULT`
   on macOS**, retiring the fork lock there, behind the unchanged
   `run_bounded_subprocess` API. Hedged: the flag is a public but Darwin-only,
   non-POSIX extension — adoption gates on compile-time availability and
   minimum-supported-macOS tests, with the current fork-lock design (correct
   today) as the standing fallback.
10. **Enforcement: a per-PR lexical gate now, CodeQL as the deep net; review
    gates the rung.** Two honest facts shape this: today's `codeql.yml` never
    runs C++ analysis on pull requests (the analyze job is gated to
    schedule/dispatch only), and the current queries are narrower than this
    ADR needs (non-literal arguments only; a path filter that misses the
    agent-core collector/trigger sites; no `fork`/`posix_spawn` coverage; no
    allowlist mechanism; no executed query tests). Enforcement is therefore
    two-tier: (a) a **per-PR lexical gate** — a zero-cost script check in the
    PR pipeline (the `check-compose-versions.sh` pattern) that fails any PR
    introducing a raw spawn token (`popen`, `_popen`, `system(`, `fork(`,
    `exec*`, `posix_spawn`, `CreateProcess`, `ShellExecute`) in
    `agents/plugins/*` or the covered agent-core paths outside the registered
    allowlist — exceptions by call identity, never by file; and (b) **CodeQL
    extended as the scheduled deep net** — widened paths, full spawn-API
    coverage, the call-identity allowlist, and executed query tests. Making
    CodeQL itself run per-PR is an explicit capacity decision (a full traced
    build per PR on the self-hosted pools), recorded as open — not assumed.
    Rung *choice* (1 vs 2) is not machine-checkable — it is enforced by the
    Decision-1 rung evidence in code review and the manifest.

## Considered alternatives

- **Rung 1 only (ban subprocesses outright).** Rejected: some capabilities
  exist only as CLIs; the CLI is sometimes the more stable contract than a
  private ABI; the subprocess boundary provides kill-ability and crash
  isolation that in-process calls cannot; and the Linux privilege model
  requires a process boundary to elevate through. The ladder captures the
  preference without pretending the top rung always reaches.
- **Per-plugin ephemeral argv runners** (each plugin its own runner/helper).
  Rejected: no isolation gained (same process, same address space); fork-lock
  coverage becomes per-site discipline again — scattered copies forgetting the
  process-global lock is precisely BR-001's residual today; a plugin-local
  runner cannot own the reaper (the agent `dlclose()`s plugins, so a detached
  thread's code gets unmapped — forcing a blocking `waitpid` on unkillable
  children or zombie leaks); and it regenerates the copy drift that made
  timeouts/exit codes/stderr inconsistent in the first place.
- **A serialised spawn service** (single dispatcher thread/queue owning all
  spawns). Never proposed, rejected pre-emptively: it is the strawman the
  centralisation worry correctly fears. Decision 4 forbids it.
- **Fork-broker helper process** (zygote pattern). Deferred, not rejected —
  the contingency if spawn rates grow orders of magnitude. Unjustified at a
  30 s trigger floor.
- **Status quo** (per-plugin `popen` + allowlists). Rejected on the Context
  evidence: 4 shipped CRITICAL injections, no timeouts, uncovered fork race,
  root/LocalSystem privilege.

## What we must refactor

### Step 0 — the sink manifest (first migration artifact)

Before wave work starts, generate a complete manifest of every spawn call
site — one row each: plugin/file/line, mechanism, platform, **ladder review**
(*does this subprocess need to exist, or does a rung-1 interface answer the
same question?* — with the per-rung evidence chain when it stays a subprocess), data
provenance (operator/server param, derived, filesystem, constant), mutating vs
read-only, shell features used, environment/cwd/stdin needs, output semantics,
privilege path (sudoers grant, if any), target wave, and the covering test.
The wave lists below are the starting inventory, not the authority — the
manifest is, and it is how "no site missed" is proven at the end.

Known rung-promotion candidates to seed the ladder-review column (each still
subject to the descent-evidence tests — contract stability and kill-ability in
particular): `sysctl -n …` spawns → `sysctlbyname()`; DEX Linux
`journalctl` `popen` → `sd_journal`; macOS `certificates` `security`-CLI
reads → Security.framework where equivalent; `ioreg` subsets → IOKit
registry reads — all rung-1 promotions.

### Runner API work to close first (prerequisites, in agent-core; feed back to #2321 follow-ups)

- **Windows implementation** — currently a stub. The contract must specify:
  explicit absolute `lpApplicationName`; a documented UTF-8→UTF-16,
  CRT-compatible argv→command-line serialization; `STARTUPINFOEXW` with an
  explicit inherited-handle list; the child created suspended and assigned to
  a kill-on-close Job Object *before* resume (avoiding the child-before-job
  race); RAII on all handles; quoting edge-case tests (empty args, spaces,
  embedded quotes, trailing backslashes, Unicode, embedded-NUL rejection);
  integration tests for non-CRT parsers (`cmd.exe`, PowerShell). The Windows
  runner additionally **rejects `.bat`/`.cmd`/`.com` as `argv[0]`** — batch
  files are always parsed by `cmd.exe` regardless of spawn API, and safe
  argument passing to them is unachievable by quoting (CVE-2024-24576);
  batch needs go through the Decision-5/7 governed shape instead. Nothing in
  `agents/` spawns batch today, so the ban costs nothing now — one check,
  one test.
- **Honest termination reporting — an automation-correctness prerequisite,
  not hygiene.** An explicit termination reason (`exited` / `signaled` /
  `deadline` / `cancelled` / `line_limit` / `spawn_error`), and removal of
  the `stop_after_max_lines` success-sentinel (`exit_code = 0` after a
  deliberate SIGKILL), matching the header's "never fabricate" contract. The
  demanding consumers are not operators but **Reflex and MCP-driven agentic
  workers**, which read subprocess results and act on them: the reason enum
  is what lets an autonomous consumer distinguish "ran and failed" (retry)
  from "killed at deadline" (escalate) from "spawn error" (never retry), and
  a fabricated exit 0 from a killed process reads as a *succeeded
  remediation* mid-chain. **Mutating-site migration waves gate on this fix.**
- **Termination semantics for mutating tools** — an optional soft-terminate
  grace (`SIGTERM` → bounded wait → process-group `SIGKILL`;
  `CTRL_BREAK`/job-close on Windows) so a deadline firing mid-`dpkg`/`rpm`
  transaction doesn't SIGKILL a tool holding real state. The manifest's
  mutating/read-only column drives the per-site policy: mutating sites get
  the grace plus generous deadlines and idempotent command design.
- **Contract enforcement at the boundary** — reject relative `argv[0]` and
  embedded NULs at runtime (today absolute-path is caller-discipline only);
  make the output byte cap caller-configurable (the 1 MB sanity cap is fixed;
  `script_exec` needs 16 MiB).
- **Environment / locale / stdio policy** — explicit child environment
  control (sanitized env, `LC_ALL=C` option so wave-3 C++ parsers never meet
  localized tool output), stdin → `/dev/null` by default, intentional signal
  defaults.
- **stderr policy** — `merge_stderr` exists (capture or `/dev/null`); confirm
  it covers all `2>&1`/`2>/dev/null` call-site patterns during wave 2.
- **Tool path probing** — a "first existing absolute path wins" helper (e.g.
  `ip` differs across distros). Honestly noted: stat-then-exec is still a
  filesystem TOCTOU if an attacker can replace the probed binary — root-owned
  tool directories are the mitigation, not the probe.
- **Streaming output** — wave 4 (`script_exec`) needs incremental line
  delivery to the command context, not just collect-at-end.

### Wave 1 — sites executing untrusted or attacker-influenceable values (highest priority)

Values interpolated into shell strings today, behind per-site
allowlists/quoting (provenance per site recorded honestly in the manifest —
not all are operator-supplied, all are influenceable):

- `network_actions` — ping host/count (operator/server params)
- `wol` — ping host (operator/server param)
- `discovery` — target IPs derived from validated CIDR
- `users` — usernames read from `/etc/passwd` into `lastlog -u …`
- `license_scan` — filesystem filenames via hand-rolled `shell_single_quote()`
- `certificates` — filesystem paths and thumbprints interpolated into
  OpenSSL/security commands on `dev` (not literal-only; also a rung-1
  promotion candidate)
- `quarantine` — destructive file operations (mutating; high blast radius)
- `services` — service mutation commands (mutating)
- `interaction` — a **redesign, not a spawn swap**: it nests shells inside
  shells (`sh -c` wrapping zenity command substitution; `_popen` of
  PowerShell with interpolated operator text through a character-replacement
  `sanitize()`). Converting to frozen-script-plus-data-as-argv is
  dialog-layer work — sized accordingly (interpreter payload; Decision-5
  register)

The allowlists stay (defense-in-depth per Decision 6) but stop being the only
line of defense.

### Wave 2 — literal single-command sites (mechanical swaps or rung promotions)

Straight `run_command("tool args")` with no shell features: per the manifest's
ladder review, either **promote** (delete the spawn for a rung-1 call) or
**swap** to a runner call with a probed absolute path. Representative set:
`hardware`, `os_info`, `device_identity`, `antivirus`, `bitlocker`, `sccm`,
`network_diag`, `processes` (`ps -axo …`), `firewall`. Sites whose only shell
feature is `2>/dev/null`/`2>&1`/`2>nul` also land here via `merge_stderr`.
Branch note: the `certificates`/`event_logs` migrations on
`feat/macos-subproc-runner-certs` cover their **macOS paths only** — their
generic-path `popen` helpers are wave 2/3 work like everyone else's.

### Wave 3 — shell-feature restructures (pipelines, globs, fallbacks)

Each replaces in-shell text processing with the base tool + C++ filtering —
the same code the `*_parsers.hpp` test discipline wants anyway. Run with
`LC_ALL=C` so parsers never meet localized output:

- **Pipelines** (`… | grep | awk | head | wc`): `wifi`
  (`iw`/`iwlist`/`iwconfig`), `hardware` (`system_profiler`/`ioreg` on
  macOS), `network_config` (`route`/`scutil`), `software_actions`
  (`yum`/`dpkg` counting), `windows_updates` (`rpm`/`apt` listings), `users`
  (`last | head`), `installed_apps` + `vuln_scan`
  (`system_profiler SPApplicationsDataType`), `event_logs`
  (`log show … | head`), `services` (`launchctl list`). Truncation moves to
  the runner's `max_lines` (+ `stop_after_max_lines` where "first N lines" is
  the whole ask).
- **Glob:** `windows_updates` `ls -t /boot/vmlinuz-* | head -1` →
  `std::filesystem` iteration + mtime sort.
- **Fallback chain:** `network_actions` `systemd-resolve … || true` → run
  first argv, check exit code, run alternate.
- **`system()` capability probes** (`command -v tool`): `vuln_scan`,
  `discovery`, `installed_apps`, `license_scan` → stat against the probe
  list.

### Wave 4 — converge the argv islands, agent-core sites, and the tar exception

- `script_exec` and `content_dist` keep their specialised behaviours (env
  whitelist, staged-binary execution, streaming, 16 MiB cap) and converge onto
  the shared runner **only after** the prerequisite runner features above
  exist — premature convergence would regress behaviour.
- Agent-core shell-outs migrate under the same rules: `dex_macos_collector.cpp`,
  `dex_linux_collector.cpp` (a `sd_journal` rung-1 candidate), and the
  `trigger_engine.cpp` `popen` sites (the Linux branch of which is also
  outside the fork lock today).
- `tar` mapdrive/service collectors: re-homed as Decision-7 registered
  exceptions executing via the runner's shell shape — commands stay literal
  shell strings, the raw `popen` spawns go away, and the sites gain the
  lock/deadline/caps.

### Explicit non-goals

- Existing rung-1 paths (Windows WMI/Win32, TAR ES/ETW capture sources,
  `/proc`//`sys` reads) are untouched — they are already the target state.
- The Erlang gateway spawns no plugin subprocesses and is out of scope; the
  only interaction is budget arithmetic (an agent-side subprocess deadline
  must fit inside the command/gateway response budget, and a Reflex-step
  budget must likewise enclose the subprocess deadlines of the actions it
  dispatches — recorded in the manifest per site).
- Content authorization for customer-authored scripts (signing, approval,
  revocation) is a separate control, tracked in #2329 (the signed-script
  execution tier: immutable, signature-verified scripts invoked by
  reference, with authoring and invocation as separate RBAC gates) — the
  argv runner is the bounded mechanism such scripts ride on, not the
  authorization for their content.

## Consequences

- **Positive:** the ladder gives every future plugin and capture source a
  recorded, reviewable acquisition pattern aligned with the lightweight-
  footprint principle; rung promotions delete subprocesses outright
  (microseconds and structs where there were processes and text);
  shell-metacharacter injection is eliminated structurally at rungs ≤2 in
  bundled plugins (out-of-tree plugins: see Decision 4's stated gap); every
  surviving spawn — shell exceptions included — gains a deadline, caps, group
  kill, honest termination reporting, and fork-lock coverage; 27 divergent
  helpers collapse into one tested seam; the standard, the CI gates, and the
  code finally agree; a future spawn-mechanism swap becomes a one-file
  change. **Reflex and other autonomous consumers may be the biggest single
  beneficiaries**: today a hung tool wedges a plugin thread with no terminal
  state, so an autonomous remediation step can hang indefinitely — the
  runner's mandatory deadline converts every step into a bounded outcome,
  the precondition for autonomous retry/escalation existing at all.
- **Negative / accepted:** migration effort across 27 plugins (staged waves,
  each independently shippable); rung-1 promotions cost per-OS API code and
  carry their own ABI/blocking risks — hence the recognised evidence
  categories rather than silent judgment; the sequential-descent rule
  front-loads investigation effort (each site must research the higher rung
  before building lower — a deliberate cost; cost-based descents survive
  only with a written comparison); pipeline sites gain C++ parsing code
  (offset: it lands in `*_parsers.hpp`, unit-testable on every host, which
  shell strings never were); absolute-path probing must track distro drift;
  `| head` truncation now happens in the runner after the child produces
  output (bounded by caps); spawn bursts still consume one plugin-host thread
  per in-flight call — unchanged from today, revisit with an async variant
  only if measured; the runner seam couples bundled plugins to agent-core's
  C++ API (accepted per Decision 4's internal-seam boundary — never for third
  parties).
- **Risk:** behaviour drift during restructures — a C++ filter subtly unlike
  the `grep`/`awk` it replaces, a native API subtly unlike the CLI's output,
  an argv rewrite subtly unlike the sudoers grant it must match. Controlled by
  fixture-driven parser tests per site (capture real command output as the
  fixture before migrating; assert identical extraction after), per-site
  sudoers verification (Decision 8), and treating rung promotions as
  behaviour-compared changes, not drop-in swaps.

## Verification

- Per-wave: fixture tests in `tests/unit/` for each new/extended
  `*_parsers.hpp` (canned real-output fixtures captured pre-migration,
  `LC_ALL=C`); plugin suite green (`meson test -C build-<os> --suite agent`);
  on macOS additionally the migrated plugins' actions exercised against the
  live host tools. Rung promotions additionally diff their output against the
  replaced command's parsed output on a live host before the spawn is deleted.
- Privilege: for every migrated privileged site, a test that the emitted argv
  matches the sudoers grant form (`sudo -n -- /abs/tool …`) from
  `scripts/install-agent-user.sh`, run against a **live sudoers install**
  and preserving the run-as-root skip-`sudo` conditional — quarantine,
  services, network actions, certificates, patching.
- Fleet-wide: the extended CodeQL queries (with query unit tests) prove zero
  un-excepted raw spawn sites in `agents/plugins/*` and the covered agent-core
  paths on the scheduled runs; the Decision-10 **per-PR lexical gate is
  demonstrated to actually fail a PR** that adds a raw spawn token outside
  the registered allowlist; `grep -rn "popen\|system(" agents/plugins/`
  matches only Decision-7 registered call sites. Manifest completeness: every
  row carries a rung and, where below rung 1, the evidence for every rung
  passed over.
- Runner: `test_subprocess_runner.cpp` extended for the termination-reason
  enum, argv[0]/NUL enforcement, byte-cap configurability, env/locale policy,
  the probe helper, and the Windows quoting edge cases, before the wave that
  depends on each starts.
- Concurrency: a deterministic fork-lock coverage test — a test hook/barrier
  around pipe creation plus direct inspection of child fd state — pinning the
  "library seam, not chokepoint" contract (Decision 4); plus a
  representative-load latency measurement of the fork-lock critical section to
  replace the arithmetic estimate in the Concurrency section.
