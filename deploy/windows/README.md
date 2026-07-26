# Windows CI runner — provisioning spec

This directory is the **versioned source of truth for a native Windows CI build
host**, the Windows analog of `deploy/docker/Dockerfile.ci-linux`. Linux runners
get their toolchain from a Dockerfile; Windows needs native MSVC (no practical
container), so the equivalent is a declarative, idempotent PowerShell spec plus a
machine-readable manifest a self-test verifies.

The goal: a new Windows runner is reproducible from this directory, not a
multi-hour archaeology dig, and no script hardcodes one host's layout.

| File | Role |
|---|---|
| `Provision-Windows-Runner.ps1` | Installs the pinned toolchain, sets machine env (incl. the gateway + shared-cache contracts), emits `toolchain-manifest.json`. |
| `Assert-Toolchain.ps1` | Runner self-test: verifies the manifest, contract env, and every per-agent PostgreSQL binary/service/health check. Run at provision time **and** as a registration/preflight gate. |
| `Start-PinnedRunner.ps1` | Supervises one runner, hard-pinned to one Threadripper CCD (L3 domain); shares the vcpkg binary cache and selects that runner's persistent telemetry DB. |

## Standing up a new box

1. **Provision** (elevated pwsh 7, over RDP/console — winget's source catalog
   doesn't work headless):
   ```powershell
   pwsh -File deploy\windows\Provision-Windows-Runner.ps1
   ```
   Re-runnable; pins live in the `param()` block (bump deliberately). Open a new
   shell afterwards so machine PATH/env take effect.

   **On an existing shared box, stop all four runners first.** Provisioning
   restarts shared PostgreSQL services and rewrites machine PATH/env under
   whatever is running. A maintenance gate at the top of the script enforces
   this: it exits (code 2) before *any* step if a `Runner.Listener.exe` or
   `Runner.Worker.exe` is live. It gates on the **listener**, not just the
   worker — an idle listener can accept a job mid-run, so "no job right now" is
   not a safe state. The long-running per-agent PostgreSQL-binary step
   re-asserts the gate on entry and again immediately before each service
   restart. `-AllowActiveRunners` overrides the gate and will kill in-flight
   jobs; it exists for a box you know is yours.

2. **Self-test** (must pass before registering):
   ```powershell
   pwsh -File deploy\windows\Assert-Toolchain.ps1
   ```

3. **Register the runners.** One runner per CCD. Configure each with its own root
   and a work dir on the fast data drive, labelled into the Windows pool
   (`.github/runner-inventory.json` declares the expected set):
   ```powershell
   # repeat for r0..r3 with a fresh --token each (gh api ... /registration-token)
   C:\actions-runner\r0\config.cmd --unattended --replace `
     --url https://github.com/Tr3kkR/Yuzu `
     --name yuzu-weetam-windows-0 `
     --labels self-hosted,Windows,X64,yuzu-weetam-windows `
     --work D:\ci\work-0 --token <TOKEN>
   ```

4. **Pin + supervise.** Run each runner under a **boot-triggered scheduled task**
   (NOT `svc.cmd install` — the service control manager starts it with full
   affinity, breaking the CCD pin), invoking the wrapper:
   ```
   pwsh.exe -NoProfile -File C:\actions-runner\Start-PinnedRunner.ps1 -Index 0
   ```
   Boot trigger ⇒ the runners auto-rejoin after a reboot / physical move.

## Contracts (why the env vars exist)

- **Gateway build (de-Shulgi-ified).** `scripts/build_gateway.py` resolves the
  Erlang toolchain from `YUZU_ESCRIPT` / `YUZU_REBAR3` (set by provisioning),
  then PATH/glob — it no longer assumes Shulgi's `C:\Erlang` junction or the
  Chocolatey rebar3 path. A box that sets those env vars builds the gateway with
  no filesystem fakery.
- **Per-agent PostgreSQL (#2094).** Provisioning creates **one cluster per
  runner agent**: agent 0's winget-installed service on `:5433`, plus an
  initdb'd cluster + service `postgresql-x64-18-yuzu-ci-<n>` on `:5433+<n>`
  (data under `D:\ci\pg\agent-<n>`, run as NETWORK SERVICE like agent 0) for
  each further agent. The machine-level `YUZU_TEST_POSTGRES_DSN` stays the
  **agent-0** DSN; `scripts/ci/ensure-postgres.sh` derives "base port + agent
  index" from the runner's `-<n>` name suffix at job time and probes before
  switching, falling back to the shared agent-0 cluster with a `::warning` if
  a per-agent cluster is missing. Rationale: 4 concurrent jobs sharing one
  cluster mutually DoS their `[pg]` server suites through the shared
  WAL/buffer pool (the 2026-07-12 server-suite timeouts). No runner `.env` or
  wrapper change is involved — re-running the provisioning script is the whole
  cutover.
- **Per-agent PostgreSQL binaries (#2354).** Each cluster also gets a **private
  copy of the whole PostgreSQL install tree** under `D:\ci\pgbin\agent-<n>`, and
  its Windows-service `ImagePath` is repointed at that copy's `pg_ctl.exe` (the
  `-D` datadir and every other argument left intact). Rationale: Postgres on
  Windows is `EXEC_BACKEND` — every connection `CreateProcess()`es a fresh
  `postgres.exe` — and when all four CCD-pinned agents shared one
  `C:\pgsql\bin\postgres.exe`, every backend spawn box-wide contended that single
  image file's FCB / image-section lock (~1000–1466 ms/spawn under concurrency;
  root-caused 2026-07-22, **not** Defender and **not** disk). A byte-identical
  copy at its own path has its own FCB and spawns in ~10–20 ms — validated ~50–70×
  under all-four-agent churn. The step is idempotent (`robocopy` refreshes the
  tree in place; an already-repointed `ImagePath` is accepted only after
  `pg_isready` plus authenticated `SELECT 1`) and per-agent catch-and-continue.
  A failed repoint restores the exact original `ImagePath`, restarts from the
  original bin directory, and verifies the same two health checks; a failed
  rollback is reported distinctly instead of claiming recovery. Both registry
  writes preserve the value's original kind, so a rollback restores the exact
  original bytes. Agent 0's live data exclusion comes from the service's actual
  `-D` argument (canonicalised before it is handed to `robocopy /XD`, which
  matches by path string), not an assumed install-root layout. `D:\ci\pgbin` and
  each copy's `postgres.exe` join the Defender exclusions below — and, unlike
  before, those two are verified fail-closed rather than added best-effort. The
  manifest self-test verifies all four private binary sets, registered service
  executables, `Running` states, and live authenticated probes, so drift fails
  before a build starts.
- **Shared vcpkg binary cache.** `RUNNER_TOOL_CACHE=D:\ci\tool_cache` points
  `${{ runner.tool_cache }}` (hence `VCPKG_DEFAULT_BINARY_CACHE` in `ci.yml`) at
  **one** machine-level dir, so the 4 CCD-pinned runners share one warm vcpkg
  binary cache instead of fragmenting it 4× (~1.9 GB each). Mirrors
  `CCACHE_DIR=D:\ci\ccache`. Set in each runner's `.env` (durable) and exported
  by the wrapper. The vcpkg binary cache is content-addressed → concurrent writes
  across runners are safe.
- **Persistent CI telemetry.** Each runner owns
  `D:\ci\test-runs\yuzu-weetam-windows-N\test-runs.db`. Provisioning initializes
  all four databases; the pin wrapper exports the matching path as
  `YUZU_TEST_DB`, and `ci.yml` records every Windows MSVC job, Meson suite
  duration/timeout and recovered known flake. The files sit outside the checkout
  and are never shared between agents, so history survives branch/build cleanup
  without adding SQLite writer contention between CCDs.
- **Defender CI exclusions.** Provisioning preserves Wee Tam's four exact runner
  work-root exclusions (`D:\ci\work-0` … `work-3`), which cover each runner's
  `_temp` directory and checkout/build outputs. PostgreSQL's executable and
  disposable data paths are also excluded, as are the Catch2 test binaries
  (`yuzu_{server,agent,tar}_tests.exe`) via process exclusions — a process
  exclusion skips scanning that binary's file I/O wherever it lands, which covers
  the SQLite temp churn even in the LOCAL SYSTEM `%TEMP%` the routing can't reach.
  Provisioning verifies every `_temp`
  path with Defender's own `MpCmdRun.exe -CheckExclusion`. It deliberately does
  not exempt the whole of user/system `%TEMP%` or `D:\ci` — only the scoped
  `C:\Windows\Temp\yuzu*` wildcard, for tests that run in a LOCAL SYSTEM context
  (`yuzu_test_kv_SYSTEM`, guardian, …) whose `TEMP` the per-runner `_temp`
  routing below cannot reach. The pin wrapper routes native `TEMP`/`TMP` and
  MSYS2 `TMPDIR` into that runner's own `_temp`; the CI telemetry start step
  repeats those exports so the fix applies before the next planned runner
  restart too. A daily `Yuzu-CI-Temp-Sweep` scheduled task purges
  `C:\Windows\Temp\yuzu*` entries older than 1 day so the SYSTEM-context leak
  cannot re-bloat the NTFS directory index.

## `toolchain-manifest.json`

Emitted by provisioning (default `C:\actions-runner\toolchain-manifest.json`),
verified by `Assert-Toolchain.ps1`:

```json
{
  "generated": "2026-06-20T13:00:00Z",
  "host": "WEETAM",
  "runner_count": 4,
  "pins":  { "python": "3.14.6", "meson": "1.11.1", "erlang": "28.4.2",
             "rebar3": "3.24.0", "postgres": "18.4", "vcpkg_baseline": "4b77da7..." },
  "env":   { "VCPKG_ROOT": "C:\\vcpkg", "CCACHE_DIR": "D:\\ci\\ccache",
             "RUNNER_TOOL_CACHE": "D:\\ci\\tool_cache",
             "YUZU_ESCRIPT": "...erts-*\\bin\\escript.exe",
             "YUZU_REBAR3": "C:\\tools\\rebar3\\rebar3",
             "YUZU_TEST_POSTGRES_DSN": "postgresql://yuzu:yuzu@127.0.0.1:5433/yuzu_test" },
  "telemetry": {
    "root": "D:\\ci\\test-runs",
    "databases": ["D:\\ci\\test-runs\\yuzu-weetam-windows-0\\test-runs.db", "..."]
  },
  "postgres_clusters": [
    { "agent": 0, "service": "postgresql-x64-18-yuzu-ci", "port": 5433,
      "bin": "D:\\ci\\pgbin\\agent-0\\bin",
      "pg_ctl": "D:\\ci\\pgbin\\agent-0\\bin\\pg_ctl.exe",
      "postgres": "D:\\ci\\pgbin\\agent-0\\bin\\postgres.exe",
      "psql": "D:\\ci\\pgbin\\agent-0\\bin\\psql.exe",
      "pg_isready": "D:\\ci\\pgbin\\agent-0\\bin\\pg_isready.exe" },
    "..."
  ],
  "tools": [ { "name": "vcpkg", "path": "C:\\vcpkg\\vcpkg.exe", "version": "...", "required": true }, ... ]
}
```

The manifest is host-generated (like a lockfile) and not committed; this README
documents its shape so the self-test and any tooling agree on the contract.
