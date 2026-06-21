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
| `Assert-Toolchain.ps1` | Runner self-test: verifies the manifest (every required tool present, every contract env set). Run at provision time **and** as a registration/preflight gate. |
| `Start-PinnedRunner.ps1` | Supervises one runner, hard-pinned to one Threadripper CCD (L3 domain); shares the vcpkg binary cache via `RUNNER_TOOL_CACHE`. |

## Standing up a new box

1. **Provision** (elevated pwsh 7, over RDP/console — winget's source catalog
   doesn't work headless):
   ```powershell
   pwsh -File deploy\windows\Provision-Windows-Runner.ps1
   ```
   Re-runnable; pins live in the `param()` block (bump deliberately). Open a new
   shell afterwards so machine PATH/env take effect.

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
- **Shared vcpkg binary cache.** `RUNNER_TOOL_CACHE=D:\ci\tool_cache` points
  `${{ runner.tool_cache }}` (hence `VCPKG_DEFAULT_BINARY_CACHE` in `ci.yml`) at
  **one** machine-level dir, so the 4 CCD-pinned runners share one warm vcpkg
  binary cache instead of fragmenting it 4× (~1.9 GB each). Mirrors
  `CCACHE_DIR=D:\ci\ccache`. Set in each runner's `.env` (durable) and exported
  by the wrapper. The vcpkg binary cache is content-addressed → concurrent writes
  across runners are safe.

## `toolchain-manifest.json`

Emitted by provisioning (default `C:\actions-runner\toolchain-manifest.json`),
verified by `Assert-Toolchain.ps1`:

```json
{
  "generated": "2026-06-20T13:00:00Z",
  "host": "WEETAM",
  "pins":  { "python": "3.14.6", "meson": "1.11.1", "erlang": "28.4.2",
             "rebar3": "3.24.0", "postgres": "18.4", "vcpkg_baseline": "4b77da7..." },
  "env":   { "VCPKG_ROOT": "C:\\vcpkg", "CCACHE_DIR": "D:\\ci\\ccache",
             "RUNNER_TOOL_CACHE": "D:\\ci\\tool_cache",
             "YUZU_ESCRIPT": "...erts-*\\bin\\escript.exe",
             "YUZU_REBAR3": "C:\\tools\\rebar3\\rebar3",
             "YUZU_TEST_POSTGRES_DSN": "postgresql://yuzu:yuzu@127.0.0.1:5433/yuzu_test" },
  "tools": [ { "name": "vcpkg", "path": "C:\\vcpkg\\vcpkg.exe", "version": "...", "required": true }, ... ]
}
```

The manifest is host-generated (like a lockfile) and not committed; this README
documents its shape so the self-test and any tooling agree on the contract.
