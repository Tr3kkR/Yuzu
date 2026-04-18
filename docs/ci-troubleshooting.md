# CI / Infrastructure Troubleshooting Runbook

**A decision tree for the failure modes we have actually hit on Yuzu's
self-hosted CI infrastructure.** Every entry is here because a previous
session burned wall-clock time chasing it without a runbook. Add a new
entry whenever you spend more than ~5 minutes diagnosing something that
will recur — fresh memory is the highest-quality writing material.

If you are about to run `gh api`, `journalctl`, or `last reboot` to figure
out why a CI run is failing, **search this file first**. The pattern you
are about to debug is probably already here.

Companion docs:

- `docs/ci-cpp23-troubleshooting.md` — C++23 / cross-compiler issues
  (Clang 18 + libstdc++, Apple Clang version drift, MSVC-only failures).
  Read that one first if you suspect a compile-time problem.
- `.claude/agents/build-ci.md` — full Windows MSVC static-link history,
  including the option D LNK2038 fix and the four failed approaches that
  preceded it.
- `docs/windows-build.md` — the canonical Windows build path
  (MSYS2 bash + `setup_msvc_env.sh` + `scripts/ensure-erlang.sh`).

---

## 1. Linux runner `yuzu-wsl2-linux` shows offline / tmux is dying

**Symptom:**

- GitHub Actions runners page (`gh api repos/Tr3kkR/Yuzu/actions/runners`)
  shows `yuzu-wsl2-linux` as `{"status":"offline"}`.
- A scheduled or push CI run is stuck with one or more Linux jobs in
  `in_progress` for far longer than the job's normal duration.
- `tmux ls` from inside the WSL2 distro returns "no server running" even
  though you had a session attached recently.
- `last reboot` inside the distro shows multiple "system boot" entries
  in the last few hours despite no manual reboots.

**Root cause:**

The `yuzu-wsl2-linux` runner lives **inside the WSL2 host distro on
Shulgi**. WSL2's default `vmIdleTimeout=60000` (60 seconds) shuts the
utility VM down ~60 seconds after the last interactive shell session
ends. When the VM dies:

1. The
   `actions.runner.Tr3kkR-Yuzu.yuzu-wsl2-linux.service` systemd unit
   dies with it.
2. Any `tmux` server in the distro dies (tmux servers don't survive VM
   shutdowns — they are processes inside the VM).
3. Any in-flight CI job loses its runner mid-execution. From GitHub's
   side the job stays `in_progress` until the 6-hour job timeout, because
   the new Runner.Listener that comes up on next VM boot is a fresh
   process with no record of the orphaned job assignment, so it cannot
   acknowledge cancellation.

**Why it appears intermittent:** the VM only shuts down when the **last**
shell session (SSH + interactive WSL + service worker shells) is gone for
60 s. As long as you have one SSH session attached or one long-running
foreground command, the VM stays up. The pattern looks random because
"last session ended" depends on whether you had two SSH windows or one.

**Detection commands:**

```bash
# From the WSL2 distro:
last reboot | head -10            # multiple boots/day == VM cycling
uptime                            # tiny uptime + load average suggests fresh boot

# Look for the signature in dmesg-equivalent journal of the previous boot
sudo journalctl -b -1 | grep -E 'recv failed|InitCreateProcessUtilityVm'
# Pattern: "InitCreateProcessUtilityVm:1805: recv failed 0 17"

# Check WSL2 host config
cat /mnt/c/Users/$USER/.wslconfig | grep vmIdleTimeout
# Default (broken for runner host): vmIdleTimeout=60000 or unset
# Fixed: vmIdleTimeout=-1
```

**Fix (two coordinated changes — both are required):**

1. Edit `/mnt/c/Users/<your-user>/.wslconfig` (Windows-side WSL2 host
   config) and add inside the `[wsl2]` section:

   ```ini
   [wsl2]
   memory=48GB
   processors=16

   # Keep the WSL2 utility VM alive even when no shells are connected.
   # vmIdleTimeout=-1 disables the idle timeout entirely. Required for
   # runner hosts because the cost of the VM running idle is dwarfed by
   # the cost of cancelling an in-flight CI run.
   vmIdleTimeout=-1
   ```

2. Apply by running `wsl --shutdown` from a Windows shell (or
   `cmd.exe /c "wsl --shutdown"` from inside WSL — note that this kills
   the calling session, so reconnect afterward). The setting takes
   effect on the next VM boot.

3. Defense-in-depth: enable systemd user-session linger so user-scope
   units survive "no sessions" windows even with the VM up:

   ```bash
   sudo loginctl enable-linger dornbrn
   # Verify:
   ls /var/lib/systemd/linger/dornbrn   # should exist
   loginctl show-user dornbrn | grep Linger   # Linger=yes
   ```

   The runner unit itself is system-scope so it does not strictly need
   linger, but tmux servers and any future user-scope helper services do.

**Verification (next session):**

After applying the fix, the next SSH disconnect/reconnect cycle should
NOT produce a new entry in `last reboot`. The VM uptime should keep
growing past 60 s of idle time. Subsequent CI runs should have all Linux
jobs report a stable single runner across the run lifetime.

**If a CI run is wedged with an orphaned `in_progress` job from before
the fix landed:**

```bash
gh run view <run-id> --json jobs --jq '.jobs[] | select(.status=="in_progress")'
gh api -X POST repos/Tr3kkR/Yuzu/actions/runs/<run-id>/force-cancel
# Force-cancel takes ~30-60 s to propagate; re-poll until status==completed
```

After force-cancel, the runner state should free up:
`gh api repos/Tr3kkR/Yuzu/actions/runners` should show
`{"status":"online", "busy": false}`. Note that the orphaned job's logs
will return `BlobNotFound` because the dead runner never finalized them.

**Reference incident:** session 2026-04-15b → 2026-04-15c. Four VM
cycles on 2026-04-15 (07:52, 08:24, 10:06, 13:07 UTC) correlated with
SSH disconnect events. CI run `24450261405` lost its `Linux gcc-13
debug` job at 13:07 and stayed wedged until force-cancel at 13:37.

---

## 2. CI Linux job fails on `apt-get install` with sudo password prompt

**Symptom:**

`Install system packages` step on a self-hosted Linux runner job fails
with one of:

```
sudo: a terminal is required to read the password
sudo: a password is required
E: Could not open lock file /var/lib/dpkg/lock-frontend - open (13: Permission denied)
```

**Root cause:**

The `github-runner` user that runs the `actions.runner.*.service`
systemd unit on `yuzu-wsl2-linux` does not have NOPASSWD sudo by default.
GHA workflows that use `sudo apt-get install` assume passwordless sudo,
which works on hosted `ubuntu-24.04` runners (where the runner user is
in `/etc/sudoers.d/runner`) but not on freshly registered self-hosted
runners.

**Fix:**

Create `/etc/sudoers.d/github-runner` on the runner host, granting
NOPASSWD for the apt family only (do not grant blanket NOPASSWD ALL):

```bash
sudo tee /etc/sudoers.d/github-runner > /dev/null <<'EOF'
github-runner ALL=(ALL) NOPASSWD: /usr/bin/apt-get, /usr/bin/apt, /usr/bin/dpkg
EOF
sudo chmod 0440 /etc/sudoers.d/github-runner
sudo visudo -c   # validates all sudoers files, exits non-zero on syntax error
```

This grant is host-side and not version-controlled. If you re-image the
runner, re-apply it as part of the runner-bootstrap procedure. (Future
work: bake into a runner provisioning script — tracked in issue #387's
research deliverable.)

**Verification:**

```bash
sudo -u github-runner sudo -n apt-get -v >/dev/null && echo "OK"
```

**Reference incident:** session 2026-04-15b, commit `f4d634e` first push
to dev with the migrated Linux runners failed before this grant landed.

---

## 3. CI Linux job fails on `pip3 install` with `externally-managed-environment`

**Symptom:**

```
error: externally-managed-environment

× This environment is externally managed
╰─> To install Python packages system-wide, try apt install
    python3-xyz, where xyz is the package you are trying to install.

    If you wish to install a non-Debian-packaged Python package,
    create a virtual environment using python3 -m venv path/to/venv.
```

**Root cause:**

Ubuntu 24.04 (and the Debian-derived WSL2 distro on `yuzu-wsl2-linux`)
ships **PEP 668** which marks the system Python as externally managed
to prevent system-wide `pip install` from clobbering apt-managed Python
packages. The hosted `ubuntu-24.04` GHA runners disable this marker;
self-hosted ones do not.

**Fix:**

Use the documented `--user --break-system-packages` bypass for ephemeral
CI install-and-go environments, plus a `$GITHUB_PATH` append so the
`~/.local/bin/<binary>` shim is found by subsequent steps:

```yaml
- name: Install Meson
  run: |
    pip3 install --user --break-system-packages -r requirements-ci.txt
    echo "$HOME/.local/bin" >> $GITHUB_PATH
```

`--user` writes to `~/.local/lib/python3.X/site-packages` instead of the
system site-packages. `--break-system-packages` is the explicit opt-out
of PEP 668 for the install. The combination is safe in CI because the
runner workspace is not used for anything except the CI job.

**Why not `python3 -m venv`?** The error message suggests it, but venvs
add ~5 s of CI overhead per job and complicate the `meson` shim search
path because `$VIRTUAL_ENV/bin` would have to be added per-step. For a
single tooling pin we accept the lighter-weight `--user` approach.

**Verification:**

```bash
pip3 install --user --break-system-packages meson==1.9.2
echo $? "  $(meson --version)"
```

**Reference incident:** session 2026-04-15b, commit `d12ba74` after the
first CI run on the Linux self-hosted runners hit this on every Linux
matrix leg.

---

## 4. CI run is wedged with a stuck `in_progress` job

**Symptom:**

A CI run shows `status: in_progress` with one or more jobs stuck in
`in_progress` long after their normal duration. Plain `gh run cancel`
returns success but the run does not transition to `completed` /
`cancelled` even after several minutes.

**Root cause (most common):**

The runner that owned the stuck job died mid-execution (see Section 1
for the WSL2 case, but other causes are: runner host hard-rebooted,
network split, runner.listener crash, OOM kill of the worker). When the
runner reincarnates (systemd restart, host reboot, etc.) it is a fresh
Runner.Listener instance with no record of the prior job assignment.
Plain cancel waits for the runner to acknowledge; the new instance
never will.

**Fix:**

Use the **force-cancel** API endpoint, which is documented for exactly
this case:

```bash
gh api -X POST repos/Tr3kkR/Yuzu/actions/runs/<run-id>/force-cancel
# Returns 202 with {} on success.
# Wait ~30-60 s and re-poll status:
gh run view <run-id> --json status,conclusion
```

The endpoint propagates within ~1 minute. Once the run transitions to
`completed/cancelled`, the runner's `busy` flag clears.

**Side effect:** logs for the orphaned job will return `BlobNotFound`
(`HTTP 404`) because the dead runner never finalized the log upload.
Step state from `gh api repos/<owner>/<repo>/actions/jobs/<job-id>` is
still available and is often enough to identify which step the job was
on when it died — useful for diagnosing whether the failure was real
or just runner death.

**Verification:**

```bash
# Before force-cancel:
gh api repos/Tr3kkR/Yuzu/actions/runners --jq '.runners[] | {name, status, busy}'
# {"busy":true, "name":"yuzu-wsl2-linux", "status":"offline"}

# After force-cancel propagates:
gh api repos/Tr3kkR/Yuzu/actions/runners --jq '.runners[] | {name, status, busy}'
# {"busy":false, "name":"yuzu-wsl2-linux", "status":"online"}
```

**Reference incident:** session 2026-04-15c, run `24450261405` had
`Linux gcc-13 debug` (databaseId `71437122017`) wedged from 12:25 UTC
after the WSL2 VM cycled at 13:07. Plain cancel did not propagate;
force-cancel resolved within ~1 minute.

---

## 5. CodeQL Windows job fails with `path::c_str()` / `wchar_t*` mismatches

**Symptom:**

CodeQL Windows analysis fails with errors like:

```
error: cannot convert 'const wchar_t*' to 'const char*'
note: in template argument deduction for std::filesystem::path::c_str
```

**Root cause:**

`std::filesystem::path::c_str()` returns `const value_type*`, where
`value_type` is `wchar_t` on Windows and `char` on POSIX. Code that
splices `path.c_str()` into a `const char*`-expecting API (`fopen`,
`std::system`, gRPC channel address) compiles cleanly on Linux/macOS and
fails on Windows. CodeQL's Windows leg is the first place this surfaces
because it's the only Windows leg in the matrix that runs the full
project build.

**Fix:**

Use `path.string().c_str()` (which produces a UTF-8 `std::string` on
both POSIX and Windows) for narrow-char APIs, OR use the wide-char
variant of the API on Windows behind `#ifdef _WIN32`.

**Reference fix:** commit `cd190f2`. Search the diff for the pattern
`.string().c_str()` to see the canonical replacement.

**Why this is in the runbook:** Every Yuzu C++ author who touches
`std::filesystem::path` will eventually hit this. The diagnostic chain
is non-obvious because the Windows-only failure looks like a CodeQL
configuration problem at first glance.

---

## 6. Windows MSVC build fails with LNK2038 / LNK2005 / `_ITERATOR_DEBUG_LEVEL`

**Symptom:**

```
error LNK2038: mismatch detected for '_ITERATOR_DEBUG_LEVEL':
  value '2' doesn't match value '0' in <object>.obj
error LNK2038: mismatch detected for 'RuntimeLibrary':
  value 'MD_DynamicRelease' doesn't match value 'MDd_DynamicDebug'
error LNK2005: <symbol> already defined in absl_*.lib
```

against `absl_cord.lib`, `protobuf.lib`, `grpc.lib`, or other vcpkg
dependencies.

**Root cause:**

This is the long story. The short version: meson's cmake dependency
translator on Windows MSVC has a bug where it bakes the **release**
library paths into the **debug** link line, regardless of the active
`buildtype`. vcpkg's standard Windows triplet does not emit per-build-type
static archives, so debug builds end up linking against
release-CRT-flavored archives.

**Fix:**

The fix is "option D" — combination of:

1. `triplets/x64-windows.cmake` forcing
   `VCPKG_LIBRARY_LINKAGE static` + `VCPKG_CRT_LINKAGE dynamic` so vcpkg
   emits per-build-type static archives (`.lib` for release, `d.lib`
   for debug).
2. `meson.build` replacing the meson `dependency('grpc++', method:
   'cmake')` wiring on Windows MSVC with a hand-rolled
   `cxx.find_library()` chain that picks the correct variant per the
   active `buildtype`.
3. `vcpkg.json` openssl as an unconditional top-level dep
   (the previous `"platform": "!windows"` filter was aspirational and
   never worked).

**Both halves are load-bearing.** Removing either the triplet override
OR the hand-rolled `find_library()` wiring re-introduces the failure.

**Full history** including every failed approach
(per-build-type triplets → explicit `CMAKE_BUILD_TYPE` → drop static
override → option H hybrid) and the strategic escape path (#376 QUIC
migration if option D ever rots) lives in
`.claude/agents/build-ci.md` under **"Windows MSVC static-link history
and #375"**. **Read that file before touching the Windows build wiring.**

**Reference fix:** PR #373 merged as `bf95d3b` on 2026-04-15. Don't
simplify either half without reading the agent doc first.

---

## When to add a new entry

Add an entry here if:

- You spent more than ~5 minutes diagnosing something that will recur.
- The diagnostic chain involved more than ~2 commands you had to think
  about.
- The fix is non-obvious from the symptom alone.
- The fix is reversible / non-destructive (i.e. the runbook is safe to
  apply blind).

Each entry should follow the same shape as the entries above:

1. **Symptom** — exact strings you would search for.
2. **Root cause** — the why, in 2-4 sentences.
3. **Detection commands** — what to run to confirm the diagnosis.
4. **Fix** — exact commands or file edits.
5. **Verification** — how to know the fix landed.
6. **Reference incident** — session date + commit/run-id where this
   happened, so future-you can find the original context.

The runbook is most valuable when the fix is *exactly* runnable. Avoid
"tweak the config" — paste the config block.
