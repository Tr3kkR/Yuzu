# Follow-up issue: autoruns leg-seam tests (deferred)

**Labels:** `plugin`, `reliability`, `P2`

## Title

Autoruns: add injectable seams for the hive-unload-warning and Linux systemctl-fallback contracts

## Body

The autoruns plugin has two documented behavioral contracts that are only exercised indirectly today. Both are described in `docs/agent-spawn-sink-manifest.md` and the plugin's own routed-concerns entry, but neither has a test that drives the real code path end to end.

### 1. Hive-unload-failure warning (Windows)

Every per-user pass over an offline registry hive (`win_run_hku`, `win_runonce_hku`, `win_startup_approved`) is supposed to surface a `warning|hive_unload_failed|...` line whenever the trailing `RegUnLoadKeyW` call fails on the way out, even if the read itself succeeded cleanly. This is deliberate: a hive left mounted on a target endpoint is real state an operator needs to know about, and it must never be swallowed just because the data collection succeeded.

Right now this is only covered by unit tests against the rendering helper in isolation — nothing forces an actual `RegUnLoadKeyW` failure through one of the three call sites above and checks that the warning line survives to the plugin's output.

**Ask:** add an injectable hive-access seam at the call site (so a test can force the unload step to fail without needing a real broken hive on a real machine), and a test that asserts the `warning|hive_unload_failed` line is present in the output when it does.

### 2. Linux systemd-timer fallback (`collect_linux`)

On Linux, autoruns normally reads the three system systemd unit directories directly. It only falls back to spawning `systemctl list-timers --all --no-pager --no-legend` when systemd is present (`/run/systemd/system` exists) AND all three unit directories fail to open. This is the plugin's only subprocess spawn on any platform, so its trigger condition and exact argv are both worth pinning precisely.

Nothing today drives an injected process runner through this path. A test should:
- Pin the exact argv passed to the runner.
- Force the "systemd present, all three unit directories unreadable" trigger condition and confirm the fallback fires only then.
- Confirm zero spawns happen on the Windows and macOS legs — this is meant to be the one and only spawn site across all three platforms, and a refactor could silently add another one without any test noticing.

### Why deferred

Both gaps were identified and accepted as known, documented limitations at review time rather than blockers — see the "Known gap" notes in `docs/wave7/integration-autoruns-docs.md`'s routed-concerns and sink-manifest sections. They're real coverage holes, just not ones that should hold up the rest of the autoruns work.
