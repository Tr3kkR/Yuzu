- **Windows agent service install was fundamentally broken (#1822).** `yuzu-agent.exe --install-service`
  registered the process with the SCM, but the binary never implemented the SCM control protocol —
  no `ServiceMain`/`RegisterServiceCtrlHandler`/`SetServiceStatus` anywhere — so the SCM killed the
  process for not responding within its start timeout and `sc start YuzuAgent` always failed with
  error 1053, regardless of config, network, or token. This affected every real install via the
  shipped installer, not just ad-hoc `sc.exe` use. The agent now implements the real dispatcher
  (`service_win.{hpp,cpp}`): `--install-service` appends an internal `--service` marker to the
  registered binPath, and under that flag the process runs `ServiceMain`/a control handler instead
  of the console path — reporting `SERVICE_RUNNING` immediately after local startup (parity with the
  systemd unit, which has no readiness protocol either; the agent's server-reconnect loop is
  unbounded while the network is down, so waiting for it would itself time out the SCM start), and
  stopping cleanly on `SERVICE_CONTROL_STOP`/`SHUTDOWN` via the existing thread-safe `Agent::stop()`.
  Also fixes an unquoted service binPath (a hazard under a spaced install path like
  "Program Files") and adds `SERVICE_CONFIG_FAILURE_ACTIONS_FLAG` so the existing restart-on-failure
  actions also fire on a clean exit with an error (e.g. the #1303 fail-closed TLS refusal), not just
  a crash. Re-running `--install-service` over an existing (possibly stale/broken) registration now
  updates it in place instead of failing with "service already exists" — note this resets binPath to
  the bare exe + `--service` marker, so a manual re-run must be followed by `sc config` to restore any
  previously-applied `--server`/`--data-dir`/`--log-file` args, same as the installer's own sequence.
  The installer's `PrepareToInstall` stop-before-upgrade step now polls for `STOPPED` (skipped entirely
  on a fresh install with no prior service, to avoid a needless wait) instead of a blind 2-second
  delay, since `sc stop` only actually completes with this fix. The service still registers to run
  as LocalSystem (unchanged from before this fix) — migrating it to the least-privilege
  `NT SERVICE\YuzuAgent` virtual account is the existing, already-tracked #1442, not part of
  this fix; see `docs/agent-privilege-model.md`.
