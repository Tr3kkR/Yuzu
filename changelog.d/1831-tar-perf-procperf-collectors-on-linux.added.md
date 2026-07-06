- **TAR `perf` + `procperf` collectors on Linux (procfs).** The device
  performance sampler and the per-application top-N sampler — Windows-only
  until now — are implemented on Linux: `perf` reads `/proc/stat`,
  `/proc/meminfo` (`MemAvailable`; `commit_pct` reads 0 under
  `vm.overcommit_memory=1`), `/proc/diskstats` (whole disks only, 512-byte ABI
  sectors), and `/proc/net/dev` (loopback excluded); `procperf` does one
  `/proc/<pid>/stat` read per process per tick (kernel 15-char comm — joins
  `$Process_Live` by name; `version` is always `""` until on-disk version
  capture lands). Because `perf` is default-ON, **Linux agents begin device
  performance sampling automatically on upgrade** (device-level, no user
  identity; opt out with `perf_enabled=false`); `procperf` remains opt-in on
  every OS, and enabling it now also feeds the `app_perf` daily sync (B1/B2)
  from Linux devices — no server change, the plumbing was already
  platform-agnostic. **Enabling
  `procperf` syncs per-app names + versions off-device** to the central
  `app_perf` store (not local-triage-only); the agent emits a `notice|…` line
  on the enabling `configure`, and it is documented in the config table.
  **Linux `procperf` redaction is best-effort against the kernel's 15-byte
  comm** — a pattern only redacts reliably when its sensitive substring is a
  ≤15-byte, prefix-aligned comm slice (a token past byte 15 is truncated away);
  operator patterns are matched in the same sanitized space as the stored name
  (so `*evil|app*` redacts a process that named itself `evil|app`), and comm
  bytes are scrubbed to valid UTF-8. macOS remains planned for both sources.
