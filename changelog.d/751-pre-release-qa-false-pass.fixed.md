- **Pre-release QA no longer reports PASSED when it has verified nothing.** The
  `QA Report` job runs with `if: always()` and derived its verdict from the nine test
  jobs alone, never from `resolve`. When `resolve` skips — which it does whenever the
  triggering Release did not succeed on a `v*` tag, i.e. 94 of the last 100 Release
  runs — all nine are `skipped`, nothing matches "failure", and the job printed
  `### Result: PASSED` and exited 0. A green Pre-release QA therefore did not mean the
  release had been tested; it usually meant nothing had run. The report now treats a
  skipped `resolve` as an explicit **NOT RUN** ("this is NOT a pass — nothing was
  verified"), fails when `resolve` itself fails, and counts a `cancelled` job as a
  failure rather than a pass.
- **Pre-release QA's Docker stacks can now actually start.** Its QA, soak and upgrade
  composes healthchecked the server with `curl`, which is not installed in the server
  image (it carries only libssl3, libpq5, ca-certificates and bash), so the container
  could never report healthy and `gateway` — which waits on
  `condition: service_healthy` — could never start. They now use bash's `/dev/tcp`
  pseudo-device, the probe the reference composes use and the one the new #751 gate
  enforces.
- **Pre-release QA can now pull the images it tests.** `REGISTRY` was built from the
  mixed-case `github.repository_owner`, yielding `ghcr.io/Tr3kkR/...` — a reference
  Docker rejects outright, since repository names must be lowercase. This was not
  theoretical: the v0.11.0 QA run died with `invalid reference format: repository name
  (Tr3kkR/yuzu-server) must be lowercase`. The owner is now folded to lowercase once in
  `resolve` and consumed by every job, including Trivy's `image-ref`, which cannot read
  an `env:` override.
