- **Windows CI provisioning: a private `postgres.exe` per PostgreSQL cluster (#2354).**
  `deploy/windows/Provision-Windows-Runner.ps1` now gives each per-agent cluster its
  own copy of the PostgreSQL install tree under `D:\ci\pgbin\agent-<n>` and repoints
  the service `ImagePath` at that copy. Postgres on Windows is `EXEC_BACKEND` (a fresh
  `postgres.exe` per connection); with all four runner agents sharing one binary, every
  backend spawn contended that image file's FCB lock (~1000–1466 ms/spawn under
  concurrency), the residual driver of the `[pg]`-shard timeouts. Per-agent copies each
  get their own FCB (~10–20 ms/spawn). The step is idempotent and per-agent
  catch-and-continue; no-op and forward paths must pass `pg_isready` plus
  `SELECT 1`, and rollback restores and verifies the original service. A new
  maintenance gate at the top of the script refuses to provision at all while a
  `Runner.Listener.exe` or `Runner.Worker.exe` is live (`-AllowActiveRunners`
  overrides), so no step — including the pre-existing unconditional PostgreSQL
  service restart — can interrupt another agent's job on the shared box. The
  runner manifest/self-test now pins every private binary path, service
  `ImagePath`, running state, and authenticated health probe.
