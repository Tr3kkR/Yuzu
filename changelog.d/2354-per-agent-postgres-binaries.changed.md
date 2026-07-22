- **Windows CI provisioning: a private `postgres.exe` per PostgreSQL cluster (#2354).**
  `deploy/windows/Provision-Windows-Runner.ps1` now gives each per-agent cluster its
  own copy of the PostgreSQL install tree under `D:\ci\pgbin\agent-<n>` and repoints
  the service `ImagePath` at that copy. Postgres on Windows is `EXEC_BACKEND` (a fresh
  `postgres.exe` per connection); with all four runner agents sharing one binary, every
  backend spawn contended that image file's FCB lock (~1000–1466 ms/spawn under
  concurrency), the residual driver of the `[pg]`-shard timeouts. Per-agent copies each
  get their own FCB (~10–20 ms/spawn). The step is idempotent, per-agent
  catch-and-continue, and rolls back the `ImagePath` if a fresh copy fails to serve.
