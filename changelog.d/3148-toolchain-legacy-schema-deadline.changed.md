- **Schema-less Windows runner toolchain manifests stay compatible 31 days longer.** The bounded
  window in `deploy/windows/toolchain-contract.json` moves to **2026-09-14 23:59:59 UTC**,
  superseding the earlier 2026-08-14 deadline; drain and reprovision every Windows runner from
  merged code before it. Past the old deadline `Assert-Toolchain.ps1` threw instead of taking its
  WARN-and-accept path, turning the `Windows toolchain contract` check red on unrelated pull
  requests. Unknown explicit schemas and a missing manifest still fail closed.
