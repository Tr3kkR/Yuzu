- **Customer-assurance documentation set for security due diligence (#4315, #2857).** New
  `docs/assurance/security-whitepaper.md` and `docs/assurance/shared-responsibility-matrix.md`
  describe the `v0.13.0` release (every body claim verifiable at that tag; `dev`-only controls
  are confined to a "Not in v0.13.0" appendix). New `docs/ops-runbooks/slo.md` defines five
  Service Level Objectives (`/readyz` availability, command dispatch p99, agent heartbeat
  freshness, audit write success, PostgreSQL substrate degrade events), each tied to a real
  metric and an existing Prometheus alert or an explicitly marked proposed one, with its known
  gaps stated (no `up == 0` dead-man's-switch for the server, #4290; no shipped stack loads the
  alert rules, #2857). `docs/ops-runbooks/auth-db-recovery.md` is rewritten to describe
  `v0.13.0`'s SQLite `auth.db` authentication store, with the PostgreSQL `auth` schema recovery
  path moved to a clearly marked "Not in v0.13.0" section.
