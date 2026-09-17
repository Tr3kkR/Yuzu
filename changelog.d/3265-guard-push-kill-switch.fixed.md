- **CRITICAL — Guardian rule delivery (`__guard__.push_rules`) was
  permanently kill-switched.** A per-action kill-switch grammar landed on
  `dev` on 2026-08-15 (never in a tagged release — the last tag, `v0.13.0`,
  predates it, and no customer deployment was affected) requiring a plugin
  name to start with a lowercase letter, which `__guard__` — the server's
  own reserved-namespace dispatch capability used for every Guardian rule
  push (a normal push, a Baseline deploy, and the periodic reconcile
  re-push) — never satisfied. `action_allowed`'s fail-closed contract then
  collapsed every dispatch to disabled regardless of whether an operator
  had ever touched the switch, on any Postgres-backed server (i.e. every
  server). The caller saw a normal `202 {"queued":true,"agents":0}`
  response and audit row — a discoverable-if-you-knew-to-look signal, but
  one indistinguishable from "no agents matched the scope" or any other
  ordinary zero-match case, so nothing identified a kill switch as the
  cause. The kill-switch scope grammar now also accepts a reserved-namespace
  plugin name (`__<identifier>__`), so `__guard__.push_rules` resolves to
  its documented no-row-set default (allowed) and remains fully
  kill-switchable via `PUT /api/v1/plugin-config/__guard__/kill-switch` (or
  the MCP twin) exactly like any other capability. No backfill or manual
  remediation is needed on upgrade — a Baseline deploy's policy-generation
  bump is unconditional, so every affected agent's next heartbeat reconcile
  self-heals against the fixed server.
