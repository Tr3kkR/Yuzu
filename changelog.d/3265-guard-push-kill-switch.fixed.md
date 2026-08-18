- **Guardian rule delivery (`__guard__.push_rules`) is no longer permanently
  kill-switched.** The per-action kill-switch grammar added 2026-08-14
  required a plugin name to start with a lowercase letter, which
  `__guard__` — the server's own reserved-namespace dispatch capability
  used for every Guardian rule push (a normal push, a Baseline deploy, and
  the periodic reconcile re-push) — never satisfied. `action_allowed`'s
  fail-closed contract then collapsed every dispatch to disabled
  regardless of whether an operator had ever touched the switch, on any
  Postgres-backed server (i.e. every server). The caller saw a normal
  `202`/"pushed" response with nothing surfacing the drop on either side.
  The kill-switch scope grammar now also accepts a reserved-namespace
  plugin name (`__<identifier>__`), so `__guard__.push_rules` resolves to
  its documented no-row-set default (allowed) and remains fully
  kill-switchable via `PUT /api/v1/plugin-config/__guard__/kill-switch` (or
  the MCP twin) exactly like any other capability.
