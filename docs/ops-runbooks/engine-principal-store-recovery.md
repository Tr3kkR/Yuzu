# Engine-Principal Store Recovery Runbook

Operator runbook for the `EnginePrincipalStore` — the born-on-Postgres
identity store (schema `engine_principal_store`, ADR-0006/0012) backing
autonomous **engine principals** (`docs/auth-engine-principals-design.md`
§3.1). Covers the `/readyz` probe, the client-visible 503-vs-401 split on
`get_for_auth`, and the `engine:` namespace collision-scan boot failure.

Unlike `auth.db` (per-node SQLite, `docs/ops-runbooks/auth-db-recovery.md`),
this store lives in the shared Postgres substrate — recovery is Postgres
recovery, not a local-file procedure. See `docs/postgres-store-playbook.md`
for the substrate-wide primitives (pool, migration runner, `/readyz`
conjunction) this runbook assumes.

## Detection signal

### 1. Construction failure — server refuses to start

`yuzu-server` exits with a non-zero status at startup and the log shows one
of:

```
[error] EnginePrincipalStore: no database connection at construction (...) — engine-principal identity store disabled
[error] EnginePrincipalStore: schema migration failed — engine-principal identity store disabled
[error] [PG] Refusing to start: engine-principal store migration/open failed
```

This is the same fail-CLOSED posture as every other born-on-PG store
(ADR-0012 §1): a reachable database whose schema can't migrate/open is a
**deploy error**, not a serve-degraded state. Diagnose it exactly like any
other store on the shared pool — see `docs/postgres-store-playbook.md` §
Substrate quick facts and the general Postgres-unreachable-at-boot recovery
in that doc; there is nothing engine-principal-specific about this failure
mode once you've identified which store's migration/lease failed.

### 2. `GET /readyz` reports the store unhealthy at runtime

```json
{"status": "not_ready", "checks": {"engine_principal_store": false, ...}}
```

`engine_principal_store` in the `/readyz` checks vector mirrors every other
`X && X->is_open()` row — `false` means either the store never opened at
boot (see §1 — but then the process would already have refused to start,
so this combination should not be observable in a healthy deploy) or,
transiently, that a background health signal has flagged the pool. Treat it
as a Postgres-pool health question first: check `pg_pool` saturation /
connectivity metrics before assuming the `engine_principal_store` schema
itself is the problem.

### 3. Engine-authenticated requests failing — the 503-vs-401 split

Every session synthesized from an engine-kind API token
(`AuthRoutes::synthesize_token_session`, `auth_source="engine_token"`)
routes through `EnginePrincipalStore::get_for_auth`'s **three-state**
contract before the request is admitted:

| `get_for_auth` status | Client-visible signal | Meaning | Operator action |
|---|---|---|---|
| `Active` | request proceeds | live, non-revoked principal | none |
| `MissingOrRevoked` | request denied (401-class) | **terminal** — no such principal, or its `lifecycle_state != 'active'` | Confirm intent: if the revoke was accidental, mint a **successor** principal via `transfer_owner`/re-`create` (revoke is never reversed, §3.1) and re-issue a token against the new principal. If the caller was never meant to exist, this is correct behavior — no action needed. |
| `StoreUnreachable` | request denied (503-class in spirit — currently surfaces as the generic 401 `require_auth` produces for any failed synthesis; see the noted follow-on in `auth_routes.cpp`) | **retryable** — the store never opened, or a lease/query timed out | This is a Postgres availability problem, not a credential problem. Check `/readyz`'s `engine_principal_store` row and the shared pool's health. The caller should back off and retry — do NOT revoke or re-mint the token, its referent is fine. |

**Both non-`Active` outcomes deny the request — never confuse the two.**
`MissingOrRevoked` reads as "credential problem, go fix the principal or
token." `StoreUnreachable` reads as "infrastructure problem, go fix
Postgres." Treating a transient outage as a revoked credential (or vice
versa) is exactly the failure mode the three-state split exists to prevent
(design doc §3.1/§12 decision 1) — if you see a spike of engine-token
denials, check `/readyz` and pool metrics BEFORE assuming principals were
maliciously revoked.

## The `engine:` namespace collision-scan boot failure

At every boot, after `EnginePrincipalStore` and `RbacStore` both construct,
the server runs a **fail-closed preflight** (design doc §3.1 upgrade hazard
/ decision log #3) scanning for pre-existing names inside the reserved
`engine:` namespace:

- `AuthDB::find_reserved_prefix_users("engine:")` — any `users.username`
  (active or soft-deleted) starting with `engine:`.
- `RbacStore::find_local_groups_with_prefix("engine:")` — any locally-sourced
  RBAC group name starting with `engine:`.

If **either** scan returns a non-empty result, the server logs the exact
colliding names and refuses to start:

```
[error] [auth] Refusing to start: the 'engine:' namespace is reserved for engine principals
(design doc §3.3) but pre-existing names collide with it — colliding users: [...];
colliding local RBAC groups: [...]. Rename or remove these before upgrading.
```

**Why this is fail-closed, not fail-open.** Both creation-time guards
(`is_valid_username`'s `:` ban, `is_reserved_identity_prefix`, and
`RbacStore::create_group`'s reserved-prefix rejection) only defend **new**
rows going forward — they cannot retroactively fix a database that already
had an `engine:`-named user or group before this reservation shipped. Left
uncaught, such a row would either be silently shadowed by a real engine
principal of the same name, or — worse — a stale local group could sit
inside a namespace meant to be authoritatively engine-only. Refusing to
boot is the correct posture: this is a one-time, operator-driven migration
step, not a routine failure mode.

### Recovery procedure

1. Read the colliding names out of the log line above (both lists are
   printed in full — no truncation).
2. For each colliding **user**: decide whether the row is stale (predates
   engine principals entirely, e.g. an accidental legacy `engine:` username)
   or was somehow created out-of-band. Rename or soft-delete it via the
   normal user-management path — you cannot rename in place through the
   API (`is_valid_username` rejects `:` on write), so this is typically:
   ```bash
   # Inspect first.
   sqlite3 /var/lib/yuzu/auth.db \
     "SELECT username, is_active, identity_source FROM users WHERE username LIKE 'engine:%';"

   # Stop the service and back up auth.db first (see
   # docs/ops-runbooks/auth-db-recovery.md for the general auth.db surgery
   # cautions). Then EITHER rename the colliding row out of the reserved
   # namespace (preferred — preserves the account's audit history), OR
   # hard-delete it if it is genuinely stale and unwanted.
   #
   # Rename (preferred): move it to a non-reserved username. Do the same
   # rename in any table that carries the username as a foreign key if you
   # want to keep the account usable.
   sqlite3 /var/lib/yuzu/auth.db \
     "UPDATE users SET username = 'legacy_engine_reclaimed' WHERE username = 'engine:legacy';"

   # OR hard-delete (only if the row is stale and you do not need it):
   sqlite3 /var/lib/yuzu/auth.db \
     "DELETE FROM users WHERE username = 'engine:legacy';"
   ```
   `find_reserved_prefix_users` intentionally includes soft-deleted rows
   too (it scans the `username` primary key, not active-user visibility) —
   a soft-deleted collision still occupies the reserved name, so
   `UPDATE users SET is_active = 0` alone will NOT satisfy this preflight.
   Only a rename (moving the name out of the `engine:` namespace) or a hard
   `DELETE` (removing the primary-key row) actually clears the collision.
3. For each colliding **local RBAC group**: `RbacStore::create_group`
   already refuses new creates in this namespace, so a collision here is
   necessarily a pre-existing row. Inspect and delete it via
   `RbacStore::delete_group` (dashboard: Settings → RBAC → Groups) or
   direct SQL against `rbac.db`:
   ```bash
   sqlite3 /var/lib/yuzu/rbac.db \
     "SELECT name, source FROM groups WHERE name LIKE 'engine:%' AND source = 'local';"
   sqlite3 /var/lib/yuzu/rbac.db \
     "DELETE FROM groups WHERE name = 'engine:legacy-group';"
   ```
   Deleting a group cascades to its `group_members` rows
   (`ON DELETE CASCADE`); confirm the group had no members you need to
   re-home into a differently-named group first.
4. Restart the server. The preflight re-runs on every boot — it is not a
   one-shot migration flag — so a clean pass confirms the collision is
   fully resolved.

## Cross-references

- Store contract, three-state `get_for_auth`, and construction posture:
  `server/core/src/engine_principal_store.hpp` (file doc comment).
- Design doc: `docs/auth-engine-principals-design.md` §3.1 (posture),
  §3.3 (namespace reservation), §6 (session synthesis / referential
  integrity), §12 decision 1 (the StoreUnreachable/MissingOrRevoked split).
- Substrate-wide Postgres store recovery (pool exhaustion, PG down at boot,
  migration drift): `docs/postgres-store-playbook.md`.
- `auth.db` (SQLite, per-node) recovery for the human-principal side of
  the namespace collision: `docs/ops-runbooks/auth-db-recovery.md`.
