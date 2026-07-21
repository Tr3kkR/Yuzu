# Engine Principals

Engine principals are the durable identities behind autonomous use-case-engine
modules (ADR-1005 item 2b) — a third principal class alongside human users and
human-created API tokens. Each engine principal has a named responsible human
owner, a grant justification captured at creation, and a required
`internal`/`external` classification, and it can never be granted the
admin/wildcard role: least privilege is enforced structurally, not merely
asserted by policy.

This page is an operator walkthrough. Full API reference:
[REST API — Engine Principals](rest-api.md#engine-principals);
[MCP tools 55–63](mcp.md#available-tools); design reference:
`docs/auth-engine-principals-design.md`; architecture summary:
`docs/auth-architecture.md` "Engine principals & delegation".

## Who this is for

Use engine principals for a first-party or third-party autonomous module that
needs its own credential, distinct from any human operator's token — for
example a future use-case-engine sync job. Do **not** use an engine principal
as a substitute for a normal service-scoped API token held by a human-run
automation pipeline; engine credentials are hard-locked to MCP tier
`readonly` and structurally barred from the admin role, which is the wrong
shape for anything that needs to execute or approve on a human's behalf.

## Before you start

Every mutating operation on this surface requires:

- An **admin session** with **MFA step-up** (REST) or the **`supervised`**
  MCP tier plus **maker-checker approval** (an approver who is not the
  submitter) for the six mutating MCP tools.
- The `owner_username` (and, for a transfer, the `new_owner`) must already
  exist as a real Yuzu user — creation and transfer both fail closed
  (`400`) against an unknown username.

**A structural rule with no exception:** a caller whose *own* session is
itself engine-classed can never touch this surface at all, on either
transport — not even to read. REST and all 9 MCP tools carry the same
denial belt.

## Walkthrough: create, mint, rotate, confirm, transfer, revoke

### 1. Create the principal

Dashboard: Settings → **Engine Principals** → fill in Slug, Display Name,
Owner, Classification, Justification → Create.

REST:

```bash
curl -sk -X POST https://localhost:8080/api/v1/engine-principals \
  -H "Cookie: $COOKIE" -H 'Content-Type: application/json' \
  -d '{
    "slug": "vuln-uce",
    "display_name": "Vuln UCE",
    "owner_username": "alice",
    "classification": "internal",
    "justification": "First-party vulnerability-management use-case engine module"
  }'
```

The server derives `principal_id = "engine:vuln-uce"`. `classification` has
no default — an empty or unrecognized value is rejected outright, so an
engine principal can never exist in an unclassified state.

### 2. Mint the first credential

The principal has no credential yet. Mint one (dashboard: **Mint** button;
REST: `POST .../credentials`):

```bash
curl -sk -X POST https://localhost:8080/api/v1/engine-principals/engine:vuln-uce/credentials \
  -H "Cookie: $COOKIE" -H 'Content-Type: application/json' \
  -d '{ "ttl_days": 90 }'
```

The response carries the raw secret **exactly once**, under
`Cache-Control: no-store` — copy it immediately into the consuming module's
secret store. It cannot be retrieved again; only rotated or revoked.

### 3. Rotate the credential (overlap-pair model)

Design §7's overlap-pair rotation is the only supported rotation shape — there
is no "replace in place." Rotating mints a **successor** credential while the
existing (**predecessor**) credential stays valid for an overlap window, so
the consuming module has time to pick up the new secret without a hard cutover:

```bash
curl -sk -X POST https://localhost:8080/api/v1/engine-principals/engine:vuln-uce/credentials/rotate \
  -H "Cookie: $COOKIE" -H 'Content-Type: application/json' \
  -d '{ "overlap_secs": 604800 }'
```

- At most **two** active credentials exist for a principal at any time.
- The overlap window has a **24-hour floor** — a shorter request is rejected
  outright, never silently rounded up.
- A same-caller retry within a short (~120-second) grace window after the
  original mint **re-serves the same successor secret** rather than erroring
  or minting a second successor — safe to retry a dropped response. Every
  successful return, original or replay, is independently audited under
  `engine_principal.credential.reveal`.
- If the consuming module updates the secret and you never call `confirm`
  (next step), a **60-second background sweep** auto-revokes the predecessor
  once the overlap window elapses on its own, and separately warns
  (an operational signal, not a security alert) if the *successor* looks
  unused as its own window nears expiry — a sign the new secret was never
  actually picked up.

### 4. Confirm the rotation (optional but recommended)

Once the consuming module has verifiably picked up the new secret, close the
loop explicitly instead of waiting for the sweep:

```bash
curl -sk -X POST https://localhost:8080/api/v1/engine-principals/engine:vuln-uce/credentials/confirm \
  -H "Cookie: $COOKIE"
```

This revokes the predecessor immediately and promotes the successor to the
principal's sole active credential. `confirm` is a **separate attestation**
from the `rotate` reveal — the server never infers "installed" from "the
rotate call returned 200."

### 5. Transfer ownership

Ownership transfer is **admin-forced** — it does not require the outgoing
owner's cooperation, so an account under termination-for-cause cannot use
engine-principal ownership as a lever to stall its own deprovisioning:

```bash
curl -sk -X POST https://localhost:8080/api/v1/engine-principals/engine:vuln-uce/transfer-owner \
  -H "Cookie: $COOKIE" -H 'Content-Type: application/json' \
  -d '{ "new_owner": "bob" }'
```

### 6. Revoke (terminal)

Revoke is **terminal and irreversible** — there is no un-revoke. Recovery from
a compromised or retired principal is to create a **successor** principal and
reference the old one via `superseded_by`:

```bash
curl -sk -X DELETE https://localhost:8080/api/v1/engine-principals/engine:vuln-uce \
  -H "Cookie: $COOKIE" -H 'Content-Type: application/json' \
  -d '{ "superseded_by": "engine:vuln-uce-2" }'
```

Every active credential is revoked **first**, then the identity itself flips
to `revoked` — a caller can never observe a revoked identity with a
still-valid credential. Calling this again on an already-revoked principal is
a no-op success, not an error.

## The owner-delete interlock (two-mode enforcement)

A user who owns an active engine principal must not be silently removed —
otherwise the principal's audit trail loses its named responsible human. This
is enforced in two modes, chosen by whether an operator is in the loop:

- **Interactive dashboard delete → prevention (`409`).** Deleting such a user
  from Settings → Users is blocked with a `409` and a toast pointing at the
  transfer-owner surface above. This is fail-**closed**: if the engine-principal
  store cannot even be reached to check, the delete is blocked too, never
  allowed through on "couldn't verify." An admin is present and can transfer
  ownership first, so prevention is the right control.

- **Automated SCIM deprovision → detection (audit + metric, never blocked).**
  SCIM-driven deprovisioning (an IdP deactivating or deleting a user, via
  `PATCH`/`PUT active:false` or `DELETE`) is a **compliance-mandated termination
  flow** (SOC 2 CC6.8) with no operator in the loop. Refusing it would leave a
  terminated employee's account **active** — a worse control failure — and
  auto-revoking their engine principals is rejected because revoke is terminal
  and irreversible (an IdP flap would destroy machine identities). So the
  deprovision **always succeeds**, but if the departing user owned active engine
  principals (or ownership can't be verified), the server emits a high-signal
  audit `engine_principal.owner_deprovisioned` and increments
  `yuzu_engine_principal_owner_deprovisioned_total` so an admin can reassign
  ownership out of band. The orphaned principal keeps authenticating on its own
  credential — it never derived authority from its owner — so the departed user
  gains nothing. Alert on that metric and transfer ownership promptly when it
  fires.

## The no-admin auditor

`GET /api/v1/engine-principals/audit/no-admin` (REST) and `audit_engine_no_admin`
(MCP, available on every MCP tier) are an independently-runnable proof that
"no admin, ever" actually holds across every engine principal — not just a
claim about the write-path guard that creates and grants them. It resolves
each engine principal's real role assignments and effective permissions
against the live RBAC tables and reports three kinds of violation: a literal
`admin`/`Administrator` role grant, any role flagged `is_system`, or a granted
`securable × operation` set large enough to be functionally admin-equivalent
even under an innocuous custom role name.

```bash
curl -sk https://localhost:8080/api/v1/engine-principals/audit/no-admin \
  -H "Cookie: $COOKIE"
```

```json
{ "data": { "ok": true, "violations": [] } }
```

An empty `violations` array is the positive evidence, not the absence of a
check. If the RBAC reference data needed to compute the wildcard bound can't
be resolved, the route returns `503` ("cannot verify") rather than a false
`ok:true` — treat that response as "run again," never as "clean." This
auditor is gated on `AuditLog:Read`, not `Security`, deliberately: a
read-only auditor role can run it without holding engine-principal write
access.

## Audit trail

Every lifecycle action on this surface is recorded under an
`engine_principal.*` audit verb — see the
[Audit Log reference](audit-log.md#logged-actions) for the full table,
including the two verbs (`engine_principal.rotation.auto_revoke`,
`engine_principal.rotation.successor_unused`) emitted by the background
rotation sweep rather than an operator call.
