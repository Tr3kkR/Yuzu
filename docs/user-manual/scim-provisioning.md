# SCIM v2 Provisioning

SCIM 2.0 (System for Cross-domain Identity Management, RFC 7643/7644) lets
an enterprise identity provider — Okta, Microsoft Entra ID, OneLogin, and
others — automatically create and disable Yuzu operator accounts as people
join, move, and leave your organization, instead of an admin managing
accounts by hand in the dashboard. This is the standard mechanism auditors
look for when assessing SOC 2 **CC6.2** (provisioning) and **CC6.8**
(termination).

> **Groups→role mapping is supported.** Push SCIM `Group` resources and
> configure `--scim-admin-group` to grant `role=admin` to members of a
> configured admin group, the same pattern [SAML](authentication.md#saml-group-to-role-mapping)
> and OIDC already support. Without that flag set, every SCIM-provisioned
> account stays the fixed, read-only `user` role — see
> [What gets provisioned](#what-gets-provisioned) and
> [Groups → role mapping](#groups--role-mapping) below.

## What SCIM does

Once enabled, your IdP's SCIM connector talks to `https://<your-server>/scim/v2`
using a bearer token you configure. From then on:

- **New hire assigned the Yuzu app in the IdP** → the IdP calls
  `POST /scim/v2/Users` → a Yuzu account is created automatically, ready to
  sign in via SSO.
- **Employee terminated / unassigned from the app in the IdP** → the IdP
  calls `PATCH`, `PUT` (or `DELETE`) → the Yuzu account is disabled
  immediately, and any active session for that user is revoked. No admin
  has to remember to go disable the account by hand.
- **Employee later re-assigned / re-hired** → the IdP re-activates the same
  SCIM resource → the Yuzu account is restored (any stale account lockout
  is cleared). The user re-enrolls MFA on their next login — a reactivation
  never resurrects an old second factor. A returning employee whose account
  was fully deprovisioned and later re-`POST`ed by the IdP is also handled —
  see [Reprovisioning a returning employee](#reprovisioning-a-returning-employee)
  below.

## Enabling SCIM

Two flags, both required together:

| Flag | Env var | Description |
|---|---|---|
| `--scim-enable` | `YUZU_SCIM_ENABLE` | Turns on the `/scim/v2/*` endpoint surface. Default `false` — the surface does not exist at all until you opt in. |
| `--scim-token` | `YUZU_SCIM_TOKEN` | The bearer credential your IdP's SCIM connector will authenticate with. Generate a long random secret and treat it like a password (a 32+ byte random hex/base64 string is a good choice). |

**Prefer the environment variable.** A `--scim-token` value passed on the
command line is visible to any local user via `ps`/`/proc/<pid>/cmdline`;
`YUZU_SCIM_TOKEN` is not. Use the env var as the primary method:

```bash
export YUZU_SCIM_TOKEN="$(openssl rand -hex 32)"
./yuzu-server \
  --https-cert    /etc/yuzu/server.crt \
  --https-key     /etc/yuzu/server.key \
  --scim-enable
```

(`--scim-token` remains available for local/manual testing, but is not
recommended for a production invocation for the `ps`-visibility reason
above.)

**The server refuses to start** in either of these cases:

- `--scim-enable` is set but `--scim-token` is not — there is no safe way
  to expose the provisioning surface without a credential gating it.
- `--scim-enable` is set together with `--no-https` — the bearer token is a
  credential capable of creating and disabling operator accounts; it must
  never be sent in plaintext. **SCIM requires HTTPS.**

The server logs its SCIM posture once at startup so you have a record of
when provisioning was turned on (compliance evidence for CC6.2).

## Configuring your IdP's SCIM connector

Point your IdP's SCIM connector at the base URL and supply the bearer token:

- **SCIM base URL:** `https://yuzu.example.com/scim/v2`
- **Authentication:** Bearer token — enter the same value you set with
  `YUZU_SCIM_TOKEN` (or `--scim-token`).

> **Required: map `userName` to a slug, not an email address.** Yuzu account
> usernames only allow letters, numbers, `.`, `_`, and `-` — no `@`. Most
> IdPs (Okta, Entra ID) default a new SCIM app's `userName` mapping to the
> user's email address, which will cause every provisioning call to fail
> `400`. Before assigning any users, open the connector's attribute-mapping
> screen (Okta: "Provisioning" → "To App" → attribute mappings; Entra ID:
> "Provisioning" → mapping editor) and change the `userName` source
> attribute to something slug-shaped — e.g. the part of the email before
> the `@`, an employee ID, or another existing non-email directory
> attribute. Native support for an email-shaped `userName` is on the
> roadmap; until then this remapping step is required.

Consult your IdP's SCIM setup documentation for the exact steps (Okta:
"SCIM Provisioning" app integration wizard; Entra ID: "Provisioning" tab on
the Enterprise Application). Yuzu implements the standard discovery
endpoints (`ServiceProviderConfig`, `ResourceTypes`, `Schemas`) that most
connector wizards use to auto-detect capabilities — after entering the base
URL and token, use your IdP's "Test Connection" button to confirm the
handshake works before assigning any users.

Once connected, assign users/groups to the Yuzu application in your IdP as
you would for any other SCIM-provisioned app; the IdP handles the
create/update/deactivate calls automatically from that point on.

## What gets provisioned

A user created via SCIM:

- Is assigned the **`user` role** (read-only, floor privilege) by default —
  unless they are already a member of your configured
  [`--scim-admin-group`](#groups--role-mapping) at the moment of
  provisioning, in which case they are created `role=admin` directly. No
  other group or role attribute the IdP might send has any effect on role.
- Gets a **random, discarded password** — SCIM users never log in with a
  local password. They authenticate through your SSO flow (OIDC or SAML)
  the same as any other SSO user.
- Is tracked with a **provisioning source of "scim"**. This matters for
  deprovisioning safety (see below): a locally-created admin account, or
  the emergency break-glass account, can never be touched by a SCIM
  deactivate/delete call — even if the IdP or connector is compromised or
  misconfigured. A SCIM push can only ever affect accounts it created.

If you need admin access for a SCIM-provisioned person, configure
[Groups → role mapping](#groups--role-mapping) below — or, if you'd rather
keep it independent of SCIM entirely, grant it through
[OIDC group→role mapping](authentication.md#group-to-role-mapping) or
[SAML group→role mapping](authentication.md#saml-group-to-role-mapping)
instead; all three mechanisms are independent and unaffected by one another.

## Groups → role mapping

Your IdP can push SCIM `Group` resources, and Yuzu can grant `role=admin` to
any SCIM-provisioned user who is currently a member of one configured admin
group — mirroring how [SAML group→role mapping](authentication.md#saml-group-to-role-mapping)
and OIDC group→role mapping already work.

### Endpoints

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/scim/v2/Groups` | Create a group (`displayName`, optional `members[]`) |
| `GET` | `/scim/v2/Groups/{id}` | Read a single group |
| `GET` | `/scim/v2/Groups` | List groups (`startIndex`/`count` pagination, optional `filter=displayName eq "..."`) |
| `PUT` | `/scim/v2/Groups/{id}` | Replace a group |
| `PATCH` | `/scim/v2/Groups/{id}` | Add/remove members (RFC 7644 §3.5.2 PatchOp on the `members` path) |
| `DELETE` | `/scim/v2/Groups/{id}` | Delete a group |

`Group` is now advertised in `/scim/v2/ResourceTypes` and `/scim/v2/Schemas`
(schema urn `urn:ietf:params:scim:schemas:core:2.0:Group`) alongside `User`.

**Group size is bounded.** Each Group create/replace/patch enforces a
bounded maximum on `members[]` — a request that would push a group past
that bound is rejected rather than silently truncated or accepted
unbounded. If your admin group is very large, split membership pushes
across multiple `PATCH` calls.

### Configuration

| Flag | Env var | Description |
|---|---|---|
| `--scim-admin-group` | `YUZU_SCIM_ADMIN_GROUP` | The `displayName` of the SCIM group whose members are granted `role=admin`. Default empty — no SCIM group grants admin, and every SCIM-provisioned user stays `role=user`. The value is whitespace-trimmed at load. |

`--scim-admin-group` mirrors `--saml-admin-group`: set it to the exact
`displayName` of the group in your IdP that should map to Yuzu admin
(case-sensitive, exact byte match — no wildcard/prefix matching, and no
leading/trailing whitespace tolerance beyond the trim above).

**Requires a restart to take effect.** `--scim-admin-group` is read once at
startup; changing it (or renaming the mapped group's `displayName` in the
IdP) requires updating the flag and restarting the server — there is no
live-reload or Settings-UI path. A restart alone does not re-evaluate any
user's membership; see [Recovery and alerting](#recovery-and-alerting)
below for how to force re-evaluation after a config fix.

### How role is resolved

Because Yuzu's role model is binary (`admin` or `user`), the mapping is a
simple parity check: a SCIM-provisioned user is `role=admin` **if and only
if** they are currently a member of the group named by `--scim-admin-group`;
otherwise they are `role=user`. Role is recomputed whenever it could have
changed — on user creation, and on any Group create, replace, patch, or
delete that could add or remove the user from the admin group. Removing a
user from the admin group demotes them back to `user` on the next
recomputation; it does not require a separate role-change call.

### Provenance guard still applies

Role changes driven by Group membership only ever touch accounts with
`provisioning_source == "scim"` — the same guard that protects deactivate/
reactivate/delete (see [What gets provisioned](#what-gets-provisioned)
above). If a Group's `members[]` list includes the SCIM `id` of a
non-SCIM account (a locally-created admin, or the `--break-glass-user`
account), that member is **never** role-changed. A compromised or
misconfigured IdP cannot use Group push to elevate, demote, or otherwise
touch a local principal.

### Manual role changes to a SCIM account are not durable

For a SCIM-provisioned account, IdP group membership — not a manual
dashboard edit — is the authoritative, durable source of truth for role.
If you (or another admin) manually change a SCIM-provisioned user's role
from the dashboard, that change is **reverted back to the group-derived
role the next time something recomputes that user's membership** — a
Group `POST`/`PUT`/`PATCH`/`DELETE` that touches this user, or the user
being reprovisioned (a `POST` reviving a deactivated account). It is
**not** reverted by a plain deactivate/delete attempt (the deprovision
guard blocks those against a non-`user` account before any recompute runs
— see [Deprovisioning order matters for group-granted admins](#deprovisioning-order-matters-for-group-granted-admins)
below), and it is **not** reverted by a server restart or by changing
`--scim-admin-group` itself — both require a subsequent Group mutation to
actually re-evaluate membership.

**One residual case:** if you manually promote a SCIM-provisioned user to
`admin` and that user is not a member of *any* SCIM group, there is no
membership-recompute event that will ever touch them, so the manual
promotion is neither reverted nor is the account SCIM-deprovisionable
(the deprovision guard still blocks it) — an operator must demote it by
hand. This is a pre-existing residual carried over from the Users slice,
not new in Groups → role mapping.

### Deprovisioning order matters for group-granted admins

The SCIM deprovision role-guard refuses to delete or deactivate an account
whose role is not `user` (it returns `404`, not a `403` that would confirm
the account exists). This means **a user who is `admin` via group
membership cannot be SCIM-deprovisioned until the IdP first removes them
from the admin group** — which demotes them back to `user`, at which point
the next deactivate/delete call succeeds normally.

In practice this is not extra work: standard Okta/Entra offboarding already
removes a departing employee from all their groups (including any admin
group) as part of unassigning the app, before or as part of deactivating
the user. As long as your offboarding flow follows that normal order —
remove from groups, then deactivate/delete — deprovisioning a group-granted
admin behaves exactly like deprovisioning any other SCIM user.

### Recovery and alerting

Deploy these alert rules alongside SCIM Groups → role mapping:

- **`yuzu_scim_role_change_failures_total > 0`** — a role change was decided
  but did not durably apply (an AuthDB write failure during
  `recompute_scim_user_role`). Investigate immediately; the account is
  running with a role that does not match its IdP group membership until
  fixed.
- **A spike in `rate(yuzu_scim_role_changes_total[5m])`** — a sudden burst
  of role changes is the signature of an IdP-side misconfiguration or
  accidental mass group edit (e.g. someone attached the wrong group to the
  Yuzu app, or bulk-edited the admin group's membership), not routine
  churn. Alert on a rate threshold well above your organization's normal
  onboarding/offboarding cadence.
- **`yuzu_scim_audit_write_failures_total`** — the existing CC6.8
  evidence-integrity alert; it also covers a lost audit row for a group
  create/update/delete or role-change event (the SCIM call and the role
  change themselves still succeeded — only the evidence row is missing).

**Remediation for a misconfigured `--scim-admin-group`:** fix the flag
value and restart the server (see [Configuration](#configuration) above —
this flag is not live-reloadable). **A restart alone does not fix already
wrong roles** — it only changes which group name new recomputes will
check against; any user whose role drifted under the old value stays
drifted until a recompute actually runs for them. To force re-evaluation
of every member's role after correcting the flag, re-`PATCH` the affected
group(s) (even a no-op add/remove of an already-current member triggers
`recompute_scim_user_role` for every affected user) rather than waiting for
the IdP's next natural sync.

### Example: Okta/Entra Group push

Creating the admin group and adding a member:

```http
POST /scim/v2/Groups
Authorization: Bearer <scim-token>
Content-Type: application/scim+json

{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
  "displayName": "yuzu-admins",
  "members": [
    { "value": "<scim-user-id>" }
  ]
}
```

Adding a member to an existing group via `PATCH` (the form most IdP
connectors issue when a user is later assigned to the group):

```http
PATCH /scim/v2/Groups/{id}
Authorization: Bearer <scim-token>
Content-Type: application/scim+json

{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
  "Operations": [
    {
      "op": "add",
      "path": "members",
      "value": [{ "value": "<scim-user-id>" }]
    }
  ]
}
```

Removing a member (e.g. as part of offboarding, before deactivating the
user) uses the same `PATCH` shape with `"op": "remove"`. Set
`--scim-admin-group` to `yuzu-admins` (or whatever `displayName` you chose)
for this group's membership to grant `role=admin`.

## Deprovisioning and termination

When your IdP deactivates or removes a user's app assignment, it sends a
`PATCH` or `PUT` (setting `active: false`) or a `DELETE`. Any of the three
has the same effect:

- The Yuzu account is disabled immediately.
- Any session the user currently holds is revoked — they are logged out,
  not just blocked from a future login.
- The action is recorded in the audit log (`scim.user.deactivated` /
  `scim.user.deleted`), giving you a timestamped record for termination
  evidence (CC6.8).

> **API/MCP tokens are not automatically revoked.** SCIM deprovisioning
> terminates the user's login and revokes their active **sessions**, but it
> does **not** revoke any API or MCP token that user previously generated for
> themselves. A terminated employee who holds a long-lived personal API token
> keeps the ability to authenticate with it until an admin revokes that token
> by hand. If a deprovisioned user may have minted an API token, revoke it
> manually from the dashboard (Settings → API Tokens) or via the REST API.
> This is a pre-existing gap shared with the dashboard's manual "disable
> user" path, not something specific to SCIM — tracked as
> [#2022](https://github.com/Tr3kkR/Yuzu/issues/2022).

**SCIM will not deactivate an account that is currently `role=admin`,**
whether that admin role came from a dashboard promotion or from
[Groups → role mapping](#groups--role-mapping) — that account drops out of
SCIM's reach until it is back to `role=user`, and an IdP-side deactivate/
delete call against it is refused in the meantime. This is a
**demote-before-delete ordering gate**, not a guarantee that a manual
promotion is permanently protected: SCIM simply must never be able to
deprovision a non-`user` account without an explicit, auditable demotion
happening first. For a group-granted admin, see
[Deprovisioning order matters for group-granted admins](#deprovisioning-order-matters-for-group-granted-admins)
above for the expected offboarding order; for a manually-promoted account,
see [Manual role changes to a SCIM account are not durable](#manual-role-changes-to-a-scim-account-are-not-durable)
above — a manual promotion is not otherwise durable, but demotion is still
a required, explicit step before SCIM can deprovision the account.

If the person is later re-added in the IdP, the same SCIM resource is
reactivated (`active: true`): the account comes back, any lockout state is
cleared, but **MFA is not restored** — they will re-enroll TOTP the next
time they sign in.

## Reprovisioning a returning employee

If someone leaves and is later re-hired, and your IdP re-issues a `POST`
for the same `userName` rather than reactivating the existing SCIM resource
(some IdP connectors do this after a long enough gap), Yuzu handles it
correctly: `POST` against a `userName` that matches an existing,
**already-deactivated** SCIM-provisioned account revives that account
rather than failing. You do not need to manually clean up or re-create
anything — a `409` conflict is only returned when the `userName` collides
with a **currently-active** account.

## Troubleshooting

- **IdP reports "connection test failed."** Confirm `--scim-enable` is set,
  the server is reachable over HTTPS at the configured base URL, and the
  bearer token in the IdP matches `YUZU_SCIM_TOKEN`/`--scim-token` exactly
  (whitespace/newline differences are a common copy-paste mistake).
- **Every request returns 401.** The bearer token is checked on every
  `/scim/v2/*` call including the discovery endpoints — there's no
  unauthenticated preview. Re-verify the token value configured in the IdP.
- **Provisioning fails with a 400 about `userName`.** Your IdP is almost
  certainly sending an email address as `userName` — Yuzu usernames must be
  a slug (letters, numbers, `.`, `_`, `-` only, no `@`). Remap `userName` to
  a non-email attribute in the IdP's attribute-mapping screen (see
  [Configuring your IdP's SCIM connector](#configuring-your-idps-scim-connector)
  above) and re-run the sync.
- **A user I expected to be deactivated is still active.** Two possible
  causes: (1) the account was never SCIM-provisioned (check
  `provisioning_source` via an admin) — a locally-created account is not
  reachable by SCIM deactivation by design, disable it from the dashboard
  instead; or (2) the account is `role=admin` — either promoted by a
  dashboard admin, or granted admin via [Groups → role mapping](#groups--role-mapping)
  through the configured `--scim-admin-group` — SCIM deliberately refuses to
  touch an account whose role is not `user` (see above). Remove the user
  from the admin group first (which demotes them back to `user`), or
  disable the account from the dashboard instead.
- **Deleting/deactivating a group-granted admin via SCIM returns 404.** This
  is expected, not a bug — see
  [Deprovisioning order matters for group-granted admins](#deprovisioning-order-matters-for-group-granted-admins).
  Remove the user from the admin group first; the deactivate/delete call
  then succeeds on the next sync.

## See also

- `docs/auth-architecture.md` "SCIM v2 provisioning" — full technical
  reference (endpoint list, provenance-guard design, storage decision, audit
  actions).
- [REST API Reference](rest-api.md#scim-v2-provisioning) — endpoint-by-endpoint
  wire reference.
- [Authentication](authentication.md) — OIDC/SAML SSO setup (SCIM
  provisions the account; SSO is how the account signs in).
- `docs/security-reviews/scim-groups-role-2026-07-13.md` — security review
  for Groups → role mapping (threat model, provenance-guard extension,
  deprovision-ordering decision).
