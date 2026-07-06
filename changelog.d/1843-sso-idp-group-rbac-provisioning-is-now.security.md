- **SSO IdP-group→RBAC provisioning is now source-aware and reconciled (#1832, HIGH).** Fixes two
  bugs in the OIDC `/auth/callback` group sync: a **confused-deputy** (a locally-created RBAC group
  and a same-named IdP group were the same `groups` row, so an operator-created local group named
  e.g. `admins` silently inherited any role granted to an IdP group also asserting `admins`, and vice
  versa) and a **deprovisioning bypass** (group memberships were only ever added, never removed, so
  a user dropped from an IdP group kept every role that group granted indefinitely). Fix: IdP
  memberships are now written under a **namespaced** group name (`entra:<group-id>`, via
  `RbacStore::namespaced_group_name`) through a new transactional `RbacStore::reconcile_idp_memberships`
  that both upserts the asserted set and deletes any of the user's `entra:`-owned memberships not
  re-asserted this login — so IdP-side removal takes effect on the next SSO login. A
  `source='local'` group create is rejected if its name collides with a reserved IdP prefix
  (`local:`/`entra:`/`saml:`/`ad:`). The callback is **fail-closed**: an over-cap assertion
  (`>200` groups) or a reconcile-store failure denies the login outright (no session minted) rather
  than falling through to a session with stale/unreconciled roles. New audit action
  `auth.sso_group_provision` (result=ok/skipped/error) and metric
  `yuzu_auth_sso_group_provision_total{source,result}`. **Upgrade note:** operators who assigned an
  RBAC role to the old raw-gid OIDC group must re-assign it to the namespaced `entra:<group-id>`
  group — see `docs/user-manual/authentication.md` "RBAC Group Provisioning". SAML group sync is
  out of scope here (dropped in #1827; will ride this same reconcile path once #1826 merges).

- **#1832 hardening round — Entra group-overage no longer silently mass-deprovisions SSO users
  (HIGH).** A user in more than ~200 Entra groups gets no `groups` claim at all — Entra replaces it
  with a `_claim_names`/`_claim_sources` indirection pointer — and the original #1832 reconcile read
  that as "this user is in zero groups", deleting every one of their existing IdP-sourced RBAC
  memberships on their next login. `OidcProvider::parse_id_token` now sets
  `groups_claim_present`/`groups_overage` on the parsed claims; `/auth/callback` calls
  `reconcile_idp_memberships` only when the new `groups_claim_reconcilable(claims)` gate passes, and
  otherwise **skips reconciliation entirely** — existing memberships are left untouched and the login
  still proceeds (fail-open on membership, never on authentication). New audit result
  `auth.sso_group_provision` `result=skipped` (`reason=groups_overage|groups_absent`). Also in this
  round: `reconcile_idp_memberships` now verifies a namespaced group row's `source` before joining a
  membership to it, so a pre-existing differently-sourced row occupying the same namespaced name (a
  legacy local group literally named `entra:<gid>`, predating the reserved-prefix guard) can no longer
  be silently joined and leak its roles; rejects `source=="local"`/empty outright (the stale-membership
  DELETE is only safe for a real IdP source); drops blank/oversized asserted `external_id` entries
  instead of seeding a garbage group; and now returns `{added, removed}` membership counts so a no-op
  reconcile (the common steady-state login) writes no `auth.sso_group_provision` row at all, while a
  denied login (over-cap or store failure) also emits the shared `auth.oidc_login_failed` audit +
  analytics event so SIEM queries on that action don't miss a provisioning denial. See
  `docs/auth-architecture.md` "RBAC group provisioning (#1832)".
