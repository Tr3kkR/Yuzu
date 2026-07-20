- **SCIM Groups → role mapping (#2021).** `/scim/v2/Groups` now accepts
  `POST`/`GET`/`PUT`/`PATCH`/`DELETE` (list with pagination and
  `filter=displayName eq "..."`), and `--scim-admin-group`
  (`YUZU_SCIM_ADMIN_GROUP`) grants `role=admin` to any SCIM-provisioned user
  currently a member of that group — mirroring the existing SAML/OIDC
  group→role mapping (SOC 2 CC6.7). The Users-slice provenance guard is
  preserved: only accounts SCIM itself provisioned are ever role-changed.
  Note the deprovision-ordering interaction — a group-granted admin cannot
  be SCIM-deprovisioned until the IdP first removes them from the admin
  group (see `docs/user-manual/scim-provisioning.md` "Groups → role
  mapping").
