- **SCIM-provisioned users can now become admin via IdP group membership.**
  Corrects earlier documentation stating a SCIM-provisioned account could
  never reach `role=admin` — with `--scim-admin-group`
  (`YUZU_SCIM_ADMIN_GROUP`) configured (opt-in, default unset), a
  SCIM-provisioned user is granted `role=admin` while they are a current
  member of that IdP-managed group (#2021).
