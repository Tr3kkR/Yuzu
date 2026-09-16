- **`GET /api/v1/agent/plugin-policy` is deprecated.** Use `GET /api/v2/agent/plugin-policy` (see the
  paired `.added.md` fragment). The v1 route is unchanged from its pre-#4028 shape — flat top-level
  body, `require_admin` gate, no audit, the old bespoke error envelope — and keeps working for at
  least 90 days and at least one intervening feature release (`docs/api-versioning-policy.md`); see
  `docs/user-manual/server-admin.md`'s vNEXT note for the migration and the announced removal
  window.
