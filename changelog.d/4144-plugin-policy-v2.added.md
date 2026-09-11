- **`GET /api/v2/agent/plugin-policy`.** The hardened plugin-signing distribution route from #4028
  (A4 `data`/`meta` success envelope, standard A4 error envelope, `PluginSigning:Read` RBAC gate,
  fail-closed audit, two new retryable `503`s where the route previously answered `200` with a
  value it could not stand behind) — moved here from `/api/v1/agent/plugin-policy` because #4028
  originally shipped that hardening as an in-place change to an already-shipped route, which
  violates `docs/api-versioning-policy.md`'s breaking-change rule (external review, #4144). Also
  closes a TOCTOU the #4028 fix round only partially fixed: `cert_count`/`sha256`/`subjects`/
  `trust_bundle_pem` are now derived from a single filesystem read, so a concurrent trust-bundle
  upload can no longer produce a response pairing a stale `sha256` with the newly-uploaded PEM
  bytes. See the paired `.deprecated.md` fragment.
