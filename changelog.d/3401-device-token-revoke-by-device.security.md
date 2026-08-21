- **Device-token re-registration revoke now actually revokes the tokens it exists to revoke
  (#823 defence gap, #3401).** `AgentRegistry`'s re-registration sweep (W1.5/#823) called
  `revoke_by_principal(agent_id)`, but every token's `principal_id` is the *operator* who issued
  it, not the agent — REST-issued tokens (`POST /api/v1/device-tokens`) can never match, so the
  sweep silently revoked zero rows on every real re-registration. A new `revoke_by_device`,
  keyed on the column `validate_token` actually binds a presenter against, closes the gap.
  Registration now also fails closed on a genuine revoke failure (previously logged and
  proceeded), and the revoke's blocking database round-trip no longer runs under the registry's
  mutex. `DeviceTokenStore` remains dormant — not yet constructed in production — so this has
  no live effect today; it closes an activation gate ahead of a future wiring change.
