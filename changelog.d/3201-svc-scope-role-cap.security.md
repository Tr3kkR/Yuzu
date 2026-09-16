- **Closed a service-scoped API token authority-inheritance bug.** A service-scoped token's
  session previously inherited the minting principal's *current, live* legacy role, independent of
  the token's declared service scope — so a token minted by an admin carried `role == admin` and
  satisfied inline `effective_role(*session) == admin` checks with no independent service-scope
  guard of their own, including workflow/instruction role-gated step approval (a human-decision
  gate) and an MCP bundle-ownership check. `require_admin()` itself was never bypassable — it
  already denies every service-scoped token independent of role — the exposure was those *other*
  checks. A service-scoped token's session role is now floored to the base `user` level regardless
  of the minter's role; an `ITServiceOwner` RBAC grant is the sole authority ceiling. Requires RBAC
  explicitly enabled and a service-scoped token explicitly minted — not reachable by default.
