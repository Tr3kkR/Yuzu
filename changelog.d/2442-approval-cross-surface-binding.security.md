- **An approval ticket can no longer be redeemed on a surface other than the one that minted it,
  where that surface is recorded.** Approvals are one shared store with three mint paths, and the
  MCP approval recall matches a ticket on its definition id and scope expression without binding the
  minting surface — so an approval raised through the REST instruction gate, where both of those
  fields are caller-influenced, could line up with an MCP tool's canonical arguments and be redeemed
  against it. What that bought was **the human approval itself**, not a new permission: an
  administrator reviewing that ticket sees a ticket id, a submitter and a scope expression, and
  nothing that names the surface it was raised on, so they would have been authorising an MCP tool
  invocation with no way to tell. Two of the three mint paths already record their surface; the recall now
  refuses any ticket whose **recorded** surface is something other than MCP. The refusal is
  deliberately indistinguishable from an ordinary spent-ticket response, so the recall cannot be
  used to probe which surface minted a ticket. A ticket with no recorded surface stays redeemable — the
  MCP mint is itself undeclared until its own follow-up lands, so that exemption is what keeps the
  gate working; it closes when the MCP mint declares itself.

- **Breaking — an approval granted but not yet redeemed when you upgrade is refused, and must be
  re-requested.** Rows predating the new column record no surface, and rather than assume one they
  may not have come from, the upgrade labels them with a sentinel that fails closed. The refusal
  reports as an ordinary spent ticket, because that message is uniform by design, so the upgrade note
  in `docs/user-manual/server-admin.md` is where the real cause is recorded. Recover by calling the
  tool again without `approval_id`. This reaches any deployment holding an **MCP** approval in
  flight, independent of whether it uses `mcp.`-prefixed definitions. Scheduled approvals are not
  affected — a schedule redeems by matching its own schedule id rather than through the MCP recall,
  so the origin check never sees one. The affected population does not grow after the upgrade.

- **This binds the surface, not the submitter.** The recall still does not compare who obtained the
  approval against who presents it, so a valid `approval_id` remains redeemable by any principal
  that also passes the tier gate and the tool's own RBAC. Treat an `approval_id` as a secret. Both
  halves are tracked: #2442 stays open for the submitter binding, #1803 for the read exposure.

- **A stored origin this build does not recognise is now refused rather than treated as
  undeclared.** "No declared origin" is the value that *grants*, so folding an unknown string into
  it would have made a row written by a newer binary redeemable here — the fail-open direction.

- **Minting into the reserved `mcp.` namespace is no longer refused at the approval store**, and
  that is deliberate rather than a relaxation. A definition already under the prefix with a schedule
  re-submits on every fire, so refusing at mint stopped that schedule permanently, and moving a
  schedule between definitions is not supported (#2742). Creating or importing a *new* definition
  under the prefix is still refused, at the authoring routes where authoring happens. Defending at
  redemption also reaches something a mint-time check cannot: a ticket that already existed before
  the guard shipped is refused at the point of use. That is the one-directional part of the claim —
  a mint-time check applied to every caller of `submit()`, so it is not the case that redemption
  covers strictly more in every respect.

- **New counter `yuzu_mcp_approval_refused_total{tool}`** records recall refusals at the consume
  step — a replay, a cross-surface ticket, or a store failure — pre-seeded for every approval-gated
  tool so an `absent()` alert stays meaningful. It deliberately carries **no `reason` label**: the
  denial kind is precisely what the client response withholds, and `/metrics` is not a stronger
  reader than the caller. Alert on the rate; the kind is in the audit row.
