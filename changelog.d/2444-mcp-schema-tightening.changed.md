- **Tightened MCP tool schemas to close the remaining semantic-burn class (#2444).**
  `revoke_certificate.serial_hex`, `confirm_engine_rotation.token_id`, `quarantine_device.reason`/
  `whitelist`, and the eight *approval-gated* engine-principal tools' `principal_id` (both the
  `engine:<slug>` and bare-slug forms) now carry `pattern`/`maxLength` bounds that mirror their
  handlers' existing checks, so a malformed argument is refused by schema — before an approval
  ticket is ever minted or consumed — instead of burning an already-approved, one-time ticket at
  the handler. `get_engine_principal` and `list_engine_roles` gained the same `principal_id`
  pattern too, but being Read-tier and never approval-gated, it's advertised `tools/list` metadata
  only — this codebase enforces input schemas solely on the approval-gated path, so a malformed
  value there still reaches the handler exactly as before. Roughly two
  dozen other required-string MCP tool arguments (`agent_id`, `expression`, `approval_id`,
  `campaign_id`, etc.) gained `minLength: 1`. For the approval-gated tools among them, an empty
  string is now refused the same pre-ticket way as the pattern tightenings above; for the rest
  (validation runs only on the approval-gated path), every handler already rejected an empty
  required string at runtime — the schema addition documents that existing behavior rather than
  changing it. The residual burn class this can't close by construction — args that pass the schema but
  still fail a handler's own business/state check — is now alertable via the new
  `yuzu_mcp_approval_burned_total{tool,reason}` counter, wired at a single response-inspecting
  chokepoint so it counts every approval-gated tool's outcome uniformly.
