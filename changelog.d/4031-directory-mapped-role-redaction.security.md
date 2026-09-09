- Redacted `get_directory_status`'s `groups[].mapped_role` (the AD/Entra
  group → Yuzu-role authorization map) to the empty string for non-admin
  callers, on the REST v1 route, the legacy route, and the MCP tool —
  previously reachable at Viewer role and readonly MCP tier, unlike the
  sibling `OidcConfig` `admin_group` field, which is floored.
