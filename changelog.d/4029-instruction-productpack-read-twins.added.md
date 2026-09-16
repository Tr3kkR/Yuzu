- **REST v1 + MCP twins for instruction definitions and product packs.** `GET
  /api/v1/instructions[/{id}[/export]]` and `GET /api/v1/product-packs[/{id}]`
  are new versioned REST routes; MCP gains `export_definition`,
  `list_product_packs`, and `get_product_pack`, and the existing
  `list_definitions`/`get_definition` tools now share a reconciled field set
  and full filter set with their REST twins (api-parity programme, #2146,
  #4029). Also fixes a prerequisite RBAC defect: `ProductPack` was used as a
  securable string by the shipped `/api/product-packs*` routes but was never
  seeded into the RBAC securable-types catalogue, so no role — not even
  Administrator — could ever be granted `ProductPack:*` while RBAC was
  enabled.
