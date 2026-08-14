- **Registry-independent authz model on the ADR-0033 spine.** New header-only
  `server/core/src/authz_model.hpp` defines the securable×operation×risk_tier×`mcp_tier_class`
  classification (ADR-0033 §2) a future runtime capability-declaration registry will consume when a
  Module registers a tool or REST route, plus the PR1.9-facing `CapabilityDeclaration` schema that
  references (without redefining) the ADR-1005/ADR-0032 per-capability obligations — the REST/MCP
  twin pair, discovery entry, A4 error envelope, agentic-context annotations, `data_class` and
  `audit_verb`. The seed catalogue includes the `AccessReview` securable's `Attest` operation and
  Guardian's `Push`, both deliberately outside the CRUD loops, following the existing
  hardcoded securable/operation vocabulary as a read-only reference. No wire enforcement and no
  database migration ship with this model — see `docs/authz-model.md`.
