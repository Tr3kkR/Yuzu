- **SLE compliance evaluation, dashboard page and erasure surface.** The SLE
  **compliance evaluator** now derives the fleet licence posture hourly — matching
  detected licences against the product registry, rolling per-product state counts
  up with a first-class **as-of** stamp (keep-last-good on any failure; staleness is
  metric- and alert-observable) — and raises deduplicated
  **`software_license.expiring` / `software_license.expired`** notifications and
  webhook/offload events (worsening 30/14/7/1-day buckets, 7-day re-arm; the first
  evaluation fires once per product in-condition). A new top-nav **SLE** page
  (`/sle`) renders the posture as KPI tiles + a filterable per-product table (every
  nav copy gained the entry, and long-standing nav drift — missing Result Sets /
  Guardian / DEX links and six absent command-palette destinations — was reconciled
  in the same sweep). Two MCP tools (**`query_software_licenses`**,
  **`get_license_compliance_summary`**) mirror the REST aggregates. The per-device
  drill now reports **`effective_user_ref_mode`** (verifies a
  `--license-scan-user-ref` flip landed), a new
  **`POST /api/v1/sle/agents/{id}/surfaces`** returns live per-surface detection
  diagnostics (e.g. `privilege_missing`) with a PII-proof whitelist parser, the
  devices fan-out serves real per-device rows, and
  **`DELETE /api/v1/sle/agents/{id}`** triggers the durable erasure cascade with a
  fail-closed audit-before-erase evidence chain (`sle.agent.decommission` attempt +
  per-store outcome events — GDPR Art. 17). (#266)
