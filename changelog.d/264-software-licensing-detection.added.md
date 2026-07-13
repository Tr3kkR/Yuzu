- **Software licence detection (SLE).** Agents now detect installed **software
  licences** per endpoint — product, vendor, licence type, channel, status and expiry —
  across Windows (WMI `SoftwareLicensingProduct`, Office Click-to-Run, an extensible
  `ProbeSpec` table), Linux (rpm/dpkg licence tags, RHEL entitlement certs, FlexLM
  `.lic` files) and macOS (App Store receipts + vendor plists), syncing them daily to
  Postgres. Per **ADR-1005** (headless platform), the server ships the **discovery
  mechanism** only: a new **`SoftwareLicensing`** RBAC securable gates a per-device read
  surface — the per-device-scoped, per-open-audited **`GET /api/v1/sle/agents/{id}`**
  drill (serves the per-user `user_ref` rows) and its machine-scope MCP twin
  **`query_software_licenses`** (no `user_ref` — that PII is served only by the audited
  REST drill) — plus the audited GDPR-erasure **`DELETE /api/v1/sle/agents/{id}`**
  decommission cascade (gated `SoftwareLicensing:Delete`, audit-before-erase
  fail-closed). Licence **compliance/entitlement/reclamation** evaluation and the fleet
  posture reads (the `/sle` page and the `summary`/`licenses`/per-product device fan-out)
  **interpret** discovered facts and ship with the future **SAM use-case-engine module**,
  not in-server. The `/inventory` software catalog is unchanged and remains under
  `Inventory:Read`. Per-user licence surfaces can attribute a licence to a local
  profile — the **`--license-scan-user-ref=collect|hash|omit`** agent flag (default
  `hash`, a per-device keyed-HMAC pseudonym) controls that identifier, and
  `--inventory-disable` turns the whole source off. See the user manual's
  [Software licence detection](docs/user-manual/software-licensing.md) page for the
  per-surface collection disclosure and privacy limits. (#264)
