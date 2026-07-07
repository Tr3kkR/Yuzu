- **Software licence detection (SLE).** Agents now detect installed **software
  licences** per endpoint — product, vendor, licence type, channel, status and expiry —
  across Windows (WMI `SoftwareLicensingProduct`, Office Click-to-Run, an extensible
  `ProbeSpec` table), Linux (rpm/dpkg licence tags, RHEL entitlement certs, FlexLM
  `.lic` files) and macOS (App Store receipts + vendor plists), syncing them daily to
  Postgres. A new **`SoftwareLicensing`** RBAC securable gates a **SLE** dashboard page
  and the read-only **`/api/v1/sle/*`** REST surface (`summary`, `licenses`,
  `licenses/{key}/devices`, and the per-device-scoped, per-open-audited `agents/{id}`
  drill); the `/inventory` software catalog is unchanged and remains under
  `Inventory:Read`. Per-user licence surfaces can attribute a licence to a local
  profile — the **`--license-scan-user-ref=collect|hash|omit`** agent flag (default
  `hash`, a per-device keyed-HMAC pseudonym) controls that identifier, and
  `--inventory-disable` turns the whole source off. See the user manual's
  [Software licence detection](docs/user-manual/software-licensing.md) page for the
  per-surface collection disclosure and privacy limits. (#264)
