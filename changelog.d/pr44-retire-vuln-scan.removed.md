- **Breaking — retired the `vuln_scan` agent plugin outright (ADR-0018, ADR-0028 Decision 2).** Agent-side
  CVE and config matching (`cve_rules.hpp`, `config_checks.hpp`) predates server-authoritative
  vulnerability matching — the agent collects, it never decides — and the plugin's `inventory`
  action duplicated, more crudely, `installed_apps`' richer `list_inventory` collector. All five
  instruction definitions (`security.vuln_scan.scan`, `.cve_scan`, `.config_scan`, `.summary`,
  `.inventory`), the plugin code, the server-side catalogue/registry/result-parsing rows, Windows
  packaging, UAT and dashboard suite entries, and the plugin's ABI4 capability declaration are all
  removed together — superseding the group-A ABI4 declarations landed in this same release, which
  announce `vuln_scan`'s descriptors as new. **Server-side vulnerability handling is unaffected:**
  NVD sync, CVE correlation, the vulnerability dashboard, and the finding store all continue to
  work. **Operators upgrading an existing deployment must clean up manually** — boot content
  import skips conflicts and never prunes, so the five definitions persist in `instructions.db`,
  stay visible in the Send panel, and fail with an unknown-plugin error if dispatched; see
  *`vuln_scan` plugin retired* in `docs/user-manual/upgrading.md` for the removal steps. This
  leaves no vulnerability-scan entry point on the agent side until the ADR-0028 component-inventory
  collector lands, at which point `security.vuln_scan.scan` is re-created against it (superseding
  ADR-0028's original repoint-and-keep phasing, per the maintainer decision of 2026-08-21).
