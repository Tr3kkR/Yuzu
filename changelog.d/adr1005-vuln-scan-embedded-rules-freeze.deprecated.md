- **`vuln_scan` embedded CVE rule list frozen and deprecated (ADR-1005).** The
  agent plugin's built-in static CVE list (`cve_rules.hpp`) receives no further
  rule updates, and its use as an authoritative finding source via the
  `scan`/`cve_scan` actions is deprecated — results against the frozen list
  grow increasingly stale. The plugin's `inventory` collection action and the
  generic rule-evaluation plumbing are unaffected and stay supported.
  Authoritative CVE matching moves to the vulnerability-management use-case
  engine module (server-side NVD matching is separately deprecated on its own
  announced cycle); the long-term replacement for on-device rules is
  engine-published content via the content-distribution plane.
