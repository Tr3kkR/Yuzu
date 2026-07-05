- **NVD vulnerability matching now evaluates full CPE version ranges.** The server-side
  CVE store was reshaped from a flat single-upper-bound model to a normalized `cve` +
  `cve_match` schema that carries NVD's real `versionStartIncluding/Excluding` and
  `versionEndIncluding/Excluding` bounds, matched by an NVD-grade version comparator
  (epoch-aware, pre-release ordering, letter-releases). `/api/nvd/match` now returns
  far fewer false results on real-world version strings. Identity is still
  product-name based (vendor-precise CPE matching is pending the agent typed-identity
  collector, ADR-0018), so name-collision false positives are still possible.
- **`GET /api/nvd/status` `total_cves` now reports a distinct-CVE count.** It previously
  counted one row per affected product, so a multi-product CVE inflated the figure; the
  number will read **lower** after upgrade even once fully synced. This is expected, not
  data loss.
- **On upgrade, the local NVD mirror is rebuilt.** The CVE-store schema migration
  (v1→v2) drops and rebuilds the mirror; vulnerability-matching coverage is reduced
  until the next NVD sync completes (rate-limited — up to a few hours without an API
  key). The server logs a warning at migration time and self-heals automatically.
