- **Fixed silent loss of multi-product CVE matches.** The NVD store's `INSERT OR REPLACE`
  upsert keyed on `cve_id`, so a CVE affecting several products kept only the last
  product row — the others were dropped, causing that CVE to under-report on affected
  devices. The reshaped store keeps every affected-product row, and per-CVE upserts are
  now atomic (a mid-sync failure rolls back that CVE and retains its prior match set
  rather than committing a wiped one).
