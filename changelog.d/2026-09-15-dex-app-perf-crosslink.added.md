- **DEX Apps tab cross-links to per-version fleet performance, with a version filter.**
  The Apps tab's crash/hang blast-radius page now links to that application's fleet-wide
  CPU & memory trend (and back), joined on the exact process-image key crash and perf
  identity already share — no fuzzy or display-name matching. The performance trend page
  gains a per-version filter (click through a version row to narrow the view, or back to
  "all versions"), using the same `version` parameter the REST API already accepted.
