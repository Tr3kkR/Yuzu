- **Guardian's lifecycle-journal retention guard no longer swallows a
  distinct clock anomaly under a still-active one.** Age eviction's decline
  was tracked with a single `bool` latch, which cannot carry anomaly
  identity: a DIFFERENT anomaly arriving while the latch was still set from a
  previous decline was neither declined nor counted, and the pass deleted the
  journal silently (measured, #2573, the same defect class as TAR's earlier
  fix). The guard now dedups on the whole fact set (shared with the audit
  store's and TAR's clock guards), so a distinct anomaly reports again
  instead of deleting, while an identical repeat still drains at the same
  paced rate as before. One accepted behavior change: an idle journal (no
  batch actually past its retention window) that observes a large forward
  clock jump is no longer reported as a clock anomaly — with nothing at risk
  of loss, there is nothing to decline.
