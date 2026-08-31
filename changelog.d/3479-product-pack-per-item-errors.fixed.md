- **`POST /api/product-packs` no longer silently drops per-item install errors.** A bundle where
  `install_fn` tolerates one document failing without failing the whole install (a genuine
  partial success) now returns `"errors"` (one entry per failed document and why),
  `"installed_count"`, and `"total_items"` alongside the usual `{"id", "status"}` — previously a
  `201` response gave no signal that anything failed. The audit row's `detail` also names the
  failed/total count on a partial success, matching the existing compensation-outcome
  convention (#3481). A total failure (every document rejected) now reports every document's
  reason in the `400` error message, `; `-separated, instead of only the first — `errors[0]` was
  all that ever reached the caller before. `ProductPackStore::install()`'s new trailing
  `partial_result` out-param defaults to null, so every existing caller's behavior is unchanged
  unless it opts in. Closes #3479.
