- **`ProductPackStore::install()` no longer silently orphans sibling-store content on a late
  failure.** Any failure reached after `install_fn` has already committed one or more documents
  into `InstructionStore`/`PolicyStore`/`WorkflowEngine` — the final Postgres persist transaction
  failing, or the duplicate-item-id validation check — now best-effort compensates (undoes) every
  already-installed item, in reverse install order, via the same per-kind delete dispatch
  `DELETE /api/product-packs/{id}` already used (now shared through one helper so the two paths
  can't drift). The final-persist failure path specifically distinguishes a genuinely-aborted
  transaction (safe to compensate) from one whose outcome merely couldn't be confirmed after the
  connection failed — a lost COMMIT acknowledgment after Postgres actually committed, or a
  connection severed at a point uncorrelated with the backend's own commit progress — by asking
  Postgres itself (`pg_xact_status()`) rather than inferring the outcome from a side effect;
  compensating on anything but a confirmed abort would actively delete real, already-persisted
  content. **Known gap, not closed by this change:** compensation is best-effort — a sibling
  store's own delete can itself fail (e.g. a referential-integrity refusal outside the bundle's
  own dependency chain); a residual orphan from that is logged at `spdlog::error` and counted in
  the new `yuzu_server_product_pack_install_compensation_total{result}` metric (pre-seeded,
  paired with a new `YuzuProductPackCompensationPartial` Prometheus alert — apply
  `docs/prometheus/yuzu-alerts.yml` to pick it up) for operator follow-up, not automatically
  retried. A client that retries the install after a partial
  compensation failure gets a fresh `install_fn` pass over the whole bundle rather than a repair
  of just the residual item, and the outcome depends on whether the retry's re-creation of that
  specific residual item collides: for a kind/id with no collision, the residual and the retry's
  new copy simply coexist as duplicate content. For `PolicyFragment` specifically — which
  refuses a duplicate *name*, independent of any explicit `id:` — and for any kind whose bundle
  hard-codes a retry-stable explicit `id:`, the retry's re-creation of that ONE document instead
  FAILS outright; if every OTHER document in the bundle still installs, the pre-existing
  (unrelated to this PR) per-document error tolerance means the pack still reports `201`, and
  any other document that cross-references the failed one by id (e.g. a `Policy`'s
  `spec.fragment`) silently resolves against the STALE residual rather than a freshly tracked
  copy — the resulting pack can end up depending on content that isn't listed among its own
  items, invisible to that pack's own future uninstall. **Since this same PR (#3479, a
  separate fragment): the `201` is no longer silent** — the response body now names every
  document that failed to (re-)install and why, so this specific hazard is now VISIBLE to the
  caller rather than requiring a cross-reference to notice. What's still open, and was the
  actual design question: whether the platform should go further and make the whole install
  all-or-nothing on ANY post-loop document failure (rejecting the retry outright instead of
  reporting a visible partial success) — deliberately left open rather than decided
  unilaterally, since it changes pre-existing API semantics beyond a late-Postgres-failure fix.
- `uninstall()`'s mirror-image gap — its metadata-delete transaction failing after sibling
  content has already been removed — is accepted as a store-scoped residual risk (documented in
  `product_pack_store.hpp` alongside the existing retry-self-heals mitigant, since no
  compensating action is possible once the content is gone) rather than closed, with a sharper,
  more specific operator-facing error log naming exactly how many sibling items were already
  removed. No behavior change.
