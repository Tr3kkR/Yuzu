- **`ProductPackStore::install()` no longer silently orphans sibling-store content on a late
  failure.** Any failure reached after `install_fn` has already committed one or more documents
  into `InstructionStore`/`PolicyStore`/`WorkflowEngine` — the final Postgres persist transaction
  failing, or the duplicate-item-id validation check — now best-effort compensates (undoes) every
  already-installed item, in reverse install order, via the same per-kind delete dispatch
  `DELETE /api/product-packs/{id}` already used (now shared through one helper so the two paths
  can't drift). **Known gap, not closed by this change:** compensation is best-effort — a sibling
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
  (unrelated to this PR) per-document error tolerance means the pack still reports `201`
  installed with no per-item error surfaced to the caller, and any other document that
  cross-references the failed one by id (e.g. a `Policy`'s `spec.fragment`) silently resolves
  against the STALE residual rather than a freshly tracked copy — the resulting pack can end up
  depending on content that isn't listed among its own items, invisible to that pack's own
  future uninstall. The compensation metric surfaces the originating partial-compensation event
  for operator cleanup but does not itself prevent either outcome; closing the second one is an
  open design question (surface per-item install errors in the response, or make the whole
  install all-or-nothing on ANY post-loop document failure) intentionally left open by this PR
  rather than decided unilaterally.
- `uninstall()`'s mirror-image gap — its metadata-delete transaction failing after sibling
  content has already been removed — is accepted as a store-scoped residual risk (documented in
  `product_pack_store.hpp` alongside the existing retry-self-heals mitigant, since no
  compensating action is possible once the content is gone) rather than closed, with a sharper,
  more specific operator-facing error log naming exactly how many sibling items were already
  removed. No behavior change.
