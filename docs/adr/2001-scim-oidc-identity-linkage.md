# ADR-2001 — SCIM ↔ OIDC identity linkage for deprovision (SOC 2 CC6.8)

**Status:** Accepted (rev 3, 2026-08-12 — D1/D2/D3 decided; see "Decisions" below)
**Authors:** Fraser Jarvis (@fjarvis)
**Date:** 2026-08-12
**Relates to:** ADR-0031 (`0031-engine-principal-store.md`), ADR-0017 (management-group confinement), ADR-0012 (PG store contract), the SCIM v2 provisioning surface, the OIDC stable-principal decision (#1837), and the #2021 SCIM role/provenance guard.

---

## Context

A user deprovisioned through SCIM (`active:false` / `DELETE`) or the dashboard keeps working **API tokens** — SOC 2 CC6.8 (termination) is unmet.

**Surface cause.** All six human-deprovision paths funnel through `AuthManager::remove_user`, which soft-deletes the auth row and wipes MFA but never calls `ApiTokenStore`. `revoke_for_principal(principal_id)` exists and is used correctly by the engine-principal `DELETE` and by `/me` — no user-deprovision path calls it.

**Root cause — two disjoint identities.** A SCIM-provisioned user and their OIDC login identity are **separate `auth.users` rows that are never linked**:

- SCIM provisions `username = <slug>`, `provisioning_source = 'scim'`, stores the IdP's stable id in indexed `scim_resources.external_id`. Stores **no email, no `iss`/`sub`**.
- OIDC login (`auth_routes.cpp:2438`) always mints `username = "oidc:" + iss + "#" + sub`, upserts that row with `external_iss`/`external_sub`, and **never adopts the slug**.
- Tokens mint on `principal_id = session->username`. SCIM users are **SSO-only**, so every token they hold is keyed on the **`oidc:` principal, not the slug**.

So `revoke_for_principal(resource.username)` at the SCIM seam reaches **zero** of a federated user's tokens while reporting success. Closing CC6.8 for the population SCIM governs requires linking the two identities.

### Hard constraints (verified against the code, rev-2)

1. **The `oidc:<iss>#<sub>` principal is the RBAC key and cannot be re-keyed.** `principal_roles`, group reconcile (#1832), JIT eligibility, and the audit trail key on it (`rbac_store.cpp:188-195`). "Adopt the slug at login" orphans every grant. **Rejected.**
2. **No join key exists in the data today.** `externalId` (SCIM) and `sub` (OIDC) are both stable/IdP-asserted but *not asserted equal*, and IdP-dependent: Okta typically `sub == externalId`; **Entra typically not** (`externalId` = AAD object id, which rides the token as the `oid` claim, **not** `sub`). Email↔email unavailable (SCIM stores none; OIDC `email_verified` not captured).
3. **Only IdP-asserted, stable claims may enter the trust path.** `sub` and `iss` are parsed and validated fail-closed today (`oidc_provider.cpp:331-419`: non-empty, ≤255, no control bytes — the #1837 hardening). **`oid` is NOT parsed or validated anywhere today** (no field on `IdTokenClaims`, no parser branch). Using it as the Entra join is therefore **new work delivered by this ADR** (§ Deliverables), not an existing toggle, and admitting a new claim to the trust path must replicate the `sub` validation exactly — else it becomes an audit-injection / malformed-key vector. `email`/`preferred_username`/`name` are mutable display fields — **forbidden as a join key** (a mutable join is an auth bypass).
4. **Provenance guard interaction (stated precisely).** The link + cross-identity deprovision are gated to `provisioning_source='scim'`, `role='user'` **on the slug**. Local-admin and break-glass accounts are genuinely unreachable (non-`scim` provenance ⇒ no `external_id` ⇒ no link forms). But the **linked `oidc:` principal's own role is not consulted and MAY be admin** — a federated identity elevated by standing grant or group→role. Revoking a federated admin's tokens on termination is the *intended* CC6.8 behavior and must be **audited as an admin revoke**; the earlier draft's "fires only for role=user" was false about the *target* of the revoke and is corrected here.
5. **Single-issuer precondition.** `ScimStore::find_by_external_id` is a global `WHERE external_id=$1` with **no issuer predicate**, and `scim_resources` carries no `iss`. Link formation is sound **only under a single trusted OIDC issuer** (Yuzu's current config). Any future multi-IdP OIDC MUST partition the externalId space by issuer (add `iss` to the SCIM resource or the match) before this design is safe. **Binding precondition, not prose.**

### The good news

`auth.users` already carries `external_iss`/`external_sub`/`provisioning_source`; `scim_resources.external_id` is indexed. What is missing is forming/recording the link and a policy for which claim forms it.

---

## Decision

A **durable, login-established, IdP-asserted-claim link** between a SCIM slug and the OIDC principal(s) that authenticate as that person, with deprovision acting across the link. Reconciliation idea unchanged from rev 1; the mechanics below are corrected per review.

### 1. Join key: configured, IdP-asserted claim, default `sub`, allow-list `{sub, oid}`
`--oidc-scim-link-claim` (default `sub`; boot **rejects** anything outside `{sub, oid}`). Okta: default. Entra: `oid` (which this ADR adds to the parser with `sub`-equivalent fail-closed validation). No shared id ⇒ no link forms ⇒ see D2.

### 2. Link recorded at login, from authenticated data only — fail-closed on ambiguity
**`scim_resources.external_id` is indexed but NOT unique today** (`scim_store.cpp:43,49`), and `find_by_external_id` takes `LIMIT 1` — so a duplicate externalId would let link-formation pick a row arbitrarily and **mis-link an OIDC identity to the wrong SCIM user, revoking the wrong principal** (codex-sol plan-review BLOCK, 2026-08-12). Two mandatory mitigations, belt-and-braces:
- **Link formation forms a link only when EXACTLY ONE active SCIM resource matches** the link-claim value. Zero matches → no link (normal). More than one → **no link**, never an arbitrary pick — `ScimStore::find_unique_active_by_external_id` folds both zero and more-than-one matches into `nullopt`. This is the load-bearing safety and works on existing data even before the index below lands.
- **Add a partial-unique index** on `external_id` where non-empty (the correct SCIM posture, shipped as `scim_resources_external_id_uniq` in migration v3). The migration **detects pre-existing duplicates and fails closed** (refuses to open, per the store's ADR-0012 posture) rather than silently skipping index creation — a store that opens with a violated uniqueness assumption is exactly the mis-link hazard.

**Amendment (2026-08-12, post-implementation): no separate "ambiguity signal" is wired, and this is correct, not a gap.** An earlier draft of this section additionally called for incrementing a dedicated `external_id`-ambiguity counter on the `find_unique_active_by_external_id` more-than-one-match branch, folding it into the D2 detector family. That branch is now **structurally unreachable in ordinary operation**: the partial-unique index makes a second active row sharing a non-empty `external_id` impossible to create in the first place (an `INSERT`/`UPDATE` that would produce one raises `unique_violation` and the write fails, surfaced through this store's existing db-failure return contract on `create_resource`/`update_resource` — an operator-visible failure at write time, not a silent success), and a database that somehow already violated the constraint before the index existed fails the **migration** at boot (see the "duplicate externalId now refuses to boot" upgrade note in `docs/user-manual/server-admin.md`) before any login-time ambiguity could ever be observed. The migration-time fail-closed boot refusal and the insert-time `unique_violation` are together a **strictly stronger** mitigation than a login-time signal would have been — they prevent the ambiguous state from ever existing, rather than detecting it after the fact — so the more-than-one-match branch in `find_unique_active_by_external_id` is retained purely as defense-in-depth (belt-and-braces against the index ever being bypassed, dropped, or absent on a downgrade) and deliberately does not emit its own metric. Do not add one under a future refactor without first checking whether the index is still in force; this note exists so that omission is never mistaken for an oversight. This resolves consistency-auditor finding C2.

On successful OIDC login whose link-claim value matches **exactly one** active SCIM `external_id`, record a durable link in a **dedicated `identity_links` table owned by `ScimStore`** (schema `scim_store`; born-on-PG per ADR-0012). Keyed `(iss, sub)` **unique**, with a **secondary index on `scim_id`** (deprovision looks up by `scim_id`, which the `(iss,sub)` key does not serve), carrying `linked_at`. The link write is **fail-OPEN** — a failed write never fails the login (the missing link is caught by the D2 detector). A dedicated table is mandatory, not a preference: the model is **many** `(iss,sub)` per `scim_id`, which a single `external_iss/sub` column pair on the slug row cannot represent (and those columns do not exist on `scim_resources`) — the column-overload alternative is **withdrawn as infeasible**.

### 3. Deprovision acts across the link, credentials-first, fail-closed, orchestrated ABOVE the stores
SCIM `active:false`/`DELETE` and dashboard delete resolve slug → `scim_id` → linked `(iss,sub)` → principal strings, and for **each** principal (slug + every linked `oidc:` id) revoke tokens (`revoke_for_principal`) and sessions **before** marking the account inactive. This **reorders** today's `deactivate()` (which does `remove_user` first) — safe, all ops idempotent, and it matches the engine-principal `DELETE` ordering. On any `revoke_for_principal → unexpected`, do not report clean success: SCIM `500` so the IdP retries; audit `partial`; metric `result=partial`; the did-not-persist-vs-zero-tokens distinction preserved per principal. **The deprovision orchestrator is credentials-FIRST and must NOT reuse `session_revoke_fn`** (`server.cpp:15346`), which is session-first and carries `caller=self|admin` semantics — a distinct helper over the per-principal `revoke_for_principal` + `invalidate_user_sessions` primitives (codex-sol plan-review, 2026-08-12).

**Lock/pool discipline (the real hazard, per architect):** the three stores share one bounded `pg_pool_`. The orchestration lives **above** the stores — it calls each store's public method in sequence and **never holds one store's pool lease while calling another** (a nested second lease from the same pool can exhaust/deadlock it, `api_token_store.hpp:257`). `AuthManager::mu_` stays a leaf, never held across a store/DB/bus call (unchanged house discipline). Acquisition order to hold: resolve links (ScimStore) → revoke tokens (ApiTokenStore) → revoke sessions (AuthManager) → mark inactive (AuthManager) → SCIM mirror (ScimStore), each self-contained.

### 4. Deny-at-login backstop (own PR — see Delivery)
An OIDC login whose linked SCIM resource is deprovisioned is **denied** — fail-CLOSED — emitting the **identical `?error=sso_failed` redirect** as the existing token-exchange-failure branch (`auth_routes.cpp:2422`), with a server-side `auth.oidc.deprovisioned_denied` audit. This closes the re-login-mints-fresh-tokens window that eager revoke alone leaves. Architecturally decoupled from §3 (different site, opposite failure direction) → separate PR.

### 5. Single shared principal-string helper (mandatory)
The `oidc:<iss>#<sub>` string is hand-built at two sites today; the resolver would be a third. A drift in the format silently misses every token — the exact "reported success, revoked nothing" failure. **Require one `oidc_principal_id(iss,sub)` helper**; the resolver returns raw `(iss,sub)` rows and this helper builds every principal string. Do **not** widen `session_revoke_fn` (it carries `caller=self|admin` metric semantics) — add a resolver over the existing per-principal revoke primitive.

---

## Decisions (accepted 2026-08-12, @fjarvis)

- **D1 → preserve #2021 for the slug's account state, do NOT auto-revoke a manually-elevated federated admin on the IdP's say-so, and make the refusal LOUD** — a `kCritical` audit + `yuzu_scim_deprovision_role_refused_with_active_link_total`. The silent hole becomes a paged alert a human resolves; #2021's IdP-compromise protection is preserved. (Horn (b) below.)
- **D2 → record every OIDC login's attempted link-claim value** (a durable `(iss, sub, claim_name, claim_value)` observation, written regardless of match) so a deprovision can surface a should-have-matched candidate under a mis-configured `--oidc-scim-link-claim`. (Horn (a) below.)
- **D3 → PR1+PR2 ship together, PR3 (deny-at-login) separate.** Token-revoke seam + full linkage as one PR (CC6.8 cell moves only when linkage lands); the fail-closed login-path change isolated in its own PR.

The full analysis of each fork is retained below for the build team.

## The forks, analysed (D1/D2 decided above)

**D1 — the #2021 provenance fork (security F1, HIGH).** When a SCIM slug was elevated to admin *outside* SCIM and the IdP sends a deprovision, `deprovision_role_ok` 404s to protect that admin from a racing/compromised IdP (#2021). Post-linkage this silently leaves the terminated person's *federated* tokens live and never arms deny-at-login. Two horns:
  - **(a) Auto-revoke the linked federated identity anyway** — termination-complete, but reopens what #2021 defends (a compromised IdP can kill an admin's access via SCIM).
  - **(b) [recommended default] Preserve #2021 for the slug's account state, do NOT auto-revoke the federated admin on the IdP's say-so, but make it LOUD** — a `kCritical` audit + `yuzu_scim_deprovision_role_refused_with_active_link_total` so a human resolves the termination deliberately. This closes the *silent* half of F1 (the hole becomes a paged alert, not an invisible gap) without letting an IdP unilaterally revoke an admin. The residual (a genuine termination of a manually-elevated federated admin needs one manual step) is acceptable and auditable.

**D2 — the fail-loud detector (security F2, HIGH).** The rev-1 fail-loud predicate is unrealizable — the slug and `oidc:` rows are disjoint, so "logged in but link never formed" is indistinguishable from "never logged in," and that is exactly the Entra/mismatch silent-under-revocation case. To make it detectable requires capturing new data. Options:
  - **(a) [recommended] Record every OIDC login's *attempted* link-claim value** (a row per `(iss, sub, claim_value_seen, claim_name)` regardless of match). A deprovision of externalId `E` can then ask "did any login present a candidate that should have matched `E` under a different configured claim?" → a real, actionable "your `--oidc-scim-link-claim` is wrong for this IdP" signal. Cost: one more durable table + a login-time write.
  - **(b) Capture `email`/`email_verified` on both sides** as a fallback correlator. Larger SCIM-schema change; weaker (email is mutable).
  - **(c) Accept a weaker CC6.8 claim** for mismatched-IdP deployments and state the limitation, no detector. Cheapest, least honest.
  Without one of these, the CC6.8 completeness claim for the federated population is unproven — which is the reason this went ADR-first.

---

## Consequences

- **CC6.8 residual, stated honestly:** after deprovision, a previously-issued API token may keep validating for up to **~60s** (the `ApiTokenStore` validate-cache TTL, `api_token_store.hpp:787`; MCP stream sessions carry the same), plus the irreducible IdP→SCIM lag before deprovision fires. Cookie sessions are erased immediately. Deny-at-login (§4) closes re-login mint. The guarantee is "revoked within ~60s of the deprovision reaching Yuzu, and no new access thereafter," not "instant."
- **Deliverables (new work this ADR authorizes):** `oid` claim parse + `sub`-equivalent validation; `identity_links` table (ScimStore, `(iss,sub)` unique + `scim_id` index, no-prune-by-decision — orphan links from a claim-config change accumulate but only ever cause safe over-revoke); `--oidc-scim-link-claim` flag; the shared `oidc_principal_id` helper; a principal-set resolver; the deprovision reorder; new audit verbs + metrics; plus whichever D1/D2 options are chosen.
- **INV-31-3 not crossed:** `identity_links` has one owning store (ScimStore), method-mediated — a future engine/core split stays clean.
- **Delivery (architect recommendation, reconciled with the "A+B together" intent):** three reviewable PRs — **PR1** per-principal revoke at the deprovision seams (`{slug}` only, forward-compatible set-resolver); **PR2** linkage (`oid`, `identity_links`, resolver, D2 detector); **PR3** deny-at-login (D1 handling + §4). The CC6.8 compliance cell may only be updated to "complete for federated users" **after PR2** — PR1 alone must not touch it, or it overstates. If you want a single PR per your earlier call, PR1+PR2 can merge together; PR3 (login-path, fail-closed) is best kept separate for blast-radius.

### Known residuals

- **The ~60s validate-cache window** (see Consequences above) — stated honestly, not treated as fixed by this ADR.
- **A manually-elevated federated admin's tokens are not auto-revoked (D1)** — by design, a human step; see D1 above.
- **Login-mid-deprovision TOCTOU, open until PR3.** PR1+PR2 (shipped) close the *deprovision-time* revoke gap; they do not close a race between an OIDC login's principal-set resolution and a concurrent deactivation of the same slug. Concretely: a login that authenticates and forms/refreshes an `identity_links` row for `(iss, sub)` **between** a deprovision's `resolve_deprovision_principals` read and its `set_active(..., false)`/delete write can mint a fresh session and API/MCP tokens for that identity that the in-flight deprovision pass never saw and therefore never revoked — a freshly-linked (or freshly re-authenticated) principal can walk away with live credentials from a termination that, from the operator's point of view, just completed successfully. This is exactly the gap §4 (deny-at-login, PR3, not yet shipped) closes: once a login is refused for a deprovisioned linked SCIM slug, the race has nothing left to win — the login itself fails before any new credential is minted. Until PR3 ships, this is a genuine, acknowledged residual, not a theoretical one: **do not describe CC6.8 as fully closed for the federated population without naming this window.** Operationally it is bounded by ordinary IdP-to-Yuzu SCIM propagation latency (typically seconds to low minutes, IdP-dependent), not unbounded.

## Review provenance
Rev 2 folds: architect B1 (`oid` unbuilt) + B2 (overload infeasible) + lease-nesting/reorder/resolver/index/helper notes; security-guardian F1 (D1), F2 (D2), F3 (single-issuer precondition, constraint 5), F4 (`oid`, constraint 3), F5 (constraint 4 wording), F6 (60s residual), F7 (generic deny redirect). Both reviews called the core reconciliation idea sound; the defects were in the provenance interaction and the fail-loud realizability, now surfaced as D1/D2.
