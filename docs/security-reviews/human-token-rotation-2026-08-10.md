# Security review — Human API-token rotation (SOC 2 CC6.3)

| Field | Value |
|---|---|
| Date | 2026-08-10 |
| Scope | Self-service overlap-pair rotation for human-owned API tokens — `ApiTokenStore::rotate_token`/`confirm_token_rotation` (store core), kind-discriminated telemetry, `POST /api/v1/tokens/{id}/rotate`/`.../confirm` (REST), and a 33-case adversarial regression suite |
| Control | SOC 2 **CC6.3** (authentication/credential lifecycle) — closes the human-token half of `/auth-and-authz` gap-matrix **P2 #11** (the engine-credential half shipped earlier as part of the `engine` principal ladder) |
| Driver | `/auth-and-authz` gap matrix P2 #11 |
| Branch | `feat/auth-human-token-rotation`, integration commit `e1bf2d86` |
| Reviewer | Multiple review rounds across store-core, REST, and telemetry sub-branches (round numbers below), including plan-review before implementation, two ownership/architecture specialists, and an independent architect adjudication on the confirm-error taxonomy. A fifth piece — MCP tool twins — is **still in review, not in this branch**, and is covered separately below. |
| Status | Store core + REST + telemetry: implemented, adversarial-regression-suite green (33 `[human]` cases). MCP twins: in review, not merged. |

## Purpose

Records the evidence chain for adding self-service credential rotation to
human-owned API tokens — mint a successor while the existing (predecessor)
token stays valid for a bounded overlap window, then an explicit
maker-checker confirm that revokes the predecessor and closes the rotation.
Engine-credential rotation shipped earlier (`rotate_engine_credential`/
`confirm_rotation`, `docs/auth-architecture.md` "Overlap-pair credential
rotation") on a **principal-keyed** state machine. This is the human twin, on
a deliberately different, **token-keyed** state machine — see the design
decision below for why the two cannot share one invariant.

## Control surface

| Element | Location |
|---|---|
| Store core (`rotate_token`/`confirm_token_rotation`) | `server/core/src/api_token_store.{hpp,cpp}` |
| Group-scoped confirm-state classifier | `server/core/src/rotation_confirm_state.hpp` (`classify_confirm_state_in_group`) |
| Shared REST/MCP error classifier | `server/core/src/engine_store_error_class.hpp` |
| Shared successor-lookup seam | `server/core/src/token_rotation_lookup.hpp` (`derive_rotation_successor`) |
| Kind-discriminated telemetry naming | `server/core/src/rotation_sweep_naming.hpp` |
| REST routes | `server/core/src/rest_api_v1.cpp` (`POST /api/v1/tokens/{id}/rotate`, `.../confirm`) |
| T12 maintenance sweep (shared engine+human) | `server/core/src/server.cpp` (`engine_rotation_sweep_thread_`) |
| Tests | `tests/unit/server/test_api_token_store.cpp` (33 `[human]`-tagged cases) |
| Docs | `docs/auth-architecture.md` "Human API-token rotation" (this feature's design record), `docs/user-manual/rest-api.md` "API Tokens" (REST reference), `docs/user-manual/authentication.md` "Rotating a Token" (user-manual walkthrough), `docs/user-manual/metrics.md`, `docs/observability-conventions.md`, `docs/user-manual/audit-log.md` |

## Design decisions with security rationale

- **Token-keyed, not principal-keyed (caught at plan review, before code
  existed).** The engine arm's ≤2-active-credential ceiling is enforced
  **per principal** — correct because an engine principal has exactly one
  credential. A human routinely holds several unrelated concurrent tokens, so
  a principal-keyed ceiling on the human arm would block rotating any one
  token the moment its owner held a third, unrelated one. `rotate_token`/
  `confirm_token_rotation` key on the token being rotated and enforce the
  ≤2 ceiling **per `rotation_group`** instead — a human's other tokens never
  count against it. The advisory lock stays `hashtext(principal_id)` (same
  key as the engine arm and the T12 sweep), so activity for a shared
  principal still serializes across both arms.
- **The identical invariant gap recurred one layer up, in the REST route,
  and was caught a second time (round 3).** The route's successor lookup —
  needed to return the freshly-minted token's `token_id`/`expires_at` — was
  copied from the engine rotate route's inline loop ("the active row whose
  `supersedes_token_id` is set"), sound there only because that route's own
  store arm enforces the per-principal ≤2 ceiling and so at most one linked
  row can exist. On the human arm, with several independent in-flight
  rotations possible per principal, the copied loop matched the *first*
  linked row, not necessarily the one belonging to the predecessor actually
  rotated. **Two independent reproductions against live Postgres, plus an
  architectural ruling that the fix belonged at a shared seam rather than
  inline.** The reproduction: rotating token A then token B (same owner)
  inside A's overlap window returned B's raw secret paired with A's
  successor `token_id` — confirming that id would have revoked A while B,
  the token whose secret the caller actually held, stayed live and
  unconfirmed. Fixed (`c1325015`) by extracting the derivation into one
  shared, DB-free, unit-testable seam — `derive_rotation_successor`
  (`token_rotation_lookup.hpp`) — so the REST route today and the MCP twin
  landing separately both call the same function. A second inline copy of
  this loop is exactly the drift that produced the bug the first time; see
  the header's own doc comment for the full reproduction writeup. The seam
  extraction is itself the evidence the architectural ruling was acted on —
  an inline fix on the REST route would have been the cheaper change and was
  explicitly rejected in favour of the shared seam.
  **Attribution note:** `c1325015`'s own commit message is the only
  artifact this record can cite for "two specialists" plus "per the
  coordinator's correction" — no `governance.d/` ledger fragment exists for
  this work, and an independence claim in a compliance record should not
  rest on a recollection routed through the party being reviewed (the
  coordinator, here). If per-round/per-reviewer attribution is needed for
  audit purposes, cite it from a governance ledger fragment once one is
  produced for this work, not from this paragraph or from memory.
- **Ownership is enforced at the store seam, not merely at the route.**
  `rotate_token`/`confirm_token_rotation` reject unless `requesting_user`
  equals the resolved token row's own `principal_id` — checked in a
  pre-transaction lookup and again, authoritatively, on the fresh re-read
  taken under the advisory lock. The route-level ownership check that runs
  first is defense-in-depth on top of this, never a substitute for it. This
  is a deliberate asymmetry with the engine arm (whose caller is a
  third-party admin by design): a human token's raw successor secret
  authenticates *as that user*, so an admin re-serving or confirming
  another user's rotation would be handed (or would complete the cutover
  of) a credential impersonating someone else — identity takeover, not a
  permission gap an admin override could legitimately cross. There is no
  rotate-as-admin path; an admin acting on another user's token has
  `revoke_token`/`revoke_for_principal` instead.
- **"Self-service" is qualified, not absolute — under RBAC-on this composes
  to effectively admin-only, and that is true of the shipped surface, not a
  future caveat.** REST rotate/confirm gate on `ApiToken:Write`. Verified
  against this branch's RBAC seed data (`rbac_store.cpp`): `ApiToken:Write`
  is granted only to `Administrator` (full-CRUD loop) and `ApiTokenManager`
  (explicit grant); `Operator`, `PlatformEngineer`, `Viewer` (read-only), and
  `ITServiceOwner` (explicitly excluded, per its own seeding comment) do not
  hold it. Composed with the store-seam ownership requirement above (no
  admin override, ever): an `Operator`- or `Viewer`-role user who **owns** a
  token has no RBAC-on path to rotate it themselves, and no admin can do it
  for them either — the token cannot be rotated by anyone until its owner is
  separately granted `ApiToken:Write`. This is **pre-existing and unchanged
  by this work** — `POST /api/v1/tokens` is already gated the same way;
  `DELETE /api/v1/tokens/{id}` is gated on the sibling `ApiToken:Delete`
  operation (`rest_api_v1.cpp:2624`), not `Write` — but the RBAC seed data
  grants both operations to the same two roles (`Administrator`,
  `ApiTokenManager`) and to no others, so the admin-only conclusion holds
  identically for delete. Recorded here because every "self-service" claim
  elsewhere in this record means *self-service subject to holding the
  relevant `ApiToken:*` grant*, not *available to any authenticated owner*.
- **A wrong-owner rejection is indistinguishable from a nonexistent token —
  the surface is not an enumeration oracle.** Both the store-level rejection
  and the REST route's own 404 use identical wording/status for "this token
  doesn't exist" and "this token exists but isn't yours"
  (`"no such token to rotate"` / `"no such token to confirm"` at the store;
  `404 token not found` at REST, mirroring the existing `DELETE
  /api/v1/tokens/{id}` route's posture). A denied attempt is still fully
  audited server-side (`result=denied`, `detail=owner=<real owner>`) —
  the ambiguity is client-facing only.
- **Lifetime-neutral by deliberate choice.** The successor's absolute
  `expires_at` always inherits the predecessor's verbatim — never
  recomputed as `now + 90d`, which would silently extend authorization
  lifetime through what should be a lateral credential swap. The store-level
  function retains an internal `successor_expires_at` override parameter
  (shared plumbing with the engine arm's own successor-TTL logic), but the
  REST route deliberately does not expose it as a request field — a
  senior-architecture ruling that rotation must read as lifetime-neutral in
  CC6.3 evidence, with no caller-controlled path to extend a grant through
  what should be a lateral swap. A caller needing a longer-lived replacement
  mints a fresh token via `POST /api/v1/tokens`, a distinct,
  separately-audited action.
- **Confirm error taxonomy was explicitly adjudicated, and an earlier
  reading was wrong in the dangerous direction (round 5).** The group-scoped
  classifier (`classify_confirm_state_in_group`) distinguishes a POSITIVE
  fact — `kGroupEmpty`: the principal-wide active read succeeded and
  returned rows, but none carry the pinned `rotation_group`, i.e. the
  rotation has already resolved — from a genuinely AMBIGUOUS one —
  `kAmbiguousEmpty`: the principal-wide read came back empty, indistinguishable
  from a swallowed `SELECT` failure. Round 4 shipped `kGroupEmpty` as
  `Transient` (REST `503`, retryable). Independent architect adjudication,
  escalated after that classification was flagged as doubtful, corrected it
  to `Conflict` (REST `409` / MCP `kInvalidParams`, terminal) before merge,
  on three independent grounds: (1) `#2404` precedent — the engine arm was
  once `503`-retryable for the same shape of state and made an
  idempotent-hint-honouring agentic client retry a permanently-failing call
  forever; `Transient` on `kGroupEmpty` reintroduces that exact defect on
  the human arm; (2) arm parity — the engine arm's `kSoleOtherToken` state
  carries the identical "rotate again if needed" guidance and classifies
  `Conflict`, and telling a client to take a *different* action (call
  rotate, not retry confirm) is the definition of `409`, not `503`; (3) the
  classifier's own file-level contract ("every terminal state → Conflict or
  ClientValidation") — `kGroupEmpty` is documented as a positive fact, not
  ambiguous. `kAmbiguousEmpty` stays `Transient`, unchanged, for the
  symmetric reason: it genuinely cannot be told apart from a swallowed read
  failure, so retry is the correct client behaviour.

## Review-round chronology (what each round found, briefly)

Skimmable index into the branch's own commit history — full detail is in
each commit message, not repeated here:

- **Round 2** (`a5e0f8fa`) — non-ASCII hyphen in new `describe()` help
  strings; cosmetic, fixed.
- **Round 3** (`c1325015`) — the successor-lookup scoping defect above;
  BLOCKING, fixed, extracted to `token_rotation_lookup.hpp`.
- **Round 4** (`6899aae8`) — two defects: a grace-cache entry could leak
  (never evictable) if a Postgres `COMMIT` failed *after* the transaction
  callback itself returned success (a narrow but real TOCTOU in
  `PgPool::run_in_txn`'s contract), fixed with an RAII `ScopeExit`-style
  guard covering every exit path; and two new confirm-error strings had
  silently inherited the engine arm's `kSoleOtherToken` classification via
  substring collision in `engine_store_error_class.hpp`, giving a
  never-rotated token's confirm attempt a `409` whose own text said "retry"
  — given distinct wording and an explicit classifier entry.
- **Round 5** (`7332ae52`) — the `kGroupEmpty` Transient→Conflict
  correction above.
- **Round 6** (`a960e8b1`) — ownership-specialist review of rounds 4–5
  found the fix shape sound but flagged one BLOCKING gap (a new regression
  test armed its test hook by bare assignment instead of the RAII pattern
  this repo requires for test hooks, generalised into a reusable
  `ScopedPgConnHook`) and three follow-ups (an unconditional-on-all-paths
  secret scrub that had excluded the commit-failure path; a `std::function`
  closure exceeding libstdc++'s small-object buffer, replaced with an
  allocation-free template `ScopeExit`; a defensive `try_acquire_for` +
  `REQUIRE` in place of a bare pool re-entry that was safe only by
  configuration accident). A second, independent pass in the same round
  found the round-5 doc comment had overclaimed ("every terminal state →
  Conflict, no ClientValidation exists here" — false; `kOverfullGroup` is
  ClientValidation, and the file's own tests assert it) and corrected it.
- **Post-merge integration** (`035099e8`, `c1325015` continuation,
  `1fca6352`, `7caa1134`) — two of the 33 `[human]` test cases had their
  asserted contract corrected against the merged shape; `token_rotation_lookup.hpp`
  was made fully DB-free (the derivation takes a plain `std::vector<ApiToken>`,
  not a store handle, so it is unit-testable without live Postgres) and its
  post-confirm contract stated explicitly (see "Design decisions" above and
  the header's own extensive doc comment).

## Privilege-escalation finding — caught in review, not shipped

During review of the (separate, still-in-review) MCP tool twins, a proposed
`operator`-tier MCP allowance on the `ApiToken:Write` securable was found to
be directly exploitable — not via a downstream hop through rotate/confirm.
`ApiToken:Write` is the gate on `POST /api/v1/tokens` (mint, `rest_api_v1.cpp`)
**and** its settings twin `POST /api/settings/api-tokens`
(`settings_routes.cpp`), and **both accept a caller-chosen `mcp_tier`**
(including empty/untiered). An `operator`-tier token minting a token with no
`mcp_tier` set produces a credential that then skips `tier_allows` entirely
on every later call (an empty `mcp_tier` is the untiered/interactive case).
So the proposed allowance would have let an `operator`-tier token directly
mint itself an untiered, unconfined credential — a **first-order**
consequence of the one-line change, present the moment the allowance
existed, with no rotate/confirm call required. `#2945` below is the
**pre-existing** instance of this identical escape at the `supervised` tier;
the proposed allowance would have extended it to `operator`.

A first attempted fix scoped the allowance narrowly to the rotate/confirm
MCP *tools themselves* and was found structurally unreachable — RBAC
evaluates on the shared REST/MCP `(securable, operation)` pair, not
per-tool, so a tool-scoped carve-out cannot exist without duplicating the
permission model. The adjudicated remedy is a **new, narrower RBAC
operation — `ApiToken:Rotate`** — separate from `ApiToken:Write`, so the
MCP allowance (once it lands) can be granted without also widening
`POST /api/v1/tokens`(-equivalent) mint access to every `ApiToken:Write`
holder. **The remedy is not REST-scope-neutral: it also re-gates this
branch's own `POST /api/v1/tokens/{id}/rotate`/`.../confirm` routes from
`ApiToken:Write` onto the new `ApiToken:Rotate`, for parity across
transports.** Neither the operator-tier MCP allowance, the `ApiToken:Rotate`
operation, nor the REST re-gating is present in this branch — the finding
and its full remedy belong to the MCP-twins piece, which has not merged;
this record exists so the whole decision — including the REST-side
re-gating — is not re-litigated or silently dropped when that piece lands.

**Detection mechanism — corrected. The 920-cell sweep verified the remedy;
it did not detect the defect.** 920 = 5 tiers × 23 securables × **8**
operations — but this branch's own RBAC operation set
(`rbac_store.cpp`'s `ops[]`) has **7** (`Read`, `Write`, `Execute`,
`Delete`, `Approve`, `Push`, `Attest`); the eighth, `Rotate`, exists only on
the remedy commit. The sweep therefore necessarily ran against the
**post-fix** operation vocabulary. A before/after sweep of the *vulnerable
proposal* (the one-line `operator`-tier allowance on `ApiToken:Write`,
against the 7-operation pre-fix vocabulary) changes exactly **one** cell —
which is evidence the change *was* narrow, not evidence it was safe: the
defect's severity comes from what else is gated on that one cell
(`ApiToken:Write`), not from the cell count changing. The defect was
instead found by **enumerating the call sites that consult the
`(ApiToken, Write)` pair** — exactly **four**: `POST /api/v1/tokens`, `POST
/api/settings/api-tokens`, and the REST rotate/confirm routes — and
recognising that the proposed allowance widened all four at once, not just
the two rotate/confirm MCP tools it was written for.

The suite claim is narrower than first stated: `tests/unit/server/test_auth_routes.cpp`
does exercise the REST-path tier predicate (`require_permission`/
`require_scoped_permission`) — ten call sites across its `[mcp]`-tagged
cases, against the `Execution`, `Infrastructure`, `Security`, and `Tag`
securables (verified by grep; none against `ApiToken`). The defensible
statement: **no test exercised the tier predicate for the `ApiToken`
securable specifically on the REST transport, and there is no
per-`(securable, operation)` REST tier coverage matrix** — so this class of
defect had a real, specific blind spot, not a suite that never tests
tiering at all.

The durable lesson: **a one-cell change to a shared permission predicate
inherits the union of every route consulting that `(securable, operation)`
pair — enumerate the call graph behind the chokepoint, not the grid of
possible values the predicate can take.** The vulnerable proposal itself
moved exactly **one** cell (the `operator`-tier allowance on
`ApiToken:Write`); the remedy's own delta is **two** (splitting the gate
into `ApiToken:Write` and the new `ApiToken:Rotate`). A one-cell delta is
precisely why a grid sweep could not have found this: the grid a sweep
compares before/after is a snapshot of the predicate's OUTPUT (which values
it returns per input), and a single narrow cell changing looks identical
whether that cell is inert or, as here, the single most consequential grant
in the table — severity lives in what else consults that cell, information
the grid does not encode at all. A grid sweep is the right tool for
verifying a remedy's blast radius *after* the operation vocabulary is
final (it correctly proved the two-cell remedy's narrowness above); it is
the wrong tool for finding a defect in a proposal that hasn't shipped its
own new operation yet, because the grid it would sweep doesn't exist yet
either.

## Open risks (pre-existing, surfaced by this work)

Three issues were opened while building this feature. None is a defect *in*
this feature's own new rotate/confirm code, but `#2945` shares this record's
central chokepoint (`ApiToken:Write`) and the shipped-default (RBAC-off)
configuration, so it is recorded here as a live open risk, not a footnote.
Owner: **unassigned** for all three — filed, not yet triaged to an owner.

- **`#2943`** (Owner: unassigned) — `confirm_rotation` (engine arm) **and**
  `confirm_token_rotation` (human arm, this feature) share a structural
  fallthrough after their respective "exactly one pair matched" case:
  when the matched rows' linkage doesn't resolve to a clean
  predecessor/successor pair, both reuse the ambiguous-empty
  `"no in-flight rotation to confirm"` string — classified `Transient` for a
  state reached only after a *positive*, non-empty read. Same defect class
  as `#2404` and the round-5 `kGroupEmpty` correction above, in the same
  direction; not fixed by this branch — the human arm inherits it because
  both arms share the fallthrough shape, and the fix (a dedicated terminal
  string classified `Conflict`) is scoped to touch both arms together.
- **`#2944`** (Owner: unassigned) — the **engine** rotate response's
  `overlap_expires_at` is read off the successor row at both the engine
  REST and MCP call sites; the store never stamps that column on a
  successor (only the predecessor UPDATE sets it), so it reports a
  structural `0`. Surfaced while building this feature's
  `token_rotation_lookup.hpp`, whose `RotationSuccessorInfo::
  predecessor_overlap_expires_at` sources the field from the predecessor row
  precisely to avoid this — the human REST route (this feature) does
  **not** have this defect. The engine call sites are unmigrated and
  tracked separately.
- **`#2945`** (Owner: unassigned; **security-labelled, open**) — a
  `supervised`-tier API/MCP token can mint itself a tier-less, perpetual
  token via `POST /api/v1/tokens` (and its settings twin `POST
  /api/settings/api-tokens`), escaping its own tier confinement — the same
  chokepoint (`ApiToken:Write`) and the same first-order minting mechanism
  the "Privilege-escalation finding" above traces in detail for the
  `operator`-tier proposal that was caught before shipping. **Compensating
  control: none identified.** Traced `auth_routes.cpp`'s tiered-token
  fall-through: after `tier_allows` passes, the request still needs to
  clear either the RBAC-on `check_permission(username, ApiToken, Write)`
  check or the RBAC-off legacy-floor `effective_role == admin` check — but
  in every reachable path, the principal who can exploit this already holds
  `ApiToken:Write` outright (`Administrator`/`ApiTokenManager` under
  RBAC-on, or a legacy `admin`-role account under RBAC-off — legacy `Role`
  is binary `{user, admin}`, `auth.hpp:29`), which is the SAME grant needed
  to mint the narrowed token in the first place. So enabling RBAC changes
  *which* mechanism gates the fall-through but does not remove the
  exploit's precondition — a Write-privileged principal can de-confine
  their own deliberately-narrowed token under either configuration. This is
  a confinement-escape (an already-privileged principal defeating their own
  blast-radius reduction), not a vertical low-to-high privilege escalation
  — but it is real, open, and shares this feature's chokepoint. Surfaced
  while reviewing the proposed `operator`-tier MCP allowance above, whose
  extension of the same class of gap to `operator` tokens was caught and
  not shipped.

## Threats considered

- **Ownership bypass / cross-user rotation.** No path: enforced at the store
  seam on both the pre-lock lookup and the authoritative locked re-read;
  no admin override exists.
- **Enumeration of another user's token via the rotate/confirm 404.**
  Closed — identical wording/status for absent and not-owned.
- **Grant-lifetime extension disguised as rotation.** Closed —
  `expires_at` inheritance is unconditional at the REST surface; no request
  field can override it.
- **Retry-forever on a permanently-failing confirm.** Closed for
  `kGroupEmpty` (round 5); the sibling `#2943` fallthrough is a known,
  filed, not-yet-fixed instance of the same class — see above.
- **Raw-secret/`token_id` mismatch across concurrent rotations for one
  user.** Closed (round 3) via `derive_rotation_successor`'s exact-predecessor
  scoping.
- **Grace-cache leak on a Postgres commit failure.** Closed (round 4) via
  the RAII `ScopeExit` guard.
- **Cross-transport privilege widening via a shared securable.** Caught
  before any code shipped (MCP-twins review); remedy decided (including a
  REST-side re-gate), not yet implemented — see "Privilege-escalation
  finding" above.
- **Tiered-token self-de-confinement via `ApiToken:Write` minting (`#2945`).**
  OPEN, no compensating control identified, pre-existing (not introduced or
  fixed by this feature) — see "Open risks" above.

## Validation

- Unit: `tests/unit/server/test_api_token_store.cpp` `[human]` — 33 cases
  added by the adversarial regression suite (`67c585c9`, written against
  the pinned `rotate_token`/`confirm_token_rotation` signatures **before**
  the implementation landed, so the suite judges the implementation
  independently). Coverage: group- vs principal-scoped ceiling (the core
  regression this feature exists to prevent), Hermes F1/F2 concurrency and
  atomic pair-commit twins, `sweep_expired_rotations` +
  `list_rotations_nearing_expiry_unused` kind-discrimination, successor TTL
  inheritance, `#2384`-style pin-mismatch (same- and cross-lineage), confirm
  terminal-vs-retryable state discrimination, store-level self-service
  ownership binding, absence of a token-enumeration oracle, the
  group-scoped >2-active defensive reject, and a
  `classify_engine_store_error` round-trip. Two cases had their asserted
  contract corrected post-merge (`035099e8`) against the final shape.
- **Directly verified, 2026-08-10** (not sourced from
  `~/.local/share/yuzu/test-runs.db` — this was an ad hoc binary invocation,
  not a `/test`-skill run, so it has no ledger entry there): built
  `tests-build-server-linux_x64/yuzu_server_tests` from this branch (`e1bf2d86`
  plus this record's own doc-only commits on top) and ran against live
  Postgres (`localhost:5433`, `YUZU_TEST_ENABLE_PG=1`). `"[human]"` →
  **33 test cases, 404 assertions, all passed**. `"[token]"` (broader
  API-token sanity check) → **161 test cases, 1804 assertions, all passed**.
  Reproducible via `./tests-build-server-linux_x64/yuzu_server_tests
  "[human]"` with `YUZU_TEST_POSTGRES_DSN` set.

## Reviewer

Multi-round review across the store-core, telemetry, and REST sub-branches
(rounds 2–6 above), plan-review before implementation (token-keyed vs
principal-keyed), two ownership/architecture specialists (round 6), and an
independent architect adjudication (round 5, confirm-error taxonomy). MCP
tool twins are reviewed separately and remain in progress.
