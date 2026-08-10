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
| Docs | `docs/auth-architecture.md` "Human API-token rotation" (this feature's design record), `docs/user-manual/rest-api.md` "API Tokens", `docs/user-manual/metrics.md`, `docs/observability-conventions.md`, `docs/user-manual/audit-log.md` |

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
  rotated. **Two specialists independently reproduced this end-to-end
  against live Postgres**: rotating token A then token B (same owner) inside
  A's overlap window returned B's raw secret paired with A's successor
  `token_id` — confirming that id would have revoked A while B, the token
  whose secret the caller actually held, stayed live and unconfirmed. Fixed
  (`c1325015`) by extracting the derivation into one shared, DB-free,
  unit-testable seam — `derive_rotation_successor`
  (`token_rotation_lookup.hpp`) — so the REST route today and the MCP twin
  landing separately both call the same function. A second inline copy of
  this loop is exactly the drift that produced the bug the first time; see
  the header's own doc comment for the full reproduction writeup.
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
be exploitable: because REST's `POST /api/v1/tokens/{id}/rotate` and
`.../confirm` gate on the same `ApiToken:Write` permission MCP tooling would
have shared, an `operator`-tier token would have been able to reach the
rotate/confirm surface via REST — and, per the pre-existing chain `#2945`
below, use adjacent token-minting behaviour to escape its own tier
confinement. A first attempted fix scoped the allowance narrowly to the
rotate/confirm MCP *tools themselves* and was found structurally
unreachable — RBAC evaluates on the shared REST/MCP `(securable, operation)`
pair, not per-tool, so a tool-scoped carve-out cannot exist without
duplicating the permission model. The adjudicated remedy is a **new,
narrower RBAC operation — `ApiToken:Rotate`** — separate from
`ApiToken:Write`, so the MCP allowance (once it lands) can be granted
without also widening REST rotate/confirm access to every `ApiToken:Write`
holder. **Neither the operator-tier allowance nor the `ApiToken:Rotate`
operation is present in this branch** — the finding and its remedy belong to
the MCP-twins piece, which has not merged; this record exists so the
decision is not re-litigated or silently re-broken when that piece lands.
The REST routes documented above gate on the existing `ApiToken:Write`
only, as designed for a self-service human surface, and are not implicated
by this finding.

## Follow-up issues filed (pre-existing, surfaced by this work)

Three issues were opened for defects found while building this feature, none
of which are defects *in* this feature's own new code (the human arm's
rotate/confirm surface does not reproduce #2944, and #2945 is unrelated to
rotation):

- **`#2943`** — `confirm_rotation` (engine arm) **and**
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
- **`#2944`** — the **engine** rotate response's `overlap_expires_at` is
  read off the successor row at both the engine REST and MCP call sites;
  the store never stamps that column on a successor (only the predecessor
  UPDATE sets it), so it reports a structural `0`. Surfaced while building
  this feature's `token_rotation_lookup.hpp`, whose
  `RotationSuccessorInfo::predecessor_overlap_expires_at` sources the field
  from the predecessor row precisely to avoid this — the human REST route
  (this feature) does **not** have this defect. The engine call sites are
  unmigrated and tracked separately.
- **`#2945`** (security-labelled) — pre-existing and unrelated to rotation:
  a `supervised`-tier API/MCP token can mint itself a tier-less, perpetual
  token via the existing `POST /api/v1/tokens` route, escaping its own tier
  confinement (RBAC off, the shipped default, and step-up is out of scope
  for API-token principals). Surfaced while reviewing the proposed
  `operator`-tier MCP allowance above, whose extension of the same class of
  gap to `operator` tokens was caught and not shipped. Tracked and gated
  separately from this feature's rotation surface.

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
  before any code shipped (MCP-twins review); remedy decided, not yet
  implemented — see "Privilege-escalation finding" above.

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
- Reviewer statement: full `--suite server` reported green on integration
  commit `e1bf2d86`.

## Reviewer

Multi-round review across the store-core, telemetry, and REST sub-branches
(rounds 2–6 above), plan-review before implementation (token-keyed vs
principal-keyed), two ownership/architecture specialists (round 6), and an
independent architect adjudication (round 5, confirm-error taxonomy). MCP
tool twins are reviewed separately and remain in progress.
