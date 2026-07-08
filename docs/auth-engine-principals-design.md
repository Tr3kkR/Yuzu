# Engine principals & delegation — auth-architecture follow-up design (ADR-0022 item 2b)

Status: **Draft for governance review** — this is the execution plan's item 2b
(`docs/adr-0022-execution-plan.md`, Phase 2), the program's critical-path
deliverable. Phase 4 (engine principal class) is gated on this design being
accepted; Phase 5 (delegation/write-back) and 2c's Decision-14 confinement
choice consume it. Nothing here ships code; every mechanism below lands via
the Phase-4/5 PR ladder mapped in §11.

Companion docs: `docs/adr/0022-headless-platform-use-case-engines.md` (the
ADR; its Decision 5 is the trust-tier/delegation decision this design
elaborates), `docs/adr-0022-execution-plan.md` (phases + its own Decision log
— cited below as "plan Decision N", distinct from the ADR's Decisions 1–7),
`docs/auth-architecture.md` (shipped auth surface),
`docs/adr/0017-management-group-confinement-list-reads.md` (the scoped
list-read model this design adopts as its authorization chokepoint).

## 1. Scope

In scope (the six questions 2b was chartered to answer):

1. Delegation token-exchange mechanics (§5).
2. Principal granularity — per-module vs per-host (§3).
3. Credential lifetime and rotation ceilings (§7).
4. Token-session attribution change for engine principals (§6).
5. Self-target destruction-guard extension (§9).
6. MCP tier applicability to engine principals (§8).

Binding design directions from the maintainer (2026-07-08):

- **Every user keeps their own identity end-to-end** — including operators
  whose reads are served through a UCE. No shared-credential blob may ever
  stand in for a set of humans.
- **Authorization is three-dimensional**: securable type × operation ×
  **management-group scope** (e.g. `Inventory:Read` confined to one
  management group). Two-dimensional global grants are the legacy floor, not
  the model.
- **Established, industry-standard mechanisms; no v1 shortcuts.** Where a
  standard exists (OAuth 2.0 Token Exchange, cloud-IAM scoped role
  assignments, service-account governance norms), this design follows its
  shape rather than inventing a local variant.

Out of scope, tracked elsewhere: the full quota mechanism (Phase 8; minimum
cap = plan PR 4.4, interlock #1973), the Decision-14 confinement mechanism
*choice* (2c owns it; §10 hands over candidates + criteria), streaming
egress, write-back orchestration semantics beyond the delegation mechanics
themselves (plan Decision 13).

## 2. Current state (verified against `dev`, 2026-07-08)

The gaps this design closes, with their exact locations:

- **Token sessions attribute to the human creator.**
  `AuthRoutes::synthesize_token_session` (`server/core/src/auth_routes.cpp`)
  sets `session.username = api_token.principal_id` — and `ApiToken::principal_id`
  is documented as "Username who created it"
  (`server/core/src/api_token_store.hpp`). The session's role is re-resolved
  from the *creator's current role* via `auth_mgr_.get_user_role(...)`. An
  automation token is therefore always a mask over a human identity — the
  exact anti-pattern plan Decision 9 requires Phase 4 to remove.
- **No principal-kind exists anywhere.** `ApiToken` has no kind field;
  RBAC's `PrincipalRole::principal_type` (`server/core/src/rbac_store.hpp`)
  admits only `"user"` and `"group"`; the legacy `auth::Role` enum is
  `{user, admin}`. A repo grep for service-account/machine-principal
  scaffolding returns zero hits.
- **Permissions are two-dimensional and global.** `RbacStore::check_permission`
  resolves roles (direct + group-inherited) and consults `role_permissions`
  keyed on `(role_name, securable_type, operation)` — there is no scope
  column. Management-group confinement exists as a *separate, currently
  inert* mechanism: ADR-0017's `authorize_list_read(user, securable, op) →
  DenyAll | AdmitAll | AdmitScoped(visible_set)` is **designed and ratified
  but unbuilt** (its PR-A..E ladder has zero code in the tree; call sites
  across the server carry "not yet effective under the global gate" comments
  citing #1634/#1716).
- **The self-target destruction guard is a username-string comparison.**
  Three sites in `server/core/src/settings_routes.cpp` (self-delete,
  self-demote, plus the Users-fragment `is_self` suppression) compare the
  target name byte-exact against `session->username`
  (`docs/auth-architecture.md` "Self-target principal-destruction guard").
- **MCP tier rides the credential.** `ApiToken::mcp_tier`
  (`readonly|operator|supervised|""`) is copied onto `Session::mcp_tier` at
  synthesis and checked *before* RBAC at ~28 per-tool sites in
  `server/core/src/mcp_server.cpp` (`tier_allows` /
  `requires_approval`, `server/core/src/mcp_policy.hpp`).
- **Lifetime is uneven; rotation does not exist.** MCP-tier tokens force
  expiry ≤ 90 days and service-scoped tokens force an expiry
  (`ApiTokenStore::create_token`), but a plain API token may be perpetual
  (`expires_at = 0`). No token type has a rotation workflow — only create
  and revoke.
- **Interim rules already enforced (Phase 1, PR #1972 branch):** on-behalf-of
  assertions are rejected (not ignored) at the HTTP pre-routing chokepoint
  and via a gRPC interceptor (`on_behalf_guard.hpp`,
  `grpc_on_behalf_interceptor.hpp`); the presentation-level
  `principal_class` label exists for HTTP metrics (`principal_class.hpp`)
  and the additive `AuditStore.principal_class` column (plan item 3a) is
  built on the same branch.

## 3. Identity model — every actor is a first-class principal

### 3.1 EnginePrincipalStore (born on Postgres)

A dedicated store, NOT columns bolted onto the token table — because the
governance metadata plan PR 4.3 requires does not describe a credential, it
describes an *identity* that outlives any one credential:

| Field | Notes |
|---|---|
| `principal_id` | Stable, immutable. Reserved namespace — see §3.3. |
| `display_name` | UI/audit label. |
| `owner_username` | **Named responsible human** — must reference an existing user; re-pointed (never orphaned) when that user is deleted, via an explicit transfer step in the lifecycle surface. |
| `justification` | Grant justification captured at creation (cloud-IAM service-account norm; feeds access reviews). |
| `classification` | `internal` \| `external`. **Unset/ambiguous ⇒ `external`** — the stricter, Phase-8-gated treatment (plan PR 4.3's fail-toward-rechecking rule). The classification *mechanics* remain PR 4.3's named deliverable; this store just persists the answer. |
| `lifecycle_state` | `active` \| `revoked`. **Soft-retained forever** — a revoked row is never hard-deleted, so audit attribution stays resolvable after credential revocation (plan Decision 9). |
| `created_at`, `revoked_at`, `created_by` | Lifecycle audit anchors. |

Substrate: born-on-Postgres per ADR-0006 (no new server SQLite stores) and
ADR-0012's author contract; it naturally accompanies plan PR 4.1's
pulled-forward `ApiTokenStore` Postgres migration. No secret material lives
in this store (credentials stay in `ApiTokenStore`, hash-only), so no
ADR-0010 SecretCodec involvement.

### 3.2 Granularity: one principal per module

**Per-module, not per-host.** A UCE host running the vuln module and a
future second module holds two engine principals with disjoint grants. This
is the least-privilege cut: grants, quota (PR 4.4's per-principal cap),
audit attribution, and revocation blast-radius all land at module
granularity. A compromised or misbehaving module is revocable without
severing its host siblings. (Per-host was rejected: it recreates a
mini-union-of-permissions across modules — the ServiceNow-admin-token
shape at smaller scale.)

### 3.3 Identity namespace — collisions must be impossible

Engine principal ids live in a reserved namespace: `engine:<slug>` (e.g.
`engine:vuln`). Two structural rules:

- User creation (local, OIDC/SAML provisioning, SCIM later) **rejects**
  usernames matching the reserved prefix — an engine id can never collide
  with a human username. This matters because `session->username` is the
  key for audit rows, the self-target guard, token ownership, and RBAC
  lookups; a collision would silently merge two identities across every one
  of those surfaces.
- The prefix makes audit rows and access-review exports self-describing
  without a join.

### 3.4 Operators viewing through a UCE keep their own identity

Decision 14's requirement plus the maintainer's end-to-end-identity
direction means: the UCE findings view must never serve operator reads on
the engine's own fleet-wide credential. The mechanism *choice* is 2c's
(§10), but this design fixes the invariant: **any read rendered to an
individual operator is authorized as that operator** — the engine's
autonomous-sync identity is for autonomous sync only.

## 4. Grant model — scoped role assignments, one model for every principal class

### 4.1 The assignment triple

Authorization becomes a set of **scoped role assignments**:

```
(principal, role, scope)
```

- `principal` — a user, a group, or an engine principal (`principal_type`
  gains `engine` as its third value — additive on either substrate, plan
  Decision 9).
- `role` — an RBAC role (the existing `role_permissions` machinery keeps
  defining what a role can do: securable × operation, deny-overrides-allow).
- `scope` — **fleet-wide** or **one management group**, expanding
  descendant-ward per ADR-0017's expansion invariant.

This is the cloud-IAM shape (a role assignment *at a scope*), and it
generalizes the existing management-group `GroupRoleAssignment` concept
rather than inventing an engine-only parallel path. The maintainer's
worked example — `Vuln → Read → management group X` — is exactly one
assignment row: `(engine:vuln-viewer-role-holder, role-with-Vuln:Read,
scope=MG-X)`.

**One model for all classes.** Humans, agentic workers (API/MCP tokens),
and engine principals resolve effective authority identically:

```
effective authority = ⋃ assignments, evaluated as (permissions ∩ scope)
```

enforced at ADR-0017's `authorize_list_read` chokepoint for list/fan-out
reads and at the per-device scoped-permission path for single-target
operations. No second resolution path is introduced — a deliberate
rejection of a separate engine-grants table, which would give every future
authorization change two places to forget.

### 4.2 Engine-principal constraints (structural, not conventional)

- **Default-deny per securable.** An engine principal with no assignments
  can do nothing.
- **No admin, ever.** Assignment APIs *reject* (not merely omit in UI)
  granting an engine principal the `admin` legacy role, any built-in
  wildcard role, or elevation eligibility. The ServiceNow-integration
  admin-token pattern must be unconstructable through any surface.
- **No "all permissions" toggle** exists for engine principals on any
  surface (plan PR 4.3's explicit requirement).
- Engine principals are excluded from JIT elevation, MFA enrollment, login
  surfaces, and password paths — they are not users; they only ever
  authenticate by credential (§6).

### 4.3 ADR-0017 is hereby on the critical path — named dependency

Phase 5's effective-authority intersection and Decision 14's confinement
outcome both cite `authorize_list_read` — which **does not exist in code**.
This design makes the dependency explicit rather than inherited silently:

> **Dependency edge:** ADR-0017 PR-A (the `authorize_list_read` chokepoint
> + scoped-assignment resolution) must ship **before Phase 5 begins**, and
> before any scoped engine assignment can actually confine a read. Phase 4
> can proceed without it (engine principals with *fleet-wide* read grants
> are expressible in the current global model), but the maintainer's
> three-dimensional-RBAC direction is only real once ADR-0017 PR-A lands.

Sequencing and resourcing of the ADR-0017 ladder (PR-A..E, plus the #1715
deny-precedence decision that gates PR-A) is the maintainer's call — this
doc's job is to ensure that call is made consciously, not discovered at
Phase-5 kickoff.

## 5. Delegation — OAuth 2.0 Token Exchange shape (RFC 8693)

Phase 5's write-back unlock. The mechanics, fixed now so Phase 4's stores
don't need reshaping later:

1. **Grant:** an operator, authenticated to Yuzu normally (session or
   token), requests a delegation to a named engine principal for a named
   purpose. The server issues a **delegation artifact**:
   - opaque handle (not a self-contained JWT the engine could inspect or
     mint against) — server-side state keyed by `jti`;
   - **audience-bound** to one engine principal id;
   - **purpose-bound** (requested operation class recorded at issuance);
   - **short-lived** (minutes-scale TTL; single-digit default, operator
     cannot extend past a server ceiling);
   - single-use for mutating operations (`jti` consumed on redemption);
   - revocable (operator or admin can void it before expiry).
2. **Exchange:** the engine presents *its own credential* + the artifact
   (RFC 8693 `subject_token` = artifact, `actor_token` = engine credential
   — the standard delegation, not impersonation, composition). The server
   verifies both, checks the audience binding, and mints a bounded
   delegated context.
3. **Effective authority of a delegated operation:**

   ```
   engine's assignments ∩ operator's assignments ∩ operator's scope
   ```

   — an intersection, never a union; computed through the same ADR-0017
   chokepoint (§4.3). A delegation can only ever *narrow*.
4. **Self-asserted delegation stays rejected forever.** The Phase-1
   on-behalf-of guard (reserved header/metadata rejection) is permanent —
   ADR-0022's Interim rule survives as a standing invariant; the only
   delegation the server honors is one it issued itself.
5. **Audit:** every delegated operation writes both identities — the full
   plan-Decision-9 shape (engine principal id, `is_delegated`, delegated
   operator identity, delegation artifact id,
   `delegation_verification_status`), landing with AuditStore's Postgres
   Wave-1 migration (plan 3b). Until Phase 5 produces real values these
   columns carry defaults; pre-enforcement rows use
   `delegation_verification_status=unverified` per ADR-0022's
   incremental-shipping rule. The already-built 3a `principal_class` column
   is the early, delegation-independent half of this shape.

## 6. Token-session attribution — branch on persisted kind, never inference

`ApiToken` gains a persisted **`principal_kind`** (`human` | `engine`), set
at creation, immutable thereafter. Legacy rows backfill `human` —
bit-for-bit preservation of current behavior. Plan Decision 9's rule is
adopted verbatim: session synthesis branches on the stored field, **never**
on the shape of the `principal_id` string (the reserved namespace in §3.3
is defense-in-depth and readability, not the discriminator).

`synthesize_token_session` becomes a two-branch function:

- `principal_kind=human` (all existing rows): exactly today's behavior —
  attribute to the creating user, re-resolve their current role.
- `principal_kind=engine`: the session **is** the engine principal —
  `username = principal_id` (the `engine:<slug>` id), `auth_source =
  "engine_token"` (a sixth value alongside
  `local|oidc|saml|api_token|mcp_token`), role/authority resolved from the
  engine's scoped assignments (§4) — `get_user_role` is never consulted
  (there is no user row to consult), and the legacy `Role` enum slot is
  pinned to `user` (floor; real authority comes from assignments). A
  **revoked or missing engine-principal row fails closed** — no session.

`principal_class` then reports `engine` truthfully at both consumers: the
HTTP request metric (plan PR 4.5 flips the reserved value live) and the
AuditStore column (3a — already built to receive it; its honest-empty rule
for non-HTTP writers is unaffected).

## 7. Credential lifetime and rotation

- **Ceiling: 90 days**, inherited from the MCP-token precedent — engine
  credentials can never be perpetual. `create` for `principal_kind=engine`
  rejects `expires_at = 0` or > 90 days, same enforcement point as the
  existing MCP cap in `ApiTokenStore::create_token`.
- **Rotation: overlap-pair, designed here, built in plan PR 4.3.** An
  autonomous host cannot tolerate a hard cutover the way a human clicking
  "new token" can, so `rotate` is:
  1. mint the successor credential (same principal, same expiry rules) —
     **both credentials valid** from this moment;
  2. bounded overlap window (default 7 days, admin-configurable downward;
     never past either credential's own expiry) for the module to pick up
     and verify the successor;
  3. predecessor **auto-revokes** at window end (or immediately on operator
     confirm) — the window is a ceiling, not a promise.
  - At most **two** active credentials per engine principal at any moment —
    a third mint is rejected until the overlap resolves. Every step audits.
- This is the platform's first rotation workflow (the gap matrix in
  `.claude/skills/auth-and-authz/SKILL.md` lists token rotation as missing
  for all types); the design is deliberately credential-generic so the
  later human-token rotation feature can adopt it unchanged.

## 8. MCP tier applicability

**Reused, hard-locked `readonly` for v1.** Engine credentials carry
`mcp_tier=readonly` — the creation API *rejects* any other tier while
Decision 1's read-only/autonomous scoping holds. Rationale: the two-gate
(tier-then-RBAC) ordering at ~28 MCP sites is exactly the defense-in-depth
this principal class most needs; discarding tier for engines ("defer to
RBAC") would remove the second gate from the widest-read-scope principal,
and allowing `operator|supervised` now would hand a read-only-by-design
principal a write-capable tier the moment an assignment slips. Unlocking
higher tiers is a **Phase 5 decision**, taken together with delegation —
where `supervised`'s approval-ticket flow is the natural fit for delegated
mutations.

## 9. Self-target destruction guard

- **Phase 4 — structural posture.** Engine principals cannot reach
  principal-destruction surfaces at all: default-deny + the §4.2 admin bar
  means no engine session can hold `UserManagement:*`/`Security:*` grants
  on principal-lifecycle routes, and the engine-principal lifecycle surface
  itself (create/rotate/revoke/transfer-owner) requires a **human admin
  session + MFA step-up** (same posture as the existing 11 step-up
  surfaces). One defensive addition: those routes deny any
  `auth_source="engine_token"` session outright (fail-closed belt to the
  structural braces), audited as `denied`.
- **Phase 5 — re-key on effective identity.** Once delegated mutations
  exist, the guard's comparison re-keys on the **effective delegated
  identity** (ADR-0022 Decision 5's named extension): a delegated operation
  targeting the *delegating operator's own* account or the *acting engine
  principal itself* is rejected exactly as a human self-target is today.
  The §3.3 reserved namespace guarantees the string comparison stays
  collision-free across classes.

## 10. Hand-off to 2c — Decision-14 confinement candidates

2c owns the choice; 2b supplies the candidates and the evaluation criteria.
The invariant to satisfy (Decision 14): a group-confined operator's
findings view shows the same device set `/devices` would show them — never
more — and per §3.4, authorized *as that operator*.

| Candidate | Sketch | Against the criteria |
|---|---|---|
| (a) View-time scoped read-through | Findings page render triggers per-operator reads to the Yuzu server, carrying a short-lived operator-bound artifact (the §5 primitive, read-purpose variant); server evaluates confinement via ADR-0017 | Server stays authoritative; zero staleness; per-view latency + server load; needs the §5 artifact early |
| (b) Identity assertion / session exchange | Operator's browser obtains an operator-bound artifact from Yuzu; UCE backend exchanges it for a scoped read context covering the view session | Same authority + freshness as (a) with fewer round-trips; more moving parts (exchange endpoint, context lifetime) |
| (c) Synced confinement predicate | Per-operator scope predicate synced alongside findings, re-validated on short TTL | No view-time server dependency; but confinement is evaluated *by the UCE* against a cached predicate — weakest fit for both "server authoritative" and the never-stale requirement (Decision 14 itself warns the shared access layer is explicitly a cache) |

Evaluation criteria (in order): server remains the confinement authority;
staleness window ≈ 0 (a scope change takes effect at next view); per-view
identity preserved in Yuzu's audit; operational cost at fleet scale.
**2b's recommendation: the (a)/(b) family** — both reuse the §5 delegation
artifact as their identity primitive, which is why its shape is fixed now.
(c) should only survive 2c if a concrete latency/scale constraint defeats
(a)/(b), and then only with a TTL bound stated in the requirements doc.

Other onward hand-offs: internal-vs-external classification mechanics (plan
PR 4.3 named deliverable; store field reserved in §3.1), quota beyond the
minimum cap (Phase 8; interlock #1973 closes at plan PR 4.4), ADR-0017
ladder sequencing + #1715 deny-precedence decision (maintainer).

## 11. Phase-4/5 PR mapping

| Piece (this doc) | Ships in | Notes |
|---|---|---|
| `ApiTokenStore` → Postgres, + `principal_kind` column | plan PR 4.1 | Backfill `human`; hash-only, no SecretCodec needed |
| `EnginePrincipalStore` (§3.1) + reserved namespace (§3.3) | plan PR 4.2 | With `principal_type='engine'` RBAC value + `synthesize_token_session` branch (§6) + `auth_source="engine_token"` |
| Lifecycle surface: create/rotate/revoke/transfer-owner, REST + MCP + admin-console page; §7 rotation; §9 Phase-4 guard posture; §4.2 structural bars | plan PR 4.3 | Human-admin + step-up gated; classification mechanics decided here |
| Per-principal quota cap + exhaustion counter | plan PR 4.4 | Closes #1973 |
| `principal_class=engine` live on metrics | plan PR 4.5 | 3a audit column already receives it |
| Scoped role assignments resolution (§4.1) at the chokepoint | **ADR-0017 PR-A** (prerequisite, see §4.3) | Gates Phase 5 and real 3-D confinement |
| Delegation artifact issue/exchange/verify (§5); guard re-key (§9); full audit shape producers | Phase 5 PRs | Gated on 3b (audit schema) + Phase 4 + ADR-0017 PR-A |

## 12. Decision log

1. Dedicated `EnginePrincipalStore` over token-row columns or `users`-table
   reuse — identity outlives credentials; soft-retain + owner/justification
   don't fit either alternative.
2. Per-module principal granularity — least-privilege blast radius.
3. Reserved `engine:` namespace with user-creation rejection — identity
   collision made impossible rather than unlikely.
4. One scoped-assignment model for all principal classes (no engine-only
   grant table) — a second resolution path is a standing consistency bug.
5. ADR-0017 PR-A promoted to named critical-path prerequisite.
6. RFC 8693 delegation shape; artifact is opaque, audience/purpose-bound,
   short-lived, single-use for mutations; authority intersects, never
   unions.
7. Attribution branches on persisted `principal_kind` only (plan Decision 9
   adopted); `auth_source="engine_token"` added; revoked principal ⇒ fail
   closed.
8. 90-day ceiling + overlap-pair rotation (≤2 active credentials); rotation
   designed credential-generic.
9. MCP tier reused, hard-locked `readonly` until Phase 5 revisits with
   delegation.
10. Self-target guard: structural denial in Phase 4, effective-identity
    re-key in Phase 5.
11. Decision-14 recommendation to 2c: operator-bound-artifact family
    ((a)/(b)); synced-predicate (c) only under a stated, TTL-bounded
    constraint.
