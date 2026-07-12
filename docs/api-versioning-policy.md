# API Versioning & Deprecation Policy

**Status:** policy — binding on all operator-facing machine surfaces once published. **Published = this document present on `main`** (the release branch); no draft, feature-branch, or `dev`-only copy counts. This is the single checkable discharge moment for the ADR-1005 Phase 8 interlock below.
**Scope:** REST (`/api/v1/*`) and MCP tools. The agent↔server gRPC wire protocol is governed separately (proto compatibility is enforced by the `proto-compat` CI job, not this policy). Dashboard HTML fragments are UI, not API, and carry no compatibility contract.
**Why now:** ADR-1005 makes the API surface a product contract (its Consequences require a published compatibility posture before any external engine credential is issued — one of the two Phase 8 issuance interlocks in `docs/adr-1005-execution-plan.md`), and ADR-0021 is landing new surface that needs this posture regardless. The NVD route retirement (execution plan Phase 7) is the first deprecation to run this cycle.

## Versioning mechanics

- **REST is path-versioned.** Everything under `/api/v1/` is the stable, versioned API: standard JSON envelope (`data`, `error`, `meta`, `pagination`), `"api_version": "v1"` in `meta`, A4 error envelope. A breaking change increments the path version (`/api/v2/`); v1 and v2 run side by side for the deprecation window.
- **Legacy `/api/` (unversioned) routes** predate this policy, are deprecated as a class, and are removed per the cycle below — no new route ever lands unversioned.
- **MCP tools follow the same posture as REST** (execution-plan Decision 10): additive-only evolution in place; a **versioned tool name** (e.g. `query_software_v2`) is introduced **only on a breaking change**, with the old tool name retained for the deprecation window. There is **no per-tool semver scheme** — a tool's contract is its name plus its discoverable input/output schema.
- **Discoverability is part of the contract:** the current surface is always enumerable live — REST via `GET /api/v1/openapi.json`, MCP via `tools/list` (A2, `docs/agentic-first-principle.md`). A surface change that doesn't show up in discovery is a defect.

## Additive-preferred posture

Evolve in place whenever the change is **additive**; version only when forced.

**Additive (allowed within a version):** new endpoints/tools; new optional request fields or parameters with backward-compatible defaults; new response fields (consumers must tolerate unknown fields); new enum values on fields documented as open; new error codes within the A4 envelope shape.

**Breaking (requires a version increment / versioned tool name):** removing or renaming an endpoint, tool, field, or parameter; changing a field's type or semantics; making an optional input required; narrowing accepted input; changing an error envelope's shape; changing auth requirements such that a previously-valid call fails. Tightening a security gate is allowed without a version bump when the prior behavior was a vulnerability — but the carve-out is narrow: the CHANGELOG **Security** entry must cite a tracked issue or advisory, and the change is limited to the minimal tightening that closes the cited vulnerability; broader tightening takes the normal cycle. Side-by-side version operation never exempts the older version from this carve-out.

## Deprecation cycle

1. **Announce.** The deprecating release carries: a `CHANGELOG.md` **Deprecated** entry naming the replacement; a `docs/user-manual/upgrading.md` section with concrete migration steps; deprecation noted in the surface's discovery output and docs. In-product banners are supplementary, never the only channel — an enterprise change-management process must be able to discover the change from the release notes alone.
2. **Window.** The deprecated surface keeps working for **at least 90 days AND at least one intervening feature release**, whichever is longer. Windows may be extended, never shortened after announcement — with one exception: a deprecated surface found exploitable mid-window may be hardened or removed immediately, with a CHANGELOG **Security** entry citing the tracked issue/advisory and explicit disclosure that the announced window was shortened and why.
3. **Remove.** Removal ships in a feature release (never a patch release), with a `CHANGELOG.md` **Breaking/Removed** entry that includes a "where the capability lives now" migration narrative. Precedent shape: execution plan Phase 7 PR B/PR E (the NVD route retirement).

While the product is pre-1.0, the same cycle applies — pre-1.0 status does not waive the window for any surface a customer or external engine consumes.

## What this policy gates

- **External engine credentials** (ADR-1005 Interim rules): no engine credential is issued to an external party before this policy is published. Publication of this document discharges the "published API versioning/deprecation policy" half of the Phase 8 issuance interlock; the per-principal quota cap is the other half and is tracked separately.
- **Every deprecation of a shipped operator surface** — including grandfathered legacy routes — runs the cycle above; the ADR-1005 exception ledger records any surface retired outside it (there should be none; the ledger also closes out grandfathered-surface retirements that ran the cycle, per execution-plan Phase 7 PR E — that entry closes the grandfather exception, it does not record a violation).
