# Code Review Agent Team Report (2026-03-20)

> **2026-03-26 Delta:** Many findings from this review were addressed during the RC sprint (2026-03-22 to 2026-03-24). Key commits: `4bdae88` (8 CRITICALs — docs, Settings UI, enforcement, tests), `73b1d65` (14 HIGHs from this review), `47aa65d` (MCP server). Findings S2 (metrics auth), F1 (log path), and F2 (token session) were specifically addressed. See `Release-Candidate.local.MD` for the full 52-finding resolution status.

## Agent Team Composition

To review this repository thoroughly, I assembled a five-agent review team with explicit scopes:

1. **Quality Auditor** — code quality, maintainability, and readability.
2. **Security Sentinel** — authentication/authorization, sensitive endpoints, and hardening.
3. **Functional Verifier** — correctness, behavior mismatches, and edge-case handling.
4. **UI/UX Reviewer** — interaction quality, accessibility, and dashboard ergonomics.
5. **Integration Lead** — synthesis, priority ranking, and concrete remediation plan.

---

## Findings by Agent

### 1) Quality Auditor (Code Quality + Readability)

#### Q1 — Large embedded HTML/JS/CSS strings in C++ translation units reduce maintainability
- **Evidence:** Login and dashboard UIs are encoded as very large raw string literals (`kLoginHtml`, `kDashboardIndexHtml`) directly in C++ source files.
- **Impact:** Harder code review diffs, weaker linting/editor support for HTML/CSS/JS, and increased merge conflict risk.
- **Recommendation:** Move UI assets into versioned static files (e.g., `server/core/web/`) and embed/load via a lightweight asset pipeline.

#### Q2 — Duplicate comment in OIDC callback block signals review noise
- **Evidence:** Repeated identical comment `// Check for error response from IdP` in the callback handler.
- **Impact:** Minor, but symptomatic of reduced local clarity and potential copy/paste drift in security-sensitive logic.
- **Recommendation:** Remove duplicate and keep callback flow comments concise and ordered.

---

### 2) Security Sentinel (Security)

#### S1 — Host header is trusted to build OIDC redirect URI
- **Evidence:** `/auth/oidc/start` derives `redirect_uri` from the incoming `Host` header and current scheme.
- **Risk:** Host header manipulation can produce incorrect redirect URIs and opens room for phishing/misrouting behavior if upstream proxy header validation is weak.
- **Recommendation:** Prefer configured canonical external URL (or strict allowlist) over raw request `Host`.

#### S2 — `/metrics` is explicitly unauthenticated
- **Evidence:** Auth middleware allows direct unauthenticated access to `/metrics`.
- **Risk:** Operational metadata exposure (fleet size, activity counters) to unauthenticated clients.
- **Recommendation:** Gate with auth by default, or bind metrics to localhost/private interface with explicit opt-out.

---

### 3) Functional Verifier (Functionality + Correctness)

#### F1 — Windows server log path points to `agent.log`
- **Evidence:** In server log path helper, Windows returns `C:\ProgramData\Yuzu\logs\agent.log`.
- **Impact:** Confusing operational diagnostics and potential log mixing between server and agent components.
- **Recommendation:** Change path to `server.log` for parity with non-Windows branches.

#### F2 — API token pre-routing auth creates an empty session object for any valid token
- **Evidence:** On valid token, middleware does `session.emplace()` without role/user context.
- **Impact:** Behavior is functionally permissive but opaque; downstream checks that depend on principal identity may not have meaningful session metadata.
- **Recommendation:** Use explicit auth context type for API-token principals (e.g., `AuthPrincipal{type=token, token_id,...}`) instead of empty user session emulation.

---

### 4) UI/UX Reviewer (Usability + Accessibility)

#### U1 — Login flow is XHR-only and keyboard/error affordances are minimal
- **Evidence:** Form submit uses `doLogin(event)` with XMLHttpRequest and inline text error region.
- **Impact:** Limited progressive enhancement; no `aria-live` attributes on error message area for assistive technologies.
- **Recommendation:** Add accessible alert semantics (`role="alert"` / `aria-live="polite"`) and graceful non-JS form fallback.

#### U2 — Dashboard layout uses dense data tables with narrow defaults and truncation
- **Evidence:** Results table applies `max-width: 300px`, ellipsis truncation, and small typography.
- **Impact:** High information density but reduced scanability on lower-resolution displays.
- **Recommendation:** Add optional row expansion/details drawer and adjustable density mode.

---

## Integrated Priority Plan (Integration Lead)

### P0 (Immediate)
1. Replace Host-header-based OIDC redirect derivation with canonical configured external URL.
2. Decide security posture for `/metrics` and enforce auth/private binding by default.

### P1 (Next sprint)
3. Correct Windows server log file name to `server.log`.
4. Refactor token-auth context so authorization decisions retain principal semantics.

### P2 (Backlog)
5. Externalize embedded UI assets from C++ translation units.
6. Improve accessibility semantics for login error and dashboard result inspection.

---

## Review Completion Status

✅ Team formed and review completed across requested dimensions:
- code quality
- readability
- security
- functionality
- UI/UX
