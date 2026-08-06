# Adversarial review — #2376 authorization-topology floor

Committed so the run ledger's `reporter_ref` for the `external-model` rows points at something a
third party can retrieve and that is version-historied — a `/tmp` path is unreadable by a reviewer
by construction, and a PR-body quote is author-editable in place.

**Panel:** Codex (`codex exec`, `workspace-write` — the empirical leg, compiles and runs tests) and
Kimi-K2.7 (`kimi-k2.7-code` via the Ollama Cloud API — static-only, reasons over an injected
bundle). Both deliberately **non-Claude-family**: the 14 governance agents and the orchestrator are
all Claude, so a shared blind spot passes every one of them. This review is the direct evidence for
that concern — see the Codex finding below.

**Files:** `TARGET.md` (scope note + the five claims the panel was asked to attack), `anchors.md`,
and each reviewer's Phase 1 and Phase 2 reports.

## Outcome

| | |
|---|---|
| Codex P1 | **BLOCK** — `/api/v1/discover/permissions` + MCP twin gated `Infrastructure:Read` returned the complete role→permission grid, bypassing the floor. Fixed in `1103e418`. |
| Codex P2 | **BLOCK** — the round-1 fix made the response permission-varying under `Cache-Control: public`, so a shared cache could serve the privileged representation to an unprivileged caller. Fixed in `63a901e7`. |
| Kimi P1 | PASS + 7 findings |
| Kimi P2 | Withdrew 6 of 7 on cross-examination; its remaining BLOCK was an epistemic gap (call sites absent from its bundle — the orchestrator's bundling error), resolved by hand. |
| Acted on | F5 — floor entries now pinned against the store's own securable/operation registry |

**Both Codex findings were real, and both were missed by a 14-agent governance run.** The first is
the more instructive: the floor is keyed on `(securable, operation)`, which is correct, but the floor
SET was derived by asking *"which securables gate the routes this change touches?"* rather than
*"which routes emit authorization topology?"*. Governance verified the first question exhaustively.
The rule that came out of it is now a catastrophic clause in `.claude/routed-concerns.md`.

The second is the classic cost of a security fix: the fix itself changed the response from
caller-invariant to caller-varying, and nothing in the per-caller test matrix can see a cache leak.
