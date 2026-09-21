<!-- The security-posture half of the "Routed concerns" table of CLAUDE.md
     (repo root), pulled in by its @-import — loaded every session, same
     authority as CLAUDE.md itself. Split out of `routed-concerns.md` (Wave 8)
     because that file sits at its 40k-per-file ceiling; platform/product/
     data/observability concerns stay in `routed-concerns.md`, auth and
     access-control in `routed-concerns-access-control.md`. Row discipline
     unchanged: catastrophic-if-violated invariants + doc pointers only —
     detail goes in the plugin README. -->

| Concern | Doc | Loaded by |
|---|---|---|
| `platform_security` plugin — read-only Secure Boot / code-signing posture (`Security:Read`, both actions `ReadOnly`/`None`, no mutation). CATASTROPHIC-IF-VIOLATED: (1) failure never reads as absent — a definitive not-present (missing efivar, no lockdown LSM, absent registry value) is its own `absent` row with no failure token and status `OK`; a refused, malformed or oversized read is `unreadable` with a `<key>:<cause>` token through the shared `ConstraintAccumulator`, and a refusal (`EACCES`/`EPERM`/`ERROR_ACCESS_DENIED`) reports `PERMISSION_DENIED` on every OS leg; (2) the whole `execute()` body sits inside ONE `try/catch(...)` (frozen-seam rule), never an exception across the plugin ABI; (3) macOS `code_integrity` is two rung-2 literal-argv leaves (`/usr/sbin/spctl --status`, `/usr/bin/csrutil status`), no shell, no PATH search, each with a sink-manifest row (`platform_security/do_code_integrity#1`/`#2`); the descriptor's rung and support must match the code. The plugin's priority is asserted, not evidenced — the README states that plainly; do not inflate it. | `agents/plugins/platform_security/README.md` + `docs/agent-spawn-sink-manifest.md` | `security-guardian`+`cpp-safety` on `agents/plugins/platform_security/`, `plugin_action_catalogue_platform_security.hpp`; `docs-writer` on the plugin README |
