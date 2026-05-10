# Domain Docs

How the engineering skills should consume this repo's domain documentation when exploring the codebase.

## Before exploring, read these

- **`CONTEXT.md`** at the repo root, if present.
- **`docs/adrs/`** — read ADRs that touch the area you're about to work in. (Note: plural `adrs/`, not `adr/`.)

If any of these files don't exist, **proceed silently**. Don't flag their absence; don't suggest creating them upfront. The producer skill (`/grill-with-docs`) creates them lazily when terms or decisions actually get resolved.

As of 2026-05-10, `CONTEXT.md` does not yet exist for Yuzu. `CLAUDE.md` at the repo root is the authoritative cross-cutting domain doc — read that first.

## File structure

This is a single-context repo:

```
/
├── CLAUDE.md                       ← cross-cutting domain doc (authoritative)
├── CONTEXT.md                      ← created lazily by /grill-with-docs
├── docs/adrs/                      ← architectural decision records (plural)
│   ├── 0001-quic-transport-msquic-quicer.md
│   └── 0002-gateway-scaling.md
├── docs/                           ← routed concerns (see CLAUDE.md "Routed concerns" table)
├── agents/                         ← agent daemon source
├── server/                         ← server source
├── gateway/                        ← Erlang/OTP gateway (standalone rebar3 project)
├── sdk/                            ← public C ABI + C++23 wrapper
├── transport/                      ← transport abstraction
└── proto/                          ← protobuf definitions
```

Although the repo has multiple distinct subsystems, there is one global `CLAUDE.md` and one global `docs/adrs/`. Subsystem-specific decisions also live in `docs/adrs/` rather than per-subsystem ADR directories.

## Use the glossary's vocabulary

When your output names a domain concept (in an issue title, a refactor proposal, a hypothesis, a test name), use the term as defined in `CONTEXT.md` (when it exists) or in `CLAUDE.md`'s "Glossary" section. Don't drift to synonyms the glossary explicitly avoids.

For Yuzu specifically, mind the three meanings of "agent" — agent daemon, governance agent, agentic worker. See `CLAUDE.md` "Glossary — three meanings of 'agent'".

If the concept you need isn't in the glossary yet, that's a signal — either you're inventing language the project doesn't use (reconsider) or there's a real gap (note it for `/grill-with-docs`).

## Flag ADR conflicts

If your output contradicts an existing ADR, surface it explicitly rather than silently overriding:

> _Contradicts ADR-0001 (msquic+quicer for QUIC transport) — but worth reopening because…_
