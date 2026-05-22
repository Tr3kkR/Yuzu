# Domain Docs

Yuzu uses a single-context domain documentation layout.

## Read Before Work

- `CONTEXT.md` at the repo root for Yuzu glossary and domain boundaries.
- `docs/adr/` for architectural decisions relevant to the area being changed.
- Domain-specific docs referenced by `CODEX.md`, `CLAUDE.md`, or the local skill being used.

If a referenced context or ADR file is missing, proceed silently. The producer workflow `/grill-with-docs` creates domain docs lazily when terms or decisions are resolved.

## Layout

```text
/
+-- CONTEXT.md
+-- docs/
    +-- adr/
    +-- agents/
```

There is no `CONTEXT-MAP.md`; do not assume multiple contexts unless one is introduced later.

## Vocabulary Rule

Use the glossary terms from `CONTEXT.md` in issue titles, hypotheses, test names, plans, PR descriptions, and docs. If a term is missing, either choose an existing Yuzu term or flag it for `/grill-with-docs`.

## ADR Rule

ADRs live in `docs/adr/`. Create them only for decisions that are hard to reverse, surprising without context, and the result of a real trade-off.
