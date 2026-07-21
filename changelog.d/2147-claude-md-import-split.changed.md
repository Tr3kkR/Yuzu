- **CLAUDE.md back under its 40k-character ceiling (#2147).** The Routed concerns
  table (22k characters, half the file) moved byte-identically to
  `.claude/routed-concerns.md` and is pulled back in via Claude Code's `@`-import,
  which loads imported files into context in full every session — so nothing an
  agent sees has changed, but each file now has its own 40k budget
  (CLAUDE.md 23.1k, table 22.5k).
