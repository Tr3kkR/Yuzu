/**
 * CURATION MANIFEST — the single source of truth for the docs site.
 *
 * Each entry maps a canonical Markdown file under repo `docs/` (path relative to
 * docs/, no extension) to its site section, order, slug, and title. Adding a doc
 * to the site means adding a line here; nothing else reads from disk to decide
 * inclusion. The diagram linter fails the build if an entry names a missing file.
 *
 * Plain ESM (not .ts) on purpose: imported by .astro pages, the content loader,
 * the remark link-rewriter, AND the standalone Node linter — one module, no
 * TS-from-mjs interop headaches.
 *
 * @typedef {{ file: string, slug: string, title: string }} NavEntry
 * @typedef {{ heading: string, entries: NavEntry[] }} NavSection
 */

/** @type {NavSection[]} */
export const NAV = [
  {
    heading: 'Start',
    entries: [
      { file: 'getting-started', slug: 'getting-started', title: 'Getting Started' },
    ],
  },
  {
    heading: 'Targeting',
    entries: [
      { file: 'user-manual/scope-engine', slug: 'scope-engine', title: 'Scope Engine' },
    ],
  },
  {
    heading: 'Identity & Access',
    entries: [
      { file: 'user-manual/authentication', slug: 'authentication', title: 'Authentication' },
      { file: 'user-manual/rbac', slug: 'rbac', title: 'RBAC' },
    ],
  },
  {
    heading: 'Interfaces',
    entries: [
      { file: 'user-manual/rest-api', slug: 'rest-api', title: 'REST API' },
      { file: 'user-manual/mcp', slug: 'mcp', title: 'MCP' },
    ],
  },
];

export const ENTRIES = NAV.flatMap((s) => s.entries);

/** docs-relative path (no .md) -> entry */
export const BY_FILE = new Map(ENTRIES.map((e) => [e.file, e]));
/** site slug -> entry */
export const BY_SLUG = new Map(ENTRIES.map((e) => [e.slug, e]));
