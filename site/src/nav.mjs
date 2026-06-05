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
    heading: 'Instructions & DSL',
    entries: [
      { file: 'Instruction-Engine', slug: 'instruction-engine', title: 'Instruction Engine' },
      { file: 'user-manual/instructions', slug: 'instructions', title: 'Instructions' },
      { file: 'yaml-dsl-spec', slug: 'yaml-dsl', title: 'YAML DSL' },
    ],
  },
  {
    heading: 'Targeting',
    entries: [
      { file: 'user-manual/scope-engine', slug: 'scope-engine', title: 'Scope Engine' },
      { file: 'scope-walking-design', slug: 'scope-walking', title: 'Scope Walking' },
      { file: 'asset-tagging-guide', slug: 'asset-tagging', title: 'Asset Tagging' },
      { file: 'user-manual/management-groups', slug: 'management-groups', title: 'Management Groups' },
      { file: 'user-manual/device-management', slug: 'device-management', title: 'Device Management' },
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
      { file: 'mcp-server', slug: 'mcp-server', title: 'MCP Server' },
      { file: 'user-manual/agent-plugins', slug: 'agent-plugins', title: 'Agent Plugins' },
      { file: 'user-manual/tar', slug: 'tar', title: 'TAR' },
      { file: 'tar-dashboard', slug: 'tar-dashboard', title: 'TAR Dashboard' },
      { file: 'fleet-viz-invariants', slug: 'fleet-viz', title: 'Fleet Visualization' },
    ],
  },
];

export const ENTRIES = NAV.flatMap((s) => s.entries);

/** docs-relative path (no .md) -> entry */
export const BY_FILE = new Map(ENTRIES.map((e) => [e.file, e]));
/** site slug -> entry */
export const BY_SLUG = new Map(ENTRIES.map((e) => [e.slug, e]));
