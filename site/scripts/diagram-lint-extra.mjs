/**
 * Off-site Tier-A docs to ALSO lint for ASCII-diagram alignment + retired arrows
 * (►◄▶◀), even though they are not pages on the site. The curation manifest
 * (src/nav.mjs) only covers site pages; this allow-list extends the linter's
 * reach so diagrams in repo docs are gated repo-wide.
 *
 * Paths are repo-relative (resolved from the repo root, one level above site/).
 *
 * Starts EMPTY so the build stays green. The diagram-normalization slices
 * (#1258 / #1259 / #1260 / #1261 / #1262, …) append a doc here once its diagrams
 * are normalised and its inline `►` retired, so it stays gated thereafter. Known
 * candidates to add as they are normalised: 'README.md', 'docs/architecture.md',
 * 'docs/capability-map.md', 'docs/roadmap.md', 'docs/scope-walking-design.md'.
 *
 * @type {string[]}
 */
export const EXTRA_DOCS = [];
