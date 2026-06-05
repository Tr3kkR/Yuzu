import { defineCollection } from 'astro:content';
import { glob } from 'astro/loaders';
import { ENTRIES } from './nav.mjs';

// Read the canonical Markdown DIRECTLY from the repo's docs/ tree — no copy,
// single source of truth, drift impossible. The glob is scoped to exactly the
// files named in the curation manifest (src/nav.mjs), so inclusion is
// manifest-driven and unrelated docs are never parsed.
const manual = defineCollection({
  loader: glob({
    base: '../docs',
    pattern: ENTRIES.map((e) => `${e.file}.md`),
  }),
});

export const collections = { manual };
