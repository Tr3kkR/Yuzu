// @ts-check
import { defineConfig } from 'astro/config';
import rewriteLinks from './src/remark/rewrite-links.mjs';
import stripFirstH1 from './src/remark/strip-first-h1.mjs';

// GitHub Pages project site: served under /Yuzu/. Change `site` if a custom
// domain is added later (then drop `base`).
export default defineConfig({
  site: 'https://tr3kkr.github.io',
  base: '/Yuzu',
  trailingSlash: 'always',
  markdown: {
    // Manifest-driven link rewriting: in-scope .md links -> site routes,
    // out-of-scope -> GitHub blob URLs, dangling -> build failure.
    remarkPlugins: [rewriteLinks, stripFirstH1],
    shikiConfig: { theme: 'night-owl', wrap: false },
  },
});
