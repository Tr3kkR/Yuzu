- **Cleared all 12 known npm advisories in the repo's JS tooling.** The
  docs site moves to Astro 7 (fixes GHSA-2pvr-wf23-7pc7, GHSA-8hv8-536x-4wqp,
  GHSA-j687-52p2-xcff, GHSA-jrpj-wcv7-9fh9, GHSA-xr5h-phrj-8vxv and the
  transitive esbuild GHSA-g7r4-m6w7-qqqr), the puppeteer test harness picks
  up patched `js-yaml`/`ws` (GHSA-h67p-54hq-rp68, GHSA-96hv-2xvq-fx4p), and
  the Cedar & Vale demo app gains a committed lockfile on `express` 4.22.2 —
  clearing a high-severity `path-to-regexp` ReDoS (GHSA-37ch-88jc-xwx2) plus
  three `qs` DoS advisories its previously unpinned tree was carrying — with
  `npm ci` in its Dockerfile so the image gets exactly the audited tree.
  Dependabot now watches all three npm lockfile directories (grouped
  minor+patch weekly; majors as separate PRs) so advisories can no longer
  accumulate silently, and the README carries the live OpenSSF Best
  Practices (Passing) badge (#407).
