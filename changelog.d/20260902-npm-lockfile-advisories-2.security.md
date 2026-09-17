- **Closed the last 2 open npm advisories in the docs-site lockfile.** `npm audit
  fix` resolved nanoid's infinite-loop-on-zero-size bug (GHSA-2v37-7h3g-55p8) and
  js-yaml's quadratic-CPU `!!omap` resolution (CVE-2026-59870 / GHSA-5p4m-2wfm-xmqj)
  within already-declared ranges — no `overrides`, `package.json` unchanged.
