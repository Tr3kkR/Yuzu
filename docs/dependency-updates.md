# Dependency Updates

This doc is the strategy reference for keeping Yuzu's pinned third-party
dependencies current. It closes the acceptance criteria for #363: every
ecosystem has a clear update path, a staleness query, and a visible merge
latency. If you're adding a new pinned dependency, this is the file that
tells you where it belongs.

## What is pinned, where, and how it gets updated

| Ecosystem         | Source of truth                               | Update path                                                                                  |
|-------------------|-----------------------------------------------|----------------------------------------------------------------------------------------------|
| GitHub Actions    | `uses: ...@vX` in every `.github/workflows/*` | Dependabot (weekly) — `.github/dependabot.yml` `github-actions` entry                         |
| Docker base images| `FROM` in `deploy/docker/*`                   | Dependabot (weekly) — `.github/dependabot.yml` `docker` entry                                 |
| Python tooling    | `requirements-ci.txt` (repo root)             | Dependabot (weekly) — `.github/dependabot.yml` `pip` entry                                    |
| vcpkg baseline    | `vcpkg.json` `builtin-baseline`               | Scheduled workflow — `.github/workflows/vcpkg-baseline-update.yml` (monthly PR, hands-off)     |
| rebar3 deps       | `gateway/rebar.config`                        | **Manual quarterly review** — see "Rebar3 review checklist" below                              |
| Git submodules    | —                                             | No submodules; nothing to track                                                               |

## Python tooling (meson, etc.)

Yuzu's CI pipeline pins meson because subtle backend rewrites between
meson minor releases have bitten us on ninja dyndep ordering. The pin
lives in `requirements-ci.txt` at the repo root, which is the **single
source of truth** consumed by:

- `.github/workflows/ci.yml` — all six jobs `pip3/pip/pipx install` from it
- `.github/workflows/release.yml` — Windows and macOS release builds

`scripts/setup.sh` assumes a `meson` binary is already on PATH and does
not install one — local developers are responsible for matching the
pinned version themselves (`pip install -r requirements-ci.txt` in a
venv is the easiest path).

Dependabot opens a PR against `requirements-ci.txt` every week if a newer
meson is released. CI runs on the PR against the new version; if anything
breaks, the PR stalls (which is visible on the "Dependency updates" label
query) instead of silently landing a broken pin.

### Known duplication — Dockerfile meson pins

`deploy/docker/Dockerfile.{agent,server,ci,ci-linux,runner-linux}` each
hardcode `meson==1.9.2` as part of the build-stage apt+pip RUN command.
These are **not** auto-tracked by Dependabot and will drift from
`requirements-ci.txt` if Dependabot bumps meson. This is a known
follow-up — centralizing them on `COPY requirements-ci.txt` is tracked
implicitly by #363 and can be done in a follow-up PR. Until then, when
merging a Dependabot meson bump, also bump the literal `meson==X.Y.Z`
string in those 5 Dockerfiles. Grep `meson==` under `deploy/docker/` to
find them:

```bash
grep -rn 'meson==' deploy/docker/
```

## vcpkg baseline

Dependabot does not understand vcpkg. We evaluated three options in #363:

1. **Renovate Bot with vcpkg regex managers** — more flexibility, but
   adds a second bot to the repo and the regex configuration is its own
   maintenance burden.
2. **Scheduled workflow that bumps the baseline and opens a PR** —
   simpler, uses GitHub Actions native tools, visible in the normal PR
   feed.
3. **Manual bump during release prep** — zero automation, relies on
   memory.

We chose **option 2**. `.github/workflows/vcpkg-baseline-update.yml`
runs at 10:00 UTC on the 1st of each month (and is
`workflow_dispatch`able). It:

1. Resolves `git ls-remote https://github.com/microsoft/vcpkg.git HEAD`
   to get the current master SHA.
2. Reads `vcpkg.json` `builtin-baseline` via `jq`.
3. If they match, exits silently.
4. Otherwise, `sed -i`s the new SHA into **every** tracked reference —
   the workflow file keeps an authoritative list and fails loudly if any
   listed file still has the old SHA after the sed (guards against new
   references being added without updating the workflow).
5. Opens a PR via `peter-evans/create-pull-request@v7` with label
   `dependencies,ci`.

CI on the PR re-resolves every downstream vcpkg port against the new
baseline — if anything breaks, the PR is left open for manual
investigation instead of silently merging a broken build.

When adding a new file that pins the vcpkg baseline SHA (e.g., a new
CI workflow, a new Dockerfile), **add it to the `files` array in
`.github/workflows/vcpkg-baseline-update.yml`**. The post-sed grep
verifier ensures the omission doesn't slip through silently.

## Rebar3 deps review checklist

`rebar3` has no dependabot ecosystem. `rebar3 update` only refreshes the
package cache — it does not bump the pins in `rebar.config`. Automating
rebar3 bumps requires custom per-dep logic (hex.pm API for hex deps,
`git ls-remote --tags` for git deps) that isn't worth the complexity for
a project with 7 gateway dependencies that change a few times a year.

**We review `gateway/rebar.config` manually every quarter**, or whenever
a gateway change is blocked on an upstream fix. Checklist:

1. `cd gateway && source ../scripts/ensure-erlang.sh`
2. For each hex dep in `rebar.config`, check the latest stable release:
   - `grpcbox` — https://github.com/tsloughter/grpcbox/tags
   - `gpb` — https://hex.pm/packages/gpb
   - `telemetry` — https://hex.pm/packages/telemetry
   - `prometheus` — https://hex.pm/packages/prometheus
   - `prometheus_httpd` — https://hex.pm/packages/prometheus_httpd
   - `recon` — https://hex.pm/packages/recon
   - `gproc` — https://hex.pm/packages/gproc
   - `meck` (test profile) — https://hex.pm/packages/meck
   - `proper` (test profile) — https://hex.pm/packages/proper
3. For each git-pinned dep (`grpcbox_plugin`), `git ls-remote --tags`.
4. Bump any dep whose latest stable is > 1 minor version ahead of the
   pin, or any dep with a known security advisory (check GitHub
   Security Advisories for the repo).
5. Run `/test --quick` (unit + eunit + dialyzer + synthetic UAT) after
   each bump — do not batch bumps without testing in between.
6. Commit the `rebar.config` change with a conventional
   `build(deps): bump <dep> to <version>` message.

## Staleness query — "what's the oldest pinned dep?"

- **Dependabot-tracked** (`github-actions`, `docker`, `pip`) — open the
  "Dependency updates" tab on the GitHub UI, or
  `gh pr list --label dependencies --state open`. An open Dependabot PR
  with an old `createdAt` is the staleness signal; merge latency is
  visible directly.
- **vcpkg** — the scheduled workflow either finds a new HEAD (PR opens)
  or it doesn't. If a PR from `.github/workflows/vcpkg-baseline-update.yml`
  is open and older than a week, that's the staleness signal. Additionally,
  the pinned SHA's age can be measured directly:
  `git -C /tmp/vcpkg show -s --format='%ci' <sha>` after a
  `git clone --bare https://github.com/microsoft/vcpkg.git /tmp/vcpkg`.
- **rebar3** — the manual quarterly review is the staleness check.
  If the last commit touching `gateway/rebar.config` is more than 90
  days old, the review is overdue.

## CODEOWNERS auto-assignment

Dependabot can auto-assign PR reviewers via CODEOWNERS. This requires
`.github/CODEOWNERS` to exist, which is tracked in #366 (currently
blocked). Once #366 lands, add `codeowners: true`-style routing to the
dependabot entries so dependency PRs automatically ping the right
reviewer group.
