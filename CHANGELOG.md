# Changelog

All notable changes to Yuzu are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **BREAKING (licensing): Yuzu is now distributed under AGPL-3.0-or-later
  (community edition) with a separate commercial license for the new
  `enterprise/` subtree.** Previously the repository was Apache-2.0. The
  motivation is §13 of the AGPL: any operator running a modified Yuzu as a
  network service must offer the modified source to users of that service.
  This protects the commons and the viability of a commercial enterprise
  edition, which a permissive licence would not.

  Releases tagged v0.11.0-rc2 and earlier **remain licensed under
  Apache-2.0** for everyone who received them — Apache grants are perpetual
  and we are not retroactively re-licensing past code. The first release
  cut after this entry lands is the first AGPL-era release.

  Mechanical changes in this commit:
  - `LICENSE` replaced with the verbatim AGPL-3.0 text from
    `https://www.gnu.org/licenses/agpl-3.0.txt`.
  - New top-level `NOTICE` file records the copyright holder, relicensing
    history, dual-licensing boundary, SDK linking exception, and starter
    third-party attribution roll-up.
  - `meson.build` `license:` field → `AGPL-3.0-or-later`.
  - `vcpkg.json` `license` field → `AGPL-3.0-or-later`.
  - `gateway/apps/yuzu_gw/src/yuzu_gw.app.src` `licenses` → `["AGPL-3.0-or-later"]`
    (fixes a legacy `"Proprietary"` drift).
  - `deploy/docker/Dockerfile.ci-gateway`,
    `deploy/docker/Dockerfile.ci-linux`, and
    `.github/workflows/release.yml` OCI image-label `org.opencontainers.image.licenses`
    set to `AGPL-3.0-or-later` (the release-workflow entry previously
    incorrectly said `MIT`).
  - `README.md` License section rewritten to document the AGPL core, the
    enterprise SKU, and the SDK linking exception.

- **New `enterprise/` subtree — opt-in commercial module surface.** Added
  as empty scaffolding behind the new Meson option
  `-Denable_enterprise=true` (default `false`). Does not compile into OSS
  builds. Includes `enterprise/README.md`, a placeholder
  `enterprise/LICENSE-ENTERPRISE.md` (TODO: legal review before shipping
  paid builds), and `enterprise/meson.build`. First real premium feature
  (SAML/SSO) will land in a follow-up PR. See
  `docs/enterprise-edition.md`.

- **Contributor License Agreement (CLA) introduced.** New `CLA.md` (based
  on the Harmony 1.0 template, pending counsel review) assigns copyright
  to the project steward with a broad re-license grant covering both AGPL
  and commercial use. `CONTRIBUTING.md` updated to reference it; a
  disabled-by-default CLA-bot stub at `.github/workflows/cla.yml` is
  included — ops must provision `CLA_REPO_ACCESS_TOKEN` to activate.
  Accepting external contributions before activation would lock those
  contributions to AGPL-only.

- **Plugin SDK linking exception documented.** New `sdk/LICENSE-SDK.md`
  carves out dynamically-loaded plugins that consume only the stable
  `plugin.h` C ABI, analogous to the GCC Runtime Library / Classpath
  Exception. Proprietary plugins remain permitted. Wording must be
  legal-reviewed before the first AGPL-era release ships.


  + exclude vendored and generated paths from CodeQL scanning.** Two
  security-tooling follow-ups surfaced by the first real CodeQL scan
  after the Scorecard lift landed.
  - **Code injection fix.** CodeQL critical rule
    `actions/code-injection/critical` flagged line 49 of
    `.github/workflows/pre-release.yml`, where
    `${{ github.event.workflow_run.head_branch }}` was interpolated
    directly into the bash `run:` block of the "Determine version" step.
    `workflow_run` is an externally-influenced event trigger, and branch
    or tag names can carry shell metacharacters. Rebound both
    `head_branch` and the `workflow_dispatch` `inputs.tag` value to step-
    level `env:` entries (`EVENT_BRANCH`, `INPUT_TAG`) and reference them
    as shell variables — the canonical Actions security pattern.
  - **CodeQL scope.** Added `.github/codeql/codeql-config.yml` with a
    `paths-ignore` list (`vcpkg_installed/**`, `build-*/**`,
    `builddir*/**`, `_build/**`) and wired it into the `codeql-action/init`
    step via `config-file:`. Previously the scan indexed every header
    under `vcpkg_installed/x64-linux/include/` — protobuf, abseil,
    httplib — producing one "critical" (protobuf `map.h`) + six "high"
    (abseil `raw_hash_set.h`, protobuf tctable, httplib `non-https-url`)
    findings that are upstream-vendor bugs we cannot fix in-tree and
    would be erased by the next vcpkg cache rebuild. Excluding them
    collapses the noise and leaves first-party findings visible.

- **Isolate `yuzu_gw_real_upstream_SUITE` from CI's gateway CT discovery.**
  The suite needs a live `yuzu-server` reachable on `127.0.0.1:50055`
  AND `YUZU_GW_TEST_TOKEN` set (or `scripts/linux-start-UAT.sh` to have
  just run); CI provisions neither. Previously the suite was registered
  alongside the regular CT tree and ran as part of `meson test --suite
  gateway`, where it failed deterministically on the Windows MSVC runner
  (TCP probe to `:50055` succeeded against an unrelated listener bound by
  WSL2 port-forwarding from the same physical box, so the suite proceeded
  to the gRPC `ProxyRegister` call and exploded). Linux hid the failure
  because the self-hosted runner has no `rebar3` on PATH and the entire
  gateway CT step is skipped at meson configure time.
  - **Move:** `gateway/apps/yuzu_gw/test/yuzu_gw_real_upstream_SUITE.erl`
    → `gateway/apps/yuzu_gw/integration_test/yuzu_gw_real_upstream_SUITE.erl`.
    `git mv` so file history follows.
  - **rebar3 wiring:** add `{extra_src_dirs, [{"integration_test",
    [{recursive, false}]}]}` under the `test` profile in
    `gateway/rebar.config` so the moved suite still compiles in the test
    profile but is reachable only via explicit `--dir
    apps/yuzu_gw/integration_test`.
  - **CI invocation:** `scripts/test_gateway.py ct` (called by the meson
    `gateway ct` test target) keeps using `--dir apps/yuzu_gw/test` and
    no longer discovers the suite — verified locally: 6 suites / 52
    tests, all pass, no `yuzu_gw_real_upstream_SUITE` entry.
  - **`/test` invocation:** `.claude/skills/test/SKILL.md` Phase 5 now
    runs a second `gate_run "CT real-upstream"` step that targets `--dir
    apps/yuzu_gw/integration_test --suite=yuzu_gw_real_upstream_SUITE`,
    relying on Phase 4's `linux-start-UAT.sh` to have stood up the
    server and provisioned the enrollment token. Doc-comment in the
    SKILL warns about the prerequisites and the per-case
    `{test_case_failed, "No enrollment token: …"}` failure mode if
    either is missing.

- **CI dedup: drop `feature/**` and `fix/**` from the `push:` triggers in
  `ci.yml` and `docs-lint.yml`.** Pushes to feature/fix branches with an
  open PR previously fired both the `push` and `pull_request` events on
  the same SHA, doubling runner consumption for every commit pushed to a
  PR branch. Mainline branches (`main`, `dev`) remain on the `push:`
  list so merge runs still fire exactly once. Pre-PR work (no PR open
  yet) no longer runs CI automatically — open the PR earlier or use the
  existing `workflow_dispatch` trigger to fire it manually.

- **Digest-pin Dockerfile `FROM` lines, replace `curl | sh` installers,
  and hash-pin `requirements-ci.txt` (PR #3 of Scorecard lift).**
  Completes Scorecard's `Pinned-Dependencies` check — the remaining
  two-thirds after PR #2 addressed the GitHub Actions third. Changes:
  - **Dockerfile `FROM` digest pins.** Eight `deploy/docker/Dockerfile.*`
    base images were previously referenced by tag only
    (`ubuntu:24.04`, `erlang:28`, `alpine:3.23`). Pinned each to its
    current multi-arch index digest. `Dockerfile.runner-linux` — which
    seeds the self-hosted runner image on Shulgi — is now pinned to an
    exact digest of `ghcr.io/actions/actions-runner:latest`; Dependabot's
    `/deploy/docker` docker scope will continue to propose bumps as new
    runner releases ship.
  - **`curl | bash` NodeSource installs replaced with verified tarball
    download.** `Dockerfile.ci-linux` and `Dockerfile.ci-gateway` both
    installed Node.js 20 via `curl -fsSL https://deb.nodesource.com/setup_20.x | bash -`,
    which Scorecard flags as unverified code execution. Replaced with a
    direct `.tar.xz` download from `nodejs.org` + `sha256sum -c`
    verification. `NODE_VERSION` and `NODE_SHA256_LINUX_X64` are `ARG`
    pairs so bumps are atomic.
  - **Trivy installer replaced with `aquasecurity/trivy-action`.**
    `pre-release.yml` was installing Trivy via `curl -sfL … install.sh | sh`;
    swapped for the SHA-pinned `aquasecurity/trivy-action@57a97c7e…`
    (v0.35.0). **Scope clarification:** while making this swap, removed
    the Trivy SBOM generation step entirely — `release.yml` already emits
    authoritative Syft-based SBOMs via `anchore/sbom-action` for every
    platform archive and container image, so Trivy's SBOMs were a
    redundant second source that disagreed on component enumeration.
    Trivy now does vulnerability scanning only (its strength); Syft owns
    SBOM generation across the entire release pipeline.
  - **Hash-pinned `requirements-ci.txt` via `pip-compile --generate-hashes`.**
    Added `requirements-ci.in` as the human-edited source; `pip-compile`
    regenerates `requirements-ci.txt` with `--hash=sha256:…` continuation
    lines. Every `pip install -r requirements-ci.txt` call in `ci.yml`
    and `release.yml` now uses `--require-hashes`; a tampered package
    would fail the install rather than silently execute. macOS pipx grep
    path updated (`awk '/^meson==/ {print $1}'`) to handle the trailing
    `\` that `pip-compile` adds to hashed requirement lines. Bump cadence
    documented at `docs/dependency-updates.md`.
  - **Docker Compose image digests.** `docker-compose.local.yml` and the
    root `docker-compose.uat.yml` referenced `prom/prometheus:latest`,
    `grafana/grafana:latest`, and `clickhouse/clickhouse-server:latest`.
    Aligned all three with the digest-pinned variants already used under
    `deploy/docker/docker-compose*.yml` (Prometheus v3.2.1, Grafana
    11.5.2, ClickHouse 24.12). Two `clickhouse-server:24.12` tag-only
    refs under `deploy/docker/` also gained digests.

- **SHA-pin every GitHub Actions reference for OpenSSF Scorecard
  Pinned-Dependencies check (PR #2 of Scorecard lift).** Scorecard's
  `Pinned-Dependencies` check scored 0 because every `uses:` line in
  `.github/workflows/*.yml` resolved by tag (`@v6`, `@v3`, `@v0`) rather
  than by immutable commit SHA — a compromised upstream could silently
  repoint the tag at a malicious commit. Rewrote all 144 `uses:` refs
  across 12 workflow files to the form
  `owner/repo@<40-char-sha> # vX.Y.Z`; the trailing version comment is
  mandatory so Dependabot can still detect newer releases and propose
  coordinated SHA+comment bumps. Floating-major refs (`anchore/sbom-action@v0`,
  `ilammy/msvc-dev-cmd@v1`, `erlef/setup-beam@v1`, `bufbuild/buf-setup-action@v1`,
  plus two cases where the `v3` major tag lagged the latest point release —
  `actions/attest-build-provenance` and `sigstore/cosign-installer`) are
  pinned to the latest exact X.Y.Z SHA rather than the floating major's
  current SHA, so the pin doesn't drift back when the major tag is
  eventually updated. `github/codeql-action/init` and `/analyze` are pinned
  to the same parent-repo SHA per CodeQL's documented invariant.
  Self-hosted runners (`yuzu-wsl2-linux`, `yuzu-local-windows`) are
  unaffected — action pins control which code runs on the runner, not the
  runner image itself. PR #3 will pin the remaining two thirds of
  `Pinned-Dependencies` (Dockerfile FROMs + `curl | sh` installers +
  pip hash-pinning).
- **Group Dependabot GitHub Actions PRs.** After SHA-pinning, Dependabot
  opens one PR per action per bump — roughly 3× the pre-pin weekly
  volume. Added a `groups:` block under the `github-actions` ecosystem
  in `.github/dependabot.yml` to bundle related cohorts:
  `actions-core` (`actions/*`), `docker-actions` (`docker/*`), and
  `github-codeql` (`github/codeql-action/*`). Ungrouped actions still
  ship as individual PRs.

- **Tighten GitHub Actions token permissions for OpenSSF Scorecard
  Token-Permissions check.** Scorecard's Token-Permissions check scored 0
  because `qodana_code_quality.yml` had no top-level `permissions:` block
  (one missing block zeroes the entire check) and several workflows
  declared writes at workflow scope that only specific jobs actually
  needed. Changes:
  - `qodana_code_quality.yml`: new top-level `permissions: contents: read`;
    dropped unused job-level `contents: write` + `pull-requests: write`
    (pr-mode is false, so the action never opens PRs); kept `checks: write`
    at job scope.
  - `release.yml`: demoted top-level `contents: write` + `packages: write`
    to job scope. `id-token: write` and `attestations: write` stay at
    workflow scope because every build job calls
    `actions/attest-build-provenance`. The `release` job gets explicit
    `contents: write` + `id-token: write`; `docker-publish` already had
    its own explicit block.
  - `vcpkg-baseline-update.yml`: top-level `permissions: contents: read`;
    moved `contents: write` + `pull-requests: write` into the
    `propose-bump` job.
  - `ci.yml`: removed unused top-level `packages: write` (the workflow
    doesn't push to any registry); top-level is now `contents: read` only.

- **Wire `SCORECARD_READ_TOKEN` PAT into `scorecard.yml`.** Scorecard's
  `Branch-Protection` check caps at ~3/10 without a PAT because the
  public GitHub API can't read Repository Rulesets. The action now
  receives `repo_token: ${{ secrets.SCORECARD_READ_TOKEN || github.token }}`
  so the ruleset-aware code path runs once the secret is populated. The
  `|| github.token` fallback keeps fork runs and first-time-setup scans
  succeeding. PAT creation + rotation procedure documented at
  `docs/security/scorecard-token.md` — classic PAT with `public_repo` +
  `read:org` scopes ONLY; 90-day expiration with a 365-day rotation
  cadence.

### Added

- **Guardian PR 2 — REST control plane + agent-side `GuardianEngine`
  skeleton.** Stands up the operator-facing surface and the agent
  scaffolding the rest of the Windows-first rollout grafts onto. No real
  guards are running yet; PR 3 lands the Registry Guard + state evaluator
  + remediation that turns the wire path into actual enforcement.
  - **Server REST endpoints under `/api/v1/guaranteed-state/*`.** Full CRUD
    on rules (`GET / POST / GET :id / PUT :id / DELETE :id`) plus `POST
    /push` (returns `202 Accepted` — fan-out is PR 3), `GET /events`
    (paginated query mirroring `audit_store` semantics; `limit` capped at
    1000 at the REST boundary), `GET /status`, `GET /status/:agent_id`,
    and `GET /alerts`. Conflict detection routes through `kConflictPrefix`
    → HTTP 409 (matching #396/#399/#402). Created/updated rules carry the
    session principal in `created_by` / `updated_by`. Every mutating route
    fires an audit event under target type `GuaranteedState`.
  - **New RBAC operation `Push` + securable type `GuaranteedState`.**
    Distributes a rule set to scoped agents — separated from `Write` so
    operators can be granted "deploy existing rules" without "author new
    rules." Default seeds: `Operator` gets `Read + Push`,
    `PlatformEngineer` gets full CRUD + `Push`, `Administrator` and
    `ITServiceOwner` get the cross-type defaults, `Viewer` gets `Read`.
    The cross-type `Push` grants on non-Guardian securables are harmless
    because only the Guardian REST handlers consult `Push`.
  - **Agent-side `GuardianEngine` class** (`agents/core/src/guardian_engine.{hpp,cpp}`).
    Two-phase startup per design §4: `start_local()` runs pre-network so
    the engine is enforcing before the Register RPC opens; `sync_with_server()`
    runs post-Register and is the future drain point for buffered events.
    Persists rules into `KvStore` under reserved namespace `__guardian__`
    as JSON (binary-safe across the SQLite text APIs `KvStore` wraps).
    `dispatch()` answers `__guard__` plugin commands `push_rules` and
    `get_status`; reserved-name dispatch is intercepted in `agent.cpp`
    *before* the plugin match loop so a third-party plugin cannot shadow
    Guardian (defence-in-depth alongside the load-time reservation that
    landed in #453). PR 2 reports every rule as `errored` because no
    guards are running yet — honest about "Guardian installed but inert"
    until PR 3.
  - **`TestRouteSink` parses query strings.** The test sink now splits
    request paths on `?` and feeds the tail to `httplib::detail::`
    `parse_query_text`, populating `req.params`. This unblocks unit-level
    coverage of every existing handler that branches on `req.has_param`
    / `req.get_param_value` (the `events` query parameters were the
    forcing function). Out-of-scope for the PR but a free win for any
    follow-up REST test.

- **Guardian: agent rejects plugins declaring a reserved internal-dispatch
  name (#453).** The agent plugin loader now refuses to load any plugin whose
  `YuzuPluginDescriptor::name` matches the reserved set `__guard__`,
  `__system__`, `__update__`. Rejected plugins are logged at `error` and
  counted in `yuzu_agent_plugin_rejected_total{reason="reserved_name"}` so
  operators can alert on reserved-name attempts distinct from generic load
  failures. Prevents a compromised plugin author (or a misconfigured
  third-party plugin) from shadowing the `__guard__` dispatch intercept that
  Guardian PR 3 will add at `agents/core/src/agent.cpp`. Reserved-name
  namespace documented in `docs/cpp-conventions.md`.

- **Guardian PR 2 prerequisites (#452).** Pre-REST-endpoint hardening of the
  `GuaranteedStateStore` so PR 2's ingest path can land on a production-ready
  foundation:
  - **`std::expected<T, std::string>` mutators with `kConflictPrefix`.**
    `create_rule`, `update_rule`, `delete_rule`, and `insert_event` now
    return `std::expected<void, std::string>` and surface duplicate-UNIQUE
    / PRIMARY KEY collisions as `kConflictPrefix`-prefixed errors so REST
    handlers can map them to HTTP 409 (matching #396/#399/#402). Not-found
    paths return a distinct non-conflict error so routes can split 404 from
    409 cleanly.
  - **`created_by` / `updated_by` audit columns on `guaranteed_state_rules`.**
    Added to the v1 migration (before schema freeze). REST handlers in PR 2
    populate both from the session principal; SOC 2 audit-chain
    reconstruction can now answer "who authorised this rule version" from
    the store alone, with the full `audit_events` join procedure documented
    in `docs/yuzu-guardian-design-v1.1.md` §9.3.
  - **Retention reaper on `guaranteed_state_events`.** 30-day default
    (new `guardian_event_retention_days` config, overridable via runtime
    config). Events carry `ttl_expires_at` populated at insert; a
    background thread mirroring `AuditStore::run_cleanup` runs a periodic
    `DELETE`. Partial index `idx_gse_ttl WHERE ttl_expires_at > 0` keeps
    the reap query fast at fleet-scale ingest. `retention_days = 0`
    disables expiry for forensic freezes.
  - **Batch `insert_events(std::vector<…>)` API.** Wraps a `BEGIN…COMMIT`
    envelope; one fsync per batch instead of one per row (10–50× faster at
    agent batch sizes). Transactional — any failing row rolls back the
    whole batch so REST handlers never have to reason about partial state.
  - **Prometheus observability.** Four new server gauges — `yuzu_server_`
    `guardian_rules_total`, `guardian_events_total`,
    `guardian_events_written_total`, `guardian_events_reaped_total`. Wired
    into the existing health-recompute thread alongside `audit_store`'s
    gauges; sized at zero before ingest starts so alert rules
    (e.g. `yuzu_server_guardian_events_total > 5e6`) can be authored up
    front.
  - **Data inventory entry.** `guaranteed_state_events` recorded in the
    workstream-E data inventory (`docs/enterprise-readiness-soc2-first-customer.md` §3.5)
    with the 30-day retention policy, reaper mechanism, and sizing
    guidance for customers with longer forensic SLAs.

- **Guardian "Guaranteed State" engine — wire contract + server store
  skeleton (PR 1 of the Windows-first rollout).** Landed dormant: a new
  SQLite file `guaranteed-state.db` is created in the server data directory
  at startup and a `guaranteed_state_store` entry appears in the `/readyz`
  probe response. No REST endpoints, no dispatch, no agent wiring, and no
  dashboard surface in this release — PR 1 ships only the proto (new package
  `yuzu.guardian.v1` at `proto/yuzu/guardian/v1/guaranteed_state.proto`),
  the server SQLite store, and 17 unit test cases. Operators upgrading will
  see the new `.db` file alongside the existing stores (same permissions,
  same backup story: copy the full `--data-dir`) and the new `/readyz` JSON
  key. Full architecture: `docs/yuzu-guardian-design-v1.1.md`. Windows-first
  delivery plan: `docs/yuzu-guardian-windows-implementation-plan.md`.

- **Supply-chain attestation bundle: CycloneDX + SPDX SBOMs, SLSA
  provenance, and cosign image signatures on every release (#362,
  #408).** The release workflow now emits, per tag, a full verifiable
  supply-chain artefact set:
  - **CycloneDX + SPDX SBOMs per platform archive** via
    [Syft](https://github.com/anchore/syft) (`anchore/sbom-action@v0`):
    `yuzu-{linux-x64,gateway-linux-x64,windows-x64,macos-arm64}.{cdx,spdx}.json`.
    Syft picks up vcpkg C++ dependencies (reading vcpkg's generated
    `vcpkg.spdx.json` under `vcpkg_installed/<triplet>/share/`), Erlang
    deps from `gateway/rebar.lock`, and metadata on the built
    ELF/PE/Mach-O binaries.
  - **CycloneDX + SPDX SBOMs per Docker image**
    (`yuzu-{server,gateway}-image.{cdx,spdx}.json`) generated by Syft
    scanning the pushed image by digest, so the SBOM is bound to the
    exact image layers customers will pull.
  - **SLSA v1.0 build provenance attestations** for every binary archive,
    installer, and Docker image via `actions/attest-build-provenance@v3`.
    Stored in GitHub's native attestation registry and verified
    customer-side with `gh attestation verify <file> --repo Tr3kkR/Yuzu`
    (images: `oci://ghcr.io/.../<image>@sha256:<digest>`).
  - **cosign keyless Docker image signing** for both
    `ghcr.io/tr3kkr/yuzu-server` and `ghcr.io/tr3kkr/yuzu-gateway`,
    bound to the release workflow's OIDC identity (no static keys to
    rotate). Existing cosign blob signature on `SHA256SUMS` is retained.
  - **New release-gate script** at
    `scripts/check-release-artifacts.sh` runs before `gh release create`
    and fails the release if any expected archive, installer, or SBOM
    is missing — preventing partially-attested releases from ever
    reaching customers.
  - **New operator doc** at
    [`docs/user-manual/release-verification.md`](docs/user-manual/release-verification.md)
    covers `sha256sum -c`, `cosign verify-blob`, `cosign verify` (images),
    `gh attestation verify` (binaries + images), and CycloneDX / SPDX
    inspection with `jq` and the CycloneDX CLI. Includes an end-to-end
    verification script and a compliance-mapping table (SOC 2 CC6.8 /
    CC7.1, NIST SSDF PW.5 / PS.3, EO 14028, EU CRA Annex V).
  - Top-level workflow permissions extended with `attestations: write`
    (required by `actions/attest-build-provenance`); `docker-publish`
    job gains `id-token: write` + `attestations: write`. `SHA256SUMS`
    now covers the SBOM files so customers can verify them alongside
    the archives. Release notes heredoc advertises the new verification
    workflow and links to the operator doc.
  - Effective at the next tag after merge. No CHANGELOG gate on
    historical releases — retro-generating provenance for shipped tags
    is out of scope.
- **OpenSSF Scorecard + Zizmor workflows (#407).** Added
  `.github/workflows/scorecard.yml` (weekly + push to main +
  `branch_protection_rule`; publishes to scorecard.dev + SARIF to the
  GitHub Security tab) and `.github/workflows/zizmor.yml` (static
  analyzer for `.github/workflows/*.yml`, runs on workflow-touching PRs
  + weekly). README now advertises the Scorecard and Zizmor badges; the
  OpenSSF Best Practices Badge slot is wired up pending manual
  application at bestpractices.dev. Triaging Scorecard findings into
  follow-up issues is the remaining work on #407.
- **README `Install`, `Contributing`, `Reporting Issues` sections
  (#407).** Addresses the OpenSSF Best Practices `[interact]` criterion
  — README now points prebuilt-binary users at GitHub Releases +
  `ghcr.io/tr3kkr/yuzu-{server,gateway,agent}` + `deploy/docker/docker-compose.yml`
  instead of only documenting the from-source build. Adds explicit
  links to `CONTRIBUTING.md`, `CLAUDE.md`, the bug-report and
  feature-request issue templates, `SECURITY.md` (private vulnerability
  reporting), and GitHub Discussions.

### Fixed

- **Guardian PR 2 hardening round 5 — doc-RR1..doc-RR4 (documentation only).**
  Closes the BLOCKING and SHOULD doc findings from the second governance
  re-run on `21c0ba4..HEAD` (rounds 3 + 4). Pure documentation — no code
  changes, no behaviour changes. The re-run confirmed that rounds 3 + 4
  introduced no new code regressions; all remaining findings were either
  doc precision gaps or pre-existing patterns newly visible after the
  `/push` sanitisation fix (filed as follow-up issues).
  - **`docs/user-manual/audit-log.md` `guaranteed_state.push` entry now
    documents the scope-sanitisation semantic** (doc-RR1). The SIEM-
    parser-facing description previously read `scope="<expr>"` as if the
    value were verbatim operator input; after round 3's UP-R3 fix the
    value is backslash-escaped for `"` and `\` and stripped of C0 control
    bytes before embedding. The entry now names the normalisation
    explicitly with a concrete example (`env="prod"` → `scope="env=\"prod\""`)
    so SIEM rule authors don't build parsers against the wrong shape.
    The `fan_out_deferred_pr3=true` marker and the non-object-body 400
    rejection are also called out in the same row.
  - **`guaranteed_state.rule.update` entry now lists 400 invalid-body as
    an explicit denied-audit case** (doc-RR2). Round 4's UP-R1 fix emits
    `result=denied` when the PUT body is unparseable JSON; the audit-log
    page did not reflect this in its per-action row or in the result
    vocabulary prose. Both now name the specific 400 branch alongside the
    existing 404/409 cases. The result-vocabulary paragraph gains a SIEM
    filter hint: "filter on `result == "denied"` scoped to the actions
    you care about — every mutating branch produces a row."
  - **`docs/user-manual/upgrading.md` v0.12.0 section gains a negative-
    retention behaviour change note** (doc-RR3). Pre-round-4 the `PUT
    /api/v1/config/<retention-key>` handler silently accepted negative
    values and the store treated `<= 0` as "never reap"; post-round-4 the
    handler rejects with 400 and operators must use `0` explicitly to
    preserve the disable-retention semantic. Also documents that non-
    numeric values (which were previously silent no-ops) now return 400 —
    surfacing configuration errors that had been hidden.
  - **Upgrading.md's RBAC remediation SQL is now a 4-step guarded
    procedure instead of a single destructive one-liner** (doc-RR4). The
    single `DELETE` block was replaced with: (1) back up `rbac.db`
    first, (2) run a `SELECT` preview and review the rows, (3) `DELETE`
    scoped to `principal_id IN ('Administrator', 'ITServiceOwner')` so a
    custom role with a legitimate non-Guardian Push grant is left alone,
    (4) re-run the preview to confirm cleanup. Same remediation, defence-
    in-depth wrapping. `principal_id` scoping matches what the bug
    actually produced — seeded roles only.

- **Guardian PR 2 hardening round 4 — UP-R1, UP-R5, and SHOULD-tier docs.**
  Small, code-local MEDIUM/SHOULD items from the governance re-run that did
  not require architectural decisions. Systemic items (retention runtime-PUT
  propagation across 3 stores, PUT TOCTOU optimistic concurrency, RBAC
  upgrade migration, audit action namespace flatten, `.get<T>()` sweep
  across 12 non-Guardian handlers, `TempDbFile` RAII adoption) are filed as
  tracking issues #483, #484, #485, #486, #487, #488 and excluded from this
  round to keep the commit focused.
  - **PUT `/api/v1/guaranteed-state/rules/:id` 400 invalid-body branch now
    emits a `denied` audit** (UP-R1). Previously the handler rejected
    malformed JSON with `400 {"error":"invalid JSON"}` but produced no
    audit record, while the sibling `/push` 400 branch did — asymmetric
    audit coverage across two branches shipped in the same hardening round.
    Added a regression test (`[rest][guaranteed_state][crud]`) that POSTs a
    non-object body and asserts the denied audit fires with the correct
    action, target, and detail fields.
  - **`PUT /api/v1/config/<key>` now validates integer-typed values before
    persisting** (UP-R5). The prior implementation called
    `runtime_config_store_->set(key, value, ...)` first, then wrapped
    `std::stoi(value)` in `try { ... } catch (...) {}`. Any non-numeric or
    negative value persisted to the store while silently failing to update
    `cfg_` — an operator PUTting `{"value":"abc"}` received `200 {"applied":
    true}` with no behaviour change, and on the next restart the invalid
    string loaded back into `RuntimeConfigStore`. Replaced with
    `std::from_chars`-based validation that runs **before** the `set` call
    and rejects with `400 {"error":{"code":400,"message":"value must be a
    non-negative integer"}}` on any parse failure. Applies to
    `heartbeat_timeout`, `response_retention_days`, `audit_retention_days`,
    and `guardian_event_retention_days`. The `try { stoi } catch (...) {}`
    blocks in the startup-config parser remain for now because that path
    has no 400 to return — this fix targets the runtime API only.
  - **`docs/user-manual/server-admin.md` Retention Settings table documents
    `--guardian-event-retention-days`** (doc-S2). Third row added alongside
    the existing `--response-retention-days` and `--audit-retention-days`
    entries. Supporting prose updated to describe the env-var alternatives
    (`YUZU_*_RETENTION_DAYS`) and the runtime `PUT /api/v1/config` path,
    with an explicit "takes effect on restart" caveat cross-referencing
    issue #483.
  - **`CHANGELOG.md` round-1 BL-4 entry annotated with the H-4 correction**
    (doc-S3). The 19×6=114 formula describing Administrator's seed count
    was accurate at BL-4 commit time but implicitly superseded by round 2's
    H-4 fix (which removed `Push` from the cross-type seed, reducing
    Administrator to 96 and ITServiceOwner to 81). Inline note added so a
    reader walking the CHANGELOG forward sees the correction before the
    implausible math statement.
  - **`CLAUDE.md` Guardian section expanded with the invariants that keep
    surfacing in governance** (N1 + N3). Three resident notes: (a) `Push`
    seed is Guardian-only — `ops[]` is the catalogue, `crud_ops[]` is the
    cross-type seed, do not cross-seed `Push`; (b) reserved plugin name
    `__guard__` has load-time rejection AND dispatch-time intercept, both
    halves must stay; (c) Guardian wire payloads carrying raw proto bytes
    must not be placed in `map<string, string>` fields the Erlang gateway
    re-encodes via `gpb:e_type_string` — UTF-8 validation crashes. New
    "Test conventions — shared helpers" section points at
    `tests/unit/test_helpers.hpp` and names the `std::hash<thread::id>` +
    `steady_clock` anti-pattern as the flake #473 vector.
  - **`docs/user-manual/upgrading.md` gains a v0.12.0 Guardian PR 2 section**
    (N2). Documents two operator-visible upgrade notes: the stale `*:Push`
    RBAC grants on deployments that ran pre-hardening code (with manual
    remediation SQL pending the #485 auto-migration), and the
    "retention PUT takes effect on restart" limitation shared across the
    three retention stores (cross-ref #483).

- **Guardian PR 2 hardening round 3 — UP-R3, doc-B1, doc-B2, UP-R9.** Closes
  the BLOCKING findings from the governance re-run on `a90a21e..HEAD`
  (rounds 1 + 2). Pattern C confirmed: the first two hardening rounds
  themselves introduced one new security regression and two doc regressions
  that this round addresses.
  - **`/push` audit detail now sanitises the scope value before embedding**
    (UP-R3 — new regression introduced by BL-6's audit format change). The
    BL-6 vocabulary fix formatted detail as `rules=N full_sync=B scope="<scope>"
    fan_out_deferred_pr3=true`, embedding operator-controlled scope between
    raw quotes. An operator with `GuaranteedState:Push` could therefore POST
    `{"scope":"x\" result=\"denied\" fake=\""}` and forge audit-record
    fragments that parse downstream as successful-looking denials — audit log
    integrity is a SOC 2 Workstream F control, so this is a real injection
    vector. Added an inline `sanitize_audit_string` lambda that
    backslash-escapes `"` and `\` and drops all C0 control bytes (CR/LF/NUL/
    TAB and the rest of 0x00–0x1F + DEL). audit_store writes the string as
    an opaque column so the sanitisation is defensive at the SIEM layer —
    but that's the layer compliance evidence is reconstructed from. Test
    `test_rest_guaranteed_state.cpp` gains a `[security]`-tagged regression
    guard that POSTs an adversarial scope and asserts no control bytes, no
    unescaped top-level injection tokens, and the structural frame of the
    detail remains intact.
  - **RBAC matrix tables in `docs/user-manual/guaranteed-state.md` and
    `docs/user-manual/rest-api.md` now show all 6 operation columns**
    (doc-B1 — new regression introduced by my BL-4 doc authoring). The
    tables as first written showed 4 columns (Read/Write/Delete/Push) and
    silently omitted Execute + Approve. Administrator and ITServiceOwner
    actually receive Execute and Approve on `GuaranteedState` via the
    `crud_ops[]` cross-type seed loop in `rbac_store.cpp`; the tables now
    reflect that. PlatformEngineer's row is narrower (Read/Write/Delete/Push
    — no Execute, no Approve) because its grants are explicit and targeted,
    not cross-type. Added a clarifying paragraph beneath each table noting
    the cross-seed origin of the Execute/Approve grants — this sets
    expectations for future readers that those ops exist in the DB but have
    no active Guardian handler today.
  - **`docs/user-manual/guaranteed-state.md` PR-2 status banner now matches
    the actual audit vocabulary** (doc-B2 — new regression introduced by
    BL-6 + my BL-8 doc authoring). The banner still said "audited as
    `accepted`" while the rest of the same file (and the code) use
    `result=success` with `fan_out_deferred_pr3=true` in the detail field.
    Updated the banner to match. Internal doc contradiction closed.
  - **`openapi_spec()` 503 description strings aligned with the runtime body
    strings** (UP-R9 / sec-L3 — H-7's scope miss). H-7 changed nine runtime
    `error_json("service unavailable", 503)` calls but left three OpenAPI
    path-entry `"503": {"description": "..."}` strings at the old "guaranteed-
    state store unavailable" wording. Client libraries generated from the
    spec saw a description that never matched the actual response body.
    Consolidated.

- **Guardian PR 2 hardening round 2 — H-3, H-4, H-7, H-8.** Second hardening
  round after the BL-1..BL-9 commit on the same governance run. Closes the
  HIGH findings that were small enough to fold into a single commit; the
  remaining HIGHs (H-1 read-side audit gap, H-2 plugin-loader RCE, H-5 gateway
  UTF-8 crash, H-6 apply_rules atomicity) are tracked as issues #477 / #478 /
  #479 and will land separately.
  - **PUT `/api/v1/guaranteed-state/rules/:id` stops type-mismatched bodies
    from surfacing as HTTP 500** (H-3). The handler was using
    `body["k"].get<T>()` which raises `nlohmann::json::type_error` on a
    type-mismatched field (e.g. `{"enabled": "yes"}`); without a server-wide
    `set_exception_handler`, httplib's default path returns 500 with an empty
    body. Swapped to `body.value("k", existing)` matching the sibling POST
    handler — type-mismatched fields silently fall back to the current value
    rather than converting a client-side request-shape mistake into a server-
    error alertable event.
  - **`Push` operation seeding restricted to `GuaranteedState`** (H-4). The
    previous cross-type seed granted `Administrator` and `ITServiceOwner`
    the `Push` op on every securable type — harmless today because only the
    Guardian REST handlers consult `Push`, but a latent privilege grant that
    any future handler reading `perm_fn(..., "Push")` on a non-Guardian
    securable would silently accept. `ops[]` is now split into `ops[]` (all
    six, seeded into the operations catalogue) and `crud_ops[]` (the five
    used for cross-type role seeding). Push is granted explicitly on
    `GuaranteedState` for `Administrator` and `ITServiceOwner`, matching
    the already-targeted grants for `Operator` and `PlatformEngineer`.
    Test assertions updated: Administrator 114 → 96 permissions,
    ITServiceOwner 96 → 81 permissions, plus new invariant checks that
    verify `Push` exists exactly once per role and only on `GuaranteedState`.
    `rbac.md` counts updated to match.
  - **503 error body vocabulary consolidated** (H-7). Nine Guardian 503
    sites previously returned `"guaranteed-state store unavailable"`; every
    other 503 site in `rest_api_v1.cpp` uses `"service unavailable"`.
    Log-based alerting that greps the sibling string will now match Guardian
    store outages too.
  - **New `tests/unit/test_helpers.hpp` replaces the stale `thread::id`-hash
    + `steady_clock` uniqueness pattern across 5 test files** (H-8, closes
    #482). The pattern that commit a90a21e replaced in
    `test_guardian_engine.cpp` for Windows MSVC flake #473 is now extinct
    in `test_rest_guaranteed_state.cpp`, `test_rest_api_tokens.cpp`,
    `test_rest_api_t2.cpp`, and `test_kv_store.cpp`. Shared header provides
    `unique_temp_path(prefix)` with a process-local `mt19937_64`-seeded
    salt + atomic monotonic counter, and `TempDbFile` RAII wrapper cleaning
    up `.db` / `-wal` / `-shm` companions. Header-only inline impl so each
    test binary owns its own salt and counter; no shared-state hazard.

- **Guardian PR 2 hardening round — governance Gate 7 BL-1..BL-9.** Consolidates
  the blocking findings from the `/governance b13ff17~1..HEAD` run on
  `feat/guardian-pr2`. No new functionality; closes the gaps between Guardian
  PR 2's implementation and the operator, SIEM, and SOC 2 contracts it shipped
  against.
  - **`/healthz` + dashboard health fragment now include
    `guaranteed_state_store` in the `all_stores_ok` conjunction** (BL-1). Prior
    to this fix, `/healthz` reported `"healthy"` while `/api/v1/guaranteed-state/*`
    returned `503` — the readiness-probe regression pattern (HC-1) that prior
    governance runs have caught on every new load-bearing store addition.
    Matches the `/readyz` per-store check which was already correct.
  - **`guardian_event_retention_days` is now actually overridable** (BL-2). The
    field was declared in `ServerConfig` with a default of 30 but had no CLI
    flag and no runtime-config parser branch, so the CHANGELOG's
    "overridable via runtime config" and the SOC 2 data-inventory doc's
    "configurable" claims were false. Adds the `--guardian-event-retention-days`
    CLI flag (+ `YUZU_GUARDIAN_EVENT_RETENTION_DAYS` env var), the `GET /api/config`
    response key, the runtime `PUT /api/config/guardian_event_retention_days`
    branch, the `RuntimeConfigStore::allowed_keys` entry, and the startup-config
    parser branch — all matching the `audit_retention_days` pattern.
  - **All 10 `/api/v1/guaranteed-state/*` routes now appear in the OpenAPI
    spec served at `/api/v1/openapi.json` and in
    `docs/user-manual/rest-api.md`** (BL-3). Adds `GuaranteedStateRule`,
    `GuaranteedStateStatus`, and `GuaranteedStateEvent` schema components plus
    per-path entries with security, request/response bodies, and status codes.
    Rest-api.md gains a full "Guaranteed State" section with the RBAC matrix,
    every endpoint's permission, request/response shape, and error paths.
  - **`docs/user-manual/rbac.md` updated for `GuaranteedState` and `Push`**
    (BL-4). Adds the securable type and operation, recomputes role permission
    counts (Administrator 19×6=114, ITServiceOwner 16×6=96, Viewer 18×1=18) to
    match code, and documents `Push` as the deploy-authority-without-author
    operation consumed only by the Guardian REST handlers. **Note:** the 19×6
    arithmetic is correct for the state at BL-4 commit time; the subsequent
    H-4 fix in hardening round 2 (entry directly above) restricted `Push`
    from the cross-type seed loop, reducing Administrator to 96 and
    ITServiceOwner to 81. The final values that ship are Administrator 96,
    ITServiceOwner 81, Viewer 18.
  - **`docs/user-manual/audit-log.md` adds the four Guardian audit actions**
    (BL-5). `guaranteed_state.rule.create / update / delete / push`. The push
    entry explicitly warns SIEM rule authors that `fan_out_deferred_pr3=true`
    in the detail field means "server accepted the push but agent delivery is
    deferred" — misreading this as delivered would be premature until the PR 3
    fan-out lands.
  - **`/push` audit vocabulary aligned with sibling handlers** (BL-6 /
    consistency-auditor F3). Previously emitted `result="accepted"` with
    `target_id=<scope>` — a novel result string and a target_id that broke
    SIEM joins (every other audit site uses a concrete entity id in target_id).
    Now emits `result="success"` with `target_id=""` (pushes are fleet-level,
    not per-entity) and `detail=rules=N full_sync=B scope="E" fan_out_deferred_pr3=true`.
    Also rejects non-object JSON bodies with `400` + denied audit (previously
    silently coerced to empty object), and replaces the engineer-facing
    `note: "fan-out lands in Guardian PR 3"` in the response body with the
    stable operational phrase `"push accepted; agent delivery is asynchronous"`.
  - **`/status` and `/status/:agent_id` field names match the agent-side proto**
    (BL-7 / consistency-auditor F1). REST previously returned `compliant`,
    `drifted`, `errored`; the proto `GuaranteedStateStatus` uses
    `compliant_rules`, `drifted_rules`, `errored_rules`. Renamed REST keys
    to the `_rules` suffix before any downstream dashboard locks in the drift.
    Per-agent status response gains `total_rules` for symmetry.
  - **New operator-facing page `docs/user-manual/guaranteed-state.md`** (BL-8).
    Covers the PR-2 limitation ("control plane + agent skeleton; no enforcement
    until PR 3"), the YAML rule schema, the create/push/query workflow with
    `curl` examples, the RBAC matrix, retention configuration, and the
    `/healthz` / `/readyz` observability surface. Linked from the user-manual
    README table of contents.
  - **Windows Defender exclusion script now refuses to run on non-runner
    hosts** (BL-9). `scripts/windows-runner-defender-exclusions.ps1` previously
    would silently weaken Defender coverage on a dev workstation if run by
    mistake (it excludes `%USERPROFILE%\AppData\Local\ccache` and
    `C:\WINDOWS\SystemTemp\yuzu_test_*` — paths that exist on dev boxes). Adds
    a hostname allowlist (default `^yuzu-local-windows`, overridable via
    `-AllowedHostPattern` when provisioning a new runner) that errors out
    before any `Add-MpPreference` call runs.

- **`/api/health` reports the actual server version instead of the
  hardcoded "0.1.0" (#401).** The endpoint now derives the version
  string from the meson-generated `yuzu/version.hpp` constant
  `kVersionString`, so health probes track the running build (currently
  `0.11.0`) rather than a stale literal that survived the v0.10.x cycle.
- **`docker-compose.uat.yml` now passes `--data-dir /var/lib/yuzu` to
  the server (#389).** Without the flag, all SQLite stores fell back to
  the working directory (`/etc/yuzu`) instead of the persistent volume
  mount — agent registrations, audit log, and tokens were lost on
  container restart. The other compose files (`docker-compose.local.yml`,
  `deploy/docker/docker-compose.full-uat.yml`) already passed the flag;
  the UAT file was the outlier.
- **`POST /api/settings/users` returns 409 on duplicate username (#399).**
  Previously the endpoint silently overwrote an existing account via
  `AuthManager::upsert_user` — a privilege-escalation primitive in the
  hands of any authenticated admin attacker. The endpoint now rejects
  duplicates with HTTP 409, an `HX-Trigger` toast (`"Username already
  exists"`), and a denied audit event
  (`user.upsert / denied / duplicate_username`). Self-password-change
  (same username, same role) is still allowed.
- **`POST /api/instructions` returns 409 on duplicate explicit `id`
  (#402).** Previously returned a generic 400 (`"insert failed"`); the
  store now pre-checks under the existing write lock and surfaces a
  structured 409 (`{"error":"instruction definition '<id>' already
  exists"}`) plus a denied audit event
  (`instruction.create / denied / duplicate_id`). Empty `id` paths still
  generate a UUID with no duplicate-check overhead.
- **`POST /api/policy-fragments` returns 409 on duplicate fragment name
  (#396).** Previously silently inserted a duplicate row; the store now
  rejects with HTTP 409 (`{"error":"policy fragment named '<name>'
  already exists"}`) plus a denied audit event
  (`policy_fragment.create / denied / duplicate_name`).

### Tests

- Added `tests/unit/server/test_store_errors.cpp` exercising the shared
  `kConflictPrefix` constant and `is_conflict_error` /
  `strip_conflict_prefix` helpers introduced for the route↔store conflict
  contract (governance Gate 3 arch-B1).
- Added duplicate-detection cases to `test_settings_routes_users.cpp`,
  `test_instruction_store.cpp`, and `test_policy_store.cpp`. The
  pre-existing "duplicate ID" policy-store test was tightened to assert
  the new `kConflictPrefix` semantics.
- Added `tests/unit/fixtures/reserved_name_plugin.cpp` — a test plugin
  declaring the reserved `__guard__` name — plus three new test cases in
  `tests/unit/test_plugin_loader.cpp` (`is_reserved_plugin_name`
  predicate, `kReservedPluginNames` namespace pin, and a behavioural
  scan-rejection test that copies the fixture into a temp directory and
  asserts `PluginLoader::scan` refuses to load it). The fixture is built
  as a `shared_library` in `tests/meson.build` and wired as a `depends:`
  of the agent test runner so it's on disk before the test runs.
- Expanded `tests/unit/server/test_guaranteed_state_store.cpp` for
  the #452 surface: new cases for `kConflictPrefix`-formatted duplicate
  errors on both `name` and `rule_id`, conflict on rename-into-existing
  name, batch `insert_events` happy path + transactional rollback on
  mid-batch collision, `created_by` / `updated_by` round-trip, and TTL
  reaper delete mechanics (including `retention_days=0` sentinel).
- Added `tests/unit/test_guardian_engine.cpp` (13 cases, 79 assertions)
  for the agent-side `GuardianEngine` ingest contract: `apply_rules`
  persists rules + bumps generation, `full_sync` wipes the prior set,
  delta merge keeps prior rules and updates overlap, empty `rule_id` is
  skipped, `dispatch` round-trips `push_rules` through proto
  `SerializeAsString`, `dispatch get_status` returns a serialised
  `GuaranteedStateStatus`, missing `push` parameter / garbage proto map
  to distinct exit codes, rule cache + `policy_generation` survive an
  in-process engine reconstruct against the same `KvStore`, null-`KvStore`
  construction degrades gracefully, and post-`stop()` `apply_rules`
  fails. Bumps the agent test suite's `agent_test_exe` deps with
  `yuzu_proto_dep` (the test constructs proto messages directly).
- Added `tests/unit/server/test_rest_guaranteed_state.cpp` (11 cases,
  88 assertions) for the `/api/v1/guaranteed-state/*` REST surface:
  `201` on create with `rule_id` echoed, `400` on missing required
  fields, `409` mapping from `kConflictPrefix` for duplicate name, full
  list/get/update/delete round-trip with version bump, `404` on unknown
  ids with denied-audit, `202` on `/push` with rule count + scope in the
  audit detail, `events` filter + `limit` pagination, `400` on invalid
  `limit`, `status` rollup, and `alerts` placeholder. Built against the
  in-process `TestRouteSink` (no live `httplib::Server`, no #438 TSan
  trap).
- Updated `tests/unit/server/test_rbac_store.cpp`: bumped securable-type
  count to 19, operations count to 6, `Administrator` perms to 114 (19
  × 6), `Viewer` to 18, and `ITServiceOwner` to 96 (16 × 6) — all
  knock-ons from adding the `GuaranteedState` securable type and the
  `Push` operation seeded for PR 2.


## [0.11.0-rc2] - 2026-04-20

### Added

- **Guardian "Guaranteed State" engine — wire contract + server store
  skeleton (PR 1 of the Windows-first rollout).** Landed dormant: a new
  SQLite file `guaranteed-state.db` is created in the server data directory
  at startup and a `guaranteed_state_store` entry appears in the `/readyz`
  probe response. No REST endpoints, no dispatch, no agent wiring, and no
  dashboard surface in this release — PR 1 ships only the proto (new package
  `yuzu.guardian.v1` at `proto/yuzu/guardian/v1/guaranteed_state.proto`),
  the server SQLite store, and 17 unit test cases. Operators upgrading will
  see the new `.db` file alongside the existing stores (same permissions,
  same backup story: copy the full `--data-dir`) and the new `/readyz` JSON
  key. Full architecture: `docs/yuzu-guardian-design-v1.1.md`. Windows-first
  delivery plan: `docs/yuzu-guardian-windows-implementation-plan.md`.

- **Supply-chain attestation bundle: CycloneDX + SPDX SBOMs, SLSA
  provenance, and cosign image signatures on every release (#362,
  #408).** The release workflow now emits, per tag, a full verifiable
  supply-chain artefact set:
  - **CycloneDX + SPDX SBOMs per platform archive** via
    [Syft](https://github.com/anchore/syft) (`anchore/sbom-action@v0`):
    `yuzu-{linux-x64,gateway-linux-x64,windows-x64,macos-arm64}.{cdx,spdx}.json`.
    Syft picks up vcpkg C++ dependencies (reading vcpkg's generated
    `vcpkg.spdx.json` under `vcpkg_installed/<triplet>/share/`), Erlang
    deps from `gateway/rebar.lock`, and metadata on the built
    ELF/PE/Mach-O binaries.
  - **CycloneDX + SPDX SBOMs per Docker image**
    (`yuzu-{server,gateway}-image.{cdx,spdx}.json`) generated by Syft
    scanning the pushed image by digest, so the SBOM is bound to the
    exact image layers customers will pull.
  - **SLSA v1.0 build provenance attestations** for every binary archive,
    installer, and Docker image via `actions/attest-build-provenance@v3`.
    Stored in GitHub's native attestation registry and verified
    customer-side with `gh attestation verify <file> --repo Tr3kkR/Yuzu`
    (images: `oci://ghcr.io/.../<image>@sha256:<digest>`).
  - **cosign keyless Docker image signing** for both
    `ghcr.io/tr3kkr/yuzu-server` and `ghcr.io/tr3kkr/yuzu-gateway`,
    bound to the release workflow's OIDC identity (no static keys to
    rotate). Existing cosign blob signature on `SHA256SUMS` is retained.
  - **New release-gate script** at
    `scripts/check-release-artifacts.sh` runs before `gh release create`
    and fails the release if any expected archive, installer, or SBOM
    is missing — preventing partially-attested releases from ever
    reaching customers.
  - **New operator doc** at
    [`docs/user-manual/release-verification.md`](docs/user-manual/release-verification.md)
    covers `sha256sum -c`, `cosign verify-blob`, `cosign verify` (images),
    `gh attestation verify` (binaries + images), and CycloneDX / SPDX
    inspection with `jq` and the CycloneDX CLI. Includes an end-to-end
    verification script and a compliance-mapping table (SOC 2 CC6.8 /
    CC7.1, NIST SSDF PW.5 / PS.3, EO 14028, EU CRA Annex V).
  - Top-level workflow permissions extended with `attestations: write`
    (required by `actions/attest-build-provenance`); `docker-publish`
    job gains `id-token: write` + `attestations: write`. `SHA256SUMS`
    now covers the SBOM files so customers can verify them alongside
    the archives. Release notes heredoc advertises the new verification
    workflow and links to the operator doc.
  - Effective at the next tag after merge. No CHANGELOG gate on
    historical releases — retro-generating provenance for shipped tags
    is out of scope.
- **OpenSSF Scorecard + Zizmor workflows (#407).** Added
  `.github/workflows/scorecard.yml` (weekly + push to main +
  `branch_protection_rule`; publishes to scorecard.dev + SARIF to the
  GitHub Security tab) and `.github/workflows/zizmor.yml` (static
  analyzer for `.github/workflows/*.yml`, runs on workflow-touching PRs
  + weekly). README now advertises the Scorecard and Zizmor badges; the
  OpenSSF Best Practices Badge slot is wired up pending manual
  application at bestpractices.dev. Triaging Scorecard findings into
  follow-up issues is the remaining work on #407.
- **README `Install`, `Contributing`, `Reporting Issues` sections
  (#407).** Addresses the OpenSSF Best Practices `[interact]` criterion
  — README now points prebuilt-binary users at GitHub Releases +
  `ghcr.io/tr3kkr/yuzu-{server,gateway,agent}` + `deploy/docker/docker-compose.yml`
  instead of only documenting the from-source build. Adds explicit
  links to `CONTRIBUTING.md`, `CLAUDE.md`, the bug-report and
  feature-request issue templates, `SECURITY.md` (private vulnerability
  reporting), and GitHub Discussions.

### Fixed

- **`/api/health` reports the actual server version instead of the
  hardcoded "0.1.0" (#401).** The endpoint now derives the version
  string from the meson-generated `yuzu/version.hpp` constant
  `kVersionString`, so health probes track the running build (currently
  `0.11.0`) rather than a stale literal that survived the v0.10.x cycle.
- **`docker-compose.uat.yml` now passes `--data-dir /var/lib/yuzu` to
  the server (#389).** Without the flag, all SQLite stores fell back to
  the working directory (`/etc/yuzu`) instead of the persistent volume
  mount — agent registrations, audit log, and tokens were lost on
  container restart. The other compose files (`docker-compose.local.yml`,
  `deploy/docker/docker-compose.full-uat.yml`) already passed the flag;
  the UAT file was the outlier.
- **`POST /api/settings/users` returns 409 on duplicate username (#399).**
  Previously the endpoint silently overwrote an existing account via
  `AuthManager::upsert_user` — a privilege-escalation primitive in the
  hands of any authenticated admin attacker. The endpoint now rejects
  duplicates with HTTP 409, an `HX-Trigger` toast (`"Username already
  exists"`), and a denied audit event
  (`user.upsert / denied / duplicate_username`). Self-password-change
  (same username, same role) is still allowed.
- **`POST /api/instructions` returns 409 on duplicate explicit `id`
  (#402).** Previously returned a generic 400 (`"insert failed"`); the
  store now pre-checks under the existing write lock and surfaces a
  structured 409 (`{"error":"instruction definition '<id>' already
  exists"}`) plus a denied audit event
  (`instruction.create / denied / duplicate_id`). Empty `id` paths still
  generate a UUID with no duplicate-check overhead.
- **`POST /api/policy-fragments` returns 409 on duplicate fragment name
  (#396).** Previously silently inserted a duplicate row; the store now
  rejects with HTTP 409 (`{"error":"policy fragment named '<name>'
  already exists"}`) plus a denied audit event
  (`policy_fragment.create / denied / duplicate_name`).

### Tests

- Added `tests/unit/server/test_store_errors.cpp` exercising the shared
  `kConflictPrefix` constant and `is_conflict_error` /
  `strip_conflict_prefix` helpers introduced for the route↔store conflict
  contract (governance Gate 3 arch-B1).
- Added duplicate-detection cases to `test_settings_routes_users.cpp`,
  `test_instruction_store.cpp`, and `test_policy_store.cpp`. The
  pre-existing "duplicate ID" policy-store test was tightened to assert
  the new `kConflictPrefix` semantics.

## [0.11.0] - 2026-04-17

_Minor bump from v0.10.0. The original `0.10.1` dev bump in `0c976c7`
predated the `feat(test)` commits that landed the `/test` skill PR1 +
PR2 (cb4cd7f, b6f1256 — ~5,000 lines of new operator-facing
functionality), the matrix CodeQL workflow expansion (8c5b934), and
the `563138f` MigrationRunner wiring with its `/readyz` response-shape
addition (`failed_stores` field on 503). Strict SemVer says any new
backward-compatible feature ⇒ MINOR bump, so this is v0.11.0 rather
than the originally-planned v0.10.1 patch. First cut as **v0.11.0-rc1**._

### Added

- **`/release` skill at `.claude/skills/release/SKILL.md`** — bash-first
  release orchestrator that runs preflight (`scripts/release-preflight.sh`
  + `scripts/check-compose-versions.sh`), pushes the tag, monitors the
  release workflow until terminal state, troubleshoots known failure
  modes (the v0.10.0 download-artifact bug, compose version mismatch,
  Windows signtool absence, macOS notarytool timeout, Windows MSVC
  LNK2038 vcpkg cache poisoning, EUnit meck false-positive), verifies
  the GitHub Releases page has every expected asset including the
  Compose Wizard zip and GHCR images, and produces a release report.
  Supports `--watch`, `--verify`, and `--resume` modes for
  re-entrant operation when a release stalls partway. Mirrors the
  `/test` skill's bash-first orchestration pattern (no agent fan-out;
  the LLM interprets failures and decides next-step). Use:
  `/release vX.Y.Z` — full pipeline; `/release --watch vX.Y.Z` —
  monitor an in-flight release; `/release --verify vX.Y.Z` —
  post-hoc verification.
- **Compose Wizard bundled as a release asset
  (`.github/workflows/release.yml` `Package Compose Wizard` step).**
  The browser-based docker-compose.yml + .env generator at
  `tools/compose-wizard/` (PR #405 by @fjarvis) is now packaged into
  `yuzu-compose-wizard-X.Y.Z.zip` during the release workflow's
  `release` job and uploaded alongside the other assets. Auto-included
  in `SHA256SUMS` and the cosign-signed `SHA256SUMS.bundle`. Release
  notes get a "Compose Wizard" section pointing customers at the
  download with `unzip + open index.html` instructions. Conditional
  on `tools/compose-wizard/` existing in the tag's commit tree —
  emits a workflow warning and skips the bundle if absent (release
  proceeds without it). Tag must be cut from a commit that has both
  this workflow change AND the wizard files merged in.
- **Runner inventory sentinel workflow
  (`.github/workflows/runner-inventory-sentinel.yml`,
  `.github/runner-inventory.json`).** Declarative expected-state file
  enumerates the self-hosted runners we expect to be online + idle
  (currently `yuzu-wsl2-linux` and `yuzu-local-windows`), and a
  scheduled workflow reconciles `gh api repos/Tr3kkR/Yuzu/actions/runners`
  against it. Reports drift (missing runners, offline runners, wrong
  labels) as a workflow failure with a human-readable summary in the run
  annotation. Built across three commits:
  - `12ef73b` — initial workflow + inventory file scaffold.
  - `a0425c8` — parse error fix (removed invalid `administration: read`
    workflow permission, added graceful HTTP 403 handling with
    PAT-setup runbook in stderr, added `.github/runner-inventory.json`
    and the workflow file itself to `ci.yml`'s `paths-ignore` so CI
    doesn't re-trigger on inventory edits).
  - `675d636` — cron schedule commented out with `[skip ci]`. The
    sentinel is **inactive until the `RUNNER_INVENTORY_TOKEN` PAT is
    created** — `gh api /actions/runners` requires admin scope which
    `GITHUB_TOKEN` cannot grant via workflow permissions (admin scope
    only exists at org/installation level, not workflow level). PAT
    creation is the first item on the Saturday at Jordanstone checklist;
    once it lands, uncomment the schedule block and the sentinel
    activates. The inactive-until-PAT pattern avoids the chronic-red
    anti-pattern where a permanently-failing scheduled workflow trains
    operators to ignore CI failure notifications.

- **Dependency automation — `pip` ecosystem + scheduled vcpkg baseline
  bumps (closes #363).** `requirements-ci.txt` at the repo root becomes
  the single source of truth for Python tooling pins (currently just
  `meson==1.9.2`), consumed directly by every `pip`/`pip3`/`pipx install`
  call site in `.github/workflows/ci.yml` (6 sites) and
  `.github/workflows/release.yml` (2 sites). The hardcoded
  `MESON_VERSION: "1.9.2"` env var is removed from all three tracked
  workflows (`ci.yml`, `release.yml`, and the dead reference in
  `sanitizer-tests.yml`) — the pin now lives in exactly one place.
  `.github/dependabot.yml` gains a `pip` ecosystem entry so Dependabot
  opens a weekly PR against `requirements-ci.txt` if a newer meson
  release lands, and CI re-runs on the PR so breaking changes stall
  instead of silently merging.

  **vcpkg baseline** — Dependabot does not understand vcpkg, so
  `.github/workflows/vcpkg-baseline-update.yml` is a new scheduled
  workflow (10:00 UTC on the 1st of each month, plus
  `workflow_dispatch`) that: resolves `git ls-remote vcpkg HEAD`,
  compares to the current `vcpkg.json` `builtin-baseline`, and if
  different, `sed`s the new SHA into every tracked reference
  (`vcpkg.json`, `vcpkg-configuration.json`, `qodana.yaml`, `CLAUDE.md`,
  all four workflow `VCPKG_COMMIT` env vars, and all three Dockerfile
  ARG/ENV references), failing loudly if any listed file still carries
  the old SHA after the replace, then opens a PR via
  `peter-evans/create-pull-request@v7` with `dependencies,ci` labels.

  **rebar3** — gateway dependencies stay on a manual quarterly review
  cadence, documented in the new `docs/dependency-updates.md`. The doc
  is also the reference for the full dependency-update strategy —
  ecosystem table, staleness query per ecosystem, and the known
  Dockerfile-meson duplication follow-up.

  **Why the Dockerfiles aren't centralized yet** — five Dockerfiles
  under `deploy/docker/` (`agent`, `server`, `ci`, `ci-linux`,
  `runner-linux`) still carry a hardcoded `meson==1.9.2` string in
  their build-stage `RUN` commands. Centralizing them on
  `COPY requirements-ci.txt` is tracked as a follow-up in
  `docs/dependency-updates.md`. Until then, the manual merge checklist
  for a Dependabot meson bump includes bumping the literal string in
  those five files (`grep -rn 'meson==' deploy/docker/` finds them all).

- **`/test` skill coverage + perf + sanitizer gates (PR2 of 3).** Phase 6
  and Phase 7 of the `/test` pipeline are now wired. `--full` mode
  dispatches `.github/workflows/sanitizer-tests.yml` on the
  `yuzu-wsl2-linux` self-hosted runner (ASan+UBSan and TSan rebuilds +
  test runs), downloads the artifacts, parses them for sanitizer
  findings + meson test failures, and records two Phase 6 rows to
  `test_gates`. Runner offline → WARN (not FAIL) with operator retry
  instructions in the notes, so the rest of the run continues. Phase 7
  runs `coverage-gate.sh` (gcovr with the same filter set and
  `--native-file meson/native/linux-gcc13.ini` as
  `.github/workflows/ci.yml`, branch coverage compared against
  `tests/coverage-baseline.json` with 0.5 pp slack) and `perf-gate.sh`
  (rebar3 ct `yuzu_gw_perf_SUITE` groups `registration,heartbeat,fanout,churn`
  — endurance excluded — with 10 % throughput / latency tolerance
  against `tests/perf-baselines.json`). Hardware fingerprint mismatch
  on the perf baseline auto-downgrades to WARN so a 5950X-captured
  baseline doesn't produce false failures on the Apple Silicon MBP.
  Both gates record `perf_*` / `branch_coverage_overall` /
  `line_coverage_overall` metrics to `test_metrics` for trend analysis
  via `test-db-query.sh --trend metric=...`.

  **PR2 governance hardening round (folded into the same commit).** A
  full 6-gate governance pass on the initial PR2 working tree produced
  10 BLOCKING findings (ca-B1/UP-1 grep arithmetic, UP-2 gcovr schema,
  UP-6/UP-7 sanitizer false-PASS cluster, UP-9 run-id path traversal,
  UP-10 `__seed` sentinel silently disabled enforcement, UP-14 /
  hp-B2 dispatch concurrent race, UP-18 broken-env baseline anchoring,
  qa-B1 perf CT exit code not propagated, hp-B1 perf seed → WARN
  propagating through SKILL.md, sec-M1 `rm -rf "$BUILD_DIR"` on
  operator-controlled path) plus associated high-value SHOULDs (bci-S5
  native-file parity, qa-S1 min-metrics threshold, qa-S4 partial-data
  flagging, sre-5 runner disk pre-check, ca-S3 unit column width,
  doc-S1/S2/sre-6/sre-7/er-5). All resolved in this same PR2 commit:

  - `dispatch-runner-job.sh` now uses a createdAt timestamp + headSha
    filter for run discovery instead of the single newest-ID compare,
    so concurrent operators dispatching the same workflow no longer
    attribute each other's runs. Rejects multiline values in the
    `--inputs` JSON to block split-injection into `--raw-field`.
  - `sanitizer-gate.sh` distinguishes dispatch exit codes 0/1/2/3
    (success/config-error/workflow-failed/runner-offline) so a
    workflow that concluded `failure` now writes FAIL rows rather
    than parsing possibly-degraded artifacts into a silent PASS.
    Empty sanitizer logs (runner disk full, upload truncation) are
    caught by a size+marker guard that WARNs instead of reading them
    as "0 findings". The `grep -cE ... || echo 0` idiom that produced
    `"0\n0"` and broke `(( n > 0 ))` was replaced with a single-value
    capture that whitespace-strips defensively. The meson test FAIL
    detector now uses POSIX `[[:space:]]FAIL` instead of the GNU-only
    `\<FAIL\>` word boundary.
  - `coverage-gate.sh` honors the `__seed: true` sentinel and emits
    WARN ("seed baseline active — run --capture-baselines to enable
    enforcement") rather than silent PASS against the permissive seed.
    Refuses `--capture-baselines` when `meson test` exited non-zero
    so a broken env can no longer anchor a false-low baseline. Prints
    an old-vs-new diff before overwriting any existing baseline.
    Adds `--native-file meson/native/linux-gcc13.ini` to the
    `meson setup` call so local coverage numbers match Codecov's
    gcc-13 baseline. Validates `--build-dir` is under `$YUZU_ROOT/build-*`
    or `/tmp/build-*` before the reconfigure-failure `rm -rf` path
    can fire. Partial-data runs (`TEST_RC != 0`) tag the metric notes
    with `(partial: meson test exit=N)` so trend queries can filter
    out contaminated points. The gcovr JSON parser now handles both
    the top-level and `{"root": {...}}` wrapping shapes and supports
    the gcovr 6.x+ `branches_covered`/`branches_valid` key names (the
    pre-hardening code used `branch_covered`/`branch_total` which
    don't exist in modern gcovr, producing a silent 0 %).
  - `perf-gate.sh` propagates `rebar3 ct` exit code to gate outcome:
    `CT_RC=1` (test assertion failed) → FAIL; `CT_RC > 1` (compile
    or tooling failure) → WARN. Adds a minimum-metrics-parsed
    threshold (≥ 3 of the 6 expected labels) so parser drift produces
    a FAIL with a specific message instead of a silent "no metrics
    parsed" WARN. Honors `__seed: true` with exit-0 PASS (not WARN)
    so SKILL.md full-mode doesn't abort Phase 7 on the first run
    against a seed baseline. Refuses `--capture-baselines` when
    fewer than 3 metrics were parsed. Guards the compare math
    against non-finite / zero / negative baseline values (sec-L4).
    Emits WARN when the current run is missing baseline metrics
    (UP-13 — prevents silent "only 1/6 checked" PASSes). Strips
    ANSI escape sequences from `ct:pal` lines before regex matching
    so colorized rebar3 output does not silently break metric
    extraction.
  - All three gate scripts validate `--run-id` against
    `^[A-Za-z0-9._-]+$` before constructing any filesystem path,
    closing the `--run-id "../../../tmp/evil"` traversal and
    whitespace-only-ID path.
  - `.github/workflows/sanitizer-tests.yml` gains a
    "≥30 GB free" disk-check step right after toolchain assertion,
    so a full runner fails fast with `::error::runner disk` instead
    of hitting `ninja: No space left on device` 15 minutes into
    the sanitizer build (sre-5 / UP-6 upstream of the false-PASS path).
  - `scripts/test/test_db.py` `--trend` output column widened from 6
    to 10 characters so `ops/sec` and `ms/agent` units no longer
    push the run_id column out of alignment.
  - `tests/shell/test_pr2_gates.sh` (NEW) — chaos-injector regression
    harness covering P0 scenarios CH-2 (grep arithmetic), CH-3
    (capture refuses broken env), CH-4 (gcovr root-wrap schema),
    CH-6 (perf parser drift), CH-8 (`__seed` honored on both gates),
    CH-15 (invalid run-ids), and CH-16 (sec-h-1 regression test for
    Python code injection via `--baseline` path with embedded quote).
    7 scenarios, 9 assertions, all green on the hardened tree. CH-1
    (clean-log + workflow-failure → FAIL) is deferred to PR2.1 because
    it needs a gh CLI mock harness.

  **Pattern C catch — second security pass on the hardening round**
  surfaced three new issues introduced by the hardening itself:

  - **sec-h-1 (HIGH, BLOCKING)** — `coverage-gate.sh` `--capture-baselines`
    diff and `__seed` detection paths interpolated the operator-controlled
    `--baseline` file path into single-quoted Python literals inside
    `python3 -c "..."` shell strings. A baseline path containing a single
    quote would break out of the Python literal and execute arbitrary code.
    Fix: all three call sites (lines 366, 367, 424) rewritten as quoted
    heredocs (`python3 - "$BASELINE" <<'PY'`) that receive the path via
    `sys.argv[1]`. CH-16 in the chaos harness regression-tests this by
    placing a real baseline under a directory name containing `'`.

  - **sec-h-2 (MEDIUM)** — `dispatch-runner-job.sh` fell back to
    `echo "$REF"` when `git rev-parse` failed, which allowed an
    unresolvable ref to be spliced verbatim into a jq filter
    (`--jq "... select(.headSha == \"$TARGET_SHA\")"`). Fix: strictly
    resolve ref via `git rev-parse --verify "$REF^{commit}"` and refuse
    the dispatch on failure; also require `TARGET_SHA` to match a
    hex[40-64] regex before it reaches jq. The jq filter now uses
    `env.DISPATCH_TS` and `env.TARGET_SHA` through environment
    variables instead of shell-interpolated jq syntax.

  - **sec-h-3 (MEDIUM)** — `tests/shell/test_pr2_gates.sh` helper
    functions `db_gate_status` / `db_gate_notes` / CH-4 metric read
    used the same shell-interpolation-into-Python anti-pattern as
    sec-h-1. Not exploitable today (harness controls all values) but
    a trap for future contributors. Fixed to pass values via
    `sys.argv` in quoted heredocs so the harness teaches the right
    pattern.

  The re-review clears the commit for landing. Low/INFO items from
  both security passes (sec-L2, sec-L4, sec-L5, sec-h-4, sec-h-5)
  are deferred to follow-up issues and captured in memory for the
  next hardening wave.
  - SKILL.md, CLAUDE.md updated to describe the `__seed` semantics,
    the `--capture-baselines` pre-flight requirement (clean
    `meson test` / `rebar3 ct` before capture), the sanitizer queue
    behavior under concurrent full-mode runs, and the baseline
    refresh cadence (recapture at every `vX.Y.0` tag on the
    canonical dev box).

  **New files:**
  - `scripts/test/dispatch-runner-job.sh` — shared `gh workflow run` + poll +
    download + parse helper with distinct exit codes for success / fail /
    runner-unavailable so callers can map to PASS / FAIL / WARN.
    Reused by PR3 for the Windows agent build dispatch.
  - `scripts/test/sanitizer-gate.sh` — Phase 6 orchestrator. Parses
    `ERROR: AddressSanitizer`, `ERROR: LeakSanitizer`, `WARNING: ThreadSanitizer`,
    `ThreadSanitizer: data race`, `runtime error:` out of the downloaded
    sanitizer logs and counts meson test FAIL lines separately.
  - `scripts/test/coverage-gate.sh` — Phase 7 coverage orchestrator.
    Configures `build-linux-coverage/` with `-Db_coverage=true` (separate
    from the main `build-linux/` so ccache hit rates stay intact), runs
    `meson test`, runs gcovr with `--json-summary`, and enforces the
    baseline with `--capture-baselines` / `--report-only` / default
    enforce modes.
  - `scripts/test/perf-gate.sh` — Phase 7 perf orchestrator. Parses
    `ct:pal` throughput lines (`Registration: N ops in M ms (O ops/sec)`),
    fanout latency lines (`Fanout to N agents: M ms`), and session
    cleanup latency (`Cleanup N agents: M ms (K ms/agent)`).
  - `.github/workflows/sanitizer-tests.yml` — `workflow_dispatch`-only
    workflow pinned to `[self-hosted, yuzu-wsl2-linux]`. Uses the same
    `ASAN_OPTIONS=detect_leaks=1:halt_on_error=1`,
    `UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1`, and
    `TSAN_OPTIONS=halt_on_error=1:second_deadlock_stack=1` as the
    existing CI sanitize jobs for parity. Uploads
    `sanitizer-{asan,tsan}.log`, their build logs, and
    `build-linux-{asan,tsan}/meson-logs/testlog.junit.xml` as artifacts.
  - `tests/coverage-baseline.json`, `tests/perf-baselines.json` —
    shipped as **permissive seeds** (`branch_percent=0 + slack_pp=100`,
    empty `metrics` map) with a `__seed: true` flag. PR2 must not break
    /test --full on merge day, so the seeds pass trivially; first
    operator run with `--capture-baselines` locks real numbers that
    replace the seeds. The `git blame` on these files is the audit
    trail for who raised/lowered the baseline and why.

- **`/test` skill scaffold + upgrade test path (PR1 of 3).** New
  `.claude/skills/test/SKILL.md` operator-facing runbook plus
  `scripts/test/` helper directory that orchestrates a pre-commit /
  pre-push test pipeline. Three modes: `--quick` (~10 min sanity check),
  default (~30-45 min build + upgrade test + standard gates), `--full`
  (~60-120 min adds OTA + sanitizers + perf + coverage enforce). The
  default-mode headline is **Phase 2 upgrade test**: pulls
  `ghcr.io/tr3kkr/yuzu-server:0.10.0`, populates fixture data, swaps to
  the local HEAD image (built in Phase 1 as `yuzu-server:0.10.1-test-${RUN_ID}`),
  verifies migrations ran via `/readyz` (uses the #339 compound-fix
  `failed_stores` body field), and re-checks fixture preservation. PR1
  ships Phases 0, 1, 2, 4, 5, 8 fully wired; Phases 3 (OTA), 6
  (sanitizers), 7 (coverage + perf) are stubbed with SKIP rows pending
  PR2/PR3.

- **Persistent test-runs SQLite database** at
  `~/.local/share/yuzu/test-runs.db` (override via `YUZU_TEST_DB`).
  Schema v1 has 4 tables: `test_runs` (per-invocation aggregate),
  `test_gates` (per-gate pass/fail + duration), `test_timings`
  (millisecond sub-step durations like `phase2.image-swap`,
  `phase3-linux.ota-download`, `synthetic-uat.os_info-roundtrip`),
  and `test_metrics` (quantitative measurements with units). Uses
  the `schema_meta` pattern from #339 so future schema changes can
  land via versioned migrations. New scripts:
  `scripts/test/test_db.py` (Python source of truth) plus thin
  bash wrappers `test-db-init.sh`, `test-db-write.sh`,
  `test-db-query.sh`. The query wrapper supports
  `--latest`, `--last N`, `--diff RUN_A RUN_B`,
  `--trend metric=NAME` / `--trend timing=GATE.STEP`,
  `--flaky --days N`, `--branch B`, `--export RUN_ID`,
  `--prune KEEP_N` (with `--dry-run` preview).
  Power users can `python3 scripts/test/test_db.py query ...`
  directly or run any sqlite query against the DB.

- **`scripts/test/preflight.sh`** — Phase 0 sanity checks (toolchains,
  ports, disk, docker context, dangling test containers, git state,
  test-runs DB initialization). `--force-cleanup` flag tears down
  dangling `yuzu-test-*` compose projects.

- **`scripts/test/synthetic-uat-tests.sh`** — extracts the 6
  connectivity tests from `linux-start-UAT.sh` (dashboard reachable,
  gateway readyz, server registered agents metric, gateway connected
  agents metric, help command round-trip, os_info command round-trip)
  into a standalone script that takes URLs as arguments and records
  per-command latencies into `test_timings`.

- **`scripts/test/test-fixtures-{write,verify}.sh`** — minimum-viable
  fixture set written before the upgrade and re-verified after, so the
  upgrade test can detect data loss. Records what's preserved /
  lost / skipped to a `fixtures-verify.json` report file.

- **`scripts/test/test-upgrade-stack.sh`** — Phase 2 orchestrator. Uses
  a purpose-built `scripts/test/docker-compose.upgrade-test.yml` that
  drops the `container_name:` declarations from
  `deploy/docker/docker-compose.reference.yml` so multiple parallel
  test runs can coexist via `--project-name` isolation. Records
  sub-step timings: `pull-old-images`, `stack-up-old`, `fixtures-write`,
  `image-swap`, `ready-after-upgrade`, `fixtures-verify`,
  `synthetic-uat-against-upgraded`. Counts `MigrationRunner` log events
  as a `phase2_migration_events` metric.

- **`scripts/test/teardown.sh`** — Phase 8. Stops every
  `yuzu-test-${RUN_ID}-*` compose project, removes the
  `/tmp/yuzu-test-${RUN_ID}/` scratch dir, finalizes the `test_runs`
  row with computed `overall_status` from gate aggregates.

- **Schema migrations wired into every server-side SQLite store (#339).**
  The `MigrationRunner` framework at
  `server/core/src/migration_runner.{hpp,cpp}` existed since earlier
  releases but had not been called by any store — every store relied on
  `CREATE TABLE IF NOT EXISTS` plus silent `ALTER TABLE` fallbacks, and
  the upgrade docs incorrectly claimed "automatic schema migrations"
  since v0.1.0. This change threads `MigrationRunner::run()` through the
  `create_tables()` method of all 30 stores and managers:
  `analytics_event_store`, `api_token_store`, `approval_manager`,
  `audit_store`, `concurrency_manager`, `custom_properties_store`,
  `deployment_store`, `device_token_store`, `directory_sync`,
  `discovery_store`, `execution_tracker`, `instruction_store`,
  `inventory_store`, `license_store`, `management_group_store`,
  `notification_store`, `nvd_db`, `patch_manager`, `policy_store`,
  `product_pack_store`, `quarantine_store`, `rbac_store`,
  `response_store`, `runtime_config_store`, `schedule_engine`,
  `software_deployment_store`, `tag_store`, `update_registry`,
  `webhook_store`, `workflow_engine`. Every database now stamps its
  schema version in the shared `schema_meta` table and future schema
  changes go through versioned migrations with transactional rollback.
- **`deploy/docker/docker-compose.reference.yml`** — copyable
  deployment template that pulls pinned
  `ghcr.io/tr3kkr/yuzu-{server,agent}:${YUZU_VERSION:-0.10.0}` images,
  uses a named `server-data` volume for all mutable state, and carries
  inline TLS hardening + backup + rollback + restore commentary.
  Covered by `scripts/check-compose-versions.sh` so release tags cannot
  drift from the compose default. Named "reference" rather than
  "production" because the image's default CMD is dev-friendly
  (`--no-tls --no-https --web-address 0.0.0.0`) and the template
  requires operator hardening before production use (#339).
- **Legacy compatibility shims in six stores** — `api_token_store`,
  `instruction_store`, `patch_manager`, `policy_store`,
  `product_pack_store`, `response_store`. These run the historical
  silent `ALTER TABLE ADD COLUMN` statements once before
  `MigrationRunner::run()` so databases created by pre-v0.10 releases
  that never received those columns still converge to schema v1.
  Kept for one release cycle; removable after v0.11.

### Changed

- **CLAUDE.md second compression pass — Auth/MCP/Windows-build
  sections trimmed to pure pointers, with reference rules pushed
  into the relevant agent definitions.** v0.10.0's slimming
  (`571 → 484 lines`) had crept back to 529 lines as new sections
  landed. This pass takes it to 502 by removing the inline lists
  that were already mirrored in `docs/auth-architecture.md`,
  `docs/mcp-server.md`, and `docs/windows-build.md`. The hard
  invariants did not move — they're still load-bearing — they're
  just no longer duplicated between CLAUDE.md and the docs that
  own them. Drift was the symptom: the Auth invariant list in
  CLAUDE.md was already 1 item behind `docs/auth-architecture.md`
  and would silently keep diverging on every doc update.

  To prevent the next compression pass having to relocate the
  same rules a third time, the relevant agent definitions now
  carry "Reference Documents" pointers that name the doc and the
  exact section that holds the invariants:

  - **`.claude/agents/security-guardian.md`** — Reference
    Documents table mapping (auth/RBAC/crypto/header/token →
    `docs/auth-architecture.md` "HTTPS and bind defaults",
    "HTTP security response headers", "API tokens and
    automation"; MCP → `docs/mcp-server.md` "Architecture",
    "Security Model"). Adds `security_headers.{hpp,cpp}`,
    `mcp_server.{hpp,cpp}`, `mcp_policy.hpp`, `mcp_jsonrpc.hpp`
    to the deep-dive read list. Triggers list per-doc loading
    rules so the agent loads the right doc on the first relevant
    file edit instead of recovering invariants from CLAUDE.md.
  - **`.claude/agents/build-ci.md`** — Reference Documents note
    pointing at `docs/windows-build.md` for any Windows-touching
    CI/build change (`setup_msvc_env.sh`, vcpkg Windows triplet,
    MSVC flags). Linux/macOS build details remain in CLAUDE.md
    `## Build` / `## CI matrix` / `## vcpkg` sections.
  - **`.claude/agents/cross-platform.md`** — Reference Documents
    note for Windows changes plus an explicit "Do NOT use Clang
    from `C:\Program Files\LLVM\bin`" row in the Standing
    pitfalls table (was previously buried in CLAUDE.md prose).

- **`Dockerfile.ci-gateway` aligned to Erlang/OTP 28 (closes #334).**
  The CI gateway image was still pinned to `erlang:27` while every
  other Erlang surface — `release.yml`'s `erlef/setup-beam` step,
  `scripts/ensure-erlang.sh`'s default, and the runtime
  `Dockerfile.gateway` (`erlang:28-alpine`) — had moved to OTP 28.
  CLAUDE.md is explicit that these must move together; leaving the
  CI image behind meant the GitHub Actions gateway build was
  exercising rebar3/dialyzer against an OTP version older than the
  one the release ships, and any 28-only behavioural change would
  have been invisible to CI until a release tag was cut.
  `Dockerfile.gateway`'s `erlang:28-alpine` digest pin was also
  rolled forward to the current build (`f36705c5…`) as part of the
  same dependabot bundle. Originally proposed by dependabot in
  PR #334 against `main`; landed directly on `dev` because PR #334's
  Windows MSVC failure was the unrelated vcpkg LNK2038 cache issue
  fixed in PR #355 after dependabot opened its branch. Dependabot
  will close #334 automatically on its next scan.

- **CodeQL workflow hardened to actually finish + parallel Windows
  coverage (closes #370).** Every CodeQL run from 2026-03-23 to
  2026-04-13 was cancelled by the 90-min timeout — 7 consecutive
  cancellations across both manually-dispatched and PR-event-triggered
  runs. The actual runtime on the `yuzu-wsl2-linux` self-hosted runner
  is closer to 15 min for a Linux-only single-leg analysis (32-thread
  WSL2 host, 60 GB RAM), but the prior workflow had been cancelling
  before completing. Rebuilt as a `strategy.matrix` workflow that fans
  out to BOTH self-hosted runners in parallel: `yuzu-wsl2-linux`
  (gcc-13 + `build-linux-codeql/`) and `yuzu-local-windows`
  (MSVC + `build-windows-codeql/`), with `fail-fast: false` so one
  leg failing doesn't kill the other. Each leg uploads SARIF with a
  distinct category (`/language:c-cpp-linux` vs `/language:c-cpp-windows`)
  so findings in platform-specific `#ifdef _WIN32` branches stay
  attributed to the analysis that actually observed them. Closes #370.

  Coverage knobs flipped to maximum:
  - `queries: +security-and-quality` (strict superset of
    `security-extended`; for C/C++ specifically, the "quality"
    queries are security-adjacent — memory leaks, UAF, null deref,
    dead code hiding logic bugs, inconsistent error handling — not
    style noise like they would be for JS/Python)
  - `languages: c-cpp,actions` on the Linux leg (Windows leg keeps
    `c-cpp` only — no need to double-scan the same
    `.github/workflows/*.yml` files; the `actions` extractor catches
    the well-known `${{ github.event.* }}` template-injection class
    in workflow `run:` bodies)
  - `-Dbuild_tests=true` (recovers the ~50-100 `tests/unit/*.cpp`
    files that were skipped in the earlier `build_tests=false`
    baseline run, which scanned only 231/364 C++ files)
  - Dedicated per-OS build dirs (`build-linux-codeql/` /
    `build-windows-codeql/`) isolated from operator's interactive
    `build-{linux,windows}/` and from PR2's
    `build-linux-{asan,tsan,coverage}/`
  - Pre-build runner disk-free assertion (≥40 GB Linux, ≥45 GB
    Windows; MSVC debug builds are chunkier)
  - Weekly scheduled run (Sunday 04:00 UTC) + manual `workflow_dispatch`
  - `timeout-minutes` tightened from 240 (speculation based on
    GitHub-hosted runner assumptions) to 90 (verified comfortably
    above the real cold runtime)

  Fixes accumulated during the matrix landing — each is a category
  of GHA / Windows / bash interaction that took a verification run to
  surface, all preserved in commit history for the next person who
  hits one:
  - **`${{ github.workspace }}` doesn't expand inside matrix
    `include:` values** — collapsed to literal `/vcpkg_installed/x64-linux`
    on Linux, breaking CMake's protobuf probe with "Preliminary CMake
    check failed". Fix: inline `${{ github.workspace }}` directly in
    each step's `env:` block (where it DOES evaluate) or use
    `$GITHUB_WORKSPACE` in `run:` blocks.
  - **`defaults.run.shell: bash` on the Windows self-hosted runner
    resolves to `C:\Windows\system32\bash.EXE`** (WSL bash), which
    refuses to run as `LOCAL SYSTEM` with
    `WSL_E_LOCAL_SYSTEM_NOT_SUPPORTED`. Fix: per-leg `shell:` matrix
    variable; Windows uses explicit
    `'C:\msys64\usr\bin\bash.exe --noprofile --norc -eo pipefail {0}'`
    (CLAUDE.md's documented Windows development shell).
  - **`hashFiles('**/*.cpp', '**/*.hpp', '**/*.h')` exceeds GHA's
    hard 120-second timeout** on the persistent NTFS Windows runner
    workspace because `vcpkg_installed/` accumulates thousands of
    vendored headers from gRPC/protobuf/abseil/openssl/etc. across
    runs. Linux-hosted CI in `ci.yml` doesn't hit the limit because
    GitHub-hosted runners get a fresh workspace per run. Fix: hash
    only build-system config files (`meson.build`, `meson_options.txt`,
    `vcpkg.json`, `vcpkg-configuration.json`, `meson/native/*.ini`,
    `meson/cross/*.ini`) — small, fast, and the only inputs that
    should rotate the GHA ccache slot. ccache itself handles
    source-level invalidation via content addressing.
  - **`${{ github.workspace }}` interpolated into bash `run:` source
    has its backslashes stripped by bash's escape processing on
    Windows** — the path `C:\actions-runner\_work\Yuzu\Yuzu` becomes
    `C:actions-runner_workYuzuYuzu` because `\a`, `\Y`, `\_` etc. are
    parsed as escape sequences. Fix: use `$GITHUB_WORKSPACE` (env var
    read at runtime — no escape processing) instead of
    `${{ github.workspace }}` (GHA source interpolation at parse time)
    in bash `run:` blocks.
  - **`sanitizer-tests.yml` runner label was wrong** —
    `runs-on: [self-hosted, yuzu-wsl2-linux]` was the original PR2
    pattern, but the runner's actual labels are
    `["self-hosted", "X64", "Linux"]` (no custom `yuzu-wsl2-linux`
    label exists; that string is the runner NAME, not a label). Gate 3
    build-ci review called the pattern "correct" without verifying
    against `gh api /runners`. Fixed both `codeql.yml` and
    `sanitizer-tests.yml` to use `[self-hosted, Linux, X64]` which
    matches the runner's real label set. The `sanitizer-gate.sh
    --expect-runner` check compares `runner_name` (not labels) via
    `gh api /jobs`, which correctly matches `yuzu-wsl2-linux` as the
    runner's name, so that check is unaffected.

- **Migration failure now closes the affected store (#339).** When
  `MigrationRunner::run()` returns false for a store that owns its
  SQLite handle (26 of 30 stores), the store's `create_tables()` closes
  the handle and sets `db_ = nullptr`, so `is_open()` correctly returns
  false. Previously a migration failure was logged but the store kept
  reporting itself as open, and `ResponseStore::store()` would silently
  no-op on inserts because `insert_stmt_` was null — agent results
  reached the server, were "accepted" over gRPC, and disappeared. This
  change ensures a migration failure surfaces loudly via `/readyz` and
  causes reads/writes to fail fast instead of dropping data. (Closes
  UP-1 / UP-2 / UP-9 / UP-20 compound finding from the #339 governance
  run.)
- **`/readyz` reports per-store status with failed store names (#339).**
  The readiness probe now walks 12 load-bearing stores (response, audit,
  instruction, api_token, policy, rbac, tag, management_group,
  runtime_config, inventory, workflow_engine, custom_properties) and
  returns a JSON body of the form
  `{"status":"not ready","failed_stores":["..."]}` on 503 so operators
  can diagnose upgrade failures without digging through logs.
- **`MigrationRunner` hardening**: explicit `ROLLBACK;` on COMMIT
  failure so shared-connection callers (`InstructionDbPool`) don't
  inherit a half-open transaction; removed redundant `ensure_meta_table`
  call in `current_version()`; `Migration::sql` is now `std::string`
  (owning) instead of `std::string_view` to guard against future callers
  constructing migrations from non-null-terminated views.
- **`docs/user-manual/upgrading.md`** rewritten (#339): Docker section
  references the new `docker-compose.reference.yml`, real `ghcr.io`
  image path, backup recipe with a dedicated backup directory, explicit
  Docker rollback recipe, `schema_meta` query for operator-side
  verification, and truthful failure-mode guidance that points at
  `/readyz` (not `/livez`) as the upgrade-success signal. The "Schema
  Migrations" section describes the real mechanism, which stores carry
  legacy shims, and what the log burst on first upgrade looks like.
  Drops the inaccurate "since v0.1.0" claim. Version compat table now
  spans 0.5.x → 0.9.x as a single row so the 0.10.x jump reads cleanly.
- **`docs/user-manual/server-admin.md`** Docker compose table now
  includes `docker-compose.reference.yml` with the "requires operator
  hardening" caveat.

### Breaking

- **`DELETE /api/settings/users/:name` now returns 403 + HTMX toast
  when the URL target matches the caller's own session username
  (was: 200 + deletion).** Operator scripts that previously called
  this endpoint to delete the credential they were authenticated
  with — for example, a decommission flow that removes its own
  service account as a final step — will receive `403 Forbidden`
  starting in v0.11.0. The full self-deletion lockout vector
  including UI suppression is documented in the Fixed entry below
  (#397). To remove the account a script is signed in as, create a
  second admin account first, switch authentication to that account,
  then issue the DELETE.
- **`POST /api/settings/users` now returns 403 + HTMX toast when an
  admin attempts to change their own role (typically a self-demote
  from `admin` to `user`).** The same lockout class as the DELETE
  case above; closed in the Gate 4 governance hardening round
  (ca-B1). Self-password-change (same username, same role, different
  password) is **explicitly allowed** and continues to return 200 —
  the guard is role-scoped, not a blanket self-upsert ban. Operator
  scripts that change their own role need to be split: have a
  second admin perform the role change, or perform the role change
  before swapping accounts.
- **Two new audit actions written to `audit_store`:**
  `user.delete` and `user.upsert`, each with `result` ∈
  {`success`, `denied`}. Downstream consumers (Splunk HEC,
  ClickHouse projections) that match on the existing
  `<noun>.<verb>` action convention pick this up automatically. SOC
  2 CC7.2 evidence chain (governance Gate 6 CO-1).

### Fixed

- **Settings → Users hardening round on top of the #397/#403 fix —
  ca-B1 sibling lockout, CO-1 audit chain, UP-1 empty-username
  fail-closed, UP-9 GET/POST defensive auth (governance Gate 4-6).**
  The original two-sided fix below closed the DELETE self-target
  case but left several adjacent hardening items open that the full
  governance pipeline surfaced:
  - **ca-B1 — POST self-demotion guard.** `POST /api/settings/users`
    is the second equivalent route to the same lockout class: an
    admin POSTing their own username with a lower role demotes
    themselves out of admin and is locked out of every admin-gated
    page on the next request. Now rejected with HTTP 403 + "Cannot
    change your own role" toast when
    `(username == session->username && role != session->role)`.
    Self-password-change (same role) is explicitly allowed.
  - **CO-1 — SOC 2 CC7.2 audit chain.** The 403 self-reject branches
    and the success delete/upsert paths now emit `audit_fn_` events
    (`user.delete` / `user.upsert` with `result` ∈ {`denied`,
    `success`}). `spdlog::warn` alone is not the audit chain — SIEM
    ingestion paths and SOC 2 evidence collection both read
    `audit_store`, not log files. Pre-existing gap on the success
    path also closed.
  - **UP-1 — empty session username fail-closed.** All three
    handlers now return HTTP 500 + `spdlog::error` when
    `session->username.empty()`. Defense-in-depth against an
    upstream OIDC mis-config returning empty `preferred_username`;
    previously the empty-string sentinel could match an empty-
    username row via `"" == ""` or render every row as non-self.
  - **UP-9 — GET/POST defensive 401.** GET `/fragments/settings/users`
    and POST `/api/settings/users` now mirror the DELETE handler's
    defensive 401 branch when `admin_fn_` passes but `auth_fn_`
    returns nullopt. Previously they fell through with empty
    `self_name`, re-rendering Remove buttons on every row including
    the operator's own — the #403 bug pattern resurrected inside
    the response body.
  - **arch-S1 — `render_users_fragment` no longer has a default
    argument.** Every call site must pass `current_username`
    explicitly so a future caller forgetting it is a compile error
    rather than a silent UI regression.
  - **CLAUDE.md** under Authentication & Authorization captures the
    self-target principal-destruction guard as a hard invariant for
    future handlers (doc-S2).
- **Self-deletion lockout in Settings → Users closed on both UI and
  handler sides (#397 critical, #403 UI — both filed from the Apr 2026
  UAT pass).** The Settings → Users page rendered a "Remove" button
  next to every account including the currently authenticated
  operator's own row, and `DELETE /api/settings/users/:name` did not
  check the target against the caller's session. Confirming the
  generic hx-confirm dialog dropped the sole admin credential on a
  running server, leaving every API call returning 401 until the
  process was restarted against its on-disk config — a permanent
  lockout on single-seat deployments where the only recovery was a
  container restart. Fix lands both halves because a hand-crafted
  HTTP DELETE bypasses the dashboard entirely:
  - `server/core/src/settings_routes.cpp` —
    `render_users_fragment(const std::string& current_username)` now
    takes the caller's session username and renders an italicised
    "Current user" badge (not a button, no hx-delete) for the matching
    row. Every call site (`GET /fragments/settings/users`,
    `POST /api/settings/users` success and error paths,
    `DELETE /api/settings/users/:name`) resolves the session via
    `auth_fn_` and threads the name through so the UI stays consistent
    after user CRUD.
  - The `DELETE` handler resolves `session = auth_fn_(req, res)` after
    the `admin_fn_` gate passes, compares `session->username` to the
    URL-captured target, and rejects with HTTP 403 +
    `HX-Trigger: {"showToast":{"message":"Cannot delete your own
    account","level":"error"}}` if they match. The rejected attempt is
    logged at warn level (`User '<x>' attempted to delete their own
    account via /api/settings/users — rejected`) so operators chasing
    a lockout incident can see it in the server log.
- **Windows MSVC LNK2038 closed end-to-end via "option D" — static
  triplet override + hand-rolled `cxx.find_library()` wiring for
  grpc/protobuf/abseil/zlib/openssl (#375, PR #373 merged as
  `bf95d3b`).** The earlier `0fe5eac` fix (removing
  `VCPKG_BUILD_TYPE release` from `triplets/x64-windows.cmake`) stopped
  vcpkg from emitting release-only binaries but did not stop meson's
  cmake dependency translator from baking the release library paths
  into the debug link line — every Windows MSVC debug build still
  produced dozens of `RuntimeLibrary` / `_ITERATOR_DEBUG_LEVEL`
  mismatches against `absl_cord.lib`, `protobuf.lib`, and friends.
  Four iterations (per-build-type triplets → explicit
  `CMAKE_BUILD_TYPE` → drop static override → option H hybrid) failed
  in distinct ways (`12e40ae` through `220e7bd` on the dev branch).
  Option D is the combination that works:
  - `triplets/x64-windows.cmake` forces `VCPKG_LIBRARY_LINKAGE static`
    + `VCPKG_CRT_LINKAGE dynamic` so vcpkg emits per-build-type static
    archives (`.lib` for release, `d.lib` for debug) that can be
    selected at link time by the consumer.
  - `meson.build` replaces the meson `dependency('grpc++',
    method: 'cmake')` wiring on Windows MSVC with a hand-rolled
    `cxx.find_library()` chain that picks the correct variant
    (`protobuf`/`protobufd`, `zlib`/`zlibd`, `libssl`/`libcrypto` —
    unconditional because gRPC's TLS/JWT/PEM paths always resolve
    against OpenSSL regardless of schannel aspirations) per the
    active `buildtype`. Debug and release link lines are now symmetric
    and CRT-consistent.
  - `vcpkg.json` openssl dependency loses its `"platform": "!windows"`
    filter (it was aspirational, never worked, and confirmed wrong by
    the option D canary's LNK2019 errors).
  Full history — every failed option, the symmetry breakage at each
  step, and the strategic escape path to a QUIC-based transport
  (P1 #376) in case the option D wiring ever rots — is preserved in
  `.claude/agents/build-ci.md` under "Windows MSVC static-link history
  and #375". **Do not simplify either half of the Windows wiring** —
  the triplet override OR the hand-rolled `cxx.find_library()` list —
  without reading that agent doc first. Linux and macOS are unaffected
  throughout (meson's cmake dep translator works correctly on
  platforms with single-variant runtime libraries). The rest of the
  dependency rollout (#363, 7 stale Dependabot PRs rebased onto
  `dev`) was gated on this fix and unblocked immediately after the
  PR #373 merge.

- **Erlang gateway test suites (`eunit` + `ct`) now survive Windows
  parallel test scheduling (#375, folded into PR #373).** Two distinct
  Windows-only failures in the gateway test wrapper
  `scripts/test_gateway.py` had to be untangled in sequence:
  - **Cover-races-compile on `gateway_pb.beam`** (commit `b33f1df`
    regression, fixed in `6d8aa5a`). `b33f1df` added a pre-fetch step
    `rebar3 as test compile --deps_only` to warm the hex cache before
    the actual test run. On Linux/macOS this is harmless because
    `_build/test/lib/yuzu_gw/src/` is a symlink to `apps/yuzu_gw/src/`
    and cover instrumentation always reads a consistent view of the
    ebin tree. On Windows — where symlinks are unavailable so rebar3
    copies source files instead — the pre-fetch left
    `_build/test/lib/yuzu_gw/` in a state where the subsequent
    `rebar3 as test eunit` incremental compile raced cover's
    `pmap_spawn` module-scan. Result was a consistent ~10 s failure
    with `{cover,get_abstract_code,2,...,{file_error,
    ".../gateway_pb.beam",enoent}}` on the gpb-generated protobuf
    module before any test executed. `6d8aa5a` drops the pre-fetch
    entirely (redundant on the persistent `yuzu-local-windows` runner
    whose hex cache is already warm) and retains the
    `run_with_retry()` helper with `max_attempts=4` on the actual
    test invocation for continued hex.pm flake protection.
  - **Parallel-compile race between the two gateway suites** (fixed
    in `f0b84c7`). Meson's default test scheduler runs `gateway eunit`
    and `gateway ct` in parallel, both invoking `test_gateway.py`,
    both running `rebar3 as test <suite>` against the same
    `_build/test/lib/<dep>/` tree. rebar3's compile worker writes
    `<name>.bea#` then atomically renames to `<name>.beam`; when two
    processes collide on the same dep (`proper` is first, being the
    largest Erlang dependency), whichever renames first wins and the
    loser's `MoveFileEx` call fails with `ENOENT` on the temp file.
    Linux/macOS tolerate the race via POSIX atomic rename and
    symlinked source trees; Windows does not. The failing suite
    flipped between eunit and ct across runs depending on which
    rebar3 process lost the race. Fix: `meson.build` sets a distinct
    `REBAR_BASE_DIR` per suite (`_build_eunit` vs `_build_ct`) via
    the test `env:` parameter; `scripts/test_gateway.py` honors the
    env var when computing its ebin-wipe path; `.gitignore` gains the
    two new build roots. Two disjoint `_build/` trees cannot race.
    Cost is a one-time extra compile of Erlang dependencies
    (`meck`, `proper`, `covertool` ≈ 10–15 s) in whichever suite
    starts second from a cold cache, paid once per fresh runner and
    then cached by rebar3's user-level hex cache for subsequent runs.
  The pre-`b33f1df` eunit path was passing on an earlier commit only
  because that run happened to avoid the parallel-race by winning the
  scheduling flip; both failure modes had to be fixed before the CI
  cycle could go consistently green. Validated on PR #373 push CI
  run `24426124422` (Windows MSVC debug: `gateway eunit OK 58.58s`,
  `gateway ct OK 78.39s`) — the first fully-green Windows MSVC
  gateway run in the #375 fix chain.

- **`.github/workflows/ci.yml`: Linux jobs (gcc-13/clang-19,
  debug/release) migrated from `ubuntu-24.04` GHA-hosted to
  `yuzu-wsl2-linux` self-hosted runner (commits `f4d634e`, `d12ba74`).**
  Mirrors the Windows MSVC migration to bring all four mainstream
  platforms under self-hosted control, trading hosted-runner cold-cache
  cost for persistent-runner warm-cache and freedom from GHA outages.
  Two follow-up infrastructure gaps surfaced and were closed during the
  migration:
  - **NOPASSWD sudo for `github-runner`** — first push run failed on the
    `Install system packages` step because the `github-runner` user had
    no NOPASSWD sudo grant. Fixed out-of-band by adding
    `/etc/sudoers.d/github-runner` granting NOPASSWD for `apt-get`,
    `apt`, and `dpkg`. The grant is host-side and not version-controlled;
    canonical recovery procedure is documented in
    `docs/ci-troubleshooting.md`.
  - **PEP 668 `externally-managed-environment` (`d12ba74`)** —
    Ubuntu 24.04 (which the WSL2 distro is) ships PEP 668's marker so a
    system-wide `pip3 install` refuses with `EXTERNALLY-MANAGED`. All
    four Linux jobs now use
    `pip3 install --user --break-system-packages -r requirements-ci.txt`
    (the documented bypass for ephemeral CI install-and-go environments)
    plus `echo "$HOME/.local/bin" >> $GITHUB_PATH` so the subsequent
    `meson setup` step finds the `~/.local/bin/meson` shim.

- **WSL2 utility VM keep-alive: `vmIdleTimeout=-1` in `.wslconfig`,
  `loginctl enable-linger dornbrn` for defense-in-depth.** The
  `yuzu-wsl2-linux` self-hosted runner lives inside the WSL2 host distro
  on Shulgi. WSL2's default `vmIdleTimeout=60000` (60 s) shut the utility
  VM down ~60 s after the last interactive shell session ended, which
  killed both the `actions.runner.Tr3kkR-Yuzu.yuzu-wsl2-linux.service`
  systemd unit AND any tmux sessions inside the distro. Confirmed by 4
  VM cycles on 2026-04-15 (07:52, 08:24, 10:06, 13:07 UTC, captured by
  `last reboot`) correlating with SSH disconnect events, and by the
  parent-run-wedge cascade where CI run `24450261405` lost its
  `Linux gcc-13 debug` job mid-execution and the orphaned job could not
  be cancelled until the runner reincarnated and force-cancel propagated.
  Fix in two coordinated changes (both host-side, neither in the repo):
  - `vmIdleTimeout=-1` in `/mnt/c/Users/natha/.wslconfig` (Windows-side
    WSL2 host config, applied via `wsl --shutdown`). `-1` disables the
    idle timeout entirely — appropriate for a runner host where the
    cost of the VM running idle is dwarfed by the cost of cancelling
    an in-flight CI run.
  - `loginctl enable-linger dornbrn` so user-scope systemd survives
    "no sessions" windows even with the VM up. Defense-in-depth, since
    the runner unit is system-scope and didn't strictly need it.
  Canonical recovery procedure documented in `docs/ci-troubleshooting.md`
  as the first runbook entry for the "Linux runner shows offline" /
  "tmux is dying" failure mode.

- **`.github/workflows/ci.yml`: Windows MSVC debug and release jobs
  migrated from the GHA-hosted `windows-2022` runner to the
  `yuzu-local-windows` self-hosted runner (#374, commit `3960f46`).**
  Hosted Windows runners have long vcpkg install times (grpc alone
  takes 10+ minutes from a cold cache) and occasional `applocal.ps1`
  / grpc-build flakes that were blocking the #375 debug iteration
  loop. Moving Windows MSVC onto the persistent self-hosted runner
  cuts warm-cycle time significantly and gives vcpkg's binary cache a
  stable disk to live on across runs. The single-runner serialization
  pattern (only one Windows MSVC job runs at a time) is deliberate —
  the `yuzu-local-windows` runner is a single physical machine with
  one worker — and has the side-effect of flushing out any Yuzu test
  code that was inadvertently relying on hosted-runner-fresh state.
  The migration exposed #375 (LNK2038 was masked on hosted runners by
  a different vcpkg cache layout) which was the gate that had to
  close before the dependabot rollout could proceed.

- **`scripts/test/` harness bugs discovered running `/test --full`
  against uncommitted #339.** Three PR1 harness fixes that landed the
  headline upgrade test at green:
  (a) `test-upgrade-stack.sh` wrote the upgrade-test admin credentials
  with `chmod 600` owned by the test runner's UID. `Dockerfile.server`
  drops to `USER yuzu` (unprivileged) before reading the config, so
  the file was invisible inside the container and v0.10.0 fell through
  to first-run-setup and exited. Now `chmod 644` on the cred file and
  `chmod 700` on the parent `/tmp/yuzu-test-${RUN_ID}/` dir — the
  parent-dir restriction prevents host-side leakage and the 644 on
  the file lets the container yuzu user read it. Also fixes the
  fallback `docker compose logs` diagnostic in the /readyz-timeout
  branch which was missing the required `YUZU_VERSION` and
  `YUZU_TEST_CONFIG` env vars, producing a confusing
  "empty section between colons" error instead of the actual logs.
  (b) `test-fixtures-verify.sh` hit `/api/settings/enrollment-tokens`
  and `/api/settings/api-tokens` as JSON list endpoints — neither
  exists; enrollment tokens are only exposed via the HTMX fragment at
  `/fragments/settings/tokens`. The verifier now reads the fragment
  HTML and counts `<code>...</code>` token-id cells; API tokens are
  verified through the proper `/api/v1/tokens` REST endpoint and
  parsed as JSON.
  (c) `test-fixtures-write.sh` POSTed to `/api/settings/api-tokens`
  with `label=` and `ttl=` form fields, but the handler expects
  `name=` and `ttl_hours=` and silently returns an HTML error
  fragment on mismatch. The writer now uses the correct field names
  and inspects the response body for `feedback-error` before accepting
  the write. (#339 /test verification)
- **`scripts/linux-start-UAT.sh` now exits non-zero on connectivity test
  failure.** Previously the script always exited 0 after the stack stood
  up, regardless of whether the 6 inline connectivity tests passed. The
  /test Phase 4 gate relied on the exit code to detect a broken stack
  and was therefore a false-positive trap. `start_all()` now captures
  the result into `UAT_TEST_RESULT` and returns it, which the script
  propagates as its exit code. **This is a breaking change for any
  caller that assumed the script always exits 0** — in practice there
  are no such callers in-tree, but operators with external scripts that
  pipe to `|| true` should verify they actually want to swallow the
  failure.
- **`ci(release)`: filter `actions/download-artifact@v4` to `yuzu-*`
  pattern.** The auto-generated `*.dockerbuild` provenance metadata files
  (uploaded by docker buildx attestation) consistently failed download
  with `Artifact download failed after 5 retries`, killing the Create
  Release job for v0.10.0 on both the initial run and a `--failed`
  retry. The v0.10.0 release was published manually from local instead,
  at the cost of the `SHA256SUMS.bundle` cosign keyless attestation
  (which requires the GitHub-Actions OIDC issuer
  `token.actions.githubusercontent.com` and cannot be replicated from a
  developer machine). The filter restores the cosign signature for
  v0.10.1+ by skipping the broken artifacts entirely; the 10 `yuzu-*`
  release binaries are unaffected.
- **`ci(cache)`: include `matrix.build_type` in Windows vcpkg cache
  key.** The Windows MSVC matrix runs both debug and release builds
  against the same `vcpkg-x64-windows-${hashFiles(...)}` cache key.
  Whichever job populated the cache first won, and the other job linked
  user code (compiled with `/MDd` and `_ITERATOR_DEBUG_LEVEL=2`) against
  `absl_*.lib` variants built with `/MD` and `_ITERATOR_DEBUG_LEVEL=0`,
  producing dozens of `LNK2038` "RuntimeLibrary mismatch" errors. The
  flake hit PR #355's CI matrix and required an admin override to merge.
  Adding `${{ matrix.build_type }}` to the cache key gives debug and
  release independent slots; the legacy build-type-less restore key was
  intentionally **not** preserved so a poisoned cache can't be silently
  restored. Both matrix jobs will populate fresh caches on their next
  run; this is self-healing. See #356 for the watch list — the
  underlying meson+vcpkg+`CMAKE_BUILD_TYPE` interaction may need a
  follow-up fix if the symptom recurs.

### Tests

- **`tests/unit/server/test_settings_routes_users.cpp` (new, 9
  cases).** First test file for the Settings routes layer. Stands up a
  real `httplib::Server` on a random port with `SettingsRoutes`
  registered against a two-account `AuthManager` (`admin` +
  `bob`), mocks the `auth_fn`/`admin_fn`/`perm_fn`/`audit_fn`
  callbacks (audit_fn captures every call into a vector for evidence-
  chain assertions), and exercises the full HTTP surface. Coverage:
  - **#397 handler guard:** admin-self-DELETE returns 403 with the
    full HX-Trigger payload (not just substring) and leaves the
    account intact; the rejected attempt emits a `user.delete` /
    `denied` audit event (CO-1 evidence chain).
  - **Non-self DELETE:** admin-DELETE of another user returns 200,
    the account is removed, and emits a `user.delete` / `success`
    audit event.
  - **Non-admin DELETE:** rejected by the `admin_fn_` gate before
    the self-delete guard is reached, no audit event recorded.
  - **Unauthenticated DELETE:** rejected by `admin_fn_` with 403,
    target account intact, no audit event recorded.
  - **ca-B1 self-demotion guard (POST):** admin POSTing
    `username=admin&role=user` is rejected with 403 +
    "Cannot change your own role" toast; role remains admin;
    `user.upsert` / `denied` audit event captured.
  - **POST self-password-change:** same username, same role only
    password change — explicitly allowed, returns 200,
    `user.upsert` / `success` audit emitted.
  - **POST success path renders self-row guard:** new user appears
    in the response fragment with hx-delete; operator's own row
    still has Current user badge — regression cover for the
    self_name threading through the success branch.
  - **#403 UI guard:** `GET /fragments/settings/users` emits no
    `hx-delete="/api/settings/users/admin"` attribute for the self
    row, still emits it for every other row, and renders the
    "Current user" badge in its place.
  - **UI guard with multiple users:** every non-self row keeps its
    Remove button when the user list grows.
  Harness uses an RAII `TmpDirGuard` member that cleans up the temp
  directory even if a `REQUIRE` inside the constructor body throws
  (qe-B1 — partially-constructed objects don't run their own
  destructor but fully-constructed members do). Pattern available for
  future Settings-routes regression coverage.
- **`tests/unit/server/test_migration_runner.cpp`** — four new cases
  tagged `[migration][adoption]` exercise the adoption and hardening
  paths: (a) running v1 on a database that already has tables populated
  with data preserves rows and stamps `schema_meta`, (b) a fresh DB gets
  the full latest schema, (c) the legacy compat shim + v1 combination
  stays idempotent across simulated server restarts, (d) a bad migration
  statement rolls back cleanly and leaves the shared connection usable
  for subsequent migrations on other stores (#339). `TestDb` now uses
  `sqlite3_open_v2` with `SQLITE_OPEN_FULLMUTEX` to match the flags
  every production store opens with; `count_rows` and `column_exists`
  helpers now `REQUIRE` that `sqlite3_prepare_v2` succeeds so a test
  typo cannot mask itself as a false-green.

### Deferred follow-ups from #339 governance

- **#358** — Chaos regression tests for the migration runner
  hardening: concurrent-server race (CH-B), mid-startup SIGKILL
  (CH-E), forward-version DB downgrade protection (CH-F / UP-6).
- **#359** — Per-shim-store adoption test coverage: targeted tests
  for the six legacy-compat-shim stores (`api_token_store`,
  `instruction_store`, `patch_manager`, `policy_store`,
  `product_pack_store`, `response_store`) plus `schema_meta` stamp
  assertions in existing store tests and test coverage for the
  eleven stores that currently have none.
- **#360** — Migration observability + SRE hardening: Prometheus
  counters for migration events (OBS-3), log-burst summary line
  (OBS-4), independent `migration.log` audit trail (compliance-F4),
  hot backup via SQLite online backup API (REC-1), CI lint for
  migration runner wiring invariants (UP-17), and compile-time
  `static_assert` for legacy shim removal (arch-SH2).

### Known issues

- **#354** — Linux build job bundles a stale `yuzu-gateway 0.9.0`
  package alongside the fresh `0.10.0` agent and server packages in the
  `yuzu-linux-deb` and `yuzu-linux-rpm` artifacts. Discovered during the
  manual v0.10.0 release on 2026-04-13. **The artifact-download flake
  above masked this** — without the flake, v0.10.0 would have shipped a
  corrupted release with mixed-version `.deb` / `.rpm` files
  (`yuzu-gateway_0.9.0_amd64.deb` next to `yuzu-server_0.10.0_amd64.deb`).
  The manual v0.10.0 release explicitly excluded the stale packages
  when assembling assets locally. Root cause not yet investigated;
  suspected ccache reuse from the v0.9.0 release run, hardcoded version
  in a packaging script, or duplicate gateway packaging in the linux
  build job that should defer to the dedicated `Build Gateway (Erlang)`
  job. P1.
- **#356** — Watch issue for the Windows MSVC debug `LNK2038` flake
  fixed by the cache-key change above. The cache-key fix prevents one
  class of cross-variant cache contamination, but the bug class can
  recur if (a) anyone reverts the discriminator, (b) Linux/macOS jobs
  hit the same pattern (latent — only Windows manifests because of
  MSVC's `_ITERATOR_DEBUG_LEVEL` ABI), or (c) the actual root cause is
  meson's CMake dependency resolver not propagating `CMAKE_BUILD_TYPE`
  into vcpkg's exported port-config files (in which case the cache-key
  fix is incomplete and the next CI run will still fail). Watch list in
  the issue body and follow-up comment. P2.

## [0.10.0] - 2026-04-12

### Added

- **`/governance` skill** at `.claude/skills/governance/SKILL.md` — a
  reusable prompt-writing runbook for the Gate 1–7 governance pipeline
  defined in CLAUDE.md. Provides parameterized agent preambles, the
  Gate 3 domain-triggered decision matrix, conditional Gate 5 chaos
  analysis, and a "Known patterns" section seeded with the five
  failure modes caught in the #222/#224 governance run (sibling IDOR,
  cycle-safe parity, error-branch info disclosure, enumeration oracle,
  readiness probe coverage). Default range is `dev..HEAD` because
  Yuzu's main working branch is `dev`, not `main`. Invoke with
  `/governance <commit-range>` — the skill doesn't fully automate
  (judgment calls on Gate 3 fan-out and Gate 5 skip still required)
  but cuts per-run prompt-writing overhead roughly in half.

- New Prometheus metrics for the auth and audit subsystems:
  `yuzu_server_token_cache_hits_total`, `yuzu_server_token_cache_misses_total`,
  and `yuzu_server_token_cache_size` expose API-token cache effectiveness so
  cold-cache stampedes after restart are visible to operators.
  `yuzu_server_audit_events_total{result}` counts audit-event writes bucketed
  by `success`/`failure`/`denied`/`other`.
- `tests/test_changelog_order.py` enforces reverse-chronological ordering of
  CHANGELOG sections (Keep a Changelog convention). Wired in as a meson test
  (`changelog order`, suite `docs`) and as a new lightweight GitHub Actions
  workflow (`Docs Lint`) that triggers on `CHANGELOG.md` / `docs/**` edits —
  CHANGELOG drift is now caught in CI rather than discovered months later.

### Changed

- **CodeQL workflow is manual-only and runs on the self-hosted Linux
  runner.** `.github/workflows/codeql.yml` previously ran on
  `ubuntu-24.04` via `push` to `main` + weekly schedule, consuming
  GitHub-hosted Actions minutes on every merge. It now targets
  `[self-hosted, Linux]` (same runner as `release.yml`) and triggers
  only on `workflow_dispatch` — fire via the Actions UI or
  `gh workflow run codeql.yml`. No `push`/`pull_request`/`schedule`
  triggers, so it cannot gate PR merges and is not listed in any
  branch protection required check. Output lands in the GitHub
  Security tab under "Code scanning alerts" for informational review.
  Preflight now uses the same `gcc-13 / cmake / ninja / meson / ccache`
  dependency-check pattern as `release.yml`, uses the runner's
  pre-installed vcpkg (drops `lukka/run-vcpkg@v11`), and wraps the
  compiler with ccache for fast repeat runs. Private-repo caveat:
  if the repo ever flips private, CodeQL will require GitHub
  Advanced Security — the action enforces the entitlement check
  server-side regardless of where the job runs.

- **`integration-test.sh` — sleep-assert sweep, gateway-crash regex,
  env-overridable ports.** Three drift fixes to
  `scripts/integration-test.sh` that together reduce per-run
  wall-clock and eliminate two assertion false positives:
  1. **Heartbeat metric wait is now loop-poll, not sleep-assert.**
     The previous `sleep 10` started before the agent finished
     enrolling (which can take ~12s on a cold run with enrollment-
     token retry backoff), so by the time the sleep ended the
     agent's 5s-interval heartbeat thread hadn't fired yet and the
     `yuzu_heartbeats_received_total` assertion failed with no
     signal that the wait budget was wrong. Now a 30s loop-poll on
     `/metrics` that exits the instant the counter appears — sub-
     second on warm runs, still succeeds within 30s on cold runs.
  2. **Gateway-stability regex tightened.** The old
     `grep -qi "crash\|supervisor.*error\|SIGTERM"` tripped on
     benign `[info]`-level diagnostic log lines of the form
     `[info] crash: class=exit exception={noproc,...}` that the
     gateway emits when an agent's first registration attempt
     races the upstream `gen_server` startup (the agent's built-in
     exponential backoff resolves it in ~6s). The regex now
     matches only actual Erlang crash markers:
     `CRASH REPORT|=ERROR REPORT|Supervisor: .* terminating|\[error\].*SIGTERM`.
  3. **Env-overridable port defaults.** Every `SERVER_*_PORT` and
     `GW_*_PORT` now uses `${VAR:-default}` so the script can
     coexist with other live stacks — notably the docker UAT from
     `scripts/docker-start-UAT.sh`, which binds `50055` and `50063`
     on the host. Override pattern:
     `SERVER_GW_PORT=50155 GW_MGMT_PORT=50163 bash scripts/integration-test.sh`.
  Bonus sweep: replaced `sleep 3` gateway grpcbox startup with
  `wait_for_port $GW_AGENT_PORT`, and `sleep 2` agent-disconnect
  propagation with a 2s poll on `kill -0` of the killed PID.
  Verified: 22/22 PASS on first run with zero flakes.

- **Friction pass on build / test workflow** — four developer-experience
  fixes from the governance-run retrospective:
  - **Third-party warnings silenced.** Every `dependency()` in the
    top-level `meson.build` and each subdirectory file now carries
    `include_type: 'system'`, so vcpkg / gRPC / abseil / protobuf /
    Catch2 deprecation warnings become `-isystem` includes and no
    longer appear in compile output. Our own code remains under
    `warning_level=3`. Compile logs dropped by dozens of lines per
    incremental build without a wrapper script in the way.
  - **Short test suite names.** `tests/meson.build` now attaches
    `suite: 'agent' | 'server' | 'tar'` to each `test()` call, so
    `meson test -C build-linux --suite server` works directly — no
    more guessing `"yuzu:server unit tests"` or `"unit tests"`.
  - **Stable top-level test binary paths.** New
    `scripts/link-tests.sh` creates
    `/tests-build-<component>-<triplet>/` directories (e.g.
    `tests-build-server-linux_x64/yuzu_server_tests`) as symlinks
    to the real build output. `scripts/setup.sh` runs it
    automatically after configure. Gitignored. Binaries stay live
    across rebuilds because the symlinks point at paths, not
    contents. Catch2 tag filtering (e.g. `[token][owner]`) is now
    one line from the repo root without remembering the build-dir
    layout.
  - **`.gitignore` cleanup.** Added `.codex`, `test_output.txt`,
    `test_xml.txt`, `update.finished`, `node_modules/`,
    `__pycache__/`, `gateway/.deps_cache/`, `gateway/ebin/`, and
    `/tests-build-*/` so `git status` no longer carries session
    noise from dev-machine artifacts.

- **`CLAUDE.md` slimmed from 571 → 484 lines** by splitting three
  implementation-detail sections into dedicated `docs/` files and
  compressing four already-linked sections to pointers. The Auth &
  Authorization feature history (inventory of mTLS, OIDC, AD/Entra,
  Windows cert store, CSP construction, etc.) moved to
  `docs/auth-architecture.md`; only the hard invariants that every
  session must respect (mTLS, HTTPS default, localhost bind,
  `/metrics` auth, owner-scoped token revoke) remain in CLAUDE.md.
  The MCP server architecture and 22-tool inventory moved to
  `docs/mcp-server.md`; only the tier-before-RBAC rule, kill-switch
  flags, audit pattern, and `JObj`/`JArr` serialization rule remain.
  The Windows build toolchain path table moved to
  `docs/windows-build.md`; CLAUDE.md keeps the "MSYS2 bash +
  `setup_msvc_env.sh`, NOT `vcvars64.bat`" rule. Instruction Engine,
  Enterprise Readiness / SOC 2, Development Roadmap, and CI matrix
  sections were compressed to pointers since the target docs already
  exist. Build, Deploy, Release, Erlang Gateway, UAT Environment,
  Darwin Compatibility, and Agent Team / Governance sections stay
  resident intact — churning subsystems and areas that repeatedly
  need re-loading belong in CLAUDE.md, not in `docs/`.

- `AuthRoutes` exposes a public `resolve_session(req)` helper that performs the
  three-tier auth resolution (cookie → `Authorization: Bearer` → `X-Yuzu-Token`)
  used by `require_auth`, `make_audit_event`, and `emit_event`, plus the eight
  call sites in `server.cpp` that previously inlined fragments of the same logic.
  Removes a shadow copy of `extract_session_cookie` from `server.cpp`.

- **Per-OS canonical build directory** — `scripts/setup.sh` now defaults the
  build directory to `build-linux`, `build-windows`, or `build-macos` based on
  the host OS so the same source tree can be configured concurrently from
  WSL2 and a native Windows shell — and a separate macOS dev box — without
  the build dirs trampling each other. The script refuses to reuse a build
  dir whose `meson-info.json` source path was recorded on a different host
  unless `--wipe` is passed (catches the opaque "ninja dyndep is not an
  input" / Windows-path failures from cross-host reuse). It also stops
  auto-wiping existing dirs — `--wipe` is now opt-in; default behaviour is
  `meson setup --reconfigure` to preserve prior compilation state. The
  legacy `builddir/` is gone from the tree; CLAUDE.md documents the
  convention. `YUZU_BUILDDIR` env var still overrides everywhere.

### Breaking

- **API token revocation is owner-scoped** — non-admin users can no longer
  revoke API tokens they do not own. A caller holding `ApiToken:Delete` may
  revoke only tokens whose `principal_id` matches their session username;
  the global `admin` role is the sole bypass. Deployments that used a
  shared non-admin service account to rotate tokens for other principals
  will begin receiving `HTTP 404 token not found` after upgrade. Either
  grant the rotation account the global `admin` role, or refactor the
  rotation so each principal owns its own token (recommended). The same
  constraint applies to both `DELETE /api/v1/tokens/{id}` and
  `DELETE /api/settings/api-tokens/{id}`. See
  `docs/user-manual/server-admin.md` "Upgrade Notes" for details.

### Fixed

- **UAT script `python` vs `python3` drift.**
  `scripts/docker-start-UAT.sh` (8 inline sites) and
  `scripts/uat-command-test.sh` (2 inline sites) both invoked
  `python -c` for JSON / regex parsing. WSL2 Ubuntu has no `python`
  symlink — only `python3` — so every inline parser silently
  returned empty string, and every downstream numeric check
  degraded without error:
  - `docker-start-UAT.sh`: the 10 embedded connectivity tests
    (server registered count, gateway connected count, Prometheus
    target count, ClickHouse event count, os_info round-trip
    parsing) all read "0" or empty strings and reported test
    failures against a stack that was actually working.
  - `uat-command-test.sh`: every command dispatch reported
    `dispatch error` because the `cmd_id` extraction returned
    empty. All 138 test cases failed. After the fix: 136 PASS /
    0 FAIL / 2 legitimate long-running-plugin timeouts
    (`firewall.rules`, `chargen.chargen_start`).

  Both scripts now use `python3 -c` via a mechanical sed fix.
  Worth a broader audit:
  `grep -rn '\bpython -c' scripts/` would surface any remaining
  sites that were missed.

- **`scripts/docker-start-UAT.sh` build dir detection.** The
  script hardcoded `BUILDDIR=$YUZU_ROOT/builddir`, which predates
  the per-OS build dir convention that landed in `830ba7c`. On a
  fresh clone configured via `scripts/setup.sh`, the agent binary
  now lives at `build-linux/agents/core/yuzu-agent` (or
  `build-macos` / `build-windows`), and the preflight check
  reported "yuzu-agent not found — run: meson compile -C builddir"
  even though the binary existed under the new name. Fixed by
  detecting the host OS and selecting `build-<os>`, falling back
  to the legacy `builddir/` path for older trees. Also added
  `Bash(bash scripts/docker-start-UAT.sh:*)` and the `./` variant
  to the project allowlist at `.claude/settings.json`.

- **Governance Gate 4 follow-up hardening** — Gate 4 unhappy-path and
  consistency-auditor surfaced three new BLOCKING items on the prior
  hardening round; all are addressed here:
  - **Denied-branch token-table leak regression (UP-11)** — the prior
    hardening round's new 404 denied branch on
    `DELETE /api/settings/api-tokens/:id` called
    `render_api_tokens_fragment()` which lists ALL users' tokens with no
    principal filter. A non-owner probe therefore received a 404
    response with a complete fleet-wide token table in the HTML body —
    worse than the IDOR the round was closing. The denied branch now
    returns a minimal static error fragment with no token data.
  - **`render_api_tokens_fragment` cross-user enumeration (C1)** — the
    same underlying `list_tokens()` leak affected the success-path
    re-render (`POST`, `DELETE` success) and the `GET
    /fragments/settings/api-tokens` panel load. The fragment now takes
    a `filter_principal` argument. All four call sites pass
    `session->username` for non-admin sessions and empty (full view)
    for admins, matching the `GET /api/v1/tokens` scoping that
    `rest_api_v1.cpp` already enforced. A new
    `ApiTokenStore: list_tokens(principal) scopes results to owner`
    unit test pins the store contract the fix relies on.
  - **Audit-trail integrity, `principal_role` hardcoded `"admin"`
    (C2, Gate 4 unhappy-path UP-9, Gate 4 happy-path SHOULD, Gate 2
    re-review NICE)** — three audit emission sites in
    `settings_routes.cpp` (token create, token revoke success, token
    revoke denied) hardcoded `.principal_role = "admin"`. This was
    benign when the panel was admin-only but became a forensic lie
    once the hardening round opened the handlers to non-admin callers
    with `ApiToken:Delete`. All three sites now read
    `auth::role_to_string(session->role)`, matching the convention in
    `auth_routes.cpp`.
  - **Test fixture brittleness** — `create_token_for` in
    `test_rest_api_tokens.cpp` used `listing.back()`, but
    `list_tokens` orders by `created_at DESC`, so `.back()` is the
    oldest token. Swapped to `.front()` with a comment so future
    multi-token tests in the same harness do not silently regress.

- **Governance hardening round for #222 and #224** — Gate 2 security review
  on the original fixes surfaced two HIGH sibling findings that are
  addressed here:
  - **Dashboard IDOR** — `DELETE /api/settings/api-tokens/:token_id` (the
    HTMX Settings path) had the same ownership gap as the REST handler
    closed by #222. It now looks up the token, rejects cross-user revokes
    with a generic 404 fragment, and emits a `denied` audit event with
    `detail=owner=<principal>` so forensics can tell an enumeration probe
    from a real not-found.
  - **`get_ancestor_ids` cycle safety** — the companion BFS-upward walk
    in `ManagementGroupStore` still had no visited-node tracking, only a
    depth-10 cap. `RbacStore::check_scoped_permission` unions ancestors
    into the set of groups used for role resolution, so on a cyclic DB a
    user could inherit spurious permissions from phantom ancestors
    reported by the cycle's alternating output. `get_ancestor_ids` now
    carries the same `unordered_set<std::string> visited` + warning-log
    pattern as `get_descendant_ids`.
  - **Enumeration oracle closed on REST `DELETE /api/v1/tokens/:id`** —
    the original fix returned `403 "cannot revoke another user's API
    token"` for cross-user revokes, which let a non-owner with
    `ApiToken:Delete` distinguish "token does not exist" (404) from
    "exists but not yours" (403) and enumerate valid token ids. Both
    paths now return `404 "token not found"` with an identical response
    body; the audit log still carries the distinction server-side via
    `result=denied` + `detail=owner=<principal>`.
  - **`create_group` self-parent** — the create path accepted a
    caller-supplied `group.id == group.parent_id` and produced an
    immediate 1-row self-cycle. It now returns
    `"group cannot be its own parent"` from the same layer as
    `update_group`.
  - **REST-handler test coverage (#222 follow-up)** — the original fix
    landed with store-level coverage only. A new
    `tests/unit/server/test_rest_api_tokens.cpp` spins up a real
    `httplib::Server` on a random port, registers `RestApiV1` routes
    with mock `auth_fn`/`perm_fn`/`audit_fn`, and exercises all four
    paths end-to-end: owner self-revoke, admin cross-user bypass,
    non-owner → 404 (no oracle), unknown id → 404 (no audit). 5 HTTP
    cases, 55 assertions, plus the existing store-level cases.
  - **Store-test fixture parallelism** — both
    `test_management_group_store.cpp` and `test_api_token_store.cpp`
    used hardcoded SQLite paths (`/tmp/test_mgmt_groups.db`,
    `/tmp/test_api_tokens.db`) that would collide under
    `meson test --num-processes N`. Each `TempDb` now builds a unique
    path per instance from `std::thread::id` + `steady_clock`, matching
    the `unique_temp_path` pattern already used in
    `test_rest_api_t2.cpp`.
  - **Deep / self-loop cycle regression tests** — the original fix
    only tested a 2-node cycle. New cases exercise a 3-node A→B→C→A
    cycle and the degenerate self-loop `parent_id == id` on a single
    row. A reparent-to-root regression test guards the null-bind
    branch in `update_group` that the cycle/depth block now gates on.

- **API token revocation is now owner-scoped (#222)** — `DELETE
  /api/v1/tokens/:token_id` previously required only `ApiToken:Delete`
  permission without verifying ownership, so any user with that
  permission could enumerate token IDs (the handler always returned 404
  for unknown IDs but 200 for any real token) and revoke other users'
  tokens. The handler now looks up the token via a new
  `ApiTokenStore::get_token(token_id)` method, rejects cross-user
  revokes with `403` and a `denied` audit event, and only allows the
  bypass for callers holding the global `admin` role. Owner-scoped
  audit detail (`owner=<principal>`) is logged on both success and
  denial paths so forensics can distinguish intent.

- **`get_descendant_ids` is cycle-safe; `update_group` validates
  `parent_id` (#224)** — the management-group BFS traversal had no
  visited-node tracking and no depth cap, so any existing cycle in
  `management_groups.parent_id` (injectable via legacy tooling or
  bugs) would hang the server thread indefinitely. It now carries an
  `unordered_set<std::string> visited` and a `10_000` node safety cap,
  logging a warning if the cap is hit. Independently,
  `ManagementGroupStore::update_group` now rejects self-parent,
  parent-not-found, cycle-forming, and depth-exceeding updates at the
  store layer so non-REST callers (admin tooling, tests, future
  endpoints) cannot bypass the checks that previously only lived in
  the REST handler. Store unit tests cover injected-cycle termination
  via a direct SQLite write that mimics on-disk corruption.

- **Docker-compose UAT image tags parameterized** — `docker-compose.uat.yml`
  was shipping with hardcoded `ghcr.io/tr3kkr/yuzu-{server,gateway}:0.8.1-rc0`
  references that were not updated when the version bumped to 0.9.0, so a
  tester running the file fresh would pull the wrong images. The tags are
  now parameterized as `${YUZU_VERSION:-0.9.0}` so operators can override at
  `docker compose up` time, and a new `scripts/check-compose-versions.sh`
  runs as the first step of the release workflow's `release:` job — it
  rejects any hardcoded `yuzu-{server,gateway,agent}:X.Y.Z` references in
  tracked compose files and verifies the parameterized default matches the
  tag being released, so a stale default blocks the release before any
  assets are published. A corrected `docker-compose.uat.yml` was uploaded as
  a v0.9.0 GitHub release asset to unblock current UAT testers.

- Login page no longer renders `[object Object]` on bad credentials. The inline
  JS in `login_ui.cpp` was reading `resp.error` directly from the structured
  error envelope (`{"error":{"code":N,"message":"..."}}`) and assigning the
  object to `textContent`. It now reads `resp.error.message`, with a string
  fallback for legacy responses and a status-keyed default if parsing fails.
  Fixes #333.

- **`ConcurrencyManager::try_acquire` TOCTOU race** — the count-then-insert
  sequence used a separate `SELECT COUNT(*)` and `INSERT OR IGNORE`, so two
  concurrent callers could each read `count < limit`, each insert, and exceed
  the configured `global:N` or `per-definition` cap. `SQLITE_OPEN_FULLMUTEX`
  serializes individual API calls but does not bind two-statement sequences
  together, so it could not catch this. Fix collapses the check and write
  into a single atomic statement: `INSERT OR IGNORE … SELECT … WHERE
  (SELECT COUNT(*) …) < ?`. The COUNT subquery and the INSERT execute as
  one statement under SQLite's per-statement write lock, so the cap is now
  honored under contention. Idempotent re-acquire of the same
  `(definition_id, execution_id)` is preserved via a follow-up existence
  check on the no-op path. Removes the dead `std::shared_mutex mtx_` member
  in `ConcurrencyManager` and `ScheduleEngine` (declared but never acquired
  by any method) — both classes prepare-and-finalize their statements per
  call, so the application-level mutex is unnecessary on top of FULLMUTEX.
  Fixes #330.

- **Audit Trail Integrity Fix (YZA-2026-001)** — Audit log and analytics event
  rows for requests authenticated via `Authorization: Bearer` or `X-Yuzu-Token`
  now populate the `principal` and `principal_role` fields. Previously these
  helpers resolved the principal from the session cookie only, so every
  API-token-authenticated request — including every MCP tool call — wrote audit
  rows with empty `principal`, breaking attribution for SOC 2 evidence purposes.
  The same gap affected `def.created_by` on instruction creation,
  `sched.created_by` on schedule creation, the `user` recorded by execution
  rerun/cancel, and the `reviewer` recorded by approval approve/reject.

  This is a forward-only fix: pre-fix audit rows are not backfilled. Operators
  auditing a window that spans v0.9.0 (released 2026-04-11) and v0.10.0 should
  expect a bimodal `principal` distribution split at the merge date — pre-fix
  token-authenticated rows will have empty `principal`. Cookie auth and login
  flows are unchanged.

### Tests

Test-suite changes are listed separately so other teams can follow test
development independently from the primary software changelog.

- **TOCTOU regression test for `ConcurrencyManager`** — new `[threading]`
  cases in `tests/unit/server/test_concurrency_manager.cpp` race 64 threads
  against `try_acquire("global:3")` and `per-definition` on a
  `SQLITE_OPEN_FULLMUTEX` `:memory:` connection, asserting that exactly the
  configured limit wins. Adds a `TestDbMt` RAII helper for thread-safe
  in-memory connections, and a non-threaded idempotent re-acquire case.
  Server unit-test count: 1112 → 1128 cases.

- **`scripts/run-tests.sh` (and integration / UAT scripts) honour the per-OS
  canonical build directory** — `build-linux` / `build-windows` / `build-macos`
  selected from `uname` (and overridable via `YUZU_BUILDDIR`). Removes the
  hard-coded `builddir/` path that broke under WSL2 once the Windows-side
  build dir disappeared.

- **`run-tests.sh erlang-unit` invokes `rebar3 eunit --dir=apps/yuzu_gw/test`**
  — works around rebar3 3.27 auto-discovery rejecting test modules whose name
  has no 1:1 src/ counterpart (`circuit_breaker_tests`, `env_override_tests`,
  `scale_tests`, every `*_SUITE` file, etc.). The bare `rebar3 eunit`
  invocation would error out with "Module … not found in project" before
  running any test. Tracking issue: #337.

- **Gateway eunit fixture leak: `agent_tests:starts_streaming` cancellation**
  — `yuzu_gw_health_nf_tests:cleanup/1` only killed the mock pids it captured
  in `setup/0`, but the `readyz_503_dead_process` test kills the original
  `yuzu_gw_registry` mock and re-registers a fresh `mock_loop/0` pid that the
  cleanup tracking never sees. The leaked mock survived into every subsequent
  test module; downstream tests checked `whereis(yuzu_gw_registry)` and
  reused it as if it were the real gen_server. When `agent_tests:setup`
  fired, `yuzu_gw_agent:init/1` issued `gen_server:call(yuzu_gw_registry,
  {register, …})` against the mock, which received the message and silently
  recursed without replying — eunit cancelled the call at its 5-second limit
  and the rest of `agent_tests` (14 tests) never ran. The full eunit suite
  reported "Passed: 132. One or more tests were cancelled" instead of the
  expected 148. Fixes:
  - `health_nf_tests:cleanup/1` now looks up the *current* registered pid
    via `whereis/1` for each name it owned at setup time, so re-registered
    mocks are killed too.
  - `agent_tests:setup/0` defensively detects a stale mock under
    `yuzu_gw_registry` (anything whose `proc_lib:initial_call/1` is not
    `{gen_server, init_it, _}`), unregisters it, and starts a real
    registry — guarding against the same class of leak from any future
    test module.
  - `agent_tests:setup/0` also asserts `whereis(yuzu_gw_upstream) =:=
    undefined` so meck-coexisting-with-a-live-gen_server failures fail
    loudly at the boundary instead of producing opaque downstream timeouts.
  - `circuit_breaker_nf_tests`, `circuit_breaker_tests`, and
    `upstream_tests` cleanup paths now use synchronous
    `gen_server:stop(Pid, shutdown, 5000)` instead of `exit(Pid, shutdown)
    + timer:sleep(50)`. The sleep was racy on busy boxes (WSL2 in
    particular) and could leave the upstream gen_server alive into the
    next test module. Eunit count: 133 passing (with all 15 `agent_tests`
    cases cancelled) → 148 passing. Fixes #336.

- **`scripts/integration-test.sh` fixes** — admin password bumped from 8 to
  12 characters to satisfy the post-v0.9 length requirement; `--no-https`
  added so the server starts without TLS in test mode; port matrix split so
  single-host gateway + server no longer collide on 50051 (server `5005x`,
  gateway `5006x`); `YUZU_KEEP_WORK_DIR=1` env var preserves
  `/tmp/yuzu-integration.*` after teardown for post-mortem of failed runs.

- **`scripts/linux-start-UAT.sh` `kill_stale` matches the gateway** —
  `pgrep -f "beam.smp"` is replaced with `pgrep -f "yuzu_gw[/_]"` because
  the rebar3 release wrapper rewrites `cmdline` so the binary name doesn't
  appear in `/proc/$pid/cmdline`. Previous behaviour leaked the gateway
  beam between UAT runs and tied up port 9568 / 50063 indefinitely.

- **`scripts/e2e-security-test.sh` no longer skips on missing creds** —
  honours `YUZU_ADMIN_PASS` env var, then auto-detects against the canonical
  UAT password (`YuzuUatAdmin1!`) and the post-tightening `adminpassword1`
  before falling back to legacy short passwords. Hard-fails if no candidate
  works rather than silently skipping the auth-bearing test categories.
  Brings the security suite from 33 → 60 tests against a live UAT stack.

## [0.9.0] - 2026-04-11

### Added

#### Server
- **`--data-dir` CLI flag** (env: `YUZU_DATA_DIR`) — separates SQLite database storage from the config file location. Required for containerized deployments where the config is mounted read-only but databases need a writable volume. Path is resolved to canonical form at startup (symlinks followed). A writable probe runs at startup to fail fast if the directory is not writable, rather than deferring to the first DB open.
- **`execute_instruction` MCP tool** — dispatches plugin commands to agents via MCP JSON-RPC. Accepts `plugin`, `action`, `params`, `scope`, and `agent_ids`. Returns a `command_id` for asynchronous result polling via `query_responses`. Plugin and action names are normalized to lowercase before dispatch. MCP tool count: 22 → 23.
  - `operator` tier: executes immediately (auto-approved).
  - `supervised` tier: returns `-32006 APPROVAL_REQUIRED` with an explicit message that approval-gated MCP execution is not yet implemented.
  - `readonly` tier: blocked.
  - If neither `scope` nor `agent_ids` is provided, defaults to all agents (documented in tool description as a warning).

#### Testing
- **Puppeteer E2E test expanded** (`Synthetic-UAT-Puppeteer.js`) — 70 → 115 non-destructive commands. Cross-platform path support via `YUZU_AGENT_OS` env var. Added: `network_config dns_cache`, `network_actions ping/flush_dns`, `users group_members`, `filesystem search/search_dir/create_temp/create_temp_dir`, `vuln_scan cve_scan/config_scan/inventory`, `storage set/get/list`, `tags set/get/get_all/check/count`, `agent_actions set_log_level`, TAR extended, `chargen start/stop`, `wol check`, registry read-only (Windows), `windows_updates` extended.
- **REST API command test expanded** (`scripts/uat-command-test.sh`) — 145 → 151 dispatches. Added: `agent_actions set_log_level`, `network_actions flush_dns`, `filesystem create_temp/create_temp_dir`, `interaction notify`. Removed destructive `status switch`.
- **MCP Haiku subagent test framework** — stdio-to-HTTP MCP adapter (`scripts/mcp-http-adapter.js`), Claude Code agent definition (`.claude/agents/mcp-uat-tester.md`), and test harness (`scripts/e2e-mcp-haiku-test.sh`) that invokes Haiku to exercise all MCP tools end-to-end.
- **15 `execute_instruction` unit tests** (`tests/unit/server/test_mcp_server.cpp`) — happy dispatch, null dispatch_fn, missing params, zero agents, default scope, explicit agent_ids, params forwarding, non-string params, read_only_mode, readonly/operator/supervised tier enforcement, audit trail on success and failure.
- **`--setup` flag on all E2E test scripts** — optional Docker Compose lifecycle management. Default: health-check and fail fast. `--setup`: bring up `docker-compose.local.yml`, wait for health, then run.
- Tool count assertions changed from exact equality to `>= 23` minimum with named presence checks — no more magic numbers that break when tools are added.

#### Deployment
- **`docker-compose.local.yml` port topology** — gateway owns host port 50051 (agent-facing), server agent port is container-internal only. Agents connect to `localhost:50051` with default settings.
- **`docker-compose.local.yml` uses `--data-dir /var/lib/yuzu`** — config at `/etc/yuzu/yuzu-server.cfg` (read-only Docker config mount), databases at `/var/lib/yuzu` (writable volume).

### Changed
- `AuthManager::state_dir()` — enrollment tokens and pending agents now written to `--data-dir` when set, instead of always using the config file's parent directory. `reload_state()` re-loads from the new location after `set_data_dir()`.
- `Config::db_dir()` helper method — all ~25 DB path derivations in `server.cpp` use `cfg_.db_dir()` instead of `cfg_.auth_config_path.parent_path()`.
- MCP `read_only_mode` and `mcp_disabled` flags captured by reference (not value) so runtime toggle via Settings UI takes effect without server restart.
- MCP operator tier no longer requires approval for `Execution/Execute` — matches documented "auto-approved" behavior.
- MCP approval-gated operations return `-32006 APPROVAL_REQUIRED` (was `-32603 Internal Error`). Audit status logged as `"approval_required"` instead of `"failure"`.
- `linux-start-UAT.sh` gateway startup changed from `erl` direct to rebar3 prod release binary.
- Default password in test scripts updated to `adminpassword1` (Docker UAT default) with `YUZU_PASS` env var override.

### Documentation
- `docs/user-manual/server-admin.md` — `--data-dir` flag added to CLI flags table and Data Storage section.
- `docs/user-manual/mcp.md` — `execute_instruction` tool added (#23), tool count updated, tier authorization table corrected (operator execution is auto-approved), approval workflow table updated, troubleshooting section clarified.
- `CLAUDE.md` — MCP Phase 1 updated (23 tools, `execute_instruction` documented), Phase 2 reduced to 5 remaining tools.
- `.claude/agents/release-deploy.md` — UAT environment knowledge documented (port topology, data directory separation, Docker file/directory race condition, Grafana dashboard packaging gap, enrollment token API).

## [0.8.1] - 2026-04-11

### Added

#### Testing
- **Comprehensive MCP protocol test suite** (`scripts/e2e-mcp-test.sh`, 140 tests) — exercises all 22 read-only tools, 3 resources, 4 prompts, JSON-RPC protocol methods (initialize, ping, notifications), parameter validation, authentication enforcement, audit trail verification, Phase 2 write tool guards, response format validation, and sequential call state isolation.
- **Expanded REST API E2E test suite** (`scripts/e2e-api-test.sh`, 153 tests) — 26 new sections covering execution statistics, help system, webhook/policy/workflow/instruction-set CRUD, YAML validation, approvals, execution lifecycle with response polling, notifications, agent properties, runtime config, analytics, NVD, inventory queries, directory/discovery, scope engine, 17 settings fragments, 5 dashboard fragments, SSE stream connectivity, static asset delivery, security header verification, MCP endpoint reachability, topology, statistics, license, software deployment, and patch management.
- **Expanded plugin command test** (`scripts/uat-command-test.sh`, ~115 commands across 36 groups) — 12 new plugin groups: example plugin (ping/echo), asset tags, network actions, storage KV CRUD, tags CRUD, TAR extended (sql/configure), vulnerability scanning extended (scan/cve_scan/config_scan), Wake-on-LAN check, chargen traffic generation, HTTP client extended, certificates, and Windows update patch connectivity. Filesystem and IOC tests auto-detect Linux vs Windows and use appropriate paths.

#### Infrastructure
- **Docker Compose local UAT stack** (`docker-compose.local.yml`, gitignored) — uses locally-built images (`yuzu-server:local`, `yuzu-gateway:local`) with full observability (Prometheus, Grafana, ClickHouse). Dashboards provisioned via Docker configs. Separate from `docker-compose.uat.yml` which references ghcr.io images for remote testers.

### Fixed

#### Server
- **Web server connection drops under modest load** — increased cpp-httplib TCP listen backlog from 5 to 128 via `-DCPPHTTPLIB_LISTEN_BACKLOG=128` compile flag. The default backlog of 5 caused the kernel to reject incoming TCP connections when more than 5 were queued for acceptance, resulting in HTTP 000 (connection refused) errors during serial API testing at ~50 requests. Also increased socket read/write timeouts from 5s to 30s to prevent in-progress connections from being dropped under load.
- **Parameterized instruction definitions returning "Unknown Action"** — agent plugins register actions in lowercase but instruction definitions preserved the original case from YAML. Added `std::tolower` normalization at all three creation paths (JSON POST, YAML POST, and the `CommandDispatchFn` adapter).
- **Approval gate not enforced on instruction execution** — `ApprovalManager` was fully implemented but never wired into `workflow_routes::register_routes`. Added approval_mode validation on create/update, fail-closed gate on execute (auto/always/role-gated/unknown), and 202 response for pending approvals.
- **PUT /api/instructions/:id resetting approval_mode** — full-object replacement was overwriting existing fields including `approval_mode`. Changed to partial update preserving unspecified fields.
- **Agent heartbeat deadlock and session races** — fixed heartbeat processing deadlock, session race conditions during re-enrollment, and gateway connection lifecycle issues.

#### Gateway
- **EUnit test cascade failure** (7 modules, 47 tests) — root cause was `yuzu_gw_scale_tests` starting `yuzu_gw_router` and `yuzu_gw_heartbeat_buffer` in test functions without stopping them in cleanup. Fixed cleanup to stop all started processes, added defensive `catch meck:unload` before `meck:new` in all test setups, and defensive `case whereis` for `start_link` calls.
- **`compute_scheduler_util` undef in gauge tests** — function was behind `-ifdef(TEST)` guard but rebar3 test profile didn't propagate `{d, 'TEST'}` to umbrella app compilation. Fixed by unconditionally exporting the function.
- **`agent_count/0` returning `undefined`** — `ets:info(Table, size)` returns `undefined` for nonexistent tables. Added guard clause in `yuzu_gw_registry.erl`.

### Documentation
- `docs/user-manual/rest-api.md` — added 202 response documentation for instruction execute endpoint.
- `docs/user-manual/instructions.md` — documented approval executor-side behavior and action case-insensitivity.
- `docs/yaml-dsl-spec.md` — added case-insensitivity note to action field specification.

## [0.8.0] - 2026-04-09

### Added

#### Security
- **HTTP security response headers (SOC2-C1, #310)** — every HTTP response (dashboard, REST API, MCP, metrics, health probes) now carries six headers: `Content-Security-Policy`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy` (deny-all baseline for camera/mic/geo/usb/etc.), and `Strict-Transport-Security: max-age=31536000; includeSubDomains` on HTTPS deployments. The CSP also appends `upgrade-insecure-requests` on HTTPS.
- New `--csp-extra-sources` CLI flag (env: `YUZU_CSP_EXTRA_SOURCES`) for whitelisting customer CDNs, monitoring beacons, or analytics endpoints. Validated at startup with strict allow-list — rejects control bytes, semicolons, commas, `'unsafe-eval'`, `'strict-dynamic'`, and other unsafe CSP keywords.
- New `server/core/src/security_headers.{hpp,cpp}` module (`yuzu::server::security` namespace) with `HeaderBundle::make()`/`apply()` shared between the production server and the unit/integration tests, ensuring header logic cannot drift between code and tests.
- New `tests/unit/server/test_security_headers.cpp` (38 cases / 146 assertions) and `tests/unit/server/test_static_js_bundle.cpp` (11 cases / 30 assertions) covering CSP construction, validation grammar, end-to-end emission via real `httplib::Server`, and embedded HTMX bundle integrity.
- Resolved security header bundle is logged at INFO at startup so operators can confirm activation: `Security headers active: CSP=N bytes, HSTS=on/off, ...`.

#### Server
- **HTMX 2.0.4 runtime and htmx-ext-sse 2.2.2 extension embedded in the server binary** (`server/core/src/static_js_bundle.cpp`) and served from same-origin `GET /static/htmx.js` and `GET /static/sse.js`. The dashboard works in **air-gapped deployments out of the box** with no internet connectivity required. The HTMX bundle is split into 4 chunks of ≤14000 bytes (MSVC raw string literal limit C2026) and concatenated at static-init into a single `extern const std::string`. Reassembled output is byte-identical to the upstream minified file (50918 bytes). Both upstream packages are 0BSD which imposes no redistribution conditions.

### Changed

#### Security
- **CSP `script-src` is now fully `'self'`-only** with no external CDN allowance — `https://unpkg.com` whitelist removed because HTMX is now served same-origin. Improves SOC 2 supply-chain posture and removes a third-party origin from the dashboard's attack surface.
- All six dashboard-bearing UI templates (`dashboard_ui.cpp`, `settings_ui.cpp`, `compliance_ui.cpp`, `instruction_ui.cpp`, `statistics_ui.cpp`, `topology_ui.cpp`) migrated from `<script src="https://unpkg.com/htmx.org@2.0.4">` to `<script src="/static/htmx.js">`. Same for the SSE extension.

#### UAT Scripts
- `scripts/win-start-UAT.sh` and `scripts/linux-start-UAT.sh`: added `--listen 0.0.0.0:50054` to the server invocation when running with the gateway on the same host. In single-host UAT both server and gateway default to `:50051` for agent gRPC; without the override the server wins the bind and the agent connects directly, bypassing the gateway. Confirmed via `gw-session-` prefix on the agent session ID. Multi-host production deployments are unaffected.

### Fixed

- **Agent registration never reported OS or architecture** — `agents/core/src/agent.cpp` declared compile-time `kAgentOs`/`kAgentArch` constants for every supported platform but never plumbed them into `RegisterRequest.info.platform`. The `Platform` sub-message was always empty, so the server stored `os=""` and `arch=""` for every agent, the dashboard scope panel meta line read `<agent_id> · / · vX.Y.Z` (orphaned `/` between empty fields), and the OTA updater couldn't match agent platform to update binaries. Fix: populate `info->mutable_platform()->set_os/set_arch/set_version` during the registration build. New `get_os_version()` helper uses `RtlGetVersion` via NTDLL on Windows (avoids manifest-based version spoofing) and `uname()` on Unix. Verified end-to-end: `/api/agents` now returns `{os: "windows", arch: "x86_64"}` and the scope panel meta line reads `<agent_id> · windows/x86_64 · vX.Y.Z`.
- **Dashboard scope panel showed "0 agents" under strict CSP** — the SOC2-C1 CSP introduced in commit 7474006 forbade `'unsafe-eval'`, but the dashboard relied on HTMX's `hx-on:` attributes and `hx-vals="js:..."` syntax which both internally call `new Function(...)`. The browser silently blocked the eval, so the scope-list HTMX poll fired without its `selected` parameter and the SSE-driven refresh hooks never ran. Effect: registered agents appeared in the server's API and could execute commands, but never appeared in the dashboard scope panel — even when they responded successfully. Fix: replaced all 8 eval-requiring HTMX attributes in `dashboard_ui.cpp` (3× `hx-on:htmx:sse-message`, 2× `hx-on::after-*`, 1× `hx-on::before-request`, 2× `hx-vals="js:..."`) with equivalent `addEventListener` and `htmx:configRequest` event-listener bindings in the existing inline `<script>` block, which is covered by the `'unsafe-inline'` allowance and does not require `'unsafe-eval'`. Verified end-to-end via headless Chrome: scope panel populates (`agent_count_text: "1 agent"`, `scope_list_child_count: 6`) and `browser_errors` count drops from 1 to 0 in the Synthetic UAT report.
- **Dashboard `agents` map was indexed wrong** — the `/fragments/scope-list` endpoint returns the agent list as a JSON array of `{agent_id, hostname, ...}` objects, but the dashboard's JS expected an object keyed by `agent_id`. `agentDisplayName(agentId)` and `cmdPalette.agentsCache` both silently failed to look up agents by ID. Fix: convert the array to a `{agent_id: agentObj}` map in the new `htmx:afterSwap` handler before assigning to the global `agents` variable.
- Closed M11 in `Release-Candidate.local.MD` risk register: HTMX no longer loaded from external `unpkg.com` CDN.

### Documentation

- `docs/user-manual/security-hardening.md` rewritten with: a six-row CSP/HSTS/X-Frame-Options/X-Content-Type-Options/Referrer-Policy/Permissions-Policy table, the `'unsafe-inline'` rationale, embedded HTMX runtime explanation (replacing the old "unpkg.com allowance" section), `--csp-extra-sources` validation behavior with rejection examples, "Behind a reverse proxy" CSP-intersection note, bandwidth note (~700-900 bytes/response overhead), and a corrected `curl | grep -E` verification example.
- `CLAUDE.md` Authentication & Authorization section updated to document the SOC2-C1 implementation, the local HTMX embedding, and the validated `--csp-extra-sources` flag.
- `docs/test-coverage.md` registers the new `test_security_headers.cpp` and `test_static_js_bundle.cpp` suites.
- `docs/user-manual/rest-api.md` cross-links to the new HTTP Security Response Headers section.
- `docs/user-manual/server-admin.md` documents the new `--csp-extra-sources` flag with rejection grammar.


## [0.7.1] - 2026-04-08

### Added

#### Server
- ClickHouse analytics event drain with CLI configuration parameters
- TAR data warehouse: typed SQLite tables, SQL query engine, rollup aggregation
- Instruction execute API endpoint for programmatic command dispatch
- Rich Grafana dashboard templates for fleet analytics and observability
- Ctrl+K command palette enabled on all dashboard pages
- Default evaluation credentials (`admin/administrator`, `user/useroperator`) documented with change-immediately warning

#### Infrastructure
- Enterprise readiness plan for SOC 2 compliance and first customer preparation
- Enterprise installers: DEB and RPM packages with systemd integration
- Pre-release QA pipeline with release workflow artifact validation
- Docker UAT environment with dep-cached builds and automated tests
- Windows UAT environment with Prometheus + Grafana observability stack
- Puppeteer synthetic UAT tests for end-to-end browser validation
- Pre-populated CI Docker images for faster build times
- Self-hosted runner infrastructure (Linux, Windows)
- NuGet binary cache as fallback for vcpkg package caching
- 3 new governance agents: compliance-officer, SRE, enterprise-readiness
- `scripts/docker-release.sh` — local Docker build + push script with `--dry-run` and `--build-only` flags

### Changed

#### Networking — Port Standardization
- **Port 50051 is now the universal agent door** — server listens on 50051 in standalone mode, gateway listens on 50051 in scaled deployments. Agents always connect to `<host>:50051` regardless of topology.
- Gateway agent-facing port changed from 50061 → 50051 (all configs, compose files, scripts, docs)
- Stale port 50054 references corrected to 50051 across 25 files
- Standalone Docker Compose (`docker-compose.yml`) simplified — server + agent only, no gateway required
- Gateway Docker Compose (`docker-compose.full-uat.yml`) updated for gateway-mode server deployment

#### Docker
- Server Dockerfile defaults to zero-arg startup: `--listen 0.0.0.0:50051 --no-tls --no-https --web-address 0.0.0.0 --web-port 8080 --config /var/lib/yuzu/yuzu-server.cfg`
- Gateway Dockerfile upgraded from Erlang/OTP 27 to 28 (pinned digest)
- Gateway Dockerfile exposes health port 8081
- Agent Docker image removed from release pipeline (use native installers instead)
- Multi-arch Docker builds removed (linux/amd64 only; macOS agent uses native installer)

#### Build & CI
- Release workflow gateway build upgraded from OTP 27 to OTP 28

### Fixed

#### Security — CRITICAL
- **SIGBUS crash in SQLite stores under concurrent HTTP load (#329)** — all 30 stores migrated from `sqlite3_open()` to `sqlite3_open_v2()` with `SQLITE_OPEN_FULLMUTEX`, enabling SQLite's serialized threading mode per-connection. Runtime `sqlite3_threadsafe()` guard added at server and agent startup. WAL mode and `busy_timeout` pragma consistency enforced across all stores.

#### Security — MEDIUM
- XSS, error information leakage, and missing SQLite pragmas (governance findings)
- MCP thread-safety race conditions identified and fixed via ThreadSanitizer
- CEL list index undefined behavior on out-of-bounds access

#### Server
- Gateway command forwarding: IPv6 port conflict resolution and retry logic
- ClickHouse analytics drain connection and ingest reliability
- Enter key form submission fixed on all dashboard pages
- Patch manager test crash on Windows

#### Build & CI
- macOS CI upgraded to macos-15 (Xcode 16) with `clock_cast` and CTAD compatibility fixes
- Clang upgraded 18 → 19 with CoreFoundation linkage and `from_chars` portability fixes
- ARM64 cross-compile: pkg-config path resolution for vcpkg
- Windows: migrated to `x64-windows-static-md` vcpkg triplet, static gRPC/abseil linkage fixes (LNK2005/LNK2019)
- Windows system libraries migrated to `#pragma comment(lib)` for build reliability
- LTO disabled for problematic configurations (Linux x64 self-hosted, Clang 19 release)
- Apple Clang: deduction guide for `ScopeExit`, `execvpe` platform guard, `environ` linkage
- CI concurrency: per-SHA group to prevent self-cancellation
- InnoSetup plugin paths corrected for Windows installer builds
- Linux ARM64 cross-compile removed from CI (no ARM64 runner available)

## [0.7.0] - 2026-03-30

### Added

#### Gateway
- Gateway defaults moved to own port range (5006x) — server, gateway, and agent can now run on the same box without port overrides
  - Agent-facing gRPC: 50051 → 50061
  - Management gRPC: 50052/50053 → 50063
  - Health HTTP: 8080 → 8081 (consistent across dev and prod configs)
- UAT enrollment token automatically saved to `/tmp/yuzu-uat/enrollment-token` for CT suite consumption

#### Server
- Semantic YAML syntax highlighting in the Instructions editor preview pane
  - `type: question` renders green, `type: action` orange, `approval: required` red, `concurrency: single/serial` yellow
  - Color legend now matches actual preview output
- YAML editor value color changed from near-blue (#a5d6ff) to gray-white (#c9d1d9) for clearer key/value contrast

#### Infrastructure
- Linux UAT script (`scripts/linux-start-UAT.sh`) with full server-gateway-agent stack, 6 automated connectivity and command round-trip tests
- `real_upstream_SUITE` CT suite auto-reads enrollment token from UAT environment (no manual token setup needed)

### Fixed
- YAML editor preview now triggers on paste events (changed HTMX trigger from `keyup` to `input` for cross-browser compatibility with Safari/context-menu paste)
- Stale database directories no longer break session authentication on server restart (UAT script wipes state on each run)
- Help command display and result table clearing on HTMX dashboard
- Enrollment token `max_uses` increased from 10 to 1000 to support CT suite test runs

## [0.6.0] - 2026-03-28

### Changed (Architecture — God Object Decomposition)

- **server.cpp decomposed from 11,437 to 4,411 LOC** — ServerImpl is now a slim composition root
- 24 new files extracted (9,008 LOC total), each independently compilable and testable
- Route modules use callback-injection pattern: `register_routes(httplib::Server&, AuthFn, PermFn, AuditFn, ...stores...)`
- Extracted route modules: `auth_routes`, `settings_routes`, `compliance_routes`, `workflow_routes`, `notification_routes`, `webhook_routes`, `discovery_routes`
- Extracted inner classes: `agent_registry`, `agent_service_impl`, `gateway_service_impl`, `event_bus`
- `InstructionDbPool` RAII wrapper replaces raw `sqlite3*` pointer for shared instruction DB (fixes G3-ARCH-T2-002)
- `route_types.hpp` provides shared `AuthFn`/`PermFn`/`AuditFn` callback type aliases
- `AgentServiceImpl` mutable members moved from public to private
- Governance findings G3-ARCH-001, G3-ARCH-T2-001, G3-ARCH-T2-002 marked FIXED in code review register

### Fixed
- Scoped API tokens with null `TagStore` now return 503 instead of silently granting access
- `InstructionDbPool` member declaration order corrected — destroyed after all consumers

### Added
- Wave 8: Release hardening (schema migrations, env var config, rate limiting, log rotation, health endpoints)
- MCP (Model Context Protocol) server embedded at `/mcp/v1/` with JSON-RPC 2.0 transport
- 22 read-only MCP tools: list_agents, get_agent_details, query_audit_log, list_definitions, get_definition, query_responses, aggregate_responses, query_inventory, list_inventory_tables, get_agent_inventory, get_tags, search_agents_by_tag, list_policies, get_compliance_summary, get_fleet_compliance, list_management_groups, get_execution_status, list_executions, list_schedules, validate_scope, preview_scope_targets, list_pending_approvals
- 3 MCP resources: yuzu://server/health, yuzu://compliance/fleet, yuzu://audit/recent
- 4 MCP prompts: fleet_overview, investigate_agent, compliance_report, audit_investigation
- Three-tier MCP authorization model (readonly, operator, supervised) enforced before RBAC
- MCP token support via existing API token system with mandatory expiration (max 90 days)
- `--mcp-disable` kill switch and `--mcp-read-only` mode CLI flags (+ YUZU_MCP_DISABLE / YUZU_MCP_READ_ONLY env vars)
- Audit trail integration for all MCP tool calls with `mcp_tool` field on AuditEvent
- MCP unit tests covering JSON-RPC parsing, tier policy, token integration, and store interactions

### Changed (Capability Audit — 2026-03-26)

- Capability map audited against codebase: 32 capabilities marked "not started" or "partial" were already implemented
- Corrected total from 96/142 (68%) to **150/184 (82%)**
- Updated per-domain summary counts and progress bars
- Plugin coverage matrix expanded from 29 to 44 entries with all plugin categories

#### Capabilities confirmed implemented (previously marked not started)
- **Network:** WiFi scanning (4.6), Wake-on-LAN (4.7), ARP subnet discovery (4.10)
- **User/Session:** Primary user determination (6.2), local group membership (6.3), connection history (6.4), active sessions (6.5)
- **Patch Management:** Deployment orchestration (8.3), per-device status tracking (8.4), metadata retrieval (8.5), fleet compliance summary (8.7)
- **Security:** Device quarantine with whitelist (9.6), IOC checking (9.7), certificate inventory (9.8), quarantine status tracking (9.9)
- **File System:** ACL/permissions inspection (10.7), Authenticode verification (10.8), find-by-hash (10.14)
- **Inventory:** Table enumeration (15.3)
- **Auth:** Management-group-scoped roles (18.4), AD/Entra integration via Graph API (18.6)
- **Device Mgmt:** Hierarchical management groups (19.4), device discovery (19.5), custom properties (19.6), deployment jobs (19.7)
- **Notifications:** System notifications (21.3), webhook event subscriptions (21.4)
- **Infrastructure:** Product packs with Ed25519 signing (22.8)

#### Capabilities upgraded from partial to done
- **Platform Configuration (22.4):** RuntimeConfigStore with safe-key whitelist, no-restart updates
- **Gateway / Scale-Out (22.5):** Full Erlang/OTP gateway with circuit breaker, heartbeat batching, health endpoints
- **REST API (24.3):** Versioned `/api/v1/` prefix, 70+ endpoints, OpenAPI spec, CORS allowlist
- **Data Export (24.5):** CSV and JSON export endpoints with Content-Disposition headers

#### Capabilities upgraded from not started to partial
- **Reboot Management (8.6):** `reboot_if_needed` flag on patch deployments (no scheduled reboot workflow yet)
- **System Health Monitoring (22.1):** /livez, /readyz probes + Prometheus metrics (no CPU/memory/queue monitoring yet)

### Added (Governance — 2026-03-28)
- 4 governance review agents: happy-path, unhappy-path, consistency-auditor, chaos-injector
- 7-gate governance process (expanded from 5 gates) with mandatory correctness & resilience analysis
- REST API v1 documentation for 25 previously undocumented endpoints (inventory, execution statistics, device tokens, software deployment, license management, topology, fleet statistics, file retrieval, OpenAPI spec)
- Agent reconnect loop with exponential backoff (1s to 5min) on registration or stream failure
- Semver downgrade protection in OTA updater — rejects older/equal versions
- Per-plugin KV namespace isolation — `PluginContextImpl` with correct `plugin_name` per plugin

### Fixed (Full Governance Review — ~380 findings across 492 files)

#### Security — CRITICAL (5 fixed)
- OIDC JWT signature verification via JWKS — forged ID tokens were previously accepted
- 4 SQLite stores had mutexes declared but never locked (tag, discovery, instruction, deployment)

#### Security — HIGH (18 fixed)
- Replaced `std::regex` with RE2 in CEL `.matches()` and scope `MATCHES` operator (ReDoS)
- CEL evaluation wall-clock timeout (prevents infinite loops in policy evaluation)
- 11 SQLite stores gained shared_mutex protection for thread-safe concurrent access
- RBAC permission cache to reduce per-request SQL query amplification
- API token IDs extended from 12-char to 24-char hex (96-bit collision resistance)
- MCP kill switch now evaluated at runtime, not just startup
- ApprovalManager TOCTOU fixed with mutex + atomic WHERE on concurrent approve/reject
- MCP read_only_mode captured by reference for runtime toggle support
- Prometheus histogram `observe()` fixed — was double-counting across all bucket boundaries
- Agent double plugin shutdown prevented on normal exit
- Stagger/delay capped at 5min each to prevent thread pool worker exhaustion

#### Security — MEDIUM (25 fixed)
- Minimum password length enforced (12 characters)
- Expired sessions opportunistically reaped
- Token generation switched from mt19937_64 to CSPRNG (RAND_bytes)
- Security response headers added (X-Frame-Options, HSTS, X-Content-Type-Options)
- CSRF protection via Origin header validation
- RBAC `set_permission` validates effect as "allow" or "deny"
- OIDC pending challenges capped at 1000 entries with expiry cleanup
- MCP `/health` resource now requires RBAC check
- Dead CORS helper removed (was reflecting arbitrary Origin)
- Execution statistics limit clamped to 1000
- CEL recursion depth reduced from 64 to 16; string concatenation capped at 64 KiB
- Unknown characters in CEL lexer return Error token instead of silent skip
- Scope engine NOT recursion protected with DepthGuard
- Response/audit store cleanup threads wrapped in proper mutex locks
- Fleet compliance cache writes corrected from shared_lock to unique_lock
- Non-thread-safe static RNGs made thread_local
- Deleted user sessions now invalidated; session role updated on role change
- Offline agents get 24hr staleness TTL on compliance status
- MCP automation gets separate rate limit bucket from dashboard
- Approval workflow: 7-day TTL and 1000 pending cap
- CEL unresolved variables produce tri-state (true/false/error) instead of silent false

#### Agent & Plugins (10 fixed)
- `SecureZeroMemory` on CNG + CAPI intermediate key blobs after cert store export
- Symlink rejection before plugin dlopen
- OTA updater download size capped at 512 MiB
- Content distribution staging directory set to owner-only permissions
- Hash re-verification before executing staged content
- HTTP client SSRF protection extended to CGNAT (100.64/10) and benchmarking (198.18/15) ranges
- HTTP client response body capped at 100 MiB
- `script_exec` output capped at 16 MiB; `setsid()` + `kill(-pid, SIGKILL)` for process group cleanup
- `script_exec` child environment sanitized (PATH, HOME, USER, LANG, LC_ALL, TERM, TZ only)
- Certificate plugin command injection fixed: hex-only thumbprint validation, safe path checks, temp file for PEM parsing

#### Gateway
- 5 dialyzer warnings resolved (ctx dependency, contract violations, dead code)
- gpb bumped 4.21.2 → 4.21.7 for OTP 28 compatibility
- Gateway proto synced from canonical (added stagger_seconds, delay_seconds)

#### Documentation
- REST API v1 now 100% documented (was 48% undocumented)
- Full governance review document with cross-tier finding register
- Erlang gateway build pitfalls documented in CLAUDE.md

### Fixed (RC Sprint — 52 findings resolved)

#### Security (CRITICAL + HIGH)
- Gateway now uses TLS for upstream gRPC connections (was plaintext)
- Gateway health/readiness endpoints (`/healthz`, gRPC Health Check)
- Gateway circuit breaker with exponential backoff for upstream failures
- AnalyticsEventStore thread safety — mutex protection on query methods
- Proto codegen reproducibility — protoc version validation
- Web UI binds to `127.0.0.1` by default (was `0.0.0.0`)
- HTTPS enabled by default — operators must provide cert/key or use `--no-https`
- `/metrics` requires authentication for remote access (localhost exempt, `--metrics-no-auth` override)
- Private key file permission validation on Unix (refuses group/others-readable)
- Certificate hot-reload with PEM validation, cert/key match, and permission checks
- CORS headers on all `/api/` endpoints via `set_post_routing_handler`

#### Server
- REST API unit test suite (previously 0 tests for 1,355 LOC, 31+ endpoints)
- JSON error envelope on all error responses: `{"error":{"code":N,"message":"..."},"meta":{"api_version":"v1"}}`
- Health probe contract: `/livez` and `/readyz` return `{"status":"..."}`

#### Gateway
- Command duration metrics (was hard-coded to 0)
- Backpressure alerting for agent send buffer
- grpcbox dependency pinned
- Graceful shutdown with in-flight command draining
- .appup files for hot code upgrades

#### Build & Packaging
- Binary signing for Windows (Authenticode) and macOS (codesign + notarization)
- Sanitizer CI jobs (ASan+UBSan, TSan)
- Release workflow artifact validation with SHA256 checksums
- deb/rpm package integration
- Docker health checks in all 3 Dockerfiles
- Docker base images pinned to sha256 digests
- buf lint + breaking change CI job for proto compatibility

#### Agent & Plugins
- Agent UUID generation uses CSPRNG (RAND_bytes/BCryptGenRandom, was Mersenne Twister)
- Plugin ABI runtime version check — sdk_version field, ABI v3
- OIDC client secret moved to Authorization: Basic header (RFC 6749 §2.3.1)

#### Build Hardening
- Compiler hardening flags: `_FORTIFY_SOURCE=2`, `-fstack-protector-strong`, full RELRO, PIE
- MSVC `/DYNAMICBASE /HIGHENTROPYVA /NXCOMPAT` for ASLR + DEP

#### Documentation
- macOS x64 limitation documented in README and user manual
- cliff.toml added for git-cliff changelog automation

## [0.1.0] - 2026-03-21

### Added

#### Server
- HTMX-based web dashboard with dark theme, role-based context bar, command palette
- REST API v1 with CORS support and OpenAPI documentation (133+ endpoints)
- Server-side response persistence with filtering, pagination, and aggregation (SQLite)
- Audit trail system with structured JSON events and configurable retention
- Device tagging system with hierarchical scope expression engine (AND/OR/NOT/LIKE/IN)
- Instruction engine: YAML-defined definitions, sets, scheduling, approval workflows
- Workflow primitives (if, foreach, retry) for multi-step instruction chains
- Policy engine with CEL-like compliance expressions and fleet compliance dashboard
- Granular RBAC with 6 roles, 14 securable types, per-operation permissions
- Management groups for hierarchical device grouping and access scoping
- OIDC SSO integration (tested with Microsoft Entra ID)
- Token-based API authentication (Bearer and X-Yuzu-Token)
- System notifications (in-app) and event subscriptions (webhooks with HMAC-SHA256)
- Product packs with Ed25519 signature verification for bundled YAML distribution
- Active Directory / Entra ID integration via Microsoft Graph API
- Agent deployment jobs and patch deployment workflow orchestration
- Device discovery (subnet scanning with ARP + ping sweep)
- Custom properties on devices with schema validation
- Runtime configuration API with safe key whitelist
- Inventory table enumeration and item lookup
- NVD CVE feed sync with vulnerability matching
- ClickHouse and JSONL analytics event drains
- Prometheus /metrics endpoint with fleet health gauges and request histograms
- CSV and JSON data export
- HTTPS for web dashboard with HTTP→HTTPS redirect
- Error code taxonomy (1xxx-4xxx)
- Concurrency enforcement (5 modes)

#### Agent
- Plugin architecture with stable C ABI (version 2, min 1) and C++ CRTP wrapper
- 44 plugins: hardware, network, security, filesystem, registry, WMI, WiFi, WoL, and more
- Trigger engine: interval, file_change, service_status, event_log, registry_change, startup
- Agent-side key-value storage (SQLite-backed, per-plugin namespaces)
- HTTP client plugin (cpp-httplib, no shell) with SSRF protection
- Content staging and execution (CreateProcessW/fork+execvp, no system())
- Desktop user interaction: notifications, questions, surveys, DND mode (Windows)
- Timeline Activity Record (TAR): persistent process tree, network, service, user session tracking
- OTA auto-update with hash verification and rollback
- Bounded thread pool (4-32 workers, 1000 max queue) with output buffering
- Windows certificate store integration (CryptoAPI/CNG)
- Tiered agent enrollment (manual approval, pre-shared tokens, platform trust stubs)

#### Gateway
- Erlang/OTP gateway node with process-per-agent supervision
- Heartbeat buffer (dedicated gen_server, batched upstream flush)
- Consistent hash ring for multi-gateway deployments
- Prometheus metrics endpoint

#### Infrastructure
- Meson + vcpkg build system with cross-platform support (Windows/Linux/macOS/ARM64)
- CI matrix: GCC 13, Clang 18, MSVC, Apple Clang, ARM64 cross-compile
- AddressSanitizer, ThreadSanitizer, and code coverage CI jobs
- Docker deployment (3 multi-stage Dockerfiles, docker-compose.yml)
- Systemd service units with security hardening
- GitHub Actions release workflow (3 platforms, SHA256 checksums)
- 628+ unit test cases across 44 test files

### Security
- 51 security findings identified and fixed (5 CRITICAL, 15 HIGH, 15 MEDIUM, 16 LOW)
- Eliminated 4 CRITICAL command injection vulnerabilities (replaced system()/popen() with safe alternatives)
- mTLS for agent-server gRPC with certificate chain validation
- PBKDF2 password hashing for local authentication
- Command-line redaction in TAR (configurable patterns)
- SSRF protection with private IP range blocking
- Input validation on all REST API endpoints
- Registry sensitive path audit logging
- PRAGMA secure_delete on TAR database

