---
name: ci-cache
description: Canonical patterns for caching in Yuzu CI workflows. Two snippets — one for ephemeral GHA-hosted runners (split actions/cache/restore + actions/cache/save, never `save-always: true`) and one for self-hosted runners (local filesystem cache under `runner.tool_cache`, no GHA cache round-trip). Use when adding a new vcpkg/ccache/dependency cache step to any workflow under `.github/workflows/`, or when reviewing a PR that touches `actions/cache@`.
---

# ci-cache

Canonical caching patterns for Yuzu CI workflows. **CI eats more time than dev — get this right the first time.**

## TL;DR — two patterns

| Runner kind | Cache mechanism | Snippet |
|---|---|---|
| GHA-hosted (`ubuntu-24.04`, `macos-15`, `windows-latest`) | `actions/cache/restore` + paired `actions/cache/save` | [GHA-hosted](#gha-hosted-ephemeral-runners) |
| Self-hosted (`yuzu-wsl2-linux`, `yuzu-local-windows`, future macOS) | Local filesystem under `runner.tool_cache` | [Self-hosted](#self-hosted-runners) |

**Hard rule (enforced by `.github/workflows/zizmor.yml`):** never use `save-always: true` on `actions/cache@`. The input is deprecated by the actions/cache maintainers as "does not work as intended and will be removed in a future release." The `Guard — no save-always on actions/cache` step in zizmor.yml fails any workflow audit if `^[[:space:]]*save-always:` reappears as a YAML key. Don't try to silence the guard — rewrite the cache step using the snippets below.

Reference: <https://github.com/actions/cache/tree/main/save#always-save-cache>.

---

## GHA-hosted (ephemeral runners)

Each job starts on a fresh disk. The cache lives in GitHub's blob storage and is moved over the network on restore + save. Use the **split restore + always-save pattern**:

```yaml
- name: Restore <thing>
  id: cache-<thing>
  uses: actions/cache/restore@27d5ce7f107fe9357f9df03efb73ab90386fccae # v5.0.5
  with:
    path: <path>
    key: <primary-key-with-strong-uniqueness>
    restore-keys: |
      <progressively-shorter-fallback-prefixes>

# ... build / test / install steps that produce the cache content ...

- name: Save <thing>
  # `if: always()` is the documented replacement for the deprecated
  # `save-always: true` input — runs even on Build/Test failure, which
  # is the only behaviour `save-always` was meant to deliver. The
  # `cache-hit != 'true'` gate skips the upload when the primary key
  # already matched on restore (no new content to save, no point
  # paying the upload cost).
  if: always() && steps.cache-<thing>.outputs.cache-hit != 'true'
  uses: actions/cache/save@27d5ce7f107fe9357f9df03efb73ab90386fccae # v5.0.5
  with:
    path: <path>
    key: ${{ steps.cache-<thing>.outputs.cache-primary-key }}
```

**Key construction (D3 of the CI overhaul plan):**

For vcpkg: include manifest + every overlay triplet + the pinned baseline. Example:

```yaml
key: vcpkg-<triplet>-${{ env.VCPKG_COMMIT }}-${{ hashFiles('vcpkg.json', 'vcpkg-configuration.json', 'triplets/*.cmake') }}
restore-keys: |
  vcpkg-<triplet>-${{ env.VCPKG_COMMIT }}-
  vcpkg-<triplet>-
```

For ccache: hash all `.cpp` / `.hpp` / `.h` source. Cascading restore-keys keep the cache mostly warm across source changes:

```yaml
key: ccache-<leg>-${{ hashFiles('**/*.cpp', '**/*.hpp', '**/*.h') }}
restore-keys: |
  ccache-<leg>-
```

**Branch-scope gotcha (the canary cold-start lesson from PR #740):**

GHA cache scope is **branch-isolated** with PR runs scoped to `refs/pull/<N>/merge`. A PR job can read caches from (a) its own ref, (b) the repo's default branch, (c) the PR's base branch. **Sibling-PR caches are unreadable.** If a job only ever runs on `pull_request`, its cache never lands on `refs/heads/main` and every PR cold-starts.

Fix: also trigger the job on `push` to `main` when the relevant inputs change. The canary job in `ci.yml` does this via `detect-ci-changes` firing on both `pull_request` and `push` to `refs/heads/main`. Mirror that pattern for any new cache that needs cross-PR warmth.

---

## Self-hosted runners

Self-hosted runners (`yuzu-wsl2-linux`, `yuzu-local-windows`, and any future self-hosted macOS) keep state across jobs. **Skip GHA's blob-storage cache entirely** — round-tripping ~1 GB of vcpkg binaries through GHA storage when the same data already lives on the runner's local disk is an unforced loss. Pin caches to `runner.tool_cache` (a stable per-runner path that survives between jobs but is owned by the runner setup, not the workspace):

```yaml
# Self-hosted: no actions/cache step at all. Set the env var that
# the build tool consumes and let it manage its own on-disk cache.
- name: Configure local cache paths (self-hosted)
  if: ${{ !contains(runner.name, 'GitHub') && runner.environment == 'self-hosted' }}
  run: |
    echo "VCPKG_DEFAULT_BINARY_CACHE=${{ runner.tool_cache }}/yuzu-vcpkg-binary-cache-${{ matrix.os }}" >> "$GITHUB_ENV"
    echo "CCACHE_DIR=${{ runner.tool_cache }}/yuzu-ccache-${{ matrix.os }}" >> "$GITHUB_ENV"
    mkdir -p "${{ runner.tool_cache }}/yuzu-vcpkg-binary-cache-${{ matrix.os }}"
    mkdir -p "${{ runner.tool_cache }}/yuzu-ccache-${{ matrix.os }}"
```

(See `.github/workflows/codeql.yml` for the existing `VCPKG_DEFAULT_BINARY_CACHE → runner.tool_cache` wiring on the Windows self-hosted runner — that's the pattern.)

**Why `runner.tool_cache` and not `~/.cache/...`:**

- `runner.tool_cache` is a stable, runner-managed path. It survives `actions/checkout` workspace cleanup (which can wipe `vcpkg_installed/` if `clean: true` is set, see lesson from session 2026-04-28).
- It's per-runner (not per-job), so back-to-back jobs on the same runner share warm caches.
- It's outside `${{ github.workspace }}`, so concurrent jobs can't race on the same file.

**Per-triplet (not per-matrix-leg) scoping:**

If two matrix legs build the same triplet (e.g., `gcc-13 debug` and `gcc-13 release` both build `x64-linux`), share the cache directory keyed on the **triplet**, not the matrix axis. The CI overhaul commit on 2026-04-28b establishes this — cumulative first-warm cost dropped ~5 h → ~2 h 20 min by collapsing per-matrix scopes into per-triplet scopes.

**Sentinel-driven invalidation:**

Self-hosted caches stay until something invalidates them. `scripts/ci/vcpkg-triplet-sentinel.sh` is the canonical invalidator: it computes the cache key from `vcpkg.json` + `vcpkg-configuration.json` + overlay triplets + `VCPKG_COMMIT`, compares against the stored sentinel, and wipes the triplet tree (and the orphaned-registry `vcpkg/info/` directory — see #741) on drift. Always run the sentinel before `vcpkg install` on self-hosted.

**Future self-hosted macOS:**

When the self-hosted Mac lands (replacing or augmenting the `macos-15` GHA runner), it should follow the self-hosted pattern: drop the `actions/cache` step from the macOS leg, set `CCACHE_DIR=${{ runner.tool_cache }}/yuzu-ccache-macos-${{ matrix.build_type }}` and `VCPKG_DEFAULT_BINARY_CACHE=${{ runner.tool_cache }}/yuzu-vcpkg-binary-cache-arm64-osx`, and rely on the runner's local SSD. ccache deltas on macOS are the same shape as Linux (~30 G with `CCACHE_MAXSIZE=30G`); the GHA-hosted cap of 10 GB total per repo no longer applies.

---

## Reading the existing tree

When in doubt, read these as worked examples (all up-to-date as of v0.12.0-rc0):

| File | Pattern shown |
|---|---|
| `.github/workflows/ci.yml` macOS legs (lines 564–675) | GHA-hosted split restore + paired save |
| `.github/workflows/ci.yml` canary (lines 730–820) | GHA-hosted split restore + paired save + push-to-main warming |
| `.github/workflows/release.yml` (lines 703–751) | Restore-only (release builds consume cache, never produce — see comment block) |
| `.github/workflows/codeql.yml` | Self-hosted `VCPKG_DEFAULT_BINARY_CACHE → runner.tool_cache` |
| `scripts/ci/vcpkg-triplet-sentinel.sh` | Sentinel invalidation logic, including the orphaned-registry self-heal |

---

## When to add a new cache

Three questions to answer before you add `actions/cache/restore`:

1. **What's the cache key?** Must be uniquely determined by the inputs that change the cache content. Source-file hash for ccache; manifest + triplet + baseline for vcpkg; pip-tools requirements file hash for `~/.cache/pip`. If the key collapses two materially-different states into one entry, the cache is poisoned.
2. **Where does it save?** GHA-hosted → blob storage with branch-scope rules. Self-hosted → local `runner.tool_cache`. Pick one based on the runner kind, never both.
3. **Will it ever warm via push-to-main?** If only `pull_request` writes the cache, every PR cold-starts. Either accept that or add a push-to-main trigger that produces the cache (see canary in ci.yml).

If any of those three feels wrong, the cache step is wrong. Re-read this skill before pushing.
