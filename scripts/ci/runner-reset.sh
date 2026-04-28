#!/usr/bin/env bash
# runner-reset.sh — sanctioned manual recovery path for self-hosted runners.
#
# When CI is wedged on stale workspace state and the in-band sentinels
# (vcpkg-triplet-sentinel.sh, branch-switch wipe in ci.yml) aren't enough,
# this is the ONE script that nukes workspace state without nuking caches.
#
# Wipes:
#   - every untracked file under the workspace EXCEPT preserved paths
#     (vcpkg/, vcpkg_installed/, build-*/ — those have their own sentinels)
#
# Preserves (DO NOT remove these from -e flags):
#   - vcpkg/                      vcpkg itself; rebuilt cost ~2 min
#   - vcpkg_installed/<triplet>/  per-triplet binary tree; cost ~25 min from-source
#   - build-*/                    per-OS build dirs; cost ~10 min cold compile
#   - $RUNNER_TOOL_CACHE/yuzu-vcpkg-binary-cache-*  (lives outside workspace anyway)
#   - ~/.cache/ccache             (lives outside workspace anyway)
#
# Usage on the runner host:
#   cd /path/to/_work/Yuzu/Yuzu      # the actions runner workspace
#   bash scripts/ci/runner-reset.sh
#
# Or with --dry-run to see what would be removed:
#   bash scripts/ci/runner-reset.sh --dry-run

set -euo pipefail

DRY_RUN=0
if [[ "${1:-}" == "--dry-run" || "${1:-}" == "-n" ]]; then
  DRY_RUN=1
  shift || true
fi

if [[ ! -d .git ]]; then
  echo "::error::$(pwd) is not a git workspace — refusing to reset" >&2
  exit 2
fi

# git clean -fdx with explicit excludes. -e accepts gitignore-style patterns.
# The -e patterns are ADDITIVE to .gitignore, so anything tracked is already
# safe; we just guard the build/cache trees that are gitignored but expensive.
git_clean_args=(
  -fdx
  -e vcpkg/
  -e vcpkg_installed/
  -e 'build-*/'
)

if (( DRY_RUN )); then
  git_clean_args=(-n "${git_clean_args[@]}")
  echo "[dry-run] git clean ${git_clean_args[*]}"
fi

git clean "${git_clean_args[@]}"

if (( ! DRY_RUN )); then
  echo "runner-reset complete. Preserved: vcpkg/, vcpkg_installed/, build-*/"
  echo "Caches outside the workspace (runner.tool_cache, ~/.cache/ccache) untouched."
fi
