#!/usr/bin/env bash
# vcpkg-triplet-sentinel.sh — invalidate vcpkg_installed/<triplet>/ ONLY when
# its inputs actually changed. Universal cache-key contract from the CI
# overhaul plan (PR-2):
#
#   key = sha256(
#       vcpkg.json
#     | vcpkg-configuration.json
#     | triplets/<triplet>.cmake     (when an overlay exists; otherwise empty)
#     | $VCPKG_COMMIT                (vcpkg baseline pinned in CI env)
#   )
#
# Scope of action on key drift:
#   - rm -rf vcpkg_installed/<triplet>/         (the per-triplet install root)
#   - write the new key to vcpkg_installed/.<triplet>-cachekey.sha256
#
# Scope NEVER touched:
#   - vcpkg/                       (vcpkg itself, owned by lukka/run-vcpkg)
#   - runner.tool_cache/...        (binary cache zips — that's the warm tier)
#   - ccache (~/.cache/ccache, %LOCALAPPDATA%\ccache)
#   - any other vcpkg_installed/<other-triplet>/ tree
#
# Cross-platform: bash only, sha256sum (Linux + MSYS2 bash on Windows + macOS).
# Idempotent. Exit 0 unconditionally — a sentinel mismatch is a normal state,
# not a failure. Hard errors (no manifest, missing workspace) exit non-zero.

set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <triplet>" >&2
  exit 2
fi
TRIPLET="$1"

WS="${GITHUB_WORKSPACE:-$(pwd)}"
cd "$WS"

if [[ ! -f vcpkg.json ]]; then
  echo "::error::$(pwd) has no vcpkg.json — cannot compute sentinel" >&2
  exit 2
fi

# --- compute the cache key ------------------------------------------------
#
# sha256sum reads every input that exists; missing inputs are skipped (they
# contribute nothing to the digest). The vcpkg-configuration.json is a hard
# requirement of the manifest layout for our pinned-baseline mode but the
# overlay triplet is conditional — only x64-linux-asan / x64-linux-static /
# x64-windows currently have one. Stock triplets (x64-linux, arm64-osx) do
# not.
inputs=(vcpkg.json)
[[ -f vcpkg-configuration.json ]] && inputs+=(vcpkg-configuration.json)
overlay="triplets/${TRIPLET}.cmake"
[[ -f "$overlay" ]] && inputs+=("$overlay")

# Include the vcpkg baseline commit so a baseline bump invalidates every
# cache (correct: ports may have changed even if our manifest didn't).
baseline="${VCPKG_COMMIT:-unset}"

want=$( { sha256sum "${inputs[@]}"; printf '%s\n' "$baseline"; } | sha256sum | awk '{print $1}')

# --- compare against stored sentinel --------------------------------------
sentinel_dir="$WS/vcpkg_installed"
sentinel_file="$sentinel_dir/.${TRIPLET}-cachekey.sha256"
installed_dir="$sentinel_dir/${TRIPLET}"

mkdir -p "$sentinel_dir"
have=$(cat "$sentinel_file" 2>/dev/null || echo "")

if [[ "$want" != "$have" ]]; then
  echo "vcpkg sentinel drift for triplet=${TRIPLET}"
  echo "  inputs:   ${inputs[*]}"
  echo "  baseline: ${baseline}"
  echo "  have=${have:-<none>}"
  echo "  want=${want}"
  if [[ -d "$installed_dir" ]]; then
    echo "  wiping ${installed_dir}"
    rm -rf "$installed_dir"
  else
    echo "  no existing tree to wipe"
  fi
  echo "$want" > "$sentinel_file"
else
  echo "vcpkg sentinel unchanged for triplet=${TRIPLET} — keeping vcpkg_installed/${TRIPLET}"
fi

exit 0
