#!/usr/bin/env bash
# test_build_examples_gating.sh — #4262 smoke test.
#
# `-Dbuild_examples=false` must still configure a full, working build: only
# the four decorative demo plugins (example, chargen, procfetch, netprobe)
# are omitted, every real plugin and the test suite's link_depends still
# resolve. Before #4262 this configuration failed at `meson setup` with an
# undefined-variable error the moment any real plugin's `*_plugin_lib`
# was referenced outside the (then much wider) build_examples gate.
#
# Configure only — no compile — to keep this cheap enough to run on every
# CI leg rather than a dedicated slow job. A full compile+link+test pass of
# this configuration is verified manually per-change; this smoke test's job
# is only to keep the flag from silently regressing back to gating
# everything.
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || { cd "$(dirname "$0")/../.." && pwd; })"
cd "$ROOT"

case "$(uname -s)" in
  Darwin) TRIPLET="$([ "$(uname -m)" = "arm64" ] && echo arm64-osx || echo x64-osx)" ;;
  Linux)  TRIPLET="x64-linux" ;;
  *)      TRIPLET="x64-windows" ;;
esac

VCPKG_INSTALLED="$ROOT/vcpkg_installed/$TRIPLET"
if [ ! -d "$VCPKG_INSTALLED" ]; then
  echo "test_build_examples_gating: SKIP — no populated vcpkg_installed/$TRIPLET (run scripts/setup.sh first)"
  exit 0
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

if ! meson setup "$tmp/build" \
    -Dbuild_examples=false -Dbuild_tests=true \
    -Dcmake_prefix_path="$VCPKG_INSTALLED" \
    -Dpkg_config_path="$VCPKG_INSTALLED/lib/pkgconfig" \
    > "$tmp/setup.log" 2>&1; then
  echo "::error::meson setup -Dbuild_examples=false -Dbuild_tests=true failed to configure — #4262 regression?" >&2
  cat "$tmp/setup.log" >&2
  exit 1
fi

echo "test_build_examples_gating: OK — -Dbuild_examples=false -Dbuild_tests=true configures cleanly"
