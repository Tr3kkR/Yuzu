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
# is only to keep the flag from silently regressing.
#
# Beyond a bare `meson setup` exit code, this also introspects the
# configured targets (still configure-only — `meson introspect --targets`
# needs no compile) and asserts the EXACT boundary: precisely the four demo
# plugins are absent, and a same-sized sample of real plugins/tools --
# including the two closest-to-toy calls, `netstat` and `status` -- are
# present. A bare setup-succeeds check would stay green even if a real
# plugin were silently re-gated behind build_examples (as long as nothing
# else referenced its *_plugin_lib variable), which defeats the point of a
# regression test for exactly that class of mistake (code-review CDX-FV-2).
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || { cd "$(dirname "$0")/../.." && pwd; })"
cd "$ROOT"

# Mirrors scripts/setup.sh's own host-triplet detection exactly (including
# its own gap: native ARM64 Linux is not auto-detected there either --
# only an explicit --cross-file selects arm64-linux/arm-linux). Diverging
# from that script's convention here would be a NEW inconsistency, not a
# fix, so this intentionally does not do more than setup.sh does.
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

targets="$tmp/targets.json"
meson introspect --targets "$tmp/build" > "$targets" 2>"$tmp/introspect.log" || {
  echo "::error::meson introspect --targets failed after a successful setup" >&2
  cat "$tmp/introspect.log" >&2
  exit 1
}

python3 - "$targets" <<'PYEOF'
import json, sys

with open(sys.argv[1]) as f:
    names = {t["name"] for t in json.load(f)}

demo_plugins = {"example", "chargen", "procfetch", "netprobe"}
# netstat and status are the two AC-named "toys" this branch deliberately
# left unconditional (real attribution action + real test, and a
# dashboard-consumed key-value plugin, respectively -- see #4262 code
# review) -- asserting their presence is exactly what would catch a
# regression that moved either one back under build_examples.
must_be_present = {"netstat", "status", "capmatrix-gen", "plugin-capture", "yuzu_agent_tests"}

present_demos = demo_plugins & names
missing_required = must_be_present - names

errors = []
if present_demos:
    errors.append(f"demo plugin target(s) unexpectedly present under build_examples=false: {sorted(present_demos)}")
if missing_required:
    errors.append(f"required target(s) missing under build_examples=false: {sorted(missing_required)}")

if errors:
    for e in errors:
        print(f"::error::{e}", file=sys.stderr)
    sys.exit(1)
PYEOF

echo "test_build_examples_gating: OK — -Dbuild_examples=false -Dbuild_tests=true configures cleanly, exactly the four demo plugins are absent, and netstat/status/capmatrix-gen/plugin-capture/yuzu_agent_tests are present"
