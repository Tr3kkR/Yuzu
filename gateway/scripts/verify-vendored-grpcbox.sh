#!/usr/bin/env bash
# Verify the vendored grpcbox (gateway/_checkouts/grpcbox) is EXACTLY upstream
# grpcbox at the rebar.config-pinned tag + the documented Yuzu patch — nothing
# more, nothing less. Fails (exit 1) on any tamper, drift, or version skew.
#
# This is the machine-verifiable integrity gate for the vendored dependency
# (PKI PR5c). Run it on every re-sync and in CI. See
# gateway/_checkouts/grpcbox/YUZU_PATCH.md for the why.
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"   # gateway/
VENDOR="$HERE/_checkouts/grpcbox"
PATCH="$HERE/_checkouts/grpcbox.yuzu.patch"

[ -d "$VENDOR" ] || { echo "FAIL: $VENDOR missing"; exit 1; }
[ -f "$PATCH" ]  || { echo "FAIL: $PATCH missing"; exit 1; }

# The pin must come from rebar.config so the check can never skew from the build.
TAG="$(grep -oE 'grpcbox\.git", \{tag, "[^"]+' "$HERE/rebar.config" | grep -oE 'v[0-9.]+' | head -1)"
[ -n "$TAG" ] || { echo "FAIL: no grpcbox {tag, \"vX.Y.Z\"} pin in rebar.config"; exit 1; }
echo "verifying _checkouts/grpcbox against upstream grpcbox $TAG + grpcbox.yuzu.patch"

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
# Pin the exact upstream commit the tag must resolve to, so a force-pushed /
# re-pointed tag (supply-chain attack on upstream) is caught. Update on re-sync.
EXPECTED_SHA="5a57125e76ea3cf2343e7e3e08bfc0b187635054"  # grpcbox v0.17.1

git clone --quiet -c advice.detachedHead=false --depth 1 --branch "$TAG" \
    https://github.com/tsloughter/grpcbox.git "$TMP/up" \
    || { echo "FAIL: could not clone grpcbox $TAG"; exit 1; }

GOT_SHA="$(git -C "$TMP/up" rev-parse HEAD)"
if [ "$GOT_SHA" != "$EXPECTED_SHA" ]; then
    echo "FAIL: upstream $TAG resolves to $GOT_SHA, expected $EXPECTED_SHA (tag re-pointed?)"
    exit 1
fi

( cd "$TMP/up" && git apply "$PATCH" ) \
    || { echo "FAIL: grpcbox.yuzu.patch does not apply cleanly to upstream $TAG"; exit 1; }

# Every vendored file (except the Yuzu-only provenance note) must byte-match the
# patched upstream. Catches a malicious/accidental edit to ANY vendored module,
# not just grpcbox_pool.erl.
rc=0
while IFS= read -r f; do
    rel="${f#"$VENDOR"/}"
    [ "$rel" = "YUZU_PATCH.md" ] && continue
    if [ ! -f "$TMP/up/$rel" ]; then
        echo "FAIL: vendored '$rel' does not exist in upstream $TAG"; rc=1; continue
    fi
    if ! diff -q "$TMP/up/$rel" "$f" >/dev/null; then
        echo "FAIL: vendored '$rel' differs from upstream $TAG + patch"; rc=1
    fi
done < <(find "$VENDOR" -type f)

# Under-vendoring guard: every upstream src/ + include/ file MUST be present in the
# vendor (a truncated re-sync that drops a module would otherwise pass the loop
# above — it only checks files that ARE vendored). src+include are the
# compile-critical sets; benchmark/interop/proto/config are intentionally omitted.
for d in src include; do
    [ -d "$TMP/up/$d" ] || continue
    while IFS= read -r uf; do
        urel="${uf#"$TMP/up/"}"
        if [ ! -f "$VENDOR/$urel" ]; then
            echo "FAIL: upstream '$urel' is MISSING from the vendor (truncated re-sync?)"; rc=1
        fi
    done < <(find "$TMP/up/$d" -type f)
done

if [ "$rc" -eq 0 ]; then
    echo "OK: _checkouts/grpcbox == grpcbox $TAG ($EXPECTED_SHA) + grpcbox.yuzu.patch (integrity verified)"
fi
exit "$rc"
