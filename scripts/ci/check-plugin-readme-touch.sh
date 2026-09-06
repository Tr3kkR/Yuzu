#!/usr/bin/env bash
# check-plugin-readme-touch.sh — the plugin README touch rule
# (docs/plugin-readme-standard.md rule 7).
#
# A change under agents/plugins/<x>/src/** must be accompanied by a change to
# agents/plugins/<x>/README.md, or the pull-request body must state
#
#     docs-unchanged: <section it would have touched> — <reason>
#
# so the reviewer sees the claim rather than a silent omission. A plugin that
# has no README at HEAD yet is exempt (the README-existence ratchet in
# tests/test_plugin_readmes.py governs that count); the exemption is printed,
# never silent.
#
# Usage:
#   check-plugin-readme-touch.sh <BASE> <HEAD> [PR_BODY_FILE]
#
# BASE/HEAD are commit-ish. The body file is read verbatim (never interpolated
# into this script); when absent, no override is possible.
set -euo pipefail

usage() {
  echo "usage: check-plugin-readme-touch.sh <BASE> <HEAD> [PR_BODY_FILE]" >&2
  exit 2
}
[ $# -ge 2 ] || usage
BASE="$1"; HEAD="$2"; BODY="${3:-}"

if ! git cat-file -e "${BASE}^{commit}" 2>/dev/null || ! git cat-file -e "${HEAD}^{commit}" 2>/dev/null; then
  echo "check-plugin-readme-touch: base or head commit unavailable (${BASE}..${HEAD}) — cannot evaluate, failing closed" >&2
  exit 1
fi

CHANGED="$(git diff --name-only "$BASE" "$HEAD" --)"

override=""
if [ -n "$BODY" ] && [ -f "$BODY" ]; then
  # First matching line wins; the text after the colon must be non-empty.
  override="$(grep -m1 -E '^[[:space:]]*docs-unchanged:[[:space:]]*[^[:space:]]' "$BODY" || true)"
fi

# Plugins whose src/ changed, deduplicated.
plugins="$(printf '%s\n' "$CHANGED" | sed -n -E 's#^agents/plugins/([^/]+)/src/.*$#\1#p' | sort -u)"
if [ -z "$plugins" ]; then
  echo "check-plugin-readme-touch: no plugin src/ changes between ${BASE} and ${HEAD} — nothing to enforce"
  exit 0
fi

failed=0
for p in $plugins; do
  readme="agents/plugins/${p}/README.md"
  if ! git cat-file -e "${HEAD}:${readme}" 2>/dev/null; then
    echo "check-plugin-readme-touch: ${p}: src/ changed and no README exists at HEAD — exempt (README-existence ratchet governs; tests/test_plugin_readmes.py)"
    continue
  fi
  if printf '%s\n' "$CHANGED" | grep -qx "$readme"; then
    echo "check-plugin-readme-touch: ${p}: src/ and README.md both changed — ok"
    continue
  fi
  if [ -n "$override" ]; then
    echo "check-plugin-readme-touch: ${p}: src/ changed, README.md unchanged, override stated in the PR body: ${override}"
    continue
  fi
  echo "check-plugin-readme-touch: ${p}: agents/plugins/${p}/src/** changed but ${readme} did not." >&2
  echo "  Either update the README (docs/plugin-readme-standard.md), or add to the PR body a line:" >&2
  echo "    docs-unchanged: <section it would have touched> — <reason>" >&2
  failed=1
done
exit $failed
