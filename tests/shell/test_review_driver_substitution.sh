#!/usr/bin/env bash
# test_review_driver_substitution.sh — regression net for the adversarial-review
# driver prompt substitution.
#
# Bash >= 5.2 turns `patsub_replacement` ON by default, which makes an unescaped
# `&` in a ${var//pat/repl} REPLACEMENT expand to the text that was MATCHED. The
# drivers render their prompt template with exactly that construct, so without an
# explicit `shopt -u patsub_replacement` every `&` in an injected value silently
# becomes the token being substituted:
#
#     --anchors "failure() && cancelled()"   ->   "failure() {{ANCHORS}}{{ANCHORS}} cancelled()"
#     a C++ snippet "bool& ref"              ->   "bool{{ANCHORS}} ref"
#     a URL "?a=1&b=2"                       ->   "?a=1{{ANCHORS}}b=2"
#
# That corrupts the anchors a reviewer grades against, and mangles any C++
# reference type or query string in the code under review — silently, in a file
# nobody reads, on every run. Observed live on the #2616 review.
#
# This drives the real driver with a stub `codex` on PATH, captures the prompt it
# would have sent, and asserts the ampersands survive.
#
# Run:  bash tests/shell/test_review_driver_substitution.sh
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || { cd "$(dirname "$0")/../.." && pwd; })"
DRIVER="$ROOT/.claude/skills/adversarial-review/run-codex-reviewer.sh"
[ -f "$DRIVER" ] || { echo "missing $DRIVER" >&2; exit 2; }

TMP="$(mktemp -d "${TMPDIR:-/tmp}/yuzu-revsub-test.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

# Stub `codex`: the driver pipes the rendered prompt to it on stdin.
mkdir -p "$TMP/bin" "$TMP/rev"
cat > "$TMP/bin/codex" <<EOF
#!/usr/bin/env bash
cat > "$TMP/captured.txt"
EOF
chmod +x "$TMP/bin/codex"

ANCHORS='- failure() && cancelled() guards
- C++ `bool& ref` params
- url?a=1&b=2'

PATH="$TMP/bin:$PATH" bash "$DRIVER" \
  --phase 1 --review-dir "$TMP/rev" --repo "$ROOT" \
  --self codex --peer kimi \
  --target 'smoke && test' --anchors "$ANCHORS" >/dev/null 2>&1 || true

[ -s "$TMP/captured.txt" ] || { echo "  [FAIL] driver produced no prompt" >&2; exit 1; }

pass=0 fail=0
# expect_literal <desc> <string that must appear verbatim in the prompt>
expect_literal() {
  local desc="$1" needle="$2"
  if grep -qF -- "$needle" "$TMP/captured.txt"; then
    printf '  [pass] %s\n' "$desc"; pass=$((pass + 1))
  else
    printf '  [FAIL] %s — %q not found in rendered prompt\n' "$desc" "$needle"; fail=$((fail + 1))
  fi
}
# expect_absent <desc> <string that must NOT appear>
expect_absent() {
  local desc="$1" needle="$2"
  if grep -qF -- "$needle" "$TMP/captured.txt"; then
    printf '  [FAIL] %s — %q leaked into rendered prompt\n' "$desc" "$needle"; fail=$((fail + 1))
  else
    printf '  [pass] %s\n' "$desc"; pass=$((pass + 1))
  fi
}

expect_literal "&& survives in anchors"            'failure() && cancelled() guards'
expect_literal "C++ reference type survives"       'bool& ref'
expect_literal "URL query separator survives"      'url?a=1&b=2'
expect_literal "&& survives in target"             'smoke && test'
# The tell-tale of the patsub bug: the token being replaced appears in its own output.
expect_absent  "no {{ANCHORS}} echoed back"        '{{ANCHORS}}'
expect_absent  "no {{TARGET}} echoed back"         '{{TARGET}}'

echo "  ---"
echo "  ${pass} passed, ${fail} failed"
[ "$fail" = 0 ]
