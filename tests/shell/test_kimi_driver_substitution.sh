#!/usr/bin/env bash
# test_kimi_driver_substitution.sh — regression net for the Kimi adversarial-review
# driver's prompt substitution.
#
# Bash >= 5.2 turns `patsub_replacement` ON by default, which makes an unescaped
# `&` in a ${var//pat/repl} REPLACEMENT expand to the text that was MATCHED. The
# driver renders its prompt template with exactly that construct (seven passes,
# run-kimi-reviewer.sh), so without an explicit `shopt -u patsub_replacement`
# every `&` in an injected value silently becomes the token being substituted:
#
#     --anchors "failure() && cancelled()"   ->   "failure() {{ANCHORS}}{{ANCHORS}} cancelled()"
#     a C++ snippet "bool& ref"              ->   "bool{{ANCHORS}} ref"
#     a URL "?a=1&b=2"                       ->   "?a=1{{ANCHORS}}b=2"
#
# The reviewer then grades against a corrupted rulebook, and any C++ reference
# type or query string in the material under review is mangled before the model
# sees it — silently, in a file nobody opens, on every run.
#
# The sibling `run-codex-reviewer.sh` has the same construct and the same guard;
# both drivers need their own net, because a guard added to one says nothing
# about the other. That asymmetry is exactly how this survived a first fix.
#
# Run:  bash tests/shell/test_kimi_driver_substitution.sh
set -euo pipefail

# The defect mechanism only exists on bash >= 5.2. On older bash the guard is
# inert AND the corruption cannot manifest, so every assertion would pass
# vacuously with or without the fix. Skip LOUDLY rather than print a green that
# verified nothing (CI runs Ubuntu bash >= 5.2; this is for stock macOS 3.2).
if (( BASH_VERSINFO[0] < 5 || (BASH_VERSINFO[0] == 5 && BASH_VERSINFO[1] < 2) )); then
  echo "  [SKIP] bash ${BASH_VERSION} < 5.2 — patsub_replacement does not exist here;"
  echo "         this net cannot arm. Re-run under bash >= 5.2 (CI does)."
  exit 0
fi

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || { cd "$(dirname "$0")/../.." && pwd; })"
DRIVER="$ROOT/.claude/skills/adversarial-review/run-kimi-reviewer.sh"
[ -f "$DRIVER" ] || { echo "missing $DRIVER" >&2; exit 2; }

TMP="$(mktemp -d "${TMPDIR:-/tmp}/yuzu-kimisub-test.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

# Stub `kimi`: the driver probes `kimi --version`, then passes the rendered
# prompt as the argument after `-p`.
mkdir -p "$TMP/bin"
cat > "$TMP/bin/kimi" <<EOF
#!/usr/bin/env bash
if [ "\${1:-}" = "--version" ]; then echo "0.16.0"; exit 0; fi
while [ \$# -gt 0 ]; do
  if [ "\$1" = "-p" ]; then printf '%s' "\$2" > "$TMP/captured.txt"; shift 2; else shift; fi
done
EOF
chmod +x "$TMP/bin/kimi"

# Restricted (default) mode wants --review-dir inside --repo and clones
# KIMI_CODE_HOME's config.toml — give it a scratch repo and a minimal config.
mkdir -p "$TMP/repo/rev" "$TMP/kimi-home"
printf 'model = "stub"\n' > "$TMP/kimi-home/config.toml"

ANCHORS='- failure() && cancelled() guards
- C++ `bool& ref` params
- url?a=1&b=2'

PATH="$TMP/bin:$PATH" KIMI_CODE_HOME="$TMP/kimi-home" bash "$DRIVER" \
  --phase 1 --review-dir "$TMP/repo/rev" --repo "$TMP/repo" \
  --self kimi --peer codex \
  --target 'smoke && test' --anchors "$ANCHORS" \
  >/dev/null 2>"$TMP/driver.stderr" || true

if [ ! -s "$TMP/captured.txt" ]; then
  echo "  [FAIL] driver produced no prompt — driver stderr:" >&2
  sed 's/^/    | /' "$TMP/driver.stderr" >&2
  exit 1
fi

pass=0 fail=0
expect_literal() {
  local desc="$1" needle="$2"
  if grep -qF -- "$needle" "$TMP/captured.txt"; then
    printf '  [pass] %s\n' "$desc"; pass=$((pass + 1))
  else
    printf '  [FAIL] %s — %q not found in rendered prompt\n' "$desc" "$needle"; fail=$((fail + 1))
  fi
}
expect_absent() {
  local desc="$1" needle="$2"
  if grep -qF -- "$needle" "$TMP/captured.txt"; then
    printf '  [FAIL] %s — %q leaked into rendered prompt\n' "$desc" "$needle"; fail=$((fail + 1))
  else
    printf '  [pass] %s\n' "$desc"; pass=$((pass + 1))
  fi
}

expect_literal "&& survives in anchors"           'failure() && cancelled() guards'
expect_literal "C++ reference type survives"      'bool& ref'
expect_literal "URL query separator survives"     'url?a=1&b=2'
expect_literal "&& survives in target"            'smoke && test'
# The tell-tale of the patsub bug: the token being replaced appears in its own output.
expect_absent  "no {{ANCHORS}} echoed back"       '{{ANCHORS}}'
expect_absent  "no {{TARGET}} echoed back"        '{{TARGET}}'

echo "  ---"
echo "  ${pass} passed, ${fail} failed"
[ "$fail" = 0 ]
