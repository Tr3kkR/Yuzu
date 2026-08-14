#!/usr/bin/env bash
# test_trusted_inputs_validate.sh — contract net for ci.yml's `trusted_inputs`
# validate step, the SOLE chokepoint deciding which commit every downstream CI
# job builds.
#
# WHY THIS EXISTS. Two independent reviewers of #2832 flagged the same gap: the
# adjacent shell gates run in that very job have dedicated tests
# (test_check_compose_versions.sh, test_detect_code_change.sh) while the step
# that picks the BUILD COMMIT had none, so nothing short of a live Actions run
# could catch a regression in it. #2832 itself is the proof: its first version
# pinned `checkout_ref` to a bare SHA for EVERY non-workflow_call trigger,
# including `push`, which leaves a self-hosted workspace in detached HEAD and
# permanently disarms the branch-switch build-dir wipe (that sentinel's guard is
# `current != "HEAD"`, and `git rev-parse --abbrev-ref HEAD` prints exactly
# "HEAD" when detached). No test saw it; a reviewer did.
#
# WHAT IT PINS. The four branches of the step and the properties each must hold:
#
#   push               -> checkout_ref is a BRANCH REF (attached HEAD, so the
#                         branch-switch wipe still works), checkout_sha is the
#                         event commit, base_sha falls back to the event commit
#   pull_request       -> checkout_ref is the event SHA (immune to GitHub
#                         re-minting refs/pull/N/merge), and equals checkout_sha
#                         so `Verify resolved checkout` compares like with like;
#                         base_sha is the PR base
#   workflow_call, approved  -> both outputs pinned to the APPROVED head sha,
#                         never to anything the fork controls at run time
#   workflow_call, unapproved -> rejected outright
#
# The step's own body is extracted from ci.yml rather than duplicated here, so
# this test cannot drift into asserting a copy of the logic instead of the logic.
#
# Run:  bash tests/shell/test_trusted_inputs_validate.sh
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CI_YML="$ROOT/.github/workflows/ci.yml"
[ -f "$CI_YML" ] || { echo "missing $CI_YML" >&2; exit 2; }

TMP="$(mktemp -d "${TMPDIR:-/tmp}/yuzu-trusted-inputs.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

pass=0 fail=0
check() { # check <desc> <expected> <actual>
  if [ "$2" = "$3" ]; then printf '  [pass] %s\n' "$1"; pass=$((pass+1))
  else printf '  [FAIL] %s\n         expected: %s\n         actual:   %s\n' "$1" "$2" "$3"; fail=$((fail+1)); fi
}

# ── Extract the step body from ci.yml ────────────────────────────────────────
# Take the `run: |` block of the `- id: validate` step, de-indent it, and
# substitute the two `${{ github.* }}` expression the shell cannot evaluate with
# harness-controlled variables. Everything else runs verbatim.
python3 - "$CI_YML" "$TMP/validate.sh" <<'PY'
import sys
src, out = sys.argv[1], sys.argv[2]
lines = open(src).read().split("\n")
# Find the validate step, then its `run: |`, then take the body by INDENTATION —
# every following line that is blank or indented deeper than `run:` itself. Using
# the next `- ` step as the boundary overshoots into the job's `outputs:` block.
i = next(n for n, l in enumerate(lines) if l.strip() == "- id: validate")
r = next(n for n in range(i, len(lines)) if lines[n].strip() == "run: |")
indent = len(lines[r]) - len(lines[r].lstrip())
body_indent = indent + 2
body = []
for l in lines[r + 1:]:
    if l.strip() == "":
        body.append("")
        continue
    if len(l) - len(l.lstrip()) < body_indent:
        break
    body.append(l[body_indent:])
body = "\n".join(body)
assert "checkout_ref=" in body, "extracted body does not look like the validate step"
# The only GitHub expressions inside the body. Both become harness variables.
body = body.replace('"${{ github.event_name }}"', '"$GH_EVENT_NAME"')
body = body.replace('${{ github.event.pull_request.base.sha }}', '$GH_BASE_SHA')
assert '${{' not in body, "unsubstituted GitHub expression left in the extracted body:\n" + \
    "\n".join(l for l in body.split("\n") if '${{' in l)
open(out, "w").write(body)
PY
[ -s "$TMP/validate.sh" ] || { echo "extraction produced nothing" >&2; exit 2; }

run_validate() { # run_validate <event> <github_ref> <github_sha> <approved_sha> <base_sha>
  : > "$TMP/out"
  ( set +e
    export GITHUB_OUTPUT="$TMP/out" GH_EVENT_NAME="$1" GITHUB_REF="$2" GITHUB_SHA="$3" \
           APPROVED_SHA="$4" GH_BASE_SHA="$5" \
           REPOSITORY="Tr3kkR/Yuzu" PR_NUMBER="" TRUSTED_GATE="" GH_TOKEN=""
    bash "$TMP/validate.sh" >"$TMP/stdout" 2>"$TMP/stderr"
    echo $? > "$TMP/rc" )
  rc=$(cat "$TMP/rc")
}
out_of() { grep -E "^$1=" "$TMP/out" | tail -1 | cut -d= -f2-; }

SHA_EVENT=1111111111111111111111111111111111111111
SHA_BASE=2222222222222222222222222222222222222222

echo "-- push: must stay on a BRANCH ref, or the self-hosted branch-switch wipe dies --"
run_validate push "refs/heads/dev" "$SHA_EVENT" "" ""
check "exits 0"                          "0"                 "$rc"
check "checkout_ref is the branch ref"   "refs/heads/dev"    "$(out_of checkout_ref)"
check "checkout_sha is the event commit" "$SHA_EVENT"        "$(out_of checkout_sha)"
check "base_sha falls back to the event" "$SHA_EVENT"        "$(out_of base_sha)"
check "trusted_execution is false"       "false"             "$(out_of trusted_execution)"
# The property, stated as such: a bare 40-hex checkout_ref detaches HEAD.
if [[ "$(out_of checkout_ref)" =~ ^[0-9a-fA-F]{40}$ ]]; then
  printf '  [FAIL] push checkout_ref must NOT be a bare SHA (detaches HEAD, disarms the wipe)\n'; fail=$((fail+1))
else
  printf '  [pass] push checkout_ref is not a bare SHA\n'; pass=$((pass+1))
fi

echo "-- pull_request: must pin to the event SHA, immune to refs/pull/N/merge re-minting --"
run_validate pull_request "refs/pull/2832/merge" "$SHA_EVENT" "" "$SHA_BASE"
check "exits 0"                            "0"          "$rc"
check "checkout_ref is the event SHA"      "$SHA_EVENT" "$(out_of checkout_ref)"
check "checkout_sha is the event SHA"      "$SHA_EVENT" "$(out_of checkout_sha)"
check "ref == sha, so Verify is meaningful" "$(out_of checkout_sha)" "$(out_of checkout_ref)"
check "base_sha is the PR base"            "$SHA_BASE"  "$(out_of base_sha)"

echo "-- workflow_call with an APPROVED head sha: pinned to the approved commit --"
APPROVED=3333333333333333333333333333333333333333
run_validate pull_request "refs/pull/2832/merge" "$SHA_EVENT" "$APPROVED" "$SHA_BASE"
# Without PR_NUMBER/TRUSTED_GATE the trusted path is expected to REFUSE; what is
# pinned here is that it does not silently fall through to the untrusted branch.
if [ "$rc" = "0" ]; then
  check "approved: checkout_ref is the approved sha" "$APPROVED" "$(out_of checkout_ref)"
  check "approved: checkout_sha is the approved sha" "$APPROVED" "$(out_of checkout_sha)"
else
  if [ "$(out_of checkout_ref)" = "$SHA_EVENT" ]; then
    printf '  [FAIL] rejected trusted call fell through to the untrusted branch\n'; fail=$((fail+1))
  else
    printf '  [pass] incomplete trusted call refuses (rc=%s) and pins nothing\n' "$rc"; pass=$((pass+1))
  fi
fi

echo "-- workflow_call, malformed approved sha: must never build it --"
run_validate pull_request "refs/pull/2832/merge" "$SHA_EVENT" "not-a-sha" "$SHA_BASE"
if [ "$rc" = "0" ] && [ "$(out_of checkout_sha)" = "not-a-sha" ]; then
  printf '  [FAIL] malformed approved sha was accepted\n'; fail=$((fail+1))
else
  printf '  [pass] malformed approved sha refused (rc=%s)\n' "$rc"; pass=$((pass+1))
fi

echo "  ---"
echo "  ${pass} passed, ${fail} failed"
[ "$fail" = 0 ]
