#!/usr/bin/env bash
# check-pin-displacement-claim-set.sh — drift gate for the "what causes a replay-ring pin
# displacement" claim, which is stated independently on every surface in STATING_SURFACES
# (see the array below) plus changelog.d fragments.
#
# WHY THIS EXISTS. #2740 falsified the claim "a full pin-slot set means admission accounting
# has drifted". Correcting it across its surfaces took repeated review passes — the run
# ledger for that work is governance.d/2740-streamed-post-flip-set.csK3yu.jsonl, which is
# the one home for how many and what each found; this comment deliberately does not restate
# a count. The shape that mattered is what recurred: the claim lives as an independent
# paraphrase on every surface that mentions it, so each pass found and fixed a different
# subset. The pass that designated a single normative home and had every other site cite it
# STILL shipped two stale copies — one in a customer changelog, one in the `/metrics` HELP
# string — under four reviewers actively looking for exactly that. A convention did not
# hold. This does.
#
# WHAT IT CHECKS, AND WHY THAT AND NOT THE PROSE. It does NOT try to diff the derivation —
# the lexical-gate approach walls at exactly that boundary and is parked for that reason.
# What it checks is the part that is machine-comparable: the CAUSE SET, i.e. which counters
# each surface names as explaining a displacement. That set is enumerable, it is what an
# on-call engineer acts on, and every defect this gate exists to catch was a disagreement
# about its membership:
#
#   - the alert expression subtracting a counter that explains nothing
#   - `/metrics` HELP saying "rule all three out"
#   - a changelog telling operators to alert via a netted rule that no longer exists
#
# (Each is recorded in the ledger cited above, with the pass that found it. The --selftest
# below reproduces every shape in this list and the runbook/changelog shapes an adversarial
# review added, so the list is exercised rather than asserted. Its case count is not
# restated here - run it.)
#
# THE INVARIANT, in two halves:
#   (a) `yuzu_mcp_bridge_pin_displaced_for_admission_total` is NOT a cause. A successful
#       reclaim releases one pin and adds one charge, so the session stays AT cap and a slot
#       is always free. It must never appear in the alert expression, and must never be
#       presented as something to rule out against.
#   (b) The two residual counters ARE the cause set. Every surface in STATING_SURFACES must
#       name BOTH. The membership is the array, not this comment - it is deliberately not
#       enumerated here, for the same reason the case count is not: a list you have to
#       remember to update twice is the defect. changelog.d fragments are held to
#       both-or-neither instead: a release note need not enumerate counters, but naming one
#       while omitting the other is the drift shape.
#
# The runbook was NOT in (b) in the first version of this gate, while the workflow header
# claimed it was. Two external reviewers found that independently and blocked on it, each
# with a fixture: a runbook naming one residual passed green. That is the same false-green
# class this gate exists to end, so it is now covered and self-tested.
#
# Derivation and proof: `What a FULL PIN-SLOT SET means` in server/core/src/mcp_stream.hpp.
#
# Usage:  check-pin-displacement-claim-set.sh [REPO_ROOT]
# Exit:   0 = consistent, 1 = drift (message names the surface and the discrepancy)

set -euo pipefail

# (ROOT is re-read below for the normal path.)
# --selftest: prove the detector reddens on each defect shape it claims to catch, using
# fixtures in a scratch dir - never the real tree. Runs in CI BEFORE the real check, on the
# plugin-spawn-gate.yml precedent: a gate nobody has watched fail is an assertion, not a
# check (claim-discipline rule 5).
if [ "${1:-}" = "--selftest" ]; then
    tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
    self="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
    pass=0; failed=0
    fixture() {  # $1 = case name; builds a minimal consistent tree, then the caller breaks it
        rm -rf "$tmp/t"; mkdir -p "$tmp/t/docs/prometheus" "$tmp/t/docs/user-manual" \
            "$tmp/t/docs/ops-runbooks" "$tmp/t/server/core/src" "$tmp/t/changelog.d"
        cat > "$tmp/t/docs/prometheus/yuzu-alerts.yml" <<'YML'
groups:
  - name: mcp
    rules:
      - alert: YuzuMcpStreamPinDisplaced
        expr: |
          increase(yuzu_mcp_stream_pin_displaced_total[15m]) > 0
        labels:
          severity: warning
        annotations:
          description: >-
            causes are yuzu_mcp_bridge_pin_release_raced_total and
            yuzu_mcp_bridge_pin_release_failed_total.
YML
        printf '%s\n' 'yuzu_mcp_bridge_pin_release_raced_total yuzu_mcp_bridge_pin_release_failed_total' \
            > "$tmp/t/server/core/src/server.cpp"
        printf '%s\n' 'yuzu_mcp_bridge_pin_release_raced_total yuzu_mcp_bridge_pin_release_failed_total' \
            > "$tmp/t/server/core/src/mcp_stream.hpp"
        printf '%s\n' 'yuzu_mcp_bridge_pin_release_raced_total yuzu_mcp_bridge_pin_release_failed_total' \
            > "$tmp/t/docs/user-manual/metrics.md"
        printf '%s\n' 'YuzuMcpStreamPinDisplaced: rule out yuzu_mcp_bridge_pin_release_raced_total and yuzu_mcp_bridge_pin_release_failed_total.' \
            > "$tmp/t/docs/ops-runbooks/mcp-stream-pin-displacement.md"
        printf '%s\n' 'yuzu_mcp_bridge_pin_release_raced_total yuzu_mcp_bridge_pin_release_failed_total' > "$tmp/t/docs/mcp-server.md"
        printf '%s\n' 'yuzu_mcp_bridge_pin_release_raced_total yuzu_mcp_bridge_pin_release_failed_total' > "$tmp/t/docs/adr-1005-execution-plan.md"
        : > "$tmp/t/changelog.d/x.md"
    }
    expect() {  # $1 = case name, $2 = expected exit (0 clean / 1 drift)
        if bash "$self" "$tmp/t" >/dev/null 2>&1; then got=0; else got=1; fi
        if [ "$got" = "$2" ]; then pass=$((pass+1)); printf '  ok    %s\n' "$1"
        else failed=$((failed+1)); printf '  FAIL  %s (expected exit %s, got %s)\n' "$1" "$2" "$got"; fi
    }

    fixture; expect "baseline consistent fixture is clean" 0

    fixture
    perl -pi -e 's{increase\(yuzu_mcp_stream_pin_displaced_total\[15m\]\) > 0}{(increase(yuzu_mcp_stream_pin_displaced_total[15m]) - increase(yuzu_mcp_bridge_pin_displaced_for_admission_total[15m])) > 0}' \
        "$tmp/t/docs/prometheus/yuzu-alerts.yml"
    expect "netted expr subtracting the reclaim counter" 1

    fixture
    printf '%s\n' 'Rule all three out against their counters.' >> "$tmp/t/server/core/src/server.cpp"
    expect '"rule all three out" in the /metrics HELP' 1

    fixture
    printf '%s\n' 'Alert via the shipped rule, which subtracts the explained paths.' \
        >> "$tmp/t/changelog.d/x.md"
    expect "changelog describing a netted rule" 1

    fixture
    printf '%s\n' 'yuzu_mcp_bridge_pin_release_failed_total' > "$tmp/t/docs/user-manual/metrics.md"
    expect "one residual counter named without the other" 1

    # The two shapes an adversarial review (kimi + codex, independently) proved this gate
    # did NOT catch while its workflow claimed to protect these surfaces.
    fixture
    printf '%s\n' 'YuzuMcpStreamPinDisplaced: rule out yuzu_mcp_bridge_pin_release_failed_total.' \
        > "$tmp/t/docs/ops-runbooks/mcp-stream-pin-displacement.md"
    expect "RUNBOOK names one residual without the other" 1

    fixture
    printf '%s\n' 'yuzu_mcp_stream_pin_displaced_total is explained by yuzu_mcp_bridge_pin_release_failed_total.' \
        > "$tmp/t/changelog.d/x.md"
    expect "CHANGELOG fragment names one residual without the other" 1

    fixture
    : > "$tmp/t/docs/ops-runbooks/mcp-stream-pin-displacement.md"
    expect "RUNBOOK names neither residual" 1

    # BC-1/QA-1: check (c) omitted the derivation header, so the banned phrasing passed
    # green in the very file every DRIFT message tells the reader to go and consult.
    fixture
    printf '%s\n' 'Rule all three out against their counters.' >> "$tmp/t/server/core/src/mcp_stream.hpp"
    expect "DERIVATION HEADER says to rule all three out" 1

    # QA-2: two live docs state the cause set and were in no surface list at all.
    fixture
    printf '%s\n' 'The shipped rule, which subtracts the explained paths.' >> "$tmp/t/docs/mcp-server.md"
    expect "docs/mcp-server.md describes a netted rule" 1

    fixture
    printf '%s\n' 'yuzu_mcp_bridge_pin_release_failed_total' > "$tmp/t/docs/adr-1005-execution-plan.md"
    expect "ADR names one residual without the other" 1

    printf '\nselftest: %s passed, %s failed\n' "$pass" "$failed"
    [ "$failed" -eq 0 ] || exit 1
    exit 0
fi

ROOT="${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}"
cd "$ROOT"

RECLAIM="yuzu_mcp_bridge_pin_displaced_for_admission_total"
RACED="yuzu_mcp_bridge_pin_release_raced_total"
FAILED="yuzu_mcp_bridge_pin_release_failed_total"

ALERTS="docs/prometheus/yuzu-alerts.yml"
HELP="server/core/src/server.cpp"
MANUAL="docs/user-manual/metrics.md"
HOME_HDR="server/core/src/mcp_stream.hpp"
RUNBOOK="docs/ops-runbooks/mcp-stream-pin-displacement.md"

# THE STATING SURFACES - ONE list, and every check derives from it.
#
# This is deliberately a single array because the two previous versions of this gate kept
# two hand-maintained lists, and BOTH holes found by review were a divergence between them:
# an external panel found the runbook missing from the cause-set check, and the next round
# found the derivation header missing from the phrase check. A list you have to remember to
# update twice is the defect, not the omissions it produces.
#
# Membership rule: a file belongs here if it STATES which counters explain a displacement.
# docs/mcp-server.md and the ADR were added after review proved they state it and were
# checked by nothing. If you add a surface that states the claim, add it HERE and both
# checks pick it up.
STATING_SURFACES=(
    "$ALERTS"
    "$HELP"
    "$MANUAL"
    "$HOME_HDR"
    "$RUNBOOK"
    "docs/mcp-server.md"
    "docs/adr-1005-execution-plan.md"
)

fail=0
note() { printf '  %s\n' "$*"; }
bad() { printf 'DRIFT: %s\n' "$*"; fail=1; }

for f in "$ALERTS" "$HELP" "$MANUAL" "$HOME_HDR"; do
    [ -f "$f" ] || { bad "missing surface: $f"; }
done
[ "$fail" -eq 0 ] || exit 1

# ---------------------------------------------------------------------------
# (a) The reclaim counter must not appear in the YuzuMcpStreamPinDisplaced expr.
#
# Extract the alert's expr block: from the alert name to the next `labels:` key.
# ---------------------------------------------------------------------------
expr_block="$(awk '
    # Tolerate a trailing comment on the alert line, and stop at ANY sibling key - an
    # earlier version stopped only at `labels:`, so a rule ordering `annotations:` first
    # (valid YAML) pulled annotation prose into the expr block and misdiagnosed it.
    /^[[:space:]]*-[[:space:]]*alert:[[:space:]]*YuzuMcpStreamPinDisplaced([[:space:]]|#|$)/ { grab=1; next }
    grab && /^[[:space:]]*(labels|annotations|for|keep_firing_for|-[[:space:]]*alert):/ { grab=0 }
    grab { print }
' "$ALERTS")"

if [ -z "$expr_block" ]; then
    bad "$ALERTS: alert YuzuMcpStreamPinDisplaced not found (renamed? then update this gate)"
elif printf '%s' "$expr_block" | grep -q "$RECLAIM"; then
    bad "$ALERTS: YuzuMcpStreamPinDisplaced's expr references $RECLAIM."
    note "A successful reclaim cannot cause a displacement, so subtracting it removes real"
    note "signal in proportion to ordinary client churn. It is also a process-wide total"
    note "while the displacement counter is per-session state, so the join cannot exist."
    note "See 'What a FULL PIN-SLOT SET means' in $HOME_HDR."
fi

# ---------------------------------------------------------------------------
# (b) Every surface that enumerates causes must name BOTH residual counters.
#
# Membership in STATING_SURFACES is what makes a file subject to this - the check does NOT
# look for the displacement counter first, so a registered surface that drops the claim
# entirely is reported too, and that is intended: silently losing the statement is the same
# drift as stating it wrongly. Checking both-or-neither rather than presence alone is
# deliberate: naming one residual and not the other is the shape that produced the
# "#2795 is deliberately silent" defect.
# ---------------------------------------------------------------------------
# The RUNBOOK is in this set, not merely the phrase check below. It is the surface an
# on-call engineer actually executes, and an adversarial review found that leaving it out
# made this gate false-green for exactly the drift it exists to stop: a runbook naming one
# residual and omitting the other passed green. Both external reviewers reproduced that
# independently, and CLAUDE.md makes a false-green offered as closure evidence a policy
# floor - so the gate claiming a surface it did not check was itself the blocking defect.
for f in "${STATING_SURFACES[@]}"; do
    [ -f "$f" ] || { bad "missing surface: $f"; continue; }
    has_raced=0; has_failed=0
    grep -q "$RACED" "$f" && has_raced=1
    grep -q "$FAILED" "$f" && has_failed=1
    if [ "$has_raced" -ne "$has_failed" ]; then
        bad "$f names one residual counter but not the other (raced=$has_raced failed=$has_failed)."
        note "Both are causes of a displacement; naming one implies the other has no signal,"
        note "which is exactly the defect $RACED was added to end."
    elif [ "$has_raced" -eq 0 ]; then
        bad "$f is a registered stating surface but names neither residual counter."
        note "Either restate the cause set here, or remove it from STATING_SURFACES."
    fi
done

# changelog.d fragments get the weaker BOTH-OR-NEITHER rule, deliberately. A fragment may
# legitimately describe the fix without enumerating counter names at all - customer release
# notes are not a rule-out procedure - but naming ONE residual while omitting the other is
# the "#2795 is deliberately silent" shape that shipped once already, and that must fail.
for f in changelog.d/*.md; do
    [ -f "$f" ] || continue
    has_raced=0; has_failed=0
    grep -q "$RACED" "$f" && has_raced=1
    grep -q "$FAILED" "$f" && has_failed=1
    if [ "$has_raced" -ne "$has_failed" ]; then
        bad "$f names one residual counter but not the other (raced=$has_raced failed=$has_failed)."
        note "A fragment may name neither, but naming one implies the other has no signal."
    fi
done

# ---------------------------------------------------------------------------
# (c) No surface may instruct the reader to rule out against the reclaim counter.
#
# Phrase-based and deliberately narrow: it catches the exact wording that shipped twice
# ("rule all three out") without pretending to understand prose.
# ---------------------------------------------------------------------------
for f in "${STATING_SURFACES[@]}" changelog.d/*.md; do
    [ -f "$f" ] || continue
    if grep -qiE 'rule[[:space:]]+(all[[:space:]]+)?three[[:space:]]+(of[[:space:]]+them[[:space:]]+)?out' "$f"; then
        bad "$f says to rule out three causes. There are two; the reclaim explains zero."
    fi
    if grep -qiE 'subtracts the explained paths|which subtracts|nets (them|all three) out' "$f"; then
        bad "$f describes a netted alert expression. The shipped rule is a plain threshold."
    fi
done

if [ "$fail" -ne 0 ]; then
    printf '\n%s\n' "The cause set is: $RACED, $FAILED."
    printf '%s\n' "$RECLAIM is NOT a cause. Derivation: $HOME_HDR."
    exit 1
fi

printf 'pin-displacement claim set: consistent across %s surfaces (+ changelog.d):\n' "${#STATING_SURFACES[@]}"
printf '  %s\n' "${STATING_SURFACES[@]}"
