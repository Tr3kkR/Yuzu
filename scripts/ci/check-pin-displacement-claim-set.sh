#!/usr/bin/env bash
# check-pin-displacement-claim-set.sh — drift gate for the "what causes a replay-ring pin
# displacement" claim, which is stated on four operator-facing surfaces at once.
#
# WHY THIS EXISTS. #2740 falsified the claim "a full pin-slot set means admission accounting
# has drifted". Fixing it took thirteen governance rounds, because the claim lives as an
# independent paraphrase on every surface that mentions it and each round found and fixed a
# different subset. Round twelve designated one normative home and had every other site cite
# it; round thirteen still shipped two stale copies, one in a customer changelog, one in the
# `/metrics` HELP string. A convention did not hold. This does.
#
# WHAT IT CHECKS, AND WHY THAT AND NOT THE PROSE. It does NOT try to diff the derivation —
# the lexical-gate approach walls at exactly that boundary and is parked for that reason.
# What it checks is the part that is machine-comparable: the CAUSE SET, i.e. which counters
# each surface names as explaining a displacement. That set is enumerable, it is what an
# on-call engineer acts on, and every defect this gate exists to catch was a disagreement
# about its membership:
#
#   - the alert expression subtracting a counter that explains nothing (round 12)
#   - `/metrics` HELP saying "rule all three out" (round 13)
#   - a changelog telling operators to alert via a netted rule that no longer exists (13)
#
# THE INVARIANT, in two halves:
#   (a) `yuzu_mcp_bridge_pin_displaced_for_admission_total` is NOT a cause. A successful
#       reclaim releases one pin and adds one charge, so the session stays AT cap and a slot
#       is always free. It must never appear in the alert expression, and must never be
#       presented as something to rule out against.
#   (b) The two residual counters ARE the cause set, and every surface that enumerates
#       causes must name both.
#
# Derivation and proof: `What a FULL PIN-SLOT SET means` in server/core/src/mcp_stream.hpp.
#
# Usage:  check-pin-displacement-claim-set.sh [REPO_ROOT]
# Exit:   0 = consistent, 1 = drift (message names the surface and the discrepancy)

set -euo pipefail

ROOT="${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}"
cd "$ROOT"

RECLAIM="yuzu_mcp_bridge_pin_displaced_for_admission_total"
RACED="yuzu_mcp_bridge_pin_release_raced_total"
FAILED="yuzu_mcp_bridge_pin_release_failed_total"

ALERTS="docs/prometheus/yuzu-alerts.yml"
HELP="server/core/src/server.cpp"
MANUAL="docs/user-manual/metrics.md"
HOME_HDR="server/core/src/mcp_stream.hpp"

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
    /^[[:space:]]*-[[:space:]]*alert:[[:space:]]*YuzuMcpStreamPinDisplaced[[:space:]]*$/ { grab=1; next }
    grab && /^[[:space:]]*labels:/ { grab=0 }
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
# A surface "enumerates causes" if it mentions the displacement counter at all. Checking
# both-or-neither rather than presence alone is deliberate: naming one residual and not the
# other is the shape that produced the "#2795 is deliberately silent" defect.
# ---------------------------------------------------------------------------
for f in "$ALERTS" "$HELP" "$MANUAL" "$HOME_HDR"; do
    has_raced=0; has_failed=0
    grep -q "$RACED" "$f" && has_raced=1
    grep -q "$FAILED" "$f" && has_failed=1
    if [ "$has_raced" -ne "$has_failed" ]; then
        bad "$f names one residual counter but not the other (raced=$has_raced failed=$has_failed)."
        note "Both are causes of a displacement; naming one implies the other has no signal,"
        note "which is exactly the defect $RACED was added to end."
    elif [ "$has_raced" -eq 0 ]; then
        bad "$f mentions the displacement claim but names neither residual counter."
    fi
done

# ---------------------------------------------------------------------------
# (c) No surface may instruct the reader to rule out against the reclaim counter.
#
# Phrase-based and deliberately narrow: it catches the exact wording that shipped twice
# ("rule all three out") without pretending to understand prose.
# ---------------------------------------------------------------------------
for f in "$ALERTS" "$HELP" "$MANUAL" docs/ops-runbooks/mcp-stream-pin-displacement.md \
         changelog.d/*.md; do
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

printf 'pin-displacement claim set: consistent across %s, %s, %s, %s\n' \
    "$ALERTS" "$HELP" "$MANUAL" "$HOME_HDR"
