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
#       name BOTH, in its own CLAIM REGION — see #2827 below. changelog.d fragments are held
#       to both-or-neither instead: a release note need not enumerate counters, but naming
#       one while omitting the other is the drift shape.
#
# The runbook was NOT in (b) in the first version of this gate, while the workflow header
# claimed it was. Two external reviewers found that independently and blocked on it, each
# with a fixture: a runbook naming one residual passed green. That was the SECOND false-green
# this gate shipped; it is now covered and self-tested.
#
# #2827 — THE THIRD FALSE-GREEN, AND WHY (b) IS REGION-SCOPED, NOT WHOLE-FILE. The first
# region-less version of (b) tested each surface with a presence-only whole-file grep. On
# four surfaces a counter identifier occurs more than once (a metrics.describe() registration,
# a counter() pre-seed, a sibling alert rule, a sibling table row) — so rewriting ONLY the
# claim text to drop a cause left an unrelated sibling occurrence satisfying the grep, and the
# gate stayed green on exactly the drift it exists to catch. Found by an adversarial review of
# #2796 after merge, reproduced independently, filed as #2827. Root cause of why --selftest
# did not catch it: every fixture wrote exactly ONE occurrence per file, so masking was
# structurally unreachable in the fixtures regardless of what the checker did. (b) now
# extracts each surface's own CLAIM REGION (claim_region() below) and tests membership only
# inside it; the fixtures below carry realistic sibling occurrences so masking is reachable
# in --selftest too, and assert_realistic_fixture() guards against that property regressing.
# New check (d) is a narrower, best-effort tripwire for the sibling class this does not close:
# a claim restated on a surface/line that was never registered at all. See its own comment.
#
# Derivation and proof: `What a FULL PIN-SLOT SET means` in server/core/src/mcp_stream.hpp.
#
# Usage:  check-pin-displacement-claim-set.sh [REPO_ROOT]
# Exit:   0 = consistent, 1 = drift (message names the surface and the discrepancy)

set -euo pipefail

RECLAIM="yuzu_mcp_bridge_pin_displaced_for_admission_total"
RACED="yuzu_mcp_bridge_pin_release_raced_total"
FAILED="yuzu_mcp_bridge_pin_release_failed_total"
DISPLACED="yuzu_mcp_stream_pin_displaced_total"

ALERTS="docs/prometheus/yuzu-alerts.yml"
HELP="server/core/src/server.cpp"
MANUAL="docs/user-manual/metrics.md"
HOME_HDR="server/core/src/mcp_stream.hpp"
RUNBOOK="docs/ops-runbooks/mcp-stream-pin-displacement.md"
MCP_SERVER_DOC="docs/mcp-server.md"
ADR_DOC="docs/adr-1005-execution-plan.md"

# A multi-line claim_region() extractor's stop condition is a FORMAT ASSUMPTION about
# future edits (e.g. "the next decision item starts with `N. **`"), not a syntactic
# guarantee - unlike an all-`grab`ped C++ describe() call, prose formatting can drift
# without anyone intending to break the gate. If a future sibling item is reformatted so
# the stop pattern never matches, grab keeps consuming lines - which can absorb a sibling's
# unrelated mention of a residual counter into the CURRENT claim's region and silently
# re-open the #2827 masking class this gate exists to close (reproduced against the ADR
# extractor in governance review of this same PR - a "16)" heading instead of "16." never
# matched the stop regex, and item 16's incidental counter mention got absorbed into
# decision 15's region, masking a deliberately stale decision-15 claim).
#
# TWO DEFENSES, not one, because they close different-sized failures. The real fix for the
# reproduced case is a STOP PATTERN broad enough to recognize a plausible reformat - the
# ADR's now matches any `N.`/`N)` numbered item regardless of emphasis style, and
# MCP_SERVER_DOC's now also stops at the next bold paragraph lead, not blank-line-only. A
# hardened pattern still can't enumerate every future format, so MAX_REGION_LINES is a
# SEPARATE backstop against the case a hardened pattern can't help: a terminator that
# matches nothing at all and runs to EOF, or absorbs many lines rather than one. It is
# deliberately sized well above every surface's real region (the largest today, the hpp
# derivation block, is ~105 lines) rather than tuned to catch a small absorption - a first
# attempt at a tight shared cap (60) both false-DRIFTed on that legitimately-long block and
# did nothing against the 1-line exploit it was meant to catch, which is why the stop
# patterns, not the cap, are the primary defense.
MAX_REGION_LINES=250

# THE STATING SURFACES - ONE list, and every check that iterates surfaces (checks b/c/d;
# the alert-expr check (a) is alert-specific by construction and operates on $ALERTS
# directly) derives from it.
#
# This is deliberately a single array because the two previous versions of this gate kept
# two hand-maintained lists, and BOTH holes found by review were a divergence between them:
# an external panel found the runbook missing from the cause-set check, and the next round
# found the derivation header missing from the phrase check. A list you have to remember to
# update twice is the defect, not the omissions it produces.
#
# Membership rule: a file belongs here if it STATES which counters explain a displacement.
# docs/mcp-server.md and the ADR were added after review proved they state it and were
# checked by nothing. If you add a surface that states the claim, add it HERE, give it a
# claim_region() arm below (its default arm is fail-closed - a surface with no extractor is
# reported as DRIFT, never silently unchecked), and every check picks it up.
STATING_SURFACES=(
    "$ALERTS"
    "$HELP"
    "$MANUAL"
    "$HOME_HDR"
    "$RUNBOOK"
    "$MCP_SERVER_DOC"
    "$ADR_DOC"
)

# ---------------------------------------------------------------------------
# claim_region() — extract the bounded region of a surface that actually states the cause
# set, so check (b) tests membership THERE rather than anywhere in the file (#2827).
#
# Protocol: on success, prints the region to stdout and returns 0. On failure, prints a
# single line "ERR <token>" and returns 1 - the caller maps the token to a DRIFT message.
# Every arm is fail-closed: an anchor that cannot be found (surface restructured), an anchor
# that matches more than once (ambiguous - would silently pick one and could pick the wrong
# one), or a terminator that goes missing (surface reformatted) is reported, never guessed
# past. Anchor/terminator matching uses index()/fixed strings, never a data-derived regex -
# several anchors below contain `|` and backticks, which are regex metacharacters.
# ---------------------------------------------------------------------------
claim_region() {
    local f="$1"
    case "$f" in
        "$ALERTS")
            # Region = the YuzuMcpStreamPinDisplaced rule block, anchor line to the next
            # `- alert:` (commented or not - a commented-out sibling must not inflate the
            # region) or EOF. Reuses check (a)'s proven anchor regex.
            awk -v max="$MAX_REGION_LINES" '
                { line = $0; sub(/\r$/, "", line) }
                line ~ /^[[:space:]]*-[[:space:]]*alert:[[:space:]]*YuzuMcpStreamPinDisplaced([[:space:]]|#|$)/ {
                    n++
                    if (n == 1) { grab = 1; buf = line "\n"; cnt = 1; next }
                    grab = 0; next
                }
                grab && line ~ /^[[:space:]]*#?[[:space:]]*-[[:space:]]*alert:/ { grab = 0 }
                grab {
                    cnt++
                    if (cnt > max) { overrun = 1; grab = 0; next }
                    buf = buf line "\n"
                }
                END {
                    if (n == 0) { print "ERR anchor-missing"; exit 1 }
                    if (n > 1)  { print "ERR anchor-ambiguous"; exit 1 }
                    if (overrun) { print "ERR region-overrun"; exit 1 }
                    printf "%s", buf
                }
            ' "$f"
            ;;
        "$HELP")
            # Region = the yuzu_mcp_stream_pin_displaced_total metrics_.describe() call,
            # anchor line through its closing `"counter");`/`"gauge");` line inclusive. A
            # lost terminator (reformatted, retyped) must not let the region run into the
            # next describe() call - that would silently re-open the #2827 mask inside this
            # very mechanism, so it is fail-closed rather than falling back to EOF.
            awk -v max="$MAX_REGION_LINES" '
                { line = $0; sub(/\r$/, "", line); stripped = line; sub(/^[[:space:]]+/, "", stripped) }
                index(stripped, "metrics_.describe(\"yuzu_mcp_stream_pin_displaced_total\",") == 1 {
                    n++
                    if (n == 1) { grab = 1; buf = line "\n"; cnt = 1; next }
                    grab = 0; next
                }
                grab {
                    cnt++
                    if (cnt > max) { overrun = 1; grab = 0; next }
                    buf = buf line "\n"
                    if (stripped == "\"counter\");" || stripped == "\"gauge\");") { grab = 0; terminated = 1; next }
                    if (index(stripped, "metrics_.") == 1) { grab = 0; next }
                }
                END {
                    if (n == 0) { print "ERR anchor-missing"; exit 1 }
                    if (n > 1)  { print "ERR anchor-ambiguous"; exit 1 }
                    if (overrun) { print "ERR region-overrun"; exit 1 }
                    if (!terminated) { print "ERR terminator-missing"; exit 1 }
                    printf "%s", buf
                }
            ' "$f"
            ;;
        "$MANUAL")
            # Region = the single markdown table row for yuzu_mcp_stream_pin_displaced_total.
            awk '
                { line = $0; sub(/\r$/, "", line); stripped = line; sub(/^[[:space:]]+/, "", stripped) }
                index(stripped, "| `yuzu_mcp_stream_pin_displaced_total` |") == 1 {
                    n++
                    if (n == 1) { buf = line "\n" }
                    next
                }
                END {
                    if (n == 0) { print "ERR anchor-missing"; exit 1 }
                    if (n > 1)  { print "ERR anchor-ambiguous"; exit 1 }
                    printf "%s", buf
                }
            ' "$f"
            ;;
        "$RUNBOOK")
            # Region = the cause table: header row through the last contiguous `|`-led line.
            awk -v max="$MAX_REGION_LINES" '
                { line = $0; sub(/\r$/, "", line); stripped = line; sub(/^[[:space:]]+/, "", stripped) }
                index(stripped, "| counter | what it means |") == 1 {
                    n++
                    if (n == 1) { grab = 1; buf = line "\n"; cnt = 1; next }
                    grab = 0; next
                }
                grab {
                    if (index(stripped, "|") != 1) { grab = 0; next }
                    cnt++
                    if (cnt > max) { overrun = 1; grab = 0; next }
                    buf = buf line "\n"
                }
                END {
                    if (n == 0) { print "ERR anchor-missing"; exit 1 }
                    if (n > 1)  { print "ERR anchor-ambiguous"; exit 1 }
                    if (overrun) { print "ERR region-overrun"; exit 1 }
                    printf "%s", buf
                }
            ' "$f"
            ;;
        "$HOME_HDR")
            # Region = the "What a FULL PIN-SLOT SET means" ### block: anchor through the
            # last contiguous `///` line, stopping early at a later `/// ###` subheading.
            # Anchored on the `###`-prefixed heading, NOT the bare phrase - the phrase alone
            # also appears in a same-file cross-reference ("see ... above"), which would
            # make a bare-phrase anchor ambiguous today.
            awk -v max="$MAX_REGION_LINES" '
                { line = $0; sub(/\r$/, "", line); stripped = line; sub(/^[[:space:]]+/, "", stripped) }
                index(stripped, "/// ### What a FULL PIN-SLOT SET means") == 1 {
                    n++
                    if (n == 1) { grab = 1; buf = line "\n"; cnt = 1; next }
                    grab = 0; next
                }
                grab {
                    if (index(stripped, "/// ###") == 1) { grab = 0; next }
                    if (index(stripped, "///") != 1) { grab = 0; next }
                    cnt++
                    if (cnt > max) { overrun = 1; grab = 0; next }
                    buf = buf line "\n"
                }
                END {
                    if (n == 0) { print "ERR anchor-missing"; exit 1 }
                    if (n > 1)  { print "ERR anchor-ambiguous"; exit 1 }
                    if (overrun) { print "ERR region-overrun"; exit 1 }
                    printf "%s", buf
                }
            ' "$f"
            ;;
        "$MCP_SERVER_DOC")
            # Region = the "A pin released to admit a new call" paragraph: anchor line
            # through the next blank line OR the next bold-lead paragraph, whichever comes
            # first. Anchored at LINE START - the phrase also occurs mid-line in a same-file
            # cross-reference table row, which a bare `index() > 0` anchor would count as a
            # second occurrence and wrongly call ambiguous.
            #
            # The bold-lead stop is defense-in-depth, not merely blank-line: every paragraph
            # in this section follows a `**Title.**` lead-in convention (see "Monotonicity.",
            # "Terminal durability." nearby), so a future edit that drops the blank-line
            # separator between two paragraphs still stops correctly, rather than absorbing
            # the next paragraph's prose into this one's claim region.
            awk -v max="$MAX_REGION_LINES" '
                { line = $0; sub(/\r$/, "", line); stripped = line; sub(/^[[:space:]]+/, "", stripped) }
                index(stripped, "**A pin released to admit a new call") == 1 {
                    n++
                    if (n == 1) { grab = 1; buf = line "\n"; cnt = 1; next }
                    grab = 0; next
                }
                grab && cnt >= 1 && index(stripped, "**") == 1 { grab = 0; next }
                grab {
                    if (stripped == "") { grab = 0; next }
                    cnt++
                    if (cnt > max) { overrun = 1; grab = 0; next }
                    buf = buf line "\n"
                }
                END {
                    if (n == 0) { print "ERR anchor-missing"; exit 1 }
                    if (n > 1)  { print "ERR anchor-ambiguous"; exit 1 }
                    if (overrun) { print "ERR region-overrun"; exit 1 }
                    printf "%s", buf
                }
            ' "$f"
            ;;
        "$ADR_DOC")
            # Region = the whole Decision-15 numbered item: anchor line through the line
            # before the next numbered decision or heading. Anchored on the decision's own
            # title, NOT a dated "AMENDED <date>" marker - a marker anchor rots the moment a
            # later amendment is appended as a new paragraph, freezing the region on the
            # OLD text while the live claim migrates past it.
            #
            # Stop pattern deliberately matches ANY markdown ordered-list item start -
            # `[0-9]+` then `.` or `)` then whitespace - not a specific emphasis style.
            # A stop pattern requiring `**` bold immediately after the number was defeated
            # in governance review of this same PR: a sibling item written `16) *Title*`
            # (paren delimiter, single-asterisk emphasis) matched neither the old regex nor
            # `^#`, so the scan ran past it into item 17, absorbing item 16's unrelated
            # counter mention into decision 15's claim region. The number+delimiter+space
            # shape is markdown's own list-item syntax, not this file's style choice, so it
            # is far less likely to drift than a specific emphasis convention - though it is
            # still a format assumption, not a guarantee, which is what MAX_REGION_LINES is
            # the backstop for.
            awk -v max="$MAX_REGION_LINES" '
                { line = $0; sub(/\r$/, "", line) }
                line ~ /^15\.[[:space:]]+\*\*MCP Streamable HTTP transport/ {
                    n++
                    if (n == 1) { grab = 1; buf = line "\n"; cnt = 1; next }
                    grab = 0; next
                }
                grab && (line ~ /^[0-9]+[.)][[:space:]]/ || line ~ /^#/) { grab = 0 }
                grab {
                    cnt++
                    if (cnt > max) { overrun = 1; grab = 0; next }
                    buf = buf line "\n"
                }
                END {
                    if (n == 0) { print "ERR anchor-missing"; exit 1 }
                    if (n > 1)  { print "ERR anchor-ambiguous"; exit 1 }
                    if (overrun) { print "ERR region-overrun"; exit 1 }
                    printf "%s", buf
                }
            ' "$f"
            ;;
        *)
            printf 'ERR no-extractor\n'
            return 1
            ;;
    esac
}

# (ROOT is re-read below for the normal path.)
# --selftest: prove the detector reddens on each defect shape it claims to catch, using
# fixtures in a scratch dir - never the real tree. Runs in CI BEFORE the real check, on the
# plugin-spawn-gate.yml precedent: a gate nobody has watched fail is an assertion, not a
# check (claim-discipline rule 5).
if [ "${1:-}" = "--selftest" ]; then
    tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
    self="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
    pass=0; failed=0

    # fixture() builds a minimal but REALISTIC tree: every maskable surface (alerts.yml,
    # server.cpp, metrics.md, the runbook) carries the SAME sibling-occurrence shape the
    # real files do - a registration/pre-seed pair, a sibling alert rule, a sibling table
    # row - so a mutation that stales ONLY the claim region while leaving siblings intact is
    # reachable here. The three surfaces that are protected today (exactly one occurrence
    # each in the real tree - mcp_stream.hpp, mcp-server.md, the ADR) still get an
    # anchor-uniqueness stress: mcp-server.md's anchor PHRASE occurs twice (a mid-line
    # cross-reference), and the ADR gets sibling numbered items naming one residual each, so
    # the region-scoping itself is exercised even where masking is not realistic today.
    fixture() {
        rm -rf "$tmp/t"; mkdir -p "$tmp/t/docs/prometheus" "$tmp/t/docs/user-manual" \
            "$tmp/t/docs/ops-runbooks" "$tmp/t/server/core/src" "$tmp/t/changelog.d"

        cat > "$tmp/t/$ALERTS" <<'YML'
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
      - alert: YuzuMcpBridgePinReleaseFailed
        expr: |
          yuzu_mcp_bridge_pin_release_failed_total > 0
        labels:
          severity: warning
        annotations:
          description: >-
            a release attempt threw and was contained; the other residual is
            yuzu_mcp_bridge_pin_release_raced_total.
YML

        cat > "$tmp/t/$HELP" <<'CPP'
metrics_.describe("yuzu_mcp_bridge_pin_release_raced_total",
                  "sibling registration, not the claim",
                  "counter");
metrics_.describe("yuzu_mcp_bridge_pin_release_failed_total",
                  "sibling registration, not the claim",
                  "counter");
metrics_.describe("yuzu_mcp_stream_pin_displaced_total",
                  "Rule THOSE TWO out: yuzu_mcp_bridge_pin_release_raced_total and "
                  "yuzu_mcp_bridge_pin_release_failed_total.",
                  "counter");
metrics_.counter("yuzu_mcp_bridge_pin_release_failed_total");
metrics_.counter("yuzu_mcp_bridge_pin_release_raced_total");
CPP

        cat > "$tmp/t/$MANUAL" <<'MD'
| `yuzu_mcp_bridge_pin_release_raced_total` | counter | the release lost a race. |
| `yuzu_mcp_bridge_pin_release_failed_total` | counter | the release threw. |
| `yuzu_mcp_stream_pin_displaced_total` | counter | Rule out yuzu_mcp_bridge_pin_release_raced_total and yuzu_mcp_bridge_pin_release_failed_total before treating this as drift. |
MD

        cat > "$tmp/t/$RUNBOOK" <<'MD'
Intro prose.

   | counter | what it means | explains how much? |
   |---|---|---|
   | `yuzu_mcp_bridge_pin_release_raced_total` | the release lost a race | at most one slot |
   | `yuzu_mcp_bridge_pin_release_failed_total` | the release threw | one slot |
   | `yuzu_mcp_bridge_pin_displaced_for_admission_total` | a successful reclaim | zero |

Trailing prose repeats yuzu_mcp_bridge_pin_release_raced_total for narrative reasons.
MD

        cat > "$tmp/t/$HOME_HDR" <<'HPP'
    /// ### What a FULL PIN-SLOT SET means
    ///
    /// Only two paths cause a displacement: yuzu_mcp_bridge_pin_release_raced_total and
    /// yuzu_mcp_bridge_pin_release_failed_total.
    std::uint64_t publish_final(std::string_view event_type, std::string_view data) noexcept;
HPP

        cat > "$tmp/t/$MCP_SERVER_DOC" <<'MD'
Some other text.

**A pin released to admit a new call.** Explains yuzu_mcp_bridge_pin_release_raced_total
and yuzu_mcp_bridge_pin_release_failed_total as the two causes.

A cross-reference table row mentions "A pin released to admit a new call" again mid-line,
which must not count as a second anchor.
MD

        cat > "$tmp/t/$ADR_DOC" <<'MD'
14. **Earlier decision** unrelated, mentions yuzu_mcp_bridge_pin_release_raced_total in passing for context.
15. **MCP Streamable HTTP transport** reclaims (yuzu_mcp_bridge_pin_release_raced_total, #2795) and (yuzu_mcp_bridge_pin_release_failed_total, #2805).
16. **Later decision** mentions yuzu_mcp_bridge_pin_release_failed_total in passing for context.
MD

        : > "$tmp/t/changelog.d/x.md"
        assert_realistic_fixture
    }

    # The guard that guards the guard (#2827's root cause was fixtures that could not
    # exercise masking at all): fail the whole selftest run hard, not just one case, if a
    # future edit collapses fixture() back to one occurrence per file.
    assert_realistic_fixture() {
        local path count
        for path in "$ALERTS" "$MANUAL" "$ADR_DOC"; do
            count=$(grep -c -- "$RACED" "$tmp/t/$path" || true)
            [ "${count:-0}" -ge 2 ] || { printf 'FIXTURE BUG: %s has only %s raced occurrence(s), need >=2 to exercise masking\n' "$path" "${count:-0}" >&2; exit 2; }
            count=$(grep -c -- "$FAILED" "$tmp/t/$path" || true)
            [ "${count:-0}" -ge 2 ] || { printf 'FIXTURE BUG: %s has only %s failed occurrence(s), need >=2 to exercise masking\n' "$path" "${count:-0}" >&2; exit 2; }
        done
        count=$(grep -c -- "$RACED" "$tmp/t/$HELP" || true)
        [ "${count:-0}" -ge 3 ] || { printf 'FIXTURE BUG: server.cpp has only %s raced occurrence(s), need >=3\n' "${count:-0}" >&2; exit 2; }
        count=$(grep -c -- "$FAILED" "$tmp/t/$HELP" || true)
        [ "${count:-0}" -ge 3 ] || { printf 'FIXTURE BUG: server.cpp has only %s failed occurrence(s), need >=3\n' "${count:-0}" >&2; exit 2; }
        count=$(grep -c -- "$RACED" "$tmp/t/$RUNBOOK" || true)
        [ "${count:-0}" -ge 2 ] || { printf 'FIXTURE BUG: runbook has only %s raced occurrence(s), need >=2\n' "${count:-0}" >&2; exit 2; }
        count=$(grep -c -- "A pin released to admit a new call" "$tmp/t/$MCP_SERVER_DOC" || true)
        [ "${count:-0}" -ge 2 ] || { printf 'FIXTURE BUG: mcp-server.md anchor phrase occurs only %s time(s), need >=2\n' "${count:-0}" >&2; exit 2; }
    }

    # expect(): $1 = case name, $2 = expected exit (0 clean / 1 drift), $3 = optional
    # substring that MUST appear in the gate's output. Without $3 a case can pass for the
    # wrong reason (#2827 finding: several pre-region cases mutated a whole file, which
    # under region-scoping trips anchor-missing rather than the "one residual" arm their
    # name claims) - the token makes that a hard failure instead of a silent pass.
    expect() {
        local out rc
        if out="$("$self" "$tmp/t" 2>&1)"; then rc=0; else rc=$?; fi
        if [ "$rc" = "$2" ]; then
            if [ -n "${3:-}" ] && ! printf '%s' "$out" | grep -qF -- "$3"; then
                failed=$((failed+1))
                printf '  FAIL  %s (exit %s matched, but output missing expected substring: %s)\n' "$1" "$2" "$3"
                printf '        output was:\n%s\n' "$out" | sed 's/^/        /'
            else
                pass=$((pass+1)); printf '  ok    %s\n' "$1"
            fi
        else
            failed=$((failed+1)); printf '  FAIL  %s (expected exit %s, got %s)\n' "$1" "$2" "$rc"
            printf '        output was:\n%s\n' "$out" | sed 's/^/        /'
        fi
    }

    fixture; expect "baseline consistent fixture is clean" 0

    # --- check (a): reclaim counter must not appear in the alert expr ---
    fixture
    perl -pi -e 's{increase\(yuzu_mcp_stream_pin_displaced_total\[15m\]\) > 0}{(increase(yuzu_mcp_stream_pin_displaced_total[15m]) - increase(yuzu_mcp_bridge_pin_displaced_for_admission_total[15m])) > 0}' \
        "$tmp/t/$ALERTS"
    expect "netted expr subtracting the reclaim counter" 1 "expr references"

    # --- check (b): MASK cases - stale ONLY the claim region, siblings stay intact. This
    # is the #2827 class; MASK-ALERTS below is its literal repro. ---
    fixture
    perl -0777 -pi -e 's/causes are yuzu_mcp_bridge_pin_release_raced_total and\n            yuzu_mcp_bridge_pin_release_failed_total\./causes are yuzu_mcp_bridge_pin_release_failed_total only - the raced case cannot happen here./' \
        "$tmp/t/$ALERTS"
    expect "MASK-ALERTS: claim region loses raced, sibling rule keeps both (#2827 repro)" 1 "names one residual"

    fixture
    perl -0777 -pi -e 's/Rule THOSE TWO out: yuzu_mcp_bridge_pin_release_raced_total and "\n\s*"yuzu_mcp_bridge_pin_release_failed_total\./Rule it out: yuzu_mcp_bridge_pin_release_failed_total only./' \
        "$tmp/t/$HELP"
    expect "MASK-HELP: HELP claim loses raced, registration+pre-seed keep both" 1 "names one residual"

    fixture
    perl -pi -e 's/Rule out yuzu_mcp_bridge_pin_release_raced_total and //' \
        "$tmp/t/$MANUAL"
    expect "MASK-MANUAL: displaced row loses raced, its own row keeps it" 1 "names one residual"

    fixture
    perl -pi -e 's/^   \| `yuzu_mcp_bridge_pin_release_raced_total`.*\n//m' \
        "$tmp/t/$RUNBOOK"
    expect "MASK-RUNBOOK: raced table row deleted, prose sibling keeps it" 1 "names one residual"

    fixture
    perl -0777 -pi -e 's/Only two paths cause a displacement: yuzu_mcp_bridge_pin_release_raced_total and\n    \/\/\/ yuzu_mcp_bridge_pin_release_failed_total\./Only one path is modelled here: yuzu_mcp_bridge_pin_release_failed_total./' \
        "$tmp/t/$HOME_HDR"
    expect "MASK-HPP: derivation block loses raced" 1 "names one residual"

    fixture
    perl -0777 -pi -e 's/Explains yuzu_mcp_bridge_pin_release_raced_total\nand yuzu_mcp_bridge_pin_release_failed_total as the two causes\./Explains yuzu_mcp_bridge_pin_release_failed_total as the cause./' \
        "$tmp/t/$MCP_SERVER_DOC"
    expect "MASK-MCP-SERVER: claim paragraph loses raced, cross-ref phrase intact" 1 "names one residual"

    fixture
    perl -pi -e 's/reclaims \(yuzu_mcp_bridge_pin_release_raced_total, #2795\) and //' \
        "$tmp/t/$ADR_DOC"
    expect "MASK-ADR: Decision-15 loses raced, sibling item 14 keeps it" 1 "names one residual"

    # --- Gate 4 regression: the exact shape governance review reproduced against this PR.
    # A sibling decision item in an alternate numbering format ("16)" instead of "16.")
    # must NOT be absorbed into decision 15's region - if it were, its incidental mention
    # of the missing residual would mask decision 15's own stale claim, exactly as the
    # unhardened stop pattern let happen before this fix.
    fixture
    printf '%s\n' \
        '14. **Earlier decision** unrelated.' \
        '15. **MCP Streamable HTTP transport** the release throw is counted as `yuzu_mcp_bridge_pin_release_failed_total` (#2805, the raced case cannot happen here).' \
        '16) *Later decision, alternate numbering format* mentions yuzu_mcp_bridge_pin_release_raced_total in passing for unrelated context.' \
        '17. **Final decision** wraps up.' \
        > "$tmp/t/$ADR_DOC"
    expect "ADR: alternate-format sibling item (16)) is not absorbed into decision 15's region" 1 "names one residual"

    # --- Gate 4 regression: MCP_SERVER_DOC's bold-lead stop (added alongside the ADR fix)
    # must catch a paragraph that runs directly into the next bold-lead paragraph with no
    # blank-line separator - the same masking shape, one surface over.
    fixture
    printf '%s\n' \
        '**A pin released to admit a new call.** Explains yuzu_mcp_bridge_pin_release_failed_total' \
        'as the cause; the raced case cannot happen here.' \
        '**Terminal durability.** Unrelated paragraph mentioning yuzu_mcp_bridge_pin_release_raced_total' \
        'in passing, immediately following with no blank-line separator.' \
        > "$tmp/t/$MCP_SERVER_DOC"
    expect "MCP_SERVER_DOC: next bold-lead paragraph is not absorbed when the blank line is missing" 1 "names one residual"

    # --- Gate 4 regression: MAX_REGION_LINES fires when a terminator truly never matches -
    # not merely a reformatted-but-recognizable sibling (the two cases above), but a
    # genuinely broken/absent boundary that would otherwise run to EOF.
    fixture
    { printf '15. **MCP Streamable HTTP transport** yuzu_mcp_bridge_pin_release_raced_total and yuzu_mcp_bridge_pin_release_failed_total.\n'
      for i in $(seq 1 260); do printf 'plain prose line %d, no numbering, no heading, never a stop pattern.\n' "$i"; done
    } > "$tmp/t/$ADR_DOC"
    expect "REGION-OVERRUN: ADR terminator never matches, exceeds MAX_REGION_LINES" 1 "exceeded"

    # --- check (b): region names neither residual ---
    fixture
    perl -0777 -pi -e 's/   \| `yuzu_mcp_bridge_pin_release_raced_total`.*\n   \| `yuzu_mcp_bridge_pin_release_failed_total`.*\n//' \
        "$tmp/t/$RUNBOOK"
    expect "RUNBOOK region names neither residual (rows removed, header+reclaim row remain)" 1 "names neither"

    # --- check (b): anchor-loss, one per surface ---
    fixture; perl -pi -e 's/alert: YuzuMcpStreamPinDisplaced/alert: YuzuMcpStreamPinDisplacedRenamed/' "$tmp/t/$ALERTS"
    expect "ANCHOR-LOSS alerts.yml (alert renamed)" 1 "anchor not found"

    fixture; perl -pi -e 's/metrics_\.describe\("yuzu_mcp_stream_pin_displaced_total",/metrics_.describe("yuzu_mcp_stream_pin_displaced_total_v2",/' "$tmp/t/$HELP"
    expect "ANCHOR-LOSS server.cpp (describe() name reworded)" 1 "anchor not found"

    fixture; perl -pi -e 's/\| `yuzu_mcp_stream_pin_displaced_total` \|/| `yuzu_mcp_stream_pin_displaced_total_v2` |/' "$tmp/t/$MANUAL"
    expect "ANCHOR-LOSS metrics.md (row lead reworded)" 1 "anchor not found"

    fixture; perl -pi -e 's/\| counter \| what it means \|/| metric | what it means |/' "$tmp/t/$RUNBOOK"
    expect "ANCHOR-LOSS runbook (table header reworded)" 1 "anchor not found"

    fixture; perl -pi -e 's{/// ### What a FULL PIN-SLOT SET means}{/// What a FULL PIN-SLOT SET means}' "$tmp/t/$HOME_HDR"
    expect "ANCHOR-LOSS mcp_stream.hpp (### dropped from heading)" 1 "anchor not found"

    fixture; perl -pi -e 's/\*\*A pin released to admit a new call\./**A pin release admits a new call./' "$tmp/t/$MCP_SERVER_DOC"
    expect "ANCHOR-LOSS mcp-server.md (claim lead reworded)" 1 "anchor not found"

    fixture; perl -pi -e 's/^15\. \*\*MCP Streamable HTTP transport/17. **MCP Streamable HTTP transport/' "$tmp/t/$ADR_DOC"
    expect "ANCHOR-LOSS ADR (item renumbered)" 1 "anchor not found"

    # --- check (b): anchor-ambiguous ---
    fixture
    printf '\n      - alert: YuzuMcpStreamPinDisplaced\n        expr: |\n          0 > 0\n' >> "$tmp/t/$ALERTS"
    expect "ANCHOR-AMBIGUOUS alerts.yml (duplicate alert name)" 1 "ambiguous"

    fixture
    printf '| `yuzu_mcp_stream_pin_displaced_total` | counter | duplicate row |\n' >> "$tmp/t/$MANUAL"
    expect "ANCHOR-AMBIGUOUS metrics.md (duplicate row)" 1 "ambiguous"

    # --- check (b): terminator-missing ---
    fixture
    perl -pi -e 's/"counter"\);/"counter" );/' "$tmp/t/$HELP"
    expect "TERMINATOR-LOSS server.cpp (closing counter\\); line altered)" 1 "terminator"

    # --- check (b): no-extractor (a surface registered without a claim_region() arm) ---
    fixture
    cp "$self" "$tmp/no-extractor-gate.sh"
    perl -pi -e 's{("\$MCP_SERVER_DOC"\s*\n)}{$1}; ' "$tmp/no-extractor-gate.sh" >/dev/null # no-op, keep for clarity
    perl -pi -e 's/(STATING_SURFACES=\(\n)/$1    "docs\/unregistered-surface.md"\n/' "$tmp/no-extractor-gate.sh"
    printf 'yuzu_mcp_bridge_pin_release_raced_total yuzu_mcp_bridge_pin_release_failed_total\n' > "$tmp/t/docs/unregistered-surface.md"
    if out="$(bash "$tmp/no-extractor-gate.sh" "$tmp/t" 2>&1)"; then rc=0; else rc=1; fi
    if [ "$rc" = 1 ] && printf '%s' "$out" | grep -qF "no claim_region() extractor"; then
        pass=$((pass+1)); printf '  ok    %s\n' "NO-EXTRACTOR (surface registered with no claim_region() arm)"
    else
        failed=$((failed+1)); printf '  FAIL  %s (exit=%s)\n' "NO-EXTRACTOR (surface registered with no claim_region() arm)" "$rc"
        printf '        output was:\n%s\n' "$out" | sed 's/^/        /'
    fi

    # --- check (c): banned phrasing (kept from prior versions, now can live in-region) ---
    fixture
    printf '%s\n' 'Rule all three out against their counters.' >> "$tmp/t/$HELP"
    expect '"rule all three out" in the /metrics HELP' 1 "rule out three causes"

    fixture
    printf '%s\n' 'Rule all three out against their counters.' >> "$tmp/t/$HOME_HDR"
    expect "DERIVATION HEADER says to rule all three out" 1 "rule out three causes"

    fixture
    printf '%s\n' 'The shipped rule, which subtracts the explained paths.' >> "$tmp/t/$MCP_SERVER_DOC"
    expect "docs/mcp-server.md describes a netted rule" 1 "netted alert expression"

    # --- changelog.d: weaker both-or-neither rule ---
    fixture
    printf '%s\n' 'Alert via the shipped rule, which subtracts the explained paths.' \
        >> "$tmp/t/changelog.d/x.md"
    expect "changelog describing a netted rule" 1 "netted alert expression"

    fixture
    printf '%s\n' 'yuzu_mcp_stream_pin_displaced_total is explained by yuzu_mcp_bridge_pin_release_failed_total.' \
        > "$tmp/t/changelog.d/x.md"
    expect "CHANGELOG fragment names one residual without the other" 1 "names one residual"

    # --- check (d): unregistered-claim-restatement tripwire ---
    fixture
    printf '\nA new paragraph says yuzu_mcp_stream_pin_displaced_total is explained by yuzu_mcp_bridge_pin_release_raced_total alone.\n' \
        >> "$tmp/t/$MANUAL"
    expect "TRIPWIRE: displacement + one residual co-occur on an unregistered line" 1 "unregistered claim restatement"

    # --- CRLF robustness ---
    fixture
    perl -pi -e 's/\n/\r\n/' "$tmp/t/$ALERTS"
    expect "CRLF baseline stays clean" 0

    fixture
    perl -0777 -pi -e 's/causes are yuzu_mcp_bridge_pin_release_raced_total and\n            yuzu_mcp_bridge_pin_release_failed_total\./causes are yuzu_mcp_bridge_pin_release_failed_total only - the raced case cannot happen here./' \
        "$tmp/t/$ALERTS"
    perl -pi -e 's/\n/\r\n/' "$tmp/t/$ALERTS"
    expect "CRLF + MASK-ALERTS still catches the mask" 1 "names one residual"

    printf '\nselftest: %s passed, %s failed\n' "$pass" "$failed"
    [ "$failed" -eq 0 ] || exit 1
    exit 0
fi

ROOT="${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}"
cd "$ROOT"

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
# (b) Every surface's CLAIM REGION must name BOTH residual counters.
#
# Region-scoped, not whole-file (#2827): a counter identifier occurring elsewhere in the
# file - a metrics registration, a pre-seed, a sibling alert rule, a sibling table row -
# must not be able to satisfy this check on behalf of a stale claim. claim_region() extracts
# the bounded text that actually states the cause set; a registered surface with no
# extractor, whose anchor cannot be found or is ambiguous, whose terminator is lost, or
# whose region grows past MAX_REGION_LINES without ever finding its stop pattern (a sibling
# item reformatted so the multi-line scan never terminates - the same absorption shape as
# the original whole-file bug, reachable again through a broken terminator instead of a
# missing region), is reported as DRIFT rather than silently skipped or trusted past EOF.
# ---------------------------------------------------------------------------
for f in "${STATING_SURFACES[@]}"; do
    [ -f "$f" ] || { bad "missing surface: $f"; continue; }
    if ! region="$(claim_region "$f")"; then
        case "$region" in
            "ERR anchor-missing")
                bad "$f: claim-region anchor not found (surface restructured? update claim_region() in this script)."
                ;;
            "ERR anchor-ambiguous")
                bad "$f: claim-region anchor matches more than once (ambiguous) - narrow it in claim_region()."
                ;;
            "ERR terminator-missing")
                bad "$f: claim region has no terminator (surface reformatted? update claim_region())."
                ;;
            "ERR region-overrun")
                bad "$f: claim region exceeded $MAX_REGION_LINES lines without finding its stop pattern - a sibling item was likely reformatted and the extractor absorbed unrelated content. Update claim_region()."
                ;;
            *)
                bad "$f: registered stating surface has no claim_region() extractor - add one."
                ;;
        esac
        continue
    fi
    has_raced=0; has_failed=0
    [[ "$region" == *"$RACED"* ]] && has_raced=1
    [[ "$region" == *"$FAILED"* ]] && has_failed=1
    if [ "$has_raced" -ne "$has_failed" ]; then
        bad "$f names one residual counter but not the other in its claim region (raced=$has_raced failed=$has_failed)."
        note "Both are causes of a displacement; naming one implies the other has no signal,"
        note "which is exactly the defect $RACED was added to end."
    elif [ "$has_raced" -eq 0 ]; then
        bad "$f's claim region names neither residual counter."
        note "Either restate the cause set here, or remove it from STATING_SURFACES."
    fi
done

# changelog.d fragments get the weaker BOTH-OR-NEITHER rule, deliberately, and stay
# whole-file: a fragment is a small, self-contained bullet, not a surface where an unrelated
# sibling occurrence could plausibly mask a stale claim. A fragment may legitimately describe
# the fix without enumerating counter names at all - customer release notes are not a
# rule-out procedure - but naming ONE residual while omitting the other is the
# "#2795 is deliberately silent" shape that shipped once already, and that must fail.
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
# ("rule all three out") without pretending to understand prose. Stays whole-file - broader
# than the claim region can only over-trigger, never mask.
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

# ---------------------------------------------------------------------------
# (d) Unregistered-claim-restatement tripwire (#2827 follow-up, best-effort).
#
# (b) only checks surfaces already in STATING_SURFACES, in the region claim_region() already
# knows about. This catches a narrower but different gap: a NEW paraphrase appearing
# somewhere on a registered surface but outside any known region - naming the displacement
# counter and exactly one residual counter on the same physical line. It cannot see a claim
# split across lines or one that names no counters at all; it can only over-trigger (a real
# hit still needs a human to register or fix it), never mask, so it is safe to keep narrow.
# ---------------------------------------------------------------------------
for f in "${STATING_SURFACES[@]}"; do
    [ -f "$f" ] || continue
    hit="$(awk -v disp="$DISPLACED" -v raced="$RACED" -v failed="$FAILED" '
        {
            line = $0; sub(/\r$/, "", line)
            d = (index(line, disp) > 0)
            r = (index(line, raced) > 0)
            h = (index(line, failed) > 0)
            if (d && (r + h == 1)) { print NR; exit }
        }
    ' "$f")"
    if [ -n "$hit" ]; then
        bad "$f:$hit names the displacement counter and exactly one residual counter on the same line."
        note "This looks like an unregistered claim restatement. If it is inside the"
        note "surface's registered claim region, claim_region() is mis-scoped - fix the"
        note "extractor. If it is a NEW paraphrase, register it or state both/neither."
    fi
done

if [ "$fail" -ne 0 ]; then
    printf '\n%s\n' "The cause set is: $RACED, $FAILED."
    printf '%s\n' "$RECLAIM is NOT a cause. Derivation: $HOME_HDR."
    exit 1
fi

printf 'pin-displacement claim set: consistent across %s surfaces (+ changelog.d):\n' "${#STATING_SURFACES[@]}"
printf '  %s\n' "${STATING_SURFACES[@]}"
