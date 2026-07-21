#!/usr/bin/env bash
# with-test-slot.sh — run a command while holding one of N machine-wide "heavy
# test" slots, so at most N concurrent CI jobs execute their test phase at once.
#
# WHY (Windows/Wee Tam only): Wee Tam runs 4 CCD-pinned GitHub Actions runners on
# ONE physical box. CPU affinity partitions cores between runners, but NOT the
# shared DRAM bandwidth, the single disk, or the Windows Defender minifilter — so
# every heavy unit-test suite's wall time scales with how many Windows jobs run
# their test phase concurrently (measured server ~[pg]: c0 289s -> c4 603s, i.e.
# a guaranteed timeout at >=4). Linux (Big Tam) does NOT need this: fork()/VFS/
# page-cache/no-AV keep per-op cost low, so it scales flat. This gate caps
# concurrent *test phases* per box; the build stays 4-wide (unaffected).
# Full diagnosis: docs/ci-architecture.md + the tests/meson.build server-shard
# comment.
#
# CRASH-SAFE: a slot is an flock on a per-slot file, held via an open fd for the
# lifetime of THIS process. If the job is killed (120-min timeout / cancel-in-
# progress), the OS closes the fd and releases the lock — a dead job never leaks
# a slot. (This is why a counter/semaphore file would be wrong: it could not be
# decremented by a killed holder.) Verified on Wee Tam MSYS2 bash: flock -x
# serialises across the separate runner bash processes.
#
# Usage:  with-test-slot.sh <max_slots> -- <cmd> [args...]
# Env:    YUZU_TEST_SLOT_DIR      lock directory (default: $RUNNER_TOOL_CACHE/yuzu-test-slots or /d/ci/yuzu-test-slots)
#         YUZU_TEST_SLOT_NAME     slot base name (default: yuzu-weetam-heavy)
#         YUZU_TEST_SLOT_TIMEOUT_MIN  max wait for a slot (default: 115)
#         YUZU_TEST_SLOT_DISABLE=1    bypass the gate entirely (run the command directly)
#
# NOT set -e: flock -n failure is control flow, and the wrapped command's exit
# code must be captured and propagated, not aborted on.
set -uo pipefail

max="${1:?with-test-slot: <max_slots> required}"; shift
[[ "${1:-}" == "--" ]] && shift
[[ $# -ge 1 ]] || { echo "::error::with-test-slot: no command given (expected: <max_slots> -- cmd ...)"; exit 2; }

# Escape hatch: on non-Wee-Tam hosts (or to disable the gate) just run the command.
if [[ "${YUZU_TEST_SLOT_DISABLE:-0}" == "1" || "$max" -le 0 ]]; then
  echo "with-test-slot: gate disabled (YUZU_TEST_SLOT_DISABLE/max<=0) — running ungated"
  "$@"; exit $?
fi

name="${YUZU_TEST_SLOT_NAME:-yuzu-weetam-heavy}"
timeout_min="${YUZU_TEST_SLOT_TIMEOUT_MIN:-115}"

lockdir="${YUZU_TEST_SLOT_DIR:-}"
if [[ -z "$lockdir" ]]; then
  base="${RUNNER_TOOL_CACHE:-/d/ci}"
  command -v cygpath >/dev/null 2>&1 && base="$(cygpath -u "$base" 2>/dev/null || echo "$base")"
  lockdir="${base}/yuzu-test-slots"
fi
mkdir -p "$lockdir" 2>/dev/null || { echo "::error::with-test-slot: cannot create lock dir $lockdir"; exit 2; }

# Poll each slot non-blocking; hold the first free one on fd 200. Poll (not
# flock-blocking) because bash flock cannot wait-on-any-of-N.
start=$(date +%s)
deadline=$(( start + timeout_min * 60 ))
slot=""
while :; do
  for (( i = 1; i <= max; i++ )); do
    exec 200>"$lockdir/${name}-${i}.lock" || continue
    if flock -n 200; then slot="$i"; break; fi
    exec 200>&-   # not ours — drop the fd and try the next slot
  done
  [[ -n "$slot" ]] && break
  if (( $(date +%s) > deadline )); then
    echo "::error::with-test-slot: no '${name}' slot free after ${timeout_min} min (${max} slots busy)"
    exit 1
  fi
  echo "with-test-slot: all ${max} slots busy, waiting... ($(( $(date +%s) - start ))s)"
  sleep 5
done

echo "with-test-slot: acquired '${name}' slot ${slot}/${max} after $(( $(date +%s) - start ))s"

# Run the command with the lock fd CLOSED in the child (200>&-), so THIS process
# is the sole lock holder. fd 200 stays open here for the command's whole
# duration (lock held), but the command and its descendants never inherit it —
# so a hard-kill / job-timeout / cancel of this process frees the slot
# immediately via OS fd-close, even if the wrapped command orphans a child.
# (Without 200>&-, a surviving orphaned test process holds the inherited lock and
# leaks the slot until it exits — verified failure mode on Wee Tam.)
"$@" 200>&-
rc=$?
echo "with-test-slot: command exited ${rc} (releasing slot ${slot})"
exit $rc
