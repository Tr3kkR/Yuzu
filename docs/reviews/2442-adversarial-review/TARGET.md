# Adversarial review target

The brief handed to both reviewers, verbatim, followed by the severity anchors. Preserved
unedited: it is the input the two reviews were produced against, so a later reader can see
what they were and were not asked to look at.

## Brief

```
TARGET: branch fix/2442-consume-side-origin-guard, range origin/dev..HEAD (25 commits).
  head        = 4b83f70be1a6ded48629f339f4c6065fd1fcca1d
  merge-base  = b061cd7475f383b5eef946b9833bd0fed2d0b76a
  diff        = git diff b061cd7475f383b5eef946b9833bd0fed2d0b76a..4b83f70be1a6ded48629f339f4c6065fd1fcca1d

REPO IS CHECKED OUT AT /home/dgr/yuzu-2442-consume-guard AND IS ALREADY BUILT.
This is a DYNAMIC review. A configured, warm build dir is at build-linux. Compile and
run the targeted suites there:
    source scripts/ensure-erlang.sh      # needed, or the gateway target fails at exit 127
    meson compile -C build-linux
    ./build-linux/tests/yuzu_server_tests "[security]"
    ./build-linux/tests/yuzu_server_tests "[approval]"
    ./build-linux/tests/yuzu_server_tests "[mcp]"
You may write inside this worktree if a test or experiment needs it; revert what you
change. Do NOT touch /home/dgr/Yuzu (a different branch).

WHAT THE CHANGE DOES
#2442 is a cross-surface approval-forgery hole. ApprovalManager is one store with three
mint paths (MCP, REST instruction gate, scheduler). The MCP recall matched a ticket on
(definition_id, scope_expression) only, binding neither the submitter nor the minting
surface, so a ticket approved on one surface could be redeemed on another. The branch
records an origin at submit() and enforces it at consume_ticket():
declares_non_mcp_surface() returns false for kMcp/kUnspecified and true for
kInstruction/kSchedule/kUnrecognised. kUnspecified is DELIBERATELY exempt - pre-v5 rows
and every ticket the MCP gate mints today. Two Prometheus counters and two [security]
tests were added, plus operator documentation.

WHERE TO AIM, AND WHY
This branch has had fourteen passes of self-run internal governance. Roughly twenty
blocking findings across the last two rounds were ALL in prose or in the governance
record, and NONE in the code. The last round ended with a reset: the run ledger was
reverted and the documentation cut back.

That history should make you suspicious in a specific direction. The CODE has been
repeatedly declared sound by the same process that kept shipping false claims about it,
and that process's own verification twice certified defects it should have caught (a
merge script that shared the misreading it was checking for; a conformance check that
passed because the defect had emptied the set it counted). So:

  * Attack the SECURITY CODE hardest. The origin guard, the kUnspecified exemption, the
    dedup path in find_pending, consume_ticket's CAS, the mint sites, and whether any
    reachable caller can store a non-MCP mint as kUnspecified.
  * Attack the TESTS. Two [security]-tagged tests are claimed to be mutation-proven.
    Verify that by mutating the source yourself and confirming they go red.
  * Do not take the documentation's account of the code as evidence about the code.
  * The upgrade/downgrade story is load-bearing: origin/dev carries the origin column
    and both non-MCP mints pass it, but has NO consume-side guard and NO counters.

Verdict lines must be real: VERDICT ... BLOCK or VERDICT ... PASS.

NOTE ADDED ON RE-RUN (2026-08-04): the first Kimi phase-1 run was discarded. The peer
reviewer, running dynamically in this same worktree, applied a source mutation to
`declares_non_mcp_surface` (making kInstruction return false, i.e. disabling the guard
for REST-minted tickets), reported in its own review that it had reverted the mutation
and that `git status --short` was clean, and had done neither. The tree has now been
restored (`git checkout -- server/core/src/approval_manager.hpp`), rebuilt, and
re-verified green. If you mutate source to test the suites, revert it yourself and
CHECK `git status` afterwards rather than reporting the revert as done.
```

## Severity anchors

```
Grade severity against these, in this order:
  1. /home/dgr/yuzu-2442-consume-guard/CLAUDE.md  (standing rules; severity is DERIVED
     from IMPACT x EXPOSURE, and BLOCKING = derived CRITICAL or HIGH)
  2. /home/dgr/yuzu-2442-consume-guard/.claude/routed-concerns.md - in particular the
     rows for: MCP server architecture; Authentication/RBAC/engine principals; the
     ADR-1005 headless-platform row and its clause "One core-owned approval primitive -
     no new approval gate outside it"; Prometheus metrics / audit envelope / event format
  3. docs/mcp-server.md
  4. docs/auth-architecture.md
  5. docs/observability-conventions.md
  6. docs/cpp-conventions.md  (C++23 conventions, ownership and lifetime)
  7. docs/adr/1005-headless-platform-use-case-engines.md
A finding that cites one of these is a CONTRACT finding and outranks a judgment call.
```
