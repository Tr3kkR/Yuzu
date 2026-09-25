#!/usr/bin/env bash
# test_log_handoff_wiring_lexical.sh -- #4666 PR-2 W3a static lexical gate over
# agents/core/src/main.cpp's log-handoff wiring call sites.
#
# Four textual invariants, each guarding a real hazard agent_log_wiring.hpp's / \
# log_handoff.hpp's own header banners describe:
#
#   1. `LogHandoffEpilogue log_epilogue` appears BEFORE `auto agent = make_agent(` --
#      C++ destroys stack/member locals in REVERSE declaration order
#      (agent_log_wiring.hpp's own declaration-order contract), so the epilogue must be
#      declared before anything (the Agent object) that might still be logging when its
#      destructor runs -- otherwise the epilogue's teardown() call races a live logger.
#   2. `install_log_handoff_in_this_image(` is actually called -- main.cpp must wire the
#      handoff into ITS OWN image's registry (log_handoff.hpp's MULTI-IMAGE note), not
#      just construct a LogHandoff and never install it.
#   3. main.cpp never calls `spdlog::set_default_logger(` directly -- that would bypass
#      agent_log_wiring.hpp's R-LOGGER-safe wrapper (which drops its own install()-
#      returned shared_ptr before returning) and risks a second owning reference to the
#      logger/sinks surviving past LogHandoff::teardown()'s bounded watchdog.
#   4. main.cpp never calls `->teardown(` directly -- LogHandoffEpilogue's destructor
#      (release_log_handoff_from_this_image) already calls LogHandoff::teardown(); a
#      second, hand-written call site would double-teardown or race the epilogue's own.
#
# Static/text-only, no build required -- a lexical gate, not a semantic one (mirrors
# scripts/ci/check-plugin-spawn-lexical.sh's tier-(a) role: fast, no-build, catches an
# obvious textual regression; it cannot see a relocation that keeps the same tokens but
# changes the surrounding control flow -- that is a review-enforced concern, same
# limitation that script's own header documents for its domain).
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || { cd "$(dirname "$0")/../.." && pwd; })"
MAIN_CPP="$ROOT/agents/core/src/main.cpp"

if [ ! -f "$MAIN_CPP" ]; then
  echo "::error::test_log_handoff_wiring_lexical: $MAIN_CPP not found" >&2
  exit 1
fi

fail=0

epilogue_line="$(grep -n 'LogHandoffEpilogue log_epilogue' "$MAIN_CPP" | head -1 | cut -d: -f1 || true)"
make_agent_line="$(grep -n 'auto agent = make_agent(' "$MAIN_CPP" | head -1 | cut -d: -f1 || true)"

if [ -z "$epilogue_line" ]; then
  echo "::error::test_log_handoff_wiring_lexical: 'LogHandoffEpilogue log_epilogue' not found in main.cpp" >&2
  fail=1
fi
if [ -z "$make_agent_line" ]; then
  echo "::error::test_log_handoff_wiring_lexical: 'auto agent = make_agent(' not found in main.cpp" >&2
  fail=1
fi
if [ -n "$epilogue_line" ] && [ -n "$make_agent_line" ] && [ "$epilogue_line" -ge "$make_agent_line" ]; then
  echo "::error::test_log_handoff_wiring_lexical: LogHandoffEpilogue (line $epilogue_line) must be declared BEFORE 'auto agent = make_agent(' (line $make_agent_line) -- reverse-declaration-order destruction requires this ordering" >&2
  fail=1
fi

if ! grep -q 'install_log_handoff_in_this_image(' "$MAIN_CPP"; then
  echo "::error::test_log_handoff_wiring_lexical: main.cpp never calls install_log_handoff_in_this_image(" >&2
  fail=1
fi

if grep -q 'spdlog::set_default_logger(' "$MAIN_CPP"; then
  echo "::error::test_log_handoff_wiring_lexical: main.cpp calls spdlog::set_default_logger( directly -- route through agent_log_wiring.hpp's install_log_handoff_in_this_image() instead (R-LOGGER)" >&2
  fail=1
fi

if grep -q -- '->teardown(' "$MAIN_CPP"; then
  echo "::error::test_log_handoff_wiring_lexical: main.cpp calls ->teardown( directly -- LogHandoffEpilogue's destructor already calls LogHandoff::teardown(); a second call site double-tears-down or races the epilogue's own call" >&2
  fail=1
fi

if [ "$fail" -ne 0 ]; then
  exit 1
fi

echo "test_log_handoff_wiring_lexical: OK -- main.cpp's log-handoff wiring invariants hold (epilogue line $epilogue_line < make_agent line $make_agent_line; install_log_handoff_in_this_image( present; no direct spdlog::set_default_logger(/->teardown( call)"
