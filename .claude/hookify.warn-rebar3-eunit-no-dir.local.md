---
name: warn-rebar3-eunit-no-dir
enabled: true
event: bash
action: warn
conditions:
  - field: command
    operator: regex_match
    pattern: rebar3\s+eunit
  - field: command
    operator: not_contains
    pattern: --dir
---

**[WARN] `rebar3 eunit` without `--dir` rejects every orphan test module (#337).**

rebar3 3.27 intersects discovered test modules against the `src/`-derived
`modules` list in `yuzu_gw.app` and fails with `Module X not found in project`
for every `*_tests`/`*_SUITE`/helper before running a single test.

Use one of:

    rebar3 eunit --dir apps/yuzu_gw/test
    bash scripts/run-tests.sh erlang-unit      # applies the flag for you

Note: `rebar3 eunit --module X` does NOT give test isolation -- it runs the full
`--dir` phase first in the same BEAM VM (CLAUDE.md, #336). For real isolation,
`rm -rf gateway/_build/test` between runs.
