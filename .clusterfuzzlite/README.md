# ClusterFuzzLite — continuous fuzzing of Yuzu's untrusted-input parsers

`cflite-pr.yml` builds this directory's `Dockerfile` + `build.sh` on any PR
touching C++/proto/fuzz paths and fuzzes **what the PR changed** for a short
budget (code-change mode, ASan). Findings surface as the workflow's SARIF /
crash artifacts — file them as issues; don't fix them inside unrelated PRs.

## Current targets (tests/fuzz/)

| Target | Parses | Why it's fuzzed |
|---|---|---|
| `fuzz_preflight_parse` | pipe-delimited plugin output → pre-flight verdicts | agent/plugin-controlled bytes decide go/no-go |
| `fuzz_deployment_parse` | deployment config fields + content_dist output | operator strings + agent bytes gate the mutating deploy step |
| `fuzz_yaml_scan` | the in-tree YAML-subset scanner | only runtime consumer of `yaml_source`; authorization-load-bearing since #1215 |
| `fuzz_guardian_rule_spec` | Guardian rule bodies + `dangerous_enforce_*` chokepoints | network-supplied specs gate enforce-mode promotion |

Every target is deliberately **closure-light** (STL + nlohmann only) so this
container needs no meson/vcpkg. The same sources build two ways:

- `build.sh` (here) — direct `$CXX` compile against `$LIB_FUZZING_ENGINE`.
- `tests/fuzz/meson.build` — `-Dbuild_fuzzers=true` (clang only) for local
  work, plus a deterministic seed-replay smoke in the `fuzz` meson suite.

**Adding a harness = edit both files** (each has a keep-in-sync banner) and
drop 2-3 seeds in `tests/fuzz/corpus/<target>/`.

## Local loop (macOS: `brew install llvm`, Apple clang has no libFuzzer)

```bash
CC=/opt/homebrew/opt/llvm/bin/clang CXX=/opt/homebrew/opt/llvm/bin/clang++ \
  meson setup build-fuzz -Dbuild_fuzzers=true -Dcmake_prefix_path=$PWD/vcpkg_installed/<triplet>
meson compile -C build-fuzz fuzz_yaml_scan
build-fuzz/tests/fuzz/fuzz_yaml_scan -max_total_time=300 tests/fuzz/corpus/fuzz_yaml_scan
```

Don't commit libFuzzer-generated corpus entries — only hand-named seeds live
in `tests/fuzz/corpus/`.

## Deferred (tracked follow-up)

- `scope_engine.cpp` `yuzu::scope::parse()` and `cel_eval.cpp` — the two
  highest-value remaining parsers; both link RE2 (+abseil), which needs an
  instrumented from-source build in this container. Add via pinned clones in
  the Dockerfile once the harness set has soaked.
- Scheduled batch-fuzzing leg + corpus pruning, once targets stabilize.
- Dependabot watch on this Dockerfile's `base-builder` digest.
