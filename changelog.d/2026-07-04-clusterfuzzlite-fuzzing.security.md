- **Continuous fuzzing via ClusterFuzzLite.** Four libFuzzer harnesses now cover
  the closure-light untrusted-input parsers — pre-flight plugin-output parsing,
  deployment config/output parsing, the in-tree YAML-subset scanner (the
  authorization-load-bearing `yaml_source` reader), and Guardian rule-spec
  derivation including the `dangerous_enforce_*` chokepoints. PRs touching
  C++/proto paths get a short ASan code-change fuzz run (`cflite-pr.yml`);
  locally, `-Dbuild_fuzzers=true` (clang) builds the harnesses and
  `meson test --suite fuzz` replays the seed corpora deterministically.
