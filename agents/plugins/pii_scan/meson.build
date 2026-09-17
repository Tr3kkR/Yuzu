# pii_scan — sensitive-data (PII) discovery plugin.
#
# re2_dep and pii_rules_embed (the embedded-ruleset custom_target) are
# both declared once at root meson.build scope, purely additive there —
# see the root meson.build's own comments on each for the full rationale
# (Meson subdir() scoping doesn't propagate a subdir-local variable back
# out to a sibling subdir; tests/meson.build needs pii_rules_embed too,
# for test_pii_ruleset_integrity.cpp).

shared_library(
  'pii_scan',
  files('src/pii_scan_plugin.cpp'),
  pii_rules_embed,
  name_prefix: '',
  dependencies: [yuzu_sdk_dep, yuzu_agent_core_dep, nlohmann_dep, re2_dep],
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
