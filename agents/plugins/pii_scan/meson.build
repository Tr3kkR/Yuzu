# pii_scan — sensitive-data (PII) discovery plugin.
#
# re2_dep is declared once at root meson.build scope (purely additive,
# right after the existing grpc/protobuf/CLI11 dependency block) since
# Meson's subdir() scoping doesn't propagate a subdir-local variable back
# out to sibling subdirs — both this plugin and tests/meson.build (which
# links pii_matcher.hpp directly into the shared agent test binary) need
# to see it. See that declaration's comment for the full rationale.
#
# embed_pii_rules.py below mirrors server/core/meson.build's
# bundled_content custom_target exactly (same PyYAML-required rationale,
# same MSVC 16380-byte string-literal chunking). Declared locally rather
# than reusing server/core's `embed_python` var because Meson subdir()
# scoping doesn't share locally-declared variables between sibling
# subdirs, and agents/plugins/* is processed before server/core in the
# root file regardless.

pii_embed_python = find_program('python3', 'python')
_pii_yaml_probe = run_command(pii_embed_python, '-c', 'import yaml', check: false)
if _pii_yaml_probe.returncode() != 0
  error(
    'PyYAML is required to embed the pii_scan ruleset but is not importable from '
    + pii_embed_python.full_path() + '. Install with `pip install pyyaml` (Linux/macOS) or '
    + '`pacman -S python-yaml` (MSYS2). See agents/plugins/pii_scan/scripts/embed_pii_rules.py.'
  )
endif

pii_rules_embed = custom_target(
  'bundled_pii_rules',
  output: 'bundled_pii_rules.cpp',
  command: [
    pii_embed_python,
    files('scripts/embed_pii_rules.py'),
    meson.project_source_root() / 'content' / 'pii-rules',
    '@OUTPUT@',
  ],
  build_always_stale: true,  # always re-scan content/pii-rules/ for edits
)

shared_library(
  'pii_scan',
  files('src/pii_scan_plugin.cpp'),
  pii_rules_embed,
  name_prefix: '',
  dependencies: [yuzu_sdk_dep, yuzu_agent_core_dep, nlohmann_dep, re2_dep],
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
