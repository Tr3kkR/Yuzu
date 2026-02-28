catch2_dep = dependency('catch2-with-main', required: true)

test_exe = executable(
  'yuzu_tests',
  files('unit/test_plugin_loader.cpp'),
  dependencies: [yuzu_agent_core_dep, yuzu_sdk_dep, catch2_dep],
)

test('unit tests', test_exe)
