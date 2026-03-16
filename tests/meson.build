catch2_dep = dependency('Catch2', modules: ['Catch2::Catch2WithMain'], method: 'cmake', required: true)

test_exe = executable(
  'yuzu_tests',
  files('unit/test_plugin_loader.cpp', 'unit/test_temp_file.cpp'),
  dependencies: [yuzu_agent_core_dep, yuzu_sdk_dep, catch2_dep],
)

test('unit tests', test_exe)
