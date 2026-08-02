yuzu_adr31_contracts_lib = static_library(
  'yuzu_adr31_contracts',
  files('src/b3_platform.cpp'),
  include_directories: include_directories('include'),
  dependencies: [nlohmann_dep],
  install: false,
)

yuzu_adr31_contracts_dep = declare_dependency(
  link_with: yuzu_adr31_contracts_lib,
  include_directories: include_directories('include'),
  dependencies: [nlohmann_dep],
)
