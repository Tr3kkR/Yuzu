if host_machine.system() == 'windows'
  adr31_crypto_dep = declare_dependency(
    include_directories: _vcpkg_inc_win,
    dependencies: [_libcrypto],
  )
else
  adr31_crypto_dep = dependency('openssl', required: true, include_type: 'system')
endif

yuzu_adr31_contracts_lib = static_library(
  'yuzu_adr31_contracts',
  files(
    'src/b2_use_case.cpp',
    'src/b3_platform.cpp',
    'src/b4_fact.cpp',
    'src/json_support.cpp',
    'src/rest_a4_support.cpp',
    'src/transport_auth_slot.cpp',
  ),
  include_directories: include_directories('include'),
  dependencies: [nlohmann_dep, adr31_crypto_dep, yuzu_sdk_dep],
  install: false,
)

yuzu_adr31_contracts_dep = declare_dependency(
  link_with: yuzu_adr31_contracts_lib,
  include_directories: include_directories('include'),
  dependencies: [nlohmann_dep, adr31_crypto_dep, yuzu_sdk_dep],
)
