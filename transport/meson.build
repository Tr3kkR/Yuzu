# yuzu::transport:: abstraction (#376).
#
# Public interface header at `include/yuzu/transport/transport.hpp` plus
# the ProtoMessage<T> adapter and the shared `detail/` helpers
# (sanitise.hpp, method_name.hpp). Backend implementations live under
# `src/grpc/` and `src/msquic/`; which one(s) compile into the static lib
# is driven by the `transport` meson option (grpc | msquic | both).
#
# `src/transport_factory.cpp` (the public make_channel / make_server_listener
# factories) and `src/transport_static_assert.cpp` (the wire-stable
# StatusCode<->proto pin) are backend-agnostic and always compiled. The
# factory dispatches to whichever backends are linked, keyed on the
# YUZU_TRANSPORT_HAVE_{GRPC,MSQUIC} defines this file sets from the option.
#
# PR 3 (this state): msquic backend present as a skeleton under src/msquic/
# — construction + lifecycle compile and link; RPC paths return
# StatusCode::Unimplemented. Increments 1-8 land the real implementation.

yuzu_transport_inc = include_directories('include')

transport_opt = get_option('transport')

# Always-compiled, backend-agnostic sources.
#
# msquic_framing.cpp is the QUIC length-prefix codec. It is named for and
# used only by the msquic backend, but has zero dependency on the msquic C
# library — so it is compiled unconditionally, which keeps its unit tests
# runnable on every `transport` configuration (including grpc-only).
yuzu_transport_srcs = [
  'src/transport_factory.cpp',
  'src/transport_static_assert.cpp',
  'src/msquic/msquic_framing.cpp',
]
yuzu_transport_backend_deps = []
# Compile defines: which backends are linked in. Propagated to consumers
# via declare_dependency(compile_args:) so test code can #ifdef on the
# selected backend(s) without touching the frozen public header.
yuzu_transport_defines = []

if transport_opt == 'grpc' or transport_opt == 'both'
  yuzu_transport_srcs += [
    'src/grpc/grpc_channel.cpp',
    'src/grpc/grpc_listener.cpp',
    'src/grpc/grpc_transport.cpp',
  ]
  yuzu_transport_backend_deps += [grpcpp_dep]
  yuzu_transport_defines += ['-DYUZU_TRANSPORT_HAVE_GRPC']
endif

if transport_opt == 'msquic' or transport_opt == 'both'
  # msquic's vcpkg port is ONLY_DYNAMIC_LIBRARY — yuzu_transport links it
  # as a shared lib; the runtime artefact set must ship libmsquic
  # alongside the binaries (see ADR-0001 / #376 PR 3 plan, risk 1).
  #
  # method: 'cmake' is pinned explicitly — the msquic port exports only a
  # CMake config (find_package(msquic CONFIG)), and pinning avoids
  # meson's pkg-config-then-cmake auto-probe ambiguity. This is the
  # safer choice on Windows MSVC, where meson's cmake-dep translator has
  # bitten the gRPC/protobuf/abseil deps before (the root meson.build
  # option-D hand-wire block). The msquic build is still UNVALIDATED on
  # Windows — tracked as governance build-S1.
  msquic_dep = dependency('msquic', method: 'cmake', include_type: 'system')
  yuzu_transport_srcs += [
    'src/msquic/msquic_internal_helpers.cpp',
    'src/msquic/msquic_bidi_stream.cpp',
    'src/msquic/msquic_channel.cpp',
    'src/msquic/msquic_listener.cpp',
    'src/msquic/msquic_transport.cpp',
  ]
  yuzu_transport_backend_deps += [msquic_dep]
  yuzu_transport_defines += ['-DYUZU_TRANSPORT_HAVE_MSQUIC']
  # Windows: format_quic_addr in msquic_listener.cpp calls inet_ntop and
  # make_quic_addr in msquic_internal_helpers.cpp calls inet_pton. Both
  # resolve from ws2_32.dll. msquic's CMake config exports a transitive
  # link to ws2_32 but pinning belt-and-braces eliminates one Windows-
  # build failure mode (xp-SHOULD-2).
  if host_machine.system() == 'windows'
    cxx = meson.get_compiler('cpp')
    yuzu_transport_backend_deps += [cxx.find_library('ws2_32', required: true)]
  endif
endif

# YUZU_TRANSPORT_TESTING gates the msquic debug:: back-pressure probes
# (cpp-SHOULD-3 / qe-SHOULD-2 / UP-9). Compile the library WITH the
# probes when tests are enabled so the test exe can link them; OMIT
# them in production builds so the symbols are not exported (a buggy
# plugin in the same process cannot dlsym
# bidi_set_backpressure_thresholds(0,0) to disable back-pressure).
if get_option('build_tests')
  yuzu_transport_defines += ['-DYUZU_TRANSPORT_TESTING']
endif

yuzu_transport_common_deps = [
  protobuf_dep, spdlog_dep, yuzu_proto_headers_dep, yuzu_sdk_dep,
]

yuzu_transport_lib = static_library(
  'yuzu_transport',
  yuzu_transport_srcs,
  cpp_args: yuzu_transport_defines,
  include_directories: yuzu_transport_inc,
  dependencies: yuzu_transport_common_deps + yuzu_transport_backend_deps,
)

yuzu_transport_dep = declare_dependency(
  link_with: yuzu_transport_lib,
  compile_args: yuzu_transport_defines,
  include_directories: yuzu_transport_inc,
  dependencies: yuzu_transport_common_deps + yuzu_transport_backend_deps,
)
