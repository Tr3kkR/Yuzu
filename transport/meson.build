# yuzu::transport:: abstraction (#376 PR 1+).
#
# This subdir owns the transport interface header at
# `include/yuzu/transport/transport.hpp`. Implementation TUs live under
# `src/grpc/` (PR 1) and `src/msquic/` (PR 3); for now (PR 0+1 design)
# only the headers exist.
#
# When PR 1 lands, this file declares a static library `yuzu_transport`
# linking grpc_transport.cpp; PR 3 adds msquic_transport.cpp behind a
# build option. For the design-only commit the dependency is
# header-only.

yuzu_transport_inc = include_directories('include')

# Header-only dependency for PR 0+1. PR 1 hardening adds
# `link_with: yuzu_transport_lib` once an implementation exists.
yuzu_transport_dep = declare_dependency(
  include_directories: yuzu_transport_inc,
  dependencies: [yuzu_proto_headers_dep],
)
