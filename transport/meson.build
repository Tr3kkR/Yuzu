# yuzu::transport:: abstraction (#376 PR 1+).
#
# Owns the transport interface header at
# `include/yuzu/transport/transport.hpp` plus the ProtoMessage<T>
# adapter at `include/yuzu/transport/proto_adapter.hpp`. The gRPC
# backend implementation lives under `src/grpc/`.
#
# PR 1a (this commit): static lib `yuzu_transport` linking the gRPC
# backend; lifecycle methods land on real grpc primitives, RPC
# dispatch is stubbed with StatusCode::Unimplemented placeholders.
#
# PR 1b: wire grpc::GenericStub (client) and grpc::AsyncGenericService
# (server) for actual RPC dispatch.
# PR 3: add msquic backend under src/msquic/, behind option toggle.

yuzu_transport_inc = include_directories('include')

yuzu_transport_grpc_srcs = [
  'src/grpc/grpc_channel.cpp',
  'src/grpc/grpc_listener.cpp',
  'src/grpc/grpc_transport.cpp',
]

yuzu_transport_lib = static_library(
  'yuzu_transport',
  yuzu_transport_grpc_srcs,
  include_directories: yuzu_transport_inc,
  dependencies: [grpcpp_dep, protobuf_dep, spdlog_dep, yuzu_proto_headers_dep, yuzu_sdk_dep],
)

yuzu_transport_dep = declare_dependency(
  link_with: yuzu_transport_lib,
  include_directories: yuzu_transport_inc,
  dependencies: [grpcpp_dep, protobuf_dep, spdlog_dep, yuzu_proto_headers_dep, yuzu_sdk_dep],
)
