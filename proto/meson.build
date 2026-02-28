protoc = find_program('protoc', required: true)
grpc_cpp_plugin = find_program('grpc_cpp_plugin', required: true)

proto_src_dir = meson.current_source_dir()
proto_out_dir = meson.current_build_dir() / 'generated'
fs = import('fs')

proto_files = files(
  'yuzu/common/v1/common.proto',
  'yuzu/agent/v1/agent.proto',
  'yuzu/server/v1/management.proto',
)

gen_srcs = []
gen_hdrs = []

foreach pf : proto_files
  pf_str = pf.full_path()
  name   = fs.stem(pf_str)

  gen = custom_target(
    name + '_proto',
    input:   pf,
    output:  [name + '.pb.cc', name + '.pb.h', name + '.grpc.pb.cc', name + '.grpc.pb.h'],
    command: [
      protoc,
      '--cpp_out=' + proto_out_dir,
      '--grpc_out=' + proto_out_dir,
      '--plugin=protoc-gen-grpc=' + grpc_cpp_plugin.full_path(),
      '-I', proto_src_dir,
      '@INPUT@',
    ],
    build_by_default: true,
  )

  gen_srcs += [gen[0], gen[2]]
  gen_hdrs += [gen[1], gen[3]]
endforeach

yuzu_proto_lib = static_library(
  'yuzu_proto',
  gen_srcs,
  include_directories: include_directories(proto_out_dir),
  dependencies: [grpc_dep, protobuf_dep],
)

yuzu_proto_dep = declare_dependency(
  link_with: yuzu_proto_lib,
  include_directories: include_directories(proto_out_dir),
  dependencies: [grpc_dep, protobuf_dep],
)
