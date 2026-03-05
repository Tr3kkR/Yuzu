# YuzuProto.cmake — helper to generate protobuf + gRPC sources from .proto files

include_guard(GLOBAL)

# yuzu_proto_library(
#   NAME     <target-name>
#   PROTOS   <file.proto> ...
# )
#
# Runs protoc + grpc_cpp_plugin for each .proto file and produces a static
# library of the generated sources.  Generated files are placed flat in
# ${CMAKE_BINARY_DIR}/generated/proto/ so that consumers can include them
# as  #include "<stem>.pb.h"  without subdirectory prefixes.
function(yuzu_proto_library)
  cmake_parse_arguments(ARG "" "NAME" "PROTOS" ${ARGN})

  find_program(PROTOC_EXE       protoc          REQUIRED)
  find_program(GRPC_CPP_PLUGIN  grpc_cpp_plugin REQUIRED)

  set(PROTO_IMPORT_DIR "${CMAKE_SOURCE_DIR}/proto")
  set(PROTO_OUT "${CMAKE_BINARY_DIR}/generated/proto")
  file(MAKE_DIRECTORY "${PROTO_OUT}")

  set(GENERATED_SRCS "")
  set(GENERATED_HDRS "")

  foreach(PROTO_FILE IN LISTS ARG_PROTOS)
    # Compute the relative path so we know where protoc will place output.
    # e.g. proto/yuzu/agent/v1/agent.proto → yuzu/agent/v1/agent
    file(RELATIVE_PATH PROTO_REL "${PROTO_IMPORT_DIR}" "${PROTO_FILE}")
    get_filename_component(PROTO_REL_DIR "${PROTO_REL}" DIRECTORY)
    get_filename_component(PROTO_NAME_WE "${PROTO_REL}" NAME_WE)

    # protoc writes into a subdirectory matching the proto file's relative
    # path (e.g. yuzu/common/v1/).  We copy the results flat into PROTO_OUT
    # so all generated headers live side-by-side.
    set(PROTOC_SUBDIR "${PROTO_OUT}/${PROTO_REL_DIR}")

    # Flat output paths — these are the canonical source/header locations.
    set(PB_H     "${PROTO_OUT}/${PROTO_NAME_WE}.pb.h")
    set(PB_CC    "${PROTO_OUT}/${PROTO_NAME_WE}.pb.cc")
    set(GRPC_H   "${PROTO_OUT}/${PROTO_NAME_WE}.grpc.pb.h")
    set(GRPC_CC  "${PROTO_OUT}/${PROTO_NAME_WE}.grpc.pb.cc")

    add_custom_command(
      OUTPUT  "${PB_H}" "${PB_CC}" "${GRPC_H}" "${GRPC_CC}"
      # 1) Run protoc — outputs land in the subdirectory tree.
      COMMAND "${PROTOC_EXE}"
        --cpp_out="${PROTO_OUT}"
        --grpc_out="${PROTO_OUT}"
        --plugin=protoc-gen-grpc="${GRPC_CPP_PLUGIN}"
        -I "${PROTO_IMPORT_DIR}"
        "${PROTO_FILE}"
      # 2) Copy the generated files flat into PROTO_OUT.
      COMMAND "${CMAKE_COMMAND}" -E copy_if_different
        "${PROTOC_SUBDIR}/${PROTO_NAME_WE}.pb.h"      "${PB_H}"
      COMMAND "${CMAKE_COMMAND}" -E copy_if_different
        "${PROTOC_SUBDIR}/${PROTO_NAME_WE}.pb.cc"     "${PB_CC}"
      COMMAND "${CMAKE_COMMAND}" -E copy_if_different
        "${PROTOC_SUBDIR}/${PROTO_NAME_WE}.grpc.pb.h" "${GRPC_H}"
      COMMAND "${CMAKE_COMMAND}" -E copy_if_different
        "${PROTOC_SUBDIR}/${PROTO_NAME_WE}.grpc.pb.cc" "${GRPC_CC}"
      DEPENDS "${PROTO_FILE}"
      VERBATIM
      COMMENT "Generating protobuf/gRPC for ${PROTO_NAME_WE}"
    )

    list(APPEND GENERATED_SRCS "${PB_CC}" "${GRPC_CC}")
    list(APPEND GENERATED_HDRS "${PB_H}"  "${GRPC_H}")
  endforeach()

  add_library(${ARG_NAME} STATIC ${GENERATED_SRCS} ${GENERATED_HDRS})
  target_include_directories(${ARG_NAME} PUBLIC "${PROTO_OUT}")
  target_link_libraries(${ARG_NAME} PUBLIC gRPC::grpc++)
endfunction()
