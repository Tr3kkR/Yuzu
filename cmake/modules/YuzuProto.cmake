# YuzuProto.cmake — helper to generate protobuf + gRPC sources from .proto files

include_guard(GLOBAL)

# yuzu_proto_library(
#   NAME     <target-name>
#   PROTOS   <file.proto> ...
# )
function(yuzu_proto_library)
  cmake_parse_arguments(ARG "" "NAME" "PROTOS" ${ARGN})

  find_program(PROTOC_EXE       protoc        REQUIRED)
  find_program(GRPC_CPP_PLUGIN  grpc_cpp_plugin REQUIRED)

  set(PROTO_IMPORT_DIR "${CMAKE_SOURCE_DIR}/proto")
  set(PROTO_OUT "${CMAKE_BINARY_DIR}/generated/proto")
  file(MAKE_DIRECTORY "${PROTO_OUT}")

  set(GENERATED_SRCS "")
  set(GENERATED_HDRS "")

  foreach(PROTO_FILE IN LISTS ARG_PROTOS)
    # Compute the path relative to the import dir so output structure matches.
    # e.g. proto/yuzu/agent/v1/agent.proto → yuzu/agent/v1/agent
    file(RELATIVE_PATH PROTO_REL "${PROTO_IMPORT_DIR}" "${PROTO_FILE}")
    get_filename_component(PROTO_REL_DIR "${PROTO_REL}" DIRECTORY)
    get_filename_component(PROTO_NAME_WE "${PROTO_REL}" NAME_WE)

    set(OUT_DIR "${PROTO_OUT}/${PROTO_REL_DIR}")
    file(MAKE_DIRECTORY "${OUT_DIR}")

    set(PB_H     "${OUT_DIR}/${PROTO_NAME_WE}.pb.h")
    set(PB_CC    "${OUT_DIR}/${PROTO_NAME_WE}.pb.cc")
    set(GRPC_H   "${OUT_DIR}/${PROTO_NAME_WE}.grpc.pb.h")
    set(GRPC_CC  "${OUT_DIR}/${PROTO_NAME_WE}.grpc.pb.cc")

    add_custom_command(
      OUTPUT  "${PB_H}" "${PB_CC}" "${GRPC_H}" "${GRPC_CC}"
      COMMAND "${PROTOC_EXE}"
        --cpp_out="${PROTO_OUT}"
        --grpc_out="${PROTO_OUT}"
        --plugin=protoc-gen-grpc="${GRPC_CPP_PLUGIN}"
        -I "${PROTO_IMPORT_DIR}"
        "${PROTO_FILE}"
      DEPENDS "${PROTO_FILE}"
      COMMENT "Generating protobuf/gRPC for ${PROTO_FILE}"
    )

    list(APPEND GENERATED_SRCS "${PB_CC}" "${GRPC_CC}")
    list(APPEND GENERATED_HDRS "${PB_H}"  "${GRPC_H}")
  endforeach()

  add_library(${ARG_NAME} STATIC ${GENERATED_SRCS} ${GENERATED_HDRS})
  target_include_directories(${ARG_NAME} PUBLIC "${PROTO_OUT}")
  target_link_libraries(${ARG_NAME} PUBLIC gRPC::grpc++ protobuf::libprotobuf)
endfunction()
