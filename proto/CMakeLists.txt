include(${CMAKE_SOURCE_DIR}/cmake/modules/YuzuProto.cmake)

file(GLOB_RECURSE PROTO_FILES CONFIGURE_DEPENDS "*.proto")

yuzu_proto_library(
  NAME  yuzu_proto
  PROTOS ${PROTO_FILES}
)
