set(VCPKG_TARGET_ARCHITECTURE x64)
set(VCPKG_CRT_LINKAGE dynamic)
set(VCPKG_LIBRARY_LINKAGE dynamic)

# Force abseil to static linkage to avoid LNK2005 duplicate symbols
# when linking grpc (static abseil baked in) + abseil_dll together.
if(PORT MATCHES "abseil")
    set(VCPKG_LIBRARY_LINKAGE static)
endif()
