# CompilerFlags.cmake — sets sensible warnings and hardening flags

include_guard(GLOBAL)

function(yuzu_set_compiler_flags target)
  if(MSVC)
    target_compile_options(${target} PRIVATE
      /W4          # High warning level
      /WX-         # Warnings not errors (change to /WX for CI)
      /permissive- # Strict conformance
      /Zc:__cplusplus
      /utf-8
      /wd4100      # unreferenced formal parameter (common in plugin boilerplate)
      /wd4251      # dll-interface warnings
    )
  else()
    target_compile_options(${target} PRIVATE
      -Wall
      -Wextra
      -Wpedantic
      -Wno-unused-parameter
      -fvisibility=hidden
      $<$<CXX_COMPILER_ID:Clang>:-Wno-gnu-zero-variadic-macro-arguments>
    )
  endif()

  # Sanitizers
  if(YUZU_ENABLE_ASAN AND NOT MSVC)
    target_compile_options(${target} PRIVATE -fsanitize=address,undefined)
    target_link_options(${target} PRIVATE -fsanitize=address,undefined)
  endif()
  if(YUZU_ENABLE_TSAN AND NOT MSVC)
    target_compile_options(${target} PRIVATE -fsanitize=thread)
    target_link_options(${target} PRIVATE -fsanitize=thread)
  endif()

  # LTO
  if(YUZU_ENABLE_LTO)
    set_property(TARGET ${target} PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)
  endif()
endfunction()
