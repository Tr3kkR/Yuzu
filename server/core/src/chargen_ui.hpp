// Chargen web UI HTML string.
// The definition lives in chargen_ui.cpp — a separate TU to work around
// an MSVC bug where long raw string literals with braces confuse brace
// matching in the surrounding translation unit.
#pragma once

namespace yuzu::server::detail {
extern const char* const kIndexHtml;
}  // namespace yuzu::server::detail
