#pragma once

// Test-only accessors for the internal MCP dispatch/classification tables.
//
// These expose copies of translation-unit-private tables defined in
// mcp_server.cpp (kToolSecurity / kToolAnnotation / kWriteTools) so the
// annotation cross-check test — a separate TU — can assert the served hints
// without duplicating the maps. Relocated out of mcp_server.hpp (issue #2385)
// so the production header carries no test-only surface. Definitions live in
// mcp_server.cpp; only the unit test includes this header.

#include <string_view>
#include <vector>

namespace yuzu::server::mcp {

// The (tool, securable, operation) dispatch rows from the internal kToolSecurity
// map, so the annotation cross-check test can assert readOnlyHint/destructiveHint
// against the dispatch class without duplicating the map.
struct ToolSecurityRow {
    std::string_view name;
    std::string_view securable;
    std::string_view operation;
};
std::vector<ToolSecurityRow> tool_security_rows_for_test();

// The names explicitly classified in the internal kToolAnnotation table, so the
// cross-check test can prove every tool is classified rather than relying on the
// generator's safe fallback.
std::vector<std::string_view> tool_annotation_names_for_test();

// The --mcp-read-only guard's write-tool set, so the cross-check test can bind it
// to the non-Read dispatch class (a mutating tool missing from kWriteTools would
// silently execute under read-only mode).
std::vector<std::string_view> write_tool_names_for_test();

} // namespace yuzu::server::mcp
