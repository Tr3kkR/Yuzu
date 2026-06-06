#pragma once

#include "result_set_store.hpp"

#include <string>
#include <vector>

namespace yuzu::server {

// Full HTML page shell for the /result-sets dashboard surface (scope walking,
// capability §30). Defined as a raw string literal in result_sets_ui.cpp to
// keep the long literal out of server.cpp's brace matching.
extern const char* const kResultSetsPageHtml;

// Render the operator's result-set sidebar list as an HTML partial. `selected`
// highlights the active set (may be empty). Pure rendering — the caller fetches
// the rows from ResultSetStore; this function does no I/O.
std::string render_result_sets_sidebar(const std::vector<ResultSet>& sets,
                                       const std::string& selected_id);

// Render the detail pane for one result set: lineage breadcrumb, status,
// counts, and pin/unpin/delete actions. `chain` is the lineage root→leaf.
std::string render_result_set_detail(const ResultSet& rs, const std::vector<LineageNode>& chain);

// Empty-state markup for the detail pane (nothing selected / set deleted).
std::string render_result_set_detail_empty();

} // namespace yuzu::server
