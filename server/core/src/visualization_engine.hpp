#pragma once

/// @file visualization_engine.hpp
/// Server-side data transformation for instruction-response charts (issue #253,
/// Phase 8.1).
///
/// An InstructionDefinition may carry a `spec.visualization` block that
/// declares how the response set should be rendered as a chart. The engine
/// reads the spec, walks the StoredResponse rows, runs the chosen processor
/// to build a labels/series shape, and returns a self-contained JSON payload
/// the dashboard's JS renderer (yuzu-charts.js) can draw without a second
/// request.
///
/// The engine is deliberately small and dependency-free beyond what the rest
/// of the server already pulls in: nlohmann::json for parsing the spec,
/// result_parsing.hpp for the pipe-delimited row split, the JObj/JArr
/// builders are local to rest_api_v1.cpp so the engine emits its JSON via
/// std::format / direct string building.
///
/// Wire shape:
///   ChartSpec         (input, parsed from the visualization_spec column)
///     ├── type        "pie" | "bar" | "column" | "line" | "area"
///     ├── processor   "single_series" | "multi_series" | "datetime_series"
///     ├── title       optional display title
///     ├── label_field column index (0-based, EXCLUDING the "Agent" column)
///     ├── value_field optional column index — null/-1 = count rows
///     ├── series_field for multi_series, the column that splits series
///     ├── x_field     for datetime_series — column index OR "agent_timestamp"
///     ├── y_field     for datetime_series — numeric column
///     └── max_categories optional cap (top-N + "Other")
///
///   ChartData         (output)
///     {chart_type, title, labels|x, series:[{name,data}], meta:{...}}

#include "response_store.hpp"

#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server {

class VisualizationEngine {
public:
    struct Result {
        bool ok{false};
        /// JSON string. On success, the chart data shape; on failure, an
        /// error envelope with `{"error": "..."}`. The route handler picks
        /// the HTTP status from `ok`.
        std::string json;
    };

    /// Render the responses for the visualization at `index` (0-based).
    /// Returns ok=false when:
    ///   * spec_json is empty / "{}"             (no visualization configured)
    ///   * spec_json fails to parse              (invalid JSON)
    ///   * processor name is unknown
    ///   * required spec fields are missing
    ///   * index is out of range
    ///
    /// `plugin` selects the column schema (see result_parsing.hpp) used to
    /// split each StoredResponse.output into fields.
    [[nodiscard]] Result transform_at(std::string_view spec_json, int index,
                                       const std::string& plugin,
                                       const std::vector<StoredResponse>& responses) const;

    /// Convenience: render the chart at index 0. Equivalent to
    /// `transform_at(spec, 0, plugin, responses)`. Kept for the common
    /// single-chart case and to preserve the original API surface.
    [[nodiscard]] Result transform(std::string_view spec_json,
                                   const std::string& plugin,
                                   const std::vector<StoredResponse>& responses) const;

    /// Lightweight predicate for callers that just want to know whether a
    /// definition has a visualization configured (so the dashboard can skip
    /// rendering an empty card and the REST endpoint can early-404). True
    /// when the spec is either a single chart object with `type+processor`
    /// or an array containing at least one such object.
    [[nodiscard]] static bool has_visualization(std::string_view spec_json);

    /// Count the configured charts. Returns 0 when no visualization is
    /// configured, 1 for a singular-object spec, and N for an array.
    /// Issue #587 — supports operators declaring multiple charts on a
    /// single definition (e.g. pie + time-series side by side).
    [[nodiscard]] static int count(std::string_view spec_json);
};

} // namespace yuzu::server
