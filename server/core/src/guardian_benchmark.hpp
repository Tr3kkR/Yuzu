#pragma once

#include "guardian_routes.hpp"
#include <expected>
#include <nlohmann/json.hpp>
#include <string>

namespace yuzu::server {
class BaselineStore;
class HttpRouteSink;
struct BenchmarkError { int status; std::string message; };

// Decision records are authoring documentation, never executable Guard specs.
std::expected<nlohmann::json, BenchmarkError>
read_benchmark(BaselineStore&, const std::string& baseline_id);
std::expected<nlohmann::json, BenchmarkError>
import_benchmark(BaselineStore&, const std::string& baseline_id,
                 const nlohmann::json& body, const std::string& author);
std::expected<nlohmann::json, BenchmarkError>
update_benchmark_decision(BaselineStore&, const std::string& baseline_id,
                          const std::string& control_id, const nlohmann::json& body,
                          const std::string& author);
std::string benchmark_export_html(const nlohmann::json& document);
std::string benchmark_export_markdown(const nlohmann::json& document);
void register_guardian_benchmark_routes(HttpRouteSink&, GuardianRoutes::AuthFn,
    GuardianRoutes::PermFn, GuardianRoutes::AuditFn, BaselineStore*);
} // namespace yuzu::server
