#pragma once

// Internal header shared by rest_api_v1 domain files.
// Declares JSON envelope helpers and CORS utilities.

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <cstdint>
#include <string>

namespace yuzu::server {

// JSON envelope helpers
nlohmann::json ok_response(const nlohmann::json& data);
nlohmann::json error_response(const std::string& message, int code = 0);
nlohmann::json list_response(const nlohmann::json& data, int64_t total,
                             int64_t start = 0, int64_t page_size = 50);

// CORS helper — adds CORS headers to a response for /api/v1/* routes.
void add_cors_headers(httplib::Response& res, const httplib::Request& req);

} // namespace yuzu::server
