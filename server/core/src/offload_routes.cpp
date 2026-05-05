#include "offload_routes.hpp"

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <stdexcept>

namespace yuzu::server {

namespace {

constexpr std::string_view kErrUnavailable =
    R"({"error":{"code":503,"message":"offload store unavailable"},"meta":{"api_version":"v1"}})";
constexpr std::string_view kErrInvalidJson =
    R"({"error":{"code":400,"message":"invalid JSON"},"meta":{"api_version":"v1"}})";
constexpr std::string_view kErrNotFound =
    R"({"error":{"code":404,"message":"offload target not found"},"meta":{"api_version":"v1"}})";

nlohmann::json target_to_json(const OffloadTarget& t) {
    return nlohmann::json{
        {"id", t.id},
        {"name", t.name},
        {"url", t.url},
        {"auth_type", offload_auth_type_to_string(t.auth_type)},
        {"event_types", t.event_types},
        {"batch_size", t.batch_size},
        {"enabled", t.enabled},
        {"created_at", t.created_at},
        // auth_credential intentionally omitted from API responses
    };
}

void send_unavailable(httplib::Response& res) {
    res.status = 503;
    res.set_content(std::string(kErrUnavailable), "application/json");
}

void send_bad_json(httplib::Response& res) {
    res.status = 400;
    res.set_content(std::string(kErrInvalidJson), "application/json");
}

void send_not_found(httplib::Response& res) {
    res.status = 404;
    res.set_content(std::string(kErrNotFound), "application/json");
}

/// Parse a numeric path segment to int64. The route regex `(\d+)` makes
/// `std::invalid_argument` impossible, but `std::stoll` still throws
/// `std::out_of_range` on values that overflow int64 (e.g. a 21-digit
/// id). We treat overflow as 404 — the id can't possibly correspond to
/// a real row — and avoid letting httplib turn the throw into a 500.
[[nodiscard]] std::optional<int64_t> parse_id_segment(const std::string& s) {
    try {
        return std::stoll(s);
    } catch (const std::out_of_range&) {
        return std::nullopt;
    } catch (const std::invalid_argument&) {
        return std::nullopt;
    }
}

void mount(HttpRouteSink& sink, OffloadRoutes::PermFn perm_fn, OffloadRoutes::AuditFn audit_fn,
           OffloadTargetStore* offload_store) {
    // GET /api/v1/offload-targets — list
    sink.Get("/api/v1/offload-targets",
             [perm_fn, offload_store](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn(req, res, "Infrastructure", "Read"))
                     return;
                 if (!offload_store || !offload_store->is_open()) {
                     send_unavailable(res);
                     return;
                 }
                 auto targets = offload_store->list();
                 nlohmann::json arr = nlohmann::json::array();
                 for (const auto& t : targets)
                     arr.push_back(target_to_json(t));
                 res.set_content(nlohmann::json({{"offload_targets", arr}}).dump(),
                                 "application/json");
             });

    // POST /api/v1/offload-targets — create
    sink.Post("/api/v1/offload-targets",
              [perm_fn, audit_fn, offload_store](const httplib::Request& req,
                                                 httplib::Response& res) {
                  if (!perm_fn(req, res, "Infrastructure", "Write"))
                      return;
                  if (!offload_store || !offload_store->is_open()) {
                      send_unavailable(res);
                      return;
                  }
                  nlohmann::json body;
                  try {
                      body = nlohmann::json::parse(req.body);
                  } catch (...) {
                      send_bad_json(res);
                      return;
                  }
                  auto name = body.value("name", std::string{});
                  auto url = body.value("url", std::string{});
                  if (name.empty() || url.empty()) {
                      res.status = 400;
                      res.set_content(
                          R"({"error":{"code":400,"message":"name and url are required"},"meta":{"api_version":"v1"}})",
                          "application/json");
                      return;
                  }
                  auto auth_type_str = body.value("auth_type", std::string{"none"});
                  auto auth_type = offload_auth_type_from_string(auth_type_str);
                  auto auth_credential = body.value("auth_credential", std::string{});
                  auto event_types = body.value("event_types", std::string{"*"});
                  auto batch_size = body.value("batch_size", 1);
                  auto enabled = body.value("enabled", true);

                  auto id = offload_store->create_target(name, url, auth_type, auth_credential,
                                                        event_types, batch_size, enabled);
                  if (id < 0) {
                      audit_fn(req, "offload_target.create", "denied", "offload_target", name,
                               "validation_failed");
                      res.status = 400;
                      res.set_content(
                          R"json({"error":{"code":400,"message":"target rejected: invalid url, name, batch_size, or duplicate name"},"meta":{"api_version":"v1"}})json",
                          "application/json");
                      return;
                  }
                  audit_fn(req, "offload_target.create", "success", "offload_target",
                           std::to_string(id), name);
                  res.status = 201;
                  res.set_content(
                      nlohmann::json({{"id", id}, {"status", "created"}}).dump(),
                      "application/json");
              });

    // GET /api/v1/offload-targets/:id — get one
    sink.Get(R"(/api/v1/offload-targets/(\d+))",
             [perm_fn, offload_store](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn(req, res, "Infrastructure", "Read"))
                     return;
                 if (!offload_store || !offload_store->is_open()) {
                     send_unavailable(res);
                     return;
                 }
                 auto id_opt = parse_id_segment(req.matches[1].str());
                 if (!id_opt) {
                     send_not_found(res);
                     return;
                 }
                 auto t = offload_store->get(*id_opt);
                 if (!t) {
                     send_not_found(res);
                     return;
                 }
                 res.set_content(target_to_json(*t).dump(), "application/json");
             });

    // DELETE /api/v1/offload-targets/:id — delete
    sink.Delete(R"(/api/v1/offload-targets/(\d+))",
                [perm_fn, audit_fn, offload_store](const httplib::Request& req,
                                                   httplib::Response& res) {
                    if (!perm_fn(req, res, "Infrastructure", "Write"))
                        return;
                    if (!offload_store || !offload_store->is_open()) {
                        send_unavailable(res);
                        return;
                    }
                    auto id_opt = parse_id_segment(req.matches[1].str());
                    if (!id_opt) {
                        audit_fn(req, "offload_target.delete", "denied", "offload_target",
                                 req.matches[1].str(), "not_found");
                        send_not_found(res);
                        return;
                    }
                    // Snapshot the URL + name BEFORE delete so the audit row
                    // captures it. After delete the row is gone and a brief
                    // compromise-and-cleanup attacker would erase the only
                    // record of which URL the data was exfiltrated to
                    // (compliance F-3 from Gate 6).
                    auto target_snapshot = offload_store->get(*id_opt);
                    std::string detail;
                    if (target_snapshot) {
                        detail =
                            "name=" + target_snapshot->name + " url=" + target_snapshot->url;
                    }
                    if (offload_store->delete_target(*id_opt)) {
                        audit_fn(req, "offload_target.delete", "success", "offload_target",
                                 std::to_string(*id_opt), detail);
                        res.set_content(R"({"status":"deleted"})", "application/json");
                    } else {
                        audit_fn(req, "offload_target.delete", "denied", "offload_target",
                                 std::to_string(*id_opt), "not_found");
                        send_not_found(res);
                    }
                });

    // GET /api/v1/offload-targets/:id/deliveries — delivery history
    sink.Get(R"(/api/v1/offload-targets/(\d+)/deliveries)",
             [perm_fn, offload_store](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn(req, res, "Infrastructure", "Read"))
                     return;
                 if (!offload_store || !offload_store->is_open()) {
                     send_unavailable(res);
                     return;
                 }
                 auto id_opt = parse_id_segment(req.matches[1].str());
                 if (!id_opt) {
                     send_not_found(res);
                     return;
                 }
                 // Match sibling GET /:id semantics (HP-2): a missing target
                 // returns 404 rather than `{"deliveries":[]}` + 200, so an
                 // operator polling for a deleted target sees the explicit
                 // 404 instead of confusing empty-success.
                 if (!offload_store->get(*id_opt)) {
                     send_not_found(res);
                     return;
                 }
                 // Cap limit to a sane maximum so an operator can't request a
                 // billion-row vector allocation. Default 50, max 1000 — the
                 // sibling executions/audit endpoints converged on this
                 // ceiling.
                 int limit = 50;
                 auto limit_str = req.get_param_value("limit");
                 if (!limit_str.empty()) {
                     try { limit = std::stoi(limit_str); } catch (...) {}
                 }
                 limit = std::clamp(limit, 1, 1000);
                 auto deliveries = offload_store->get_deliveries(*id_opt, limit);
                 nlohmann::json arr = nlohmann::json::array();
                 for (const auto& d : deliveries) {
                     arr.push_back({{"id", d.id},
                                    {"target_id", d.target_id},
                                    {"event_type", d.event_type},
                                    {"event_count", d.event_count},
                                    {"payload", d.payload},
                                    {"status_code", d.status_code},
                                    {"delivered_at", d.delivered_at},
                                    {"error", d.error}});
                 }
                 res.set_content(nlohmann::json({{"deliveries", arr}}).dump(),
                                 "application/json");
             });
}

} // namespace

void OffloadRoutes::register_routes(httplib::Server& svr, AuthFn /*auth_fn*/, PermFn perm_fn,
                                    AuditFn audit_fn, OffloadTargetStore* offload_store) {
    HttplibRouteSink sink(svr);
    mount(sink, std::move(perm_fn), std::move(audit_fn), offload_store);
}

void OffloadRoutes::register_routes(HttpRouteSink& sink, AuthFn /*auth_fn*/, PermFn perm_fn,
                                    AuditFn audit_fn, OffloadTargetStore* offload_store) {
    mount(sink, std::move(perm_fn), std::move(audit_fn), offload_store);
}

} // namespace yuzu::server
