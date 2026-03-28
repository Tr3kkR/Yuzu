#include "webhook_routes.hpp"

#include <nlohmann/json.hpp>

namespace yuzu::server {

void WebhookRoutes::register_routes(httplib::Server& svr, AuthFn auth_fn, PermFn perm_fn,
                                    AuditFn audit_fn, EmitEventFn emit_event_fn,
                                    WebhookStore* webhook_store) {
    // GET /api/webhooks — list all webhooks
    svr.Get("/api/webhooks",
            [perm_fn, webhook_store](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn(req, res, "Infrastructure", "Read"))
                    return;
                if (!webhook_store || !webhook_store->is_open()) {
                    res.status = 503;
                    res.set_content(
                        R"({"error":{"code":503,"message":"webhook store unavailable"},"meta":{"api_version":"v1"}})",
                        "application/json");
                    return;
                }
                auto webhooks = webhook_store->list();
                nlohmann::json arr = nlohmann::json::array();
                for (const auto& w : webhooks) {
                    arr.push_back({{"id", w.id},
                                   {"url", w.url},
                                   {"event_types", w.event_types},
                                   {"enabled", w.enabled},
                                   {"created_at", w.created_at}});
                    // Intentionally omit secret from list response
                }
                res.set_content(nlohmann::json({{"webhooks", arr}}).dump(),
                                "application/json");
            });

    // POST /api/webhooks — create a new webhook
    svr.Post("/api/webhooks",
             [perm_fn, audit_fn, emit_event_fn, webhook_store](const httplib::Request& req,
                                                                httplib::Response& res) {
                 if (!perm_fn(req, res, "Infrastructure", "Write"))
                     return;
                 if (!webhook_store || !webhook_store->is_open()) {
                     res.status = 503;
                     res.set_content(
                         R"({"error":{"code":503,"message":"webhook store unavailable"},"meta":{"api_version":"v1"}})",
                         "application/json");
                     return;
                 }
                 nlohmann::json body;
                 try {
                     body = nlohmann::json::parse(req.body);
                 } catch (...) {
                     res.status = 400;
                     res.set_content(
                         R"({"error":{"code":400,"message":"invalid JSON"},"meta":{"api_version":"v1"}})",
                         "application/json");
                     return;
                 }
                 auto url = body.value("url", "");
                 if (url.empty()) {
                     res.status = 400;
                     res.set_content(
                         R"({"error":{"code":400,"message":"url is required"},"meta":{"api_version":"v1"}})",
                         "application/json");
                     return;
                 }
                 auto event_types = body.value("event_types", "*");
                 auto secret = body.value("secret", "");
                 auto enabled = body.value("enabled", true);

                 auto id = webhook_store->create_webhook(url, event_types, secret, enabled);
                 audit_fn(req, "webhook.create", "success", "webhook",
                          std::to_string(id), "");
                 if (emit_event_fn)
                     emit_event_fn("webhook.created", req, {},
                                   {{"webhook_id", id}, {"url", url}});
                 res.set_content(
                     nlohmann::json({{"id", id}, {"status", "created"}}).dump(),
                     "application/json");
             });

    // DELETE /api/webhooks/:id — delete a webhook
    svr.Delete(R"(/api/webhooks/(\d+))",
               [perm_fn, audit_fn, webhook_store](const httplib::Request& req,
                                                   httplib::Response& res) {
                   if (!perm_fn(req, res, "Infrastructure", "Write"))
                       return;
                   if (!webhook_store) {
                       res.status = 503;
                       res.set_content(
                           R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})",
                           "application/json");
                       return;
                   }
                   auto id = std::stoll(req.matches[1].str());
                   if (webhook_store->delete_webhook(id)) {
                       audit_fn(req, "webhook.delete", "success", "webhook",
                                std::to_string(id), "");
                       res.set_content(R"({"status":"deleted"})", "application/json");
                   } else {
                       res.status = 404;
                       res.set_content(
                           R"({"error":{"code":404,"message":"webhook not found"},"meta":{"api_version":"v1"}})",
                           "application/json");
                   }
               });

    // GET /api/webhooks/:id/deliveries — get delivery history
    svr.Get(R"(/api/webhooks/(\d+)/deliveries)",
            [perm_fn, webhook_store](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn(req, res, "Infrastructure", "Read"))
                    return;
                if (!webhook_store) {
                    res.status = 503;
                    res.set_content(
                        R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})",
                        "application/json");
                    return;
                }
                auto webhook_id = std::stoll(req.matches[1].str());
                int limit = 50;
                auto limit_str = req.get_param_value("limit");
                if (!limit_str.empty()) {
                    try { limit = std::stoi(limit_str); } catch (...) {}
                }
                auto deliveries = webhook_store->get_deliveries(webhook_id, limit);
                nlohmann::json arr = nlohmann::json::array();
                for (const auto& d : deliveries) {
                    arr.push_back({{"id", d.id},
                                   {"webhook_id", d.webhook_id},
                                   {"event_type", d.event_type},
                                   {"payload", d.payload},
                                   {"status_code", d.status_code},
                                   {"delivered_at", d.delivered_at},
                                   {"error", d.error}});
                }
                res.set_content(nlohmann::json({{"deliveries", arr}}).dump(),
                                "application/json");
            });
}

} // namespace yuzu::server
