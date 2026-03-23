        // -- Deployment Jobs API (Issue 7.7) ------------------------------------

        // GET /api/deployment-jobs — list all deployment jobs
        web_server_->Get("/api/deployment-jobs",
                         [this](const httplib::Request& req, httplib::Response& res) {
                             if (!require_permission(req, res, "Infrastructure", "Read"))
                                 return;
                             if (!deployment_store_) {
                                 res.status = 503;
                                 res.set_content(R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})", "application/json");
                                 return;
                             }
                             auto jobs = deployment_store_->list_jobs();
                             nlohmann::json arr = nlohmann::json::array();
                             for (const auto& j : jobs) {
                                 arr.push_back({{"id", j.id},
                                                {"target_host", j.target_host},
                                                {"os", j.os},
                                                {"method", j.method},
                                                {"status", j.status},
                                                {"created_at", j.created_at},
                                                {"started_at", j.started_at},
                                                {"completed_at", j.completed_at},
                                                {"error", j.error}});
                             }
                             res.set_content(nlohmann::json({{"jobs", arr}}).dump(),
                                             "application/json");
                         });

        // POST /api/deployment-jobs — create a new deployment job
        web_server_->Post("/api/deployment-jobs",
                          [this](const httplib::Request& req, httplib::Response& res) {
                              if (!require_permission(req, res, "Infrastructure", "Write"))
                                  return;
                              if (!deployment_store_) {
                                  res.status = 503;
                                  res.set_content(R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})", "application/json");
                                  return;
                              }
                              auto body = nlohmann::json::parse(req.body, nullptr, false);
                              if (body.is_discarded()) {
                                  res.status = 400;
                                  res.set_content(R"({"error":"invalid JSON"})",
                                                  "application/json");
                                  return;
                              }
                              auto target = body.value("target_host", "");
                              auto os = body.value("os", "linux");
                              auto method = body.value("method", "manual");
                              auto result = deployment_store_->create_job(target, os, method);
                              if (!result) {
                                  res.status = 400;
                                  res.set_content(
                                      nlohmann::json({{"error", result.error()}}).dump(),
                                      "application/json");
                                  return;
                              }

                              // Generate install command for manual deployments
                              std::string install_cmd;
                              if (method == "manual") {
                                  if (os == "windows") {
                                      install_cmd = "powershell -Command \"Invoke-WebRequest "
                                                    "-Uri 'https://yuzu-server/install.ps1' "
                                                    "-OutFile install.ps1; .\\install.ps1\"";
                                  } else {
                                      install_cmd = "curl -sSL https://yuzu-server/install.sh | "
                                                    "sudo bash";
                                  }
                              }

                              auto session = require_auth(req, res);
                              if (session) {
                                  audit_log(req, "deployment.create", "success",
                                            "DeploymentJob", *result, target);
                              }

                              res.status = 201;
                              nlohmann::json resp = {{"id", *result}, {"status", "pending"}};
                              if (!install_cmd.empty())
                                  resp["install_command"] = install_cmd;
                              res.set_content(resp.dump(), "application/json");
                          });

        // GET /api/deployment-jobs/:id — get job status
        web_server_->Get(R"(/api/deployment-jobs/([a-f0-9]+))",
                         [this](const httplib::Request& req, httplib::Response& res) {
                             if (!require_permission(req, res, "Infrastructure", "Read"))
                                 return;
                             if (!deployment_store_) {
                                 res.status = 503;
                                 res.set_content(R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})", "application/json");
                                 return;
                             }
                             auto id = req.matches[1].str();
                             auto job = deployment_store_->get_job(id);
                             if (!job) {
                                 res.status = 404;
                                 res.set_content(R"({"error":"job not found"})",
                                                 "application/json");
                                 return;
                             }
                             res.set_content(
                                 nlohmann::json({{"id", job->id},
                                                 {"target_host", job->target_host},
                                                 {"os", job->os},
                                                 {"method", job->method},
                                                 {"status", job->status},
                                                 {"created_at", job->created_at},
                                                 {"started_at", job->started_at},
                                                 {"completed_at", job->completed_at},
                                                 {"error", job->error}})
                                     .dump(),
                                 "application/json");
                         });

        // DELETE /api/deployment-jobs/:id — cancel a pending/running job
        web_server_->Delete(R"(/api/deployment-jobs/([a-f0-9]+))",
                            [this](const httplib::Request& req, httplib::Response& res) {
                                if (!require_permission(req, res, "Infrastructure", "Write"))
                                    return;
                                if (!deployment_store_) {
                                    res.status = 503;
                                    res.set_content(R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})", "application/json");
                                    return;
                                }
                                auto id = req.matches[1].str();
                                auto result = deployment_store_->cancel_job(id);
                                if (!result) {
                                    res.status = 400;
                                    res.set_content(
                                        nlohmann::json({{"error", result.error()}}).dump(),
                                        "application/json");
                                    return;
                                }
                                audit_log(req, "deployment.cancel", "success",
                                          "DeploymentJob", id, "");
                                res.set_content(R"({"status":"cancelled"})",
                                                "application/json");
                            });

        // -- Discovery API (Issue 7.18) ------------------------------------------

        // POST /api/discovery/scan — store discovery scan results from agents
        web_server_->Post("/api/discovery/scan",
                          [this](const httplib::Request& req, httplib::Response& res) {
                              if (!require_permission(req, res, "Infrastructure", "Write"))
                                  return;
                              if (!discovery_store_) {
                                  res.status = 503;
                                  res.set_content(R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})", "application/json");
                                  return;
                              }
                              auto body = nlohmann::json::parse(req.body, nullptr, false);
                              if (body.is_discarded()) {
                                  res.status = 400;
                                  res.set_content(R"({"error":"invalid JSON"})",
                                                  "application/json");
                                  return;
                              }

                              auto subnet = body.value("subnet", "");
                              auto discovered_by = body.value("discovered_by", "");
                              int upserted = 0;

                              if (body.contains("devices") && body["devices"].is_array()) {
                                  for (const auto& dev : body["devices"]) {
                                      DiscoveredDevice d;
                                      d.ip_address = dev.value("ip_address", "");
                                      d.mac_address = dev.value("mac_address", "");
                                      d.hostname = dev.value("hostname", "");
                                      d.discovered_by = discovered_by;
                                      d.subnet = subnet;
                                      if (!d.ip_address.empty()) {
                                          auto r = discovery_store_->upsert_device(d);
                                          if (r)
                                              ++upserted;
                                      }
                                  }
                              }

                              audit_log(req, "discovery.scan", "success", "Discovery",
                                        subnet, std::to_string(upserted) + " devices");

                              res.status = 200;
                              res.set_content(
                                  nlohmann::json({{"status", "ok"},
                                                  {"devices_stored", upserted}}).dump(),
                                  "application/json");
                          });

        // GET /api/discovery/results — list discovered devices
        web_server_->Get("/api/discovery/results",
                         [this](const httplib::Request& req, httplib::Response& res) {
                             if (!require_permission(req, res, "Infrastructure", "Read"))
                                 return;
                             if (!discovery_store_) {
                                 res.status = 503;
                                 res.set_content(R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})", "application/json");
                                 return;
                             }
                             auto subnet = req.get_param_value("subnet");
                             auto devices = discovery_store_->list_devices(subnet);
                             nlohmann::json arr = nlohmann::json::array();
                             for (const auto& d : devices) {
                                 arr.push_back({{"id", d.id},
                                                {"ip_address", d.ip_address},
                                                {"mac_address", d.mac_address},
                                                {"hostname", d.hostname},
                                                {"managed", d.managed},
                                                {"agent_id", d.agent_id},
                                                {"discovered_by", d.discovered_by},
                                                {"discovered_at", d.discovered_at},
                                                {"last_seen", d.last_seen},
                                                {"subnet", d.subnet}});
                             }
                             res.set_content(
                                 nlohmann::json({{"devices", arr},
                                                 {"total", static_cast<int64_t>(devices.size())}})
                                     .dump(),
                                 "application/json");
                         });
