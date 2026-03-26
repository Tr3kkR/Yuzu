        // -- Directory Sync API (Phase 7: AD/Entra integration) ---------------------

        // POST /api/directory/sync — trigger directory sync
        web_server_->Post("/api/directory/sync",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!require_permission(req, res, "Directory", "Write"))
                    return;
                if (!directory_sync_ || !directory_sync_->is_open()) {
                    res.status = 503;
                    res.set_content(R"({"error":{"code":503,"message":"directory sync not available"},"meta":{"api_version":"v1"}})", "application/json");
                    return;
                }

                nlohmann::json body;
                try {
                    body = nlohmann::json::parse(req.body);
                } catch (const std::exception& e) {
                    res.status = 400;
                    res.set_content(nlohmann::json({{"error", e.what()}}).dump(), "application/json");
                    return;
                }

                auto provider = body.value("provider", "entra");

                if (provider == "entra") {
                    EntraConfig ec;
                    ec.tenant_id = body.value("tenant_id", "");
                    ec.client_id = body.value("client_id", "");
                    ec.client_secret = body.value("client_secret", "");

                    if (ec.tenant_id.empty() || ec.client_id.empty() || ec.client_secret.empty()) {
                        res.status = 400;
                        res.set_content(R"({"error":"tenant_id, client_id, and client_secret are required"})",
                                        "application/json");
                        return;
                    }

                    auto result = directory_sync_->sync_entra(ec);
                    if (!result) {
                        res.status = 500;
                        res.set_content(nlohmann::json({{"error", result.error()}}).dump(),
                                        "application/json");
                        return;
                    }

                    auto session = require_auth(req, res);
                    if (session)
                        audit_log(req, "directory.sync", "success", "Directory", "entra",
                                  "Entra ID sync completed");

                    auto status = directory_sync_->get_status();
                    res.set_content(nlohmann::json({
                        {"status", "completed"},
                        {"provider", "entra"},
                        {"user_count", status.user_count},
                        {"group_count", status.group_count}
                    }).dump(), "application/json");
                } else if (provider == "ldap") {
                    LdapConfig lc;
                    lc.server = body.value("server", "");
                    lc.port = body.value("port", 389);
                    lc.base_dn = body.value("base_dn", "");
                    lc.bind_dn = body.value("bind_dn", "");
                    lc.bind_password = body.value("bind_password", "");
                    lc.use_ssl = body.value("use_ssl", false);

                    auto result = directory_sync_->sync_ldap(lc);
                    if (!result) {
                        res.status = 501;
                        res.set_content(nlohmann::json({{"error", result.error()}}).dump(),
                                        "application/json");
                        return;
                    }
                    res.set_content(R"({"status":"completed","provider":"ldap"})", "application/json");
                } else {
                    res.status = 400;
                    res.set_content(R"({"error":"unsupported provider; use 'entra' or 'ldap'"})",
                                    "application/json");
                }
            });

        // GET /api/directory/users — list synced users
        web_server_->Get("/api/directory/users",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!require_permission(req, res, "Directory", "Read"))
                    return;
                if (!directory_sync_ || !directory_sync_->is_open()) {
                    res.status = 503;
                    res.set_content(R"({"error":{"code":503,"message":"directory sync not available"},"meta":{"api_version":"v1"}})", "application/json");
                    return;
                }

                auto group_filter = req.get_param_value("group_id");
                auto users = directory_sync_->get_synced_users(group_filter);

                nlohmann::json arr = nlohmann::json::array();
                for (const auto& u : users) {
                    nlohmann::json groups_arr = nlohmann::json::array();
                    for (const auto& g : u.groups)
                        groups_arr.push_back(g);

                    arr.push_back({{"id", u.id},
                                   {"display_name", u.display_name},
                                   {"email", u.email},
                                   {"upn", u.upn},
                                   {"enabled", u.enabled},
                                   {"groups", groups_arr},
                                   {"synced_at", u.synced_at}});
                }

                res.set_content(nlohmann::json({
                    {"users", arr},
                    {"count", arr.size()}
                }).dump(), "application/json");
            });

        // GET /api/directory/status — sync status
        web_server_->Get("/api/directory/status",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!require_permission(req, res, "Directory", "Read"))
                    return;
                if (!directory_sync_ || !directory_sync_->is_open()) {
                    res.status = 503;
                    res.set_content(R"({"error":{"code":503,"message":"directory sync not available"},"meta":{"api_version":"v1"}})", "application/json");
                    return;
                }

                auto status = directory_sync_->get_status();
                auto groups = directory_sync_->get_synced_groups();
                auto mappings = directory_sync_->get_group_role_mappings();

                nlohmann::json groups_arr = nlohmann::json::array();
                for (const auto& g : groups) {
                    groups_arr.push_back({{"id", g.id},
                                          {"display_name", g.display_name},
                                          {"description", g.description},
                                          {"mapped_role", g.mapped_role},
                                          {"synced_at", g.synced_at}});
                }

                res.set_content(nlohmann::json({
                    {"provider", status.provider},
                    {"status", status.status},
                    {"last_sync_at", status.last_sync_at},
                    {"user_count", status.user_count},
                    {"group_count", status.group_count},
                    {"last_error", status.last_error},
                    {"groups", groups_arr}
                }).dump(), "application/json");
            });

        // PUT /api/directory/group-mappings — configure group-to-role mappings
        web_server_->Put("/api/directory/group-mappings",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!require_permission(req, res, "Directory", "Write"))
                    return;
                if (!directory_sync_ || !directory_sync_->is_open()) {
                    res.status = 503;
                    res.set_content(R"({"error":{"code":503,"message":"directory sync not available"},"meta":{"api_version":"v1"}})", "application/json");
                    return;
                }

                nlohmann::json body;
                try {
                    body = nlohmann::json::parse(req.body);
                } catch (const std::exception& e) {
                    res.status = 400;
                    res.set_content(nlohmann::json({{"error", e.what()}}).dump(), "application/json");
                    return;
                }

                if (!body.contains("mappings") || !body["mappings"].is_array()) {
                    res.status = 400;
                    res.set_content(R"({"error":"'mappings' array required"})", "application/json");
                    return;
                }

                int count = 0;
                for (const auto& m : body["mappings"]) {
                    auto group_id = m.value("group_id", "");
                    auto role_name = m.value("role_name", "");
                    if (group_id.empty())
                        continue;

                    if (role_name.empty())
                        directory_sync_->remove_group_role_mapping(group_id);
                    else
                        directory_sync_->configure_group_role_mapping(group_id, role_name);
                    ++count;
                }

                auto session = require_auth(req, res);
                if (session)
                    audit_log(req, "directory.group_mapping.update", "success",
                              "Directory", "group-mappings",
                              std::to_string(count) + " mappings updated");

                auto mappings = directory_sync_->get_group_role_mappings();
                nlohmann::json mappings_arr = nlohmann::json::array();
                for (const auto& [gid, role] : mappings) {
                    mappings_arr.push_back({{"group_id", gid}, {"role_name", role}});
                }

                res.set_content(nlohmann::json({
                    {"mappings", mappings_arr},
                    {"count", mappings_arr.size()}
                }).dump(), "application/json");
            });

        // -- Patch Management API (Phase 7: Patch Deployment Workflow) ----------------

        // GET /api/patches — list patches across fleet
        web_server_->Get("/api/patches",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!require_permission(req, res, "Patch", "Read"))
                    return;
                if (!patch_manager_ || !patch_manager_->is_open()) {
                    res.status = 503;
                    res.set_content(R"({"error":{"code":503,"message":"patch manager not available"},"meta":{"api_version":"v1"}})", "application/json");
                    return;
                }

                PatchQuery q;
                q.agent_id = req.get_param_value("agent_id");
                q.severity = req.get_param_value("severity");
                q.status = req.get_param_value("status");
                try {
                    auto limit_str = req.get_param_value("limit");
                    if (!limit_str.empty())
                        q.limit = std::stoi(limit_str);
                } catch (...) {}

                auto status_filter = q.status.empty() ? "missing" : q.status;
                std::vector<PatchInfo> patches;
                if (status_filter == "installed")
                    patches = patch_manager_->get_installed_patches(q);
                else
                    patches = patch_manager_->get_missing_patches(q);

                nlohmann::json arr = nlohmann::json::array();
                for (const auto& p : patches) {
                    arr.push_back({{"kb_id", p.kb_id},
                                   {"title", p.title},
                                   {"severity", p.severity},
                                   {"status", p.status},
                                   {"agent_id", p.agent_id},
                                   {"released_at", p.released_at},
                                   {"scanned_at", p.scanned_at}});
                }

                // Also include fleet summary
                auto summary = patch_manager_->get_fleet_patch_summary(20);
                nlohmann::json summary_arr = nlohmann::json::array();
                for (const auto& [kb, cnt] : summary) {
                    summary_arr.push_back({{"kb_id", kb}, {"affected_agents", cnt}});
                }

                res.set_content(nlohmann::json({
                    {"patches", arr},
                    {"count", arr.size()},
                    {"fleet_summary", summary_arr}
                }).dump(), "application/json");
            });

        // POST /api/patches/deploy — deploy a patch to agents
        web_server_->Post("/api/patches/deploy",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!require_permission(req, res, "Patch", "Write"))
                    return;
                if (!patch_manager_ || !patch_manager_->is_open()) {
                    res.status = 503;
                    res.set_content(R"({"error":{"code":503,"message":"patch manager not available"},"meta":{"api_version":"v1"}})", "application/json");
                    return;
                }

                nlohmann::json body;
                try {
                    body = nlohmann::json::parse(req.body);
                } catch (const std::exception& e) {
                    res.status = 400;
                    res.set_content(nlohmann::json({{"error", e.what()}}).dump(), "application/json");
                    return;
                }

                auto kb_id = body.value("kb_id", "");
                if (kb_id.empty()) {
                    res.status = 400;
                    res.set_content(R"({"error":"kb_id is required"})", "application/json");
                    return;
                }

                std::vector<std::string> agent_ids;
                if (body.contains("agent_ids") && body["agent_ids"].is_array()) {
                    for (const auto& a : body["agent_ids"])
                        if (a.is_string())
                            agent_ids.push_back(a.get<std::string>());
                }

                if (agent_ids.empty()) {
                    res.status = 400;
                    res.set_content(R"({"error":"at least one agent_id is required"})",
                                    "application/json");
                    return;
                }

                bool reboot = body.value("reboot_if_needed", false);
                int reboot_delay = body.value("reboot_delay_seconds", 300);
                int64_t reboot_at = body.value("reboot_at", static_cast<int64_t>(0));

                // Validate reboot_delay range
                reboot_delay = std::clamp(reboot_delay, 60, 86400);

                // Validate reboot_at: must be 0 (disabled) or in the future
                if (reboot_at != 0) {
                    auto now_ts = std::chrono::duration_cast<std::chrono::seconds>(
                                      std::chrono::system_clock::now().time_since_epoch()).count();
                    if (reboot_at < now_ts) {
                        res.status = 400;
                        res.set_content(R"({"error":{"code":400,"message":"reboot_at must be in the future or 0"},"meta":{"api_version":"v1"}})",
                                        "application/json");
                        return;
                    }
                }

                std::string created_by = "unknown";
                auto session = require_auth(req, res);
                if (session)
                    created_by = session->username;

                auto depl_result = patch_manager_->deploy_patch(
                    kb_id, agent_ids, reboot, created_by, reboot_delay, reboot_at);
                if (!depl_result) {
                    res.status = 400;
                    res.set_content(nlohmann::json({{"error", depl_result.error()}}).dump(),
                                    "application/json");
                    return;
                }

                audit_log(req, "patch.deploy", "success", "Patch", *depl_result,
                          "Deployed " + kb_id + " to " + std::to_string(agent_ids.size()) + " agents");

                res.status = 201;
                res.set_content(nlohmann::json({
                    {"deployment_id", *depl_result},
                    {"kb_id", kb_id},
                    {"target_count", agent_ids.size()},
                    {"status", "pending"}
                }).dump(), "application/json");
            });

        // GET /api/patches/deployments/:id — deployment status
        web_server_->Get(R"(/api/patches/deployments/([a-f0-9]+))",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!require_permission(req, res, "Patch", "Read"))
                    return;
                if (!patch_manager_) {
                    res.status = 503;
                    res.set_content(R"({"error":{"code":503,"message":"patch manager not available"},"meta":{"api_version":"v1"}})", "application/json");
                    return;
                }

                auto id = req.matches[1].str();
                auto depl = patch_manager_->get_deployment(id);
                if (!depl) {
                    res.status = 404;
                    res.set_content(R"({"error":"deployment not found"})", "application/json");
                    return;
                }

                nlohmann::json targets_arr = nlohmann::json::array();
                for (const auto& t : depl->targets) {
                    targets_arr.push_back({{"agent_id", t.agent_id},
                                           {"status", t.status},
                                           {"error", t.error},
                                           {"started_at", t.started_at},
                                           {"completed_at", t.completed_at}});
                }

                res.set_content(nlohmann::json({
                    {"id", depl->id},
                    {"kb_id", depl->kb_id},
                    {"title", depl->title},
                    {"status", depl->status},
                    {"created_by", depl->created_by},
                    {"reboot_if_needed", depl->reboot_if_needed},
                    {"reboot_delay_seconds", depl->reboot_delay_seconds},
                    {"reboot_at", depl->reboot_at},
                    {"created_at", depl->created_at},
                    {"completed_at", depl->completed_at},
                    {"total_targets", depl->total_targets},
                    {"completed_targets", depl->completed_targets},
                    {"failed_targets", depl->failed_targets},
                    {"targets", targets_arr}
                }).dump(), "application/json");
            });

        // GET /api/patches/deployments — list all deployments
        web_server_->Get("/api/patches/deployments",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!require_permission(req, res, "Patch", "Read"))
                    return;
                if (!patch_manager_) {
                    res.status = 503;
                    res.set_content(R"({"error":{"code":503,"message":"patch manager not available"},"meta":{"api_version":"v1"}})", "application/json");
                    return;
                }

                int limit = 50;
                try {
                    auto limit_str = req.get_param_value("limit");
                    if (!limit_str.empty())
                        limit = std::stoi(limit_str);
                } catch (...) {}

                auto deployments = patch_manager_->list_deployments(limit);
                nlohmann::json arr = nlohmann::json::array();
                for (const auto& d : deployments) {
                    arr.push_back({{"id", d.id},
                                   {"kb_id", d.kb_id},
                                   {"title", d.title},
                                   {"status", d.status},
                                   {"created_by", d.created_by},
                                   {"created_at", d.created_at},
                                   {"completed_at", d.completed_at},
                                   {"total_targets", d.total_targets},
                                   {"completed_targets", d.completed_targets},
                                   {"failed_targets", d.failed_targets}});
                }

                res.set_content(nlohmann::json({
                    {"deployments", arr},
                    {"count", arr.size()}
                }).dump(), "application/json");
            });

        // POST /api/patches/deployments/:id/cancel — cancel a deployment
        web_server_->Post(R"(/api/patches/deployments/([a-f0-9]+)/cancel)",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!require_permission(req, res, "Patch", "Write"))
                    return;
                if (!patch_manager_) {
                    res.status = 503;
                    res.set_content(R"({"error":{"code":503,"message":"patch manager not available"},"meta":{"api_version":"v1"}})", "application/json");
                    return;
                }

                auto id = req.matches[1].str();
                auto cancel_result = patch_manager_->cancel_deployment(id);
                if (!cancel_result) {
                    res.status = 400;
                    res.set_content(nlohmann::json({{"error", cancel_result.error()}}).dump(),
                                    "application/json");
                    return;
                }

                audit_log(req, "patch.deployment.cancel", "success", "Patch", id,
                          "Deployment cancelled");

                res.set_content(R"({"status":"cancelled"})", "application/json");
            });
